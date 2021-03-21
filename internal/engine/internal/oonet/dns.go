package oonet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// DNSMonitor monitors DNS lookups. The callbacks MUST NOT
// modify any of their arguments.
type DNSMonitor interface {
	// OnDNSLookupHostStart is called when we start
	// a lookup host operation.
	OnDNSLookupHostStart(hostname string)

	// OnDNSLookupHostDone is called after
	// a lookup host operation.
	OnDNSLookupHostDone(hostname string, addrs []string, err error)

	// OnDNSSendQuery is called before sending a query. The argument
	// is a serialized user friendly version of the query.
	OnDNSSendQuery(query string)

	// OnDNSRecvReply is called when we receive a well formed
	// reply. The argument is a serialized user friendly version
	// of the reply.
	OnDNSRecvReply(reply string)
}

// DNSUnderlyingResolver is the underlying resolver
// used by an instance of DNSResolver.
type DNSUnderlyingResolver interface {
	// LookupHost should behave like net.Resolver.LookupHost.
	LookupHost(ctx context.Context, hostname string) ([]string, error)
}

// DNSResolver is the DNS resolver. Its main job is to emit
// events and to ensure returned errors are wrapped.
//
// The real DNS resolution work is demanded to an underlying
// resolver. The DNSResolver will not own the underlying resolver
// and will not attempt to reclaim unused connections that the
// underlying resolver MAY be keeping alive. It is your job
// to ensure that you are closing such connections when needed.
//
// You MUST NOT modify any field of Resolver after construction
// because this MAY result in a data race.
type DNSResolver struct {
	// UnderlyingResolver is the optional DNSUnderlyingResolver
	// to use. If not set, we use net.Resolver. If you want, e.g.,
	// a DoH resolver, then you should override this field.
	UnderlyingResolver DNSUnderlyingResolver
}

// ErrLookupHost is an error occurring during a LookupHost operation.
type ErrLookupHost struct {
	error
}

// Unwrap yields the underlying error.
func (e *ErrLookupHost) Unwrap() error {
	return e.error
}

// LookupHost maps a hostname to a list of IP addresses.
func (r *DNSResolver) LookupHost(
	ctx context.Context, hostname string) ([]string, error) {
	ContextMonitor(ctx).OnDNSLookupHostStart(hostname)
	ures := r.underlyingResolver()
	addrs, err := ures.LookupHost(ctx, hostname)
	if err != nil {
		err = &ErrLookupHost{err}
	}
	ContextMonitor(ctx).OnDNSLookupHostDone(hostname, addrs, err)
	return addrs, err
}

// underlyingResolver returns the DNSUnderlyingResolver to use.
func (r *DNSResolver) underlyingResolver() DNSUnderlyingResolver {
	if r.UnderlyingResolver != nil {
		return r.UnderlyingResolver
	}
	return &net.Resolver{}
}

// DNSCodec encodes and decodes DNS messages. In addition to
// marshalling and unmarshalling, this data structure will also
// emit an event every time we successfully marshal a query
// and every time we successfully unmarshal a reply.
type DNSCodec interface {
	// EncodeLookupHostRequest encodes a LookupHost request.
	EncodeLookupHostRequest(ctx context.Context,
		domain string, qtype uint16, padding bool) ([]byte, error)

	// DecodeLookupHostResponse decodes a LookupHost response.
	DecodeLookupHostResponse(ctx context.Context,
		qtype uint16, data []byte) ([]string, error)
}

// dnsMiekgCodec is a DNSCodec using miekg/dns. This is the
// codec used by default by this library.
type dnsMiekgCodec struct{}

// EncodeLookupHostRequest implements DNSCodec.EncodeLookupHostRequest.
func (c *dnsMiekgCodec) EncodeLookupHostRequest(
	ctx context.Context, domain string,
	qtype uint16, padding bool) ([]byte, error) {
	const (
		// desiredBlockSize is the size that the padded
		// query should be multiple of
		desiredBlockSize = 128
		// EDNS0MaxResponseSize is the maximum response size for EDNS0
		EDNS0MaxResponseSize = 4096
		// DNSSECEnabled turns on support for DNSSEC when using EDNS0
		DNSSECEnabled = true
	)
	question := dns.Question{
		Name:   dns.Fqdn(domain),
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}
	query := new(dns.Msg)
	query.Id = dns.Id()
	query.RecursionDesired = true
	query.Question = make([]dns.Question, 1)
	query.Question[0] = question
	if padding {
		query.SetEdns0(EDNS0MaxResponseSize, DNSSECEnabled)
		// Clients SHOULD pad queries to the closest multiple of
		// 128 octets RFC8467#section-4.1. We inflate the query
		// length by the size of the option (i.e. 4 octets). The
		// cast to uint is necessary to make the modulus operation
		// work as intended when the desiredBlockSize is smaller
		// than (query.Len()+4) ¯\_(ツ)_/¯.
		remainder := (desiredBlockSize - uint(query.Len()+4)) % desiredBlockSize
		opt := new(dns.EDNS0_PADDING)
		opt.Padding = make([]byte, remainder)
		query.IsEdns0().Option = append(query.IsEdns0().Option, opt)
	}
	ContextMonitor(ctx).OnDNSSendQuery(query.String())
	return query.Pack()
}

// Implementation note: the following errors try to match
// the errors returned by the Go standard library. The CGO
// implementation of the resolver maps EAI_NONAME to the
// errDNSNoSuchHost error and all other errors are basically
// wrappers for the EAI error with info on temporary.
//
// In particular, the strings we use here are the same
// ones used by the stdlib. Because of the Go 1.x stability
// guarantees, we know these strings don't change.

// ErrDNSNoSuchHost indicates that the host does not exist. When
// returned by our Go implementation, this is RcodeNameError.
var ErrDNSNoSuchHost = errors.New("no such host")

// ErrDNSNoAsnwerFromDNSServer indicates that the server did
// not provide any A/AAAA answer back to us.
var ErrDNSNoAsnwerFromDNSServer = errors.New("no answer from DNS server")

// ErrDNSServerTemporarilyMisbehaving is returned when the server
// says that it has failed to service the query. When returned
// by our Go implementation, this is RcodeServerFailure.
var ErrDNSServerTemporarilyMisbehaving = errors.New("server misbehaving")

// ErrDNSServerMisbehaving is the catch all error when we don't
// understand what error was returned by the server.
var ErrDNSServerMisbehaving = errors.New("server misbehaving")

// DecodeLookupHostResponse implements DNSCodec.DecodeLookupHostResponse.
func (c *dnsMiekgCodec) DecodeLookupHostResponse(
	ctx context.Context, qtype uint16, data []byte) ([]string, error) {
	reply := new(dns.Msg)
	if err := reply.Unpack(data); err != nil {
		return nil, err
	}
	ContextMonitor(ctx).OnDNSRecvReply(reply.String())
	switch reply.Rcode {
	case dns.RcodeNameError:
		return nil, ErrDNSNoSuchHost
	case dns.RcodeServerFailure:
		return nil, ErrDNSServerTemporarilyMisbehaving
	case dns.RcodeSuccess:
		// fallthrough
	default:
		return nil, ErrDNSServerMisbehaving
	}
	var addrs []string
	for _, answer := range reply.Answer {
		switch qtype {
		case dns.TypeA:
			if rra, ok := answer.(*dns.A); ok {
				ip := rra.A
				addrs = append(addrs, ip.String())
			}
		case dns.TypeAAAA:
			if rra, ok := answer.(*dns.AAAA); ok {
				ip := rra.AAAA
				addrs = append(addrs, ip.String())
			}
		}
	}
	if len(addrs) <= 0 {
		return nil, ErrDNSNoAsnwerFromDNSServer
	}
	return addrs, nil
}

// DNSOverHTTPSHTTPClient is the HTTP client to use. The standard
// library http.DefaultHTTPClient matches this interface.
type DNSOverHTTPSHTTPClient interface {
	// Do should behave like http.Client.Do.
	Do(req *http.Request) (*http.Response, error)
}

// DNSOverHTTPSResolver is a DNS over HTTPS resolver. You MUST NOT
// modify any field of this struct once you've initialized it because
// that MAY likely lead to data races.
//
// DNSOverHTTPSResolver WILL NOT wrap returned errors using, e.g.,
// ErrLookupHost because this is the DNSResolver's job.
//
// The DNSOverHTTPSResolver references an underlying HTTP client,
// however, it DOES NOT OWN such a client. Therefore, it won't
// attempt to reclaim any unused connections in such a client. It
// is your responsibility to do that when needed.
//
// This resolver will perform the DNS round trip (sending a query
// and receiving a reply) in a background goroutine. If the context
// expires before that operation is complete, this resolver will
// leak such a goroutine and return early. A well behaved HTTP client
// should be configured such that any I/O operation will eventually
// timeout. So, if you are using a well behaved HTTP client with
// this resolver, then goroutine leak will be temporary.
type DNSOverHTTPSResolver struct {
	// Client is the optional HTTP client to use. If not set,
	// then we will use HTTPXDefaultClient.
	Client DNSOverHTTPSHTTPClient

	// Codec is the DNSCodec to use. If not set, then
	// we will use a suitable default DNSCodec.
	Codec DNSCodec

	// URL is the mandatory URL of the server. If not set,
	// then this code will certainly fail.
	URL string

	// UserAgent is the optional User-Agent header to use. If not
	// set, Golang's standard user agent is used.
	UserAgent string
}

// LookupHost implements DNSUnderlyingResolver.LookupHost. This
// function WILL NOT wrap the returned error. We assume that
// this job is performed by DNSResolver, which should be used
// as a wrapper type for this type.
func (r *DNSOverHTTPSResolver) LookupHost(
	ctx context.Context, hostname string) ([]string, error) {
	return (&dnsGenericResolver{
		codec:   r.codec(),
		padding: true,
		t:       r,
	}).LookupHost(ctx, hostname)
}

// codec returns the DNSCodec to use.
func (r *DNSOverHTTPSResolver) codec() DNSCodec {
	if r.Codec != nil {
		return r.Codec
	}
	return &dnsMiekgCodec{}
}

// dnsOverHTTPSResult is the result of running the DNS
// round trip in a background goroutine.
type dnsOverHTTPSResult struct {
	// data is the data in the response body.
	data []byte

	// err is the error that occurred.
	err error
}

// roundTrip implements dnsTransport.roundTrip. This function
// will read the body in a background goroutine such that we're
// able to immediately react to the context being cancelled.
func (r *DNSOverHTTPSResolver) roundTrip(
	ctx context.Context, query []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(
		ctx, "POST", r.URL, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	if r.UserAgent != "" {
		req.Header.Set("user-agent", r.UserAgent)
	}
	req.Header.Set("content-type", "application/dns-message")
	var resp *http.Response
	resp, err = r.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, ErrDNSServerTemporarilyMisbehaving
	}
	if resp.Header.Get("content-type") != "application/dns-message" {
		return nil, ErrDNSServerTemporarilyMisbehaving
	}
	ch := make(chan *dnsOverHTTPSResult, 1) // buffer
	const maxBodySize = 1 << 20
	go r.readyBodyAsync(resp.Body, maxBodySize, ch)
	select {
	case out := <-ch:
		return out.data, out.err
	case <-ctx.Done():
		return nil, ctx.Err() // the context won the race
	}
}

// readyBodyAsync is a background goroutine that reads the body
// and posts the result on the provided channel.
func (r *DNSOverHTTPSResolver) readyBodyAsync(body io.Reader,
	limit int64, ch chan<- *dnsOverHTTPSResult) {
	body = io.LimitReader(body, limit)
	data, err := ioutil.ReadAll(body)
	ch <- &dnsOverHTTPSResult{data: data, err: err}
}

// client returns the DNSOverHTTPSClient to use.
func (r *DNSOverHTTPSResolver) client() DNSOverHTTPSHTTPClient {
	if r.Client != nil {
		return r.Client
	}
	return HTTPXDefaultClient
}

// dnsTransport is a DNS transport. The job of a transport
// is to send a query (as a bag of bytes) and implement the
// proper protocol (e.g. DoH) to read the bytes that will
// possibly correspond to a DNS reply.
//
// If a dnsTransport is not able to deal with concurrent
// DNS round trips, then is should use locking to prevent
// more than one concurrent round trip at a time.
//
// Implementations of dnsTransport SHOULD honour the
// context and return immediately when it has been cancelled.
type dnsTransport interface {
	// roundTrip performs the DNS round trip.
	roundTrip(ctx context.Context, data []byte) ([]byte, error)
}

// dnsGenericResolver is a generic resolver. The job of this
// structure is to generate queries to send, send them via the
// configured transport, and parse the resulting bytes that
// are returned by the transport.
//
// The dnsGenericResolver MAY issue queries in parallel. A well
// behaved transport SHOULD use locking if it's not able to deal
// correctly with queries running in parallel.
//
// This type assumes that the transport is able to immediately
// react to a cancelled context, therefore it DOESN'T check
// whether the context has been terminated while queries are
// still pending. That's the transport job, not ours.
type dnsGenericResolver struct {
	// codec is the mandatory DNSCodec.
	codec DNSCodec

	// padding indicates whether we want padding.
	padding bool

	// t is the mandatory transport.
	t dnsTransport
}

// dnsLookupHostResult is the result of a lookupHost operation.
type dnsLookupHostResult struct {
	// addrs is the list of returned addresses.
	addrs []string

	// err is the error (if any).
	err error
}

// ErrDNSQuery contains the multiple errors occurred during
// a query. You MUST construct this error ONLY when both the
// AAAA and the A query failed.
type ErrDNSQuery struct {
	// ErrA is the error occurred during the A query.
	ErrA error

	// ErrAAAA is the error occurred during the AAAA query.
	ErrAAAA error
}

// Error stringifies the error.
func (e *ErrDNSQuery) Error() string {
	return fmt.Sprintf("{A error: %s; AAAA error: %s}",
		e.ErrA.Error(), e.ErrAAAA.Error())
}

// LookupHost performs a LookupHost operation.
func (r *dnsGenericResolver) LookupHost(
	ctx context.Context, hostname string) ([]string, error) {
	resA, resAAAA := make(chan *dnsLookupHostResult), make(chan *dnsLookupHostResult)
	go r.asyncLookupHost(ctx, hostname, dns.TypeA, r.padding, resA)
	// Implementation note: we can make this parallel very easily and it will
	// also be significantly more difficult to debug because the events in the
	// monitor will overlap while the two requests are in progress.
	// Also note that we don't honour the context because it's the job
	// of the transport to react to context cancellation.
	replyA := <-resA
	go r.asyncLookupHost(ctx, hostname, dns.TypeAAAA, r.padding, resAAAA)
	replyAAAA := <-resAAAA
	if replyA.err != nil && replyAAAA.err != nil {
		err := &ErrDNSQuery{ErrA: replyA.err, ErrAAAA: replyAAAA.err}
		return nil, err
	}
	var addrs []string
	addrs = append(addrs, replyA.addrs...)
	addrs = append(addrs, replyAAAA.addrs...)
	if len(addrs) < 1 {
		// Note: the codec SHOULD NOT allow for that but we
		// want to have a second line of defense here.
		return nil, ErrDNSNoAsnwerFromDNSServer
	}
	return addrs, nil
}

// asyncLookupHost is the goroutine that performs a lookupHost.
func (r *dnsGenericResolver) asyncLookupHost(
	ctx context.Context, hostname string, qtype uint16, padding bool,
	resch chan<- *dnsLookupHostResult) {
	addrs, err := r.doLookupHost(ctx, hostname, qtype, padding)
	resch <- &dnsLookupHostResult{addrs: addrs, err: err}
}

// doLookupHost performs a lookupHost operation.
func (r *dnsGenericResolver) doLookupHost(
	ctx context.Context, hostname string, qtype uint16,
	padding bool) ([]string, error) {
	query, err := r.codec.EncodeLookupHostRequest(ctx, hostname, qtype, padding)
	if err != nil {
		return nil, err
	}
	reply, err := r.t.roundTrip(ctx, query)
	if err != nil {
		return nil, err
	}
	return r.codec.DecodeLookupHostResponse(ctx, qtype, reply)
}

// DNSOverTLSDialer is the Dialer used by DNSOverTLSResolver.
type DNSOverTLSDialer interface {
	DialTLSContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DNSOverTLSResolver is a resolver using DNSOverTLS. The
// user of this struct MUST NOT change its fields after initialization
// because that MAY lead to data races.
//
// This struct will serialize the queries sent using the
// underlying connection such that only a single thread
// at any given time will have acccess to the conn.
type DNSOverTLSResolver struct {
	// Address is the address of the TLS server to use. It
	// MUST be set by the user before using this struct. If not
	// set, then this code will obviously fail.
	Address string

	// Codec is the optional DNSCodec to use. If not set, then
	// we will use the default miekg/dns codec.
	Codec DNSCodec

	// Dialer is the optional Dialer to use. If not set, then
	// we will use a default constructed Dialer struct.
	Dialer DNSOverTLSDialer

	// mu provides synchronization.
	mu sync.Mutex

	// reso is the resolver implementation.
	reso *dnsOverTCPTLSResolver
}

// LookupHost implements DNSUnderlyingResolver.LookupHost. This
// function WILL NOT wrap the returned error. We assume that
// this job is performed by DNSResolver, which should be used
// as a wrapper type for this type.
func (r *DNSOverTLSResolver) LookupHost(
	ctx context.Context, hostname string) ([]string, error) {
	r.mu.Lock()
	if r.reso == nil {
		r.reso = &dnsOverTCPTLSResolver{
			address: r.Address,
			codec:   r.codec(),
			dial:    r.dialer().DialTLSContext,
			padding: true,
		}
	}
	r.mu.Unlock()
	return r.reso.LookupHost(ctx, hostname)
}

// codec returns the DNSCodec to use.
func (r *DNSOverTLSResolver) codec() DNSCodec {
	if r.Codec != nil {
		return r.Codec
	}
	return &dnsMiekgCodec{}
}

// dialer returns the Dialer to use.
func (r *DNSOverTLSResolver) dialer() DNSOverTLSDialer {
	if r.Dialer != nil {
		return r.Dialer
	}
	return &Dialer{ALPN: []string{"dot"}}
}

// CloseIdleConnections closes the idle connections.
func (r *DNSOverTLSResolver) CloseIdleConnections() {
	r.mu.Lock()
	reso := r.reso
	r.mu.Unlock()
	if reso != nil {
		reso.CloseIdleConnections()
	}
}

// dnsOverTCPTLSResolver is a DNS resolver that uses either
// TCP or TLS depending on how it's configured. The user
// of this struct MUST NOT change its fields after initialization
// because that MAY lead to data races.
//
// This struct will serialize the queries sent using the
// underlying connection such that only a single thread
// at any given time will have acccess to the conn.
//
// This struct will create the required internal state
// the first time such state is actually needed.
type dnsOverTCPTLSResolver struct {
	// address is the address of the TCP/TLS server to use. It
	// MUST be set by the user before using this struct.
	address string

	// conn is the persistent connection. It will be
	// initialized on demand when it's needed.
	conn net.Conn

	// codec is the DNSCodec to use. It MUST be set
	// by the user before using this struct.
	codec DNSCodec

	// dial is the function to dial. It MUST be set
	// by the user before using this struct.
	dial func(ctx context.Context, network, address string) (net.Conn, error)

	// padding indicates whether we need padding. It MAY
	// be set by the user before using this struct.
	padding bool

	// mu ensures there is mutual exclusion.
	mu sync.Mutex

	// users is the atomic number of users that are
	// currently using this data structure.
	users int32
}

// LookupHost performs an host lookup.
func (r *dnsOverTCPTLSResolver) LookupHost(
	ctx context.Context, hostname string) ([]string, error) {
	return (&dnsGenericResolver{
		codec:   r.codec,
		padding: true,
		t:       r,
	}).LookupHost(ctx, hostname)
}

// roundTrip implements dnsTransport.roundTrip.
func (r *dnsOverTCPTLSResolver) roundTrip(
	ctx context.Context, query []byte) ([]byte, error) {
	atomic.AddInt32(&r.users, 1)            // know number of waiters
	r.mu.Lock()                             // concurrent goroutines will park here
	atomic.AddInt32(&r.users, -1)           // we are not waiting anymore
	reply, err := r.rtriplocked(ctx, query) // do round trip
	r.mu.Unlock()                           // next goroutine can now proceed
	return reply, err
}

// rtriplocked is the locked part of roundTrip.
func (r *dnsOverTCPTLSResolver) rtriplocked(
	ctx context.Context, query []byte) ([]byte, error) {
	if query == nil {
		// This special sentinel value indicates that
		// we want to close the idle connections if we're
		// the only one who's using it now. Otherwise,
		// we'll just take a short trip in here and leave.
		if atomic.LoadInt32(&r.users) == 0 && r.conn != nil {
			r.conn.Close()
			r.conn = nil
		}
		return nil, nil
	}
	return r.do(ctx, query)
}

// errDNSOverTCPTLSRedial indicates that we should dial
// again because the connection was immediately lost.
type errDNSOverTCPTLSRedial struct {
	error
}

// do implements sending a query and receiving the reply
// over a TCP or TLS persistent channel. This function
// assumes to have exclusive access to the conn.
func (dl *dnsOverTCPTLSResolver) do(
	ctx context.Context, query []byte) ([]byte, error) {
	if err := dl.maybeDial(ctx); err != nil {
		return nil, err
	}
	reply, err := dl.try(ctx, query)
	if err == nil {
		return reply, nil
	}
	var redial *errDNSOverTCPTLSRedial
	if !errors.As(err, &redial) {
		return nil, err // this error was not a redial hint
	}
	if err := dl.forceDial(ctx); err != nil {
		return nil, err
	}
	return dl.try(ctx, query)
}

// maybeDial dials if the connection is nil. This function
// assumes to have exclusive access to the conn.
func (dl *dnsOverTCPTLSResolver) maybeDial(ctx context.Context) error {
	if dl.conn != nil {
		return nil
	}
	return dl.forceDial(ctx)
}

// forceDial forces dialing a new connection instance. This function
// assumes to have exclusive access to the conn.
func (dl *dnsOverTCPTLSResolver) forceDial(ctx context.Context) error {
	if dl.conn != nil {
		dl.conn.Close()
		dl.conn = nil
	}
	conn, err := dl.dial(ctx, "tcp", dl.address)
	if err != nil {
		return err
	}
	dl.conn = conn
	return nil
}

// errDNSOverTCPTLSQueryTooLong indicates that the query is too long.
var errDNSOverTCPTLSQueryTooLong = errors.New("query too long")

// dnsOverTCPTLSResult contains the result of running the
// currenct query in a background goroutine.
type dnsOverTCPTLSResult struct {
	reply []byte
	err   error
}

// try tries to send the query. Because sending and receiving the
// query is not bound to a context but to network deadlines, we run
// the I/O in a background goroutine and collect the results. This
// allows us to react immediately to context cancellation.
func (dl *dnsOverTCPTLSResolver) try(
	ctx context.Context, query []byte) ([]byte, error) {
	ch := make(chan *dnsOverTCPTLSResult, 1) // buffer!
	go dl.asyncTry(ctx, query, ch)
	select {
	case out := <-ch:
		return out.reply, out.err
	case <-ctx.Done():
		return nil, ctx.Err() // the context won
	}
}

// asyncTry is the "main" of the background goroutine that
// does the I/O required to get a DoTCP/DoTLS reply.
func (dl *dnsOverTCPTLSResolver) asyncTry(
	ctx context.Context, query []byte, ch chan<- *dnsOverTCPTLSResult) {
	var out dnsOverTCPTLSResult
	out.reply, out.err = dl.trySync(ctx, query)
	ch <- &out
}

// trySync tries to send the query and receive the reply. This
// code runs in a background goroutine, so that early cancellation
// of the context can be serviced by the caller goroutine.
func (dl *dnsOverTCPTLSResolver) trySync(
	ctx context.Context, query []byte) ([]byte, error) {
	if len(query) > math.MaxUint16 {
		return nil, errDNSOverTCPTLSQueryTooLong
	}
	defer dl.conn.SetDeadline(time.Time{})
	dl.conn.SetDeadline(time.Now().Add(10 * time.Second))
	// Write request
	buf := []byte{byte(len(query) >> 8)}
	buf = append(buf, byte(len(query)))
	buf = append(buf, query...)
	if _, err := dl.conn.Write(buf); err != nil {
		return nil, &errDNSOverTCPTLSRedial{err} // hint for possible redial
	}
	// Read response
	header := make([]byte, 2)
	if _, err := io.ReadFull(dl.conn, header); err != nil {
		return nil, err
	}
	length := int(header[0])<<8 | int(header[1])
	reply := make([]byte, length)
	if _, err := io.ReadFull(dl.conn, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// CloseIdleConnections forces the resolver to close
// any currently idle connection they might have.
func (r *dnsOverTCPTLSResolver) CloseIdleConnections() {
	r.roundTrip(context.Background(), nil) // use sentinel value
}

// DNSOverTCPDialer is the Dialer used by DNSOverTCPResolver.
type DNSOverTCPDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DNSOverTCPResolver is a resolver using DNSOverTCP. The
// user of this struct MUST NOT change its fields after initialization
// because that MAY lead to data races.
//
// This struct will serialize the queries sent using the
// underlying connection such that only a single thread
// at any given time will have acccess to the conn.
type DNSOverTCPResolver struct {
	// Address is the address of the TCP server to use. It
	// MUST be set by the user before using this struct. If not
	// set, then this code will obviously fail.
	Address string

	// Codec is the optional DNSCodec to use. If not set, then
	// we will use the default miekg/dns codec.
	Codec DNSCodec

	// Dialer is the optional Dialer to use. If not set, then
	// we will use a default constructed Dialer struct.
	Dialer DNSOverTCPDialer

	// mu provides synchronization.
	mu sync.Mutex

	// reso is the resolver implementation.
	reso *dnsOverTCPTLSResolver
}

// LookupHost implements DNSUnderlyingResolver.LookupHost. This
// function WILL NOT wrap the returned error. We assume that
// this job is performed by DNSResolver, which should be used
// as a wrapper type for this type.
func (r *DNSOverTCPResolver) LookupHost(
	ctx context.Context, hostname string) ([]string, error) {
	r.mu.Lock()
	if r.reso == nil {
		r.reso = &dnsOverTCPTLSResolver{
			address: r.Address,
			codec:   r.codec(),
			dial:    r.dialer().DialContext,
			padding: false,
		}
	}
	r.mu.Unlock()
	return r.reso.LookupHost(ctx, hostname)
}

// codec returns the DNSCodec to use.
func (r *DNSOverTCPResolver) codec() DNSCodec {
	if r.Codec != nil {
		return r.Codec
	}
	return &dnsMiekgCodec{}
}

// dialer returns the Dialer to use.
func (r *DNSOverTCPResolver) dialer() DNSOverTCPDialer {
	if r.Dialer != nil {
		return r.Dialer
	}
	return &Dialer{}
}

// CloseIdleConnections closes the idle connections.
func (r *DNSOverTCPResolver) CloseIdleConnections() {
	r.mu.Lock()
	reso := r.reso
	r.mu.Unlock()
	if reso != nil {
		reso.CloseIdleConnections()
	}
}

// DNSOverUDPDialer is the Dialer used by DNSOverUDPResolver.
type DNSOverUDPDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DNSOverUDPResolver is a resolver using DNSOverUDP. The
// user of this struct MUST NOT change its fields after initialization
// because that MAY lead to data races.
type DNSOverUDPResolver struct {
	// Address is the address of the UDP server to use. It
	// MUST be set by the user before using this struct. If not
	// set, then this code will obviously fail.
	Address string

	// Codec is the optional DNSCodec to use. If not set, then
	// we will use the default miekg/dns codec.
	Codec DNSCodec

	// Dialer is the optional Dialer to use. If not set, then
	// we will use a default constructed Dialer struct.
	Dialer DNSOverUDPDialer
}

// ErrDNSUDPLookup is an error during an UDP lookup. Since we
// try more than once, this error includes all the failures that
// occurred, as a list of errors.
type ErrDNSUDPLookup struct {
	// Errors contains all errors that occurred. They may be one
	// or more errors depending on what has happened.
	Errors []error
}

// Error returns the error string.
func (e *ErrDNSUDPLookup) Error() string {
	if len(e.Errors) == 1 {
		return e.Errors[0].Error() // optimisation for better clarity
	}
	return fmt.Sprintf("dnsUDPLookup: %+v", e.Errors)
}

// LookupHost implements DNSUnderlyingResolver.LookupHost. This
// function WILL NOT wrap the returned error. We assume that
// this job is performed by DNSResolver, which should be used
// as a wrapper type for this type.
func (r *DNSOverUDPResolver) LookupHost(
	ctx context.Context, hostname string) ([]string, error) {
	overall := &ErrDNSUDPLookup{}
	for i := 0; i < 3; i++ {
		addrs, err := (&dnsGenericResolver{
			codec:   r.codec(),
			padding: false,
			t:       r,
		}).LookupHost(ctx, hostname)
		if err != nil {
			overall.Errors = append(overall.Errors, err)
			continue
		}
		return addrs, nil
	}
	return nil, overall
}

// codec returns the DNSCodec to use.
func (r *DNSOverUDPResolver) codec() DNSCodec {
	if r.Codec != nil {
		return r.Codec
	}
	return &dnsMiekgCodec{}
}

// dnsOverUDPResult contains the result of running the
// currenct query in a background goroutine.
type dnsOverUDPResult struct {
	reply []byte
	err   error
}

// roundTrip implements dnsTransport.roundTrip. We run the real
// query in a background goroutine, so we can react without delays
// if the context has been cancelled by the user.
func (r *DNSOverUDPResolver) roundTrip(
	ctx context.Context, query []byte) ([]byte, error) {
	ch := make(chan *dnsOverUDPResult, 1) // buffer!
	go r.asyncRoundTrip(ctx, query, ch)
	select {
	case out := <-ch:
		return out.reply, out.err
	case <-ctx.Done():
		return nil, ctx.Err() // the context won
	}
}

// asyncRoundTrip is the "main" of the goroutine that runs the
// specific DNS round trip in the background.
func (r *DNSOverUDPResolver) asyncRoundTrip(
	ctx context.Context, query []byte, ch chan<- *dnsOverUDPResult) {
	out := &dnsOverUDPResult{}
	out.reply, out.err = r.syncRoundTrip(ctx, query)
	ch <- out
}

// syncRoundTrip is the sync round trip running in a background
// goroutine, so the caller goroutine can honor the context.
func (r *DNSOverUDPResolver) syncRoundTrip(ctx context.Context,
	query []byte) ([]byte, error) {
	// TODO(bassosimone): dialing every time may cause an extra DNS
	// lookup per DNS query, so this is not very smart. At the
	// same time, because we set a deadline, we cannot easily have
	// parallel queries on the same socket (maybe?).
	conn, err := r.dialer().DialContext(ctx, "udp", r.Address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// Use five seconds timeout like Bionic does. See
	// https://labs.ripe.net/Members/baptiste_jonglez_1/persistent-dns-connections-for-reliability-and-performance
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = conn.Write(query); err != nil {
		return nil, err
	}
	reply := make([]byte, 1<<17)
	var count int
	count, err = conn.Read(reply)
	if err != nil {
		return nil, err
	}
	return reply[:count], nil
}

// dialer returns the Dialer to use.
func (r *DNSOverUDPResolver) dialer() DNSOverUDPDialer {
	if r.Dialer != nil {
		return r.Dialer
	}
	return &Dialer{}
}
