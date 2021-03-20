package oonet

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"net/http"

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

// DNSResolver is a DNS resolver.
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
func (r *DNSResolver) LookupHost(ctx context.Context, hostname string) ([]string, error) {
	ContextMonitor(ctx).OnDNSLookupHostStart(hostname)
	ures := r.underlyingResolver()
	addrs, err := ures.LookupHost(ctx, hostname)
	if err != nil {
		err = &ErrLookupHost{err}
	}
	ContextMonitor(ctx).OnDNSLookupHostDone(hostname, addrs, err)
	return addrs, err
}

// DNSIdleConnectionsCloser allows to close idle connections.
type DNSIdleConnectionsCloser interface {
	CloseIdleConnections()
}

// CloseIdleConnections closes idle connections.
func (r *DNSResolver) CloseIdleConnection() {
	if c, ok := r.underlyingResolver().(DNSIdleConnectionsCloser); ok {
		c.CloseIdleConnections()
	}
}

// underlyingResolver returns the DNSUnderlyingResolver to use.
func (r *DNSResolver) underlyingResolver() DNSUnderlyingResolver {
	if r.UnderlyingResolver != nil {
		return r.UnderlyingResolver
	}
	return &net.Resolver{}
}

// DNSCodec encodes and decodes DNS messages.
type DNSCodec interface {
	// EncodeLookupHostRequest encodes a LookupHost request.
	EncodeLookupHostRequest(ctx context.Context,
		domain string, qtype uint16, padding bool) ([]byte, error)

	// DecodeLookupHostResponse decodes a LookupHost response.
	DecodeLookupHostResponse(ctx context.Context,
		qtype uint16, data []byte) ([]string, error)
}

// dnsMiekgCodec is a DNSCodec using miekg/dns.
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

// DecodeLookupHostRequest implements DNSCodec.DecodeLookupHostRequest.
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
	default:
		return nil, ErrDNSServerMisbehaving
	case dns.RcodeSuccess:
		// fallthrough
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
// library http.DefaultHTTPClient matches this interface and also
// HTTPDefaultClient matches this interface.
type DNSOverHTTPSHTTPClient interface {
	// Do should behave like http.Client.Do.
	Do(req *http.Request) (*http.Response, error)
}

// DNSOverHTTPSResolver is a DNS over HTTPS resolver. You MUST NOT
// modify any field of this struct once you've initialized it because
// that MAY likely lead to data races.
type DNSOverHTTPSResolver struct {
	// Client is the optional HTTP client to use. If not set,
	// then we will use HTTPXDefaultClient. (Because we're
	// using by default an HTTPX client, you should be able
	// to use the h3, http3, h2, and http2 schemes when
	// using this resolver by default.)
	Client DNSOverHTTPSHTTPClient

	// Codec is the DNSCodec to use. If not set, then
	// we will use a suitable default DNSCodec.
	Codec DNSCodec

	// OwnsClient indicates whether this struct owns the
	// HTTP Client or not. If it owns the Client, then
	// calling CloseIdleConnections will cause the code
	// to really close idle connections. Otherwise, we
	// assume Client is a shared Client for which we don't
	// want to aggressively close connections.
	OwnsClient bool

	// URL is the mandatory URL of the server. If not set,
	// then this code will certainly fail.
	URL string

	// UserAgent is the User-Agent header to use. If not set,
	// Go standard user agent is used.
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

// roundTrip implements dnsTransport.roundTrip
func (r *DNSOverHTTPSResolver) roundTrip(
	ctx context.Context, query []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", r.URL, bytes.NewReader(query))
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
		log.Printf("dns: the server did not set the right content type")
	}
	return ioutil.ReadAll(resp.Body)
}

// client returns the DNSOverHTTPSClient to use.
func (r *DNSOverHTTPSResolver) client() DNSOverHTTPSHTTPClient {
	if r.Client != nil {
		return r.Client
	}
	return HTTPXDefaultClient
}

// CloseIdleConnections closes idle connections.
func (r *DNSOverHTTPSResolver) CloseIdleConnection() {
	// We only close the idle connections if we own the Client, otherwise we
	// don't want to aggressively kill connections.
	if r.OwnsClient {
		if c, ok := r.client().(DNSIdleConnectionsCloser); ok {
			c.CloseIdleConnections()
		}
	}
}

// dnsTransport is a DNS transport.
type dnsTransport interface {
	// roundTrip performs the DNS round trip.
	roundTrip(ctx context.Context, data []byte) ([]byte, error)
}

// dnsGenericResolver is a generic resolver.
type dnsGenericResolver struct {
	codec   DNSCodec     // mandatory
	padding bool         // optional
	t       dnsTransport // mandatory
}

// dnsLookupHostResult is the result of a lookupHost operation.
type dnsLookupHostResult struct {
	addrs []string
	err   error
}

// LookupHost performs a LookupHost operation.
func (r *dnsGenericResolver) LookupHost(
	ctx context.Context, hostname string) ([]string, error) {
	resA, resAAAA := make(chan *dnsLookupHostResult), make(chan *dnsLookupHostResult)
	go r.asyncLookupHost(ctx, hostname, dns.TypeA, r.padding, resA)
	// Implementation note: we can make this parallel very easily and it will
	// also be significantly more difficult to debug because the events in the
	// monitor will overlap while the two requests are in progress.
	replyA := <-resA
	go r.asyncLookupHost(ctx, hostname, dns.TypeAAAA, r.padding, resAAAA)
	replyAAAA := <-resAAAA
	if replyA.err != nil && replyAAAA.err != nil {
		return nil, replyA.err
	}
	var addrs []string
	addrs = append(addrs, replyA.addrs...)
	addrs = append(addrs, replyAAAA.addrs...)
	if len(addrs) < 1 {
		// Note: the transport SHOULD NOT do that but the
		// implementation may be broken.
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
