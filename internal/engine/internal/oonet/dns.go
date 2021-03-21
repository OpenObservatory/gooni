package oonet

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNSQuery is a query we want to send. When this struct is passed
// to DNSMonitor.OnDNSSendQuery, all its fields will be initialized
// (i.e. they will not be nil).
type DNSQuery struct {
	// Msg is the message from which we serialized the query.
	Msg *dns.Msg

	// Type is the query type.
	Type uint16

	// Raw contains the serialized query.
	Raw []byte
}

// DNSReply is a reply we just received. When this struct is passed
// to DNSMonitor.OnDNSRecvReply, all the fiels will be initialized
// (i.e. they will not be nil).
type DNSReply struct {
	// Msg is the message we have parsed.
	Msg *dns.Msg

	// Query is the original query.
	Query *DNSQuery

	// Raw is the payload from which we parsed msg.
	Raw []byte
}

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
	OnDNSSendQuery(query *DNSQuery)

	// OnDNSRecvReply is called when we receive a well formed
	// reply. The argument is a serialized user friendly version
	// of the reply.
	OnDNSRecvReply(reply *DNSReply)
}

// DNSTransport is a DNS transport. The job of a transport
// is to send a query (as a bag of bytes) and implement the
// proper protocol (e.g. DoH) to read the bytes that will
// possibly correspond to a DNS reply.
//
// If a DNSTransport is not able to deal with concurrent
// DNS round trips, then is should use locking to prevent
// more than one concurrent round trip at a time.
//
// Implementations of DNSTransport SHOULD honour the
// context and return immediately when it has been cancelled.
type DNSTransport interface {
	// RoundTrip performs the DNS round trip.
	RoundTrip(ctx context.Context, query *DNSQuery,
		codec DNSCodec) (*DNSReply, error)

	// Padding returns true if we need padding.
	Padding() bool

	// CloseIdleConnections closes idle connections.
	CloseIdleConnections()
}

// DNSResolver is the DNS resolver. Its main job is to emit
// events and to ensure returned errors are wrapped.
//
// The DNSResolver takes an optional DNSTransport. If the
// DNSTransport is nil, we use the net.Resolver. Otherwise,
// we will send the queries over using the DNSTransport
// and return to you the replies we received.
//
// The DNSResolver's CloseIdleConnections method allows
// closing idle connections in the DNSTransport.
//
// You MUST NOT modify any field of Resolver after construction
// because this MAY result in a data race.
type DNSResolver struct {
	// Transport is the optional DNSTransport. If not
	// set will will use the stdlib.
	Transport DNSTransport

	// Codec is the optional DNSCodec. If not set then
	// we will use the default DNS codec.
	Codec DNSCodec
}

// ErrLookupHost is an error occurring during a LookupHost operation.
type ErrLookupHost struct {
	error
}

// Unwrap yields the underlying error.
func (e *ErrLookupHost) Unwrap() error {
	return e.error
}

// CloseIdleConnections closes idle connections
// in the underlying DNSTransport. If there's no
// DNSTransport, this function is a no-op.
func (r *DNSResolver) CloseIdleConnections() {
	if r.Transport != nil {
		r.Transport.CloseIdleConnections()
	}
}

// LookupHost maps a hostname to a list of IP addresses. If the
// input hostname is an IP address, then this function will return
// immediately WITHOUT emitting any DNS events.
func (r *DNSResolver) LookupHost(
	ctx context.Context, hostname string) ([]string, error) {
	if net.ParseIP(hostname) != nil {
		return []string{hostname}, nil
	}
	ContextMonitor(ctx).OnDNSLookupHostStart(hostname)
	addrs, err := r.doLookupHost(ctx, hostname)
	if err != nil {
		err = &ErrLookupHost{err}
	}
	ContextMonitor(ctx).OnDNSLookupHostDone(hostname, addrs, err)
	return addrs, err
}

// doLookupHost uses the underlying transport, if any, and
// otherwise falls back to the system resolver.
func (r *DNSResolver) doLookupHost(
	ctx context.Context, hostname string) ([]string, error) {
	if r.Transport != nil {
		return r.lookupHostWithTransport(ctx, hostname)
	}
	return (&net.Resolver{}).LookupHost(ctx, hostname)
}

// DNSCodec encodes and decodes DNS messages. In addition to
// marshalling and unmarshalling, this data structure will also
// emit an event every time we successfully marshal a query
// and every time we successfully unmarshal a reply.
type DNSCodec interface {
	// EncodeLookupHostQuery encodes a LookupHost query.
	EncodeLookupHostQuery(
		domain string, qtype uint16, padding bool) (*DNSQuery, error)

	// DecodeReply decodes a DNS reply.
	DecodeReply(data []byte) (*dns.Msg, error)
}

// dnsMiekgCodec is a DNSCodec using miekg/dns. This is the
// codec used by default by this library.
type dnsMiekgCodec struct{}

// EncodeLookupHostQuery implements DNSCodec.EncodeLookupHostQuery.
func (c *dnsMiekgCodec) EncodeLookupHostQuery(domain string,
	qtype uint16, padding bool) (*DNSQuery, error) {
	const (
		// blockSize is the size that the padded
		// query should be multiple of
		blockSize = 128
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
		// work as intended when the desired block size's smaller
		// than (query.Len()+4) ¯\_(ツ)_/¯.
		remainder := (blockSize - uint(query.Len()+4)) % blockSize
		opt := new(dns.EDNS0_PADDING)
		opt.Padding = make([]byte, remainder)
		query.IsEdns0().Option = append(query.IsEdns0().Option, opt)
	}
	raw, err := query.Pack()
	if err != nil {
		return nil, err
	}
	out := &DNSQuery{Msg: query, Type: qtype, Raw: raw}
	return out, nil
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

// DecodeReply implements DNSCodec.DecodeReply.
func (c *dnsMiekgCodec) DecodeReply(data []byte) (*dns.Msg, error) {
	reply := new(dns.Msg)
	if err := reply.Unpack(data); err != nil {
		return nil, err
	}
	return reply, nil
}

// RcodeToError converts the reply Rcode to the proper DNS error.
func (r *DNSReply) RcodeToError() error {
	switch r.Msg.Rcode {
	case dns.RcodeNameError:
		return ErrDNSNoSuchHost
	case dns.RcodeServerFailure:
		return ErrDNSServerTemporarilyMisbehaving
	case dns.RcodeSuccess:
		return nil
	default:
		return ErrDNSServerMisbehaving
	}
}

// AnswerToLookupHostResult converts the answer into
// the result expected by LookupHost.
func (r *DNSReply) AnswerToLookupHostResult() ([]string, error) {
	var addrs []string
	for _, answer := range r.Msg.Answer {
		switch r.Query.Type {
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

// lookupHostWithTransport performs a LookupHost operation
// using the configured DNSTransport.
func (r *DNSResolver) lookupHostWithTransport(
	ctx context.Context, hostname string) ([]string, error) {
	resA, resAAAA := make(chan *dnsLookupHostResult), make(chan *dnsLookupHostResult)
	go r.runLookupHostWithTransport(
		ctx, hostname, dns.TypeA, r.Transport.Padding(), resA)
	// Implementation note: we can make this parallel very easily and it will
	// also be significantly more difficult to debug because the events in the
	// monitor will overlap while the two requests are in progress.
	// Also note that we don't honour the context because it's the job
	// of the transport to react to context cancellation.
	replyA := <-resA
	go r.runLookupHostWithTransport(
		ctx, hostname, dns.TypeAAAA, r.Transport.Padding(), resAAAA)
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

// runLookupHostWithTransport is the goroutine that performs the
// lookup host operation using the configured transport.
func (r *DNSResolver) runLookupHostWithTransport(
	ctx context.Context, hostname string, qtype uint16, padding bool,
	resch chan<- *dnsLookupHostResult) {
	query, err := r.codec().EncodeLookupHostQuery(hostname, qtype, padding)
	if err != nil {
		resch <- &dnsLookupHostResult{err: err}
		return
	}
	ContextMonitor(ctx).OnDNSSendQuery(query)
	reply, err := r.Transport.RoundTrip(ctx, query, r.codec())
	if err != nil {
		resch <- &dnsLookupHostResult{err: err}
		return
	}
	ContextMonitor(ctx).OnDNSRecvReply(reply)
	if err := reply.RcodeToError(); err != nil {
		resch <- &dnsLookupHostResult{err: err}
		return
	}
	addrs, err := reply.AnswerToLookupHostResult()
	resch <- &dnsLookupHostResult{addrs: addrs, err: err}
}

// codec returns the DNSCodec to use.
func (r *DNSResolver) codec() DNSCodec {
	if r.Codec != nil {
		return r.Codec
	}
	return &dnsMiekgCodec{}
}

// DNSOverHTTPSHTTPClient is the HTTP client to use. The standard
// library http.DefaultHTTPClient matches this interface.
type DNSOverHTTPSHTTPClient interface {
	// Do should behave like http.Client.Do.
	Do(req *http.Request) (*http.Response, error)

	// CloseIdleConnections should behave
	// like http.Client.CloseIdleConnections.
	CloseIdleConnections()
}

// DNSOverHTTPSTransport is a DNS over HTTPS transport. You MUST NOT
// modify any field of this struct once you've initialized it because
// that MAY likely lead to data races.
//
// The DNSOverHTTPSTransport owns the underlying HTTP client and
// will close its idle connections on CloseIdleConnections.
//
// This transport will perform the DNS round trip (sending a query
// and receiving a reply) in a background goroutine. If the context
// expires before that operation is complete, this transport will
// leak such a goroutine and return early. A well behaved HTTP client
// should be configured such that any I/O operation will eventually
// timeout. So, if you are using a well behaved HTTP client with
// this transport, then goroutine leak will be temporary.
type DNSOverHTTPSTransport struct {
	// Client is the optional HTTP client to use. If not set,
	// then we will use DNSOverHTTPSDefaultHTTPClient.
	Client DNSOverHTTPSHTTPClient

	// URL is the mandatory URL of the server. If not set,
	// then this code will certainly fail.
	URL string

	// UserAgent is the optional User-Agent header to use. If not
	// set, Golang's standard user agent is used.
	UserAgent string
}

// CloseIdleConnections implements DNSTransport.CloseIdleConnections.
func (r *DNSOverHTTPSTransport) CloseIdleConnections() {
	r.client().CloseIdleConnections()
}

// Padding implements DNSTransport.Padding.
func (r *DNSOverHTTPSTransport) Padding() bool {
	return true
}

// RoundTrip implements DNSTransport.RoundTrip. This function
// will read the body in a background goroutine such that we're
// able to immediately react to the context being cancelled.
func (r *DNSOverHTTPSTransport) RoundTrip(ctx context.Context,
	query *DNSQuery, codec DNSCodec) (*DNSReply, error) {
	req, err := http.NewRequestWithContext(
		ctx, "POST", r.URL, bytes.NewReader(query.Raw))
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
	const maxBodySize = 1 << 20
	data, err := HTTPBodyReadAll(ctx, resp.Body, maxBodySize, resp.Close)
	if err != nil {
		return nil, err
	}
	replyMsg, err := codec.DecodeReply(data)
	if err != nil {
		return nil, err
	}
	return &DNSReply{Msg: replyMsg, Query: query, Raw: data}, nil
}

// DNSOverHTTPSDefaultHTTPClient is the default HTTP
// client used by DNS over HTTPS.
var DNSOverHTTPSDefaultHTTPClient = &http.Client{Transport: &HTTPXTransport{}}

// client returns the DNSOverHTTPSClient to use.
func (r *DNSOverHTTPSTransport) client() DNSOverHTTPSHTTPClient {
	if r.Client != nil {
		return r.Client
	}
	return DNSOverHTTPSDefaultHTTPClient
}

// NewDNSOverUDPTransport creates a new DNS-over-UDP DNSTransport
// using a suitably-configured DNSOverConnTransport.
func NewDNSOverUDPTransport(address string) *DNSOverConnTransport {
	return &DNSOverConnTransport{
		Address: address,
		Dial:    (&Dialer{}).DialContext,
		Network: "udp",
	}
}

// NewDNSOverTCPTransport creates a new DNS-over-TCP DNSTransport
// using a suitably-configured DNSOverConnTransport.
func NewDNSOverTCPTransport(address string) *DNSOverConnTransport {
	return &DNSOverConnTransport{
		Address: address,
		Dial:    (&Dialer{}).DialContext,
		Network: "tcp",
	}
}

// DNSOverTLSALPN is the ALPN used for DNS-over-TLS.
var DNSOverTLSALPN = []string{"dot"}

// NewDNSOverTLSTransport creates a new DNS-over-TLS DNSTransport
// using a suitably-configured DNSOverConnTransport.
func NewDNSOverTLSTransport(address string) *DNSOverConnTransport {
	return &DNSOverConnTransport{
		Address: address,
		Dial:    (&Dialer{ALPN: DNSOverTLSALPN}).DialTLSContext,
		Network: "tls",
	}
}

// dnsStreamer streams DNS queries and destreams replies. The way
// to do that depends on whether we're using an underlying datagram
// or stream connection. The main job of implementations of this
// interface would therefore be to properly stream/destream.
// An implementation of dnsStream MUST only Read or Write the
// connection and MUST NOT attempt to Close it.
type dnsStreamer interface {
	// Stream streams the specified query over conn.
	Stream(conn net.Conn, query []byte) error

	// Destream destreams a query from the conn.
	Destream(conn net.Conn) ([]byte, error)
}

// dnsStreamerTCPTLS implements dnsStreamer over a TCP/TLS conn.
type dnsStreamerTCPTLS struct{}

// errDNSStreamerQueryTooLarge means that the query is too large.
var errDNSStreamerQueryTooLarge = errors.New("oonet: query too large")

// stream implements dnsStreamer.Stream.
func (s *dnsStreamerTCPTLS) Stream(conn net.Conn, query []byte) error {
	if len(query) > math.MaxUint16 {
		return errDNSStreamerQueryTooLarge
	}
	buf := []byte{byte(len(query) >> 8)}
	buf = append(buf, byte(len(query)))
	buf = append(buf, query...)
	_, err := conn.Write(buf)
	return err
}

// Destream implements dnsStreamer.Destream.
func (s *dnsStreamerTCPTLS) Destream(conn net.Conn) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := int(header[0])<<8 | int(header[1])
	reply := make([]byte, length)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// dnsStreamerUDP implements dnsStreamer over a UDP conn.
type dnsStreamerUDP struct{}

// Stream implements dnsStreamer.Stream.
func (s *dnsStreamerUDP) Stream(conn net.Conn, query []byte) error {
	_, err := conn.Write(query)
	return err
}

// Destream implements dnsStreamer.Destream.
func (s *dnsStreamerUDP) Destream(conn net.Conn) ([]byte, error) {
	reply := make([]byte, 1<<17)
	count, err := conn.Read(reply)
	if err != nil {
		return nil, err
	}
	return reply[:count], nil
}

// dnsOverConnPendingQuery is a pending query for DNSOverConnTransport.
type dnsOverConnPendingQuery struct {
	// query is the original query. This field is set
	// by DNSOverConnTransport.RoundTrip.
	query *DNSQuery

	// reply is the reply. This field is set by the
	// dnsOverConnWorker before closing done.
	reply *dns.Msg

	// rawReply is the raw reply. This field is set by the
	// dnsOverConnWorker before closing done.
	rawReply []byte

	// done is the channel to signal completion. This field
	// is created by DNSOverConnTransport.RoundTrip and is
	// closed by dnsOverConnWorker when we have a reply.
	done chan interface{}
}

// dnsOverConnState keeps the state of DNSOverConnTransport. The
// state is shared between DNSOverConnTransport and dnsOverConnWorker.
type dnsOverConnState struct {
	// mu provides synchronized access. This field
	// does not require any initialization.
	mu sync.Mutex

	// pending contains the pending queries. The user MUST
	// ensure that this field is initialized before attempting
	// to store a dnsOverConnPendingQuery into it. If not,
	// the caller MUST initialize it. Also, any access to this
	// field MUST be under the protection of the mutex.
	pending map[uint16]*dnsOverConnPendingQuery
}

// dnsOverConnWorker runs in a background goroutine and reads
// incoming DNS replies. Whenever it finds a new reply, the
// worker will update the shared state. To terminate a worker,
// call its close method, which will shut it down.
type dnsOverConnWorker struct {
	// codec is the DNSCodec to use.
	codec DNSCodec

	// conn is the connection we're using.
	conn net.Conn

	// state is the shared state.
	state *dnsOverConnState

	// streamer is the streamer we should use.
	streamer dnsStreamer
}

// reader runs the dnsOverConnWorker read loop.
func (w *dnsOverConnWorker) reader() {
	for {
		rawReply, err := w.streamer.Destream(w.conn)
		if err != nil {
			w.conn.Close() // possibly redundant and thread safe
			return
		}
		reply, err := w.codec.DecodeReply(rawReply)
		if err != nil {
			continue
		}
		w.state.mu.Lock()
		if pq, found := w.state.pending[reply.Id]; found {
			// because the RoundTrip may not be waiting anymore, we
			// need to cleanup the pending state in advance.
			delete(w.state.pending, reply.Id)
			pq.reply = reply
			pq.rawReply = rawReply
			close(pq.done) // synchronize with the waiter (if any)
		}
		w.state.mu.Unlock()
	}
}

// write uses the connection to send a query. This method takes a
// timeout argument such that we will not know that we cannot really
// use this worker for sending a query and we need a new worker.
func (c *dnsOverConnWorker) write(rawQuery []byte, timeout time.Duration) error {
	c.conn.SetWriteDeadline(time.Now().Add(timeout))
	defer c.conn.SetWriteDeadline(time.Time{})
	if err := c.streamer.Stream(c.conn, rawQuery); err != nil {
		c.conn.Close() // possibly redundant and thread safe
		return err
	}
	return nil
}

// close closes the underlying connection.
func (c *dnsOverConnWorker) close() {
	c.conn.Close() // possibly redundant and thread safe
}

// DNSOverConnTransport is a transport that operates using
// TLS, TCP, and UDP connections. It will create a worker
// running in the background that monitors a connection of
// the proper type to the selected DNS server.
//
// The CloseIdleConnection method allows you to shutdown the
// background worker if there are no pending queries. The
// worker will created on demand, when there is no already
// running worker. There will be AT MOST one worker for
// each instance of DNSOverConnTransport.
//
// After initialization, you MUST NOT change any field of this
// structure, because this MAY lead to data races.
type DNSOverConnTransport struct {
	// Address is the address of the server. You MUST set
	// this field, otherwise the transport will fail.
	Address string

	// codec is the optional codec to use. If not set, we
	// will the default miekg/dns codec.
	codec DNSCodec

	// Dial is the dialing factory. You MUST set this field
	// to either a cleartext connection dialer or to a TLS
	// aware connection dialer. When configuring the dialer
	// for DoT, make sure you set the ALPN.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	// Network is the network of the server. You MUST set
	// this field to one of "tls", "tcp", and "udp".
	Network string

	// mu protects this data structure. This field does
	// not require any explicit initialization.
	mu sync.Mutex

	// state is the shared state. This field will be
	// automatically created on first use.
	state *dnsOverConnState

	// worker is the background worker. This field will
	// be created every time it is needed.
	worker *dnsOverConnWorker
}

// Padding implements DNSTransport.Padding. We will return that
// we need padding if and only if Network is equal to "tls".
func (t *DNSOverConnTransport) Padding() bool {
	return t.Network == "tls"
}

// CloseIdleConnections implements DNSTransport.CloseIdleConnections. We
// will tell the underlying worker to shutdown if and only if there are
// currently no pending DNS queries. Otherwise, this function is a no-op.
func (t *DNSOverConnTransport) CloseIdleConnections() {
	defer t.mu.Unlock()
	t.mu.Lock()
	if t.worker != nil && t.state != nil && len(t.state.pending) <= 0 {
		t.worker.close()
		t.worker = nil
	}
}

// ErrDNSQueryTimeout indicates that a DNS query timed out.
var ErrDNSQueryTimeout = errors.New("oonet: timeout waiting for DNS reply")

// errNoWorker indicates that we don't have a worker.
var errNoWorker = errors.New("oonet: worker is not set")

// RoundTrip implements DNSTransport.RoundTrip. This method will
// start a worker, if necessary. Then it will use the worker to
// send the query and wait for the reply. If no reply is received
// within a certain small timeout, this method will return an
// ErrDNSQueryTimeout to the caller. This method will also fail
// as soon as the context argument is cancelled or times out.
func (t *DNSOverConnTransport) RoundTrip(
	ctx context.Context, query *DNSQuery, codec DNSCodec) (*DNSReply, error) {
	if err := t.write(ctx, query, codec); err != nil {
		return nil, err // cannot send query out
	}
	pq := &dnsOverConnPendingQuery{
		query: query,
		done:  make(chan interface{}, 1), // with buffer!
	}
	t.state.mu.Lock()
	if t.state.pending == nil {
		t.state.pending = make(map[uint16]*dnsOverConnPendingQuery)
	}
	t.state.pending[query.Msg.Id] = pq
	t.state.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second) // query timeout
	defer cancel()
	select {
	case <-ctx.Done():
		t.state.mu.Lock()
		delete(t.state.pending, query.Msg.Id) // cleanup
		t.state.mu.Unlock()
		return nil, ctx.Err()
	case <-pq.done:
		reply := &DNSReply{
			Msg:   pq.reply,
			Query: query,
			Raw:   pq.rawReply,
		}
		return reply, nil
	}
}

// write writes the query using the worker. If there is no worker or
// the current worker is broken, we'll create a new worker.
func (t *DNSOverConnTransport) write(
	ctx context.Context, query *DNSQuery, codec DNSCodec) error {
	t.mu.Lock()
	if err := t.writeWithCurrentWorkerUnlocked(ctx, query, codec); err == nil {
		t.mu.Unlock() // unlock and leave
		return nil
	}
	t.mu.Unlock() // unlock because we want to dial unlocked
	conn, err := t.doDial(ctx)
	if err != nil {
		return err
	}
	t.mu.Lock() // lock again for setting the worker
	defer t.mu.Unlock()
	if t.state == nil {
		t.state = &dnsOverConnState{}
	}
	// Lock may cause a reschedule. So a goroutine that was racing with
	// us for connecting may have overtake us and the writer could already
	// have been set. In such a case, close the connection.
	if t.worker == nil {
		t.worker = &dnsOverConnWorker{
			codec:    t.getCodec(),
			conn:     conn,
			state:    t.state,
			streamer: t.streamer(),
		}
		go t.worker.reader() // all seems good, start reader
	} else {
		conn.Close()
	}
	return t.writeWithCurrentWorkerUnlocked(ctx, query, codec)
}

// writeWithCurrentWorkerUnlocked attempts to write with the
// worker that we are currently using.
func (t *DNSOverConnTransport) writeWithCurrentWorkerUnlocked(
	ctx context.Context, query *DNSQuery, codec DNSCodec) error {
	// The DNSTransport protocol says we should honour the
	// context. Here we're waiting for a few milliseconds
	// and this is not a big deal in terms of stalling OONI.
	const writeTimeout = 10 * time.Millisecond
	if t.worker == nil {
		return errNoWorker
	}
	if err := t.worker.write(query.Raw, writeTimeout); err != nil {
		t.worker.close()
		t.worker = nil
		return err
	}
	return nil
}

// doDial dials a new connection.
func (t *DNSOverConnTransport) doDial(ctx context.Context) (net.Conn, error) {
	network := t.Network
	switch network {
	case "tls":
		network = "tcp" // adjust for connecting using TCP
	}
	// Again, DNSTransportProtocol: we MUST honour the context so
	// we're doing an async dial in a background goroutine.
	return t.doDialAsync(ctx, network, t.Address)
}

// doDialAsync dials in the background so that we do
// not block for too much time if the context is cancelled.
func (t *DNSOverConnTransport) doDialAsync(ctx context.Context,
	network, address string) (net.Conn, error) {
	connch, errch := make(chan net.Conn), make(chan error, 1)
	go func() {
		conn, err := t.Dial(ctx, network, address)
		if err != nil {
			errch <- err // buffered chan
			return
		}
		select {
		case connch <- conn:
		default:
			conn.Close() // the context has won
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case conn := <-connch:
		return conn, nil
	case err := <-errch:
		return nil, err
	}
}

// getCodec returns a suitable DNSCodec.
func (t *DNSOverConnTransport) getCodec() DNSCodec {
	if t.codec != nil {
		return t.codec
	}
	return &dnsMiekgCodec{}
}

// streamer returns a suitable dnsStreamer
func (r *DNSOverConnTransport) streamer() dnsStreamer {
	switch r.Network {
	case "udp":
		return &dnsStreamerUDP{}
	default:
		return &dnsStreamerTCPTLS{}
	}
}
