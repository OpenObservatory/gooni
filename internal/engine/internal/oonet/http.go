package oonet

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bassosimone/quic-go"
	"github.com/bassosimone/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/idna"
)

// HTTPSALPN is the ALPN for HTTPS
var HTTPSALPN = []string{"http/1.1", "h2"}

// HTTPMonitor monitors HTTP events. The callbacks MUST NOT
// modify the provided values. Callbacks MAY be called by
// background goroutines and we assume this is fine for the monitor.
type HTTPMonitor interface {
	// OnHTTPRoundTripStart is called before sending the request.
	OnHTTPRoundTripStart(req *http.Request)

	// OnHTTPRoundTripDone is called with the result of sending the
	// request and reading the response headers. In case of error, the
	// resp field will of course be nil (and the err not nil).
	OnHTTPRoundTripDone(req *http.Request, resp *http.Response, err error)
}

// HTTPTransactioner is an HTTP transport that performs
// the HTTP transaction initiated by a request and completed
// by the receipt of a response.
//
// This struct is compatible with several kinds of underlying
// round trippers, including the standard library's one,
// http2, and http3 round trippers: all these round trippers
// work out of the box as the underlying RoundTripper.
//
// The transactioner will also emit the "round trip start",
// and "round trip done" events via the ContextMonitor.
//
// You MUST NOT modify any field of HTTPTransactioner after
// construction because this MAY result in a data race.
type HTTPTransactioner struct {
	// RoundTripper is the underlying http.RoundTripper we
	// should be using. If this is not set, then we'll
	// use the http.DefaultTransport round tripper.
	RoundTripper http.RoundTripper
}

// ErrHTTP is an error occurred inside HTTP code.
type ErrHTTP struct {
	error
}

// Unwrap returns the underlying error.
func (e *ErrHTTP) Unwrap() error {
	return e.error
}

// RoundTrip sends a request and returns the response. All the
// errors returned by this function are ErrHTTP instances.
func (t *HTTPTransactioner) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	ContextMonitor(ctx).OnHTTPRoundTripStart(req)
	resp, err := t.roundTripper().RoundTrip(req)
	if err != nil {
		err = &ErrHTTP{err}
	}
	ContextMonitor(ctx).OnHTTPRoundTripDone(req, resp, err)
	return resp, err
}

// roundTripper returns the http.RoundTripper to use.
func (t *HTTPTransactioner) roundTripper() http.RoundTripper {
	if t.RoundTripper != nil {
		return t.RoundTripper
	}
	return http.DefaultTransport
}

// httpCloseIdleConnectioner is any transport allowing one
// to close the idle connections like the stdlib does.
type httpCloseIdleConnectioner interface {
	CloseIdleConnections()
}

// CloseIdleConnection closes idle connections.
func (t *HTTPTransactioner) CloseIdleConnections() {
	if c, ok := t.RoundTripper.(httpCloseIdleConnectioner); ok { // http & http2
		c.CloseIdleConnections()
		return
	}
	if c, ok := t.RoundTripper.(io.Closer); ok { // http3
		c.Close()
		return
	}
}

// HTTPTransportDialer is the Dialer used by HTTP
// transports. It should behave like Dialer.
type HTTPTransportDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	DialTLSContext(ctx context.Context, network, address string) (net.Conn, error)
}

// HTTPStandardTransport is a transport that uses
// the HTTP facilities in the stdlib. This transport
// will use an instance of HTTPTransactioner as the
// underlying transport. In turn, the HTTPTransactioner
// will use an http.Transport instance.
//
// The underlying transport is created the first
// time you issue an HTTP request.
//
// You MUST NOT modify any field of HTTPStandardtransport after
// construction because this MAY result in a data race.
type HTTPStandardTransport struct {
	// NewDialer is an optional factory for constructing the dialer to be
	// used by the transport. This function is called AT MOST
	// once over the lifecycle of HTTPStandardTransport. If not
	// set, then we construct a default Dialer.
	//
	// If you are creating a custom Dialer, you SHOULD set
	// the expected ALPN to be equal to HTTPSALPN.
	//
	// Also, a custom Dialer should have timeouts set for the
	// read and write operations, so we avoid stuck connections
	// in censored networks that inject that otherwise may
	// cause the same connections to stuck forever.
	//
	// If this factory is not set, then we use a default factory.
	NewDialer func() HTTPTransportDialer

	// NewTransport is the optional function for constructing
	// a new transport. If not set, we use a default that
	// constructs a new http.Transport instance. This function
	// is called AT MOST once in the transport lifetime.
	NewTransport func(d HTTPTransportDialer) http.RoundTripper

	// mu protects this structure.
	mu sync.Mutex

	// tw is an HTTPTransactioner wrapping the real transport.
	tw *HTTPTransactioner
}

// RoundTrip sends a request and returns the response. This function will
// construct the underlying transport on first use.
func (t *HTTPStandardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock() // no races
	if t.tw == nil {
		t.tw = &HTTPTransactioner{
			RoundTripper: t.newTransport(t.newDialer()),
		}
	}
	t.mu.Unlock()
	return t.tw.RoundTrip(req)
}

// newTransport creates a new transport.
func (t *HTTPStandardTransport) newTransport(d HTTPTransportDialer) http.RoundTripper {
	if t.NewTransport != nil {
		return t.NewTransport(d)
	}
	return &http.Transport{
		DialContext:            d.DialContext,
		DialTLSContext:         d.DialTLSContext,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 1 << 22, // feels enough
		ForceAttemptHTTP2:      true,
	}
}

// newDialer returns the Dialer to use.
func (t *HTTPStandardTransport) newDialer() HTTPTransportDialer {
	if t.NewDialer != nil {
		return t.NewDialer()
	}
	// Make sure we use the expected ALPN value. Also set a
	// timeout so connections are not stuck in cases where
	// packet injection otherwise totally stucks them.
	return &Dialer{
		ALPN: HTTPSALPN,
		TCPConnector: &TCPConnector{
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
	}
}

// CloseIdleConnections closes the idle connections.
func (t *HTTPStandardTransport) CloseIdleConnections() {
	t.mu.Lock() // avoid races when accessing tw
	tw := t.tw
	t.mu.Unlock()
	if tw != nil {
		tw.CloseIdleConnections()
	}
}

// HTTPDefaultClient is the default HTTP Client. This client uses
// as a transport an instance of HTTPStandardTransport.
var HTTPDefaultClient = &http.Client{Transport: &HTTPStandardTransport{}}

// HTTP3TransportDialer is the Dialer used by HTTP3
// transports. It should behave like Dialer.
type HTTP3TransportDialer interface {
	DialQUIC(ctx context.Context, address string) (quic.EarlySession, error)
}

// HTTP3StandardTransport is a transport that uses
// the HTTP3 facilities in the quic-go lib. This transport
// will use an instance of HTTPTransactioner as the
// underlying transport. In turn, the HTTPTransactioner
// will use an http3.Transport instance.
//
// The underlying transport is created the first
// time you issue an HTTP request.
//
// You MUST NOT modify any field of HTTP3Standardtransport after
// construction because this MAY result in a data race.
type HTTP3StandardTransport struct {
	// NewDialer is the optional factory for constructing the dialer to be
	// used by the transport. This function is called once
	// for every connection that we setup. This happens because
	// we need to configure the new dialer with tlsConf and quicConf.
	//
	// If this factory is not set, then we use a default factory.
	NewDialer func(tlsConf *tls.Config, quicConf *quic.Config) HTTP3TransportDialer

	// NewTransport is the optional function for constructing
	// a new transport. If not set, we use a default that
	// constructs a new http3.Transport instance. This function
	// is called AT MOST once in the transport lifetime.
	NewTransport func() *http3.RoundTripper

	// mu protects this structure.
	mu sync.Mutex

	// tw is an HTTPTransactioner wrapping the real transport.
	tw *HTTPTransactioner
}

// RoundTrip sends a request and returns the response. This function will
// construct the underlying transport on first use.
func (t *HTTP3StandardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock() // no races
	if t.tw == nil {
		t.tw = &HTTPTransactioner{
			RoundTripper: t.newTransport(),
		}
	}
	t.mu.Unlock()
	return t.tw.RoundTrip(req)
}

// newTransport creates a new transport.
func (t *HTTP3StandardTransport) newTransport() *http3.RoundTripper {
	if t.NewTransport != nil {
		return t.NewTransport()
	}
	return &http3.RoundTripper{
		Dial: func(ctx context.Context, network, address string,
			tlsConf *tls.Config, quicConf *quic.Config) (quic.EarlySession, error) {
			// Note that the default configuration for QUIC sets a
			// an idle timeout of 30 seconds so we know that we will
			// eventually see the connections become unstuck also
			// in case there's heavy interference.
			dialer := t.newDialer(tlsConf, quicConf)
			return dialer.DialQUIC(ctx, address)
		},
		DisableCompression:     true,
		MaxResponseHeaderBytes: 1 << 22, // feels enough
	}
}

// newDialer returns the Dialer to use.
func (t *HTTP3StandardTransport) newDialer(
	tlsConf *tls.Config, quicConf *quic.Config) HTTP3TransportDialer {
	if t.NewDialer != nil {
		return t.NewDialer(tlsConf, quicConf)
	}
	// make sure we use the expected SNI and ALPN value
	return &Dialer{TLSConfig: tlsConf, QUICConfig: quicConf}
}

// CloseIdleConnections closes the idle connections.
func (t *HTTP3StandardTransport) CloseIdleConnections() {
	t.mu.Lock() // avoid races when accessing tw
	tw := t.tw
	t.mu.Unlock()
	if tw != nil {
		tw.CloseIdleConnections()
	}
}

// HTTP3DefaultClient is the default HTTP3 Client. This client uses
// as a transport an instance of HTTP3StandardTransport.
var HTTP3DefaultClient = &http.Client{Transport: &HTTP3StandardTransport{}}

// HTTP2ParrotTransport is a transport that uses
// the HTTP2 facilities in the golang.org/x library and the
// parroting functionality of utls. This transport
// will use an instance of HTTPTransactioner as the
// underlying transport. In turn, the HTTPTransactioner
// will use an http.Transport instance.
//
// The underlying transport is created the first
// time you issue an HTTP request.
//
// You MUST NOT modify any field of HTTP2ParrotTransport after
// construction because this MAY result in a data race.
//
// This transport WILL NOT work with servers that do not
// support HTTP2 and WILL NOT work with some legit
// HTTP2 servers. This occurs due to instrinsic limitations
// in the refraction-networking/utls parrot library.
type HTTP2ParrotTransport struct {
	// NewDialer is an optional factory for constructing the dialer to be
	// used by the transport. This function is called AT MOST
	// once over the lifecycle of HTTPStandardTransport. If not
	// set, then we construct a suitable parroting Dialer.
	//
	// If you are creating a custom Dialer, you SHOULD set
	// the expected ALPN to be equal to HTTPSALPN. You SHOULD
	// also configure the proper parroting handshaker.
	//
	// Also, remember to set timeouts for connections when
	// using a default dialer, because we've seen cases
	// where they were totally stuck in censored networks.
	//
	// If this factory is not set, then we use a default factory.
	NewDialer func() HTTPTransportDialer

	// NewTransport is the optional function for constructing
	// a new transport. If not set, we use a default that
	// constructs a new http.Transport instance. This function
	// is called once for every new connection we make.
	NewTransport func() http.RoundTripper

	// conncache contains the conns cache.
	conncache map[string]net.Conn

	// twmu protects this structure.
	mu sync.Mutex

	// tw is an HTTPTransactioner wrapping the real transport.
	tw *HTTPTransactioner
}

// errHTTP2ParrotNoCachedConn indicates we don't have
// any cached connection we could use. This error should
// be internal because the HTTP2ParrotTransport will
// try connecting until the context is done.
var errHTTP2ParrotNoCachedConn = errors.New("oonet: http2: no cached conn")

// RoundTrip sends a request and returns the response. This function will
// construct the underlying transport on first use.
func (t *HTTP2ParrotTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock() // no races
	if t.tw == nil {
		t.tw = &HTTPTransactioner{
			RoundTripper: t.newTransport(),
		}
	}
	t.mu.Unlock()
	ctx := req.Context()
	for {
		select {
		case <-ctx.Done():
			return nil, &ErrHTTP{ctx.Err()}
		default:
			// fallthrough
		}
		resp, err := t.tw.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		if !errors.Is(err, errHTTP2ParrotNoCachedConn) {
			return nil, err // should be wrapped
		}
		if err := t.connCacheDial(ctx, req.URL); err != nil {
			return nil, &ErrHTTP{err}
		}
	}
}

// newTransport creates a new transport.
func (t *HTTP2ParrotTransport) newTransport() http.RoundTripper {
	if t.NewTransport != nil {
		return t.NewTransport()
	}
	return &http2.Transport{
		DialTLS:            t.connCacheGet,
		DisableCompression: true,
	}
}

// newDialer returns the Dialer to use.
func (t *HTTP2ParrotTransport) newDialer() HTTPTransportDialer {
	if t.NewDialer != nil {
		return t.NewDialer()
	}
	// Make sure we use the expected ALPN value and that we
	// configure the parroting TLS library. (The ALPN we use
	// does not matter much probably, since it should be
	// overwritten by the parrot library.)
	//
	// Make also sure we have some timeout just in case
	// packet inject stucks our conns.
	return &Dialer{
		ALPN: HTTPSALPN,
		TCPConnector: &TCPConnector{
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
		TLSHandshaker: &TLSHandshaker{
			Library: &TLSParrotLibrary{},
		},
	}
}

// CloseIdleConnections closes the idle connections.
func (t *HTTP2ParrotTransport) CloseIdleConnections() {
	t.mu.Lock() // avoid races when accessing tw
	tw := t.tw
	t.mu.Unlock()
	if tw != nil {
		tw.CloseIdleConnections()
	}
	t.connCacheCleanup() // does locking
}

// errHTTP2ProtocolNegotiation indicates that protocol negotiation
// failed and we're now speaking HTTP/1.1.
var errHTTP2ProtocolNegotiation = errors.New("oonet: ALPN failed: http/1.1 was selected")

// ErrHTTP2ParrotMissingTLSFeature indicates that we detected
// that the server sent us some handshake message that we cannot
// handle, so we must interrupt the handshake.
var ErrHTTP2ParrotMissingTLSFeature = errors.New(
	"oonet: parrot failed because of missing TLS features")

// connCacheDial dials a new connection using the information inside
// of URL.Host and, on success, saves the connection in cache.
func (t *HTTP2ParrotTransport) connCacheDial(ctx context.Context, URL *url.URL) error {
	endpoint := t.makeEndpoint(URL.Host)
	d := t.newDialer()
	// We need to call the dialer here and use the conncache such that
	// it's possible to propagate the Monitor via the context.
	conn, err := d.DialTLSContext(ctx, "tcp", endpoint)
	if err != nil {
		if strings.HasSuffix(err.Error(), "tls: unexpected message") {
			return ErrHTTP2ParrotMissingTLSFeature
		}
		return err
	}
	if !t.correctProtocol(conn) {
		return errHTTP2ProtocolNegotiation
	}
	defer t.mu.Unlock()
	t.mu.Lock()
	if t.conncache == nil {
		t.conncache = make(map[string]net.Conn)
	}
	t.conncache[endpoint] = conn
	return nil
}

// correctProtocol indicates whether the protocol negotiated
// with the server is the correct protocol.
func (t *HTTP2ParrotTransport) correctProtocol(conn net.Conn) bool {
	c, ok := conn.(TLSConn)
	if !ok {
		return false // this seems a bit unexpected TBH
	}
	proto := c.ConnectionState().NegotiatedProtocol
	return proto == "h2"
}

// makeEndpoint constructs an endpoint to connect to from the
// value contained inside of the URL.Host field.
func (t *HTTP2ParrotTransport) makeEndpoint(address string) string {
	// Adapted from x/net/http2/transport.go
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host, port = address, "443"
	}
	if conv, err := idna.ToASCII(host); err == nil {
		host = conv
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host + ":" + port
	}
	return net.JoinHostPort(host, port)
}

// connCacheGet gets a connection from the cache. If there
// is no connection inside the cache, this function will
// return the errHTTP2ParrotNoCachedConn error.
//
// A limitation of this implementation is that we ignore
// the config argument because we dial elsewhere. But this
// should't be a problem in typical usage.
func (t *HTTP2ParrotTransport) connCacheGet(
	network, address string, config *tls.Config) (net.Conn, error) {
	defer t.mu.Unlock()
	t.mu.Lock()
	conn, found := t.conncache[address]
	if !found {
		return nil, errHTTP2ParrotNoCachedConn
	}
	delete(t.conncache, address)
	return conn, nil // transfers ownership
}

// connCacheCleanup closes all the cached connections.
func (t *HTTP2ParrotTransport) connCacheCleanup() {
	defer t.mu.Unlock()
	t.mu.Lock()
	for _, conn := range t.conncache {
		conn.Close()
	}
	t.conncache = nil
}

// HTTP2DefaultParrotClient is the default client that uses
// parroting to imitate the TLS ClientHello of a recent
// version of Google Chrome. This client WILL NOT handle
// HTTP/1.1 request. What's more, it MAY fail with some HTTP2
// servers when some TLS features that they advertise are
// not supported by the parroting library.
var HTTP2DefaultParrotClient = &http.Client{Transport: &HTTP2ParrotTransport{}}

// ErrHTTPBodyTruncated indicates that the body is truncated.
var ErrHTTPBodyTruncated = errors.New("oonet: HTTP body was truncated")

// HTTPBodyReadAll reads the whole body in a
// background goroutine. This function will return
// earlier if the context is cancelled. In which case
// we will continue reading the body from a background
// goroutine, and we will discard the result.
//
// The maximum acceptable body size is controlled
// using the limit argument. If we read more
// than the specified number of bytes, then we
// will return ErrHTTPBodyTruncated. If limit
// is zero or negative we'll use a default value
// for the maximum body size.
//
// The expectEOF argument indicates whether we
// except the body to terminate by EOF. This
// should copied from the response.Close
// argument. If we expect EOF, then we'll
// tolerate io.EOF when reading.
//
// All the code that reads HTTP response bodies
// in OONI SHOULD be using this facility. We have
// seen censored networks where not doing this
// causes the probe to block forever.
func HTTPBodyReadAll(ctx context.Context,
	body io.Reader, limit int64, expectEOF bool) ([]byte, error) {
	datach, errch := make(chan []byte, 1), make(chan error, 1) // buffers
	const maxBodySize = 1 << 20
	if limit <= 0 {
		limit = maxBodySize
	}
	go func(body io.Reader, limit int64) {
		r := io.LimitReader(body, limit)
		data, err := ioutil.ReadAll(r)
		if expectEOF && errors.Is(err, io.EOF) {
			err = nil // we expected EOF so it's not an error
		}
		if err != nil {
			errch <- err
			return
		}
		if int64(len(data)) >= limit {
			errch <- ErrHTTPBodyTruncated
			return
		}
		datach <- data
	}(body, limit)
	select {
	case data := <-datach:
		return data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errch:
		return nil, err
	}
}
