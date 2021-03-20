package oonet

import (
	"net/http"
	"net/url"
	"sync"
)

// HTTPXCloseableTransport is the kind of transport
// used by the HTTPXTransport transport.
type HTTPXCloseableTransport interface {
	http.RoundTripper
	CloseIdleConnections()
}

// HTTPXTransport is chooses which underlying HTTP
// transport to use depending on the URL schema. This
// is the set of supported schemas:
//
// 1. "http", "https": uses HTTPStandardTransport
// with TLSStandardLibrary;
//
// 2. "h2", "http2": uses HTTP2ParrotTransport
// with TLSParrotLibrary;
//
// 3. "h3", "http3": like h2 except that it uses
// HTTP3StandardTransport.
//
// You MUST NOT change any field of this structure
// after initialization, because this MAY lead to
// data races.
type HTTPXTransport struct {
	// NewStandardTransport is the optional factory for
	// creating a standard transport to use. If unset, we
	// will construct and use a suitable instance. This
	// function will be called AT MOST once.
	NewStandardTransport func() HTTPXCloseableTransport

	// NewParrotTransport is the optional factory for
	// creating a parroting transport to use. If unset, we
	// will construct and use a suitable instance. This
	// function will be called AT MOST once.
	NewParrotTransport func() HTTPXCloseableTransport

	// NewHTTP3Transport is the optional factory for
	// creating an HTTP3 transport to use. If unset, we'll
	// construct and use a suitable instance. This
	// function will be called AT MOST once.
	NewHTTP3Transport func() HTTPXCloseableTransport

	// standardTransport is the standard transport.
	standardTransport HTTPXCloseableTransport

	// parrotTransport is the parrot transport.
	parrotTransport HTTPXCloseableTransport

	// http3Transport is the HTTP3 transport.
	http3Transport HTTPXCloseableTransport

	// mu protects this struc.
	mu sync.Mutex
}

// RoundTrip sends a request and returns the response. This function will
// construct the underlying transports on first use.
func (t *HTTPXTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock() // no races
	if t.standardTransport == nil {
		t.standardTransport = t.newStandardTransport()
	}
	if t.parrotTransport == nil {
		t.parrotTransport = t.newParrotTransport()
	}
	if t.http3Transport == nil {
		t.http3Transport = t.newHTTP3Transport()
	}
	t.mu.Unlock()
	switch req.URL.Scheme {
	default:
		return t.standardTransport.RoundTrip(req)
	case "h3", "http3":
		req.URL = t.replaceScheme(req.URL)
		return t.http3Transport.RoundTrip(req)
	case "h2", "http2":
		req.URL = t.replaceScheme(req.URL)
		return t.parrotTransport.RoundTrip(req)
	}
}

// replaceScheme clones the original URL and replaces
// the scheme to be https instead of h2, h3, etc.
func (t *HTTPXTransport) replaceScheme(URL *url.URL) *url.URL {
	cloned := &url.URL{}
	*cloned = *URL
	cloned.Scheme = "https"
	return cloned
}

// newStandardTransport creates a new standard transport.
func (t *HTTPXTransport) newStandardTransport() HTTPXCloseableTransport {
	if t.NewStandardTransport != nil {
		return t.NewStandardTransport()
	}
	return &HTTPStandardTransport{}
}

// newParrotTransport creates a new parrot transport.
func (t *HTTPXTransport) newParrotTransport() HTTPXCloseableTransport {
	if t.NewParrotTransport != nil {
		return t.NewParrotTransport()
	}
	return &HTTP2ParrotTransport{}
}

// newHTTP3Transport creates a new HTTP3 transport.
func (t *HTTPXTransport) newHTTP3Transport() HTTPXCloseableTransport {
	if t.NewHTTP3Transport != nil {
		return t.NewHTTP3Transport()
	}
	return &HTTP3StandardTransport{}
}

// CloseIdleConnections closes the idle connections.
func (t *HTTPXTransport) CloseIdleConnections() {
	t.mu.Lock() // avoid races when accessing tw
	standardTransport := t.standardTransport
	parrotTransport := t.parrotTransport
	http3Transport := t.http3Transport
	t.mu.Unlock()
	if standardTransport != nil {
		standardTransport.CloseIdleConnections()
	}
	if parrotTransport != nil {
		parrotTransport.CloseIdleConnections()
	}
	if http3Transport != nil {
		http3Transport.CloseIdleConnections()
	}
}

// HTTPXDefaultClient is the default HTTPX client. It uses
// a default constructed HTTPXTransport.
var HTTPXDefaultClient = &http.Client{Transport: &HTTPXTransport{}}
