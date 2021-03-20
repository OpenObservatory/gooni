package oonet

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TLSHandshakeMonitor monitors TLSHandshakes. The callbacks
// MUST NOT modify their arguments.
type TLSHandashakeMonitor interface {
	// OnTLSHandshakeStart is called when the TLS handshake starts. The
	// conn argument is the cleartext TCP connection.
	OnTLSHandshakeStart(library string, conn net.Conn, config *tls.Config)

	// OnTLSHandshakeDone is called when the TLS handshake is
	// complete. The conn argument is still the cleartext
	// TCP connection, and is always set. The state argument
	// is nil if there has been an handshake error.
	OnTLSHandshakeDone(library string, conn net.Conn, config *tls.Config,
		state *tls.ConnectionState, err error)
}

// TLSHandshaker performs TLS handshakes.
//
// You MUST NOT modify any field of TLSHanshaker after construction
// because this MAY result in a data race.
type TLSHandshaker struct {
	// Library is the TLSLibrary to use. If not set,
	// then we will use the standard library.
	Library TLSLibrary

	// Timeout is the timeout for the TLS handshake. If not
	// set, we will use a default timeout value.
	Timeout time.Duration
}

// ErrTLSHandshake is an error occurring during the TLS handshake.
type ErrTLSHandshake struct {
	error
}

// Unwrap returns the underlying error.
func (e *ErrTLSHandshake) Unwrap() error {
	return e.error
}

// TLSHandshake performs the TLS handshake. The config must be present
// and must be properly initialized. This function WILL NOT take ownership
// of the input conn, which you SHOULD Close on failure.
func (th *TLSHandshaker) TLSHandshake(
	ctx context.Context, conn net.Conn, config *tls.Config) (net.Conn, error) {
	lib := th.library()
	timeo := th.timeout()
	conn.SetDeadline(time.Now().Add(timeo))
	defer conn.SetDeadline(time.Time{})
	tc := lib.Client(conn, config)
	errch := make(chan error, 1)
	ContextMonitor(ctx).OnTLSHandshakeStart(lib.Name(), conn, config)
	go func() { errch <- tc.Handshake() }()
	select {
	case <-ctx.Done():
		err := &ErrTLSHandshake{ctx.Err()}
		ContextMonitor(ctx).OnTLSHandshakeDone(lib.Name(), conn, config, nil, err)
		return nil, err
	case err := <-errch:
		if err != nil {
			err := &ErrTLSHandshake{err}
			ContextMonitor(ctx).OnTLSHandshakeDone(lib.Name(), conn, config, nil, err)
			return nil, err
		}
		state := tc.ConnectionState()
		ContextMonitor(ctx).OnTLSHandshakeDone(lib.Name(), conn, config, &state, nil)
		return tc, nil
	}
}

// timeout returns the timeout for the TLS handshake.
func (th *TLSHandshaker) timeout() time.Duration {
	if th.Timeout > 0 {
		return th.Timeout
	}
	return 10 * time.Second
}

// library returns the TLSLibrary to use.
func (th *TLSHandshaker) library() TLSLibrary {
	if th.Library != nil {
		return th.Library
	}
	return &TLSStandardLibrary{}
}

// TLSLibrary is a specific TLS library.
type TLSLibrary interface {
	// Client creates a new TLS client Conn. This function
	// should behave like tls.Client.
	Client(conn net.Conn, config *tls.Config) TLSConn

	// Name returns the TLSLibrary name.
	Name() string
}

// TLSConn is a TLS connection. It should behave
// like the tls.Conn in the standard library.
type TLSConn interface {
	// net.Conn is the underlying conn.
	net.Conn

	// ConnectionState returns the tls.ConnectionState.
	ConnectionState() tls.ConnectionState

	// Handshake performs the TLS handshake.
	Handshake() error
}

// TLSStandardLibrary is the TLS implementation inside of
// the Golang standard library.
type TLSStandardLibrary struct{}

// Client implements TLSLibrary.Client.
func (lib *TLSStandardLibrary) Client(conn net.Conn, config *tls.Config) TLSConn {
	return tls.Client(conn, config)
}

// Name implements TLSLibrary.Name.
func (lib *TLSStandardLibrary) Name() string {
	return "stdlib"
}

// TLSParrotLibrary is a TLS implementation that
// (allegedly) parrots the latest Chrome.
type TLSParrotLibrary struct{}

// Client implements TLSLibrary.Client.
func (lib *TLSParrotLibrary) Client(conn net.Conn, config *tls.Config) TLSConn {
	uconfig := &utls.Config{
		DynamicRecordSizingDisabled: config.DynamicRecordSizingDisabled,
		NextProtos:                  config.NextProtos,
		RootCAs:                     config.RootCAs,
		ServerName:                  config.ServerName,
	}
	uconn := utls.UClient(conn, uconfig, utls.HelloChrome_83)
	return &tlsConnUTLS{uconn}
}

// Name implements TLSLibrary.Name.
func (lib *TLSParrotLibrary) Name() string {
	return "utls"
}

// tlsConnUTLS wraps refraction-networking/utls connections.
type tlsConnUTLS struct {
	net.Conn
}

// ConnectionState implements TLSConn.ConnectionState.
func (c *tlsConnUTLS) ConnectionState() tls.ConnectionState {
	cs := c.Conn.(*utls.UConn).ConnectionState()
	return tls.ConnectionState{
		Version:                     cs.Version,
		HandshakeComplete:           cs.HandshakeComplete,
		DidResume:                   cs.DidResume,
		CipherSuite:                 cs.CipherSuite,
		NegotiatedProtocol:          cs.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  cs.NegotiatedProtocolIsMutual,
		ServerName:                  cs.ServerName,
		PeerCertificates:            cs.PeerCertificates,
		VerifiedChains:              cs.VerifiedChains,
		SignedCertificateTimestamps: cs.SignedCertificateTimestamps,
		OCSPResponse:                cs.OCSPResponse,
		TLSUnique:                   cs.TLSUnique,
	}
}

// Handshake implements TLSConn.Handshake.
func (c *tlsConnUTLS) Handshake() error {
	return c.Conn.(*utls.UConn).Handshake()
}
