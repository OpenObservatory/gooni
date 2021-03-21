package oonet

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/bassosimone/quic-go"
)

// TODO(bassosimone): figure out if this is the correct
// way of closing a QUIC session. It seems to be relevant
// to HTTP3 and it's private inside of quic-go.

// QUICHTTP3StatusNoError is the status sent by HTTP3
// when closing a QUIC session.
const QUICHTTP3StatusNoError = 0x100

// QUICMonitor monitors QUIC events.
//
// The callbacks MUST NOT modify their arguments.
//
// We assume that the monitor is capable of stopping the
// propagation of events once there is no need to continue
// propagating events. You need, in particular, to be
// prepared to handle events occurring after the measurement
// when you are measuring HTTP3. In such case, in fact, the
// lifetime of connections is managed by HTTP3 code.
type QUICMonitor interface {
	// OnDatagramReadFrom is called after ReadFrom. You may want to
	// copy the data field or otherwise record its size.
	OnDatagramReadFrom(conn net.PacketConn, data []byte, addr net.Addr, err error)

	// OnDatagramWriteTo is called after WriteTo. You may want to
	// copy the data field or otherwise record its size.
	OnDatagramWriteTo(conn net.PacketConn, data []byte, addr net.Addr, err error)

	// OnDatagramListen is called after a UDP listen.
	OnDatagramListen(laddr *net.UDPAddr, conn net.PacketConn, err error)

	// OnDatagramClose is called before closing a UDP socket. Note that buggy
	// code MAY cause this code to be called more than once. This is
	// a bug that should obviously be fixed.
	OnDatagramClose(conn net.PacketConn)

	// OnQUICHandshakeStart is called before the QUIC handshake.
	OnQUICHandshakeStart(address string, tlsConf *tls.Config, quicConf *quic.Config)

	// OnQUICHandshakeDone is called after the QUIC handshake. The elapsed
	// time is the time spent handshaking. Either sess is nil and err is
	// not nil (on failure) or the other way around (on succesa).
	OnQUICHandshakeDone(address string, tlsConf *tls.Config, quicConf *quic.Config,
		elapsed time.Duration, sess quic.EarlySession, err error)
}

// QUICListener creates net.PacketConn instances. This interface
// mainly exists to facilitate unit testing. The returned PacketConn
// will then be used to establish a new QUIC session.
type QUICListener interface {
	// Listen creates a new PacketConn with the given addr.
	Listen(ctx context.Context, network string,
		laddr *net.UDPAddr) (net.PacketConn, error)
}

// quicDefaultListener is the default QUICListener.
type quicDefaultListener struct{}

// Listen implement QUICListener.Listen. This function WILL NOT wrap
// the returned error because we assume it's called by QUICHandshaker
// which will instead wrao the returned error.
func (dl *quicDefaultListener) Listen(
	ctx context.Context, network string, laddr *net.UDPAddr) (net.PacketConn, error) {
	conn, err := net.ListenUDP(network, laddr)
	ContextMonitor(ctx).OnDatagramListen(laddr, conn, err)
	return conn, err
}

// QUICUnderlyingHandshaker is the underlying handshaker used to
// create QUIC sessions. This interface is mainly used for testing.
type QUICUnderlyingHandshaker interface {
	// DialEarlyContext should work exactly like the
	// quic.DialEarlyContext in quic-go.
	DialEarlyContext(
		ctx context.Context,
		pconn net.PacketConn,
		remoteAddr net.Addr,
		host string,
		tlsConf *tls.Config,
		quicConf *quic.Config,
	) (quic.EarlySession, error)
}

// quicDefaultUnderlyingHandshaker is the default QUICUnderlyingHandshaker.
type quicDefaultUnderlyingHandshaker struct{}

// DialEarlyContext implements QUICUnderlyingHandshaker.DialEarlyContext.
func (h *quicDefaultUnderlyingHandshaker) DialEarlyContext(
	ctx context.Context,
	pconn net.PacketConn,
	remoteAddr net.Addr,
	host string,
	tlsConf *tls.Config,
	quicConf *quic.Config,
) (quic.EarlySession, error) {
	return quic.DialEarlyContext(
		ctx, pconn, remoteAddr, host, tlsConf, quicConf)
}

// QUICHandshaker creates QUIC sessions. This is a low-level
// primitive for making new QUIC sessions.
//
// The handshaker will enforce a maximum timeout when connecting that
// is independent of the context. When an handshake operation fails, the
// returned error will be an instance of *ErrQUICHandshake. To enforce
// handshake timeouts and max idle timeouts, you need to properly
// configure the *quic.Config structure. If not, then the quic code
// will configure suitable defaults for these values.
//
// The returned connection will be an instance of *UDPPacketConn. This
// instance will wrap recvfrom errors with *ErrReadFrom. Likewise, it will
// wrap sendto errors using *ErrWriteTo.
//
// There will always be a timeout for reading or writing. This is
// tunable using *quic.Config (see MaxIdleTimeout).
//
// You MUST only pass to QUICHandshaker endpoints containing IP
// addresses. If you pass a domain name, the code will fail. This
// a low-level primitive. Use a Dialer to combine establishing a
// new QUIC session with domain name resolutions.
//
// You MUST NOT modify any field of QUICConnector after construction
// because this MAY result in a data race.
type QUICHandshaker struct {
	// Listener is the optional QUICListener to use. If not set,
	// we will fallback to the Go standard library.
	Listener QUICListener

	// Handshaker is the underlying handshaker. If not set, we
	// will use lucas-clemente/quic-go to QUIC-handshake.
	Handshaker QUICUnderlyingHandshaker
}

// ErrQUICHandshake is an error during the QUIC handshake.
type ErrQUICHandshake struct {
	error
}

// Unwrap returns the underlying error.
func (e *ErrQUICHandshake) Unwrap() error {
	return e.error
}

// ErrQUICInvalidIPAddress indicates that the QUIC handshaker
// was passed an invalid IP address and cannot continue. You most
// likely see this error if you pass an address containing a
// domain name to QUICHandshaker.DialEarlyContext.
var ErrQUICInvalidIPAddress = errors.New("quic: invalid IP addr")

// DialEarlyContext establishes a QUIC session. The code assumes that
// you have properly configured tlsConf with the desired SNI and it
// also assumes that quicConf is not nil. You MUST also define the
// desired QUIC protocol(s) using tlsConf.NextProtos.
//
// Note that address MUST be an endpoint containing an IP address and
// a port. If it contains a domain name, then the code will fail and
// return ErrQUICInvalidIPAddress.
//
// The handshake timeout is configured using quicConf.HandshakeTimeout
// and the idle timeout is configured using quicConf.MaxIdleTimeout.
//
// We will construct a single PacketConn for every EarlySession. The
// returned EarlySession owns the PacketConn. This arrangement simplifies
// keeping track of which events occurred.
func (c *QUICHandshaker) DialEarlyContext(ctx context.Context, address string,
	tlsConf *tls.Config, quicConf *quic.Config) (quic.EarlySession, error) {
	ipstr, portstr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, &ErrQUICHandshake{err}
	}
	ip := net.ParseIP(ipstr)
	if ip == nil {
		return nil, &ErrQUICHandshake{ErrQUICInvalidIPAddress}
	}
	port, err := strconv.Atoi(portstr)
	if err != nil {
		return nil, &ErrQUICHandshake{err}
	}
	pconn, err := c.listener().Listen(ctx, "udp", &net.UDPAddr{})
	if err != nil {
		return nil, &ErrQUICHandshake{err}
	}
	ContextMonitor(ctx).OnQUICHandshakeStart(address, tlsConf, quicConf)
	start := time.Now()
	sess, err := c.handshaker().DialEarlyContext(ctx,
		&QUICPacketConn{PacketConn: pconn, monitor: ContextMonitor(ctx)},
		&net.UDPAddr{IP: ip, Port: port},
		"", // quic-go code will use tlsConf.ServerName
		tlsConf, quicConf)
	elapsed := time.Since(start)
	if err != nil {
		err = &ErrQUICHandshake{err}
		ContextMonitor(ctx).OnQUICHandshakeDone(
			address, tlsConf, quicConf, elapsed, nil, err)
		return nil, err
	}
	sess = &quicEarlySession{EarlySession: sess, pconn: pconn}
	ContextMonitor(ctx).OnQUICHandshakeDone(
		address, tlsConf, quicConf, elapsed, sess, err)
	return sess, nil
}

// quicEarlySession is a wrapper for quic.EarlySession that
// also ensures that we close the PacketConn.
type quicEarlySession struct {
	// quic.EarlySession is the underlying quic.EarlySession.
	quic.EarlySession

	// closeErr is the close error.
	closeErr error

	// closed indicates whether we are now closed.
	closed bool

	// mu provides protection when closing.
	mu sync.Mutex

	// pconn is the packet conn using the session.
	pconn net.PacketConn
}

// CloseWithError closes this session with the specified error. The code
// is such that we will close the session just once. Every subsequent invocation
// will return the error obtained in the first invocation.
func (s *quicEarlySession) CloseWithError(ec quic.ErrorCode, reason string) error {
	defer s.mu.Unlock()
	s.mu.Lock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	if err := s.EarlySession.CloseWithError(ec, reason); err != nil {
		s.closeErr = err
	}
	// Implementation note: if other code paths call pconn.Close we will
	// still see multiple OnDatagramClose events. Also: closing the pconn here
	// will cause "use of closed network connections" down the line. It
	// is not a big deal, but we just know about this fact.
	s.pconn.Close()
	return s.closeErr
}

// listener returns the QUICListener to use.
func (c *QUICHandshaker) listener() QUICListener {
	if c.Listener != nil {
		return c.Listener
	}
	return &quicDefaultListener{}
}

// handshaker returns the QUICUnderlyingHandshaker to use.
func (c *QUICHandshaker) handshaker() QUICUnderlyingHandshaker {
	if c.Handshaker != nil {
		return c.Handshaker
	}
	return &quicDefaultUnderlyingHandshaker{}
}

// QUICPacketConn is a QUIC PacketConn. The job of this data
// struct is to connect the real PacketConn to a Monitor.
type QUICPacketConn struct {
	// net.PacketConn is the underlying conn.
	net.PacketConn

	// monitor is the mandatory QUICMonitor. This field should
	// be set by QUICHandshaker.DialEarlyAddrContext.
	monitor QUICMonitor
}

// ErrReadFrom is a ReadFrom error.
type ErrReadFrom struct {
	error
}

// Unwrap returns the underlying error.
func (e *ErrReadFrom) Unwrap() error {
	return e.error
}

// ReadFrom reads data from the underlying conn.
func (c *QUICPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	// timeouts are handled using quicConf.MaxIdleTimeout.
	count, addr, err := c.PacketConn.ReadFrom(p)
	if err != nil {
		err = &ErrReadFrom{err}
	}
	c.monitor.OnDatagramReadFrom(c, p[:count], addr, err)
	return count, addr, err
}

// ErrWriteTo is an error occurring in WriteTo.
type ErrWriteTo struct {
	error
}

// Unwrap returns the underlying error.
func (e *ErrWriteTo) Unwrap() error {
	return e.error
}

// WriteTo writes data to the underlying conn.
func (c *QUICPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	// timeouts are handled using quicConf.MaxIdleTimeout.
	count, err := c.PacketConn.WriteTo(p, addr)
	if err != nil {
		err = &ErrWriteTo{err}
	}
	c.monitor.OnDatagramWriteTo(c, p[:count], addr, err)
	return count, err
}

// Close closes the PacketConn.
func (c *QUICPacketConn) Close() error {
	c.monitor.OnDatagramClose(c)
	return c.PacketConn.Close()
}
