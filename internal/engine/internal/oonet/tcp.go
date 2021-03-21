package oonet

import (
	"context"
	"net"
	"time"
)

// TCPConnMonitor monitors TCP connections. It may occasionally
// also monitor connected UDP sockets.
//
// The callbacks MUST NOT modify their arguments.
//
// We assume that the monitor is capable of stopping the
// propagation of events once there is no need to continue
// propagating events. You need, in particular, to be
// prepared to handle events occurring after the measurement
// when you are measuring HTTP. In such case, in fact, the
// lifetime of connections is managed by HTTP code.
type TCPConnMonitor interface {
	// OnConnConnect is called after any connect operation. The elapsed
	// argument is the time spent inside connect.
	OnConnConnect(address string, conn net.Conn, elapsed time.Duration, err error)

	// OnConnRead is called after any read. You may want to copy
	// the data field, or otherwise to record its size.
	OnConnRead(conn net.Conn, data []byte, err error)

	// OnConnWrite is called after any write. You may want to copy
	// the data field, or otherwise to record its size.
	//
	// Of course, data written on the socket MAY be retransmitted
	// by the kernel at a later time, if there are losses.
	OnConnWrite(conn net.Conn, data []byte, err error)

	// OnConnClose is called before the connection is closed. If the
	// code is buggy, this callback MAY be called more than
	// once. In such a case, we have a bug to fix.
	OnConnClose(conn net.Conn)
}

// TCPUnderlyingConnector is the underlying primitive allowing
// to dial new TCP connections. This abstraction is here to
// allow us to write unit tests for TCPConnector.
type TCPUnderlyingConnector interface {
	// DialContext should behave like net.Dialer.DialContext.
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// TCPConnector establishes TCP connections. It may also be used
// to connect UDP sockets. This is a low-level primitive.
//
// The connector will enforce a maximum timeout when connecting that
// is independent of the context. When a connect operation fails, the
// returned error will be an instance of *ErrConnect.
//
// The returned connection will be an instance of *TCPConn. This
// instance will wrap read errors with *ErrRead. Likewise, it will
// wrap write errors using *ErrWrite.
//
// By default there is no timeout for reading and writing. This
// addresses the use case when you are managing the connection
// yourself. If you're using HTTP, instead, you SHOULD set both
// timeouts because we have seen censored networks where this
// would otherwise block the probe basically forever.
//
// You SHOULD only pass to TCPConnector endpoints containing IP
// addresses. If you pass a domain name, this will work, and will
// use the default resolver. When running measurements or when
// you want to use a specific resolver, you typically need to do
// domain name resolution before calling the connector.
//
// You MUST NOT modify any field of TCPConnector after construction
// because this MAY result in a data race.
type TCPConnector struct {
	// ConnectTimeout is the optional timeout for connect operations. If
	// you configure no timeout, we will use a default timeout.
	ConnectTimeout time.Duration

	// NewDialer is the optional hook for creating a
	// new TCPConnectorDialer instance. We added this
	// hook mainly to facilitate unit testing.
	NewDialer func(timeout time.Duration) TCPUnderlyingConnector

	// ReadTimeout is the optional timeout for read operations. Zero
	// or negative implies there's no timeout
	ReadTimeout time.Duration

	// WriteTimeout is the optional timeout for write operations. Zero
	// or negative implies there's no timeout
	WriteTimeout time.Duration
}

// ErrConnect is an error when connecting.
type ErrConnect struct {
	error
}

// Unwrap returns the underlying error.
func (e *ErrConnect) Unwrap() error {
	return e.error
}

// Dial calls DialContext with the background context.
func (c *TCPConnector) Dial(network, address string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, address)
}

// DialContext creates a new connection.
func (c *TCPConnector) DialContext(
	ctx context.Context, network, address string) (net.Conn, error) {
	dialer := c.newDialer(c.connectTimeout())
	start := time.Now()
	conn, err := dialer.DialContext(ctx, network, address)
	elapsed := time.Since(start)
	if err != nil {
		err = &ErrConnect{err}
		ContextMonitor(ctx).OnConnConnect(address, nil, elapsed, err)
		return nil, err
	}
	conn = &TCPConn{
		Conn:         conn,
		monitor:      ContextMonitor(ctx),
		readTimeout:  c.ReadTimeout,
		writeTimeout: c.WriteTimeout,
	}
	ContextMonitor(ctx).OnConnConnect(address, conn, elapsed, nil)
	return conn, nil
}

// connectTimeout returns a valid connect timeout to use.
func (c *TCPConnector) connectTimeout() time.Duration {
	if c.ConnectTimeout > 0 {
		return c.ConnectTimeout
	}
	return 15 * time.Second
}

// newDialer creates a new TCPConnectorDialer instance
func (c *TCPConnector) newDialer(timeout time.Duration) TCPUnderlyingConnector {
	if c.NewDialer != nil {
		return c.NewDialer(timeout)
	}
	return &net.Dialer{Timeout: c.ConnectTimeout}
}

// TCPConn is a TCP connection. It may also occasionally be
// a connected UDP socket, which behaves ~like TCP as far as
// the user of the abstraction is concerned.
type TCPConn struct {
	// net.Conn is the underlying connection.
	net.Conn

	// monitor is the mandatory TCPConnMonitor. This field should
	// be set by TCPConnector.DialContext.
	monitor TCPConnMonitor

	// readTimeout is the mandatory read timeout. This field should
	// be set by TCPConnector.DialContext.
	readTimeout time.Duration

	// writeTimeout is the mandatory write timeout. This field should
	// be set by TCPConnector.DialContext.
	writeTimeout time.Duration
}

// ErrRead is an error that occurred when reading.
type ErrRead struct {
	error
}

// Unwrap returns the underlying error.
func (e *ErrRead) Unwrap() error {
	return e.error
}

// Read reads data from the underlying connection.
func (c *TCPConn) Read(b []byte) (int, error) {
	if c.readTimeout > 0 {
		c.Conn.SetReadDeadline(time.Now().Add(c.readTimeout))
		defer c.Conn.SetDeadline(time.Time{})
	}
	count, err := c.Conn.Read(b)
	if err != nil {
		err = &ErrRead{err}
	}
	c.monitor.OnConnRead(c, b[:count], err)
	return count, err
}

// ErrWrite is an error that occurred when writing.
type ErrWrite struct {
	error
}

// Unwrap returns the underlying error.
func (e *ErrWrite) Unwrap() error {
	return e.error
}

// Write writes data to the underlying connection.
func (c *TCPConn) Write(b []byte) (int, error) {
	if c.writeTimeout > 0 {
		c.Conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
		defer c.Conn.SetDeadline(time.Time{})
	}
	count, err := c.Conn.Write(b)
	if err != nil {
		err = &ErrWrite{err}
	}
	c.monitor.OnConnWrite(c, b[:count], err)
	return count, err
}

// TCPConnAddr is the net.Addr returns by TCPConn. This particular
// implementation of net.Addr also contains the original connection,
// so you can try and inspect which underlying connection you are
// actually using from the httptrace.GotConnInfo struct _and_ you're
// using https. In this case, you can obtain the address from the
// net.Conn and then you can cast it to *TCPConnAddr, which allows
// accessing the *TCPConn. Both LocalAddr and RemoteAddr return
// an instance of *TCPConnAddr.
type TCPConnAddr struct {
	// Addr is the underlying address.
	net.Addr

	// Conn is the connection.
	Conn *TCPConn
}

// LocalAddr returns the local address. The returned value
// is an instance of *TCPConnAddr.
func (c *TCPConn) LocalAddr() net.Addr {
	return &TCPConnAddr{Addr: c.Conn.LocalAddr(), Conn: c}
}

// RemoteAddr returns the remote address. The returned value
// is an instance of *TCPConnAddr.
func (c *TCPConn) RemoteAddr() net.Addr {
	return &TCPConnAddr{Addr: c.Conn.RemoteAddr(), Conn: c}
}

// Close closes the connection. We do not insert any
// protection against the connection being closed more
// than once. The underlying connection will return
// an error if you attempt to close the connection again
// or generally to use a closed connection. We did not
// protect against multiple close or use of close network
// connections, because these are bugs and we want to
// see them. Every connection SHOULD only be closed once.
func (c *TCPConn) Close() error {
	c.monitor.OnConnClose(c)
	return c.Conn.Close()
}
