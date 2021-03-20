package oonet

import (
	"context"
	"net"

	"github.com/ooni/psiphon/oopsi/golang.org/x/net/proxy"
)

// SOCKS5UnderlyingConnector is the underlying primitive allowing
// to dial new TCP connections. This abstraction is here to
// allow us to write unit tests for SOCKS5Connector.
type SOCKS5UnderlyingConnector interface {
	// Dial should behave like net.Dialer.Dial.
	Dial(network, address string) (net.Conn, error)
}

// SOCKS5Connector is a connector that uses a SOCSK5
// proxy to create *TCPConn connections.
//
// You MUST NOT modify any field of SOCKS5Connector after
// construction because this MAY result in a data race.
type SOCKS5Connector struct {
	// Address is the mandatory endpoint of the proxy. If you
	// do not set this field, you'll get an error.
	Address string

	// Connector is the underlying connector to use. If this is
	// not set, we use a default constructed instance of TCPConnector.
	Connector SOCKS5UnderlyingConnector
}

// ErrSOCKS5 is an error ocurring in SOCKS5 code.
type ErrSOCKS5 struct {
	error
}

// Unwrap returns the underlying error.
func (e *ErrSOCKS5) Unwrap() error {
	return e.error
}

// DialContext creates a new connection. This function will return
// ErrSOCKS5 errors. This function WON'T wrap the returned
// connection _unless_ you use a TCPConnector as the connector,
// which is the default. This function will temporarily leak
// a goroutine when the context expires. The goroutine itself
// will terminate when the connect attempt times out.
func (c *SOCKS5Connector) DialContext(
	ctx context.Context, network, address string) (net.Conn, error) {
	connch := make(chan net.Conn)
	errch := make(chan error, 1)
	go func() {
		// the code at proxy/socks5.go never fails; see https://git.io/JfJ4g
		proxy, _ := proxy.SOCKS5("tcp", c.Address, nil, c.connector())
		conn, err := proxy.Dial(network, address)
		if err != nil {
			errch <- err // buffered
			return
		}
		select {
		case connch <- conn:
		default:
			conn.Close() // the context won
		}
	}()
	select {
	case <-ctx.Done():
		return nil, &ErrSOCKS5{ctx.Err()}
	case err := <-errch:
		return nil, &ErrSOCKS5{err}
	case conn := <-connch:
		return conn, nil
	}
}

// connector returns the underlying connector to use.
func (c *SOCKS5Connector) connector() SOCKS5UnderlyingConnector {
	if c.Connector != nil {
		return c.Connector
	}
	return &TCPConnector{}
}
