package oonet

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/apex/log"
	"github.com/bassosimone/quic-go"
)

// LogMonitorLogger is the logger for LogMonitor. This interface
// is compatible with github.com/apex/log.
type LogMonitorLogger interface {
	Debugf(format string, v ...interface{})
	Debug(msg string)
}

// LogMonitor is a Monitor that implements logging.
type LogMonitor struct {
	// Logger is the optional LogMonitorLogger to use.
	Logger LogMonitorLogger
}

// verify that we implement the interface.
var _ Monitor = &LogMonitor{}

// logger returns the LogMonitorLogger to use.
func (m *LogMonitor) logger() LogMonitorLogger {
	if m.Logger != nil {
		return m.Logger
	}
	return log.Log
}

// OnDNSLookupHostStart is called when we start a LookupHost operation.
func (m *LogMonitor) OnDNSLookupHostStart(hostname string) {
	m.logger().Debugf("dnsLookupHost %s...", hostname)
}

// OnDNSLookupHostDone is called after a LookupHost operation.
func (m *LogMonitor) OnDNSLookupHostDone(hostname string, addrs []string, err error) {
	m.logger().Debugf("dnsLookupHost %s... %+v %+v", hostname, addrs, err)
}

// OnDNSSendQuery is called when we are sending a query.
func (m *LogMonitor) OnDNSSendQuery(query string) {
	m.logger().Debugf("dnsQuery:\n%s", query)
}

// OnDNSRecvReply is called after we received a reply.
func (m *LogMonitor) OnDNSRecvReply(reply string) {
	m.logger().Debugf("dnsReply:\n%s", reply)
}

// OnHTTPRoundTripStart is called when we start a round trip.
func (m *LogMonitor) OnHTTPRoundTripStart(req *http.Request) {
	m.logger().Debugf("> %s %s", req.Method, req.URL.String())
	for key, values := range req.Header {
		for _, value := range values {
			m.logger().Debugf("> %s: %s", key, value)
		}
	}
	m.logger().Debug(">")
}

// OnHTTPRoundTripDone is called at the end of a round trip.
func (m *LogMonitor) OnHTTPRoundTripDone(
	req *http.Request, resp *http.Response, err error) {
	if err != nil {
		m.logger().Debugf("< %+v", err)
		return
	}
	m.logger().Debugf("< %d", resp.StatusCode)
	for key, values := range resp.Header {
		for _, value := range values {
			m.logger().Debugf("< %s: %s", key, value)
		}
	}
	m.logger().Debug("<")
}

// OnHTTPResponseBodyStart is called when we start reading the body.
func (m *LogMonitor) OnHTTPResponseBodyStart(resp *http.Response) {
	m.logger().Debug("reading response body...")
}

// OnHTTPResponseBodyDone is called when we're done reading the body.
func (m *LogMonitor) OnHTTPResponseBodyDone(
	resp *http.Response, data []byte, err error) {
	m.logger().Debugf("reading response body... <%d bytes> %+v", len(data), err)
}

// OnSockConnect is called after a socket connect.
func (m *LogMonitor) OnSockConnect(
	address string, conn net.Conn, elapsed time.Duration, err error) {
	m.logger().Debugf("connect %s... %+v %s %+v", address,
		conn.RemoteAddr(), elapsed, err)
}

// OnSockRead is called after a socket read.
func (m *LogMonitor) OnSockRead(conn net.Conn, data []byte, err error) {
	m.logger().Debugf("read %+v... <%d bytes> %+v",
		conn.RemoteAddr(), len(data), err)
}

// OnSockWrite is called after a socket write.
func (m *LogMonitor) OnSockWrite(conn net.Conn, data []byte, err error) {
	m.logger().Debugf("write %+v... <%d bytes> %+v",
		conn.RemoteAddr(), len(data), err)
}

// OnSockClose is called before a socket close.
func (m *LogMonitor) OnSockClose(conn net.Conn) {
	m.logger().Debugf("close %+v", conn.RemoteAddr())
}

// OnTLSHandshakeStart is called at the beginning of the TLS handshake
func (m *LogMonitor) OnTLSHandshakeStart(lib string, conn net.Conn, config *tls.Config) {
	m.logger().Debugf("tlsHandshake [%s] sni=%s alpn=%+v...",
		lib, config.ServerName, config.NextProtos)
}

// OnTLSHandshakeDone is called at the end of the TLS handshake.
func (m *LogMonitor) OnTLSHandshakeDone(lib string, conn net.Conn, config *tls.Config,
	state *tls.ConnectionState, err error) {
	m.logger().Debugf("tlsHandshake [%s] sni=%s alpn=%+v... %+v",
		lib, config.ServerName, config.NextProtos, err)
}

// OnUDPReadFrom is called after a ReadFrom.
func (m *LogMonitor) OnUDPReadFrom(
	conn net.PacketConn, data []byte, addr net.Addr, err error) {
	m.logger().Debugf("readFrom %+v <%d bytes> %+v %+v",
		conn.LocalAddr(), len(data), addr, err)
}

// OnUDPWriteTo is called after a WriteTo.
func (m *LogMonitor) OnUDPWriteTo(
	conn net.PacketConn, data []byte, addr net.Addr, err error) {
	m.logger().Debugf("writeTo %+v <%d bytes> %+v %+v", conn.LocalAddr(),
		len(data), addr, err)
}

// OnUDPListen is called after a UDP listen.
func (m *LogMonitor) OnUDPListen(
	laddr *net.UDPAddr, conn net.PacketConn, err error) {
	m.logger().Debugf("listen %+v %+v", conn.LocalAddr(), err)
}

// OnUDPClose is called before closing the UDP connection.
func (m *LogMonitor) OnUDPClose(conn net.PacketConn) {
	m.logger().Debugf("close %+v", conn.LocalAddr())
}

// OnQUICHandshakeStart is called before the QUIC handshake starts.
func (m *LogMonitor) OnQUICHandshakeStart(
	address string, tlsConf *tls.Config, quicConf *quic.Config) {
	m.logger().Debugf("quicHandshake sni=%s alpn=%+v...",
		tlsConf.ServerName, tlsConf.NextProtos)
}

// OnQUICHandshakeDone is called after the QUIC handshake.
func (m *LogMonitor) OnQUICHandshakeDone(
	address string, tlsConf *tls.Config, quicConf *quic.Config,
	elapsed time.Duration, sess quic.EarlySession, err error) {
	m.logger().Debugf("quicHandshake sni=%s alpn=%+v... %+v",
		tlsConf.ServerName, tlsConf.NextProtos, err)
}
