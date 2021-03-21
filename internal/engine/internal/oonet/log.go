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
	if err != nil {
		m.logger().Debugf("dnsLookupHost %s... %s", hostname, err.Error())
		return
	}
	m.logger().Debugf("dnsLookupHost %s... %+v", hostname, addrs)
}

// OnDNSSendQuery is called when we are sending a query.
func (m *LogMonitor) OnDNSSendQuery(query *DNSQuery) {
	m.logger().Debugf("dnsQuery:\n%s", query.Msg.String())
}

// OnDNSRecvReply is called after we received a reply.
func (m *LogMonitor) OnDNSRecvReply(reply *DNSReply) {
	m.logger().Debugf("dnsReply:\n%s", reply.Msg.String())
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

// OnConnConnect is called after a socket connect.
func (m *LogMonitor) OnConnConnect(
	address string, conn net.Conn, elapsed time.Duration, err error) {
	if err != nil {
		m.logger().Debugf("connect %s... %s %s", address, elapsed, err.Error())
		return
	}
	m.logger().Debugf("connect %s... %+v %s", address,
		conn.RemoteAddr(), elapsed)
}

// OnConnRead is called after a socket read.
func (m *LogMonitor) OnConnRead(conn net.Conn, data []byte, err error) {
	if err != nil {
		m.logger().Debugf("read %+v... %s", conn.RemoteAddr(), err.Error())
		return
	}
	m.logger().Debugf("read %+v... <%d bytes>",
		conn.RemoteAddr(), len(data))
}

// OnConnWrite is called after a socket write.
func (m *LogMonitor) OnConnWrite(conn net.Conn, data []byte, err error) {
	if err != nil {
		m.logger().Debugf("write %+v... %s", conn.RemoteAddr(), err.Error())
		return
	}
	m.logger().Debugf("write %+v... <%d bytes>",
		conn.RemoteAddr(), len(data))
}

// OnConnClose is called before a socket close.
func (m *LogMonitor) OnConnClose(conn net.Conn) {
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
	if err != nil {
		m.logger().Debugf("tlsHandshake [%s] sni=%s alpn=%+v... %s",
			lib, config.ServerName, config.NextProtos, err.Error())
		return
	}
	m.logger().Debugf("tlsHandshake [%s] sni=%s alpn=%+v... ok",
		lib, config.ServerName, config.NextProtos)
}

// OnDatagramReadFrom is called after a ReadFrom.
func (m *LogMonitor) OnDatagramReadFrom(
	conn net.PacketConn, data []byte, addr net.Addr, err error) {
	if err != nil {
		m.logger().Debugf("readFrom %+v %s",
			conn.LocalAddr(), err.Error())
		return
	}
	m.logger().Debugf("readFrom %+v <%d bytes> %+v",
		conn.LocalAddr(), len(data), addr)
}

// OnDatagramWriteTo is called after a WriteTo.
func (m *LogMonitor) OnDatagramWriteTo(
	conn net.PacketConn, data []byte, addr net.Addr, err error) {
	if err != nil {
		m.logger().Debugf("writeTo %+v %+v %s",
			conn.LocalAddr(), addr, err.Error())
		return
	}
	m.logger().Debugf("writeTo %+v %+v <%d bytes> %+v", conn.LocalAddr(),
		addr, len(data), addr)
}

// OnDatagramListen is called after a UDP listen.
func (m *LogMonitor) OnDatagramListen(
	laddr *net.UDPAddr, conn net.PacketConn, err error) {
	if err != nil {
		m.logger().Debugf("listen %+v %s", laddr, err.Error())
		return
	}
	m.logger().Debugf("listen %+v ok", laddr)
}

// OnDatagramClose is called before closing the UDP connection.
func (m *LogMonitor) OnDatagramClose(conn net.PacketConn) {
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
	if err != nil {
		m.logger().Debugf("quicHandshake sni=%s alpn=%+v... %s",
			tlsConf.ServerName, tlsConf.NextProtos, err.Error())
		return
	}
	m.logger().Debugf("quicHandshake sni=%s alpn=%+v... ok",
		tlsConf.ServerName, tlsConf.NextProtos)
}
