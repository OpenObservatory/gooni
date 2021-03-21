package oonet

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/bassosimone/quic-go"
)

// Monitor allows to monitor events. You configure a Monitor for
// a specific context by using WithMonitor. Every request using
// such a context will then log events into the Monitor. You will
// use ContextMonitor to get the context's Monitor.
type Monitor interface {
	// DNSMonitor allows monitoring DNS events.
	DNSMonitor

	// HTTPMonitor allows monitoring HTTP events.
	HTTPMonitor

	// TCPConnMonitor allows monitoring TCP evewnts.
	TCPConnMonitor

	// TLSHandshakeMonitor allows monitoring TLS.
	TLSHandashakeMonitor

	// QUICMonitor allows monitoring QUIC.
	QUICMonitor
}

// monitorDefault is a do-nothing monitor.
type monitorDefault struct{}

// verify that we implement the interface.
var _ Monitor = &monitorDefault{}

// OnDNSLookupHostStart implements DNSMonitor.OnDNSLookupHostStart.
func (m *monitorDefault) OnDNSLookupHostStart(hostname string) {}

// OnDNSLookupHostDone implements DNSMonitor.OnDNSLookupHostDone.
func (m *monitorDefault) OnDNSLookupHostDone(
	hostname string, addrs []string, err error) {
	// nothing
}

// OnDNSSendQuery implements DNSMonitor.OnDNSSendQuery.
func (m *monitorDefault) OnDNSSendQuery(query string) {}

// OnDNSRecvReply implements DNSMonitor.OnDNSRecvReply.
func (m *monitorDefault) OnDNSRecvReply(reply string) {}

// OnHTTPRoundTripStart implements HTTPMonitor.OnHTTPRoundTripStart.
func (m *monitorDefault) OnHTTPRoundTripStart(req *http.Request) {}

// OnHTTPRoundTripDone implements HTTPMonitor.OnHTTPRoundTripDone.
func (m *monitorDefault) OnHTTPRoundTripDone(
	req *http.Request, resp *http.Response, err error) {
	// nothing
}

// OnHTTPResponseBodyStart implements HTTPMonitor.OnHTTPResponseBodyStart.
func (m *monitorDefault) OnHTTPResponseBodyStart(resp *http.Response) {}

// OnHTTPResponseBodyDone implements HTTPMonitor.OnHTTPResponseBodyDone.
func (m *monitorDefault) OnHTTPResponseBodyDone(
	resp *http.Response, data []byte, err error) {
	// nothing
}

// OnConnConnect implements TCPConnMonitor.OnConnConnect.
func (m *monitorDefault) OnConnConnect(
	address string, conn net.Conn, elapsed time.Duration, err error) {
	// nothing
}

// OnConnRead implements TCPConnMonitor.OnConnRead.
func (m *monitorDefault) OnConnRead(conn net.Conn, data []byte, err error) {}

// OnConnWrite implements TCPConnMonitor.OnConnWrite.
func (m *monitorDefault) OnConnWrite(conn net.Conn, data []byte, err error) {}

// OnConnClose implements TCPConnMonitor.OnConnClose.
func (m *monitorDefault) OnConnClose(conn net.Conn) {}

// OnTLSHandshakeStart implements TLSHandshakeMonitor.OnTLSHandshakeStart.
func (m *monitorDefault) OnTLSHandshakeStart(lib string,
	conn net.Conn, config *tls.Config) {
	// nothing
}

// OnTLSHandshakeDone implements TLSHandshakeMonitor.OnTLSHandshakeDone.
func (m *monitorDefault) OnTLSHandshakeDone(lib string,
	conn net.Conn, config *tls.Config, state *tls.ConnectionState, err error) {
	// nothing
}

// OnDatagramReadFrom implements QUICMonitor.OnDatagramReadFrom.
func (m *monitorDefault) OnDatagramReadFrom(
	conn net.PacketConn, data []byte, addr net.Addr, err error) {
	//nothing
}

// OnDatagramWriteTo implements QUICMonitor.OnDatagramWriteTo.
func (m *monitorDefault) OnDatagramWriteTo(
	conn net.PacketConn, data []byte, addr net.Addr, err error) {
	// nothing
}

// OnDatagramListen implements QUICMonitor.OnDatagramListen.
func (m *monitorDefault) OnDatagramListen(
	laddr *net.UDPAddr, conn net.PacketConn, err error) {
	// nothing
}

// OnDatagramClose implements QUICMonitor.OnDatagramClose.
func (m *monitorDefault) OnDatagramClose(conn net.PacketConn) {
	// nothing
}

// OnQUICHandshakeStart implements QUICMonitor.OnQUICHandshakeStart.
func (m *monitorDefault) OnQUICHandshakeStart(
	address string, tlsConf *tls.Config, quicConf *quic.Config) {
	// nothing
}

// OnQUICHandshakeDone implements QUICMonitor.OnQUICHandshakeDone.
func (m *monitorDefault) OnQUICHandshakeDone(address string, tlsConf *tls.Config, quicConf *quic.Config,
	elapsed time.Duration, sess quic.EarlySession, err error) {
	// nothing
}
