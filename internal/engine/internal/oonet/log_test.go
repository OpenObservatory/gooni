package oonet

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/bassosimone/quic-go"
	"github.com/miekg/dns"
)

func TestLoggerDoesNotCrash(t *testing.T) {
	logger := &log.Logger{Handler: log.Log.(*log.Logger).Handler}
	lm := &LogMonitor{Logger: logger}
	lm.OnDNSLookupHostStart("example.com")
	lm.OnDNSLookupHostDone("example.com", nil, errors.New("x"))
	lm.OnDNSLookupHostDone("example.com", []string{"8.8.8.8"}, nil)
	lm.OnDNSSendQuery(&DNSQuery{Msg: &dns.Msg{}})
	lm.OnDNSRecvReply(&DNSReply{Msg: &dns.Msg{}})
	lm.OnHTTPRoundTripStart(&http.Request{URL: &url.URL{}})
	lm.OnHTTPRoundTripDone(&http.Request{}, nil, errors.New("x"))
	lm.OnHTTPRoundTripDone(&http.Request{}, &http.Response{}, nil)
	lm.OnConnConnect("1.2.3.4", nil, 124, errors.New("x"))
	lm.OnConnConnect("1.2.3.4", &net.TCPConn{}, 128, nil)
	lm.OnConnRead(&net.TCPConn{}, nil, errors.New("x"))
	lm.OnConnRead(&net.TCPConn{}, make([]byte, 1117), nil)
	lm.OnConnWrite(&net.TCPConn{}, nil, errors.New("x"))
	lm.OnConnWrite(&net.TCPConn{}, make([]byte, 1117), nil)
	lm.OnConnClose(&net.TCPConn{})
	lm.OnTLSHandshakeStart("utls", &net.TCPConn{}, &tls.Config{})
	lm.OnTLSHandshakeDone(
		"utls", &net.TCPConn{}, &tls.Config{}, nil, errors.New("x"))
	lm.OnTLSHandshakeDone(
		"utls", &net.TCPConn{}, &tls.Config{}, new(tls.ConnectionState), nil)
	lm.OnDatagramReadFrom(&net.UDPConn{}, nil, nil, errors.New("x"))
	lm.OnDatagramReadFrom(
		&net.UDPConn{}, make([]byte, 177), &net.UDPAddr{}, nil)
	lm.OnDatagramWriteTo(&net.UDPConn{}, nil, &net.UDPAddr{}, errors.New("x"))
	lm.OnDatagramWriteTo(
		&net.UDPConn{}, make([]byte, 177), &net.UDPAddr{}, nil)
	lm.OnDatagramListen(&net.UDPAddr{}, nil, errors.New("x"))
	lm.OnDatagramListen(&net.UDPAddr{}, &net.UDPConn{}, nil)
	lm.OnDatagramClose(&net.UDPConn{})
	lm.OnQUICHandshakeStart("1.2.3.4", &tls.Config{}, &quic.Config{})
	lm.OnQUICHandshakeDone("1.2.3.4", &tls.Config{}, &quic.Config{},
		12*time.Millisecond, nil, errors.New("x"))
	lm.OnQUICHandshakeDone("1.2.3.4", &tls.Config{}, &quic.Config{},
		12*time.Millisecond, &quicEarlySession{}, nil)
}
