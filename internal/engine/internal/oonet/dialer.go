package oonet

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/bassosimone/quic-go"
	"github.com/ooni/probe-cli/v3/internal/engine/netx"
)

// DialerDNSResolver is the DNSResolver used by a Dialer.
type DialerDNSResolver interface {
	// LookupHost should behave like net.Resolver.LookupHost.
	LookupHost(ctx context.Context, hostname string) ([]string, error)
}

// DialerTCPConnector is the TCPConnector used by a Dialer.
type DialerTCPConnector interface {
	// DialContext should behave like net.Dialer.DialContext.
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DialerTLSHandshaker is the TLSHandshaker used by a Dialer.
type DialerTLSHandshaker interface {
	// TLSHandshake should behave like TLSHandshaker.TLSHandshake.
	TLSHandshake(
		ctx context.Context, conn net.Conn, config *tls.Config) (net.Conn, error)
}

// DialerQUICHandshaker is the QUICHandshaker used by a Dialer.
type DialerQUICHandshaker interface {
	// DialEarlyContext should behave like QUICHandshaker.DialEarlyContext.
	DialEarlyContext(ctx context.Context, address string,
		tlsConf *tls.Config, quicConf *quic.Config) (quic.EarlySession, error)
}

// Dialer performs domain name resolutions and attempts to
// create several kind of connections (cleartext, TLS,
// and QUIC). To this end, it will iterate over the available
// IP addresses and attempt all of them, until it finds
// an IP address that works.
//
// When your objective is performing exhaustive measurements
// aiming at finding everything that is blocked, you SHOULD
// NOT use a Dialer. If some IP addresses are censored and
// some other IP addresses are not, the Dialer may be lucky
// and one of the addresses that works.
//
// What's more, the Dialer will hide partial failures. For
// example, if the first IP address is down (or maybe censored)
// and the second one works, the Dialer will return success.
//
// You MUST NOT modify any field of Dialer after construction
// because this MAY result in a data race.
type Dialer struct {
	// ALPN contains optional configuration for ALPN when
	// performing the TLS handshake. If TLSConfig is not set
	// or its NextProtos field is not set _and_ this field
	// is set, then we use the value of this field.
	ALPN []string

	// DNSResolver is the optional DNSResolver to
	// use. If not is set, we use a default initialized
	// DNSResolver instance.
	DNSResolver DialerDNSResolver

	// QUICConfig is the optional QUIC config. If not set,
	// then we will use an empty config.
	QUICConfig *quic.Config

	// QUICHandshaker is the optional QUICHandshaker
	// to use. If not set we will use a default
	// initialized QUICHandshaker instance.
	QUICHandshaker DialerQUICHandshaker

	// SNI contains the optional SNI for the TLS handshake. We
	// will give preference to TLSConfig.ServerName (if TLSConfig
	// is set). Otherwise, we use this value, if set. Otherwise,
	// we will use the domain name inside the address.
	SNI string

	// TCPConnector is the optional TCPConnector to
	// use. If not is set, we use a default initialized
	// TCPConnector instance.
	TCPConnector DialerTCPConnector

	// TLSConfig is the tls.Config template. If not set,
	// we will use default values. See also the documentation
	// of SNI and ALPN (above). As a general note, if this
	// field is set, the settings inside it will take
	// precedence over other settings inside the Dialer.
	TLSConfig *tls.Config

	// TLSHandshaker is the optional TLSHandshaker to
	// use. If not is set, we use a default initialized
	// TLSHandshaker instance.
	TLSHandshaker *TLSHandshaker
}

// ErrDial is an error when dialing.
type ErrDial struct {
	// Errors contains all errors that occurred. They may be one
	// or more errors depending on what has happened.
	Errors []error
}

// Error returns the error string.
func (e *ErrDial) Error() string {
	if len(e.Errors) == 1 {
		return e.Errors[0].Error() // optimisation for better clarity
	}
	return fmt.Sprintf("dial: %+v", e.Errors)
}

// DialContext dials a (typically-TCP) connection.
func (d *Dialer) DialContext(
	ctx context.Context, network, address string) (net.Conn, error) {
	dw, err := d.newDialerWorker(network, address)
	if err != nil {
		return nil, err // already wrapped
	}
	return dw.dial(ctx) // error already wrapped
}

// DialTLSContext dials a TLS connection.
func (d *Dialer) DialTLSContext(
	ctx context.Context, network, address string) (net.Conn, error) {
	dw, err := d.newDialerWorker(network, address)
	if err != nil {
		return nil, err // already wrapped
	}
	return dw.dialTLS(ctx) // error already wrapped
}

// DialQUIC creates a new QUIC session.
func (d *Dialer) DialQUIC(ctx context.Context, address string) (quic.EarlySession, error) {
	dw, err := d.newDialerWorker("udp", address)
	if err != nil {
		return nil, err // already wrapped
	}
	return dw.dialQUIC(ctx) // error already wrapped
}

// dialerWorker implements Dialer.
type dialerWorker struct {
	// address is the argument to the DialXXX function.
	address string

	// dialer is the dialer we're using.
	dialer *Dialer

	// hostname is the hostname inside address.
	hostname string

	// network is the argument to the DialXXX function.
	network string

	// port is the port inside address.
	port string
}

// newDialerWorker creates a new dialerWorker. The returned error is already
// an instance of ErrDial, so you MUST NOT wrap it again.
func (d *Dialer) newDialerWorker(network, address string) (*dialerWorker, error) {
	hostname, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, &ErrDial{Errors: []error{err}}
	}
	return &dialerWorker{
		address:  address,
		dialer:   d,
		hostname: hostname,
		network:  network,
		port:     port,
	}, nil
}

// dial performs a cleartext dial. The returned error is already
// an instance of ErrDial, so you MUST NOT wrap it again.
func (dw *dialerWorker) dial(ctx context.Context) (net.Conn, error) {
	addrs, err := dw.dialer.dnsResolver().LookupHost(ctx, dw.hostname)
	if err != nil {
		return nil, &ErrDial{Errors: []error{err}}
	}
	allErrors := &ErrDial{}
	for _, addr := range addrs {
		epnt := net.JoinHostPort(addr, dw.port)
		conn, err := dw.dialer.tcpConnector().DialContext(ctx, dw.network, epnt)
		if err != nil {
			allErrors.Errors = append(allErrors.Errors, err)
			continue
		}
		return conn, nil
	}
	return nil, allErrors
}

// dnsResolver returns the DNSResolver to use.
func (d *Dialer) dnsResolver() DialerDNSResolver {
	if d.DNSResolver != nil {
		return d.DNSResolver
	}
	return &DNSResolver{}
}

// tcpConnector returns the TCPConnector to use.
func (d *Dialer) tcpConnector() DialerTCPConnector {
	if d.TCPConnector != nil {
		return d.TCPConnector
	}
	return &TCPConnector{}
}

// dialTLS performs a TLS dial. The returned error is already
// an instance of ErrDial, so you MUST NOT wrap it again.
func (dw *dialerWorker) dialTLS(ctx context.Context) (net.Conn, error) {
	cconn, err := dw.dial(ctx)
	if err != nil {
		return nil, err // already wrapped
	}
	config := dw.dialer.tlsConfig()
	// Settings inside config take precedence. Otherwise we
	// see if we have overrides in Dialer.
	if config.ServerName != "" {
		// nothing
	} else if dw.dialer.SNI != "" {
		config.ServerName = dw.dialer.SNI
	} else {
		config.ServerName = dw.hostname
	}
	if config.NextProtos == nil && dw.dialer.ALPN != nil {
		config.NextProtos = dw.dialer.ALPN
	}
	if config.RootCAs == nil {
		config.RootCAs = netx.NewDefaultCertPool()
	}
	config.DynamicRecordSizingDisabled = true // fingerprinting
	tconn, err := dw.dialer.tlsHandshaker().TLSHandshake(ctx, cconn, config)
	if err != nil {
		return nil, &ErrDial{Errors: []error{err}}
	}
	return tconn, nil
}

// tlsConfig returns the *tls.Config to use.
func (d *Dialer) tlsConfig() *tls.Config {
	if d.TLSConfig != nil {
		return d.TLSConfig.Clone() // mutate a copy
	}
	return &tls.Config{}
}

// tlsHandshaker returns the TLSHandshaker to use.
func (d *Dialer) tlsHandshaker() DialerTLSHandshaker {
	if d.TLSHandshaker != nil {
		return d.TLSHandshaker
	}
	return &TLSHandshaker{}
}

// dialQUIC performs a QUIC dial. The returned error is already
// an instance of ErrDial, so you MUST NOT wrap it again.
func (dw *dialerWorker) dialQUIC(ctx context.Context) (quic.EarlySession, error) {
	tlsConf := dw.dialer.tlsConfig()
	// Settings inside config take precedence. Otherwise we
	// see if we have overrides in Dialer.
	if tlsConf.ServerName != "" {
		// nothing
	} else if dw.dialer.SNI != "" {
		tlsConf.ServerName = dw.dialer.SNI
	} else {
		tlsConf.ServerName = dw.hostname
	}
	if tlsConf.NextProtos == nil && dw.dialer.ALPN != nil {
		tlsConf.NextProtos = dw.dialer.ALPN
	}
	if tlsConf.RootCAs == nil {
		tlsConf.RootCAs = netx.NewDefaultCertPool()
	}
	tlsConf.DynamicRecordSizingDisabled = true // fingerprinting
	quicConf := dw.dialer.quicConfig()
	addrs, err := dw.dialer.dnsResolver().LookupHost(ctx, dw.hostname)
	if err != nil {
		return nil, &ErrDial{Errors: []error{err}}
	}
	allErrors := &ErrDial{}
	for _, addr := range addrs {
		epnt := net.JoinHostPort(addr, dw.port)
		sess, err := dw.dialer.quicHandshaker().DialEarlyContext(
			ctx, epnt, tlsConf, quicConf)
		if err != nil {
			allErrors.Errors = append(allErrors.Errors, err)
			continue
		}
		return sess, nil
	}
	return nil, allErrors
}

// quicConfig returns the *quic.Config to use.
func (d *Dialer) quicConfig() *quic.Config {
	if d.QUICConfig != nil {
		return d.QUICConfig
	}
	return &quic.Config{}
}

// quicHandshaker returns the QUICHandshaker to use.
func (d *Dialer) quicHandshaker() DialerQUICHandshaker {
	if d.QUICHandshaker != nil {
		return d.QUICHandshaker
	}
	return &QUICHandshaker{}
}
