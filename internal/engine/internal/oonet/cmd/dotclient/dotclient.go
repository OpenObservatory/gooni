// Command dotclient is an example dotclient.
package main

import (
	"context"
	"flag"
	"time"

	"github.com/apex/log"
	"github.com/ooni/probe-cli/v3/internal/engine/internal/oonet"
)

func main() {
	log.SetLevel(log.DebugLevel)
	timeout := flag.Duration("timeout", 15*time.Second, "DNS timeout")
	addr := flag.String("addr", "", "DoT server address")
	domain := flag.String("domain", "example.com", "Domain to resolve")
	flag.Parse()
	if *addr == "" {
		log.Fatal("-addr is mandatory")
	}
	monitor := &oonet.LogMonitor{}
	ctx := oonet.WithMonitor(context.Background(), monitor) // tracing: ON
	resolver := &oonet.DNSResolver{
		Transport: oonet.NewDNSOverTLSTransport(*addr),
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	addrs, err := resolver.LookupHost(ctx, *domain)
	if err != nil {
		log.WithError(err).Fatal("LookupHost failed")
	}
	for _, addr := range addrs {
		log.Infof("- %s", addr)
	}
	resolver.CloseIdleConnections()
	time.Sleep(1 * time.Second)
}
