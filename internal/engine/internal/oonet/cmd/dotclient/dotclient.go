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
	timeout := flag.Duration("timeout", 4*time.Second, "DNS timeout")
	addr := flag.String("addr", "", "DoT server address")
	domain := flag.String("domain", "example.com", "Domain to resolve")
	flag.Parse()
	if *addr == "" {
		log.Fatal("-addr is mandatory")
	}
	monitor := &oonet.LogMonitor{}
	ctx := oonet.WithMonitor(context.Background(), monitor) // tracing: ON
	resolver := &oonet.DNSResolver{
		UnderlyingResolver: &oonet.DNSOverUDPResolver{
			Address: *addr,
		},
	}
	defer resolver.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	addrs, err := resolver.LookupHost(ctx, *domain)
	if err != nil {
		log.WithError(err).Fatal("LookupHost failed")
	}
	for _, addr := range addrs {
		log.Infof("- %s", addr)
	}
}
