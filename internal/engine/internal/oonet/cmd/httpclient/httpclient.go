// Command http2client is an HTTP2 client with parroting.
package main

import (
	"context"
	"flag"
	"io/ioutil"
	"net/http"

	"github.com/apex/log"
	"github.com/ooni/probe-cli/v3/internal/engine/internal/oonet"
)

func main() {
	log.SetLevel(log.DebugLevel)
	url := flag.String("url", "", "DoH server URL")
	flag.Parse()
	if *url == "" {
		log.Fatal("-url is mandatory")
	}
	monitor := &oonet.LogMonitor{}
	ctx := oonet.WithMonitor(context.Background(), monitor) // tracing: ON
	req, err := http.NewRequestWithContext(ctx, "GET", *url, nil)
	if err != nil {
		log.WithError(err).Fatal("http.NewRequestWithContext failed")
	}
	resp, err := oonet.HTTPXDefaultClient.Do(req)
	if err != nil {
		log.WithError(err).Fatal("oonet.HTTPXDefaultClient.Do failed")
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Fatal("ioutil.ReadAll failed")
	}
	log.Infof("fetched %d bytes", len(data))
}
