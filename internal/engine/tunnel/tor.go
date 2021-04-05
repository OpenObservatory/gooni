package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/cretz/bine/tor"
)

// torProcess is a running tor process.
type torProcess interface {
	io.Closer
}

// torTunnel is the Tor tunnel
type torTunnel struct {
	// bootstrapTime is the duration of the bootstrap
	bootstrapTime time.Duration

	// instance is the running tor instance
	instance torProcess

	// proxy is the SOCKS5 proxy URL
	proxy *url.URL
}

// BootstrapTime returns the bootstrap time
func (tt *torTunnel) BootstrapTime() time.Duration {
	return tt.bootstrapTime
}

// SOCKS5ProxyURL returns the URL of the SOCKS5 proxy
func (tt *torTunnel) SOCKS5ProxyURL() *url.URL {
	return tt.proxy
}

// Stop stops the Tor tunnel
func (tt *torTunnel) Stop() {
	tt.instance.Close()
}

// TODO(bassosimone): the current design is such that we have a bunch of
// torrc-$number and a growing tor.log file inside of stateDir.

// ErrTorUnableToGetSOCKSProxyAddress indicates that we could not
// get the SOCKS proxy address via the control port.
var ErrTorUnableToGetSOCKSProxyAddress = errors.New(
	"unable to get socks proxy address")

// ErrTorReturnedUnsupportedProxy indicates that tor returned to
// us the address of a proxy that we don't support.
var ErrTorReturnedUnsupportedProxy = errors.New(
	"tor returned unsupported proxy")

// torStart starts the tor tunnel.
func torStart(ctx context.Context, config *Config) (Tunnel, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err() // allows to write unit tests using this code
	default:
	}
	if config.TunnelDir == "" {
		return nil, ErrEmptyTunnelDir
	}
	stateDir := filepath.Join(config.TunnelDir, "tor")
	logfile := filepath.Join(stateDir, "tor.log")
	extraArgs := append([]string{}, config.TorArgs...)
	extraArgs = append(extraArgs, "Log")
	extraArgs = append(extraArgs, "notice stderr")
	extraArgs = append(extraArgs, "Log")
	extraArgs = append(extraArgs, fmt.Sprintf(`notice file %s`, logfile))
	instance, err := config.torStart(ctx, &tor.StartConf{
		DataDir:   stateDir,
		ExtraArgs: extraArgs,
		ExePath:   config.TorBinary,
		NoHush:    true,
	})
	if err != nil {
		return nil, err
	}
	instance.StopProcessOnClose = true
	start := time.Now()
	if err := config.torEnableNetwork(ctx, instance, true); err != nil {
		instance.Close()
		return nil, err
	}
	stop := time.Now()
	// Adapted from <https://git.io/Jfc7N>
	info, err := config.torGetInfo(instance.Control, "net/listeners/socks")
	if err != nil {
		instance.Close()
		return nil, err
	}
	if len(info) != 1 || info[0].Key != "net/listeners/socks" {
		instance.Close()
		return nil, ErrTorUnableToGetSOCKSProxyAddress
	}
	proxyAddress := info[0].Val
	if strings.HasPrefix(proxyAddress, "unix:") {
		instance.Close()
		return nil, ErrTorReturnedUnsupportedProxy
	}
	return &torTunnel{
		bootstrapTime: stop.Sub(start),
		instance:      instance,
		proxy:         &url.URL{Scheme: "socks5", Host: proxyAddress},
	}, nil
}
