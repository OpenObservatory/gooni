package engine

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"syscall"
	"testing"

	"github.com/apex/log"
	"github.com/google/go-cmp/cmp"
	"github.com/ooni/probe-cli/v3/internal/engine/geolocate"
	"github.com/ooni/probe-cli/v3/internal/engine/model"
	"github.com/ooni/probe-cli/v3/internal/engine/probeservices"
	"github.com/ooni/probe-cli/v3/internal/iox"
	"github.com/ooni/probe-cli/v3/internal/version"
)

func TestSessionByteCounter(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	s := newSessionForTesting(t)
	client := s.DefaultHTTPClient()
	resp, err := client.Get("https://www.google.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	ctx := context.Background()
	if _, err := iox.CopyContext(ctx, io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if s.KibiBytesSent() <= 0 || s.KibiBytesReceived() <= 0 {
		t.Fatal("byte counter is not working")
	}
}

func TestNewSessionBuilderChecks(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	t.Run("with no settings", func(t *testing.T) {
		newSessionMustFail(t, SessionConfig{})
	})
	t.Run("with also logger", func(t *testing.T) {
		newSessionMustFail(t, SessionConfig{
			Logger: model.DiscardLogger,
		})
	})
	t.Run("with also software name", func(t *testing.T) {
		newSessionMustFail(t, SessionConfig{
			Logger:       model.DiscardLogger,
			SoftwareName: "ooniprobe-engine",
		})
	})
	t.Run("with software version and wrong tempdir", func(t *testing.T) {
		newSessionMustFail(t, SessionConfig{
			Logger:          model.DiscardLogger,
			SoftwareName:    "ooniprobe-engine",
			SoftwareVersion: "0.0.1",
			TempDir:         "./nonexistent",
		})
	})
}

func TestNewSessionBuilderGood(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	newSessionForTesting(t)
}

func newSessionMustFail(t *testing.T, config SessionConfig) {
	sess, err := NewSession(context.Background(), config)
	if err == nil {
		t.Fatal("expected an error here")
	}
	if sess != nil {
		t.Fatal("expected nil session here")
	}
}

func TestSessionTorArgsTorBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	sess, err := NewSession(context.Background(), SessionConfig{
		AvailableProbeServices: []model.Service{{
			Address: "https://ams-pg-test.ooni.org",
			Type:    "https",
		}},
		Logger:          model.DiscardLogger,
		SoftwareName:    "ooniprobe-engine",
		SoftwareVersion: "0.0.1",
		TorArgs:         []string{"antani1", "antani2", "antani3"},
		TorBinary:       "mascetti",
	})
	if err != nil {
		t.Fatal(err)
	}
	if sess.TorBinary() != "mascetti" {
		t.Fatal("not the TorBinary we expected")
	}
	if len(sess.TorArgs()) != 3 {
		t.Fatal("not the TorArgs length we expected")
	}
	if sess.TorArgs()[0] != "antani1" {
		t.Fatal("not the TorArgs[0] we expected")
	}
	if sess.TorArgs()[1] != "antani2" {
		t.Fatal("not the TorArgs[1] we expected")
	}
	if sess.TorArgs()[2] != "antani3" {
		t.Fatal("not the TorArgs[2] we expected")
	}
}

func newSessionForTestingNoLookupsWithProxyURL(t *testing.T, URL *url.URL) *Session {
	sess, err := NewSession(context.Background(), SessionConfig{
		AvailableProbeServices: []model.Service{{
			Address: "https://ams-pg-test.ooni.org",
			Type:    "https",
		}},
		Logger:          model.DiscardLogger,
		ProxyURL:        URL,
		SoftwareName:    "ooniprobe-engine",
		SoftwareVersion: "0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

func newSessionForTestingNoLookups(t *testing.T) *Session {
	return newSessionForTestingNoLookupsWithProxyURL(t, nil)
}

func newSessionForTestingNoBackendsLookup(t *testing.T) *Session {
	sess := newSessionForTestingNoLookups(t)
	if err := sess.MaybeLookupLocation(); err != nil {
		t.Fatal(err)
	}
	log.Infof("Platform: %s", sess.Platform())
	log.Infof("ProbeASN: %d", sess.ProbeASN())
	log.Infof("ProbeASNString: %s", sess.ProbeASNString())
	log.Infof("ProbeCC: %s", sess.ProbeCC())
	log.Infof("ProbeIP: %s", sess.ProbeIP())
	log.Infof("ProbeNetworkName: %s", sess.ProbeNetworkName())
	log.Infof("ResolverASN: %d", sess.ResolverASN())
	log.Infof("ResolverASNString: %s", sess.ResolverASNString())
	log.Infof("ResolverIP: %s", sess.ResolverIP())
	log.Infof("ResolverNetworkName: %s", sess.ResolverNetworkName())
	return sess
}

func newSessionForTesting(t *testing.T) *Session {
	sess := newSessionForTestingNoBackendsLookup(t)
	if err := sess.MaybeLookupBackends(); err != nil {
		t.Fatal(err)
	}
	return sess
}

func TestInitOrchestraClientMaybeRegisterError(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // so we fail immediately
	sess := newSessionForTestingNoLookups(t)
	defer sess.Close()
	clnt, err := probeservices.NewClient(sess, model.Service{
		Address: "https://ams-pg-test.ooni.org/",
		Type:    "https",
	})
	if err != nil {
		t.Fatal(err)
	}
	outclnt, err := sess.initOrchestraClient(
		ctx, clnt, clnt.MaybeLogin,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("not the error we expected")
	}
	if outclnt != nil {
		t.Fatal("expected a nil client here")
	}
}

func TestInitOrchestraClientMaybeLoginError(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	ctx := context.Background()
	sess := newSessionForTestingNoLookups(t)
	defer sess.Close()
	clnt, err := probeservices.NewClient(sess, model.Service{
		Address: "https://ams-pg-test.ooni.org/",
		Type:    "https",
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := errors.New("mocked error")
	outclnt, err := sess.initOrchestraClient(
		ctx, clnt, func(context.Context) error {
			return expected
		},
	)
	if !errors.Is(err, expected) {
		t.Fatal("not the error we expected")
	}
	if outclnt != nil {
		t.Fatal("expected a nil client here")
	}
}

func TestBouncerError(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	// Combine proxy testing with a broken proxy with errors
	// in reaching out to the bouncer.
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
		},
	))
	defer server.Close()
	URL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	sess := newSessionForTestingNoLookupsWithProxyURL(t, URL)
	defer sess.Close()
	if sess.ProxyURL() == nil {
		t.Fatal("expected to see explicit proxy here")
	}
	if err := sess.MaybeLookupBackends(); err == nil {
		t.Fatal("expected an error here")
	}
}

func TestMaybeLookupBackendsNewClientError(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	sess := newSessionForTestingNoLookups(t)
	sess.availableProbeServices = []model.Service{{
		Type:    "onion",
		Address: "httpo://jehhrikjjqrlpufu.onion",
	}}
	defer sess.Close()
	err := sess.MaybeLookupBackends()
	if !errors.Is(err, ErrAllProbeServicesFailed) {
		t.Fatal("not the error we expected")
	}
}

func TestSessionLocationLookup(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	sess := newSessionForTestingNoLookups(t)
	defer sess.Close()
	if err := sess.MaybeLookupLocation(); err != nil {
		t.Fatal(err)
	}
	if sess.ProbeASNString() == geolocate.DefaultProbeASNString {
		t.Fatal("unexpected ProbeASNString")
	}
	if sess.ProbeASN() == geolocate.DefaultProbeASN {
		t.Fatal("unexpected ProbeASN")
	}
	if sess.ProbeCC() == geolocate.DefaultProbeCC {
		t.Fatal("unexpected ProbeCC")
	}
	if sess.ProbeIP() == geolocate.DefaultProbeIP {
		t.Fatal("unexpected ProbeIP")
	}
	if sess.ProbeNetworkName() == geolocate.DefaultProbeNetworkName {
		t.Fatal("unexpected ProbeNetworkName")
	}
	if sess.ResolverASN() == geolocate.DefaultResolverASN {
		t.Fatal("unexpected ResolverASN")
	}
	if sess.ResolverASNString() == geolocate.DefaultResolverASNString {
		t.Fatal("unexpected ResolverASNString")
	}
	if sess.ResolverIP() == geolocate.DefaultResolverIP {
		t.Fatal("unexpected ResolverIP")
	}
	if sess.ResolverNetworkName() == geolocate.DefaultResolverNetworkName {
		t.Fatal("unexpected ResolverNetworkName")
	}
}

func TestSessionCheckInWithRealAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	sess := newSessionForTesting(t)
	defer sess.Close()
	results, err := sess.CheckIn(context.Background(), &model.CheckInConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if results == nil {
		t.Fatal("expected non nil results here")
	}
}

func TestSessionCloseCancelsTempDir(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	sess := newSessionForTestingNoLookups(t)
	tempDir := sess.TempDir()
	if _, err := os.Stat(tempDir); err != nil {
		t.Fatal(err)
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tempDir); !errors.Is(err, syscall.ENOENT) {
		t.Fatal("not the error we expected")
	}
}

func TestGetAvailableProbeServices(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	sess, err := NewSession(context.Background(), SessionConfig{
		Logger:          model.DiscardLogger,
		SoftwareName:    "ooniprobe-engine",
		SoftwareVersion: "0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	all := sess.GetAvailableProbeServices()
	diff := cmp.Diff(all, probeservices.Default())
	if diff != "" {
		t.Fatal(diff)
	}
}

func TestMaybeLookupBackendsFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	sess, err := NewSession(context.Background(), SessionConfig{
		Logger:          model.DiscardLogger,
		SoftwareName:    "ooniprobe-engine",
		SoftwareVersion: "0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // so we fail immediately
	err = sess.MaybeLookupBackendsContext(ctx)
	if !errors.Is(err, ErrAllProbeServicesFailed) {
		t.Fatal("unexpected error")
	}
}

func TestMaybeLookupTestHelpersIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	sess, err := NewSession(context.Background(), SessionConfig{
		Logger:          model.DiscardLogger,
		SoftwareName:    "ooniprobe-engine",
		SoftwareVersion: "0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	ctx := context.Background()
	if err = sess.MaybeLookupBackendsContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err = sess.MaybeLookupBackendsContext(ctx); err != nil {
		t.Fatal(err)
	}
	if sess.QueryProbeServicesCount() != 1 {
		t.Fatal("unexpected number of queries sent to the bouncer")
	}
}

func TestAllProbeServicesUnsupported(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	sess, err := NewSession(context.Background(), SessionConfig{
		Logger:          model.DiscardLogger,
		SoftwareName:    "ooniprobe-engine",
		SoftwareVersion: "0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	sess.AppendAvailableProbeService(model.Service{
		Address: "mascetti",
		Type:    "antani",
	})
	err = sess.MaybeLookupBackends()
	if !errors.Is(err, ErrAllProbeServicesFailed) {
		t.Fatal("unexpected error")
	}
}

func TestUserAgentNoProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	expect := "ooniprobe-engine/0.0.1 ooniprobe-engine/" + version.Version
	sess := newSessionForTestingNoLookups(t)
	ua := sess.UserAgent()
	diff := cmp.Diff(expect, ua)
	if diff != "" {
		t.Fatal(diff)
	}
}

func TestNewOrchestraClientMaybeLookupBackendsFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	errMocked := errors.New("mocked error")
	sess := newSessionForTestingNoLookups(t)
	sess.testMaybeLookupBackendsContext = func(ctx context.Context) error {
		return errMocked
	}
	client, err := sess.NewOrchestraClient(context.Background())
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if client != nil {
		t.Fatal("expected nil client here")
	}
}

func TestNewOrchestraClientMaybeLookupLocationFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	errMocked := errors.New("mocked error")
	sess := newSessionForTestingNoLookups(t)
	sess.testMaybeLookupLocationContext = func(ctx context.Context) error {
		return errMocked
	}
	client, err := sess.NewOrchestraClient(context.Background())
	if !errors.Is(err, errMocked) {
		t.Fatalf("not the error we expected: %+v", err)
	}
	if client != nil {
		t.Fatal("expected nil client here")
	}
}

func TestNewOrchestraClientProbeServicesNewClientFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	sess := newSessionForTestingNoLookups(t)
	sess.selectedProbeServiceHook = func(svc *model.Service) {
		svc.Type = "antani" // should really not be supported for a long time
	}
	client, err := sess.NewOrchestraClient(context.Background())
	if !errors.Is(err, probeservices.ErrUnsupportedEndpoint) {
		t.Fatal("not the error we expected")
	}
	if client != nil {
		t.Fatal("expected nil client here")
	}
}

func TestSessionNewSubmitterReturnsNonNilSubmitter(t *testing.T) {
	sess := newSessionForTesting(t)
	subm, err := sess.NewSubmitter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if subm == nil {
		t.Fatal("expected non nil submitter here")
	}
}

func TestSessionFetchURLList(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	sess := newSessionForTesting(t)
	resp, err := sess.FetchURLList(context.Background(), model.URLListConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response here")
	}
}
