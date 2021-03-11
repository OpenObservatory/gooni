package oonimkall

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/ooni/probe-cli/v3/internal/engine/model"
)

func TestWebConnectivityRunnerWithMaybeLookupBackendsFailure(t *testing.T) {
	errMocked := errors.New("mocked error")
	sess := &FakeExperimentSession{LookupBackendsErr: errMocked}
	runner := &webConnectivityRunner{sess: sess}
	ctx := context.Background()
	config := &WebConnectivityConfig{
		Input: "https://ooni.org",
	}
	out, err := runner.run(ctx, config)
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if out != nil {
		t.Fatal("expected nil here")
	}
	if sess.LockCount != 1 || sess.UnlockCount != 1 {
		t.Fatal("invalid locking pattern")
	}
}

func TestWebConnectivityRunnerWithMaybeLookupLocationFailure(t *testing.T) {
	errMocked := errors.New("mocked error")
	sess := &FakeExperimentSession{LookupLocationErr: errMocked}
	runner := &webConnectivityRunner{sess: sess}
	ctx := context.Background()
	config := &WebConnectivityConfig{
		Input: "https://ooni.org",
	}
	out, err := runner.run(ctx, config)
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if out != nil {
		t.Fatal("expected nil here")
	}
	if sess.LockCount != 1 || sess.UnlockCount != 1 {
		t.Fatal("invalid locking pattern")
	}
}

func TestWebConnectivityRunnerWithNewExperimentBuilderFailure(t *testing.T) {
	errMocked := errors.New("mocked error")
	sess := &FakeExperimentSession{NewExperimentBuilderErr: errMocked}
	runner := &webConnectivityRunner{sess: sess}
	ctx := context.Background()
	config := &WebConnectivityConfig{
		Input: "https://ooni.org",
	}
	out, err := runner.run(ctx, config)
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if out != nil {
		t.Fatal("expected nil here")
	}
	if sess.LockCount != 1 || sess.UnlockCount != 1 {
		t.Fatal("invalid locking pattern")
	}
}

func TestWebConnectivityRunnerWithMeasureFailure(t *testing.T) {
	errMocked := errors.New("mocked error")
	cbs := &FakeExperimentCallbacks{}
	e := &FakeExperiment{Err: errMocked}
	eb := &FakeExperimentBuilder{Experiment: e}
	sess := &FakeExperimentSession{ExperimentBuilder: eb}
	runner := &webConnectivityRunner{sess: sess}
	ctx := context.Background()
	config := &WebConnectivityConfig{
		Callbacks: cbs,
		Input:     "https://ooni.org",
	}
	out, err := runner.run(ctx, config)
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if out != nil {
		t.Fatal("expected nil here")
	}
	if sess.LockCount != 1 || sess.UnlockCount != 1 {
		t.Fatal("invalid locking pattern")
	}
	if eb.Callbacks != cbs {
		t.Fatal("unexpected callbacks")
	}
}

func TestWebConnectivityRunnerWithNoError(t *testing.T) {
	m := &model.Measurement{Input: "https://ooni.org"}
	cbs := &FakeExperimentCallbacks{}
	e := &FakeExperiment{Measurement: m, Sent: 10, Received: 128}
	eb := &FakeExperimentBuilder{Experiment: e}
	sess := &FakeExperimentSession{ExperimentBuilder: eb}
	runner := &webConnectivityRunner{sess: sess}
	ctx := context.Background()
	config := &WebConnectivityConfig{
		Callbacks: cbs,
		Input:     "https://ooni.org",
	}
	out, err := runner.run(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if out == nil {
		t.Fatal("expected non-nil here")
	}
	if sess.LockCount != 1 || sess.UnlockCount != 1 {
		t.Fatal("invalid locking pattern")
	}
	if eb.Callbacks != cbs {
		t.Fatal("unexpected callbacks")
	}
	if out.KibiBytesSent != 10 || out.KibiBytesReceived != 128 {
		t.Fatal("invalid bytes sent or received")
	}
	var mm *model.Measurement
	mdata := []byte(out.Measurement)
	if err := json.Unmarshal(mdata, &mm); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(m, mm); diff != "" {
		t.Fatal(diff)
	}
}

func TestWebConnectivityRunWithCancelledContext(t *testing.T) {
	sess, err := NewSession(&SessionConfig{
		AssetsDir:        "../testdata/oonimkall/assets",
		ProbeServicesURL: "https://ams-pg-test.ooni.org/",
		SoftwareName:     "oonimkall-test",
		SoftwareVersion:  "0.1.0",
		StateDir:         "../testdata/oonimkall/state",
		TempDir:          "../testdata/",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := sess.NewContext()
	ctx.Cancel() // kill it immediately
	out, err := sess.WebConnectivity(ctx, &WebConnectivityConfig{})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("not the error we expected", err)
	}
	if out != nil {
		t.Fatal("expected nil output here")
	}
}
