// Code generated by go generate; DO NOT EDIT.
// 2021-02-23 23:42:25.561774 +0100 CET m=+2.375200008

package ooapi

//go:generate go run ./internal/generator

import (
	"context"
	"sync/atomic"

	"github.com/ooni/probe-cli/v3/internal/engine/ooapi/apimodel"
)

type FakeCheckReportIDAPI struct {
	Err       error
	Response  *apimodel.CheckReportIDResponse
	CountCall int32
}

func (fapi *FakeCheckReportIDAPI) Call(ctx context.Context, req *apimodel.CheckReportIDRequest) (*apimodel.CheckReportIDResponse, error) {
	atomic.AddInt32(&fapi.CountCall, 1)
	return fapi.Response, fapi.Err
}

var (
	_ CheckReportIDCaller = &FakeCheckReportIDAPI{}
)

type FakeCheckInAPI struct {
	Err       error
	Response  *apimodel.CheckInResponse
	CountCall int32
}

func (fapi *FakeCheckInAPI) Call(ctx context.Context, req *apimodel.CheckInRequest) (*apimodel.CheckInResponse, error) {
	atomic.AddInt32(&fapi.CountCall, 1)
	return fapi.Response, fapi.Err
}

var (
	_ CheckInCaller = &FakeCheckInAPI{}
)

type FakeLoginAPI struct {
	Err       error
	Response  *apimodel.LoginResponse
	CountCall int32
}

func (fapi *FakeLoginAPI) Call(ctx context.Context, req *apimodel.LoginRequest) (*apimodel.LoginResponse, error) {
	atomic.AddInt32(&fapi.CountCall, 1)
	return fapi.Response, fapi.Err
}

var (
	_ LoginCaller = &FakeLoginAPI{}
)

type FakeMeasurementMetaAPI struct {
	Err       error
	Response  *apimodel.MeasurementMetaResponse
	CountCall int32
}

func (fapi *FakeMeasurementMetaAPI) Call(ctx context.Context, req *apimodel.MeasurementMetaRequest) (*apimodel.MeasurementMetaResponse, error) {
	atomic.AddInt32(&fapi.CountCall, 1)
	return fapi.Response, fapi.Err
}

var (
	_ MeasurementMetaCaller = &FakeMeasurementMetaAPI{}
)

type FakeRegisterAPI struct {
	Err       error
	Response  *apimodel.RegisterResponse
	CountCall int32
}

func (fapi *FakeRegisterAPI) Call(ctx context.Context, req *apimodel.RegisterRequest) (*apimodel.RegisterResponse, error) {
	atomic.AddInt32(&fapi.CountCall, 1)
	return fapi.Response, fapi.Err
}

var (
	_ RegisterCaller = &FakeRegisterAPI{}
)

type FakeTestHelpersAPI struct {
	Err       error
	Response  apimodel.TestHelpersResponse
	CountCall int32
}

func (fapi *FakeTestHelpersAPI) Call(ctx context.Context, req *apimodel.TestHelpersRequest) (apimodel.TestHelpersResponse, error) {
	atomic.AddInt32(&fapi.CountCall, 1)
	return fapi.Response, fapi.Err
}

var (
	_ TestHelpersCaller = &FakeTestHelpersAPI{}
)

type FakePsiphonConfigAPI struct {
	WithResult PsiphonConfigCaller
	Err        error
	Response   apimodel.PsiphonConfigResponse
	CountCall  int32
}

func (fapi *FakePsiphonConfigAPI) Call(ctx context.Context, req *apimodel.PsiphonConfigRequest) (apimodel.PsiphonConfigResponse, error) {
	atomic.AddInt32(&fapi.CountCall, 1)
	return fapi.Response, fapi.Err
}

func (fapi *FakePsiphonConfigAPI) WithToken(token string) PsiphonConfigCaller {
	return fapi.WithResult
}

var (
	_ PsiphonConfigCaller = &FakePsiphonConfigAPI{}
	_ PsiphonConfigCloner = &FakePsiphonConfigAPI{}
)

type FakeTorTargetsAPI struct {
	WithResult TorTargetsCaller
	Err        error
	Response   apimodel.TorTargetsResponse
	CountCall  int32
}

func (fapi *FakeTorTargetsAPI) Call(ctx context.Context, req *apimodel.TorTargetsRequest) (apimodel.TorTargetsResponse, error) {
	atomic.AddInt32(&fapi.CountCall, 1)
	return fapi.Response, fapi.Err
}

func (fapi *FakeTorTargetsAPI) WithToken(token string) TorTargetsCaller {
	return fapi.WithResult
}

var (
	_ TorTargetsCaller = &FakeTorTargetsAPI{}
	_ TorTargetsCloner = &FakeTorTargetsAPI{}
)

type FakeURLsAPI struct {
	Err       error
	Response  *apimodel.URLsResponse
	CountCall int32
}

func (fapi *FakeURLsAPI) Call(ctx context.Context, req *apimodel.URLsRequest) (*apimodel.URLsResponse, error) {
	atomic.AddInt32(&fapi.CountCall, 1)
	return fapi.Response, fapi.Err
}

var (
	_ URLsCaller = &FakeURLsAPI{}
)

type FakeOpenReportAPI struct {
	Err       error
	Response  *apimodel.OpenReportResponse
	CountCall int32
}

func (fapi *FakeOpenReportAPI) Call(ctx context.Context, req *apimodel.OpenReportRequest) (*apimodel.OpenReportResponse, error) {
	atomic.AddInt32(&fapi.CountCall, 1)
	return fapi.Response, fapi.Err
}

var (
	_ OpenReportCaller = &FakeOpenReportAPI{}
)

type FakeSubmitMeasurementAPI struct {
	Err       error
	Response  *apimodel.SubmitMeasurementResponse
	CountCall int32
}

func (fapi *FakeSubmitMeasurementAPI) Call(ctx context.Context, req *apimodel.SubmitMeasurementRequest) (*apimodel.SubmitMeasurementResponse, error) {
	atomic.AddInt32(&fapi.CountCall, 1)
	return fapi.Response, fapi.Err
}

var (
	_ SubmitMeasurementCaller = &FakeSubmitMeasurementAPI{}
)
