// Code generated by go generate; DO NOT EDIT.
// 2021-02-23 23:33:19.13434 +0100 CET m=+1.767707138

package ooapi

//go:generate go run ./internal/generator

import (
	"context"

	"github.com/ooni/probe-cli/v3/internal/engine/ooapi/apimodel"
)

// CheckReportIDCaller abstracts CheckReportIDAPI caller behavior.
type CheckReportIDCaller interface {
	Call(ctx context.Context, req *apimodel.CheckReportIDRequest) (*apimodel.CheckReportIDResponse, error)
}

// CheckInCaller abstracts CheckInAPI caller behavior.
type CheckInCaller interface {
	Call(ctx context.Context, req *apimodel.CheckInRequest) (*apimodel.CheckInResponse, error)
}

// LoginCaller abstracts LoginAPI caller behavior.
type LoginCaller interface {
	Call(ctx context.Context, req *apimodel.LoginRequest) (*apimodel.LoginResponse, error)
}

// MeasurementMetaCaller abstracts MeasurementMetaAPI caller behavior.
type MeasurementMetaCaller interface {
	Call(ctx context.Context, req *apimodel.MeasurementMetaRequest) (*apimodel.MeasurementMetaResponse, error)
}

// RegisterCaller abstracts RegisterAPI caller behavior.
type RegisterCaller interface {
	Call(ctx context.Context, req *apimodel.RegisterRequest) (*apimodel.RegisterResponse, error)
}

// TestHelpersCaller abstracts TestHelpersAPI caller behavior.
type TestHelpersCaller interface {
	Call(ctx context.Context, req *apimodel.TestHelpersRequest) (apimodel.TestHelpersResponse, error)
}

// PsiphonConfigCaller abstracts PsiphonConfigAPI caller behavior.
type PsiphonConfigCaller interface {
	Call(ctx context.Context, req *apimodel.PsiphonConfigRequest) (apimodel.PsiphonConfigResponse, error)
}

// TorTargetsCaller abstracts TorTargetsAPI caller behavior.
type TorTargetsCaller interface {
	Call(ctx context.Context, req *apimodel.TorTargetsRequest) (apimodel.TorTargetsResponse, error)
}

// URLsCaller abstracts URLsAPI caller behavior.
type URLsCaller interface {
	Call(ctx context.Context, req *apimodel.URLsRequest) (*apimodel.URLsResponse, error)
}

// OpenReportCaller abstracts OpenReportAPI caller behavior.
type OpenReportCaller interface {
	Call(ctx context.Context, req *apimodel.OpenReportRequest) (*apimodel.OpenReportResponse, error)
}

// SubmitMeasurementCaller abstracts SubmitMeasurementAPI caller behavior.
type SubmitMeasurementCaller interface {
	Call(ctx context.Context, req *apimodel.SubmitMeasurementRequest) (*apimodel.SubmitMeasurementResponse, error)
}
