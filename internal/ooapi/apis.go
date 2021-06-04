// Code generated by go generate; DO NOT EDIT.
// 2021-05-12 09:15:00.422051399 +0200 CEST m=+0.000129449

package ooapi

//go:generate go run ./internal/generator -file apis.go

import (
	"context"
	"net/http"

	"github.com/ooni/probe-cli/v3/internal/ooapi/apimodel"
)

// simpleCheckReportIDAPI implements the CheckReportID API.
type simpleCheckReportIDAPI struct {
	BaseURL      string       // optional
	HTTPClient   HTTPClient   // optional
	JSONCodec    JSONCodec    // optional
	RequestMaker RequestMaker // optional
	UserAgent    string       // optional
}

func (api *simpleCheckReportIDAPI) baseURL() string {
	if api.BaseURL != "" {
		return api.BaseURL
	}
	return "https://ps1.ooni.io"
}

func (api *simpleCheckReportIDAPI) requestMaker() RequestMaker {
	if api.RequestMaker != nil {
		return api.RequestMaker
	}
	return &defaultRequestMaker{}
}

func (api *simpleCheckReportIDAPI) jsonCodec() JSONCodec {
	if api.JSONCodec != nil {
		return api.JSONCodec
	}
	return &defaultJSONCodec{}
}

func (api *simpleCheckReportIDAPI) httpClient() HTTPClient {
	if api.HTTPClient != nil {
		return api.HTTPClient
	}
	return http.DefaultClient
}

// Call calls the CheckReportID API.
func (api *simpleCheckReportIDAPI) Call(ctx context.Context, req *apimodel.CheckReportIDRequest) (*apimodel.CheckReportIDResponse, error) {
	httpReq, err := api.newRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Add("Accept", "application/json")
	if api.UserAgent != "" {
		httpReq.Header.Add("User-Agent", api.UserAgent)
	}
	return api.newResponse(api.httpClient().Do(httpReq))
}

// simpleCheckInAPI implements the CheckIn API.
type simpleCheckInAPI struct {
	BaseURL      string       // optional
	HTTPClient   HTTPClient   // optional
	JSONCodec    JSONCodec    // optional
	RequestMaker RequestMaker // optional
	UserAgent    string       // optional
}

func (api *simpleCheckInAPI) baseURL() string {
	if api.BaseURL != "" {
		return api.BaseURL
	}
	return "https://ps1.ooni.io"
}

func (api *simpleCheckInAPI) requestMaker() RequestMaker {
	if api.RequestMaker != nil {
		return api.RequestMaker
	}
	return &defaultRequestMaker{}
}

func (api *simpleCheckInAPI) jsonCodec() JSONCodec {
	if api.JSONCodec != nil {
		return api.JSONCodec
	}
	return &defaultJSONCodec{}
}

func (api *simpleCheckInAPI) httpClient() HTTPClient {
	if api.HTTPClient != nil {
		return api.HTTPClient
	}
	return http.DefaultClient
}

// Call calls the CheckIn API.
func (api *simpleCheckInAPI) Call(ctx context.Context, req *apimodel.CheckInRequest) (*apimodel.CheckInResponse, error) {
	httpReq, err := api.newRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Add("Accept", "application/json")
	if api.UserAgent != "" {
		httpReq.Header.Add("User-Agent", api.UserAgent)
	}
	return api.newResponse(api.httpClient().Do(httpReq))
}

// simpleLoginAPI implements the Login API.
type simpleLoginAPI struct {
	BaseURL      string       // optional
	HTTPClient   HTTPClient   // optional
	JSONCodec    JSONCodec    // optional
	RequestMaker RequestMaker // optional
	UserAgent    string       // optional
}

func (api *simpleLoginAPI) baseURL() string {
	if api.BaseURL != "" {
		return api.BaseURL
	}
	return "https://ps1.ooni.io"
}

func (api *simpleLoginAPI) requestMaker() RequestMaker {
	if api.RequestMaker != nil {
		return api.RequestMaker
	}
	return &defaultRequestMaker{}
}

func (api *simpleLoginAPI) jsonCodec() JSONCodec {
	if api.JSONCodec != nil {
		return api.JSONCodec
	}
	return &defaultJSONCodec{}
}

func (api *simpleLoginAPI) httpClient() HTTPClient {
	if api.HTTPClient != nil {
		return api.HTTPClient
	}
	return http.DefaultClient
}

// Call calls the Login API.
func (api *simpleLoginAPI) Call(ctx context.Context, req *apimodel.LoginRequest) (*apimodel.LoginResponse, error) {
	httpReq, err := api.newRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Add("Accept", "application/json")
	if api.UserAgent != "" {
		httpReq.Header.Add("User-Agent", api.UserAgent)
	}
	return api.newResponse(api.httpClient().Do(httpReq))
}

// simpleMeasurementMetaAPI implements the MeasurementMeta API.
type simpleMeasurementMetaAPI struct {
	BaseURL      string       // optional
	HTTPClient   HTTPClient   // optional
	JSONCodec    JSONCodec    // optional
	RequestMaker RequestMaker // optional
	UserAgent    string       // optional
}

func (api *simpleMeasurementMetaAPI) baseURL() string {
	if api.BaseURL != "" {
		return api.BaseURL
	}
	return "https://ps1.ooni.io"
}

func (api *simpleMeasurementMetaAPI) requestMaker() RequestMaker {
	if api.RequestMaker != nil {
		return api.RequestMaker
	}
	return &defaultRequestMaker{}
}

func (api *simpleMeasurementMetaAPI) jsonCodec() JSONCodec {
	if api.JSONCodec != nil {
		return api.JSONCodec
	}
	return &defaultJSONCodec{}
}

func (api *simpleMeasurementMetaAPI) httpClient() HTTPClient {
	if api.HTTPClient != nil {
		return api.HTTPClient
	}
	return http.DefaultClient
}

// Call calls the MeasurementMeta API.
func (api *simpleMeasurementMetaAPI) Call(ctx context.Context, req *apimodel.MeasurementMetaRequest) (*apimodel.MeasurementMetaResponse, error) {
	httpReq, err := api.newRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Add("Accept", "application/json")
	if api.UserAgent != "" {
		httpReq.Header.Add("User-Agent", api.UserAgent)
	}
	return api.newResponse(api.httpClient().Do(httpReq))
}

// simpleRegisterAPI implements the Register API.
type simpleRegisterAPI struct {
	BaseURL      string       // optional
	HTTPClient   HTTPClient   // optional
	JSONCodec    JSONCodec    // optional
	RequestMaker RequestMaker // optional
	UserAgent    string       // optional
}

func (api *simpleRegisterAPI) baseURL() string {
	if api.BaseURL != "" {
		return api.BaseURL
	}
	return "https://ps1.ooni.io"
}

func (api *simpleRegisterAPI) requestMaker() RequestMaker {
	if api.RequestMaker != nil {
		return api.RequestMaker
	}
	return &defaultRequestMaker{}
}

func (api *simpleRegisterAPI) jsonCodec() JSONCodec {
	if api.JSONCodec != nil {
		return api.JSONCodec
	}
	return &defaultJSONCodec{}
}

func (api *simpleRegisterAPI) httpClient() HTTPClient {
	if api.HTTPClient != nil {
		return api.HTTPClient
	}
	return http.DefaultClient
}

// Call calls the Register API.
func (api *simpleRegisterAPI) Call(ctx context.Context, req *apimodel.RegisterRequest) (*apimodel.RegisterResponse, error) {
	httpReq, err := api.newRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Add("Accept", "application/json")
	if api.UserAgent != "" {
		httpReq.Header.Add("User-Agent", api.UserAgent)
	}
	return api.newResponse(api.httpClient().Do(httpReq))
}

// simpleTestHelpersAPI implements the TestHelpers API.
type simpleTestHelpersAPI struct {
	BaseURL      string       // optional
	HTTPClient   HTTPClient   // optional
	JSONCodec    JSONCodec    // optional
	RequestMaker RequestMaker // optional
	UserAgent    string       // optional
}

func (api *simpleTestHelpersAPI) baseURL() string {
	if api.BaseURL != "" {
		return api.BaseURL
	}
	return "https://ps1.ooni.io"
}

func (api *simpleTestHelpersAPI) requestMaker() RequestMaker {
	if api.RequestMaker != nil {
		return api.RequestMaker
	}
	return &defaultRequestMaker{}
}

func (api *simpleTestHelpersAPI) jsonCodec() JSONCodec {
	if api.JSONCodec != nil {
		return api.JSONCodec
	}
	return &defaultJSONCodec{}
}

func (api *simpleTestHelpersAPI) httpClient() HTTPClient {
	if api.HTTPClient != nil {
		return api.HTTPClient
	}
	return http.DefaultClient
}

// Call calls the TestHelpers API.
func (api *simpleTestHelpersAPI) Call(ctx context.Context, req *apimodel.TestHelpersRequest) (apimodel.TestHelpersResponse, error) {
	httpReq, err := api.newRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Add("Accept", "application/json")
	if api.UserAgent != "" {
		httpReq.Header.Add("User-Agent", api.UserAgent)
	}
	return api.newResponse(api.httpClient().Do(httpReq))
}

// simplePsiphonConfigAPI implements the PsiphonConfig API.
type simplePsiphonConfigAPI struct {
	BaseURL      string       // optional
	HTTPClient   HTTPClient   // optional
	JSONCodec    JSONCodec    // optional
	Token        string       // mandatory
	RequestMaker RequestMaker // optional
	UserAgent    string       // optional
}

// WithToken returns a copy of the API where the
// value of the Token field is replaced with token.
func (api *simplePsiphonConfigAPI) WithToken(token string) callerForPsiphonConfigAPI {
	out := &simplePsiphonConfigAPI{}
	out.BaseURL = api.BaseURL
	out.HTTPClient = api.HTTPClient
	out.JSONCodec = api.JSONCodec
	out.RequestMaker = api.RequestMaker
	out.UserAgent = api.UserAgent
	out.Token = token
	return out
}

func (api *simplePsiphonConfigAPI) baseURL() string {
	if api.BaseURL != "" {
		return api.BaseURL
	}
	return "https://ps1.ooni.io"
}

func (api *simplePsiphonConfigAPI) requestMaker() RequestMaker {
	if api.RequestMaker != nil {
		return api.RequestMaker
	}
	return &defaultRequestMaker{}
}

func (api *simplePsiphonConfigAPI) jsonCodec() JSONCodec {
	if api.JSONCodec != nil {
		return api.JSONCodec
	}
	return &defaultJSONCodec{}
}

func (api *simplePsiphonConfigAPI) httpClient() HTTPClient {
	if api.HTTPClient != nil {
		return api.HTTPClient
	}
	return http.DefaultClient
}

// Call calls the PsiphonConfig API.
func (api *simplePsiphonConfigAPI) Call(ctx context.Context, req *apimodel.PsiphonConfigRequest) (apimodel.PsiphonConfigResponse, error) {
	httpReq, err := api.newRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Add("Accept", "application/json")
	if api.Token == "" {
		return nil, ErrMissingToken
	}
	httpReq.Header.Add("Authorization", newAuthorizationHeader(api.Token))
	if api.UserAgent != "" {
		httpReq.Header.Add("User-Agent", api.UserAgent)
	}
	return api.newResponse(api.httpClient().Do(httpReq))
}

// simpleTorTargetsAPI implements the TorTargets API.
type simpleTorTargetsAPI struct {
	BaseURL      string       // optional
	HTTPClient   HTTPClient   // optional
	JSONCodec    JSONCodec    // optional
	Token        string       // mandatory
	RequestMaker RequestMaker // optional
	UserAgent    string       // optional
}

// WithToken returns a copy of the API where the
// value of the Token field is replaced with token.
func (api *simpleTorTargetsAPI) WithToken(token string) callerForTorTargetsAPI {
	out := &simpleTorTargetsAPI{}
	out.BaseURL = api.BaseURL
	out.HTTPClient = api.HTTPClient
	out.JSONCodec = api.JSONCodec
	out.RequestMaker = api.RequestMaker
	out.UserAgent = api.UserAgent
	out.Token = token
	return out
}

func (api *simpleTorTargetsAPI) baseURL() string {
	if api.BaseURL != "" {
		return api.BaseURL
	}
	return "https://ps1.ooni.io"
}

func (api *simpleTorTargetsAPI) requestMaker() RequestMaker {
	if api.RequestMaker != nil {
		return api.RequestMaker
	}
	return &defaultRequestMaker{}
}

func (api *simpleTorTargetsAPI) jsonCodec() JSONCodec {
	if api.JSONCodec != nil {
		return api.JSONCodec
	}
	return &defaultJSONCodec{}
}

func (api *simpleTorTargetsAPI) httpClient() HTTPClient {
	if api.HTTPClient != nil {
		return api.HTTPClient
	}
	return http.DefaultClient
}

// Call calls the TorTargets API.
func (api *simpleTorTargetsAPI) Call(ctx context.Context, req *apimodel.TorTargetsRequest) (apimodel.TorTargetsResponse, error) {
	httpReq, err := api.newRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Add("Accept", "application/json")
	if api.Token == "" {
		return nil, ErrMissingToken
	}
	httpReq.Header.Add("Authorization", newAuthorizationHeader(api.Token))
	if api.UserAgent != "" {
		httpReq.Header.Add("User-Agent", api.UserAgent)
	}
	return api.newResponse(api.httpClient().Do(httpReq))
}

// simpleURLsAPI implements the URLs API.
type simpleURLsAPI struct {
	BaseURL      string       // optional
	HTTPClient   HTTPClient   // optional
	JSONCodec    JSONCodec    // optional
	RequestMaker RequestMaker // optional
	UserAgent    string       // optional
}

func (api *simpleURLsAPI) baseURL() string {
	if api.BaseURL != "" {
		return api.BaseURL
	}
	return "https://ps1.ooni.io"
}

func (api *simpleURLsAPI) requestMaker() RequestMaker {
	if api.RequestMaker != nil {
		return api.RequestMaker
	}
	return &defaultRequestMaker{}
}

func (api *simpleURLsAPI) jsonCodec() JSONCodec {
	if api.JSONCodec != nil {
		return api.JSONCodec
	}
	return &defaultJSONCodec{}
}

func (api *simpleURLsAPI) httpClient() HTTPClient {
	if api.HTTPClient != nil {
		return api.HTTPClient
	}
	return http.DefaultClient
}

// Call calls the URLs API.
func (api *simpleURLsAPI) Call(ctx context.Context, req *apimodel.URLsRequest) (*apimodel.URLsResponse, error) {
	httpReq, err := api.newRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Add("Accept", "application/json")
	if api.UserAgent != "" {
		httpReq.Header.Add("User-Agent", api.UserAgent)
	}
	return api.newResponse(api.httpClient().Do(httpReq))
}

// simpleOpenReportAPI implements the OpenReport API.
type simpleOpenReportAPI struct {
	BaseURL      string       // optional
	HTTPClient   HTTPClient   // optional
	JSONCodec    JSONCodec    // optional
	RequestMaker RequestMaker // optional
	UserAgent    string       // optional
}

func (api *simpleOpenReportAPI) baseURL() string {
	if api.BaseURL != "" {
		return api.BaseURL
	}
	return "https://ps1.ooni.io"
}

func (api *simpleOpenReportAPI) requestMaker() RequestMaker {
	if api.RequestMaker != nil {
		return api.RequestMaker
	}
	return &defaultRequestMaker{}
}

func (api *simpleOpenReportAPI) jsonCodec() JSONCodec {
	if api.JSONCodec != nil {
		return api.JSONCodec
	}
	return &defaultJSONCodec{}
}

func (api *simpleOpenReportAPI) httpClient() HTTPClient {
	if api.HTTPClient != nil {
		return api.HTTPClient
	}
	return http.DefaultClient
}

// Call calls the OpenReport API.
func (api *simpleOpenReportAPI) Call(ctx context.Context, req *apimodel.OpenReportRequest) (*apimodel.OpenReportResponse, error) {
	httpReq, err := api.newRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Add("Accept", "application/json")
	if api.UserAgent != "" {
		httpReq.Header.Add("User-Agent", api.UserAgent)
	}
	return api.newResponse(api.httpClient().Do(httpReq))
}

// simpleSubmitMeasurementAPI implements the SubmitMeasurement API.
type simpleSubmitMeasurementAPI struct {
	BaseURL          string           // optional
	HTTPClient       HTTPClient       // optional
	JSONCodec        JSONCodec        // optional
	RequestMaker     RequestMaker     // optional
	TemplateExecutor templateExecutor // optional
	UserAgent        string           // optional
}

func (api *simpleSubmitMeasurementAPI) baseURL() string {
	if api.BaseURL != "" {
		return api.BaseURL
	}
	return "https://ps1.ooni.io"
}

func (api *simpleSubmitMeasurementAPI) requestMaker() RequestMaker {
	if api.RequestMaker != nil {
		return api.RequestMaker
	}
	return &defaultRequestMaker{}
}

func (api *simpleSubmitMeasurementAPI) jsonCodec() JSONCodec {
	if api.JSONCodec != nil {
		return api.JSONCodec
	}
	return &defaultJSONCodec{}
}

func (api *simpleSubmitMeasurementAPI) templateExecutor() templateExecutor {
	if api.TemplateExecutor != nil {
		return api.TemplateExecutor
	}
	return &defaultTemplateExecutor{}
}

func (api *simpleSubmitMeasurementAPI) httpClient() HTTPClient {
	if api.HTTPClient != nil {
		return api.HTTPClient
	}
	return http.DefaultClient
}

// Call calls the SubmitMeasurement API.
func (api *simpleSubmitMeasurementAPI) Call(ctx context.Context, req *apimodel.SubmitMeasurementRequest) (*apimodel.SubmitMeasurementResponse, error) {
	httpReq, err := api.newRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Add("Accept", "application/json")
	if api.UserAgent != "" {
		httpReq.Header.Add("User-Agent", api.UserAgent)
	}
	return api.newResponse(api.httpClient().Do(httpReq))
}
