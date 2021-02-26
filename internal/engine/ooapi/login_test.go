// Code generated by go generate; DO NOT EDIT.
// 2021-02-26 11:28:50.461722161 +0100 CET m=+0.915553549

package ooapi

//go:generate go run ./internal/generator

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/ooni/probe-cli/v3/internal/engine/ooapi/apimodel"
)

func TestRegisterAndLoginPsiphonConfigAPISuccess(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.PsiphonConfigResponse
	ff.fill(&expect)
	registerAPI := &FakeRegisterAPI{
		Response: &apimodel.RegisterResponse{
			ClientID: "antani-antani",
		},
	}
	loginAPI := &FakeLoginAPI{
		Response: &apimodel.LoginResponse{
			Expire: time.Now().Add(3600 * time.Second),
			Token:  "antani-antani-token",
		},
	}
	login := &PsiphonConfigAPIWithLogin{
		API: &FakePsiphonConfigAPI{
			WithResult: &FakePsiphonConfigAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if diff := cmp.Diff(expect, resp); diff != "" {
		t.Fatal(diff)
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestPsiphonConfigAPIContinueUsingToken(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.PsiphonConfigResponse
	ff.fill(&expect)
	registerAPI := &FakeRegisterAPI{
		Response: &apimodel.RegisterResponse{
			ClientID: "antani-antani",
		},
	}
	loginAPI := &FakeLoginAPI{
		Response: &apimodel.LoginResponse{
			Expire: time.Now().Add(3600 * time.Second),
			Token:  "antani-antani-token",
		},
	}
	login := &PsiphonConfigAPIWithLogin{
		API: &FakePsiphonConfigAPI{
			WithResult: &FakePsiphonConfigAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if diff := cmp.Diff(expect, resp); diff != "" {
			t.Fatal(diff)
		}
		if loginAPI.CountCall != 1 {
			t.Fatal("invalid loginAPI.CountCall")
		}
		if registerAPI.CountCall != 1 {
			t.Fatal("invalid registerAPI.CountCall")
		}
	}
	// step 2: we disable register and login but we
	// should be okay because of the token
	errMocked := errors.New("mocked error")
	registerAPI.Err = errMocked
	registerAPI.Response = nil
	loginAPI.Err = errMocked
	loginAPI.Response = nil
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if diff := cmp.Diff(expect, resp); diff != "" {
		t.Fatal(diff)
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestPsiphonConfigAPIWithValidButExpiredToken(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.PsiphonConfigResponse
	ff.fill(&expect)
	errMocked := errors.New("mocked error")
	registerAPI := &FakeRegisterAPI{
		Err: errMocked,
	}
	loginAPI := &FakeLoginAPI{
		Response: &apimodel.LoginResponse{
			Expire: time.Now().Add(3600 * time.Second),
			Token:  "antani-antani-token",
		},
	}
	login := &PsiphonConfigAPIWithLogin{
		API: &FakePsiphonConfigAPI{
			WithResult: &FakePsiphonConfigAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
	}
	ls := &loginState{
		ClientID: "antani-antani",
		Expire:   time.Now().Add(-5 * time.Second),
		Token:    "antani-antani-token",
		Password: "antani-antani-password",
	}
	if err := login.writestate(ls); err != nil {
		t.Fatal(err)
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if diff := cmp.Diff(expect, resp); diff != "" {
		t.Fatal(diff)
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 0 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestPsiphonConfigAPIWithRegisterAPIError(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.PsiphonConfigResponse
	ff.fill(&expect)
	errMocked := errors.New("mocked error")
	registerAPI := &FakeRegisterAPI{
		Err: errMocked,
	}
	login := &PsiphonConfigAPIWithLogin{
		API: &FakePsiphonConfigAPI{
			WithResult: &FakePsiphonConfigAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		KVStore:     &memkvstore{},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestPsiphonConfigAPIWithLoginFailure(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.PsiphonConfigResponse
	ff.fill(&expect)
	registerAPI := &FakeRegisterAPI{
		Response: &apimodel.RegisterResponse{
			ClientID: "antani-antani",
		},
	}
	errMocked := errors.New("mocked error")
	loginAPI := &FakeLoginAPI{
		Err: errMocked,
	}
	login := &PsiphonConfigAPIWithLogin{
		API: &FakePsiphonConfigAPI{
			WithResult: &FakePsiphonConfigAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestRegisterAndLoginPsiphonConfigAPIThenFail(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.PsiphonConfigResponse
	ff.fill(&expect)
	registerAPI := &FakeRegisterAPI{
		Response: &apimodel.RegisterResponse{
			ClientID: "antani-antani",
		},
	}
	loginAPI := &FakeLoginAPI{
		Response: &apimodel.LoginResponse{
			Expire: time.Now().Add(3600 * time.Second),
			Token:  "antani-antani-token",
		},
	}
	errMocked := errors.New("mocked error")
	login := &PsiphonConfigAPIWithLogin{
		API: &FakePsiphonConfigAPI{
			WithResult: &FakePsiphonConfigAPI{
				Err: errMocked,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestPsiphonConfigAPITheDatabaseIsReplaced(t *testing.T) {
	ff := &fakeFill{}
	handler := &LoginHandler{t: t}
	srvr := httptest.NewServer(handler)
	defer srvr.Close()
	registerAPI := &RegisterAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	loginAPI := &LoginAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	baseAPI := &PsiphonConfigAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	login := &PsiphonConfigAPIWithLogin{
		API:         baseAPI,
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if handler.logins != 1 {
			t.Fatal("invalid handler.logins")
		}
		if handler.registers != 1 {
			t.Fatal("invalid handler.registers")
		}
	}
	// step 2: we forget accounts and try again.
	handler.forgetLogins()
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if handler.logins != 3 {
		t.Fatal("invalid handler.logins")
	}
	if handler.registers != 2 {
		t.Fatal("invalid handler.registers")
	}
}

func TestRegisterAndLoginPsiphonConfigAPICannotWriteState(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.PsiphonConfigResponse
	ff.fill(&expect)
	registerAPI := &FakeRegisterAPI{
		Response: &apimodel.RegisterResponse{
			ClientID: "antani-antani",
		},
	}
	loginAPI := &FakeLoginAPI{
		Response: &apimodel.LoginResponse{
			Expire: time.Now().Add(3600 * time.Second),
			Token:  "antani-antani-token",
		},
	}
	errMocked := errors.New("mocked error")
	login := &PsiphonConfigAPIWithLogin{
		API: &FakePsiphonConfigAPI{
			WithResult: &FakePsiphonConfigAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
		JSONCodec: &FakeCodec{
			EncodeErr: errMocked,
		},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestPsiphonConfigAPIReadStateDecodeFailure(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.PsiphonConfigResponse
	ff.fill(&expect)
	errMocked := errors.New("mocked error")
	login := &PsiphonConfigAPIWithLogin{
		KVStore:   &memkvstore{},
		JSONCodec: &FakeCodec{DecodeErr: errMocked},
	}
	ls := &loginState{
		ClientID: "antani-antani",
		Expire:   time.Now().Add(-5 * time.Second),
		Token:    "antani-antani-token",
		Password: "antani-antani-password",
	}
	if err := login.writestate(ls); err != nil {
		t.Fatal(err)
	}
	out, err := login.readstate()
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if out != nil {
		t.Fatal("expected nil here")
	}
}

func TestPsiphonConfigAPITheDatabaseIsReplacedThenFailure(t *testing.T) {
	ff := &fakeFill{}
	handler := &LoginHandler{t: t}
	srvr := httptest.NewServer(handler)
	defer srvr.Close()
	registerAPI := &RegisterAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	loginAPI := &LoginAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	baseAPI := &PsiphonConfigAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	login := &PsiphonConfigAPIWithLogin{
		API:         baseAPI,
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if handler.logins != 1 {
			t.Fatal("invalid handler.logins")
		}
		if handler.registers != 1 {
			t.Fatal("invalid handler.registers")
		}
	}
	// step 2: we forget accounts and try again.
	// but registrations are also failing.
	handler.forgetLogins()
	handler.noRegister = true
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, ErrHTTPFailure) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if handler.logins != 2 {
		t.Fatal("invalid handler.logins")
	}
	if handler.registers != 2 {
		t.Fatal("invalid handler.registers")
	}
}

func TestPsiphonConfigAPIClockIsOffThenSuccess(t *testing.T) {
	ff := &fakeFill{}
	handler := &LoginHandler{t: t}
	srvr := httptest.NewServer(handler)
	defer srvr.Close()
	registerAPI := &RegisterAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	loginAPI := &LoginAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	baseAPI := &PsiphonConfigAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	login := &PsiphonConfigAPIWithLogin{
		API:         baseAPI,
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if handler.logins != 1 {
			t.Fatal("invalid handler.logins")
		}
		if handler.registers != 1 {
			t.Fatal("invalid handler.registers")
		}
	}
	// step 2: we forget tokens and try again.
	// this should simulate the client clock
	// being off and considering a token still valid
	handler.forgetTokens()
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if handler.logins != 2 {
		t.Fatal("invalid handler.logins")
	}
	if handler.registers != 1 {
		t.Fatal("invalid handler.registers")
	}
}

func TestPsiphonConfigAPIClockIsOffThen401(t *testing.T) {
	ff := &fakeFill{}
	handler := &LoginHandler{t: t}
	srvr := httptest.NewServer(handler)
	defer srvr.Close()
	registerAPI := &RegisterAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	loginAPI := &LoginAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	baseAPI := &PsiphonConfigAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	login := &PsiphonConfigAPIWithLogin{
		API:         baseAPI,
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if handler.logins != 1 {
			t.Fatal("invalid handler.logins")
		}
		if handler.registers != 1 {
			t.Fatal("invalid handler.registers")
		}
	}
	// step 2: we forget tokens and try again.
	// this should simulate the client clock
	// being off and considering a token still valid
	handler.forgetTokens()
	handler.failCallWith = []int{401, 401}
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal("not the error we expected", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if handler.logins != 3 {
		t.Fatal("invalid handler.logins")
	}
	if handler.registers != 2 {
		t.Fatal("invalid handler.registers")
	}
}

func TestPsiphonConfigAPIClockIsOffThen500(t *testing.T) {
	ff := &fakeFill{}
	handler := &LoginHandler{t: t}
	srvr := httptest.NewServer(handler)
	defer srvr.Close()
	registerAPI := &RegisterAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	loginAPI := &LoginAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	baseAPI := &PsiphonConfigAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	login := &PsiphonConfigAPIWithLogin{
		API:         baseAPI,
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
	}
	var req *apimodel.PsiphonConfigRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if handler.logins != 1 {
			t.Fatal("invalid handler.logins")
		}
		if handler.registers != 1 {
			t.Fatal("invalid handler.registers")
		}
	}
	// step 2: we forget tokens and try again.
	// this should simulate the client clock
	// being off and considering a token still valid
	handler.forgetTokens()
	handler.failCallWith = []int{401, 500}
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, ErrHTTPFailure) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if handler.logins != 2 {
		t.Fatal("invalid handler.logins")
	}
	if handler.registers != 1 {
		t.Fatal("invalid handler.registers")
	}
}

func TestRegisterAndLoginTorTargetsAPISuccess(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.TorTargetsResponse
	ff.fill(&expect)
	registerAPI := &FakeRegisterAPI{
		Response: &apimodel.RegisterResponse{
			ClientID: "antani-antani",
		},
	}
	loginAPI := &FakeLoginAPI{
		Response: &apimodel.LoginResponse{
			Expire: time.Now().Add(3600 * time.Second),
			Token:  "antani-antani-token",
		},
	}
	login := &TorTargetsAPIWithLogin{
		API: &FakeTorTargetsAPI{
			WithResult: &FakeTorTargetsAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if diff := cmp.Diff(expect, resp); diff != "" {
		t.Fatal(diff)
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestTorTargetsAPIContinueUsingToken(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.TorTargetsResponse
	ff.fill(&expect)
	registerAPI := &FakeRegisterAPI{
		Response: &apimodel.RegisterResponse{
			ClientID: "antani-antani",
		},
	}
	loginAPI := &FakeLoginAPI{
		Response: &apimodel.LoginResponse{
			Expire: time.Now().Add(3600 * time.Second),
			Token:  "antani-antani-token",
		},
	}
	login := &TorTargetsAPIWithLogin{
		API: &FakeTorTargetsAPI{
			WithResult: &FakeTorTargetsAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if diff := cmp.Diff(expect, resp); diff != "" {
			t.Fatal(diff)
		}
		if loginAPI.CountCall != 1 {
			t.Fatal("invalid loginAPI.CountCall")
		}
		if registerAPI.CountCall != 1 {
			t.Fatal("invalid registerAPI.CountCall")
		}
	}
	// step 2: we disable register and login but we
	// should be okay because of the token
	errMocked := errors.New("mocked error")
	registerAPI.Err = errMocked
	registerAPI.Response = nil
	loginAPI.Err = errMocked
	loginAPI.Response = nil
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if diff := cmp.Diff(expect, resp); diff != "" {
		t.Fatal(diff)
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestTorTargetsAPIWithValidButExpiredToken(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.TorTargetsResponse
	ff.fill(&expect)
	errMocked := errors.New("mocked error")
	registerAPI := &FakeRegisterAPI{
		Err: errMocked,
	}
	loginAPI := &FakeLoginAPI{
		Response: &apimodel.LoginResponse{
			Expire: time.Now().Add(3600 * time.Second),
			Token:  "antani-antani-token",
		},
	}
	login := &TorTargetsAPIWithLogin{
		API: &FakeTorTargetsAPI{
			WithResult: &FakeTorTargetsAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
	}
	ls := &loginState{
		ClientID: "antani-antani",
		Expire:   time.Now().Add(-5 * time.Second),
		Token:    "antani-antani-token",
		Password: "antani-antani-password",
	}
	if err := login.writestate(ls); err != nil {
		t.Fatal(err)
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if diff := cmp.Diff(expect, resp); diff != "" {
		t.Fatal(diff)
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 0 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestTorTargetsAPIWithRegisterAPIError(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.TorTargetsResponse
	ff.fill(&expect)
	errMocked := errors.New("mocked error")
	registerAPI := &FakeRegisterAPI{
		Err: errMocked,
	}
	login := &TorTargetsAPIWithLogin{
		API: &FakeTorTargetsAPI{
			WithResult: &FakeTorTargetsAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		KVStore:     &memkvstore{},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestTorTargetsAPIWithLoginFailure(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.TorTargetsResponse
	ff.fill(&expect)
	registerAPI := &FakeRegisterAPI{
		Response: &apimodel.RegisterResponse{
			ClientID: "antani-antani",
		},
	}
	errMocked := errors.New("mocked error")
	loginAPI := &FakeLoginAPI{
		Err: errMocked,
	}
	login := &TorTargetsAPIWithLogin{
		API: &FakeTorTargetsAPI{
			WithResult: &FakeTorTargetsAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestRegisterAndLoginTorTargetsAPIThenFail(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.TorTargetsResponse
	ff.fill(&expect)
	registerAPI := &FakeRegisterAPI{
		Response: &apimodel.RegisterResponse{
			ClientID: "antani-antani",
		},
	}
	loginAPI := &FakeLoginAPI{
		Response: &apimodel.LoginResponse{
			Expire: time.Now().Add(3600 * time.Second),
			Token:  "antani-antani-token",
		},
	}
	errMocked := errors.New("mocked error")
	login := &TorTargetsAPIWithLogin{
		API: &FakeTorTargetsAPI{
			WithResult: &FakeTorTargetsAPI{
				Err: errMocked,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestTorTargetsAPITheDatabaseIsReplaced(t *testing.T) {
	ff := &fakeFill{}
	handler := &LoginHandler{t: t}
	srvr := httptest.NewServer(handler)
	defer srvr.Close()
	registerAPI := &RegisterAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	loginAPI := &LoginAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	baseAPI := &TorTargetsAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	login := &TorTargetsAPIWithLogin{
		API:         baseAPI,
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if handler.logins != 1 {
			t.Fatal("invalid handler.logins")
		}
		if handler.registers != 1 {
			t.Fatal("invalid handler.registers")
		}
	}
	// step 2: we forget accounts and try again.
	handler.forgetLogins()
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if handler.logins != 3 {
		t.Fatal("invalid handler.logins")
	}
	if handler.registers != 2 {
		t.Fatal("invalid handler.registers")
	}
}

func TestRegisterAndLoginTorTargetsAPICannotWriteState(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.TorTargetsResponse
	ff.fill(&expect)
	registerAPI := &FakeRegisterAPI{
		Response: &apimodel.RegisterResponse{
			ClientID: "antani-antani",
		},
	}
	loginAPI := &FakeLoginAPI{
		Response: &apimodel.LoginResponse{
			Expire: time.Now().Add(3600 * time.Second),
			Token:  "antani-antani-token",
		},
	}
	errMocked := errors.New("mocked error")
	login := &TorTargetsAPIWithLogin{
		API: &FakeTorTargetsAPI{
			WithResult: &FakeTorTargetsAPI{
				Response: expect,
			},
		},
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
		JSONCodec: &FakeCodec{
			EncodeErr: errMocked,
		},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if loginAPI.CountCall != 1 {
		t.Fatal("invalid loginAPI.CountCall")
	}
	if registerAPI.CountCall != 1 {
		t.Fatal("invalid registerAPI.CountCall")
	}
}

func TestTorTargetsAPIReadStateDecodeFailure(t *testing.T) {
	ff := &fakeFill{}
	var expect apimodel.TorTargetsResponse
	ff.fill(&expect)
	errMocked := errors.New("mocked error")
	login := &TorTargetsAPIWithLogin{
		KVStore:   &memkvstore{},
		JSONCodec: &FakeCodec{DecodeErr: errMocked},
	}
	ls := &loginState{
		ClientID: "antani-antani",
		Expire:   time.Now().Add(-5 * time.Second),
		Token:    "antani-antani-token",
		Password: "antani-antani-password",
	}
	if err := login.writestate(ls); err != nil {
		t.Fatal(err)
	}
	out, err := login.readstate()
	if !errors.Is(err, errMocked) {
		t.Fatal("not the error we expected", err)
	}
	if out != nil {
		t.Fatal("expected nil here")
	}
}

func TestTorTargetsAPITheDatabaseIsReplacedThenFailure(t *testing.T) {
	ff := &fakeFill{}
	handler := &LoginHandler{t: t}
	srvr := httptest.NewServer(handler)
	defer srvr.Close()
	registerAPI := &RegisterAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	loginAPI := &LoginAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	baseAPI := &TorTargetsAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	login := &TorTargetsAPIWithLogin{
		API:         baseAPI,
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if handler.logins != 1 {
			t.Fatal("invalid handler.logins")
		}
		if handler.registers != 1 {
			t.Fatal("invalid handler.registers")
		}
	}
	// step 2: we forget accounts and try again.
	// but registrations are also failing.
	handler.forgetLogins()
	handler.noRegister = true
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, ErrHTTPFailure) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if handler.logins != 2 {
		t.Fatal("invalid handler.logins")
	}
	if handler.registers != 2 {
		t.Fatal("invalid handler.registers")
	}
}

func TestTorTargetsAPIClockIsOffThenSuccess(t *testing.T) {
	ff := &fakeFill{}
	handler := &LoginHandler{t: t}
	srvr := httptest.NewServer(handler)
	defer srvr.Close()
	registerAPI := &RegisterAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	loginAPI := &LoginAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	baseAPI := &TorTargetsAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	login := &TorTargetsAPIWithLogin{
		API:         baseAPI,
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if handler.logins != 1 {
			t.Fatal("invalid handler.logins")
		}
		if handler.registers != 1 {
			t.Fatal("invalid handler.registers")
		}
	}
	// step 2: we forget tokens and try again.
	// this should simulate the client clock
	// being off and considering a token still valid
	handler.forgetTokens()
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if handler.logins != 2 {
		t.Fatal("invalid handler.logins")
	}
	if handler.registers != 1 {
		t.Fatal("invalid handler.registers")
	}
}

func TestTorTargetsAPIClockIsOffThen401(t *testing.T) {
	ff := &fakeFill{}
	handler := &LoginHandler{t: t}
	srvr := httptest.NewServer(handler)
	defer srvr.Close()
	registerAPI := &RegisterAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	loginAPI := &LoginAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	baseAPI := &TorTargetsAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	login := &TorTargetsAPIWithLogin{
		API:         baseAPI,
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if handler.logins != 1 {
			t.Fatal("invalid handler.logins")
		}
		if handler.registers != 1 {
			t.Fatal("invalid handler.registers")
		}
	}
	// step 2: we forget tokens and try again.
	// this should simulate the client clock
	// being off and considering a token still valid
	handler.forgetTokens()
	handler.failCallWith = []int{401, 401}
	resp, err := login.Call(ctx, req)
	if err != nil {
		t.Fatal("not the error we expected", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if handler.logins != 3 {
		t.Fatal("invalid handler.logins")
	}
	if handler.registers != 2 {
		t.Fatal("invalid handler.registers")
	}
}

func TestTorTargetsAPIClockIsOffThen500(t *testing.T) {
	ff := &fakeFill{}
	handler := &LoginHandler{t: t}
	srvr := httptest.NewServer(handler)
	defer srvr.Close()
	registerAPI := &RegisterAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	loginAPI := &LoginAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	baseAPI := &TorTargetsAPI{
		HTTPClient: &VerboseHTTPClient{t: t},
		BaseURL:    srvr.URL,
	}
	login := &TorTargetsAPIWithLogin{
		API:         baseAPI,
		RegisterAPI: registerAPI,
		LoginAPI:    loginAPI,
		KVStore:     &memkvstore{},
	}
	var req *apimodel.TorTargetsRequest
	ff.fill(&req)
	ctx := context.Background()
	// step 1: we register and login and use the token
	// inside a scope just to avoid mistakes
	{
		resp, err := login.Call(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if handler.logins != 1 {
			t.Fatal("invalid handler.logins")
		}
		if handler.registers != 1 {
			t.Fatal("invalid handler.registers")
		}
	}
	// step 2: we forget tokens and try again.
	// this should simulate the client clock
	// being off and considering a token still valid
	handler.forgetTokens()
	handler.failCallWith = []int{401, 500}
	resp, err := login.Call(ctx, req)
	if !errors.Is(err, ErrHTTPFailure) {
		t.Fatal("not the error we expected", err)
	}
	if resp != nil {
		t.Fatal("expected nil response")
	}
	if handler.logins != 2 {
		t.Fatal("invalid handler.logins")
	}
	if handler.registers != 1 {
		t.Fatal("invalid handler.registers")
	}
}
