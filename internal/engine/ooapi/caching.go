// Code generated by go generate; DO NOT EDIT.
// 2021-02-23 11:13:46.645066 +0100 CET m=+1.944586735

package ooapi

//go:generate go run ./internal/generator

import (
	"context"
	"reflect"

	"github.com/ooni/probe-cli/v3/internal/engine/ooapi/apimodel"
)

// CheckReportIDCache implements caching for CheckReportIDAPI.
type CheckReportIDCache struct {
	API      CheckReportIDCaller // mandatory
	GobCodec GobCodec            // optional
	KVStore  KVStore             // mandatory
}

type cacheEntryForCheckReportID struct {
	Req  *apimodel.CheckReportIDRequest
	Resp *apimodel.CheckReportIDResponse
}

func (c *CheckReportIDCache) Call(ctx context.Context, req *apimodel.CheckReportIDRequest) (*apimodel.CheckReportIDResponse, error) {
	resp, err := c.API.Call(ctx, req)
	if err != nil {
		if resp, _ := c.readcache(req); resp != nil {
			return resp, nil
		}
		return nil, err
	}
	if err := c.writecache(req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *CheckReportIDCache) gobCodec() GobCodec {
	if c.GobCodec != nil {
		return c.GobCodec
	}
	return &defaultGobCodec{}
}

func (c *CheckReportIDCache) getcache() ([]cacheEntryForCheckReportID, error) {
	data, err := c.KVStore.Get("CheckReportID.cache")
	if err != nil {
		return nil, err
	}
	var out []cacheEntryForCheckReportID
	if err := c.gobCodec().Decode(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *CheckReportIDCache) setcache(in []cacheEntryForCheckReportID) error {
	data, err := c.gobCodec().Encode(in)
	if err != nil {
		return err
	}
	return c.KVStore.Set("CheckReportID.cache", data)
}

func (c *CheckReportIDCache) readcache(req *apimodel.CheckReportIDRequest) (*apimodel.CheckReportIDResponse, error) {
	cache, err := c.getcache()
	if err != nil {
		return nil, err
	}
	for _, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			return cur.Resp, nil
		}
	}
	return nil, errCacheNotFound
}

func (c *CheckReportIDCache) writecache(req *apimodel.CheckReportIDRequest, resp *apimodel.CheckReportIDResponse) error {
	cache, _ := c.getcache()
	out := []cacheEntryForCheckReportID{{Req: req, Resp: resp}}
	const toomany = 32
	for idx, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			continue // we already updated the cache
		}
		if idx > toomany {
			break
		}
		out = append(out, cur)
	}
	return c.setcache(out)
}

var _ CheckReportIDCaller = &CheckReportIDCache{}

// CheckInCache implements caching for CheckInAPI.
type CheckInCache struct {
	API      CheckInCaller // mandatory
	GobCodec GobCodec      // optional
	KVStore  KVStore       // mandatory
}

type cacheEntryForCheckIn struct {
	Req  *apimodel.CheckInRequest
	Resp *apimodel.CheckInResponse
}

func (c *CheckInCache) Call(ctx context.Context, req *apimodel.CheckInRequest) (*apimodel.CheckInResponse, error) {
	resp, err := c.API.Call(ctx, req)
	if err != nil {
		if resp, _ := c.readcache(req); resp != nil {
			return resp, nil
		}
		return nil, err
	}
	if err := c.writecache(req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *CheckInCache) gobCodec() GobCodec {
	if c.GobCodec != nil {
		return c.GobCodec
	}
	return &defaultGobCodec{}
}

func (c *CheckInCache) getcache() ([]cacheEntryForCheckIn, error) {
	data, err := c.KVStore.Get("CheckIn.cache")
	if err != nil {
		return nil, err
	}
	var out []cacheEntryForCheckIn
	if err := c.gobCodec().Decode(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *CheckInCache) setcache(in []cacheEntryForCheckIn) error {
	data, err := c.gobCodec().Encode(in)
	if err != nil {
		return err
	}
	return c.KVStore.Set("CheckIn.cache", data)
}

func (c *CheckInCache) readcache(req *apimodel.CheckInRequest) (*apimodel.CheckInResponse, error) {
	cache, err := c.getcache()
	if err != nil {
		return nil, err
	}
	for _, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			return cur.Resp, nil
		}
	}
	return nil, errCacheNotFound
}

func (c *CheckInCache) writecache(req *apimodel.CheckInRequest, resp *apimodel.CheckInResponse) error {
	cache, _ := c.getcache()
	out := []cacheEntryForCheckIn{{Req: req, Resp: resp}}
	const toomany = 32
	for idx, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			continue // we already updated the cache
		}
		if idx > toomany {
			break
		}
		out = append(out, cur)
	}
	return c.setcache(out)
}

var _ CheckInCaller = &CheckInCache{}

// LoginCache implements caching for LoginAPI.
type LoginCache struct {
	API      LoginCaller // mandatory
	GobCodec GobCodec    // optional
	KVStore  KVStore     // mandatory
}

type cacheEntryForLogin struct {
	Req  *apimodel.LoginRequest
	Resp *apimodel.LoginResponse
}

func (c *LoginCache) Call(ctx context.Context, req *apimodel.LoginRequest) (*apimodel.LoginResponse, error) {
	resp, err := c.API.Call(ctx, req)
	if err != nil {
		if resp, _ := c.readcache(req); resp != nil {
			return resp, nil
		}
		return nil, err
	}
	if err := c.writecache(req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *LoginCache) gobCodec() GobCodec {
	if c.GobCodec != nil {
		return c.GobCodec
	}
	return &defaultGobCodec{}
}

func (c *LoginCache) getcache() ([]cacheEntryForLogin, error) {
	data, err := c.KVStore.Get("Login.cache")
	if err != nil {
		return nil, err
	}
	var out []cacheEntryForLogin
	if err := c.gobCodec().Decode(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *LoginCache) setcache(in []cacheEntryForLogin) error {
	data, err := c.gobCodec().Encode(in)
	if err != nil {
		return err
	}
	return c.KVStore.Set("Login.cache", data)
}

func (c *LoginCache) readcache(req *apimodel.LoginRequest) (*apimodel.LoginResponse, error) {
	cache, err := c.getcache()
	if err != nil {
		return nil, err
	}
	for _, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			return cur.Resp, nil
		}
	}
	return nil, errCacheNotFound
}

func (c *LoginCache) writecache(req *apimodel.LoginRequest, resp *apimodel.LoginResponse) error {
	cache, _ := c.getcache()
	out := []cacheEntryForLogin{{Req: req, Resp: resp}}
	const toomany = 32
	for idx, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			continue // we already updated the cache
		}
		if idx > toomany {
			break
		}
		out = append(out, cur)
	}
	return c.setcache(out)
}

var _ LoginCaller = &LoginCache{}

// MeasurementMetaCache implements caching for MeasurementMetaAPI.
type MeasurementMetaCache struct {
	API      MeasurementMetaCaller // mandatory
	GobCodec GobCodec              // optional
	KVStore  KVStore               // mandatory
}

type cacheEntryForMeasurementMeta struct {
	Req  *apimodel.MeasurementMetaRequest
	Resp *apimodel.MeasurementMetaResponse
}

func (c *MeasurementMetaCache) Call(ctx context.Context, req *apimodel.MeasurementMetaRequest) (*apimodel.MeasurementMetaResponse, error) {
	resp, err := c.API.Call(ctx, req)
	if err != nil {
		if resp, _ := c.readcache(req); resp != nil {
			return resp, nil
		}
		return nil, err
	}
	if err := c.writecache(req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *MeasurementMetaCache) gobCodec() GobCodec {
	if c.GobCodec != nil {
		return c.GobCodec
	}
	return &defaultGobCodec{}
}

func (c *MeasurementMetaCache) getcache() ([]cacheEntryForMeasurementMeta, error) {
	data, err := c.KVStore.Get("MeasurementMeta.cache")
	if err != nil {
		return nil, err
	}
	var out []cacheEntryForMeasurementMeta
	if err := c.gobCodec().Decode(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *MeasurementMetaCache) setcache(in []cacheEntryForMeasurementMeta) error {
	data, err := c.gobCodec().Encode(in)
	if err != nil {
		return err
	}
	return c.KVStore.Set("MeasurementMeta.cache", data)
}

func (c *MeasurementMetaCache) readcache(req *apimodel.MeasurementMetaRequest) (*apimodel.MeasurementMetaResponse, error) {
	cache, err := c.getcache()
	if err != nil {
		return nil, err
	}
	for _, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			return cur.Resp, nil
		}
	}
	return nil, errCacheNotFound
}

func (c *MeasurementMetaCache) writecache(req *apimodel.MeasurementMetaRequest, resp *apimodel.MeasurementMetaResponse) error {
	cache, _ := c.getcache()
	out := []cacheEntryForMeasurementMeta{{Req: req, Resp: resp}}
	const toomany = 32
	for idx, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			continue // we already updated the cache
		}
		if idx > toomany {
			break
		}
		out = append(out, cur)
	}
	return c.setcache(out)
}

var _ MeasurementMetaCaller = &MeasurementMetaCache{}

// RegisterCache implements caching for RegisterAPI.
type RegisterCache struct {
	API      RegisterCaller // mandatory
	GobCodec GobCodec       // optional
	KVStore  KVStore        // mandatory
}

type cacheEntryForRegister struct {
	Req  *apimodel.RegisterRequest
	Resp *apimodel.RegisterResponse
}

func (c *RegisterCache) Call(ctx context.Context, req *apimodel.RegisterRequest) (*apimodel.RegisterResponse, error) {
	resp, err := c.API.Call(ctx, req)
	if err != nil {
		if resp, _ := c.readcache(req); resp != nil {
			return resp, nil
		}
		return nil, err
	}
	if err := c.writecache(req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *RegisterCache) gobCodec() GobCodec {
	if c.GobCodec != nil {
		return c.GobCodec
	}
	return &defaultGobCodec{}
}

func (c *RegisterCache) getcache() ([]cacheEntryForRegister, error) {
	data, err := c.KVStore.Get("Register.cache")
	if err != nil {
		return nil, err
	}
	var out []cacheEntryForRegister
	if err := c.gobCodec().Decode(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *RegisterCache) setcache(in []cacheEntryForRegister) error {
	data, err := c.gobCodec().Encode(in)
	if err != nil {
		return err
	}
	return c.KVStore.Set("Register.cache", data)
}

func (c *RegisterCache) readcache(req *apimodel.RegisterRequest) (*apimodel.RegisterResponse, error) {
	cache, err := c.getcache()
	if err != nil {
		return nil, err
	}
	for _, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			return cur.Resp, nil
		}
	}
	return nil, errCacheNotFound
}

func (c *RegisterCache) writecache(req *apimodel.RegisterRequest, resp *apimodel.RegisterResponse) error {
	cache, _ := c.getcache()
	out := []cacheEntryForRegister{{Req: req, Resp: resp}}
	const toomany = 32
	for idx, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			continue // we already updated the cache
		}
		if idx > toomany {
			break
		}
		out = append(out, cur)
	}
	return c.setcache(out)
}

var _ RegisterCaller = &RegisterCache{}

// TestHelpersCache implements caching for TestHelpersAPI.
type TestHelpersCache struct {
	API      TestHelpersCaller // mandatory
	GobCodec GobCodec          // optional
	KVStore  KVStore           // mandatory
}

type cacheEntryForTestHelpers struct {
	Req  *apimodel.TestHelpersRequest
	Resp apimodel.TestHelpersResponse
}

func (c *TestHelpersCache) Call(ctx context.Context, req *apimodel.TestHelpersRequest) (apimodel.TestHelpersResponse, error) {
	resp, err := c.API.Call(ctx, req)
	if err != nil {
		if resp, _ := c.readcache(req); resp != nil {
			return resp, nil
		}
		return nil, err
	}
	if err := c.writecache(req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *TestHelpersCache) gobCodec() GobCodec {
	if c.GobCodec != nil {
		return c.GobCodec
	}
	return &defaultGobCodec{}
}

func (c *TestHelpersCache) getcache() ([]cacheEntryForTestHelpers, error) {
	data, err := c.KVStore.Get("TestHelpers.cache")
	if err != nil {
		return nil, err
	}
	var out []cacheEntryForTestHelpers
	if err := c.gobCodec().Decode(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *TestHelpersCache) setcache(in []cacheEntryForTestHelpers) error {
	data, err := c.gobCodec().Encode(in)
	if err != nil {
		return err
	}
	return c.KVStore.Set("TestHelpers.cache", data)
}

func (c *TestHelpersCache) readcache(req *apimodel.TestHelpersRequest) (apimodel.TestHelpersResponse, error) {
	cache, err := c.getcache()
	if err != nil {
		return nil, err
	}
	for _, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			return cur.Resp, nil
		}
	}
	return nil, errCacheNotFound
}

func (c *TestHelpersCache) writecache(req *apimodel.TestHelpersRequest, resp apimodel.TestHelpersResponse) error {
	cache, _ := c.getcache()
	out := []cacheEntryForTestHelpers{{Req: req, Resp: resp}}
	const toomany = 32
	for idx, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			continue // we already updated the cache
		}
		if idx > toomany {
			break
		}
		out = append(out, cur)
	}
	return c.setcache(out)
}

var _ TestHelpersCaller = &TestHelpersCache{}

// PsiphonConfigCache implements caching for PsiphonConfigAPI.
type PsiphonConfigCache struct {
	API      PsiphonConfigCaller // mandatory
	GobCodec GobCodec            // optional
	KVStore  KVStore             // mandatory
}

type cacheEntryForPsiphonConfig struct {
	Req  *apimodel.PsiphonConfigRequest
	Resp apimodel.PsiphonConfigResponse
}

func (c *PsiphonConfigCache) Call(ctx context.Context, req *apimodel.PsiphonConfigRequest) (apimodel.PsiphonConfigResponse, error) {
	resp, err := c.API.Call(ctx, req)
	if err != nil {
		if resp, _ := c.readcache(req); resp != nil {
			return resp, nil
		}
		return nil, err
	}
	if err := c.writecache(req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *PsiphonConfigCache) gobCodec() GobCodec {
	if c.GobCodec != nil {
		return c.GobCodec
	}
	return &defaultGobCodec{}
}

func (c *PsiphonConfigCache) getcache() ([]cacheEntryForPsiphonConfig, error) {
	data, err := c.KVStore.Get("PsiphonConfig.cache")
	if err != nil {
		return nil, err
	}
	var out []cacheEntryForPsiphonConfig
	if err := c.gobCodec().Decode(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *PsiphonConfigCache) setcache(in []cacheEntryForPsiphonConfig) error {
	data, err := c.gobCodec().Encode(in)
	if err != nil {
		return err
	}
	return c.KVStore.Set("PsiphonConfig.cache", data)
}

func (c *PsiphonConfigCache) readcache(req *apimodel.PsiphonConfigRequest) (apimodel.PsiphonConfigResponse, error) {
	cache, err := c.getcache()
	if err != nil {
		return nil, err
	}
	for _, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			return cur.Resp, nil
		}
	}
	return nil, errCacheNotFound
}

func (c *PsiphonConfigCache) writecache(req *apimodel.PsiphonConfigRequest, resp apimodel.PsiphonConfigResponse) error {
	cache, _ := c.getcache()
	out := []cacheEntryForPsiphonConfig{{Req: req, Resp: resp}}
	const toomany = 32
	for idx, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			continue // we already updated the cache
		}
		if idx > toomany {
			break
		}
		out = append(out, cur)
	}
	return c.setcache(out)
}

var _ PsiphonConfigCaller = &PsiphonConfigCache{}

// TorTargetsCache implements caching for TorTargetsAPI.
type TorTargetsCache struct {
	API      TorTargetsCaller // mandatory
	GobCodec GobCodec         // optional
	KVStore  KVStore          // mandatory
}

type cacheEntryForTorTargets struct {
	Req  *apimodel.TorTargetsRequest
	Resp apimodel.TorTargetsResponse
}

func (c *TorTargetsCache) Call(ctx context.Context, req *apimodel.TorTargetsRequest) (apimodel.TorTargetsResponse, error) {
	resp, err := c.API.Call(ctx, req)
	if err != nil {
		if resp, _ := c.readcache(req); resp != nil {
			return resp, nil
		}
		return nil, err
	}
	if err := c.writecache(req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *TorTargetsCache) gobCodec() GobCodec {
	if c.GobCodec != nil {
		return c.GobCodec
	}
	return &defaultGobCodec{}
}

func (c *TorTargetsCache) getcache() ([]cacheEntryForTorTargets, error) {
	data, err := c.KVStore.Get("TorTargets.cache")
	if err != nil {
		return nil, err
	}
	var out []cacheEntryForTorTargets
	if err := c.gobCodec().Decode(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *TorTargetsCache) setcache(in []cacheEntryForTorTargets) error {
	data, err := c.gobCodec().Encode(in)
	if err != nil {
		return err
	}
	return c.KVStore.Set("TorTargets.cache", data)
}

func (c *TorTargetsCache) readcache(req *apimodel.TorTargetsRequest) (apimodel.TorTargetsResponse, error) {
	cache, err := c.getcache()
	if err != nil {
		return nil, err
	}
	for _, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			return cur.Resp, nil
		}
	}
	return nil, errCacheNotFound
}

func (c *TorTargetsCache) writecache(req *apimodel.TorTargetsRequest, resp apimodel.TorTargetsResponse) error {
	cache, _ := c.getcache()
	out := []cacheEntryForTorTargets{{Req: req, Resp: resp}}
	const toomany = 32
	for idx, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			continue // we already updated the cache
		}
		if idx > toomany {
			break
		}
		out = append(out, cur)
	}
	return c.setcache(out)
}

var _ TorTargetsCaller = &TorTargetsCache{}

// URLsCache implements caching for URLsAPI.
type URLsCache struct {
	API      URLsCaller // mandatory
	GobCodec GobCodec   // optional
	KVStore  KVStore    // mandatory
}

type cacheEntryForURLs struct {
	Req  *apimodel.URLsRequest
	Resp *apimodel.URLsResponse
}

func (c *URLsCache) Call(ctx context.Context, req *apimodel.URLsRequest) (*apimodel.URLsResponse, error) {
	resp, err := c.API.Call(ctx, req)
	if err != nil {
		if resp, _ := c.readcache(req); resp != nil {
			return resp, nil
		}
		return nil, err
	}
	if err := c.writecache(req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *URLsCache) gobCodec() GobCodec {
	if c.GobCodec != nil {
		return c.GobCodec
	}
	return &defaultGobCodec{}
}

func (c *URLsCache) getcache() ([]cacheEntryForURLs, error) {
	data, err := c.KVStore.Get("URLs.cache")
	if err != nil {
		return nil, err
	}
	var out []cacheEntryForURLs
	if err := c.gobCodec().Decode(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *URLsCache) setcache(in []cacheEntryForURLs) error {
	data, err := c.gobCodec().Encode(in)
	if err != nil {
		return err
	}
	return c.KVStore.Set("URLs.cache", data)
}

func (c *URLsCache) readcache(req *apimodel.URLsRequest) (*apimodel.URLsResponse, error) {
	cache, err := c.getcache()
	if err != nil {
		return nil, err
	}
	for _, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			return cur.Resp, nil
		}
	}
	return nil, errCacheNotFound
}

func (c *URLsCache) writecache(req *apimodel.URLsRequest, resp *apimodel.URLsResponse) error {
	cache, _ := c.getcache()
	out := []cacheEntryForURLs{{Req: req, Resp: resp}}
	const toomany = 32
	for idx, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			continue // we already updated the cache
		}
		if idx > toomany {
			break
		}
		out = append(out, cur)
	}
	return c.setcache(out)
}

var _ URLsCaller = &URLsCache{}

// OpenReportCache implements caching for OpenReportAPI.
type OpenReportCache struct {
	API      OpenReportCaller // mandatory
	GobCodec GobCodec         // optional
	KVStore  KVStore          // mandatory
}

type cacheEntryForOpenReport struct {
	Req  *apimodel.OpenReportRequest
	Resp *apimodel.OpenReportResponse
}

func (c *OpenReportCache) Call(ctx context.Context, req *apimodel.OpenReportRequest) (*apimodel.OpenReportResponse, error) {
	resp, err := c.API.Call(ctx, req)
	if err != nil {
		if resp, _ := c.readcache(req); resp != nil {
			return resp, nil
		}
		return nil, err
	}
	if err := c.writecache(req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *OpenReportCache) gobCodec() GobCodec {
	if c.GobCodec != nil {
		return c.GobCodec
	}
	return &defaultGobCodec{}
}

func (c *OpenReportCache) getcache() ([]cacheEntryForOpenReport, error) {
	data, err := c.KVStore.Get("OpenReport.cache")
	if err != nil {
		return nil, err
	}
	var out []cacheEntryForOpenReport
	if err := c.gobCodec().Decode(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *OpenReportCache) setcache(in []cacheEntryForOpenReport) error {
	data, err := c.gobCodec().Encode(in)
	if err != nil {
		return err
	}
	return c.KVStore.Set("OpenReport.cache", data)
}

func (c *OpenReportCache) readcache(req *apimodel.OpenReportRequest) (*apimodel.OpenReportResponse, error) {
	cache, err := c.getcache()
	if err != nil {
		return nil, err
	}
	for _, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			return cur.Resp, nil
		}
	}
	return nil, errCacheNotFound
}

func (c *OpenReportCache) writecache(req *apimodel.OpenReportRequest, resp *apimodel.OpenReportResponse) error {
	cache, _ := c.getcache()
	out := []cacheEntryForOpenReport{{Req: req, Resp: resp}}
	const toomany = 32
	for idx, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			continue // we already updated the cache
		}
		if idx > toomany {
			break
		}
		out = append(out, cur)
	}
	return c.setcache(out)
}

var _ OpenReportCaller = &OpenReportCache{}

// SubmitMeasurementCache implements caching for SubmitMeasurementAPI.
type SubmitMeasurementCache struct {
	API      SubmitMeasurementCaller // mandatory
	GobCodec GobCodec                // optional
	KVStore  KVStore                 // mandatory
}

type cacheEntryForSubmitMeasurement struct {
	Req  *apimodel.SubmitMeasurementRequest
	Resp *apimodel.SubmitMeasurementResponse
}

func (c *SubmitMeasurementCache) Call(ctx context.Context, req *apimodel.SubmitMeasurementRequest) (*apimodel.SubmitMeasurementResponse, error) {
	resp, err := c.API.Call(ctx, req)
	if err != nil {
		if resp, _ := c.readcache(req); resp != nil {
			return resp, nil
		}
		return nil, err
	}
	if err := c.writecache(req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *SubmitMeasurementCache) gobCodec() GobCodec {
	if c.GobCodec != nil {
		return c.GobCodec
	}
	return &defaultGobCodec{}
}

func (c *SubmitMeasurementCache) getcache() ([]cacheEntryForSubmitMeasurement, error) {
	data, err := c.KVStore.Get("SubmitMeasurement.cache")
	if err != nil {
		return nil, err
	}
	var out []cacheEntryForSubmitMeasurement
	if err := c.gobCodec().Decode(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *SubmitMeasurementCache) setcache(in []cacheEntryForSubmitMeasurement) error {
	data, err := c.gobCodec().Encode(in)
	if err != nil {
		return err
	}
	return c.KVStore.Set("SubmitMeasurement.cache", data)
}

func (c *SubmitMeasurementCache) readcache(req *apimodel.SubmitMeasurementRequest) (*apimodel.SubmitMeasurementResponse, error) {
	cache, err := c.getcache()
	if err != nil {
		return nil, err
	}
	for _, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			return cur.Resp, nil
		}
	}
	return nil, errCacheNotFound
}

func (c *SubmitMeasurementCache) writecache(req *apimodel.SubmitMeasurementRequest, resp *apimodel.SubmitMeasurementResponse) error {
	cache, _ := c.getcache()
	out := []cacheEntryForSubmitMeasurement{{Req: req, Resp: resp}}
	const toomany = 32
	for idx, cur := range cache {
		if reflect.DeepEqual(req, cur.Req) {
			continue // we already updated the cache
		}
		if idx > toomany {
			break
		}
		out = append(out, cur)
	}
	return c.setcache(out)
}

var _ SubmitMeasurementCaller = &SubmitMeasurementCache{}
