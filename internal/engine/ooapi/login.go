// Code generated by go generate; DO NOT EDIT.
// 2021-02-23 11:53:23.750267 +0100 CET m=+1.483818163

package ooapi

//go:generate go run ./internal/generator

import (
	"context"
	"errors"

	"github.com/ooni/probe-cli/v3/internal/engine/ooapi/apimodel"
)

// PsiphonConfigAPIWithLogin implements login for PsiphonConfigAPI.
type PsiphonConfigAPIWithLogin struct {
	API         PsiphonConfigCloner // mandatory
	JSONCodec   JSONCodec           // optional
	KVStore     KVStore             // mandatory
	RegisterAPI RegisterCaller      // mandatory
	LoginAPI    LoginCaller         // mandatory
}

func (api *PsiphonConfigAPIWithLogin) Call(ctx context.Context, req *apimodel.PsiphonConfigRequest) (apimodel.PsiphonConfigResponse, error) {
	token, err := api.maybeLogin(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := api.API.WithToken(token).Call(ctx, req)
	if errors.Is(err, ErrUnauthorized) {
		token, err = api.forceRegister(ctx)
		if err != nil {
			return nil, err
		}
		resp, err = api.API.WithToken(token).Call(ctx, req)
		// fallthrough
	}
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (api *PsiphonConfigAPIWithLogin) jsonCodec() JSONCodec {
	if api.JSONCodec != nil {
		return api.JSONCodec
	}
	return &defaultJSONCodec{}
}

func (api *PsiphonConfigAPIWithLogin) readstate() (*loginState, error) {
	data, err := api.KVStore.Get(loginKey)
	if err != nil {
		return nil, err
	}
	var ls loginState
	if err := api.jsonCodec().Decode(data, &ls); err != nil {
		return nil, err
	}
	return &ls, nil
}

func (api *PsiphonConfigAPIWithLogin) writestate(ls *loginState) error {
	data, err := api.jsonCodec().Encode(*ls)
	if err != nil {
		return err
	}
	return api.KVStore.Set(loginKey, data)
}

func (api *PsiphonConfigAPIWithLogin) forceRegister(ctx context.Context) (string, error) {
	req := newRegisterRequest()
	ls := &loginState{}
	resp, err := api.RegisterAPI.Call(ctx, req)
	if err != nil {
		return "", err
	}
	ls.ClientID = resp.ClientID
	ls.Password = req.Password
	return api.doLogin(ctx, ls)
}

func (api *PsiphonConfigAPIWithLogin) maybeLogin(ctx context.Context) (string, error) {
	ls, _ := api.readstate()
	if ls == nil || !ls.credentialsValid() {
		return api.forceRegister(ctx)
	}
	if !ls.tokenValid() {
		return api.doLogin(ctx, ls)
	}
	return ls.Token, nil
}

func (api *PsiphonConfigAPIWithLogin) doLogin(ctx context.Context, ls *loginState) (string, error) {
	req := &apimodel.LoginRequest{
		ClientID: ls.ClientID,
		Password: ls.Password,
	}
	resp, err := api.LoginAPI.Call(ctx, req)
	if err != nil {
		return "", err
	}
	ls.Token = resp.Token
	ls.Expire = resp.Expire
	if err := api.writestate(ls); err != nil {
		return "", err
	}
	return ls.Token, nil
}

var _ PsiphonConfigCaller = &PsiphonConfigAPIWithLogin{}

// TorTargetsAPIWithLogin implements login for TorTargetsAPI.
type TorTargetsAPIWithLogin struct {
	API         TorTargetsCloner // mandatory
	JSONCodec   JSONCodec        // optional
	KVStore     KVStore          // mandatory
	RegisterAPI RegisterCaller   // mandatory
	LoginAPI    LoginCaller      // mandatory
}

func (api *TorTargetsAPIWithLogin) Call(ctx context.Context, req *apimodel.TorTargetsRequest) (apimodel.TorTargetsResponse, error) {
	token, err := api.maybeLogin(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := api.API.WithToken(token).Call(ctx, req)
	if errors.Is(err, ErrUnauthorized) {
		token, err = api.forceRegister(ctx)
		if err != nil {
			return nil, err
		}
		resp, err = api.API.WithToken(token).Call(ctx, req)
		// fallthrough
	}
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (api *TorTargetsAPIWithLogin) jsonCodec() JSONCodec {
	if api.JSONCodec != nil {
		return api.JSONCodec
	}
	return &defaultJSONCodec{}
}

func (api *TorTargetsAPIWithLogin) readstate() (*loginState, error) {
	data, err := api.KVStore.Get(loginKey)
	if err != nil {
		return nil, err
	}
	var ls loginState
	if err := api.jsonCodec().Decode(data, &ls); err != nil {
		return nil, err
	}
	return &ls, nil
}

func (api *TorTargetsAPIWithLogin) writestate(ls *loginState) error {
	data, err := api.jsonCodec().Encode(*ls)
	if err != nil {
		return err
	}
	return api.KVStore.Set(loginKey, data)
}

func (api *TorTargetsAPIWithLogin) forceRegister(ctx context.Context) (string, error) {
	req := newRegisterRequest()
	ls := &loginState{}
	resp, err := api.RegisterAPI.Call(ctx, req)
	if err != nil {
		return "", err
	}
	ls.ClientID = resp.ClientID
	ls.Password = req.Password
	return api.doLogin(ctx, ls)
}

func (api *TorTargetsAPIWithLogin) maybeLogin(ctx context.Context) (string, error) {
	ls, _ := api.readstate()
	if ls == nil || !ls.credentialsValid() {
		return api.forceRegister(ctx)
	}
	if !ls.tokenValid() {
		return api.doLogin(ctx, ls)
	}
	return ls.Token, nil
}

func (api *TorTargetsAPIWithLogin) doLogin(ctx context.Context, ls *loginState) (string, error) {
	req := &apimodel.LoginRequest{
		ClientID: ls.ClientID,
		Password: ls.Password,
	}
	resp, err := api.LoginAPI.Call(ctx, req)
	if err != nil {
		return "", err
	}
	ls.Token = resp.Token
	ls.Expire = resp.Expire
	if err := api.writestate(ls); err != nil {
		return "", err
	}
	return ls.Token, nil
}

var _ TorTargetsCaller = &TorTargetsAPIWithLogin{}
