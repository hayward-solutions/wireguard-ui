package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDCProvider struct {
	provider     *oidc.Provider
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
	groupsClaim  string
}

type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       string
	GroupsClaim  string
}

type OIDCUser struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
}

func NewOIDCProvider(ctx context.Context, cfg OIDCConfig) (*OIDCProvider, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("init oidc provider: %w", err)
	}

	scopes := []string{oidc.ScopeOpenID}
	for _, s := range strings.Split(cfg.Scopes, ",") {
		s = strings.TrimSpace(s)
		if s != "" && s != oidc.ScopeOpenID {
			scopes = append(scopes, s)
		}
	}

	oauth2Config := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	groupsClaim := cfg.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "cognito:groups"
	}

	return &OIDCProvider{
		provider:     provider,
		oauth2Config: oauth2Config,
		verifier:     verifier,
		groupsClaim:  groupsClaim,
	}, nil
}

// AuthCodeURL returns the URL to redirect the user to for authentication.
func (p *OIDCProvider) AuthCodeURL(state string) string {
	return p.oauth2Config.AuthCodeURL(state)
}

// Exchange exchanges an authorization code for tokens and returns the user info.
func (p *OIDCProvider) Exchange(ctx context.Context, code string) (*OIDCUser, error) {
	token, err := p.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in response")
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", err)
	}

	var rawClaims map[string]interface{}
	if err := idToken.Claims(&rawClaims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	email, _ := rawClaims["email"].(string)
	name, _ := rawClaims["name"].(string)

	var groups []string
	if gc, ok := rawClaims[p.groupsClaim]; ok {
		if arr, ok := gc.([]interface{}); ok {
			for _, v := range arr {
				if s, ok := v.(string); ok {
					groups = append(groups, s)
				}
			}
		}
	}

	return &OIDCUser{
		Subject: idToken.Subject,
		Email:   email,
		Name:    name,
		Groups:  groups,
	}, nil
}
