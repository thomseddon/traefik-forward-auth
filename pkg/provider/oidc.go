package provider

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// OIDC provider
type OIDC struct {
	IssuerURL    string `long:"issuer-url" env:"ISSUER_URL" description:"Issuer URL"`
	ClientID     string `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret string `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`

	OAuthProvider

	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

// Name returns the name of the provider
func (o *OIDC) Name() string {
	return "oidc"
}

type LoggingRoundTripper struct {
	Proxied http.RoundTripper
	Logger  *log.Logger
}

func (lrt *LoggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()

	// Log request details
	lrt.Logger.Printf("Sending request: %s %s", req.Method, req.URL.String())

	// Execute the actual request
	resp, err := lrt.Proxied.RoundTrip(req)

	// Log response details or error
	if err != nil {
		lrt.Logger.Printf("Request failed: %s %s - Error: %v", req.Method, req.URL.String(), err)
		return nil, err
	}

	lrt.Logger.Printf("Received response: %s %s - Status: %s - Duration: %v",
		req.Method, req.URL.String(), resp.Status, time.Since(start))

	return resp, nil
}

// Setup performs validation and setup
func (o *OIDC) Setup() error {
	// Check params
	if o.IssuerURL == "" || o.ClientID == "" || o.ClientSecret == "" {
		return errors.New("providers.oidc.issuer-url, providers.oidc.client-id, providers.oidc.client-secret must be set")
	}
	myLogger := log.Default()

	httpClient := &http.Client{
		Transport: &LoggingRoundTripper{
			Proxied: http.DefaultTransport, // Or any other http.RoundTripper
			Logger:  myLogger,
		},
	}

	var err error
	ctx := context.Background()
	o.ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	// Try to initiate provider
	o.provider, err = oidc.NewProvider(o.ctx, o.IssuerURL)
	if err != nil {
		return err
	}

	// Create oauth2 config
	o.Config = &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		Endpoint:     o.provider.Endpoint(),
		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email", oidc.ScopeOfflineAccess},
	}

	// Create OIDC verifier
	o.verifier = o.provider.Verifier(&oidc.Config{
		ClientID: o.ClientID,
	})

	return nil
}

// GetLoginURL provides the login url for the given redirect uri and state
func (o *OIDC) GetLoginURL(redirectURI, state string) string {
	return o.OAuthGetLoginURL(redirectURI, state)
}

// ExchangeCode exchanges the given redirect uri and code for a token
func (o *OIDC) ExchangeCode(redirectURI, code string) (string, error) {
	token, err := o.OAuthExchangeCode(redirectURI, code)
	if err != nil {
		return "", err
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("access_token").(string)
	if !ok {
		return "", errors.New("Missing access_token")
	}

	return rawIDToken, nil
}

// GetUser uses the given token and returns a complete provider.User object
func (o *OIDC) GetUser(token string) (User, error) {
	var user User

	// Parse & Verify ID Token
	idToken, err := o.verifier.Verify(o.ctx, token)
	if err != nil {
		return user, err
	}

	// Extract custom claims
	if err := idToken.Claims(&user); err != nil {
		return user, err
	}

	return user, nil
}
