package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/thomseddon/traefik-forward-auth/internal/cookie"
	"github.com/thomseddon/traefik-forward-auth/internal/pkce"
	"golang.org/x/oauth2"
)

const (
	cookieNameNonce    = "oidc-nonce"
	cookieNamePkceCode = "oidc-pkce-code"
	cookieMaxAge       = 600 // 10 minutes
)

// OIDC provider
type OIDC struct {
	IssuerURL    string `long:"issuer-url" env:"ISSUER_URL" description:"Issuer URL"`
	ClientID     string `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret string `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`
	PkceRequired bool   `long:"pkce-required" env:"PKCE_REQUIRED" description:"Optional pkce required indicator"`

	OAuthProvider

	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

// Name returns the name of the provider
func (o *OIDC) Name() string {
	return "oidc"
}

// Setup performs validation and setup
func (o *OIDC) Setup() error {
	// Check params
	if err := o.checkParams(); err != nil {
		return err
	}

	var err error
	o.ctx = context.Background()

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
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}

	// Create OIDC verifier
	o.verifier = o.provider.Verifier(&oidc.Config{
		ClientID: o.ClientID,
	})

	return nil
}

// GetLoginURL provides the login url for the given redirect uri and state
func (o *OIDC) GetLoginURL(redirectURI, state string, cookieStore cookie.CookieStore) (string, error) {
	var opts []oauth2.AuthCodeOption

	// Generate and store nonce
	nonce, err := pkce.GenerateNonce()
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	cookieStore.SetCookie(cookieNameNonce, nonce,
		cookie.WithMaxAge(cookieMaxAge),
		cookie.WithSameSite(http.SameSiteStrictMode),
	)

	opts = append(opts, oauth2.SetAuthURLParam("nonce", nonce))

	if o.PkceRequired {
		pkceVerifier, err := pkce.CreateCodeVerifier()
		if err != nil {
			return "", fmt.Errorf("failed to create PKCE verifier: %w", err)
		}

		opts = append(opts,
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
			oauth2.SetAuthURLParam("code_challenge", pkceVerifier.CodeChallengeS256()),
		)

		cookieStore.SetCookie(cookieNamePkceCode, pkceVerifier.String(),
			cookie.WithMaxAge(cookieMaxAge),
			cookie.WithSameSite(http.SameSiteStrictMode),
		)
	}
	return o.OAuthGetLoginURL(redirectURI, state, opts...), nil
}

// ExchangeCode exchanges the given redirect uri and code for a token
func (o *OIDC) ExchangeCode(redirectURI, code string, cookieStore cookie.CookieStore) (string, error) {
	var opts []oauth2.AuthCodeOption

	if o.PkceRequired {
		pkceCode, err := cookieStore.GetCookie(cookieNamePkceCode)
		if err != nil {
			return "", err
		}
		cookieStore.DeleteCookie(cookieNamePkceCode)
		opts = append(opts, oauth2.SetAuthURLParam("code_verifier", pkceCode))
	}

	token, err := o.OAuthExchangeCode(redirectURI, code, opts...)
	if err != nil {
		return "", err
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", errors.New("Missing id_token")
	}

	// Verify nonce
	idToken, err := o.verifier.Verify(o.ctx, rawIDToken)
	if err != nil {
		return "", err
	}

	nonce, err := cookieStore.GetCookie(cookieNameNonce)
	if err != nil {
		return "", errors.New("nonce not found")
	}

	cookieStore.DeleteCookie(cookieNameNonce)

	if idToken.Nonce != nonce {
		return "", errors.New("nonce verification failed")
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

func (o *OIDC) checkParams() error {
	if o.IssuerURL == "" || o.ClientID == "" || (o.ClientSecret == "" && !o.PkceRequired) {
		var emptyFields []string

		if o.IssuerURL == "" {
			emptyFields = append(emptyFields, "providers.oidc.issuer-url")
		}

		if o.ClientID == "" {
			emptyFields = append(emptyFields, "providers.oidc.client-id")
		}

		if o.ClientSecret == "" && !o.PkceRequired {
			emptyFields = append(emptyFields, "providers.oidc.client-secret")
		}

		return errors.New(strings.Join(emptyFields, ", ") + " must be set")
	}

	return nil
}
