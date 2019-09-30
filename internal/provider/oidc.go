package provider

import (
	"errors"
	// "context"
	// "net/url"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type OIDC struct {
	IssuerURL    string `long:"issuer-url" env:"ISSUER_URL" description:"Issuer URL"`
	ClientID     string `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret string `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`

	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	config *oauth2.Config
}

func (o *OIDC) Name() string {
	return "oidc"
}

func (o *OIDC) Validate() error {
	// Check parms
	if o.IssuerURL == "" || o.ClientID == "" || o.ClientSecret == "" {
		return errors.New("providers.oidc.issuer-url, providers.oidc.client-id, providers.oidc.client-secret must be set")
	}

	// Try to initiate provider
	var err error
	// TODO: fix context
	o.provider, err = oidc.NewProvider(oauth2.NoContext, o.IssuerURL)
	if err != nil {
		return err
	}

	// Create oauth2 config
	o.config = &oauth2.Config{
    ClientID: o.ClientID,
    ClientSecret: o.ClientSecret,
    Endpoint: o.provider.Endpoint(),

    // "openid" is a required scope for OpenID Connect flows.
    Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}

	// Create OIDC verifier
	o.verifier = o.provider.Verifier(&oidc.Config{
		ClientID: o.ClientID,
	})

	return nil
}

func (o *OIDC) GetLoginURL(redirectUri, state string) string {
	config := o.config
	config.RedirectURL = redirectUri
	return o.config.AuthCodeURL(state)
}

func (o *OIDC) ExchangeCode(redirectUri, code string) (string, error) {
	config := o.config
	config.RedirectURL = redirectUri

	token, err := o.config.Exchange(oauth2.NoContext, code)
	if err != nil {
		return "", err
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", errors.New("Missing id_token")
	}

	return rawIDToken, nil
}

func (o *OIDC) GetUser(token string) (User, error) {
	var user User

	// Parse & Verify ID Token
	idToken, err := o.verifier.Verify(oauth2.NoContext, token)
	if err != nil {
		return user, err
	}

	// Extract custom claims
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return user, err
	}

	user.Email = claims.Email
	user.Verified = claims.Verified

	return user, nil

	// client := &http.Client{}
	// req, err := http.NewRequest("GET", g.UserURL.String(), nil)
	// if err != nil {
	// 	return user, err
	// }

	// req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	// res, err := client.Do(req)
	// if err != nil {
	// 	return user, err
	// }

	// defer res.Body.Close()
	// err = json.NewDecoder(res.Body).Decode(&user)

	// return user, err
}
