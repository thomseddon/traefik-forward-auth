package provider

import (
	"context"
	// "net/url"

	"golang.org/x/oauth2"
)

// Providers contains all the implemented providers
type Providers struct {
	GenericOAuth GenericOAuth `group:"Generic OAuth2 Provider" namespace:"generic-oauth" env-namespace:"GENERIC_OAUTH"`
	Google       Google       `group:"Google Provider" namespace:"google" env-namespace:"GOOGLE"`
	OIDC         OIDC         `group:"OIDC Provider" namespace:"oidc" env-namespace:"OIDC"`
}

// Provider is used to authenticate users
type Provider interface {
	Name() string
	GetLoginURL(redirectURI, state string) string
	ExchangeCode(redirectURI, code string) (string, error)
	GetUser(token string) (User, error)
	Setup() error
}

type token struct {
	Token string `json:"access_token"`
}

// User is the authenticated user
type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Verified bool   `json:"verified_email"`
	Hd       string `json:"hd"`
}

// OAuthProvider is a provider using the oauth2 library
type OAuthProvider struct {
	Resource string `long:"resource" env:"RESOURCE" description:"Optional resource indicator"`

	Config *oauth2.Config
	ctx    context.Context
}

// ConfigCopy returns a copy of the oauth2 config with the given redirectURI
// which ensures the underlying config is not modified
func (p *OAuthProvider) ConfigCopy(redirectURI string) oauth2.Config {
	config := *p.Config
	config.RedirectURL = redirectURI
	return config
}

// OAuthGetLoginURL provides a base "GetLoginURL" for proiders using OAauth2
func (p *OAuthProvider) OAuthGetLoginURL(redirectURI, state string) string {
	config := p.ConfigCopy(redirectURI)

	if p.Resource != "" {
		return config.AuthCodeURL(state, oauth2.SetAuthURLParam("resource", p.Resource))
	}

	return config.AuthCodeURL(state)
}

// OAuthExchangeCode provides a base "ExchangeCode" for proiders using OAauth2
func (p *OAuthProvider) OAuthExchangeCode(redirectURI, code string) (*oauth2.Token, error) {
	config := p.ConfigCopy(redirectURI)
	return config.Exchange(p.ctx, code)
}
