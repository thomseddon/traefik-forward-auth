package provider

import (
	"context"
	// "net/url"

	"github.com/thomseddon/traefik-forward-auth/internal/cookie"
	"golang.org/x/oauth2"
)

// Providers contains all the implemented providers
type Providers struct {
	Google       Google       `group:"Google Provider" namespace:"google" env-namespace:"GOOGLE"`
	OIDC         OIDC         `group:"OIDC Provider" namespace:"oidc" env-namespace:"OIDC"`
	GenericOAuth GenericOAuth `group:"Generic OAuth2 Provider" namespace:"generic-oauth" env-namespace:"GENERIC_OAUTH"`
}

// Provider is used to authenticate users
type Provider interface {
	Name() string
	GetLoginURL(redirectURI, state string, cookieStore cookie.CookieStore) (string, error)
	ExchangeCode(redirectURI, code string, cookieStore cookie.CookieStore) (string, error)
	GetUser(token string) (User, error)
	Setup() error
}

type token struct {
	Token string `json:"access_token"`
}

// User is the authenticated user
type User struct {
	Email string `json:"email"`
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
func (p *OAuthProvider) OAuthGetLoginURL(redirectURI, state string, opts ...oauth2.AuthCodeOption) string {
	config := p.ConfigCopy(redirectURI)

	if p.Resource != "" {
		return config.AuthCodeURL(state, oauth2.SetAuthURLParam("resource", p.Resource))
	}

	return config.AuthCodeURL(state, opts...)
}

// OAuthExchangeCode provides a base "ExchangeCode" for proiders using OAauth2
func (p *OAuthProvider) OAuthExchangeCode(redirectURI, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := p.ConfigCopy(redirectURI)
	return config.Exchange(p.ctx, code, opts...)
}
