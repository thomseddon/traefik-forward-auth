package provider

import (
	"context"

	"golang.org/x/oauth2"
)

type Providers struct {
	Google Google `group:"Google Provider" namespace:"google" env-namespace:"GOOGLE"`
	OIDC   OIDC   `group:"ODIC Provider" namespace:"odic" env-namespace:"ODIC"`
}

type Provider interface {
	Name() string
	GetLoginURL(redirectUri, state string) string
	ExchangeCode(redirectUri, code string) (string, error)
	GetUser(token string) (User, error)
	Validate() error
}

type Token struct {
	Token string `json:"access_token"`
}

type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Verified bool   `json:"verified_email"`
	Hd       string `json:"hd"`
}

type OAuthProvider struct {
	config *oauth2.Config
	ctx    context.Context
}

// ConfigCopy returns a copy of the oauth2 config with the given redirectUri
// which ensures the underlying config is not modified
func (p *OAuthProvider) ConfigCopy(redirectUri string) oauth2.Config {
	config := *p.config
	config.RedirectURL = redirectUri
	return config
}

// OAuthGetLoginURL provides a base "GetLoginURL" for proiders using OAauth2
func (p *OAuthProvider) OAuthGetLoginURL(redirectUri, state string) string {
	config := p.ConfigCopy(redirectUri)
	return config.AuthCodeURL(state)
}

// OAuthExchangeCode provides a base "ExchangeCode" for proiders using OAauth2
func (p *OAuthProvider) OAuthExchangeCode(redirectUri, code string) (*oauth2.Token, error) {
	config := p.ConfigCopy(redirectUri)
	return config.Exchange(p.ctx, code)
}
