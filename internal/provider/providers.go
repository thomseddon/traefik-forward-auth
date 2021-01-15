package provider

import (
	"context"
	"fmt"
	"io"
	// "net/url"

	"github.com/Jeffail/gabs/v2"
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
	GetLoginURL(redirectURI, state string) string
	ExchangeCode(redirectURI, code string) (string, error)
	GetUser(token, UserPath string) (string, error)
	Setup() error
}

type token struct {
	Token string `json:"access_token"`
}

// User is the authenticated user
type User struct {
	Email string `json:"email"`
}

// GetUser extracts a UserID located at the (dot notation) path (UserPath) in the json io.Reader of the UserURL
func GetUser(r io.Reader, UserPath string) (string, error) {
	json, err := gabs.ParseJSONBuffer(r)
	if err != nil {
		return "", err
	}

	if !json.ExistsP(UserPath) {
		return "", fmt.Errorf("no such user path: '%s' in the UserURL response: %s", UserPath, string(json.Bytes()))
	}
	return fmt.Sprintf("%v", json.Path(UserPath).Data()), nil
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
