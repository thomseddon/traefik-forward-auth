//+build wireinject

package tfa

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/google/wire"
	"github.com/thomseddon/traefik-forward-auth/internal/provider"
)

func initiateProvider(c Config) (provider.AuthProvider, error) {
	// This will be filled in by Wire with providers
	wire.Build(setupProvider)
	return nil, nil
}

func setupProvider(c Config) (provider.AuthProvider, error) {
	switch c.IDService {
	case GoogleAuth:
		return setupGoogle(c), nil
	case AzureAD:
		return setupAzure(c), nil
	default:
		return nil, errors.New("Bad Auth provider")
	}
}

func setupGoogle(c Config) *provider.Google {
	return &provider.Google{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Prompt:       c.Prompt,
		Scope:        "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email",
		LoginURL: &url.URL{
			Scheme: "https",
			Host:   "accounts.google.com",
			Path:   "/o/oauth2/auth",
		},
		TokenURL: &url.URL{
			Scheme: "https",
			Host:   "www.googleapis.com",
			Path:   "/oauth2/v3/token",
		},
		UserURL: &url.URL{
			Scheme: "https",
			Host:   "www.googleapis.com",
			Path:   "/oauth2/v2/userinfo",
		},
	}
}

func setupAzure(c Config) *provider.Azure {
	return &provider.Azure{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Prompt:       c.Prompt,
		LoginURL: &url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   fmt.Sprintf("/%s/oauth2/authorize", c.TenantID),
		},
		TokenURL: &url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   fmt.Sprintf("/%s/oauth2/token", c.TenantID),
		},
		UserURL: &url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   fmt.Sprintf("/%s/openid/userinfo", c.TenantID),
		},
	}
}
