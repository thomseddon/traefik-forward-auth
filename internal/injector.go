//+build wireinject

package tfa

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"

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
	case OIDC:
		return setupOIDC(c), nil
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

func getOIDCConfig(oidc string) map[string]interface{} {
	uri, err := url.Parse(oidc)
	if err != nil {
		log.Fatal("Failed to parse OIDC string.")
	}

	uri.Path = path.Join(uri.Path, "/.well-known/openid-configuration")
	res, err := http.Get(uri.String())
	if err != nil {
		log.Fatal("Failed to get OIDC parameter from OIDC connect.")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal("Failed to read response body.")
	}

	var result map[string]interface{}
	json.Unmarshal(body, &result)
	log.Debug(result)

	return result
}

func setupOIDC(c Config) *provider.OIDC {
	var OIDCParams = getOIDCConfig(c.OIDCIssuer)

	LoginURL, err := url.Parse((OIDCParams["authorization_endpoint"].(string)))
	if err != nil {
		log.Fatal("Unable to parse Login URL.")
	}

	TokenURL, err := url.Parse((OIDCParams["token_endpoint"].(string)))
	if err != nil {
		log.Fatal("Unable to parse Token URL.")
	}

	UserURL, err := url.Parse((OIDCParams["userinfo_endpoint"].(string)))
	if err != nil {
		log.Fatal("Unable to parse User URL.")
	}

	return &provider.OIDC{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Prompt:       c.Prompt,
		LoginURL:     LoginURL,
		TokenURL:     TokenURL,
		UserURL:      UserURL,
	}
}
