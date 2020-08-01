package provider

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Tests

func TestGoogleName(t *testing.T) {
	p := Google{}
	assert.Equal(t, "google", p.Name())
}

func TestGoogleSetup(t *testing.T) {
	assert := assert.New(t)
	p := Google{}

	// Check validation
	err := p.Setup()
	if assert.Error(err) {
		assert.Equal("providers.google.client-id, providers.google.client-secret must be set", err.Error())
	}

	// Check setup
	p = Google{
		ClientID:     "id",
		ClientSecret: "secret",
	}
	err = p.Setup()
	assert.Nil(err)
	assert.Equal("https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email", p.Scope)
	assert.Equal("", p.Prompt)

	assert.Equal(&url.URL{
		Scheme: "https",
		Host:   "accounts.google.com",
		Path:   "/o/oauth2/auth",
	}, p.LoginURL)

	assert.Equal(&url.URL{
		Scheme: "https",
		Host:   "www.googleapis.com",
		Path:   "/oauth2/v3/token",
	}, p.TokenURL)

	assert.Equal(&url.URL{
		Scheme: "https",
		Host:   "www.googleapis.com",
		Path:   "/oauth2/v2/userinfo",
	}, p.UserURL)
}

func TestGoogleGetLoginURL(t *testing.T) {
	assert := assert.New(t)
	p := Google{
		ClientID:     "idtest",
		ClientSecret: "sectest",
		Scope:        "scopetest",
		Prompt:       "consent select_account",
		LoginURL: &url.URL{
			Scheme: "https",
			Host:   "google.com",
			Path:   "/auth",
		},
	}

	// Check url
	uri, err := url.Parse(p.GetLoginURL("http://example.com/_oauth", "state"))
	assert.Nil(err)
	assert.Equal("https", uri.Scheme)
	assert.Equal("google.com", uri.Host)
	assert.Equal("/auth", uri.Path)

	// Check query string
	qs := uri.Query()
	expectedQs := url.Values{
		"client_id":     []string{"idtest"},
		"redirect_uri":  []string{"http://example.com/_oauth"},
		"response_type": []string{"code"},
		"scope":         []string{"scopetest"},
		"prompt":        []string{"consent select_account"},
		"state":         []string{"state"},
	}
	assert.Equal(expectedQs, qs)
}

func TestGoogleExchangeCode(t *testing.T) {
	assert := assert.New(t)

	// Setup server
	expected := url.Values{
		"client_id":     []string{"idtest"},
		"client_secret": []string{"sectest"},
		"code":          []string{"code"},
		"grant_type":    []string{"authorization_code"},
		"redirect_uri":  []string{"http://example.com/_oauth"},
	}
	server, serverURL := NewOAuthServer(t, map[string]string{
		"token": expected.Encode(),
	})
	defer server.Close()

	// Setup provider
	p := Google{
		ClientID:     "idtest",
		ClientSecret: "sectest",
		Scope:        "scopetest",
		Prompt:       "consent select_account",
		TokenURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/token",
		},
	}

	token, err := p.ExchangeCode("http://example.com/_oauth", "code")
	assert.Nil(err)
	assert.Equal("123456789", token)
}

func TestGoogleGetUser(t *testing.T) {
	assert := assert.New(t)

	// Setup server
	server, serverURL := NewOAuthServer(t, nil)
	defer server.Close()

	// Setup provider
	p := Google{
		ClientID:     "idtest",
		ClientSecret: "sectest",
		Scope:        "scopetest",
		Prompt:       "consent select_account",
		UserURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/userinfo",
		},
	}

	user, err := p.GetUser("123456789", "email")
	assert.Nil(err)

	assert.Equal("example@example.com", user)
}
