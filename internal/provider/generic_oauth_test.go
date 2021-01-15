package provider

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

// Tests

func TestGenericOAuthName(t *testing.T) {
	p := GenericOAuth{}
	assert.Equal(t, "generic-oauth", p.Name())
}

func TestGenericOAuthSetup(t *testing.T) {
	assert := assert.New(t)
	p := GenericOAuth{}

	// Check validation
	err := p.Setup()
	if assert.Error(err) {
		assert.Equal("providers.generic-oauth.auth-url, providers.generic-oauth.token-url, providers.generic-oauth.user-url, providers.generic-oauth.client-id, providers.generic-oauth.client-secret must be set", err.Error())
	}

	// Check setup
	p = GenericOAuth{
		AuthURL:      "https://provider.com/oauth2/auth",
		TokenURL:     "https://provider.com/oauth2/token",
		UserURL:      "https://provider.com/oauth2/user",
		ClientID:     "id",
		ClientSecret: "secret",
	}
	err = p.Setup()
	assert.Nil(err)
}

func TestGenericOAuthGetLoginURL(t *testing.T) {
	assert := assert.New(t)
	p := GenericOAuth{
		AuthURL:      "https://provider.com/oauth2/auth",
		TokenURL:     "https://provider.com/oauth2/token",
		UserURL:      "https://provider.com/oauth2/user",
		ClientID:     "idtest",
		ClientSecret: "secret",
		Scopes:       []string{"scopetest"},
	}
	err := p.Setup()
	if err != nil {
		t.Fatal(err)
	}

	// Check url
	uri, err := url.Parse(p.GetLoginURL("http://example.com/_oauth", "state"))
	assert.Nil(err)
	assert.Equal("https", uri.Scheme)
	assert.Equal("provider.com", uri.Host)
	assert.Equal("/oauth2/auth", uri.Path)

	// Check query string
	qs := uri.Query()
	expectedQs := url.Values{
		"client_id":     []string{"idtest"},
		"redirect_uri":  []string{"http://example.com/_oauth"},
		"response_type": []string{"code"},
		"scope":         []string{"scopetest"},
		"state":         []string{"state"},
	}
	assert.Equal(expectedQs, qs)
}

func TestGenericOAuthExchangeCode(t *testing.T) {
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
	p := GenericOAuth{
		AuthURL:      "https://provider.com/oauth2/auth",
		TokenURL:     serverURL.String() + "/token",
		UserURL:      "https://provider.com/oauth2/user",
		ClientID:     "idtest",
		ClientSecret: "sectest",
	}
	err := p.Setup()
	if err != nil {
		t.Fatal(err)
	}

	// We force AuthStyleInParams to prevent the test failure when the
	// AuthStyleInHeader is attempted
	p.Config.Endpoint.AuthStyle = oauth2.AuthStyleInParams

	token, err := p.ExchangeCode("http://example.com/_oauth", "code")
	assert.Nil(err)
	assert.Equal("123456789", token)
}

func TestGenericOAuthGetUser(t *testing.T) {
	assert := assert.New(t)

	// Setup server
	server, serverURL := NewOAuthServer(t, nil)
	defer server.Close()

	// Setup provider
	p := GenericOAuth{
		AuthURL:      "https://provider.com/oauth2/auth",
		TokenURL:     "https://provider.com/oauth2/token",
		UserURL:      serverURL.String() + "/userinfo",
		ClientID:     "idtest",
		ClientSecret: "sectest",
	}
	err := p.Setup()
	if err != nil {
		t.Fatal(err)
	}

	// We force AuthStyleInParams to prevent the test failure when the
	// AuthStyleInHeader is attempted
	p.Config.Endpoint.AuthStyle = oauth2.AuthStyleInParams

	user, err := p.GetUser("123456789", "email")
	assert.Nil(err)

	assert.Equal("example@example.com", user)
}
