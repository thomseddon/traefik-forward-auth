package provider

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Utilities

type TokenServerHandler struct{}

func (t *TokenServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	if r.Method == "POST" &&
			string(body) == "client_id=idtest&client_secret=sectest&code=code&grant_type=authorization_code&redirect_uri=http%3A%2F%2Fexample.com%2F_oauth" {
		fmt.Fprint(w, `{"access_token":"123456789"}`)
	} else {
		fmt.Fprint(w, `TokenServerHandler received bad request`)
	}
}

type UserServerHandler struct{}

func (t *UserServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `{
    "id":"1",
    "email":"example@example.com",
    "verified_email":true,
    "hd":"example.com"
  }`)
}

// Tests

func TestGoogleName(t *testing.T) {
	p := Google{}
	assert.Equal(t, "google", p.Name())
}

func TestGoogleValidate(t *testing.T) {
	assert := assert.New(t)
	p := Google{}

	err := p.Validate()
	if assert.Error(err) {
		assert.Equal("providers.google.client-id, providers.google.client-secret must be set", err.Error())
	}
}

func TestGoogleGetLoginURL(t *testing.T) {
	assert := assert.New(t)
	p := Google{
		ClientId:     "idtest",
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
	p := Google{
		ClientId:     "idtest",
		ClientSecret: "sectest",
		Scope:        "scopetest",
		Prompt:       "consent select_account",
		LoginURL: &url.URL{
			Scheme: "https",
			Host:   "google.com",
			Path:   "/auth",
		},
	}

	// Setup token server
	tokenServerHandler := &TokenServerHandler{}
	tokenServer := httptest.NewServer(tokenServerHandler)
	defer tokenServer.Close()
	tokenURL, _ := url.Parse(tokenServer.URL)
	p.TokenURL = tokenURL

	token, err := p.ExchangeCode("http://example.com/_oauth", "code")
	assert.Nil(err)
	assert.Equal("123456789", token)
}

func TestGoogleGetUser(t *testing.T) {
	assert := assert.New(t)
	p := Google{
		ClientId:     "idtest",
		ClientSecret: "sectest",
		Scope:        "scopetest",
		Prompt:       "consent select_account",
		LoginURL: &url.URL{
			Scheme: "https",
			Host:   "google.com",
			Path:   "/auth",
		},
	}

	// Setup user server
	userServerHandler := &UserServerHandler{}
	userServer := httptest.NewServer(userServerHandler)
	defer userServer.Close()
	userURL, _ := url.Parse(userServer.URL)
	p.UserURL = userURL

	user, err := p.GetUser("123456789")
	assert.Nil(err)

  assert.Equal("1", user.Id)
  assert.Equal("example@example.com", user.Email)
  assert.True(user.Verified)
  assert.Equal("example.com", user.Hd)
}
