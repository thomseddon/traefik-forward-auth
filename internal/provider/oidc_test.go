package provider

import (
	// "fmt"
	// "io/ioutil"
	// "net/http"
	// "net/http/httptest"
	"net/url"
	"testing"

	"golang.org/x/oauth2"
	"github.com/stretchr/testify/assert"
)
// Utilities

// type IssuerServerHandler struct{}

// func NewIssuerServer() (*httptest.Server, *url.URL) {
// 	handler := &IssuerServerHandler{}
// 	server := httptest.NewServer(handler)
// 	URL, _ := url.Parse(server.URL)
// 	return server, URL
// }

// func (t *IssuerServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
// 	// body, _ := ioutil.ReadAll(r.Body)
// 	fmt.Fprint(w, `{"access_token":"123456789"}`)
// 	// if r.Method == "POST" &&
// 	// 		string(body) == "client_id=idtest&client_secret=sectest&code=code&grant_type=authorization_code&redirect_uri=http%3A%2F%2Fexample.com%2F_oauth" {
// 	// 	fmt.Fprint(w, `{"access_token":"123456789"}`)
// 	// } else {
// 	// 	fmt.Fprint(w, `IssuerServerHandler received bad request`)
// 	// }
// }

// Tests

func TestOIDCName(t *testing.T) {
	p := OIDC{}
	assert.Equal(t, "oidc", p.Name())
}

func TestOIDCValidate(t *testing.T) {
	assert := assert.New(t)
	p := OIDC{}

	err := p.Validate()
	if assert.Error(err) {
		assert.Equal("providers.oidc.issuer-url, providers.oidc.client-id, providers.oidc.client-secret must be set", err.Error())
	}

	// TODO: validate config object
}

func TestOIDCGetLoginURL(t *testing.T) {
	assert := assert.New(t)

	// Set up token server
	tokenServer, tokenURL := NewTokenServer(map[string]string{})
	defer tokenServer.Close()

	p := OIDC{
		config: &oauth2.Config{
			ClientID:     "idtest",
			ClientSecret: "sectest",
			Endpoint: oauth2.Endpoint{
				AuthURL: tokenURL.String(),
			},
			Scopes: []string{"profile", "email"},
		},
	}

	// Check url
	uri, err := url.Parse(p.GetLoginURL("http://example.com/_oauth", "state"))
	assert.Nil(err)
	assert.Equal(tokenURL.Scheme, uri.Scheme)
	assert.Equal(tokenURL.Host, uri.Host)
	assert.Equal(tokenURL.Path, uri.Path)

	// Check query string
	qs := uri.Query()
	expectedQs := url.Values{
		"client_id":     []string{"idtest"},
		"redirect_uri":  []string{"http://example.com/_oauth"},
		"response_type": []string{"code"},
		"scope":         []string{"profile email"},
		"state":         []string{"state"},
	}
	assert.Equal(expectedQs, qs)
}

func TestOIDCExchangeCode(t *testing.T) {
	assert := assert.New(t)

	// Set up token server
	tokenServer, tokenURL := NewTokenServer(map[string]string{
		"code": "code",
		"grant_type": "authorization_code",
		"redirect_uri": "http://example.com/_oauth",
	})
	defer tokenServer.Close()

	p := OIDC{
		config: &oauth2.Config{
			ClientID:     "idtest",
			ClientSecret: "sectest",
			Endpoint: oauth2.Endpoint{
				TokenURL: tokenURL.String(),
			},
			Scopes: []string{"profile", "email"},
		},
	}

	token, err := p.ExchangeCode("http://example.com/_oauth", "code")
	assert.Nil(err)
	assert.Equal("id_123456789", token)
}

func TestOIDCGetUser(t *testing.T) {
	assert := assert.New(t)

	// Set up token server
	userServer, userURL := NewUserServer()
	defer userServer.Close()

	p := OIDC{
		config: &oauth2.Config{
			ClientID:     "idtest",
			ClientSecret: "sectest",
			Endpoint: oauth2.Endpoint{
				TokenURL: userURL.String(),
			},
			Scopes: []string{"profile", "email"},
		},
	}

	user, err := p.GetUser("123456789")
	assert.Nil(err)

  assert.Equal("1", user.Id)
  assert.Equal("example@example.com", user.Email)
  assert.True(user.Verified)
	assert.Equal("example.com", user.Hd)
	return

	// assert := assert.New(t)
	// p := OIDC{
	// 	ClientId:     "idtest",
	// 	ClientSecret: "sectest",
	// 	Scope:        "scopetest",
	// 	Prompt:       "consent select_account",
	// 	LoginURL: &url.URL{
	// 		Scheme: "https",
	// 		Host:   "google.com",
	// 		Path:   "/auth",
	// 	},
	// }

	// // Setup user server
	// userServerHandler := &UserServerHandler{}
	// userServer := httptest.NewServer(userServerHandler)
	// defer userServer.Close()
	// userURL, _ := url.Parse(userServer.URL)
	// p.UserURL = userURL

	// user, err := p.GetUser("123456789")
	// assert.Nil(err)

  // assert.Equal("1", user.Id)
  // assert.Equal("example@example.com", user.Email)
  // assert.True(user.Verified)
  // assert.Equal("example.com", user.Hd)
}
