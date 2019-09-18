package provider

// import (
// 	"net/http"
// 	"net/url"
// 	"testing"

// 	"github.com/stretchr/testify/assert"
// 	// tfa "github.com/thomseddon/traefik-forward-auth/internal"
// )

// TODO: Split google tests out
// func TestAuthGetLoginURL(t *testing.T) {
// 	assert := assert.New(t)
// 	google := Google{
// 		ClientId:     "idtest",
// 		ClientSecret: "sectest",
// 		Scope:        "scopetest",
// 		Prompt:       "consent select_account",
// 		LoginURL: &url.URL{
// 			Scheme: "https",
// 			Host:   "test.com",
// 			Path:   "/auth",
// 		},
// 	}

// 	config, _ = tfa.NewConfig([]string{})
// 	config.Providers.Google = google

// 	r, _ := http.NewRequest("GET", "http://example.com", nil)
// 	r.Header.Add("X-Forwarded-Proto", "http")
// 	r.Header.Add("X-Forwarded-Host", "example.com")
// 	r.Header.Add("X-Forwarded-Uri", "/hello")

// 	// Check url
// 	uri, err := url.Parse(GetLoginURL(r, "nonce"))
// 	assert.Nil(err)
// 	assert.Equal("https", uri.Scheme)
// 	assert.Equal("test.com", uri.Host)
// 	assert.Equal("/auth", uri.Path)

// 	// Check query string
// 	qs := uri.Query()
// 	expectedQs := url.Values{
// 		"client_id":     []string{"idtest"},
// 		"redirect_uri":  []string{"http://example.com/_oauth"},
// 		"response_type": []string{"code"},
// 		"scope":         []string{"scopetest"},
// 		"prompt":        []string{"consent select_account"},
// 		"state":         []string{"nonce:http://example.com/hello"},
// 	}
// 	assert.Equal(expectedQs, qs)

// 	//
// 	// With Auth URL but no matching cookie domain
// 	// - will not use auth host
// 	//
// 	config, _ = tfa.NewConfig([]string{})
// 	config.AuthHost = "auth.example.com"
// 	config.Providers.Google = google

// 	// Check url
// 	uri, err = url.Parse(GetLoginURL(r, "nonce"))
// 	assert.Nil(err)
// 	assert.Equal("https", uri.Scheme)
// 	assert.Equal("test.com", uri.Host)
// 	assert.Equal("/auth", uri.Path)

// 	// Check query string
// 	qs = uri.Query()
// 	expectedQs = url.Values{
// 		"client_id":     []string{"idtest"},
// 		"redirect_uri":  []string{"http://example.com/_oauth"},
// 		"response_type": []string{"code"},
// 		"scope":         []string{"scopetest"},
// 		"prompt":        []string{"consent select_account"},
// 		"state":         []string{"nonce:http://example.com/hello"},
// 	}
// 	assert.Equal(expectedQs, qs)

// 	//
// 	// With correct Auth URL + cookie domain
// 	//
// 	config, _ = tfa.NewConfig([]string{})
// 	config.AuthHost = "auth.example.com"
// 	config.CookieDomains = []CookieDomain{*NewCookieDomain("example.com")}
// 	config.Providers.Google = google

// 	// Check url
// 	uri, err = url.Parse(GetLoginURL(r, "nonce"))
// 	assert.Nil(err)
// 	assert.Equal("https", uri.Scheme)
// 	assert.Equal("test.com", uri.Host)
// 	assert.Equal("/auth", uri.Path)

// 	// Check query string
// 	qs = uri.Query()
// 	expectedQs = url.Values{
// 		"client_id":     []string{"idtest"},
// 		"redirect_uri":  []string{"http://auth.example.com/_oauth"},
// 		"response_type": []string{"code"},
// 		"scope":         []string{"scopetest"},
// 		"state":         []string{"nonce:http://example.com/hello"},
// 		"prompt":        []string{"consent select_account"},
// 	}
// 	assert.Equal(expectedQs, qs)

// 	//
// 	// With Auth URL + cookie domain, but from different domain
// 	// - will not use auth host
// 	//
// 	r, _ = http.NewRequest("GET", "http://another.com", nil)
// 	r.Header.Add("X-Forwarded-Proto", "http")
// 	r.Header.Add("X-Forwarded-Host", "another.com")
// 	r.Header.Add("X-Forwarded-Uri", "/hello")

// 	// Check url
// 	uri, err = url.Parse(GetLoginURL(r, "nonce"))
// 	assert.Nil(err)
// 	assert.Equal("https", uri.Scheme)
// 	assert.Equal("test.com", uri.Host)
// 	assert.Equal("/auth", uri.Path)

// 	// Check query string
// 	qs = uri.Query()
// 	expectedQs = url.Values{
// 		"client_id":     []string{"idtest"},
// 		"redirect_uri":  []string{"http://another.com/_oauth"},
// 		"response_type": []string{"code"},
// 		"scope":         []string{"scopetest"},
// 		"state":         []string{"nonce:http://another.com/hello"},
// 		"prompt":        []string{"consent select_account"},
// 	}
// 	assert.Equal(expectedQs, qs)
// }
//