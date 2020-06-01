package tfa

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

/**
 * Setup
 */

func init() {
	config = newDefaultConfig()
	config.LogLevel = "panic"
	log = NewDefaultLogger()
}

/**
 * Tests
 */

func TestServerAuthHandlerInvalid(t *testing.T) {
	assert := assert.New(t)
	config = newDefaultConfig()
	var hook *test.Hook
	log, hook = test.NewNullLogger()

	// Should redirect vanilla request to login url
	req := newDefaultHttpRequest("/foo")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "vanilla request should be redirected")

	fwd, _ := res.Location()
	assert.Equal("https", fwd.Scheme, "vanilla request should be redirected to google")
	assert.Equal("accounts.google.com", fwd.Host, "vanilla request should be redirected to google")
	assert.Equal("/o/oauth2/auth", fwd.Path, "vanilla request should be redirected to google")

	// Check state string
	qs := fwd.Query()
	state, exists := qs["state"]
	require.True(t, exists)
	require.Len(t, state, 1)
	parts := strings.SplitN(state[0], ":", 3)
	require.Len(t, parts, 3)
	assert.Equal("google", parts[1])
	assert.Equal("http://example.com/foo", parts[2])

	// Should warn as using http without insecure cookie
	logs := hook.AllEntries()
	assert.Len(logs, 1)
	assert.Equal("You are using \"secure\" cookies for a request that was not "+
		"received via https. You should either redirect to https or pass the "+
		"\"insecure-cookie\" config option to permit cookies via http.", logs[0].Message)
	assert.Equal(logrus.WarnLevel, logs[0].Level)

	// Should catch invalid cookie
	req = newDefaultHttpRequest("/foo")
	c := MakeCookie(req, "test@example.com")
	parts = strings.Split(c.Value, "|")
	c.Value = fmt.Sprintf("bad|%s|%s", parts[1], parts[2])

	res, _ = doHttpRequest(req, c)
	assert.Equal(401, res.StatusCode, "invalid cookie should not be authorised")

	// Should validate email
	req = newDefaultHttpRequest("/foo")
	c = MakeCookie(req, "test@example.com")
	config.Domains = []string{"test.com"}

	res, _ = doHttpRequest(req, c)
	assert.Equal(401, res.StatusCode, "invalid email should not be authorised")
}

func TestServerAuthHandlerExpired(t *testing.T) {
	assert := assert.New(t)
	config = newDefaultConfig()
	config.Lifetime = time.Second * time.Duration(-1)
	config.Domains = []string{"test.com"}

	// Should redirect expired cookie
	req := newDefaultHttpRequest("/foo")
	c := MakeCookie(req, "test@example.com")
	res, _ := doHttpRequest(req, c)
	assert.Equal(307, res.StatusCode, "request with expired cookie should be redirected")

	// Check for CSRF cookie
	var cookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == config.CSRFCookieName {
			cookie = c
		}
	}
	assert.NotNil(cookie)

	// Check redirection location
	fwd, _ := res.Location()
	assert.Equal("https", fwd.Scheme, "request with expired cookie should be redirected to google")
	assert.Equal("accounts.google.com", fwd.Host, "request with expired cookie should be redirected to google")
	assert.Equal("/o/oauth2/auth", fwd.Path, "request with expired cookie should be redirected to google")
}

func TestServerAuthHandlerValid(t *testing.T) {
	assert := assert.New(t)
	config = newDefaultConfig()

	// Should allow valid request email
	req := newDefaultHttpRequest("/foo")
	c := MakeCookie(req, "test@example.com")
	config.Domains = []string{}

	res, _ := doHttpRequest(req, c)
	assert.Equal(200, res.StatusCode, "valid request should be allowed")

	// Should pass through user
	users := res.Header["X-Forwarded-User"]
	assert.Len(users, 1, "valid request should have X-Forwarded-User header")
	assert.Equal([]string{"test@example.com"}, users, "X-Forwarded-User header should match user")
}

func TestServerAuthCallback(t *testing.T) {
	assert := assert.New(t)
	config = newDefaultConfig()

	// Setup OAuth server
	server, serverURL := NewOAuthServer(t)
	defer server.Close()
	config.Providers.Google.TokenURL = &url.URL{
		Scheme: serverURL.Scheme,
		Host:   serverURL.Host,
		Path:   "/token",
	}
	config.Providers.Google.UserURL = &url.URL{
		Scheme: serverURL.Scheme,
		Host:   serverURL.Host,
		Path:   "/userinfo",
	}

	// Should pass auth response request to callback
	req := newDefaultHttpRequest("/_oauth")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(401, res.StatusCode, "auth callback without cookie shouldn't be authorised")

	// Should catch invalid csrf cookie
	req = newDefaultHttpRequest("/_oauth?state=12345678901234567890123456789012:http://redirect")
	c := MakeCSRFCookie(req, "nononononononononononononononono")
	res, _ = doHttpRequest(req, c)
	assert.Equal(401, res.StatusCode, "auth callback with invalid cookie shouldn't be authorised")

	// Should redirect valid request
	req = newDefaultHttpRequest("/_oauth?state=12345678901234567890123456789012:google:http://redirect")
	c = MakeCSRFCookie(req, "12345678901234567890123456789012")
	res, _ = doHttpRequest(req, c)
	assert.Equal(307, res.StatusCode, "valid auth callback should be allowed")

	fwd, _ := res.Location()
	assert.Equal("http", fwd.Scheme, "valid request should be redirected to return url")
	assert.Equal("redirect", fwd.Host, "valid request should be redirected to return url")
	assert.Equal("", fwd.Path, "valid request should be redirected to return url")
}

func TestServerLogout(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	config = newDefaultConfig()

	req := newDefaultHttpRequest("/_oauth/logout")
	res, _ := doHttpRequest(req, nil)
	require.Equal(401, res.StatusCode, "should return a 401")

	// Check for cookie
	var cookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == config.CookieName {
			cookie = c
		}
	}
	require.NotNil(cookie)
	require.Less(cookie.Expires.Local().Unix(), time.Now().Local().Unix()-50, "cookie should have expired")

	// Test with redirect
	config.LogoutRedirect = "http://redirect/path"
	req = newDefaultHttpRequest("/_oauth/logout")
	res, _ = doHttpRequest(req, nil)
	require.Equal(307, res.StatusCode, "should return a 307")

	// Check for cookie
	cookie = nil
	for _, c := range res.Cookies() {
		if c.Name == config.CookieName {
			cookie = c
		}
	}
	require.NotNil(cookie)
	require.Less(cookie.Expires.Local().Unix(), time.Now().Local().Unix()-50, "cookie should have expired")

	fwd, _ := res.Location()
	require.NotNil(fwd)
	assert.Equal("http", fwd.Scheme, "valid request should be redirected to return url")
	assert.Equal("redirect", fwd.Host, "valid request should be redirected to return url")
	assert.Equal("/path", fwd.Path, "valid request should be redirected to return url")

}

func TestServerDefaultAction(t *testing.T) {
	assert := assert.New(t)
	config = newDefaultConfig()

	req := newDefaultHttpRequest("/random")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "request should require auth with auth default handler")

	config.DefaultAction = "allow"
	req = newDefaultHttpRequest("/random")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request should be allowed with default handler")
}

func TestServerDefaultProvider(t *testing.T) {
	assert := assert.New(t)
	config = newDefaultConfig()

	// Should use "google" as default provider when not specified
	req := newDefaultHttpRequest("/random")
	res, _ := doHttpRequest(req, nil)
	fwd, _ := res.Location()
	assert.Equal("https", fwd.Scheme, "request with expired cookie should be redirected to google")
	assert.Equal("accounts.google.com", fwd.Host, "request with expired cookie should be redirected to google")
	assert.Equal("/o/oauth2/auth", fwd.Path, "request with expired cookie should be redirected to google")

	// Should use alternative default provider when set
	config.DefaultProvider = "oidc"
	config.Providers.OIDC.OAuthProvider.Config = &oauth2.Config{
		Endpoint: oauth2.Endpoint{
			AuthURL: "https://oidc.com/oidcauth",
		},
	}

	res, _ = doHttpRequest(req, nil)
	fwd, _ = res.Location()
	assert.Equal("https", fwd.Scheme, "request with expired cookie should be redirected to oidc")
	assert.Equal("oidc.com", fwd.Host, "request with expired cookie should be redirected to oidc")
	assert.Equal("/oidcauth", fwd.Path, "request with expired cookie should be redirected to oidc")
}

func TestServerRouteHeaders(t *testing.T) {
	assert := assert.New(t)
	config = newDefaultConfig()
	config.Rules = map[string]*Rule{
		"1": {
			Action: "allow",
			Rule:   "Headers(`X-Test`, `test123`)",
		},
		"2": {
			Action: "allow",
			Rule:   "HeadersRegexp(`X-Test`, `test(456|789)`)",
		},
	}

	// Should block any request
	req := newDefaultHttpRequest("/random")
	req.Header.Add("X-Random", "hello")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "request not matching any rule should require auth")

	// Should allow matching
	req = newDefaultHttpRequest("/api")
	req.Header.Add("X-Test", "test123")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")

	// Should allow matching
	req = newDefaultHttpRequest("/api")
	req.Header.Add("X-Test", "test789")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")
}

func TestServerRouteHost(t *testing.T) {
	assert := assert.New(t)
	config = newDefaultConfig()
	config.Rules = map[string]*Rule{
		"1": {
			Action: "allow",
			Rule:   "Host(`api.example.com`)",
		},
		"2": {
			Action: "allow",
			Rule:   "HostRegexp(`sub{num:[0-9]}.example.com`)",
		},
	}

	// Should block any request
	req := newHttpRequest("GET", "https://example.com/", "/")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "request not matching any rule should require auth")

	// Should allow matching request
	req = newHttpRequest("GET", "https://api.example.com/", "/")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")

	// Should allow matching request
	req = newHttpRequest("GET", "https://sub8.example.com/", "/")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")
}

func TestServerRouteMethod(t *testing.T) {
	assert := assert.New(t)
	config = newDefaultConfig()
	config.Rules = map[string]*Rule{
		"1": {
			Action: "allow",
			Rule:   "Method(`PUT`)",
		},
	}

	// Should block any request
	req := newHttpRequest("GET", "https://example.com/", "/")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "request not matching any rule should require auth")

	// Should allow matching request
	req = newHttpRequest("PUT", "https://example.com/", "/")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")
}

func TestServerRoutePath(t *testing.T) {
	assert := assert.New(t)
	config = newDefaultConfig()
	config.Rules = map[string]*Rule{
		"1": {
			Action: "allow",
			Rule:   "Path(`/api`)",
		},
		"2": {
			Action: "allow",
			Rule:   "PathPrefix(`/private`)",
		},
	}

	// Should block any request
	req := newDefaultHttpRequest("/random")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "request not matching any rule should require auth")

	// Should allow /api request
	req = newDefaultHttpRequest("/api")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")

	// Should allow /private request
	req = newDefaultHttpRequest("/private")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")

	req = newDefaultHttpRequest("/private/path")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")
}

func TestServerRouteQuery(t *testing.T) {
	assert := assert.New(t)
	config = newDefaultConfig()
	config.Rules = map[string]*Rule{
		"1": {
			Action: "allow",
			Rule:   "Query(`q=test123`)",
		},
	}

	// Should block any request
	req := newHttpRequest("GET", "https://example.com/", "/?q=no")
	res, _ := doHttpRequest(req, nil)
	assert.Equal(307, res.StatusCode, "request not matching any rule should require auth")

	// Should allow matching request
	req = newHttpRequest("GET", "https://api.example.com/", "/?q=test123")
	res, _ = doHttpRequest(req, nil)
	assert.Equal(200, res.StatusCode, "request matching allow rule should be allowed")
}

/**
 * Utilities
 */

type OAuthServer struct {
	t *testing.T
}

func (s *OAuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/token" {
		fmt.Fprintf(w, `{"access_token":"123456789"}`)
	} else if r.URL.Path == "/userinfo" {
		fmt.Fprint(w, `{
			"id":"1",
			"email":"example@example.com",
			"verified_email":true,
			"hd":"example.com"
		}`)
	} else {
		s.t.Fatal("Unrecognised request: ", r.Method, r.URL)
	}
}

func NewOAuthServer(t *testing.T) (*httptest.Server, *url.URL) {
	handler := &OAuthServer{}
	server := httptest.NewServer(handler)
	serverURL, _ := url.Parse(server.URL)
	return server, serverURL
}

func doHttpRequest(r *http.Request, c *http.Cookie) (*http.Response, string) {
	w := httptest.NewRecorder()

	// Set cookies on recorder
	if c != nil {
		http.SetCookie(w, c)
	}

	// Copy into request
	for _, c := range w.HeaderMap["Set-Cookie"] {
		r.Header.Add("Cookie", c)
	}

	NewServer().RootHandler(w, r)

	res := w.Result()
	body, _ := ioutil.ReadAll(res.Body)

	// if res.StatusCode > 300 && res.StatusCode < 400 {
	// 	fmt.Printf("%#v", res.Header)
	// }

	return res, string(body)
}

func newDefaultConfig() *Config {
	config, _ = NewConfig([]string{
		"--providers.google.client-id=id",
		"--providers.google.client-secret=secret",
	})

	// Setup the google providers without running all the config validation
	config.Providers.Google.Setup()

	return config
}

func newDefaultHttpRequest(uri string) *http.Request {
	return newHttpRequest("", "http://example.com/", uri)
}

func newHttpRequest(method, dest, uri string) *http.Request {
	r := httptest.NewRequest("", "http://should-use-x-forwarded.com", nil)
	p, _ := url.Parse(dest)
	r.Header.Add("X-Forwarded-Method", method)
	r.Header.Add("X-Forwarded-Proto", p.Scheme)
	r.Header.Add("X-Forwarded-Host", p.Host)
	r.Header.Add("X-Forwarded-Uri", uri)
	return r
}
