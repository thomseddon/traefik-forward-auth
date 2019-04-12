package tfa

import (
	"fmt"
	"time"
	// "reflect"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/thomseddon/traefik-forward-auth/internal/provider"
)

/**
 * Setup
 */

func init() {
	config.LogLevel = "panic"
	log = NewDefaultLogger()
}

/**
 * Utilities
 */

type TokenServerHandler struct{}

func (t *TokenServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `{"access_token":"123456789"}`)
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

func httpRequest(s *Server, r *http.Request, c *http.Cookie) (*http.Response, string) {
	w := httptest.NewRecorder()

	// Set cookies on recorder
	if c != nil {
		http.SetCookie(w, c)
	}

	// Copy into request
	for _, c := range w.HeaderMap["Set-Cookie"] {
		r.Header.Add("Cookie", c)
	}

	s.RootHandler(w, r)

	res := w.Result()
	body, _ := ioutil.ReadAll(res.Body)

	// if res.StatusCode > 300 && res.StatusCode < 400 {
	// 	fmt.Printf("%#v", res.Header)
	// }

	return res, string(body)
}

func newHttpRequest(uri string) *http.Request {
	r := httptest.NewRequest("", "http://example.com/", nil)
	r.Header.Add("X-Forwarded-Uri", uri)
	return r
}

func qsDiff(one, two url.Values) {
	for k := range one {
		if two.Get(k) == "" {
			fmt.Printf("Key missing: %s\n", k)
		}
		if one.Get(k) != two.Get(k) {
			fmt.Printf("Value different for %s: expected: '%s' got: '%s'\n", k, one.Get(k), two.Get(k))
		}
	}
	for k := range two {
		if one.Get(k) == "" {
			fmt.Printf("Extra key: %s\n", k)
		}
	}
}

/**
 * Tests
 */

func TestServerHandler(t *testing.T) {
	server := NewServer()

	config = Config{
		Path:       "/_oauth",
		CookieName: "cookie_test",
		Lifetime:   time.Second * time.Duration(10),
		Providers: provider.Providers{
			Google: provider.Google{
				ClientId:     "idtest",
				ClientSecret: "sectest",
				Scope:        "scopetest",
				LoginURL: &url.URL{
					Scheme: "http",
					Host:   "test.com",
					Path:   "/auth",
				},
			},
		},
	}

	// Should redirect vanilla request to login url
	req := newHttpRequest("/foo")
	res, _ := httpRequest(server, req, nil)
	if res.StatusCode != 307 {
		t.Error("Vanilla request should be redirected with 307, got:", res.StatusCode)
	}
	fwd, _ := res.Location()
	if fwd.Scheme != "http" || fwd.Host != "test.com" || fwd.Path != "/auth" {
		t.Error("Vanilla request should be redirected to login url, got:", fwd)
	}

	// Should catch invalid cookie
	req = newHttpRequest("/foo")

	c := MakeCookie(req, "test@example.com")
	parts := strings.Split(c.Value, "|")
	c.Value = fmt.Sprintf("bad|%s|%s", parts[1], parts[2])

	res, _ = httpRequest(server, req, c)
	if res.StatusCode != 401 {
		t.Error("Request with invalid cookie shound't be authorised", res.StatusCode)
	}

	// Should validate email
	req = newHttpRequest("/foo")

	c = MakeCookie(req, "test@example.com")
	config.Domains = []string{"test.com"}

	res, _ = httpRequest(server, req, c)
	if res.StatusCode != 401 {
		t.Error("Request with invalid cookie shound't be authorised", res.StatusCode)
	}

	// Should allow valid request email
	req = newHttpRequest("/foo")

	c = MakeCookie(req, "test@example.com")
	config.Domains = []string{}

	res, _ = httpRequest(server, req, c)
	if res.StatusCode != 200 {
		t.Error("Valid request should be allowed, got:", res.StatusCode)
	}

	// Should pass through user
	users := res.Header["X-Forwarded-User"]
	if len(users) != 1 {
		t.Error("Valid request missing X-Forwarded-User header")
	} else if users[0] != "test@example.com" {
		t.Error("X-Forwarded-User should match user, got: ", users)
	}
}

func TestServerAuthCallback(t *testing.T) {
	server := NewServer()
	config = Config{
		Path:           "/_oauth",
		CookieName:     "cookie_test",
		Lifetime:       time.Second * time.Duration(10),
		CSRFCookieName: "csrf_test",
		Providers: provider.Providers{
			Google: provider.Google{
				ClientId:     "idtest",
				ClientSecret: "sectest",
				Scope:        "scopetest",
				LoginURL: &url.URL{
					Scheme: "http",
					Host:   "test.com",
					Path:   "/auth",
				},
			},
		},
	}

	// Setup token server
	tokenServerHandler := &TokenServerHandler{}
	tokenServer := httptest.NewServer(tokenServerHandler)
	defer tokenServer.Close()
	tokenUrl, _ := url.Parse(tokenServer.URL)
	config.Providers.Google.TokenURL = tokenUrl

	// Setup user server
	userServerHandler := &UserServerHandler{}
	userServer := httptest.NewServer(userServerHandler)
	defer userServer.Close()
	userUrl, _ := url.Parse(userServer.URL)
	config.Providers.Google.UserURL = userUrl

	// Should pass auth response request to callback
	req := newHttpRequest("/_oauth")
	res, _ := httpRequest(server, req, nil)
	if res.StatusCode != 401 {
		t.Error("Auth callback without cookie shound't be authorised, got:", res.StatusCode)
	}

	// Should catch invalid csrf cookie
	req = newHttpRequest("/_oauth?state=12345678901234567890123456789012:http://redirect")
	c := MakeCSRFCookie(req, "nononononononononononononononono")
	res, _ = httpRequest(server, req, c)
	if res.StatusCode != 401 {
		t.Error("Auth callback with invalid cookie shound't be authorised, got:", res.StatusCode)
	}

	// Should redirect valid request
	req = newHttpRequest("/_oauth?state=12345678901234567890123456789012:http://redirect")
	c = MakeCSRFCookie(req, "12345678901234567890123456789012")
	res, _ = httpRequest(server, req, c)
	if res.StatusCode != 307 {
		t.Error("Valid callback should be allowed, got:", res.StatusCode)
	}
	fwd, _ := res.Location()
	if fwd.Scheme != "http" || fwd.Host != "redirect" || fwd.Path != "" {
		t.Error("Valid request should be redirected to return url, got:", fwd)
	}
}

func TestServerRoutePathPrefix(t *testing.T) {
	server := NewServer()
	config = Config{
		Path:       "/_oauth",
		CookieName: "cookie_test",
		Lifetime:   time.Second * time.Duration(10),
		Providers: provider.Providers{
			Google: provider.Google{
				ClientId:     "idtest",
				ClientSecret: "sectest",
				Scope:        "scopetest",
				LoginURL: &url.URL{
					Scheme: "http",
					Host:   "test.com",
					Path:   "/auth",
				},
			},
		},
		Rules: []Rule{
			{
				Action: "allow",
				Rule:   "PathPrefix(`/api`)",
			},
		},
	}

	// Should allow /api request
	req := newHttpRequest("/api")
	c := MakeCookie(req, "test@example.com")
	res, _ := httpRequest(server, req, c)
	if res.StatusCode != 200 {
		t.Error("Request matching allowed rule should be allowed, got:", res.StatusCode)
	}
}
