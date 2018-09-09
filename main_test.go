
package main

import (
  "fmt"
  "time"
  // "reflect"
  "strings"
  "testing"
  "net/url"
  "net/http"
  "io/ioutil"
  "net/http/httptest"

  "github.com/op/go-logging"
)


type TokenServerHandler struct {}
func (t *TokenServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  fmt.Fprint(w, `{"access_token":"123456789"}`)
}

type UserServerHandler struct {}
func (t *UserServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  fmt.Fprint(w, `{
    "id":"1",
    "email":"example@example.com",
    "verified_email":true,
    "hd":"example.com"
  }`)
}

func init() {
  // Remove for debugging
  logging.SetLevel(logging.INFO, "traefik-forward-auth")
}

func httpRequest(r *http.Request, c *http.Cookie) (*http.Response, string) {
  w := httptest.NewRecorder()

  // Set cookies on recorder
  if c != nil {
    http.SetCookie(w, c)
  }

  // Copy into request
  for _, c := range w.HeaderMap["Set-Cookie"] {
    r.Header.Add("Cookie", c)
  }

  handler(w, r)

  res := w.Result()
  body, _ := ioutil.ReadAll(res.Body)

  return res, string(body)
}

func newHttpRequest(uri string) *http.Request {
  r := httptest.NewRequest("", "http://example.com", nil)
  r.Header.Add("X-Forwarded-Uri", uri)
  r.Header.Add("X-Forwarded-Host", "example.com")
  return r
}

func TestHandler(t *testing.T) {
  fw = &ForwardAuth{
    Path: "_oauth",
    ClientId: "idtest",
    ClientSecret: "sectest",
    Scope: "scopetest",
    LoginURL: &url.URL{
      Scheme: "http",
      Host: "test.com",
      Path: "/auth",
    },
    CookieName: "cookie_test",
    Lifetime: time.Second * time.Duration(10),
  }

  // Should redirect vanilla request to login url
  req := newHttpRequest("foo")
  res, _ := httpRequest(req, nil)
  if res.StatusCode != 307 {
    t.Error("Vanilla request should be redirected with 307, got:", res.StatusCode)
  }
  fwd, _ := res.Location()
  if fwd.Scheme != "http" || fwd.Host != "test.com" || fwd.Path != "/auth" {
    t.Error("Vanilla request should be redirected to login url, got:", fwd)
  }

  // Should catch invalid cookie
  req = newHttpRequest("foo")

  c := fw.MakeCookie(req, "test@example.com")
  parts := strings.Split(c.Value, "|")
  c.Value = fmt.Sprintf("bad|%s|%s", parts[1], parts[2])

  res, _ = httpRequest(req, c)
  if res.StatusCode != 401 {
    t.Error("Request with invalid cookie shound't be authorised", res.StatusCode)
  }

  // Should validate email
  req = newHttpRequest("foo")

  c = fw.MakeCookie(req, "test@example.com")
  fw.Domain = []string{"test.com"}

  res, _ = httpRequest(req, c)
  if res.StatusCode != 401 {
    t.Error("Request with invalid cookie shound't be authorised", res.StatusCode)
  }

  // Should allow valid request email
  req = newHttpRequest("foo")

  c = fw.MakeCookie(req, "test@example.com")
  fw.Domain = []string{}

  res, _ = httpRequest(req, c)
  if res.StatusCode != 200 {
    t.Error("Valid request should be allowed, got:", res.StatusCode)
  }

  // Should validate against domain
  req = newHttpRequest("foo")

  // Restricts only example.com
  fw.AuthDomain = []string{"example.com"}

  // Restricts emails to come with @example.com
  fw.Domain = []string{"example.com"}

  // Request with user using not-example email domain (should fail validation)
  c = fw.MakeCookie(req, "test@not-example.com")
  res, _ = httpRequest(req, c)

  if res.StatusCode != 401 {
    t.Error("Request with restricted domain should be validated", res.StatusCode)
  }

  // Should ignore non restricted domain
  req = newHttpRequest("foo") // to example.com/foo

  // Restricts only not-example.com
  fw.AuthDomain = []string{"not-example.com"}

  // Restricts emails to @example.com
  fw.Domain = []string{"example.com"}

  // Cookie from another-example.com should fail but be irrelevant against example.com
  c = fw.MakeCookie(req, "test@another-example.com")
  res, _ = httpRequest(req, c)

  if res.StatusCode != 200 {
    t.Error("Request for non-restricted domain should not be validated", res.StatusCode)
  }
}

func TestCallback(t *testing.T) {
  fw = &ForwardAuth{
    Path: "_oauth",
    ClientId: "idtest",
    ClientSecret: "sectest",
    Scope: "scopetest",
    LoginURL: &url.URL{
      Scheme: "http",
      Host: "test.com",
      Path: "/auth",
    },
    CSRFCookieName: "csrf_test",
  }

  // Setup token server
  tokenServerHandler := &TokenServerHandler{}
  tokenServer := httptest.NewServer(tokenServerHandler)
  defer tokenServer.Close()
  tokenUrl, _ := url.Parse(tokenServer.URL)
  fw.TokenURL = tokenUrl

  // Setup user server
  userServerHandler := &UserServerHandler{}
  userServer := httptest.NewServer(userServerHandler)
  defer userServer.Close()
  userUrl, _ := url.Parse(userServer.URL)
  fw.UserURL = userUrl

  // Should pass auth response request to callback
  req := newHttpRequest("_oauth")
  res, _ := httpRequest(req, nil)
  if res.StatusCode != 401 {
    t.Error("Auth callback without cookie shound't be authorised, got:", res.StatusCode)
  }

  // Should catch invalid csrf cookie
  req = newHttpRequest("_oauth?state=12345678901234567890123456789012:http://redirect")
  c := fw.MakeCSRFCookie(req, "nononononononononononononononono")
  res, _ = httpRequest(req, c)
  if res.StatusCode != 401 {
    t.Error("Auth callback with invalid cookie shound't be authorised, got:", res.StatusCode)
  }

  // Should redirect valid request
  req = newHttpRequest("_oauth?state=12345678901234567890123456789012:http://redirect")
  c = fw.MakeCSRFCookie(req, "12345678901234567890123456789012")
  res, _ = httpRequest(req, c)
  if res.StatusCode != 307 {
    t.Error("Valid callback should be allowed, got:", res.StatusCode)
  }
  fwd, _ := res.Location()
  if fwd.Scheme != "http" || fwd.Host != "redirect" || fwd.Path != "" {
    t.Error("Valid request should be redirected to return url, got:", fwd)
  }
}