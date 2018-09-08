
package main

import (
  "fmt"
  "time"
  "errors"
  "strings"
  "strconv"
  "net/url"
  "net/http"
  "crypto/hmac"
  "crypto/rand"
  "crypto/sha256"
  "encoding/json"
  "encoding/base64"
)

// Forward Auth
type ForwardAuth struct {
  Path string
  Lifetime time.Duration

  ClientId string
  ClientSecret string
  Scope string

  LoginURL *url.URL
  TokenURL *url.URL
  UserURL *url.URL

  CookieName string
  CookieDomains []CookieDomain
  CSRFCookieName string
  CookieSecret []byte
  CookieSecure bool

  Domain []string
  Email []string

  Direct bool
}

// Request Validation

// Cookie = hash(secret, cookie domain, email, expires)|expires|email
func (f *ForwardAuth) ValidateCookie(r *http.Request, c *http.Cookie) (bool, string, error) {
  parts := strings.Split(c.Value, "|")

  if len(parts) != 3 {
    return false, "", errors.New("Invalid cookie format")
  }

  mac, err := base64.URLEncoding.DecodeString(parts[0])
  if err != nil {
    return false, "", errors.New("Unable to decode cookie mac")
  }

  expectedSignature := f.cookieSignature(r, parts[2], parts[1])
  expected, err := base64.URLEncoding.DecodeString(expectedSignature)
  if err != nil {
    return false, "", errors.New("Unable to generate mac")
  }

  // Valid token?
  if !hmac.Equal(mac, expected) {
    return false, "", errors.New("Invalid cookie mac")
  }

  expires, err := strconv.ParseInt(parts[1], 10, 64)
  if err != nil {
    return false, "", errors.New("Unable to parse cookie expiry")
  }

  // Has it expired?
  if time.Unix(expires, 0).Before(time.Now()) {
    return false, "", errors.New("Cookie has expired")
  }

  // Looks valid
  return true, parts[2], nil
}

// Validate email against domain
func (f *ForwardAuth) ValidateEmailDomain(email string) bool {
  parts := strings.Split(email, "@")
  if len(parts) < 2 {
    return false
  }

  for _, domain := range f.Domain {
    if domain == parts[1] {
      return true
    }
  }

  return false
}

// Validate email
func (f *ForwardAuth) ValidateEmail(email string) bool {
  for _, allowed := range f.Email {
    if email == allowed {
      return true
    }
  }

  return false
}


// OAuth Methods

// Get login url
func (f *ForwardAuth) GetLoginURL(r *http.Request, nonce string) string {
  state := fmt.Sprintf("%s:%s", nonce, f.returnUrl(r))

  q := url.Values{}
  q.Set("client_id", fw.ClientId)
  q.Set("response_type", "code")
  q.Set("scope", fw.Scope)
  // q.Set("approval_prompt", fw.ClientId)
  q.Set("redirect_uri", f.redirectUri(r))
  q.Set("state", state)

  var u url.URL
  u = *fw.LoginURL
  u.RawQuery = q.Encode()

  return u.String()
}

// Exchange code for token

type Token struct {
  Token string `json:"access_token"`
}

func (f *ForwardAuth) ExchangeCode(r *http.Request, code string) (string, error) {
  form := url.Values{}
  form.Set("client_id", fw.ClientId)
  form.Set("client_secret", fw.ClientSecret)
  form.Set("grant_type", "authorization_code")
  form.Set("redirect_uri", f.redirectUri(r))
  form.Set("code", code)


  res, err := http.PostForm(fw.TokenURL.String(), form)
  if err != nil {
    return "", err
  }

  var token Token
  defer res.Body.Close()
  err = json.NewDecoder(res.Body).Decode(&token)

  return token.Token, err
}

// Get user with token

type User struct {
  Id string `json:"id"`
  Email string `json:"email"`
  Verified bool `json:"verified_email"`
  Hd string `json:"hd"`
}

func (f *ForwardAuth) GetUser(token string) (User, error) {
  var user User

  client := &http.Client{}
  req, err := http.NewRequest("GET", fw.UserURL.String(), nil)
  if err != nil {
    return user, err
  }

  req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
  res, err := client.Do(req)
  if err != nil {
    return user, err
  }

  defer res.Body.Close()
  err = json.NewDecoder(res.Body).Decode(&user)

  return user, err
}

// Utility methods

// Get the redirect base
func (f *ForwardAuth) redirectBase(r *http.Request) string {
  proto := r.Header.Get("X-Forwarded-Proto")
  host := r.Header.Get("X-Forwarded-Host")

  // Direct mode
  if f.Direct {
    proto = "http"
    host = r.Host
  }

  return fmt.Sprintf("%s://%s", proto, host)
}

// Return url
func (f *ForwardAuth) returnUrl(r *http.Request) string {
  path := r.Header.Get("X-Forwarded-Uri")

  // Testing
  if f.Direct {
    path = r.URL.String()
  }

  return fmt.Sprintf("%s%s", f.redirectBase(r), path)
}

// Get oauth redirect uri
func (f *ForwardAuth) redirectUri(r *http.Request) string {
  return fmt.Sprintf("%s%s", f.redirectBase(r), f.Path)
}

// Cookie methods

// Create an auth cookie
func (f *ForwardAuth) MakeCookie(r *http.Request, email string) *http.Cookie {
  expires := f.cookieExpiry()
  mac := f.cookieSignature(r, email, fmt.Sprintf("%d", expires.Unix()))
  value := fmt.Sprintf("%s|%d|%s", mac, expires.Unix(), email)

  return &http.Cookie{
    Name: f.CookieName,
    Value: value,
    Path: "/",
    Domain: f.cookieDomain(r),
    HttpOnly: true,
    Secure: f.CookieSecure,
    Expires: expires,
  }
}

// Make a CSRF cookie (used during login only)
func (f *ForwardAuth) MakeCSRFCookie(r *http.Request, nonce string) *http.Cookie {
  return &http.Cookie{
    Name: f.CSRFCookieName,
    Value: nonce,
    Path: "/",
    Domain: f.cookieDomain(r),
    HttpOnly: true,
    Secure: f.CookieSecure,
    Expires: f.cookieExpiry(),
  }
}

// Create a cookie to clear csrf cookie
func (f *ForwardAuth) ClearCSRFCookie(r *http.Request) *http.Cookie {
  return &http.Cookie{
    Name: f.CSRFCookieName,
    Value: "",
    Path: "/",
    Domain: f.cookieDomain(r),
    HttpOnly: true,
    Secure: f.CookieSecure,
    Expires: time.Now().Local().Add(time.Hour * -1),
  }
}

// Validate the csrf cookie against state
func (f *ForwardAuth) ValidateCSRFCookie(c *http.Cookie, state string) (bool, string, error) {
  if len(c.Value) != 32 {
    return false, "", errors.New("Invalid CSRF cookie value")
  }

  if len(state) < 34 {
    return false, "", errors.New("Invalid CSRF state value")
  }

  // Check nonce match
  if c.Value != state[:32] {
    return false, "", errors.New("CSRF cookie does not match state")
  }

  // Valid, return redirect
  return true, state[33:], nil
}

func (f *ForwardAuth) Nonce() (error, string) {
  // Make nonce
  nonce := make([]byte, 16)
  _, err := rand.Read(nonce)
  if err != nil {
    return err, ""
  }

  return nil, fmt.Sprintf("%x", nonce)
}

// Cookie domain
func (f *ForwardAuth) cookieDomain(r *http.Request) string {
  host := r.Header.Get("X-Forwarded-Host")

  // Direct mode
  if f.Direct {
    host = r.Host
  }

  // Remove port for matching
  p := strings.Split(host, ":")

  // Check if any of the given cookie domains matches
  for _, domain := range f.CookieDomains {
    if domain.Match(p[0]) {
      return domain.Domain
    }
  }

  return p[0]
}

// Create cookie hmac
func (f *ForwardAuth) cookieSignature(r *http.Request, email, expires string) string {
  hash := hmac.New(sha256.New, f.CookieSecret)
  hash.Write([]byte(f.cookieDomain(r)))
  hash.Write([]byte(email))
  hash.Write([]byte(expires))
  return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}

// Get cookie expirary
func (f *ForwardAuth) cookieExpiry() time.Time {
  return time.Now().Local().Add(f.Lifetime)
}

// Cookie Domain

// Cookie Domain
type CookieDomain struct {
  Domain string
  DomainLen int
  SubDomain string
  SubDomainLen int
}

func NewCookieDomain(domain string) *CookieDomain {
  return &CookieDomain{
    Domain: domain,
    DomainLen: len(domain),
    SubDomain: fmt.Sprintf(".%s", domain),
    SubDomainLen: len(domain) + 1,
  }
}

func (c *CookieDomain) Match(host string) bool {
  // Exact domain match?
  if host == c.Domain {
    return true
  }

  // Subdomain match?
  if len(host) >= c.SubDomainLen && host[len(host) - c.SubDomainLen:] == c.SubDomain {
    return true
  }

  return false
}
