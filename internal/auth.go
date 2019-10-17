package tfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/thomseddon/traefik-forward-auth/internal/provider"
)

const ERRORS_COOKIE_HAS_EXPIRED = "cookie has expired"
const ERRORS_UNABLE_TO_PARSE_COOKIE_EXPIRY = "unable to parse cookie expiry"
const ERRORS_INVALID_COOKIE_MAC = "invalid cookie mac"
const ERRORS_UNABLE_TO_GENERATE_MAC = "unable to generate mac"
const ERRORS_UNABLE_TO_DECODE_MAC = "unable to decode cookie mac"
const ERRORS_INVALID_COOKIE_FORMAT = "invalid cookie format"

const ERRORS_INVALID_CSRF_COOKIE_VALUE = "invalid CSRF cookie value"
const ERRORS_INVALID_CSRF_STATE_VALUE = "invalid CSRF state value"
const ERRORS_CSRF_COOKIES_DOESNT_MATCH = "csrf cookie does not match state"
const ERRORS_INVALID_CSRF_FORMAT = "invalid CSRF state format"


// Request Validation

// Cookie = hash(secret, cookie domain, authmethod, expires)|expires|authmethod
func ValidateCookie(r *http.Request, c *http.Cookie) (string, error) {
	parts := strings.Split(c.Value, "|")

	if len(parts) != 3 {
		return "", errors.New(ERRORS_INVALID_COOKIE_FORMAT)
	}

	mac, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New(ERRORS_UNABLE_TO_DECODE_MAC)
	}

	expectedSignature := cookieSignature(r, parts[2], parts[1])
	expected, err := base64.URLEncoding.DecodeString(expectedSignature)
	if err != nil {
		return "", errors.New(ERRORS_UNABLE_TO_GENERATE_MAC)
	}

	// Valid token?
	if !hmac.Equal(mac, expected) {
		return "", errors.New(ERRORS_INVALID_COOKIE_MAC)
	}

	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", errors.New(ERRORS_UNABLE_TO_PARSE_COOKIE_EXPIRY)
	}

	// Has it expired?
	now := time.Now()
	if time.Unix(expires, 0).Before(now) {
		return "", errors.New(ERRORS_COOKIE_HAS_EXPIRED)
	}

	// Looks valid
	return parts[2], nil
}

// Validate email
func ValidateEmail(email string) bool {
	found := false
	if len(config.Whitelist) > 0 {
		for _, whitelist := range config.Whitelist {
			if email == whitelist {
				found = true
			}
		}
	} else if len(config.Domains) > 0 {
		parts := strings.Split(email, "@")
		if len(parts) < 2 {
			return false
		}
		for _, domain := range config.Domains {
			if domain == parts[1] {
				found = true
			}
		}
	} else {
		return true
	}

	return found
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// Validate teams
func ValidateTeams(teamsS string) bool {
	teams := strings.Split(teamsS, ",")

	if len(config.Teams) > 0 {
		for _, team := range config.Teams {
			if contains(teams, team) {
				return true
			}
		}
	}

	return false
}

// Utility methods

// TODO: test

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

// Get the redirect base
func redirectBase(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	port := r.Header.Get("X-Forwarded-Port")

   if port != "" {
		   port, err := strconv.Atoi(port)
		   if err == nil && port >= 1 && port <= 65535 {
				   return fmt.Sprintf("%s://%s:%d", proto, host, port)
		   }
   }
	return fmt.Sprintf("%s://%s", proto, host)
}

// // Return url
func returnUrl(r *http.Request) string {
	path := r.Header.Get("X-Forwarded-Uri")

	return fmt.Sprintf("%s%s", redirectBase(r), path)
}

// Get oauth redirect uri
func redirectUri(r *http.Request) string {
	if use, _ := useAuthDomain(r); use {
		proto := r.Header.Get("X-Forwarded-Proto")
		port := r.Header.Get("X-Forwarded-Port")

		if port != "" {
			   port, err := strconv.Atoi(port)
			   log.Info("Got port: ", port)
			   if err == nil && port >= 1 && port <= 65535 {
					   return fmt.Sprintf("%s://%s:%d%s", proto, config.AuthHost, port, config.Path)
			   }
		}
		return fmt.Sprintf("%s://%s%s", proto, config.AuthHost, config.Path)
	}

	return fmt.Sprintf("%s%s", redirectBase(r), config.Path)
}

// Should we use auth host + what it is
func useAuthDomain(r *http.Request) (bool, string) {
	if config.AuthHost == "" {
		return false, ""
	}

	// Does the request match a given cookie domain?
	reqMatch, reqHost := matchCookieDomains(r.Header.Get("X-Forwarded-Host"))

	// Do any of the auth hosts match a cookie domain?
	authMatch, authHost := matchCookieDomains(config.AuthHost)

	// We need both to match the same domain
	return reqMatch && authMatch && reqHost == authHost, reqHost
}

// Cookie methods

// Create an auth cookie
func MakeCookie(r *http.Request, authMethod url.Values) *http.Cookie {
	expires := cookieExpiry()
	mac := cookieSignature(r, authMethod.Encode(), fmt.Sprintf("%d", expires.Unix()))
	value := fmt.Sprintf("%s|%d|%s", mac, expires.Unix(), authMethod.Encode())

	return &http.Cookie{
		Name:     config.CookieName,
		Value:    value,
		Path:     "/",
		Domain:   cookieDomain(r),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  expires,
	}
}

// Make a CSRF cookie (used during login only)
func MakeCSRFCookie(r *http.Request, nonce string) *http.Cookie {
	return &http.Cookie{
		Name:     config.CSRFCookieName,
		Value:    nonce,
		Path:     "/",
		Domain:   csrfCookieDomain(r),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  cookieExpiry(),
	}
}

// Create a cookie to clear csrf cookie
func ClearCSRFCookie(r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     config.CSRFCookieName,
		Value:    "",
		Path:     "/",
		Domain:   csrfCookieDomain(r),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}

// Validate the csrf cookie against state
func ValidateCSRFCookie(r *http.Request, c *http.Cookie) (valid bool, provider string, redirect string, err error) {
	state := r.URL.Query().Get("state")

	if len(c.Value) != 32 {
		return false, "", "", errors.New(ERRORS_INVALID_CSRF_COOKIE_VALUE)
	}

	if len(state) < 34 {
		return false, "", "", errors.New(ERRORS_INVALID_CSRF_STATE_VALUE)
	}

	// Check nonce match
	if c.Value != state[:32] {
		return false, "", "", errors.New(ERRORS_CSRF_COOKIES_DOESNT_MATCH)
	}

	// Extract provider
	params := state[33:]
	split := strings.Index(params, ":")
	if split == -1 {
		return false, "", "", errors.New(ERRORS_INVALID_CSRF_FORMAT)
	}

	// Valid, return provider and redirect
	return true, params[:split], params[split+1:], nil
}

func MakeState(r *http.Request, p provider.Provider, nonce string) string {
	return fmt.Sprintf("%s:%s:%s", nonce, p.Name(), returnUrl(r))
}

func Nonce() (error, string) {
	// Make nonce
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return err, ""
	}

	return nil, fmt.Sprintf("%x", nonce)
}

// Cookie domain
func cookieDomain(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")

	// Check if any of the given cookie domains matches
	_, domain := matchCookieDomains(host)
	return domain
}

// Cookie domain
func csrfCookieDomain(r *http.Request) string {
	var host string
	if use, domain := useAuthDomain(r); use {
		host = domain
	} else {
		host = r.Header.Get("X-Forwarded-Host")
	}

	// Remove port
	p := strings.Split(host, ":")
	return p[0]
}

// Return matching cookie domain if exists
func matchCookieDomains(domain string) (bool, string) {
	// Remove port
	p := strings.Split(domain, ":")

	for _, d := range config.CookieDomains {
		if d.Match(p[0]) {
			return true, d.Domain
		}
	}

	return false, p[0]
}

// Create cookie hmac
func cookieSignature(r *http.Request, email, expires string) string {
	hash := hmac.New(sha256.New, config.Secret)
	hash.Write([]byte(cookieDomain(r)))
	hash.Write([]byte(email))
	hash.Write([]byte(expires))
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}

// Get cookie expiry
func cookieExpiry() time.Time {
	return time.Now().Local().Add(config.Lifetime)
}

// Cookie Domain

// Cookie Domain
type CookieDomain struct {
	Domain       string `description:"TEST1"`
	DomainLen    int    `description:"TEST2"`
	SubDomain    string `description:"TEST3"`
	SubDomainLen int    `description:"TEST4"`
}

func NewCookieDomain(domain string) *CookieDomain {
	return &CookieDomain{
		Domain:       domain,
		DomainLen:    len(domain),
		SubDomain:    fmt.Sprintf(".%s", domain),
		SubDomainLen: len(domain) + 1,
	}
}

func (c *CookieDomain) Match(host string) bool {
	// Exact domain match?
	if host == c.Domain {
		return true
	}

	// Subdomain match?
	if len(host) >= c.SubDomainLen && host[len(host)-c.SubDomainLen:] == c.SubDomain {
		return true
	}

	return false
}

func (c *CookieDomain) UnmarshalFlag(value string) error {
	*c = *NewCookieDomain(value)
	return nil
}

func (c *CookieDomain) MarshalFlag() (string, error) {
	return c.Domain, nil
}

// Legacy support for comma separated list of cookie domains

type CookieDomains []CookieDomain

func (c *CookieDomains) UnmarshalFlag(value string) error {
	if len(value) > 0 {
		for _, d := range strings.Split(value, ",") {
			cookieDomain := NewCookieDomain(d)
			*c = append(*c, *cookieDomain)
		}
	}
	return nil
}

func (c *CookieDomains) MarshalFlag() (string, error) {
	var domains []string
	for _, d := range *c {
		domains = append(domains, d.Domain)
	}
	return strings.Join(domains, ","), nil
}
