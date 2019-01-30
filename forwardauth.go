package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	// "encoding/json"
	"errors"
	"fmt"
	"net/http"
	// "net/url"
	"strconv"
	"strings"
	"time"

	"github.com/thomseddon/traefik-forward-auth/provider"
)

type ForwardAuthContext int

const (
	Nonce ForwardAuthContext = iota
	Request
)

// Forward Auth
type ForwardAuth struct {
}

func NewForwardAuth() *ForwardAuth {
	return &ForwardAuth{}
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

// Validate email
func (f *ForwardAuth) ValidateEmail(email string) bool {
	found := false
	if len(config.Whitelist) > 0 {
		for _, whitelist := range config.Whitelist {
			if email == whitelist {
				found = true
			}
		}
	} else if len(config.Domain) > 0 {
		parts := strings.Split(email, "@")
		if len(parts) < 2 {
			return false
		}
		for _, domain := range config.Domain {
			if domain == parts[1] {
				found = true
			}
		}
	} else {
		return true
	}

	return found
}

// OAuth Methods

// Get login url
func (f *ForwardAuth) GetLoginURL(r *http.Request, nonce string) string {
	state := fmt.Sprintf("%s:%s", nonce, f.returnUrl(r))

	// TODO: Support multiple providers
	return config.Providers.Google.GetLoginURL(f.redirectUri(r), state)
}

// Exchange code for token

func (f *ForwardAuth) ExchangeCode(r *http.Request) (string, error) {
	code := r.URL.Query().Get("code")

	// TODO: Support multiple providers
	return config.Providers.Google.ExchangeCode(f.redirectUri(r), code)
}

// Get user with token

func (f *ForwardAuth) GetUser(token string) (provider.User, error) {
	// TODO: Support multiple providers
	return config.Providers.Google.GetUser(token)
}

// Utility methods

// Get the redirect base
func (f *ForwardAuth) redirectBase(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")

	return fmt.Sprintf("%s://%s", proto, host)
}

// // Return url
func (f *ForwardAuth) returnUrl(r *http.Request) string {
	path := r.Header.Get("X-Forwarded-Uri")

	return fmt.Sprintf("%s%s", f.redirectBase(r), path)
}

// Get oauth redirect uri
func (f *ForwardAuth) redirectUri(r *http.Request) string {
	if use, _ := f.useAuthDomain(r); use {
		proto := r.Header.Get("X-Forwarded-Proto")
		return fmt.Sprintf("%s://%s%s", proto, config.AuthHost, config.Path)
	}

	return fmt.Sprintf("%s%s", f.redirectBase(r), config.Path)
}

// Should we use auth host + what it is
func (f *ForwardAuth) useAuthDomain(r *http.Request) (bool, string) {
	if config.AuthHost == "" {
		return false, ""
	}

	// Does the request match a given cookie domain?
	reqMatch, reqHost := f.matchCookieDomains(r.Header.Get("X-Forwarded-Host"))

	// Do any of the auth hosts match a cookie domain?
	authMatch, authHost := f.matchCookieDomains(config.AuthHost)

	// We need both to match the same domain
	return reqMatch && authMatch && reqHost == authHost, reqHost
}

// Cookie methods

// Create an auth cookie
func (f *ForwardAuth) MakeCookie(r *http.Request, email string) *http.Cookie {
	expires := f.cookieExpiry()
	mac := f.cookieSignature(r, email, fmt.Sprintf("%d", expires.Unix()))
	value := fmt.Sprintf("%s|%d|%s", mac, expires.Unix(), email)

	return &http.Cookie{
		Name:     config.CookieName,
		Value:    value,
		Path:     "/",
		Domain:   f.cookieDomain(r),
		HttpOnly: true,
		Secure:   config.CookieSecure,
		Expires:  expires,
	}
}

// Make a CSRF cookie (used during login only)
func (f *ForwardAuth) MakeCSRFCookie(r *http.Request, nonce string) *http.Cookie {
	return &http.Cookie{
		Name:     config.CSRFCookieName,
		Value:    nonce,
		Path:     "/",
		Domain:   f.csrfCookieDomain(r),
		HttpOnly: true,
		Secure:   config.CookieSecure,
		Expires:  f.cookieExpiry(),
	}
}

// Create a cookie to clear csrf cookie
func (f *ForwardAuth) ClearCSRFCookie(r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     config.CSRFCookieName,
		Value:    "",
		Path:     "/",
		Domain:   f.csrfCookieDomain(r),
		HttpOnly: true,
		Secure:   config.CookieSecure,
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}

// // Validate the csrf cookie against state
func (f *ForwardAuth) ValidateCSRFCookie(r *http.Request, c *http.Cookie) (bool, string, error) {
	state := r.URL.Query().Get("state")

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

	// Check if any of the given cookie domains matches
	_, domain := f.matchCookieDomains(host)
	return domain
}

// Cookie domain
func (f *ForwardAuth) csrfCookieDomain(r *http.Request) string {
	var host string
	if use, domain := f.useAuthDomain(r); use {
		host = domain
	} else {
		host = r.Header.Get("X-Forwarded-Host")
	}

	// Remove port
	p := strings.Split(host, ":")
	return p[0]
}

// Return matching cookie domain if exists
func (f *ForwardAuth) matchCookieDomains(domain string) (bool, string) {
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
func (f *ForwardAuth) cookieSignature(r *http.Request, email, expires string) string {
	hash := hmac.New(sha256.New, config.SecretBytes)
	hash.Write([]byte(f.cookieDomain(r)))
	hash.Write([]byte(email))
	hash.Write([]byte(expires))
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}

// Get cookie expirary
func (f *ForwardAuth) cookieExpiry() time.Time {
	return time.Now().Local().Add(config.Lifetime)
}

// Cookie Domain

// Cookie Domain
type CookieDomain struct {
	Domain       string
	DomainLen    int
	SubDomain    string
	SubDomainLen int
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
