package tfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/thomseddon/traefik-forward-auth/internal/provider"
)

// Request Validation

// ValidateCookie verifies that a cookie matches the expected format of:
// Cookie = hash(secret, cookie domain, email, expires)|expires|email
func ValidateCookie(r *http.Request, c *http.Cookie) (string, error) {
	parts := strings.Split(c.Value, "|")

	if len(parts) != 3 {
		return "", errors.New("Invalid cookie format")
	}

	mac, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("Unable to decode cookie mac")
	}

	expectedSignature := cookieSignature(r, parts[2], parts[1])
	expected, err := base64.URLEncoding.DecodeString(expectedSignature)
	if err != nil {
		return "", errors.New("Unable to generate mac")
	}

	// Valid token?
	if !hmac.Equal(mac, expected) {
		return "", errors.New("Invalid cookie mac")
	}

	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", errors.New("Unable to parse cookie expiry")
	}

	// Has it expired?
	if time.Unix(expires, 0).Before(time.Now()) {
		return "", errors.New("Cookie has expired")
	}

	// Looks valid
	return parts[2], nil
}

// ValidateEmail checks if the given email address matches either a whitelisted
// email address, as defined by the "whitelist" config parameter. Or is part of
// a permitted domain, as defined by the "domains" config parameter
func ValidateEmail(email string) bool {
	// Do we have any validation to perform?
	if len(config.Whitelist) == 0 && len(config.Domains) == 0 {
		return true
	}

	// Email whitelist validation
	if len(config.Whitelist) > 0 {
		for _, whitelist := range config.Whitelist {
			if email == whitelist {
				return true
			}
		}

		// If we're not matching *either*, stop here
		if !config.MatchWhitelistOrDomain {
			return false
		}
	}

	// Domain validation
	if len(config.Domains) > 0 {
		parts := strings.Split(email, "@")
		if len(parts) < 2 {
			return false
		}
		for _, domain := range config.Domains {
			if domain == parts[1] {
				return true
			}
		}
	}

	return false
}

// Utility methods

// Get the redirect base
func redirectBase(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")

	return fmt.Sprintf("%s://%s", proto, host)
}

// Return url
func returnUrl(r *http.Request) string {
	path := r.Header.Get("X-Forwarded-Uri")

	return fmt.Sprintf("%s%s", redirectBase(r), path)
}

// Get oauth redirect uri
func redirectUri(r *http.Request) string {
	if use, _ := useAuthDomain(r); use {
		proto := r.Header.Get("X-Forwarded-Proto")
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

// MakeCookie creates an auth cookie
func MakeCookie(r *http.Request, email string) *http.Cookie {
	expires := cookieExpiry()
	mac := cookieSignature(r, email, fmt.Sprintf("%d", expires.Unix()))
	value := fmt.Sprintf("%s|%d|%s", mac, expires.Unix(), email)

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

// ClearCookie clears the auth cookie
func ClearCookie(r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     config.CookieName,
		Value:    "",
		Path:     "/",
		Domain:   cookieDomain(r),
		HttpOnly: true,
		Secure:   !config.InsecureCookie,
		Expires:  time.Now().Local().Add(time.Hour * -1),
	}
}

// MakeCSRFCookie makes a csrf cookie (used during login only)
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

// ClearCSRFCookie makes an expired csrf cookie to clear csrf cookie
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

// ValidateCSRFCookie validates the csrf cookie against state
func ValidateCSRFCookie(r *http.Request, c *http.Cookie) (valid bool, provider string, redirect string, err error) {
	state := r.URL.Query().Get("state")

	if len(c.Value) != 32 {
		return false, "", "", errors.New("Invalid CSRF cookie value")
	}

	if len(state) < 34 {
		return false, "", "", errors.New("Invalid CSRF state value")
	}

	// Check nonce match
	if c.Value != state[:32] {
		return false, "", "", errors.New("CSRF cookie does not match state")
	}

	// Extract provider
	params := state[33:]
	split := strings.Index(params, ":")
	if split == -1 {
		return false, "", "", errors.New("Invalid CSRF state format")
	}

	// Valid, return provider and redirect
	return true, params[:split], params[split+1:], nil
}

// MakeState generates a state value
func MakeState(r *http.Request, p provider.Provider, nonce string) string {
	return fmt.Sprintf("%s:%s:%s", nonce, p.Name(), returnUrl(r))
}

// Nonce generates a random nonce
func Nonce() (error, string) {
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

// CookieDomain holds cookie domain info
type CookieDomain struct {
	Domain       string
	DomainLen    int
	SubDomain    string
	SubDomainLen int
}

// NewCookieDomain creates a new CookieDomain from the given domain string
func NewCookieDomain(domain string) *CookieDomain {
	return &CookieDomain{
		Domain:       domain,
		DomainLen:    len(domain),
		SubDomain:    fmt.Sprintf(".%s", domain),
		SubDomainLen: len(domain) + 1,
	}
}

// Match checks if the given host matches this CookieDomain
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

// UnmarshalFlag converts a string to a CookieDomain
func (c *CookieDomain) UnmarshalFlag(value string) error {
	*c = *NewCookieDomain(value)
	return nil
}

// MarshalFlag converts a CookieDomain to a string
func (c *CookieDomain) MarshalFlag() (string, error) {
	return c.Domain, nil
}

// CookieDomains provides legacy sypport for comma separated list of cookie domains
type CookieDomains []CookieDomain

// UnmarshalFlag converts a comma separated list of cookie domains to an array
// of CookieDomains
func (c *CookieDomains) UnmarshalFlag(value string) error {
	if len(value) > 0 {
		for _, d := range strings.Split(value, ",") {
			cookieDomain := NewCookieDomain(d)
			*c = append(*c, *cookieDomain)
		}
	}
	return nil
}

// MarshalFlag converts an array of CookieDomain to a comma seperated list
func (c *CookieDomains) MarshalFlag() (string, error) {
	var domains []string
	for _, d := range *c {
		domains = append(domains, d.Domain)
	}
	return strings.Join(domains, ","), nil
}
