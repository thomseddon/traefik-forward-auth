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

// Validate email
func ValidateEmail(email string, rule string) bool {
	found := false

	_, ruleExists := config.Rules[rule]
	if ruleExists && len(config.Rules[rule].Whitelist) > 0 {
		found = ValidateWhitelist(email, config.Rules[rule].Whitelist)
	} else if ruleExists && len(config.Rules[rule].Domains) > 0 {
		found = ValidateDomains(email, config.Rules[rule].Domains)
	} else if len(config.Whitelist) > 0 {
		found = ValidateWhitelist(email, config.Whitelist)
	} else if len(config.Domains) > 0 {
		found = ValidateDomains(email, config.Domains)
	} else {
		return true
	}

	return found
}

// Validate email is in whitelist
func ValidateWhitelist(email string, whitelist CommaSeparatedList) bool {
	found := false
	for _, whitelist := range whitelist {
		if email == whitelist {
			found = true
		}
	}
	return found
}

// Validate email match a domains
func ValidateDomains(email string, domains CommaSeparatedList) bool {
	found := false
	parts := strings.Split(email, "@")
	if len(parts) < 2 {
		return false
	}
	for _, domain := range domains {
		if domain == parts[1] {
			found = true
		}
	}
	return found
}

// OAuth Methods

// Get login url
func GetLoginURL(r *http.Request, nonce string) string {
	state := fmt.Sprintf("%s:%s", nonce, returnUrl(r))

	// TODO: Support multiple providers
	return config.Providers.Google.GetLoginURL(redirectUri(r), state)
}

// Exchange code for token

func ExchangeCode(r *http.Request) (string, error) {
	code := r.URL.Query().Get("code")

	// TODO: Support multiple providers
	return config.Providers.Google.ExchangeCode(redirectUri(r), code)
}

// Get user with token

func GetUser(token string) (provider.User, error) {
	// TODO: Support multiple providers
	return config.Providers.Google.GetUser(token)
}

// Utility methods

// Get the redirect base
func redirectBase(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")

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
func ValidateCSRFCookie(r *http.Request, c *http.Cookie) (bool, string, error) {
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

// Get cookie expirary
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
