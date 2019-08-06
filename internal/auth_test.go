package tfa

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/thomseddon/traefik-forward-auth/internal/provider"
)

/**
 * Tests
 */

func TestAuthValidateCookie(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	c := &http.Cookie{}

	// Should require 3 parts
	c.Value = ""
	_, err := ValidateCookie(r, c)
	if assert.Error(err) {
		assert.Equal("Invalid cookie format", err.Error())
	}
	c.Value = "1|2"
	_, err = ValidateCookie(r, c)
	if assert.Error(err) {
		assert.Equal("Invalid cookie format", err.Error())
	}
	c.Value = "1|2|3|4"
	_, err = ValidateCookie(r, c)
	if assert.Error(err) {
		assert.Equal("Invalid cookie format", err.Error())
	}

	// Should catch invalid mac
	c.Value = "MQ==|2|3"
	_, err = ValidateCookie(r, c)
	if assert.Error(err) {
		assert.Equal("Invalid cookie mac", err.Error())
	}

	// Should catch expired
	config.Lifetime = time.Second * time.Duration(-1)
	c = MakeCookie(r, "test@test.com")
	_, err = ValidateCookie(r, c)
	if assert.Error(err) {
		assert.Equal("Cookie has expired", err.Error())
	}

	// Should accept valid cookie
	config.Lifetime = time.Second * time.Duration(10)
	c = MakeCookie(r, "test@test.com")
	email, err := ValidateCookie(r, c)
	assert.Nil(err, "valid request should not return an error")
	assert.Equal("test@test.com", email, "valid request should return user email")
}

func TestAuthValidateEmail(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})

	// Should allow any
	v := ValidateEmail("test@test.com", "default")
	assert.True(v, "should allow any domain if email domain is not defined")
	v = ValidateEmail("one@two.com", "default")
	assert.True(v, "should allow any domain if email domain is not defined")

	// Should block non matching domain
	config.Domains = []string{"test.com"}
	v = ValidateEmail("one@two.com", "default")
	assert.False(v, "should not allow user from another domain")

	// Should allow matching domain
	config.Domains = []string{"test.com"}
	v = ValidateEmail("test@test.com", "default")
	assert.True(v, "should allow user from allowed domain")

	// Should block non whitelisted email address
	config.Domains = []string{}
	config.Whitelist = []string{"test@test.com"}
	v = ValidateEmail("one@two.com", "default")
	assert.False(v, "should not allow user not in whitelist")

	// Should allow matching whitelisted email address
	config.Domains = []string{}
	config.Whitelist = []string{"test@test.com"}
	v = ValidateEmail("test@test.com", "default")
	assert.True(v, "should allow user in whitelist")

	// Should allow matching whitelisted in rules email address
	config.Domains = []string{"globaltestdomain.com"}
	config.Whitelist = []string{}
	config.Rules = map[string]*Rule{"test": NewRule()}
	config.Rules["test"].Whitelist = []string{"test@test.com"}
	// Validation for user in the rule whitelist
	v = ValidateEmail("test@test.com", "test")
	assert.True(v, "should allow user in rule whitelist")
	// Validation for user not in the rule whitelist
	v = ValidateEmail("test2@test.com", "test")
	assert.False(v, "should not allow user not in rule whitelist")
	// Validation for user in global domain but not in rule
	v = ValidateEmail("test@globaltestdomain.com", "test")
	assert.False(v, "should not allow user in global but not in rule")
	// Validation for user in the whitelist, but that not this rule
	v = ValidateEmail("test@test.com", "default")
	assert.False(v, "should not allow user not in the rule whitelisted")

	// Should allow matching domains
	config.Domains = []string{"globaltestdomain.com"}
	config.Whitelist = []string{}
	config.Rules = map[string]*Rule{"test": NewRule()}
	config.Rules["test"].Domains = []string{"test.com"}
	// Validation for user in the rule domains
	v = ValidateEmail("test@test.com", "test")
	assert.True(v, "should allow user in rule domains")
	// Validation for user not in the rule whitelist
	v = ValidateEmail("test@test2.com", "test")
	assert.False(v, "should not allow user not in rule domains")
	// Validation for user in the whitelist, but that not this rule
	v = ValidateEmail("test@test.com", "default")
	assert.False(v, "should not allow user not in the rule")
}

func TestRedirectUri(t *testing.T) {
	assert := assert.New(t)

	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.Header.Add("X-Forwarded-Proto", "http")
	r.Header.Add("X-Forwarded-Host", "app.example.com")
	r.Header.Add("X-Forwarded-Uri", "/hello")

	//
	// No Auth Host
	//
	config, _ = NewConfig([]string{})

	uri, err := url.Parse(redirectUri(r))
	assert.Nil(err)
	assert.Equal("http", uri.Scheme)
	assert.Equal("app.example.com", uri.Host)
	assert.Equal("/_oauth", uri.Path)

	//
	// With Auth URL but no matching cookie domain
	// - will not use auth host
	//
	config.AuthHost = "auth.example.com"

	uri, err = url.Parse(redirectUri(r))
	assert.Nil(err)
	assert.Equal("http", uri.Scheme)
	assert.Equal("app.example.com", uri.Host)
	assert.Equal("/_oauth", uri.Path)

	//
	// With correct Auth URL + cookie domain
	//
	config.AuthHost = "auth.example.com"
	config.CookieDomains = []CookieDomain{*NewCookieDomain("example.com")}

	// Check url
	uri, err = url.Parse(redirectUri(r))
	assert.Nil(err)
	assert.Equal("http", uri.Scheme)
	assert.Equal("auth.example.com", uri.Host)
	assert.Equal("/_oauth", uri.Path)

	//
	// With Auth URL + cookie domain, but from different domain
	// - will not use auth host
	//
	r, _ = http.NewRequest("GET", "http://another.com", nil)
	r.Header.Add("X-Forwarded-Proto", "https")
	r.Header.Add("X-Forwarded-Host", "another.com")
	r.Header.Add("X-Forwarded-Uri", "/hello")

	config.AuthHost = "auth.example.com"
	config.CookieDomains = []CookieDomain{*NewCookieDomain("example.com")}

	// Check url
	uri, err = url.Parse(redirectUri(r))
	assert.Nil(err)
	assert.Equal("https", uri.Scheme)
	assert.Equal("another.com", uri.Host)
	assert.Equal("/_oauth", uri.Path)
}

func TestAuthMakeCookie(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})
	r, _ := http.NewRequest("GET", "http://app.example.com", nil)
	r.Header.Add("X-Forwarded-Host", "app.example.com")

	c := MakeCookie(r, "test@example.com")
	assert.Equal("_forward_auth", c.Name)
	parts := strings.Split(c.Value, "|")
	assert.Len(parts, 3, "cookie should be 3 parts")
	_, err := ValidateCookie(r, c)
	assert.Nil(err, "should generate valid cookie")
	assert.Equal("/", c.Path)
	assert.Equal("app.example.com", c.Domain)
	assert.True(c.Secure)

	expires := time.Now().Local().Add(config.Lifetime)
	assert.WithinDuration(expires, c.Expires, 10*time.Second)

	config.CookieName = "testname"
	config.InsecureCookie = true
	c = MakeCookie(r, "test@example.com")
	assert.Equal("testname", c.Name)
	assert.False(c.Secure)
}

func TestAuthMakeCSRFCookie(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})
	r, _ := http.NewRequest("GET", "http://app.example.com", nil)
	r.Header.Add("X-Forwarded-Host", "app.example.com")

	// No cookie domain or auth url
	c := MakeCSRFCookie(r, "12345678901234567890123456789012")
	assert.Equal("app.example.com", c.Domain)

	// With cookie domain but no auth url
	config = &Config{
		CookieDomains: []CookieDomain{*NewCookieDomain("example.com")},
	}
	c = MakeCSRFCookie(r, "12345678901234567890123456789012")
	assert.Equal("app.example.com", c.Domain)

	// With cookie domain and auth url
	config = &Config{
		AuthHost:      "auth.example.com",
		CookieDomains: []CookieDomain{*NewCookieDomain("example.com")},
	}
	c = MakeCSRFCookie(r, "12345678901234567890123456789012")
	assert.Equal("example.com", c.Domain)
}

func TestAuthClearCSRFCookie(t *testing.T) {
	config, _ = NewConfig([]string{})
	r, _ := http.NewRequest("GET", "http://example.com", nil)

	c := ClearCSRFCookie(r)
	if c.Value != "" {
		t.Error("ClearCSRFCookie should create cookie with empty value")
	}
}

func TestAuthValidateCSRFCookie(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})
	c := &http.Cookie{}

	newCsrfRequest := func(state string) *http.Request {
		u := fmt.Sprintf("http://example.com?state=%s", state)
		r, _ := http.NewRequest("GET", u, nil)
		return r
	}

	// Should require 32 char string
	r := newCsrfRequest("")
	c.Value = ""
	valid, _, _, err := ValidateCSRFCookie(r, c)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal("Invalid CSRF cookie value", err.Error())
	}
	c.Value = "123456789012345678901234567890123"
	valid, _, _, err = ValidateCSRFCookie(r, c)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal("Invalid CSRF cookie value", err.Error())
	}

	// Should require valid state
	r = newCsrfRequest("12345678901234567890123456789012:")
	c.Value = "12345678901234567890123456789012"
	valid, _, _, err = ValidateCSRFCookie(r, c)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal("Invalid CSRF state value", err.Error())
	}

	// Should require provider
	r = newCsrfRequest("12345678901234567890123456789012:99")
	c.Value = "12345678901234567890123456789012"
	valid, _, _, err = ValidateCSRFCookie(r, c)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal("Invalid CSRF state format", err.Error())
	}

	// Should allow valid state
	r = newCsrfRequest("12345678901234567890123456789012:p99:url123")
	c.Value = "12345678901234567890123456789012"
	valid, provider, redirect, err := ValidateCSRFCookie(r, c)
	assert.True(valid, "valid request should return valid")
	assert.Nil(err, "valid request should not return an error")
	assert.Equal("p99", provider, "valid request should return correct provider")
	assert.Equal("url123", redirect, "valid request should return correct redirect")
}

func TestMakeState(t *testing.T) {
	assert := assert.New(t)

	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.Header.Add("X-Forwarded-Proto", "http")
	r.Header.Add("X-Forwarded-Host", "example.com")
	r.Header.Add("X-Forwarded-Uri", "/hello")

	// Test with google
	p := provider.Google{}
	state := MakeState(r, &p, "nonce")
	assert.Equal("nonce:google:http://example.com/hello", state)

	// Test with OIDC
	p2 := provider.OIDC{}
	state = MakeState(r, &p2, "nonce")
	assert.Equal("nonce:oidc:http://example.com/hello", state)

	// Test with Generic OAuth
	p3 := provider.GenericOAuth{}
	state = MakeState(r, &p3, "nonce")
	assert.Equal("nonce:generic-oauth:http://example.com/hello", state)
}

func TestAuthNonce(t *testing.T) {
	assert := assert.New(t)
	err, nonce1 := Nonce()
	assert.Nil(err, "error generating nonce")
	assert.Len(nonce1, 32, "length should be 32 chars")

	err, nonce2 := Nonce()
	assert.Nil(err, "error generating nonce")
	assert.Len(nonce2, 32, "length should be 32 chars")

	assert.NotEqual(nonce1, nonce2, "nonce should not be equal")
}

func TestAuthCookieDomainMatch(t *testing.T) {
	assert := assert.New(t)
	cd := NewCookieDomain("example.com")

	// Exact should match
	assert.True(cd.Match("example.com"), "exact domain should match")

	// Subdomain should match
	assert.True(cd.Match("test.example.com"), "subdomain should match")
	assert.True(cd.Match("twolevels.test.example.com"), "subdomain should match")
	assert.True(cd.Match("many.many.levels.test.example.com"), "subdomain should match")

	// Derived domain should not match
	assert.False(cd.Match("testexample.com"), "derived domain should not match")

	// Other domain should not match
	assert.False(cd.Match("test.com"), "other domain should not match")
}

func TestAuthCookieDomains(t *testing.T) {
	assert := assert.New(t)
	cds := CookieDomains{}

	err := cds.UnmarshalFlag("one.com,two.org")
	assert.Nil(err)
	expected := CookieDomains{
		CookieDomain{
			Domain:       "one.com",
			DomainLen:    7,
			SubDomain:    ".one.com",
			SubDomainLen: 8,
		},
		CookieDomain{
			Domain:       "two.org",
			DomainLen:    7,
			SubDomain:    ".two.org",
			SubDomainLen: 8,
		},
	}
	assert.Equal(expected, cds)

	marshal, err := cds.MarshalFlag()
	assert.Nil(err)
	assert.Equal("one.com,two.org", marshal)
}
