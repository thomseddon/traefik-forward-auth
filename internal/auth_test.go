package tfa

import (
	"net/http"
	"net/http/httptest"
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

	// Should allow any with no whitelist/domain is specified
	v := ValidateEmail("test@test.com", "default")
	assert.True(v, "should allow any domain if email domain is not defined")
	v = ValidateEmail("one@two.com", "default")
	assert.True(v, "should allow any domain if email domain is not defined")

	// Should allow matching domain
	config.Domains = []string{"test.com"}
	v = ValidateEmail("one@two.com", "default")
	assert.False(v, "should not allow user from another domain")
	v = ValidateEmail("test@test.com", "default")
	assert.True(v, "should allow user from allowed domain")

	// Should allow matching whitelisted email address
	config.Domains = []string{}
	config.Whitelist = []string{"test@test.com"}
	v = ValidateEmail("one@two.com", "default")
	assert.False(v, "should not allow user not in whitelist")
	v = ValidateEmail("test@test.com", "default")
	assert.True(v, "should allow user in whitelist")

	// Should allow only matching email address when
	// MatchWhitelistOrDomain is disabled
	config.Domains = []string{"example.com"}
	config.Whitelist = []string{"test@test.com"}
	config.MatchWhitelistOrDomain = false
	v = ValidateEmail("one@two.com", "default")
	assert.False(v, "should not allow user not in either")
	v = ValidateEmail("test@example.com", "default")
	assert.False(v, "should not allow user from allowed domain")
	v = ValidateEmail("test@test.com", "default")
	assert.True(v, "should allow user in whitelist")

	// Should allow either matching domain or email address when
	// MatchWhitelistOrDomain is enabled
	config.Domains = []string{"example.com"}
	config.Whitelist = []string{"test@test.com"}
	config.MatchWhitelistOrDomain = true
	v = ValidateEmail("one@two.com", "default")
	assert.False(v, "should not allow user not in either")
	v = ValidateEmail("test@example.com", "default")
	assert.True(v, "should allow user from allowed domain")
	v = ValidateEmail("test@test.com", "default")
	assert.True(v, "should allow user in whitelist")

	// Rule testing

	// Should use global whitelist/domain when not specified on rule
	config.Domains = []string{"example.com"}
	config.Whitelist = []string{"test@test.com"}
	config.Rules = map[string]*Rule{"test": NewRule()}
	config.MatchWhitelistOrDomain = true
	v = ValidateEmail("one@two.com", "test")
	assert.False(v, "should not allow user not in either")
	v = ValidateEmail("test@example.com", "test")
	assert.True(v, "should allow user from allowed global domain")
	v = ValidateEmail("test@test.com", "test")
	assert.True(v, "should allow user in global whitelist")

	// Should allow matching domain in rule
	config.Domains = []string{"testglobal.com"}
	config.Whitelist = []string{}
	rule := NewRule()
	config.Rules = map[string]*Rule{"test": rule}
	rule.Domains = []string{"testrule.com"}
	config.MatchWhitelistOrDomain = false
	v = ValidateEmail("one@two.com", "test")
	assert.False(v, "should not allow user from another domain")
	v = ValidateEmail("one@testglobal.com", "test")
	assert.False(v, "should not allow user from global domain")
	v = ValidateEmail("test@testrule.com", "test")
	assert.True(v, "should allow user from allowed domain")

	// Should allow matching whitelist in rule
	config.Domains = []string{}
	config.Whitelist = []string{"test@testglobal.com"}
	rule = NewRule()
	config.Rules = map[string]*Rule{"test": rule}
	rule.Whitelist = []string{"test@testrule.com"}
	config.MatchWhitelistOrDomain = false
	v = ValidateEmail("one@two.com", "test")
	assert.False(v, "should not allow user from another domain")
	v = ValidateEmail("test@testglobal.com", "test")
	assert.False(v, "should not allow user from global domain")
	v = ValidateEmail("test@testrule.com", "test")
	assert.True(v, "should allow user from allowed domain")

	// Should allow only matching email address when
	// MatchWhitelistOrDomain is disabled
	config.Domains = []string{"exampleglobal.com"}
	config.Whitelist = []string{"test@testglobal.com"}
	rule = NewRule()
	config.Rules = map[string]*Rule{"test": rule}
	rule.Domains = []string{"examplerule.com"}
	rule.Whitelist = []string{"test@testrule.com"}
	config.MatchWhitelistOrDomain = false
	v = ValidateEmail("one@two.com", "test")
	assert.False(v, "should not allow user not in either")
	v = ValidateEmail("test@testglobal.com", "test")
	assert.False(v, "should not allow user in global whitelist")
	v = ValidateEmail("test@exampleglobal.com", "test")
	assert.False(v, "should not allow user from global domain")
	v = ValidateEmail("test@examplerule.com", "test")
	assert.False(v, "should not allow user from allowed domain")
	v = ValidateEmail("test@testrule.com", "test")
	assert.True(v, "should allow user in whitelist")

	// Should allow either matching domain or email address when
	// MatchWhitelistOrDomain is enabled
	config.Domains = []string{"exampleglobal.com"}
	config.Whitelist = []string{"test@testglobal.com"}
	rule = NewRule()
	config.Rules = map[string]*Rule{"test": rule}
	rule.Domains = []string{"examplerule.com"}
	rule.Whitelist = []string{"test@testrule.com"}
	config.MatchWhitelistOrDomain = true
	v = ValidateEmail("one@two.com", "test")
	assert.False(v, "should not allow user not in either")
	v = ValidateEmail("test@testglobal.com", "test")
	assert.False(v, "should not allow user in global whitelist")
	v = ValidateEmail("test@exampleglobal.com", "test")
	assert.False(v, "should not allow user from global domain")
	v = ValidateEmail("test@examplerule.com", "test")
	assert.True(v, "should allow user from allowed domain")
	v = ValidateEmail("test@testrule.com", "test")
	assert.True(v, "should allow user in whitelist")
}

func TestAuthValidateRequest(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})

	r := httptest.NewRequest("GET", "http://example.com/foo", nil)
	r.Header.Add("X-Forwarded-Method", "POST")
	r.Header.Add("X-Forwarded-Host", "example.com")
	r.Header.Add("X-Forwarded-Uri", "/foo")

	// No Authorization URL configured, skip request validation
	config.AuthorizationURL = ""
	v := ValidateRequest(r, "test@test.com")
	assert.True(v, "should skip request validation if no authorization URL is configured")

	// Authorization URL configured, validate request response 200 Authorized
	srvOk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Authorized"))
	}))
	defer srvOk.Close()

	config.AuthorizationURL = srvOk.URL
	v = ValidateRequest(r, "test@test.com")
	assert.True(v, "should allow request if authorization URL returns 200 OK")

	// Authorization URL configured, validate request response 200 Unauthorized
	srvKo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Unauthorized"))
	}))
	defer srvKo.Close()

	config.AuthorizationURL = srvKo.URL
	v = ValidateRequest(r, "test@test.com")
	assert.False(v, "should not allow request if authorization URL returns 200 Unauthorized")
}

func TestRedirectUri(t *testing.T) {
	assert := assert.New(t)

	r := httptest.NewRequest("GET", "http://app.example.com/hello", nil)
	r.Header.Add("X-Forwarded-Proto", "http")

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
	r = httptest.NewRequest("GET", "https://another.com/hello", nil)
	r.Header.Add("X-Forwarded-Proto", "https")

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
	assert.Equal("_forward_auth_csrf_123456", c.Name)
	assert.Equal("app.example.com", c.Domain)

	// With cookie domain but no auth url
	config.CookieDomains = []CookieDomain{*NewCookieDomain("example.com")}
	c = MakeCSRFCookie(r, "12222278901234567890123456789012")
	assert.Equal("_forward_auth_csrf_122222", c.Name)
	assert.Equal("app.example.com", c.Domain)

	// With cookie domain and auth url
	config.AuthHost = "auth.example.com"
	config.CookieDomains = []CookieDomain{*NewCookieDomain("example.com")}
	c = MakeCSRFCookie(r, "12333378901234567890123456789012")
	assert.Equal("_forward_auth_csrf_123333", c.Name)
	assert.Equal("example.com", c.Domain)
}

func TestAuthClearCSRFCookie(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})
	r, _ := http.NewRequest("GET", "http://example.com", nil)

	c := ClearCSRFCookie(r, &http.Cookie{Name: "someCsrfCookie"})
	assert.Equal("someCsrfCookie", c.Name)
	if c.Value != "" {
		t.Error("ClearCSRFCookie should create cookie with empty value")
	}
}

func TestAuthValidateCSRFCookie(t *testing.T) {
	assert := assert.New(t)
	config, _ = NewConfig([]string{})
	c := &http.Cookie{}
	state := ""

	// Should require 32 char string
	state = ""
	c.Value = ""
	valid, _, _, err := ValidateCSRFCookie(c, state)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal("Invalid CSRF cookie value", err.Error())
	}
	c.Value = "123456789012345678901234567890123"
	valid, _, _, err = ValidateCSRFCookie(c, state)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal("Invalid CSRF cookie value", err.Error())
	}

	// Should require provider
	state = "12345678901234567890123456789012:99"
	c.Value = "12345678901234567890123456789012"
	valid, _, _, err = ValidateCSRFCookie(c, state)
	assert.False(valid)
	if assert.Error(err) {
		assert.Equal("Invalid CSRF state format", err.Error())
	}

	// Should allow valid state
	state = "12345678901234567890123456789012:p99:url123"
	c.Value = "12345678901234567890123456789012"
	valid, provider, redirect, err := ValidateCSRFCookie(c, state)
	assert.True(valid, "valid request should return valid")
	assert.Nil(err, "valid request should not return an error")
	assert.Equal("p99", provider, "valid request should return correct provider")
	assert.Equal("url123", redirect, "valid request should return correct redirect")
}

func TestValidateState(t *testing.T) {
	assert := assert.New(t)

	// Should require valid state
	state := "12345678901234567890123456789012:"
	err := ValidateState(state)
	if assert.Error(err) {
		assert.Equal("Invalid CSRF state value", err.Error())
	}
	// Should pass this state
	state = "12345678901234567890123456789012:p99:url123"
	err = ValidateState(state)
	assert.Nil(err, "valid request should not return an error")
}

func TestMakeState(t *testing.T) {
	assert := assert.New(t)

	r := httptest.NewRequest("GET", "http://example.com/hello", nil)
	r.Header.Add("X-Forwarded-Proto", "http")

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
