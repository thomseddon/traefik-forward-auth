package tfa

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/thomseddon/traefik-forward-auth/internal/provider"
)

/**
 * Tests
 */

func TestAuthValidateCookie(t *testing.T) {
	config, _ = NewConfig([]string{})
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	c := &http.Cookie{}

	// Should require 3 parts
	c.Value = ""
	valid, _, err := ValidateCookie(r, c)
	if valid || err.Error() != "Invalid cookie format" {
		t.Error("Should get \"Invalid cookie format\", got:", err)
	}
	c.Value = "1|2"
	valid, _, err = ValidateCookie(r, c)
	if valid || err.Error() != "Invalid cookie format" {
		t.Error("Should get \"Invalid cookie format\", got:", err)
	}
	c.Value = "1|2|3|4"
	valid, _, err = ValidateCookie(r, c)
	if valid || err.Error() != "Invalid cookie format" {
		t.Error("Should get \"Invalid cookie format\", got:", err)
	}

	// Should catch invalid mac
	c.Value = "MQ==|2|3"
	valid, _, err = ValidateCookie(r, c)
	if valid || err.Error() != "Invalid cookie mac" {
		t.Error("Should get \"Invalid cookie mac\", got:", err)
	}

	// Should catch expired
	config.Lifetime = time.Second * time.Duration(-1)
	c = MakeCookie(r, "test@test.com")
	valid, _, err = ValidateCookie(r, c)
	if valid || err.Error() != "Cookie has expired" {
		t.Error("Should get \"Cookie has expired\", got:", err)
	}

	// Should accept valid cookie
	config.Lifetime = time.Second * time.Duration(10)
	c = MakeCookie(r, "test@test.com")
	valid, email, err := ValidateCookie(r, c)
	if !valid {
		t.Error("Valid request should return as valid")
	}
	if err != nil {
		t.Error("Valid request should not return error, got:", err)
	}
	if email != "test@test.com" {
		t.Error("Valid request should return user email")
	}
}

func TestAuthValidateEmail(t *testing.T) {
	config, _ = NewConfig([]string{})

	// Should allow any
	if !ValidateEmail("test@test.com") || !ValidateEmail("one@two.com") {
		t.Error("Should allow any domain if email domain is not defined")
	}

	// Should block non matching domain
	config.Domains = []string{"test.com"}
	if ValidateEmail("one@two.com") {
		t.Error("Should not allow user from another domain")
	}

	// Should allow matching domain
	config.Domains = []string{"test.com"}
	if !ValidateEmail("test@test.com") {
		t.Error("Should allow user from allowed domain")
	}

	// Should block non whitelisted email address
	config.Domains = []string{}
	config.Whitelist = []string{"test@test.com"}
	if ValidateEmail("one@two.com") {
		t.Error("Should not allow user not in whitelist.")
	}

	// Should allow matching whitelisted email address
	config.Domains = []string{}
	config.Whitelist = []string{"test@test.com"}
	if !ValidateEmail("test@test.com") {
		t.Error("Should allow user in whitelist.")
	}
}

// TODO: Split google tests out
func TestAuthGetLoginURL(t *testing.T) {
	google := provider.Google{
		ClientId:     "idtest",
		ClientSecret: "sectest",
		Scope:        "scopetest",
		Prompt:       "consent select_account",
		LoginURL: &url.URL{
			Scheme: "https",
			Host:   "test.com",
			Path:   "/auth",
		},
	}

	config, _ = NewConfig([]string{})
	config.Providers.Google = google

	r, _ := http.NewRequest("GET", "http://example.com", nil)
	r.Header.Add("X-Forwarded-Proto", "http")
	r.Header.Add("X-Forwarded-Host", "example.com")
	r.Header.Add("X-Forwarded-Uri", "/hello")

	// Check url
	uri, err := url.Parse(GetLoginURL(r, "nonce"))
	if err != nil {
		t.Error("Error parsing login url:", err)
	}
	if uri.Scheme != "https" {
		t.Error("Expected login Scheme to be \"https\", got:", uri.Scheme)
	}
	if uri.Host != "test.com" {
		t.Error("Expected login Host to be \"test.com\", got:", uri.Host)
	}
	if uri.Path != "/auth" {
		t.Error("Expected login Path to be \"/auth\", got:", uri.Path)
	}

	// Check query string
	qs := uri.Query()
	expectedQs := url.Values{
		"client_id":     []string{"idtest"},
		"redirect_uri":  []string{"http://example.com/_oauth"},
		"response_type": []string{"code"},
		"scope":         []string{"scopetest"},
		"prompt":        []string{"consent select_account"},
		"state":         []string{"nonce:http://example.com/hello"},
	}
	if !reflect.DeepEqual(qs, expectedQs) {
		for _, err := range qsDiff(t, expectedQs, qs) {
			t.Error(err)
		}
	}

	//
	// With Auth URL but no matching cookie domain
	// - will not use auth host
	//
	config, _ = NewConfig([]string{})
	config.AuthHost = "auth.example.com"
	config.Providers.Google = google

	// Check url
	uri, err = url.Parse(GetLoginURL(r, "nonce"))
	if err != nil {
		t.Error("Error parsing login url:", err)
	}
	if uri.Scheme != "https" {
		t.Error("Expected login Scheme to be \"https\", got:", uri.Scheme)
	}
	if uri.Host != "test.com" {
		t.Error("Expected login Host to be \"test.com\", got:", uri.Host)
	}
	if uri.Path != "/auth" {
		t.Error("Expected login Path to be \"/auth\", got:", uri.Path)
	}

	// Check query string
	qs = uri.Query()
	expectedQs = url.Values{
		"client_id":     []string{"idtest"},
		"redirect_uri":  []string{"http://example.com/_oauth"},
		"response_type": []string{"code"},
		"scope":         []string{"scopetest"},
		"prompt":        []string{"consent select_account"},
		"state":         []string{"nonce:http://example.com/hello"},
	}
	if !reflect.DeepEqual(qs, expectedQs) {
		for _, err := range qsDiff(t, expectedQs, qs) {
			t.Error(err)
		}
	}

	//
	// With correct Auth URL + cookie domain
	//
	config, _ = NewConfig([]string{})
	config.AuthHost = "auth.example.com"
	config.CookieDomains = []CookieDomain{*NewCookieDomain("example.com")}
	config.Providers.Google = google

	// Check url
	uri, err = url.Parse(GetLoginURL(r, "nonce"))
	if err != nil {
		t.Error("Error parsing login url:", err)
	}
	if uri.Scheme != "https" {
		t.Error("Expected login Scheme to be \"https\", got:", uri.Scheme)
	}
	if uri.Host != "test.com" {
		t.Error("Expected login Host to be \"test.com\", got:", uri.Host)
	}
	if uri.Path != "/auth" {
		t.Error("Expected login Path to be \"/auth\", got:", uri.Path)
	}

	// Check query string
	qs = uri.Query()
	expectedQs = url.Values{
		"client_id":     []string{"idtest"},
		"redirect_uri":  []string{"http://auth.example.com/_oauth"},
		"response_type": []string{"code"},
		"scope":         []string{"scopetest"},
		"state":         []string{"nonce:http://example.com/hello"},
		"prompt":        []string{"consent select_account"},
	}
	for _, err := range qsDiff(t, expectedQs, qs) {
		t.Error(err)
	}
	if !reflect.DeepEqual(qs, expectedQs) {
		for _, err := range qsDiff(t, expectedQs, qs) {
			t.Error(err)
		}
	}

	//
	// With Auth URL + cookie domain, but from different domain
	// - will not use auth host
	//
	r, _ = http.NewRequest("GET", "http://another.com", nil)
	r.Header.Add("X-Forwarded-Proto", "http")
	r.Header.Add("X-Forwarded-Host", "another.com")
	r.Header.Add("X-Forwarded-Uri", "/hello")

	// Check url
	uri, err = url.Parse(GetLoginURL(r, "nonce"))
	if err != nil {
		t.Error("Error parsing login url:", err)
	}
	if uri.Scheme != "https" {
		t.Error("Expected login Scheme to be \"https\", got:", uri.Scheme)
	}
	if uri.Host != "test.com" {
		t.Error("Expected login Host to be \"test.com\", got:", uri.Host)
	}
	if uri.Path != "/auth" {
		t.Error("Expected login Path to be \"/auth\", got:", uri.Path)
	}

	// Check query string
	qs = uri.Query()
	expectedQs = url.Values{
		"client_id":     []string{"idtest"},
		"redirect_uri":  []string{"http://another.com/_oauth"},
		"response_type": []string{"code"},
		"scope":         []string{"scopetest"},
		"state":         []string{"nonce:http://another.com/hello"},
		"prompt":        []string{"consent select_account"},
	}
	for _, err := range qsDiff(t, expectedQs, qs) {
		t.Error(err)
	}
	if !reflect.DeepEqual(qs, expectedQs) {
		for _, err := range qsDiff(t, expectedQs, qs) {
			t.Error(err)
		}
	}
}

// TODO
// func TestAuthExchangeCode(t *testing.T) {
// }

// TODO
// func TestAuthGetUser(t *testing.T) {
// }

func TestAuthMakeCookie(t *testing.T) {
	config, _ = NewConfig([]string{})
	r, _ := http.NewRequest("GET", "http://app.example.com", nil)
	r.Header.Add("X-Forwarded-Host", "app.example.com")

	c := MakeCookie(r, "test@example.com")
	if c.Name != "_forward_auth" {
		t.Error("Cookie name should be \"_forward_auth\", got:", c.Name)
	}
	parts := strings.Split(c.Value, "|")
	if len(parts) != 3 {
		t.Error("Cookie should be in 3 parts, got:", c.Value)
	}
	valid, _, _ := ValidateCookie(r, c)
	if !valid {
		t.Error("Should generate valid cookie:", c.Value)
	}
	if c.Path != "/" {
		t.Error("Cookie path should be \"/\", got:", c.Path)
	}
	if c.Domain != "app.example.com" {
		t.Error("Cookie domain should be \"app.example.com\", got:", c.Domain)
	}
	if c.Secure != true {
		t.Error("Cookie domain should be true, got:", c.Secure)
	}
	if !c.Expires.After(time.Now().Local()) {
		t.Error("Expires should be after now, got:", c.Expires)
	}
	if !c.Expires.Before(time.Now().Local().Add(config.Lifetime).Add(10 * time.Second)) {
		t.Error("Expires should be before lifetime + 10 seconds, got:", c.Expires)
	}

	config.CookieName = "testname"
	config.InsecureCookie = true
	c = MakeCookie(r, "test@example.com")
	if c.Name != "testname" {
		t.Error("Cookie name should be \"testname\", got:", c.Name)
	}
	if c.Secure != false {
		t.Error("Cookie domain should be false, got:", c.Secure)
	}
}

func TestAuthMakeCSRFCookie(t *testing.T) {
	config, _ = NewConfig([]string{})
	r, _ := http.NewRequest("GET", "http://app.example.com", nil)
	r.Header.Add("X-Forwarded-Host", "app.example.com")

	// No cookie domain or auth url
	c := MakeCSRFCookie(r, "12345678901234567890123456789012")
	if c.Domain != "app.example.com" {
		t.Error("Cookie Domain should match request domain, got:", c.Domain)
	}

	// With cookie domain but no auth url
	config = Config{
		CookieDomains: []CookieDomain{*NewCookieDomain("example.com")},
	}
	c = MakeCSRFCookie(r, "12345678901234567890123456789012")
	if c.Domain != "app.example.com" {
		t.Error("Cookie Domain should match request domain, got:", c.Domain)
	}

	// With cookie domain and auth url
	config = Config{
		AuthHost:      "auth.example.com",
		CookieDomains: []CookieDomain{*NewCookieDomain("example.com")},
	}
	c = MakeCSRFCookie(r, "12345678901234567890123456789012")
	if c.Domain != "example.com" {
		t.Error("Cookie Domain should match request domain, got:", c.Domain)
	}
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
	valid, _, err := ValidateCSRFCookie(r, c)
	if valid || err.Error() != "Invalid CSRF cookie value" {
		t.Error("Should get \"Invalid CSRF cookie value\", got:", err)
	}
	c.Value = "123456789012345678901234567890123"
	valid, _, err = ValidateCSRFCookie(r, c)
	if valid || err.Error() != "Invalid CSRF cookie value" {
		t.Error("Should get \"Invalid CSRF cookie value\", got:", err)
	}

	// Should require valid state
	r = newCsrfRequest("12345678901234567890123456789012:")
	c.Value = "12345678901234567890123456789012"
	valid, _, err = ValidateCSRFCookie(r, c)
	if valid || err.Error() != "Invalid CSRF state value" {
		t.Error("Should get \"Invalid CSRF state value\", got:", err)
	}

	// Should allow valid state
	r = newCsrfRequest("12345678901234567890123456789012:99")
	c.Value = "12345678901234567890123456789012"
	valid, state, err := ValidateCSRFCookie(r, c)
	if !valid {
		t.Error("Valid request should return as valid")
	}
	if err != nil {
		t.Error("Valid request should not return error, got:", err)
	}
	if state != "99" {
		t.Error("Valid request should return correct state, got:", state)
	}
}

func TestAuthNonce(t *testing.T) {
	err, nonce1 := Nonce()
	if err != nil {
		t.Error("Error generation nonce:", err)
	}

	err, nonce2 := Nonce()
	if err != nil {
		t.Error("Error generation nonce:", err)
	}

	if len(nonce1) != 32 || len(nonce2) != 32 {
		t.Error("Nonce should be 32 chars")
	}
	if nonce1 == nonce2 {
		t.Error("Nonce should not be equal")
	}
}

func TestAuthCookieDomainMatch(t *testing.T) {
	cd := NewCookieDomain("example.com")

	// Exact should match
	if !cd.Match("example.com") {
		t.Error("Exact domain should match")
	}

	// Subdomain should match
	if !cd.Match("test.example.com") {
		t.Error("Subdomain should match")
	}

	// Derived domain should not match
	if cd.Match("testexample.com") {
		t.Error("Derived domain should not match")
	}

	// Other domain should not match
	if cd.Match("test.com") {
		t.Error("Other domain should not match")
	}
}

func TestAuthCookieDomains(t *testing.T) {
	cds := CookieDomains{}

	err := cds.UnmarshalFlag("one.com,two.org")
	if err != nil {
		t.Error(err)
	}
	if len(cds) != 2 {
		t.Error("Expected UnmarshalFlag to provide 2 CookieDomains, got", cds)
	}
	if cds[0].Domain != "one.com" || cds[0].SubDomain != ".one.com" {
		t.Error("Expected UnmarshalFlag to provide one.com, got", cds[0])
	}
	if cds[1].Domain != "two.org" || cds[1].SubDomain != ".two.org" {
		t.Error("Expected UnmarshalFlag to provide two.org, got", cds[1])
	}

	marshal, err := cds.MarshalFlag()
	if err != nil {
		t.Error(err)
	}
	if marshal != "one.com,two.org" {
		t.Error("Expected MarshalFlag to provide \"one.com,two.org\", got", cds)
	}
}
