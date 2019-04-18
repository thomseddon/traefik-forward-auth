package tfa

import (
	"bytes"
	"os"
	"testing"
	"time"
)

/**
 * Tests
 */

func TestConfigDefaults(t *testing.T) {
	// Check defaults
	c, err := NewConfig([]string{})
	if err != nil {
		t.Error(err)
	}

	if c.LogLevel != "warn" {
		t.Error("LogLevel default should be warn, got", c.LogLevel)
	}
	if c.LogFormat != "text" {
		t.Error("LogFormat default should be text, got", c.LogFormat)
	}

	if c.AuthHost != "" {
		t.Error("AuthHost default should be empty, got", c.AuthHost)
	}
	if len(c.CookieDomains) != 0 {
		t.Error("CookieDomains default should be empty, got", c.CookieDomains)
	}
	if c.InsecureCookie != false {
		t.Error("InsecureCookie default should be false, got", c.InsecureCookie)
	}
	if c.CookieName != "_forward_auth" {
		t.Error("CookieName default should be _forward_auth, got", c.CookieName)
	}
	if c.CSRFCookieName != "_forward_auth_csrf" {
		t.Error("CSRFCookieName default should be _forward_auth_csrf, got", c.CSRFCookieName)
	}
	if c.DefaultAction != "auth" {
		t.Error("DefaultAction default should be auth, got", c.DefaultAction)
	}
	if len(c.Domains) != 0 {
		t.Error("Domain default should be empty, got", c.Domains)
	}
	if c.Lifetime != time.Second*time.Duration(43200) {
		t.Error("Lifetime default should be 43200, got", c.Lifetime)
	}
	if c.Path != "/_oauth" {
		t.Error("Path default should be /_oauth, got", c.Path)
	}
	if len(c.Whitelist) != 0 {
		t.Error("Whitelist default should be empty, got", c.Whitelist)
	}

	if c.Providers.Google.Prompt != "" {
		t.Error("Providers.Google.Prompt default should be empty, got", c.Providers.Google.Prompt)
	}
}

func TestConfigParseArgs(t *testing.T) {
	c, err := NewConfig([]string{
		"--cookie-name=cookiename",
		"--csrf-cookie-name", "\"csrfcookiename\"",
		"--rule.1.action=allow",
		"--rule.1.rule=PathPrefix(`/one`)",
		"--rule.two.action=auth",
		"--rule.two.rule=\"Host(`two.com`) && Path(`/two`)\"",
	})
	if err != nil {
		t.Error(err)
	}

	// Check normal flags
	if c.CookieName != "cookiename" {
		t.Error("CookieName default should be cookiename, got", c.CookieName)
	}
	if c.CSRFCookieName != "csrfcookiename" {
		t.Error("CSRFCookieName default should be csrfcookiename, got", c.CSRFCookieName)
	}

	// Check rules
	if len(c.Rules) != 2 {
		t.Error("Should create 2 rules, got:", len(c.Rules))
	}

	// First rule
	if rule, ok := c.Rules["1"]; !ok {
		t.Error("Could not find rule key '1'")
	} else {
		if rule.Action != "allow" {
			t.Error("First rule action should be allow, got:", rule.Action)
		}
		if rule.Rule != "PathPrefix(`/one`)" {
			t.Error("First rule rule should be PathPrefix(`/one`), got:", rule.Rule)
		}
		if rule.Provider != "google" {
			t.Error("First rule provider should be google, got:", rule.Provider)
		}
	}

	// Second rule
	if rule, ok := c.Rules["two"]; !ok {
		t.Error("Could not find rule key '1'")
	} else {
		if rule.Action != "auth" {
			t.Error("Second rule action should be auth, got:", rule.Action)
		}
		if rule.Rule != "Host(`two.com`) && Path(`/two`)" {
			t.Error("Second rule rule should be Host(`two.com`) && Path(`/two`), got:", rule.Rule)
		}
		if rule.Provider != "google" {
			t.Error("Second rule provider should be google, got:", rule.Provider)
		}
	}
}

func TestConfigParseUnknownFlags(t *testing.T) {
	_, err := NewConfig([]string{
		"--unknown=_oauthpath2",
	})
	if err.Error() != "unknown flag: unknown" {
		t.Error("Error should be \"unknown flag: unknown\", got:", err)
	}
}

func TestConfigFlagBackwardsCompatability(t *testing.T) {
	c, err := NewConfig([]string{
		"--client-id=clientid",
		"--client-secret=verysecret",
		"--prompt=prompt",
		"--lifetime=200",
		"--cookie-secure=false",
	})
	if err != nil {
		t.Error(err)
	}

	if c.ClientIdLegacy != "clientid" {
		t.Error("ClientIdLegacy should be clientid, got", c.ClientIdLegacy)
	}
	if c.Providers.Google.ClientId != "clientid" {
		t.Error("Providers.Google.ClientId should be clientid, got", c.Providers.Google.ClientId)
	}
	if c.ClientSecretLegacy != "verysecret" {
		t.Error("ClientSecretLegacy should be verysecret, got", c.ClientSecretLegacy)
	}
	if c.Providers.Google.ClientSecret != "verysecret" {
		t.Error("Providers.Google.ClientSecret should be verysecret, got", c.Providers.Google.ClientSecret)
	}
	if c.PromptLegacy != "prompt" {
		t.Error("PromptLegacy should be prompt, got", c.PromptLegacy)
	}
	if c.Providers.Google.Prompt != "prompt" {
		t.Error("Providers.Google.Prompt should be prompt, got", c.Providers.Google.Prompt)
	}

	// "cookie-secure" used to be a standard go bool flag that could take
	// true, TRUE, 1, false, FALSE, 0 etc. values.
	// Here we're checking that format is still suppoted
	if c.CookieSecureLegacy != "false" || c.InsecureCookie != true {
		t.Error("Setting cookie-secure=false should set InsecureCookie true, got", c.InsecureCookie)
	}
	c, err = NewConfig([]string{"--cookie-secure=TRUE"})
	if err != nil {
		t.Error(err)
	}
	if c.CookieSecureLegacy != "TRUE" || c.InsecureCookie != false {
		t.Error("Setting cookie-secure=TRUE should set InsecureCookie false, got", c.InsecureCookie)
	}
}

func TestConfigParseIni(t *testing.T) {
	c, err := NewConfig([]string{
		"--config=../test/config0",
		"--config=../test/config1",
		"--csrf-cookie-name=csrfcookiename",
	})
	if err != nil {
		t.Error(err)
	}

	if c.CookieName != "inicookiename" {
		t.Error("CookieName should be read as inicookiename from ini file, got", c.CookieName)
	}
	if c.CSRFCookieName != "csrfcookiename" {
		t.Error("CSRFCookieName argument should override ini file, got", c.CSRFCookieName)
	}
	if c.Path != "/two" {
		t.Error("Path in second ini file should override first ini file, got", c.Path)
	}
}

func TestConfigFileBackwardsCompatability(t *testing.T) {
	c, err := NewConfig([]string{
		"--config=../test/config-legacy",
	})
	if err != nil {
		t.Error(err)
	}

	if c.Path != "/two" {
		t.Error("Path in legacy config file should be read, got", c.Path)
	}
}

func TestConfigParseEnvironment(t *testing.T) {
	os.Setenv("COOKIE_NAME", "env_cookie_name")
	c, err := NewConfig([]string{})
	if err != nil {
		t.Error(err)
	}

	if c.CookieName != "env_cookie_name" {
		t.Error("CookieName should be read as env_cookie_name from environment, got", c.CookieName)
	}
}

func TestConfigTransformation(t *testing.T) {
	c, err := NewConfig([]string{
		"--url-path=_oauthpath",
		"--secret=verysecret",
		"--lifetime=200",
	})
	if err != nil {
		t.Error(err)
	}

	if c.Path != "/_oauthpath" {
		t.Error("Path should add slash to front to get /_oauthpath, got:", c.Path)
	}

	if c.SecretString != "verysecret" {
		t.Error("SecretString should be verysecret, got:", c.SecretString)
	}
	if bytes.Compare(c.Secret, []byte("verysecret")) != 0 {
		t.Error("Secret should be []byte(verysecret), got:", string(c.Secret))
	}

	if c.LifetimeString != 200 {
		t.Error("LifetimeString should be 200, got:", c.LifetimeString)
	}
	if c.Lifetime != time.Second*time.Duration(200) {
		t.Error("Lifetime default should be 200, got", c.Lifetime)
	}
}

func TestConfigCommaSeparatedList(t *testing.T) {
	list := CommaSeparatedList{}

	err := list.UnmarshalFlag("one,two")
	if err != nil {
		t.Error(err)
	}
	if len(list) != 2 || list[0] != "one" || list[1] != "two" {
		t.Error("Expected UnmarshalFlag to provide CommaSeparatedList{one,two}, got", list)
	}

	marshal, err := list.MarshalFlag()
	if err != nil {
		t.Error(err)
	}
	if marshal != "one,two" {
		t.Error("Expected MarshalFlag to provide \"one,two\", got", list)
	}
}
