package tfa

import (
	// "fmt"
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

/**
 * Tests
 */

func TestConfigDefaults(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{})
	assert.Nil(err)

	assert.Equal("warn", c.LogLevel)
	assert.Equal("text", c.LogFormat)

	assert.Equal("", c.AuthHost)
	assert.Len(c.CookieDomains, 0)
	assert.False(c.InsecureCookie)
	assert.Equal("_forward_auth", c.CookieName)
	assert.Equal("_forward_auth_csrf", c.CSRFCookieName)
	assert.Equal("auth", c.DefaultAction)
	assert.Equal("google", c.DefaultProvider)
	assert.Len(c.Domains, 0)
	assert.Equal(time.Second*time.Duration(43200), c.Lifetime)
	assert.Equal("", c.LogoutRedirect)
	assert.False(c.MatchWhitelistOrDomain)
	assert.Equal("/_oauth", c.Path)
	assert.Len(c.Whitelist, 0)
	assert.Equal(c.Port, 4181)
	assert.Equal("", c.AuthorizationURL)

	assert.Equal("select_account", c.Providers.Google.Prompt)
}

func TestConfigParseArgs(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{
		"--cookie-name=cookiename",
		"--csrf-cookie-name", "\"csrfcookiename\"",
		"--default-provider", "\"oidc\"",
		"--rule.1.action=allow",
		"--rule.1.rule=PathPrefix(`/one`)",
		"--rule.two.action=auth",
		"--rule.two.rule=\"Host(`two.com`) && Path(`/two`)\"",
		"--authorization-url=http://authorize.example.org/authorize",
		"--port=8000",
	})
	require.Nil(t, err)

	// Check normal flags
	assert.Equal("cookiename", c.CookieName)
	assert.Equal("csrfcookiename", c.CSRFCookieName)
	assert.Equal("oidc", c.DefaultProvider)
	assert.Equal("http://authorize.example.org/authorize", c.AuthorizationURL)
	assert.Equal(8000, c.Port)

	// Check rules
	assert.Equal(map[string]*Rule{
		"1": {
			Action:   "allow",
			Rule:     "PathPrefix(`/one`)",
			Provider: "oidc",
		},
		"two": {
			Action:   "auth",
			Rule:     "Host(`two.com`) && Path(`/two`)",
			Provider: "oidc",
		},
	}, c.Rules)
}

func TestConfigParseUnknownFlags(t *testing.T) {
	_, err := NewConfig([]string{
		"--unknown=_oauthpath2",
	})
	if assert.Error(t, err) {
		assert.Equal(t, "unknown flag: unknown", err.Error())
	}
}

func TestConfigParseRuleError(t *testing.T) {
	assert := assert.New(t)

	// Rule without name
	_, err := NewConfig([]string{
		"--rule..action=auth",
	})
	if assert.Error(err) {
		assert.Equal("route name is required", err.Error())
	}

	// Rule without value
	c, err := NewConfig([]string{
		"--rule.one.action=",
	})
	if assert.Error(err) {
		assert.Equal("route param value is required", err.Error())
	}
	// Check rules
	assert.Equal(map[string]*Rule{}, c.Rules)
}

func TestConfigFlagBackwardsCompatability(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{
		"--client-id=clientid",
		"--client-secret=verysecret",
		"--prompt=prompt",
		"--cookie-secret=veryverysecret",
		"--lifetime=200",
		"--cookie-secure=false",
		"--cookie-domains=test1.com,example.org",
		"--cookie-domain=another1.net",
		"--domain=test2.com,example.org",
		"--domain=another2.net",
		"--whitelist=test3.com,example.org",
		"--whitelist=another3.net",
	})
	require.Nil(t, err)

	// The following used to be passed as comma separated list
	expected1 := []CookieDomain{
		*NewCookieDomain("another1.net"),
		*NewCookieDomain("test1.com"),
		*NewCookieDomain("example.org"),
	}
	assert.Equal(expected1, c.CookieDomains, "should read legacy comma separated list cookie-domains")

	expected2 := CommaSeparatedList{"test2.com", "example.org", "another2.net"}
	assert.Equal(expected2, c.Domains, "should read legacy comma separated list domains")

	expected3 := CommaSeparatedList{"test3.com", "example.org", "another3.net"}
	assert.Equal(expected3, c.Whitelist, "should read legacy comma separated list whitelist")

	// Name changed
	assert.Equal([]byte("veryverysecret"), c.Secret)

	// Google provider params used to be top level
	assert.Equal("clientid", c.ClientIdLegacy)
	assert.Equal("clientid", c.Providers.Google.ClientID, "--client-id should set providers.google.client-id")
	assert.Equal("verysecret", c.ClientSecretLegacy)
	assert.Equal("verysecret", c.Providers.Google.ClientSecret, "--client-secret should set providers.google.client-secret")
	assert.Equal("prompt", c.PromptLegacy)
	assert.Equal("prompt", c.Providers.Google.Prompt, "--prompt should set providers.google.promot")

	// "cookie-secure" used to be a standard go bool flag that could take
	// true, TRUE, 1, false, FALSE, 0 etc. values.
	// Here we're checking that format is still suppoted
	assert.Equal("false", c.CookieSecureLegacy)
	assert.True(c.InsecureCookie, "--cookie-secure=false should set insecure-cookie true")

	c, err = NewConfig([]string{"--cookie-secure=TRUE"})
	assert.Nil(err)
	assert.Equal("TRUE", c.CookieSecureLegacy)
	assert.False(c.InsecureCookie, "--cookie-secure=TRUE should set insecure-cookie false")
}

func TestConfigParseIni(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{
		"--config=../test/config0",
		"--config=../test/config1",
		"--csrf-cookie-name=csrfcookiename",
	})
	require.Nil(t, err)

	assert.Equal("inicookiename", c.CookieName, "should be read from ini file")
	assert.Equal("csrfcookiename", c.CSRFCookieName, "should be read from ini file")
	assert.Equal("/two", c.Path, "variable in second ini file should override first ini file")
	assert.Equal(map[string]*Rule{
		"1": {
			Action:   "allow",
			Rule:     "PathPrefix(`/one`)",
			Provider: "google",
		},
		"two": {
			Action:   "auth",
			Rule:     "Host(`two.com`) && Path(`/two`)",
			Provider: "google",
		},
	}, c.Rules)
}

func TestConfigFileBackwardsCompatability(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{
		"--config=../test/config-legacy",
	})
	require.Nil(t, err)

	assert.Equal("/two", c.Path, "variable in legacy config file should be read")
	assert.Equal("auth.legacy.com", c.AuthHost, "variable in legacy config file should be read")
}

func TestConfigParseEnvironment(t *testing.T) {
	assert := assert.New(t)
	os.Setenv("COOKIE_NAME", "env_cookie_name")
	os.Setenv("PROVIDERS_GOOGLE_CLIENT_ID", "env_client_id")
	os.Setenv("COOKIE_DOMAIN", "test1.com,example.org")
	os.Setenv("DOMAIN", "test2.com,example.org")
	os.Setenv("WHITELIST", "test3.com,example.org")

	c, err := NewConfig([]string{})
	assert.Nil(err)

	assert.Equal("env_cookie_name", c.CookieName, "variable should be read from environment")
	assert.Equal("env_client_id", c.Providers.Google.ClientID, "namespace variable should be read from environment")
	assert.Equal([]CookieDomain{
		*NewCookieDomain("test1.com"),
		*NewCookieDomain("example.org"),
	}, c.CookieDomains, "array variable should be read from environment COOKIE_DOMAIN")
	assert.Equal(CommaSeparatedList{"test2.com", "example.org"}, c.Domains, "array variable should be read from environment DOMAIN")
	assert.Equal(CommaSeparatedList{"test3.com", "example.org"}, c.Whitelist, "array variable should be read from environment WHITELIST")

	os.Unsetenv("COOKIE_NAME")
	os.Unsetenv("PROVIDERS_GOOGLE_CLIENT_ID")
	os.Unsetenv("COOKIE_DOMAIN")
	os.Unsetenv("DOMAIN")
	os.Unsetenv("WHITELIST")
}

func TestConfigParseEnvironmentBackwardsCompatability(t *testing.T) {
	assert := assert.New(t)
	vars := map[string]string{
		"CLIENT_ID":      "clientid",
		"CLIENT_SECRET":  "verysecret",
		"PROMPT":         "prompt",
		"COOKIE_SECRET":  "veryverysecret",
		"LIFETIME":       "200",
		"COOKIE_SECURE":  "false",
		"COOKIE_DOMAINS": "test1.com,example.org",
		"COOKIE_DOMAIN":  "another1.net",
		"DOMAIN":         "test2.com,example.org",
		"WHITELIST":      "test3.com,example.org",
	}
	for k, v := range vars {
		os.Setenv(k, v)
	}
	c, err := NewConfig([]string{})
	require.Nil(t, err)

	// The following used to be passed as comma separated list
	expected1 := []CookieDomain{
		*NewCookieDomain("another1.net"),
		*NewCookieDomain("test1.com"),
		*NewCookieDomain("example.org"),
	}
	assert.Equal(expected1, c.CookieDomains, "should read legacy comma separated list cookie-domains")

	expected2 := CommaSeparatedList{"test2.com", "example.org"}
	assert.Equal(expected2, c.Domains, "should read legacy comma separated list domains")

	expected3 := CommaSeparatedList{"test3.com", "example.org"}
	assert.Equal(expected3, c.Whitelist, "should read legacy comma separated list whitelist")

	// Name changed
	assert.Equal([]byte("veryverysecret"), c.Secret)

	// Google provider params used to be top level
	assert.Equal("clientid", c.ClientIdLegacy)
	assert.Equal("clientid", c.Providers.Google.ClientID, "--client-id should set providers.google.client-id")
	assert.Equal("verysecret", c.ClientSecretLegacy)
	assert.Equal("verysecret", c.Providers.Google.ClientSecret, "--client-secret should set providers.google.client-secret")
	assert.Equal("prompt", c.PromptLegacy)
	assert.Equal("prompt", c.Providers.Google.Prompt, "--prompt should set providers.google.promot")

	// "cookie-secure" used to be a standard go bool flag that could take
	// true, TRUE, 1, false, FALSE, 0 etc. values.
	// Here we're checking that format is still supported
	assert.Equal("false", c.CookieSecureLegacy)
	assert.True(c.InsecureCookie, "--cookie-secure=false should set insecure-cookie true")

	c, err = NewConfig([]string{"--cookie-secure=TRUE"})
	assert.Nil(err)
	assert.Equal("TRUE", c.CookieSecureLegacy)
	assert.False(c.InsecureCookie, "--cookie-secure=TRUE should set insecure-cookie false")

	for k := range vars {
		os.Unsetenv(k)
	}
}

func TestConfigTransformation(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{
		"--url-path=_oauthpath",
		"--secret=verysecret",
		"--lifetime=200",
	})
	require.Nil(t, err)

	assert.Equal("/_oauthpath", c.Path, "path should add slash to front")

	assert.Equal("verysecret", c.SecretString)
	assert.Equal([]byte("verysecret"), c.Secret, "secret should be converted to byte array")

	assert.Equal(200, c.LifetimeString)
	assert.Equal(time.Second*time.Duration(200), c.Lifetime, "lifetime should be read and converted to duration")
}

func TestConfigValidate(t *testing.T) {
	assert := assert.New(t)

	// Install new logger + hook
	var hook *test.Hook
	log, hook = test.NewNullLogger()
	log.ExitFunc = func(code int) {}

	// Validate defualt config + rule error
	c, _ := NewConfig([]string{
		"--rule.1.action=bad",
	})
	c.Validate()

	logs := hook.AllEntries()
	assert.Len(logs, 3)

	// Should have fatal error requiring secret
	assert.Equal("\"secret\" option must be set", logs[0].Message)
	assert.Equal(logrus.FatalLevel, logs[0].Level)

	// Should also have default provider (google) error
	assert.Equal("providers.google.client-id, providers.google.client-secret must be set", logs[1].Message)
	assert.Equal(logrus.FatalLevel, logs[1].Level)

	// Should validate rule
	assert.Equal("invalid rule action, must be \"auth\" or \"allow\"", logs[2].Message)
	assert.Equal(logrus.FatalLevel, logs[2].Level)

	hook.Reset()

	// Validate with invalid providers
	c, _ = NewConfig([]string{
		"--secret=veryverysecret",
		"--providers.google.client-id=id",
		"--providers.google.client-secret=secret",
		"--rule.1.action=auth",
		"--rule.1.provider=bad2",
	})
	c.Validate()

	logs = hook.AllEntries()
	assert.Len(logs, 1)

	// Should have error for rule provider
	assert.Equal("Unknown provider: bad2", logs[0].Message)
	assert.Equal(logrus.FatalLevel, logs[0].Level)
}

func TestConfigGetProvider(t *testing.T) {
	assert := assert.New(t)
	c, _ := NewConfig([]string{})

	// Should be able to get "google" provider
	p, err := c.GetProvider("google")
	assert.Nil(err)
	assert.Equal(&c.Providers.Google, p)

	// Should be able to get "oidc" provider
	p, err = c.GetProvider("oidc")
	assert.Nil(err)
	assert.Equal(&c.Providers.OIDC, p)

	// Should be able to get "generic-oauth" provider
	p, err = c.GetProvider("generic-oauth")
	assert.Nil(err)
	assert.Equal(&c.Providers.GenericOAuth, p)

	// Should catch unknown provider
	p, err = c.GetProvider("bad")
	if assert.Error(err) {
		assert.Equal("Unknown provider: bad", err.Error())
	}
}

func TestConfigGetConfiguredProvider(t *testing.T) {
	assert := assert.New(t)
	c, _ := NewConfig([]string{})

	// Should be able to get "google" default provider
	p, err := c.GetConfiguredProvider("google")
	assert.Nil(err)
	assert.Equal(&c.Providers.Google, p)

	// Should fail to get valid "oidc" provider as it's not configured
	p, err = c.GetConfiguredProvider("oidc")
	if assert.Error(err) {
		assert.Equal("Unconfigured provider: oidc", err.Error())
	}
}

func TestConfigCommaSeparatedList(t *testing.T) {
	assert := assert.New(t)
	list := CommaSeparatedList{}

	err := list.UnmarshalFlag("one,two")
	assert.Nil(err)
	assert.Equal(CommaSeparatedList{"one", "two"}, list, "should parse comma sepearated list")

	marshal, err := list.MarshalFlag()
	assert.Nil(err)
	assert.Equal("one,two", marshal, "should marshal back to comma sepearated list")
}
