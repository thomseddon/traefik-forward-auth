package tfa

import (
	"os"
	"testing"
	"time"

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
	assert.Len(c.Domains, 0)
	assert.Equal(time.Second*time.Duration(43200), c.Lifetime)
	assert.Equal("/_oauth", c.Path)
	assert.Len(c.Whitelist, 0)

	assert.Equal("", c.Providers.Google.Prompt)
}

func TestConfigParseArgs(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{
		"--cookie-name=cookiename",
		"--csrf-cookie-name", "\"csrfcookiename\"",
		"--rule.1.action=allow",
		"--rule.1.rule=PathPrefix(`/one`)",
		"--rule.two.action=auth",
		"--rule.two.rule=\"Host(`two.com`) && Path(`/two`)\"",
	})
	require.Nil(t, err)

	// Check normal flags
	assert.Equal("cookiename", c.CookieName)
	assert.Equal("csrfcookiename", c.CSRFCookieName)

	// Check rules
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

func TestConfigParseUnknownFlags(t *testing.T) {
	_, err := NewConfig([]string{
		"--unknown=_oauthpath2",
	})
	if assert.Error(t, err) {
		assert.Equal(t, "unknown flag: unknown", err.Error())
	}
}

func TestConfigFlagBackwardsCompatability(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{
		"--client-id=clientid",
		"--client-secret=verysecret",
		"--prompt=prompt",
		"--lifetime=200",
		"--cookie-secure=false",
		"--cookie-domains=test1.com,example.org",
		"--cookie-domain=another1.net",
		"--domains=test2.com,example.org",
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

	expected2 := []string{"another2.net", "test2.com", "example.org"}
	assert.Equal(expected2, c.Domains, "should read legacy comma separated list domains")

	expected3 := CommaSeparatedList{"test3.com", "example.org", "another3.net"}
	assert.Equal(expected3, c.Whitelist, "should read legacy comma separated list whitelist")

	// Google provider params used to be top level
	assert.Equal("clientid", c.ClientIdLegacy)
	assert.Equal("clientid", c.Providers.Google.ClientId, "--client-id should set providers.google.client-id")
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
}

func TestConfigFileBackwardsCompatability(t *testing.T) {
	assert := assert.New(t)
	c, err := NewConfig([]string{
		"--config=../test/config-legacy",
	})
	require.Nil(t, err)

	assert.Equal("/two", c.Path, "Variable in legacy config file should be read")
}

func TestConfigParseEnvironment(t *testing.T) {
	assert := assert.New(t)
	os.Setenv("COOKIE_NAME", "env_cookie_name")
	c, err := NewConfig([]string{})
	assert.Nil(err)

	assert.Equal("env_cookie_name", c.CookieName, "variable should be read from environment")
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
