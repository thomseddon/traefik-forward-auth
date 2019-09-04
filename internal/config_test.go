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
			Action: "allow",
			Rule:   "PathPrefix(`/one`)",
		},
		"two": {
			Action: "auth",
			Rule:   "Host(`two.com`) && Path(`/two`)",
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
			Action: "allow",
			Rule:   "PathPrefix(`/one`)",
		},
		"two": {
			Action: "auth",
			Rule:   "Host(`two.com`) && Path(`/two`)",
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
	c, err := NewConfig([]string{})
	assert.Nil(err)

	assert.Equal("env_cookie_name", c.CookieName, "variable should be read from environment")

	os.Unsetenv("COOKIE_NAME")
	os.Unsetenv("PROVIDERS_GOOGLE_CLIENT_ID")
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
