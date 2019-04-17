package tfa

import (
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
	if c.ConfigFile != "" {
		t.Error("ConfigFile default should be empty, got", c.ConfigFile)
	}
	if len(c.CookieDomains) != 0 {
		t.Error("CookieDomains default should be empty, got", c.CookieDomains)
	}
	if c.CookieInsecure != false {
		t.Error("CookieInsecure default should be false, got", c.CookieInsecure)
	}
	if c.CookieName != "_forward_auth" {
		t.Error("CookieName default should be _forward_auth, got", c.CookieName)
	}
	if c.CSRFCookieName != "_forward_auth_csrf" {
		t.Error("CSRFCookieName default should be _forward_auth_csrf, got", c.CSRFCookieName)
	}
	if c.DefaultAction != "allow" {
		t.Error("DefaultAction default should be allow, got", c.DefaultAction)
	}
	if len(c.Domains) != 0 {
		t.Error("Domain default should be empty, got", c.Domains)
	}
	if c.Lifetime != time.Second * time.Duration(43200) {
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

	// Deprecated options
	if c.CookieSecure != "true" {
		t.Error("CookieSecure default should be true, got", c.CookieSecure)
	}
}

func TestConfigParseFlags(t *testing.T) {
	c, err := NewConfig([]string{
		"--path=_oauthpath",
		"--cookie-name", "\"cookiename\"",
		"--rule.1.action=allow",
		"--rule.1.rule=PathPrefix(`/one`)",
		"--rule.two.action=auth",
		"--rule.two.rule=\"Host(`two.com`) && Path(`/two`)\"",
	})
	if err != nil {
		t.Error(err)
	}

	// Check normal flags
	if c.Path != "/_oauthpath" {
		t.Error("Path default should be /_oauthpath, got", c.Path)
	}
	if c.CookieName != "cookiename" {
		t.Error("CookieName default should be cookiename, got", c.CookieName)
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

// func TestConfigParseUnknownFlags(t *testing.T) {
// 	c := NewConfig([]string{
// 		"--unknown=_oauthpath",
// 	})

// }

// func TestConfigToml(t *testing.T) {
//   logrus.SetLevel(logrus.DebugLevel)
//   flag.CommandLine = flag.NewFlagSet("tfa-test", flag.ContinueOnError)

//   flags := []string{
//     "-config=../test/config.toml",
//   }
//   c := NewDefaultConfigWithFlags(flags)

//   if c == nil {
//     t.Error(c)
//   }
// }
