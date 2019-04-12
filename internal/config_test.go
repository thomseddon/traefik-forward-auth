package tfa

import (
	"testing"
	"time"
	// "github.com/jessevdk/go-flags"
	// "github.com/sirupsen/logrus"
)

/**
 * Tests
 */

func TestConfigDefaults(t *testing.T) {
	// Check defaults
	c := NewGlobalConfigWithArgs([]string{})

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

	// Deprecated options
	if c.CookieSecure != "true" {
		t.Error("CookieSecure default should be true, got", c.CookieSecure)
	}
}

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
