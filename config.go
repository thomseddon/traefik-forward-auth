package main

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/namsral/flag"
	"github.com/thomseddon/traefik-forward-auth/provider"
)

type Config struct {
	DefaultAction string
	Path          string
	Lifetime      time.Duration
	Secret        string
	SecretBytes   []byte
	AuthHost      string

	LogLevel   *string
	LogFormat  *string
	TomlConfig *string // temp

	CookieName     string
	CookieDomains  []CookieDomain
	CSRFCookieName string
	CookieSecure   bool

	Domain    []string
	Whitelist []string

	Providers provider.Providers
	Rules     map[string]Rules
}

type Rules struct {
	Action string
	Match  []Match
}

type Match struct {
	Host       []string
	PathPrefix []string
	Header     [][]string
}

func NewConfig() *Config {
	c := &Config{}
	c.parseFlags()
	c.applyDefaults()
	return c
}

// TODO: Fix
// At the moment any flag value will overwrite the toml config
// Need to put the flag default values in applyDefaults & empty the flag
// defaults so we can check if they're being passed and set accordingly
// Ideally we also need to remove the two calls to parseFlags
//
// We also need to check the default -config flag for toml suffix and
// parse that as needed
//
// Ideally we'd also support multiple config files

func NewParsedConfig() *Config {
	c := &Config{}

	// Temp
	c.parseFlags()

	// Parse toml
	if *c.TomlConfig != "" {
		if _, err := toml.DecodeFile(*c.TomlConfig, &c); err != nil {
			panic(err)
		}
	}

	c.applyDefaults()

	// Conversions
	c.SecretBytes = []byte(c.Secret)

	return c
}

func (c *Config) Checks() {
	// Check for show stopper errors
	if c.Providers.Google.ClientId == "" || c.Providers.Google.ClientSecret == "" || len(c.Secret) == 0 {
		log.Fatal("client-id, client-secret and secret must all be set")
	}
}

func (c *Config) applyDefaults() {
	// Providers
	// Google
	if c.Providers.Google.Scope == "" {
		c.Providers.Google.Scope = "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email"
	}
	if c.Providers.Google.LoginURL == nil {
		c.Providers.Google.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "accounts.google.com",
			Path:   "/o/oauth2/auth",
		}
	}
	if c.Providers.Google.TokenURL == nil {
		c.Providers.Google.TokenURL = &url.URL{
			Scheme: "https",
			Host:   "www.googleapis.com",
			Path:   "/oauth2/v3/token",
		}
	}
	if c.Providers.Google.UserURL == nil {
		c.Providers.Google.UserURL = &url.URL{
			Scheme: "https",
			Host:   "www.googleapis.com",
			Path:   "/oauth2/v2/userinfo",
		}
	}
}

func (c *Config) parseFlags() {
	c.LogLevel = flag.String("log-level", "warn", "Log level: trace, debug, info, warn, error, fatal, panic")
	c.LogFormat = flag.String("log-format", "text", "Log format: text, json, pretty")
	c.TomlConfig = flag.String("toml-config", "", "TEMP")

	// Legacy?
	path := flag.String("url-path", "_oauth", "Callback URL")
	lifetime := flag.Int("lifetime", 43200, "Session length in seconds")
	secret := flag.String("secret", "", "*Secret used for signing (required)")
	authHost := flag.String("auth-host", "", "Central auth login")
	clientId := flag.String("client-id", "", "*Google Client ID (required)")
	clientSecret := flag.String("client-secret", "", "*Google Client Secret (required)")
	cookieName := flag.String("cookie-name", "_forward_auth", "Cookie Name")
	cSRFCookieName := flag.String("csrf-cookie-name", "_forward_auth_csrf", "CSRF Cookie Name")
	cookieDomainList := flag.String("cookie-domains", "", "Comma separated list of cookie domains") //todo
	cookieSecret := flag.String("cookie-secret", "", "Deprecated")
	cookieSecure := flag.Bool("cookie-secure", true, "Use secure cookies")
	domainList := flag.String("domain", "", "Comma separated list of email domains to allow")
	emailWhitelist := flag.String("whitelist", "", "Comma separated list of emails to allow")
	prompt := flag.String("prompt", "", "Space separated list of OpenID prompt options")

	flag.Parse()

	// Add to config
	c.Path = fmt.Sprintf("/%s", *path)
	c.Lifetime = time.Second * time.Duration(*lifetime)
	c.AuthHost = *authHost
	c.Providers.Google.ClientId = *clientId
	c.Providers.Google.ClientSecret = *clientSecret
	c.Providers.Google.Prompt = *prompt
	c.CookieName = *cookieName
	c.CSRFCookieName = *cSRFCookieName
	c.CookieSecure = *cookieSecure

	// Backwards compatibility
	if *secret == "" && *cookieSecret != "" {
		*secret = *cookieSecret
	}
	c.Secret = *secret

	// Parse lists
	if *cookieDomainList != "" {
		for _, d := range strings.Split(*cookieDomainList, ",") {
			cookieDomain := NewCookieDomain(d)
			c.CookieDomains = append(c.CookieDomains, *cookieDomain)
		}
	}

	if *domainList != "" {
		c.Domain = strings.Split(*domainList, ",")
	}

	if *emailWhitelist != "" {
		c.Whitelist = strings.Split(*emailWhitelist, ",")
	}
}

// Temp
func (c Config) Walk() {
	for name, rule := range c.Rules {
		fmt.Printf("Rule: %s\n", name)
		for _, match := range rule.Match {
			if len(match.Host) > 0 {
				for _, val := range match.Host {
					fmt.Printf(" - Host: %s\n", val)
				}
			}
			if len(match.PathPrefix) > 0 {
				for _, val := range match.PathPrefix {
					fmt.Printf(" - PathPrefix: %s\n", val)
				}
			}
			if len(match.Header) > 0 {
				for _, val := range match.Header {
					fmt.Printf(" - Header: %s: %s\n", val[0], val[1])
				}
			}
		}
	}
}
