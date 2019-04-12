package tfa

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/thomseddon/traefik-forward-auth/internal/provider"
)

type Config struct {
	LogLevel  string `long:"log-level" default:"warn" description:"Log level: trace, debug, info, warn, error, fatal, panic"`
	LogFormat string `long:"log-format" default:"text" description:"Log format: text, json, pretty"`

	AuthHost       string             `long:"auth-host" description:"Host for central auth login"`
	ConfigFile     string             `long:"config-file" description:"Config File"`
	CookieDomains  CookieDomains      `long:"cookie-domains" description:"Comma separated list of cookie domains"`
	CookieInsecure bool               `long:"cookie-insecure" description:"Use secure cookies"`
	CookieName     string             `long:"cookie-name" default:"_forward_auth" description:"Cookie Name"`
	CSRFCookieName string             `long:"csrf-cookie-name" default:"_forward_auth_csrf" description:"CSRF Cookie Name"`
	DefaultAction  string             `long:"default-action" default:"allow" description:"Default Action"`
	Domains        CommaSeparatedList `long:"domains" description:"Comma separated list of email domains to allow"`
	LifetimeString int                `long:"lifetime" default:"43200" description:"Lifetime in seconds"`
	Path           string             `long:"path" default:"_oauth" description:"Callback URL Path"`
	SecretString   string             `long:"secret" description:"*Secret used for signing (required)"`
	Whitelist      CommaSeparatedList `long:"whitelist" description:"Comma separated list of email addresses to allow"`

	Providers provider.Providers
	Rules     []Rule `long:"rule"`

	Secret   []byte
	Lifetime time.Duration

	Prompt string `long:"prompt" description:"DEPRECATED - Use providers.google.prompt"`
	// TODO: Need to mimick the default behaviour of bool flags
	CookieSecure string `long:"cookie-secure" default:"true" description:"DEPRECATED - Use \"cookie-insecure\""`

	flags     []string
	usingToml bool
}

type CommaSeparatedList []string

func (c *CommaSeparatedList) UnmarshalFlag(value string) error {
	*c = strings.Split(value, ",")
	return nil
}

func (c *CommaSeparatedList) MarshalFlag() (string, error) {
	return strings.Join(*c, ","), nil
}

type Rule struct {
	Action string
	Rule   string
}

func (r *Rule) UnmarshalFlag(value string) error {
	// Format is "action:rule"
	parts := strings.SplitN(value, ":", 2)

	if len(parts) != 2 {
		return errors.New("Invalid rule format, should be \"action:rule\"")
	}

	if parts[0] != "auth" && parts[0] != "allow" {
		return errors.New("Invalid rule action, must be \"auth\" or \"allow\"")
	}

	// Parse rule
	*r = Rule{
		Action: parts[0],
		Rule:   parts[1],
	}

	return nil
}

func (r *Rule) MarshalFlag() (string, error) {
	// TODO: format correctly
	return fmt.Sprintf("%+v", *r), nil
}

var config Config

// TODO:
// - parse ini
// - parse env vars
// - parse env var file
// - support multiple config files
// - maintain backwards compat

func NewGlobalConfig() Config {
	return NewGlobalConfigWithArgs(os.Args[1:])
}

func NewGlobalConfigWithArgs(args []string) Config {
	config = Config{}

	config.parseFlags(args)

	// Struct defaults
	config.Providers.Google.Build()

	// Transformations
	config.Path = fmt.Sprintf("/%s", config.Path)
	config.Secret = []byte(config.SecretString)
	config.Lifetime = time.Second * time.Duration(config.LifetimeString)

	// TODO: Backwards compatability
	// "secret" used to be "cookie-secret"

	return config
}

func (c *Config) parseFlags(args []string) {
	if _, err := flags.ParseArgs(c, args); err != nil {
		flagsErr, ok := err.(*flags.Error)
		if ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			fmt.Printf("%+v", err)
			os.Exit(1)
		}
	}
}

func (c *Config) Checks() {
	// Check for show stopper errors
	if len(c.Secret) == 0 {
		log.Fatal("\"secret\" option must be set.")
	}

	if c.Providers.Google.ClientId == "" || c.Providers.Google.ClientSecret == "" {
		log.Fatal("google.providers.client-id, google.providers.client-secret must be set")
	}
}

func (c Config) Serialise() string {
	jsonConf, _ := json.Marshal(c)
	return string(jsonConf)
}
