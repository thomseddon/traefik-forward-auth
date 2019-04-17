package tfa

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/thomseddon/traefik-forward-auth/internal/provider"
)

var config Config

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
	Rules     map[string]*Rule `long:"rule"`

	Secret   []byte
	Lifetime time.Duration

	Prompt string `long:"prompt" description:"DEPRECATED - Use providers.google.prompt"`
	// TODO: Need to mimick the default behaviour of bool flags
	CookieSecure string `long:"cookie-secure" default:"true" description:"DEPRECATED - Use \"cookie-insecure\""`

	flags     []string
	usingToml bool
}

// TODO:
// - parse ini
// - parse env vars
// - parse env var file
// - support multiple config files
// - maintain backwards compat

func NewGlobalConfig() Config {
	var err error
	config, err = NewConfig(os.Args[1:])
	if err != nil {
		fmt.Printf("startup error: %+v", err)
		os.Exit(1)
	}

	return config
}

func NewConfig(args []string) (Config, error) {
	c := Config{
		Rules: map[string]*Rule{},
	}

	err := c.parseFlags(args)
	if err != nil {
		return c, err
	}

	// Struct defaults
	c.Providers.Google.Build()

	// Transformations
	c.Path = fmt.Sprintf("/%s", c.Path)
	c.Secret = []byte(c.SecretString)
	c.Lifetime = time.Second * time.Duration(c.LifetimeString)

	// TODO: Backwards compatability
	// "secret" used to be "cookie-secret"

	return c, nil
}

func (c *Config) parseFlags(args []string) error {
	parser := flags.NewParser(c, flags.Default)
	parser.UnknownOptionHandler = c.parseUnknownFlag

	_, err := parser.ParseArgs(args)
	if err != nil {
		flagsErr, ok := err.(*flags.Error)
		if ok && flagsErr.Type == flags.ErrHelp {
			// Library has just printed cli help
			os.Exit(0)
		} else {
			return err
		}
	}

	return nil
}

func (c *Config) parseUnknownFlag(option string, arg flags.SplitArgument, args []string) ([]string, error) {
	// Parse rules in the format "rule.<name>.<param>"
	parts := strings.Split(option, ".")
	if len(parts) == 3 && parts[0] == "rule" {
		// Get or create rule
		rule, ok := c.Rules[parts[1]]
		if !ok {
			rule = NewRule()
			c.Rules[parts[1]] = rule
		}

		// Get value, or pop the next arg
		val, ok := arg.Value()
		if !ok {
			val = args[0]
			args = args[1:]
		}

		// Check value
		if len(val) == 0 {
			return args, errors.New("route param value is required")
		}

		// Unquote if required
		if val[0] == '"' {
			var err error
			val, err = strconv.Unquote(val)
			if err != nil {
				return args, err
			}
		}

		// Add param value to rule
		switch(parts[2]) {
		case "action":
			rule.Action = val
		case "rule":
			rule.Rule = val
		case "provider":
			rule.Provider = val
		default:
			return args, fmt.Errorf("inavlid route param: %v", option)
		}
	} else {
		return args, fmt.Errorf("unknown flag: %v", option)
	}

	return args, nil
}

func (c *Config) Validate() {
	// Check for show stopper errors
	if len(c.Secret) == 0 {
		log.Fatal("\"secret\" option must be set.")
	}

	if c.Providers.Google.ClientId == "" || c.Providers.Google.ClientSecret == "" {
		log.Fatal("google.providers.client-id, google.providers.client-secret must be set")
	}

	// Check rules
	for _, rule := range c.Rules {
		rule.Validate()
	}
}

func (c Config) String() string {
	jsonConf, _ := json.Marshal(c)
	return string(jsonConf)
}

type Rule struct {
	Action   string
	Rule     string
	Provider string
}

func NewRule() *Rule {
	return &Rule{
		Action: "auth",
		Provider: "google", // TODO: Use default provider
	}
}

func (r *Rule) Validate() {
	if r.Action != "auth" && r.Action != "allow" {
		log.Fatal("invalid rule action, must be \"auth\" or \"allow\"")
	}

	// TODO: Update with more provider support
	if r.Provider != "google" {
		log.Fatal("invalid rule provider, must be \"google\"")
	}
}

func (r *Rule) UnmarshalFlag(value string) error {
	// Format is "action:rule"
	parts := strings.SplitN(value, ":", 2)

	if len(parts) != 2 {
		return errors.New("invalid rule format, should be \"action:rule\"")
	}

	if parts[0] != "auth" && parts[0] != "allow" {
		return errors.New("invalid rule action, must be \"auth\" or \"allow\"")
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

type CommaSeparatedList []string

func (c *CommaSeparatedList) UnmarshalFlag(value string) error {
	*c = strings.Split(value, ",")
	return nil
}

func (c *CommaSeparatedList) MarshalFlag() (string, error) {
	return strings.Join(*c, ","), nil
}
