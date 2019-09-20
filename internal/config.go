package tfa

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/thomseddon/go-flags"
	"github.com/thomseddon/traefik-forward-auth/internal/provider"
)

var config Config

type Config struct {
	LogLevel  string `long:"log-level" env:"LOG_LEVEL" default:"warn" choice:"trace" choice:"debug" choice:"info" choice:"warn" choice:"error" choice:"fatal" choice:"panic" description:"Log level"`
	LogFormat string `long:"log-format"  env:"LOG_FORMAT" default:"text" choice:"text" choice:"json" choice:"pretty" description:"Log format"`

	AuthHost       string               `long:"auth-host" env:"AUTH_HOST" description:"Single host to use when returning from 3rd party auth"`
	Config         func(s string) error `long:"config" env:"CONFIG" description:"Path to config file" json:"-"`
	CookieDomains  []CookieDomain       `long:"cookie-domain" env:"COOKIE_DOMAIN" description:"Domain to set auth cookie on, can be set multiple times"`
	InsecureCookie bool                 `long:"insecure-cookie" env:"INSECURE_COOKIE" description:"Use insecure cookies"`
	CookieName     string               `long:"cookie-name" env:"COOKIE_NAME" default:"_forward_auth" description:"Cookie Name"`
	CSRFCookieName string               `long:"csrf-cookie-name" env:"CSRF_COOKIE_NAME" default:"_forward_auth_csrf" description:"CSRF Cookie Name"`
	DefaultAction  string               `long:"default-action" env:"DEFAULT_ACTION" default:"auth" choice:"auth" choice:"allow" description:"Default action"`
	Domains        CommaSeparatedList   `long:"domain" env:"DOMAIN" description:"Only allow given email domains, can be set multiple times"`
	LifetimeString int                  `long:"lifetime" env:"LIFETIME" default:"43200" description:"Lifetime in seconds"`
	Path           string               `long:"url-path" env:"URL_PATH" default:"/_oauth" description:"Callback URL Path"`
	SecretString   string               `long:"secret" env:"SECRET" description:"Secret used for signing (required)" json:"-"`
	Whitelist      CommaSeparatedList   `long:"whitelist" env:"WHITELIST" description:"Only allow given email addresses, can be set multiple times"`

	Providers provider.Providers `group:"providers" namespace:"providers" env-namespace:"PROVIDERS"`
	Rules     map[string]*Rule   `long:"rule.<name>.<param>" description:"Rule definitions, param can be: \"action\" or \"rule\""`

	// Filled during transformations
	Secret   []byte `json:"-"`
	Lifetime time.Duration

	// Legacy
	CookieDomainsLegacy CookieDomains `long:"cookie-domains" env:"COOKIE_DOMAINS" description:"DEPRECATED - Use \"cookie-domain\""`
	CookieSecretLegacy  string        `long:"cookie-secret" env:"COOKIE_SECRET" description:"DEPRECATED - Use \"secret\""  json:"-"`
	CookieSecureLegacy  string        `long:"cookie-secure" env:"COOKIE_SECURE" description:"DEPRECATED - Use \"insecure-cookie\""`
	ClientIdLegacy      string        `long:"client-id" env:"CLIENT_ID" group:"DEPs" description:"DEPRECATED - Use \"providers.google.client-id\""`
	ClientSecretLegacy  string        `long:"client-secret" env:"CLIENT_SECRET" description:"DEPRECATED - Use \"providers.google.client-id\""  json:"-"`
	PromptLegacy        string        `long:"prompt" env:"PROMPT" description:"DEPRECATED - Use \"providers.google.prompt\""`
}

func NewGlobalConfig() Config {
	var err error
	config, err = NewConfig(os.Args[1:])
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}

	return config
}

func NewConfig(args []string) (Config, error) {
	c := Config{
		Rules: map[string]*Rule{},
		Providers: provider.Providers{
			Google: provider.Google{
				Scope: "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email",
				LoginURL: &url.URL{
					Scheme: "https",
					Host:   "accounts.google.com",
					Path:   "/o/oauth2/auth",
				},
				TokenURL: &url.URL{
					Scheme: "https",
					Host:   "www.googleapis.com",
					Path:   "/oauth2/v3/token",
				},
				UserURL: &url.URL{
					Scheme: "https",
					Host:   "www.googleapis.com",
					Path:   "/oauth2/v2/userinfo",
				},
			},
		},
	}

	err := c.parseFlags(args)
	if err != nil {
		return c, err
	}

	// TODO: as log flags have now been parsed maybe we should return here so
	// any further errors can be logged via logrus instead of printed?

	// Backwards compatability
	if c.CookieSecretLegacy != "" && c.SecretString == "" {
		fmt.Println("cookie-secret config option is deprecated, please use secret")
		c.SecretString = c.CookieSecretLegacy
	}
	if c.ClientIdLegacy != "" {
		c.Providers.Google.ClientId = c.ClientIdLegacy
	}
	if c.ClientSecretLegacy != "" {
		c.Providers.Google.ClientSecret = c.ClientSecretLegacy
	}
	if c.PromptLegacy != "" {
		fmt.Println("prompt config option is deprecated, please use providers.google.prompt")
		c.Providers.Google.Prompt = c.PromptLegacy
	}
	if c.CookieSecureLegacy != "" {
		fmt.Println("cookie-secure config option is deprecated, please use insecure-cookie")
		secure, err := strconv.ParseBool(c.CookieSecureLegacy)
		if err != nil {
			return c, err
		}
		c.InsecureCookie = !secure
	}
	if len(c.CookieDomainsLegacy) > 0 {
		fmt.Println("cookie-domains config option is deprecated, please use cookie-domain")
		c.CookieDomains = append(c.CookieDomains, c.CookieDomainsLegacy...)
	}

	// Transformations
	if len(c.Path) > 0 && c.Path[0] != '/' {
		c.Path = "/" + c.Path
	}
	c.Secret = []byte(c.SecretString)
	c.Lifetime = time.Second * time.Duration(c.LifetimeString)

	return c, nil
}

func (c *Config) parseFlags(args []string) error {
	p := flags.NewParser(c, flags.Default|flags.IniUnknownOptionHandler)
	p.UnknownOptionHandler = c.parseUnknownFlag

	i := flags.NewIniParser(p)
	c.Config = func(s string) error {
		// Try parsing at as an ini
		err := i.ParseFile(s)

		// If it fails with a syntax error, try converting legacy to ini
		if err != nil && strings.Contains(err.Error(), "malformed key=value") {
			converted, convertErr := convertLegacyToIni(s)
			if convertErr != nil {
				// If conversion fails, return the original error
				return err
			}

			fmt.Println("config format deprecated, please use ini format")
			return i.Parse(converted)
		}

		return err
	}

	_, err := p.ParseArgs(args)
	if err != nil {
		return handlFlagError(err)
	}

	return nil
}

func (c *Config) parseUnknownFlag(option string, arg flags.SplitArgument, args []string) ([]string, error) {
	// Parse rules in the format "rule.<name>.<param>"
	parts := strings.Split(option, ".")
	if len(parts) == 3 && parts[0] == "rule" {
		// Ensure there is a name
		name := parts[1]
		if len(name) == 0 {
			return args, errors.New("route name is required")
		}

		// Get value, or pop the next arg
		val, ok := arg.Value()
		if !ok && len(args) > 1 {
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

		// Get or create rule
		rule, ok := c.Rules[name]
		if !ok {
			rule = NewRule()
			c.Rules[name] = rule
		}

		// Add param value to rule
		switch parts[2] {
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

func handlFlagError(err error) error {
	flagsErr, ok := err.(*flags.Error)
	if ok && flagsErr.Type == flags.ErrHelp {
		// Library has just printed cli help
		os.Exit(0)
	}

	return err
}

var legacyFileFormat = regexp.MustCompile(`(?m)^([a-z-]+) (.*)$`)

func convertLegacyToIni(name string) (io.Reader, error) {
	b, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(legacyFileFormat.ReplaceAll(b, []byte("$1=$2"))), nil
}

func (c *Config) Validate() {
	// Check for show stopper errors
	if len(c.Secret) == 0 {
		log.Fatal("\"secret\" option must be set.")
	}

	if c.Providers.Google.ClientId == "" || c.Providers.Google.ClientSecret == "" {
		log.Fatal("providers.google.client-id, providers.google.client-secret must be set")
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
		Action:   "auth",
		Provider: "google", // TODO: Use default provider
	}
}

func (r *Rule) formattedRule() string {
	// Traefik implements their own "Host" matcher and then offers "HostRegexp"
	// to invoke the mux "Host" matcher. This ensures the mux version is used
	return strings.ReplaceAll(r.Rule, "Host(", "HostRegexp(")
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

// Legacy support for comma separated lists

type CommaSeparatedList []string

func (c *CommaSeparatedList) UnmarshalFlag(value string) error {
	*c = append(*c, strings.Split(value, ",")...)
	return nil
}

func (c *CommaSeparatedList) MarshalFlag() (string, error) {
	return strings.Join(*c, ","), nil
}
