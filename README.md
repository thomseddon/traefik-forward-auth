
# Traefik Forward Auth 
### Overview

The following configuration options are supported:

```
Usage:
  traefik-forward-auth [OPTIONS]

Application Options:
  --log-level=[trace|debug|info|warn|error|fatal|panic] Log level (default: warn) [$LOG_LEVEL]
  --log-format=[text|json|pretty]                       Log format (default: text) [$LOG_FORMAT]
  --auth-host=                                          Single host to use when returning from 3rd party auth [$AUTH_HOST]
  --config=                                             Path to config file [$CONFIG]
  --cookie-domain=                                      Domain to set auth cookie on, can be set multiple times [$COOKIE_DOMAIN]
  --insecure-cookie                                     Use insecure cookies [$INSECURE_COOKIE]
  --cookie-name=                                        Cookie Name (default: _forward_auth) [$COOKIE_NAME]
  --csrf-cookie-name=                                   CSRF Cookie Name (default: _forward_auth_csrf) [$CSRF_COOKIE_NAME]
  --default-action=[auth|allow]                         Default action (default: auth) [$DEFAULT_ACTION]
  --default-provider=[google|oidc]                      Default provider (default: google) [$DEFAULT_PROVIDER]
  --domain=                                             Only allow given email domains, can be set multiple times [$DOMAIN]
  --lifetime=                                           Lifetime in seconds (default: 43200) [$LIFETIME]
  --url-path=                                           Callback URL Path (default: /_oauth) [$URL_PATH]
  --secret=                                             Secret used for signing (required) [$SECRET]
  --whitelist=                                          Only allow given email addresses, can be set multiple times [$WHITELIST]
  --rule.<name>.<param>=                                Rule definitions, param can be: "action", "rule" or "provider"

OIDC Provider:
  --providers.oidc.issuer-url=                          Issuer URL [$PROVIDERS_OIDC_ISSUER_URL]
  --providers.oidc.client-id=                           Client ID [$PROVIDERS_OIDC_CLIENT_ID]
  --providers.oidc.client-secret=                       Client Secret [$PROVIDERS_OIDC_CLIENT_SECRET]

Help Options:
  -h, --help                                            Show this help message
```
