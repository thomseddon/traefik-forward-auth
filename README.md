
# Traefik Forward Auth ![Build Status](https://img.shields.io/github/workflow/status/thomseddon/traefik-forward-auth/CI) [![Go Report Card](https://goreportcard.com/badge/github.com/thomseddon/traefik-forward-auth)](https://goreportcard.com/report/github.com/thomseddon/traefik-forward-auth) ![Docker Pulls](https://img.shields.io/docker/pulls/thomseddon/traefik-forward-auth.svg) [![GitHub release](https://img.shields.io/github/release/thomseddon/traefik-forward-auth.svg)](https://GitHub.com/thomseddon/traefik-forward-auth/releases/)


A minimal forward authentication service that provides OAuth/SSO login and authentication for the [traefik](https://github.com/containous/traefik) reverse proxy/load balancer.

## Why?

- Seamlessly overlays any http service with a single endpoint (see: `url-path` in [Configuration](#configuration))
- Supports multiple providers including Google and OpenID Connect (supported by Azure, Github, Salesforce etc.)
- Supports multiple domains/subdomains by dynamically generating redirect_uri's
- Allows authentication to be selectively applied/bypassed based on request parameters (see `rules` in [Configuration](#configuration))
- Supports use of centralised authentication host/redirect_uri (see `auth-host` in [Configuration](#configuration))
- Allows authentication to persist across multiple domains (see [Cookie Domains](#cookie-domains))
- Supports extended authentication beyond Google token lifetime (see: `lifetime` in [Configuration](#configuration))

# Contents

- [Releases](#releases)
- [Usage](#usage)
  - [Simple](#simple)
  - [Advanced](#advanced)
  - [Provider Setup](#provider-setup)
- [Configuration](#configuration)
  - [Overview](#overview)
  - [Option Details](#option-details)
- [Concepts](#concepts)
  - [Forwarded Headers](#forwarded-headers)
  - [User Restriction](#user-restriction)
  - [Applying Authentication](#applying-authentication)
    - [Global Authentication](#global-authentication)
    - [Selective Ingress Authentication in Kubernetes](#selective-ingress-authentication-in-kubernetes)
    - [Selective Container Authentication in Swarm](#selective-container-authentication-in-swarm)
    - [Rules Based Authentication](#rules-based-authentication)
  - [Operation Modes](#operation-modes)
    - [Overlay Mode](#overlay-mode)
    - [Auth Host Mode](#auth-host-mode)
  - [Logging Out](#logging-out)
- [Copyright](#copyright)
- [License](#license)

## Releases

We recommend using the `2` tag on docker hub (`thomseddon/traefik-forward-auth:2`).

You can also use the latest incremental releases found on [docker hub](https://hub.docker.com/r/thomseddon/traefik-forward-auth/tags) and [github](https://github.com/thomseddon/traefik-forward-auth/releases).

ARM releases are also available on docker hub, just append `-arm` or `-arm64` to your desired released (e.g. `2-arm` or `2.1-arm64`).

We also build binary files for usage without docker starting with releases after 2.2.0 You can find these as assets of the specific GitHub release.

#### Upgrade Guide

v2 was released in June 2019, whilst this is fully backwards compatible, a number of configuration options were modified, please see the [upgrade guide](https://github.com/thomseddon/traefik-forward-auth/wiki/v2-Upgrade-Guide) to prevent warnings on startup and ensure you are using the current configuration.

## Usage

#### Simple:

See below for instructions on how to setup your [Provider Setup](#provider-setup).

docker-compose.yml:

```yaml
version: '3'

services:
  traefik:
    image: traefik:v2.2
    command: --providers.docker
    ports:
      - "8085:80"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  traefik-forward-auth:
    image: thomseddon/traefik-forward-auth:2
    environment:
      - PROVIDERS_GOOGLE_CLIENT_ID=your-client-id
      - PROVIDERS_GOOGLE_CLIENT_SECRET=your-client-secret
      - SECRET=something-random
      - INSECURE_COOKIE=true # Example assumes no https, do not use in production
    labels:
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.address=http://traefik-forward-auth:4181"
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.authResponseHeaders=X-Forwarded-User"
      - "traefik.http.services.traefik-forward-auth.loadbalancer.server.port=4181"

  whoami:
    image: containous/whoami
    labels:
      - "traefik.http.routers.whoami.rule=Host(`whoami.mycompany.com`)"
      - "traefik.http.routers.whoami.middlewares=traefik-forward-auth"
```

#### Advanced:

Please see the examples directory for a more complete [docker-compose.yml](https://github.com/thomseddon/traefik-forward-auth/blob/master/examples/traefik-v2/swarm/docker-compose.yml) or [kubernetes/simple-separate-pod](https://github.com/thomseddon/traefik-forward-auth/blob/master/examples/traefik-v2/kubernetes/simple-separate-pod/).

Also in the examples directory is [docker-compose-auth-host.yml](https://github.com/thomseddon/traefik-forward-auth/blob/master/examples/traefik-v2/swarm/docker-compose-auth-host.yml) and [kubernetes/advanced-separate-pod](https://github.com/thomseddon/traefik-forward-auth/blob/master/examples/traefik-v2/kubernetes/advanced-separate-pod/) which shows how to configure a central auth host, along with some other options.

#### Provider Setup

Below are some general notes on provider setup, specific instructions and examples for a number of providers can be found on the [Provider Setup](https://github.com/thomseddon/traefik-forward-auth/wiki/Provider-Setup) wiki page.

##### Google

Head to https://console.developers.google.com and make sure you've switched to the correct email account.

Create a new project then search for and select "Credentials" in the search bar. Fill out the "OAuth Consent Screen" tab.

Click "Create Credentials" > "OAuth client ID". Select "Web Application", fill in the name of your app, skip "Authorized JavaScript origins" and fill "Authorized redirect URIs" with all the domains you will allow authentication from, appended with the `url-path` (e.g. https://app.test.com/_oauth)

You must set the `providers.google.client-id` and `providers.google.client-secret` config options.

##### OpenID Connect

Any provider that supports OpenID Connect 1.0 can be configured via the OIDC config options below.

You must set the `providers.oidc.issuer-url`, `providers.oidc.client-id` and `providers.oidc.client-secret` config options.

Please see the [Provider Setup](https://github.com/thomseddon/traefik-forward-auth/wiki/Provider-Setup) wiki page for examples.

##### Generic OAuth2

For providers that don't support OpenID Connect, we also have the Generic OAuth2 provider where you can statically configure the OAuth2 and "user" endpoints.

You must set:
- `providers.generic-oauth.auth-url` - URL the client should be sent to authenticate the authenticate
- `providers.generic-oauth.token-url` - URL the service should call to exchange an auth code for an access token
- `providers.generic-oauth.user-url` - URL used to retrieve user info (service makes a GET request)
- `providers.generic-oauth.client-id` - Client ID
- `providers.generic-oauth.client-secret` - Client Secret

You can also set:
- `providers.generic-oauth.scope`- Any scopes that should be included in the request (default: profile, email)
- `providers.generic-oauth.token-style` - How token is presented when querying the User URL. Can be `header` or `query`, defaults to `header`. With `header` the token is provided in an Authorization header, with query the token is provided in the `access_token` query string value.

Please see the [Provider Setup](https://github.com/thomseddon/traefik-forward-auth/wiki/Provider-Setup) wiki page for examples.

## Configuration

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
  --default-provider=[google|oidc|generic-oauth]        Default provider (default: google) [$DEFAULT_PROVIDER]
  --domain=                                             Only allow given email domains, can be set multiple times [$DOMAIN]
  --lifetime=                                           Lifetime in seconds (default: 43200) [$LIFETIME]
  --logout-redirect=                                    URL to redirect to following logout [$LOGOUT_REDIRECT]
  --url-path=                                           Callback URL Path (default: /_oauth) [$URL_PATH]
  --secret=                                             Secret used for signing (required) [$SECRET]
  --whitelist=                                          Only allow given email addresses, can be set multiple times [$WHITELIST]
  --port=                                               Port to listen on (default: 4181) [$PORT]
  --rule.<name>.<param>=                                Rule definitions, param can be: "action", "rule" or "provider"

Google Provider:
  --providers.google.client-id=                         Client ID [$PROVIDERS_GOOGLE_CLIENT_ID]
  --providers.google.client-secret=                     Client Secret [$PROVIDERS_GOOGLE_CLIENT_SECRET]
  --providers.google.prompt=                            Space separated list of OpenID prompt options [$PROVIDERS_GOOGLE_PROMPT]

OIDC Provider:
  --providers.oidc.issuer-url=                          Issuer URL [$PROVIDERS_OIDC_ISSUER_URL]
  --providers.oidc.client-id=                           Client ID [$PROVIDERS_OIDC_CLIENT_ID]
  --providers.oidc.client-secret=                       Client Secret [$PROVIDERS_OIDC_CLIENT_SECRET]
  --providers.oidc.resource=                            Optional resource indicator [$PROVIDERS_OIDC_RESOURCE]

Generic OAuth2 Provider:
  --providers.generic-oauth.auth-url=                   Auth/Login URL [$PROVIDERS_GENERIC_OAUTH_AUTH_URL]
  --providers.generic-oauth.token-url=                  Token URL [$PROVIDERS_GENERIC_OAUTH_TOKEN_URL]
  --providers.generic-oauth.user-url=                   URL used to retrieve user info [$PROVIDERS_GENERIC_OAUTH_USER_URL]
  --providers.generic-oauth.client-id=                  Client ID [$PROVIDERS_GENERIC_OAUTH_CLIENT_ID]
  --providers.generic-oauth.client-secret=              Client Secret [$PROVIDERS_GENERIC_OAUTH_CLIENT_SECRET]
  --providers.generic-oauth.scope=                      Scopes (default: profile, email) [$PROVIDERS_GENERIC_OAUTH_SCOPE]
  --providers.generic-oauth.token-style=[header|query]  How token is presented when querying the User URL (default: header)
                                                        [$PROVIDERS_GENERIC_OAUTH_TOKEN_STYLE]
  --providers.generic-oauth.resource=                   Optional resource indicator [$PROVIDERS_GENERIC_OAUTH_RESOURCE]

Help Options:
  -h, --help                                            Show this help message
```

All options can be supplied in any of the following ways, in the following precedence (first is highest precedence):

1. **Command Arguments/Flags** - As shown above
2. **Environment Variables** - As shown in square brackets above
3. **File**
    1. Use INI format (e.g. `url-path = _oauthpath`)
    2. Specify the file location via the `--config` flag or `$CONFIG` environment variable
    3. Can be specified multiple times, each file will be read in the order they are passed

### Option Details

- `auth-host`

  When set, when a user returns from authentication with a 3rd party provider they will always be forwarded to this host. By using one central host, this means you only need to add this `auth-host` as a valid redirect uri to your 3rd party provider.

  The host should be specified without protocol or path, for example:

   ```
   --auth-host="auth.example.com"
   ```

   For more details, please also read the [Auth Host Mode](#auth-host-mode), operation mode in the concepts section.

   Please Note - this should be considered advanced usage, if you are having problems please try disabling this option and then re-read the [Auth Host Mode](#auth-host-mode) section.

- `config`

   Used to specify the path to a configuration file, can be set multiple times, each file will be read in the order they are passed. Options should be set in an INI format, for example:

   ```
   url-path = _oauthpath
   ```

- `cookie-domain`

  When set, if a user successfully completes authentication, then if the host of the original request requiring authentication is a subdomain of a given cookie domain, then the authentication cookie will be set for the higher level cookie domain. This means that a cookie can allow access to multiple subdomains without re-authentication. Can be specificed multiple times.

   For example:
   ```
   --cookie-domain="example.com"  --cookie-domain="test.org"
   ```

   For example, if the cookie domain `test.com` has been set, and a request comes in on `app1.test.com`, following authentication the auth cookie will be set for the whole `test.com` domain. As such, if another request is forwarded for authentication from `app2.test.com`, the original cookie will be sent and so the request will be allowed without further authentication.

   Beware however, if using cookie domains whilst running multiple instances of traefik/traefik-forward-auth for the same domain, the cookies will clash. You can fix this by using a different `cookie-name` in each host/cluster or by using the same `cookie-secret` in both instances.

- `insecure-cookie`

   If you are not using HTTPS between the client and traefik, you will need to pass the `insecure-cookie` option which will mean the `Secure` attribute on the cookie will not be set.

- `cookie-name`

   Set the name of the cookie set following successful authentication.

   Default: `_forward_auth`

- `csrf-cookie-name`

   Set the name of the temporary CSRF cookie set during authentication.

   Default: `_forward_auth_csrf`

- `default-action`

   Specifies the behavior when a request does not match any [rules](#rules). Valid options are `auth` or `allow`.

   Default: `auth` (i.e. all requests require authentication)

- `default-provider`

   Set the default provider to use for authentication, this can be overridden within [rules](#rules). Valid options are currently `google` or `oidc`.

   Default: `google`

- `domain`

   When set, only users matching a given domain will be permitted to access.

   For example, setting `--domain=example.com --domain=test.org` would mean that only users from example.com or test.org will be permitted. So thom@example.com would be allowed but thom@another.com would not.

   For more details, please also read [User Restriction](#user-restriction) in the concepts section.

- `lifetime`

   How long a successful authentication session should last, in seconds.

   Default: `43200` (12 hours)

- `logout-redirect`

   When set, users will be redirected to this URL following logout.

- `match-whitelist-or-domain`

   When enabled, users will be permitted if they match *either* the `whitelist` or `domain` parameters.

   This will be enabled by default in v3, but is disabled by default in v2 to maintain backwards compatibility.

   Default: `false`

   For more details, please also read [User Restriction](#user-restriction) in the concepts section.

- `url-path`

   Customise the path that this service uses to handle the callback following authentication.

   Default: `/_oauth`

   Please note that when using the default [Overlay Mode](#overlay-mode) requests to this exact path will be intercepted by this service and not forwarded to your application. Use this option (or [Auth Host Mode](#auth-host-mode)) if the default `/_oauth` path will collide with an existing route in your application.

- `secret`

   Used to sign cookies authentication, should be a random (e.g. `openssl rand -hex 16`)

- `whitelist`

   When set, only specified users will be permitted.

   For example, setting `--whitelist=thom@example.com --whitelist=alice@example.com` would mean that only those two exact users will be permitted. So thom@example.com would be allowed but john@example.com would not.

   For more details, please also read [User Restriction](#user-restriction) in the concepts section.

- `rule`

   Specify selective authentication rules. Rules are specified in the following format: `rule.<name>.<param>=<value>`

   - `<name>` can be any string and is only used to group rules together
   - `<param>` can be:
       - `action` - same usage as [`default-action`](#default-action), supported values:
           - `auth` (default)
           - `allow`
       - `domains` - optional, same usage as [`domain`](#domain)
       - `provider` - same usage as [`default-provider`](#default-provider), supported values:
           - `google`
           - `oidc`
       - `rule` - a rule to match a request, this uses traefik's v2 rule parser for which you can find the documentation here: https://docs.traefik.io/v2.0/routing/routers/#rule, supported values are summarised here:
           - ``Headers(`key`, `value`)``
           - ``HeadersRegexp(`key`, `regexp`)``
           - ``Host(`example.com`, ...)``
           - ``HostRegexp(`example.com`, `{subdomain:[a-z]+}.example.com`, ...)``
           - ``Method(methods, ...)``
           - ``Path(`path`, `/articles/{category}/{id:[0-9]+}`, ...)``
           - ``PathPrefix(`/products/`, `/articles/{category}/{id:[0-9]+}`)``
           - ``Query(`foo=bar`, `bar=baz`)``
       - `whitelist` - optional, same usage as whitelist`](#whitelist)

   For example:
   ```
   # Allow requests that being with `/api/public` and contain the `Content-Type` header with a value of `application/json`
   rule.1.action = allow
   rule.1.rule = PathPrefix(`/api/public`) && Headers(`Content-Type`, `application/json`)

   # Allow requests that have the exact path `/public`
   rule.two.action = allow
   rule.two.rule = Path(`/public`)

   # Use OpenID Connect provider (must be configured) for requests that begin with `/github`
   rule.oidc.action = auth
   rule.oidc.provider = oidc
   rule.oidc.rule = PathPrefix(`/github`)

   # Allow jane@example.com to `/janes-eyes-only`
   rule.two.action = allow
   rule.two.rule = Path(`/janes-eyes-only`)
   rule.two.whitelist = jane@example.com
   ```

   Note: It is possible to break your redirect flow with rules, please be careful not to create an `allow` rule that matches your redirect_uri unless you know what you're doing. This limitation is being tracked in in #101 and the behaviour will change in future releases.

## Concepts

### User Restriction

You can restrict who can login with the following parameters:

* `domain` - Use this to limit logins to a specific domain, e.g. test.com only
* `whitelist` - Use this to only allow specific users to login e.g. thom@test.com only

Note, if you pass both `whitelist` and `domain`, then the default behaviour is for only `whitelist` to be used and `domain` will be effectively ignored. You can allow users matching *either* `whitelist` or `domain` by passing the `match-whitelist-or-domain` parameter (this will be the default behaviour in v3). If you set `domains` or `whitelist` on a rule, the global configuration is ignored.

### Forwarded Headers

The authenticated user is set in the `X-Forwarded-User` header, to pass this on add this to the `authResponseHeaders` config option in traefik, as shown below in the [Applying Authentication](#applying-authentication) section.

### Applying Authentication

Authentication can be applied in a variety of ways, either globally across all requests, or selectively to specific containers/ingresses.

#### Global Authentication

This can be achieved by enabling forward authentication for an entire entrypoint, for example, with http only:

```ini
--entryPoints.http.address=:80
--entrypoints.http.http.middlewares=traefik-forward-auth # "default-traefik-forward-auth" on kubernetes
```

Or https:

```ini
--entryPoints.http.address=:80
--entryPoints.http.http.redirections.entryPoint.to=https
--entryPoints.http.http.redirections.entryPoint.scheme=https
--entryPoints.https.address=:443
--entrypoints.https.http.middlewares=traefik-forward-auth # "default-traefik-forward-auth" on kubernetes
```

Note: Traefik prepends the namespace to the name of middleware defined via a kubernetes resource. This is handled automatically when referencing the middleware from another resource in the same namespace (so the namespace does not need to be prepended when referenced). However the full name, including the namespace, must be used when referenced from static configuration (e.g. command arguments or config file), hence you must prepend the namespace to your traefik-forward-auth middleware reference, as shown in the comments above (e.g. `default-traefik-forward-auth` if your middleware is named `traefik-forward-auth` and is defined in the `default` namespace).

#### Selective Ingress Authentication in Kubernetes

If you choose not to enable forward authentication for a specific entrypoint, you can apply the middleware to selected ingressroutes:

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: whoami
  labels:
    app: whoami
spec:
  entryPoints:
    - http
  routes:
  - match: Host(`whoami.example.com`)
    kind: Rule
    services:
      - name: whoami
        port: 80
    middlewares:
      - name: traefik-forward-auth
```

See the examples directory for more examples.

#### Selective Container Authentication in Swarm

You can apply labels to selected containers:

```yaml
whoami:
  image: containous/whoami
  labels:
    - "traefik.http.routers.whoami.rule=Host(`whoami.example.com`)"
    - "traefik.http.routers.whoami.middlewares=traefik-forward-auth"
```

See the examples directory for more examples.

#### Rules Based Authentication

You can also leverage the `rules` config to selectively apply authentication via traefik-forward-auth. For example if you enabled global authentication by enabling forward authentication for an entire entrypoint, you can still exclude some patterns from requiring authentication:

```ini
# Allow requests to 'dash.example.com'
rule.1.action = allow
rule.1.rule = Host(`dash.example.com`)

# Allow requests to `app.example.com/public`
rule.two.action = allow
rule.two.rule = Host(`app.example.com`) && Path(`/public`)
```

### Operation Modes

#### Overlay Mode

Overlay is the default operation mode, in this mode the authorisation endpoint is overlaid onto any domain. By default the `/_oauth` path is used, this can be customised using the `url-path` option.

The user flow will be:

1. Request to `www.myapp.com/home`
2. User redirected to Google login
3. After Google login, user is redirected to `www.myapp.com/_oauth`
4. Token, user and CSRF cookie is validated (this request in intercepted and is never passed to your application)
5. User is redirected to `www.myapp.com/home`
6. Request is allowed

As the hostname in the `redirect_uri` is dynamically generated based on the original request, every hostname must be permitted in the Google OAuth console (e.g. `www.myappp.com` would need to be added in the above example)

#### Auth Host Mode

This is an optional mode of operation that is useful when dealing with a large number of subdomains, it is activated by using the `auth-host` config option (see [this example docker-compose.yml](https://github.com/thomseddon/traefik-forward-auth/blob/master/examples/traefik-v2/swarm/docker-compose-auth-host.yml) or [this kubernetes example](https://github.com/thomseddon/traefik-forward-auth/tree/master/examples/traefik-v2/kubernetes/advanced-separate-pod)).

For example, if you have a few applications: `app1.test.com`, `app2.test.com`, `appN.test.com`, adding every domain to Google's console can become laborious.
To utilise an auth host, permit domain level cookies by setting the cookie domain to `test.com` then set the `auth-host` to: `auth.test.com`.

The user flow will then be:

1. Request to `app10.test.com/home/page`
2. User redirected to Google login
3. After Google login, user is redirected to `auth.test.com/_oauth`
4. Token, user and CSRF cookie is validated, auth cookie is set to `test.com`
5. User is redirected to `app10.test.com/home/page`
6. Request is allowed

With this setup, only `auth.test.com` must be permitted in the Google console.

Two criteria must be met for an `auth-host` to be used:

1. Request matches given `cookie-domain`
2. `auth-host` is also subdomain of same `cookie-domain`

Please note: For Auth Host mode to work, you must ensure that requests to your auth-host are routed to the traefik-forward-auth container, as demonstrated with the service labels in the [docker-compose-auth.yml](https://github.com/thomseddon/traefik-forward-auth/blob/master/examples/traefik-v2/swarm/docker-compose-auth-host.yml) example and the [ingressroute resource](https://github.com/thomseddon/traefik-forward-auth/blob/master/examples/traefik-v2/kubernetes/advanced-separate-pod/traefik-forward-auth/ingress.yaml) in a kubernetes example.

### Logging Out

The service provides an endpoint to clear a users session and "log them out". The path is created by appending `/logout` to your configured `path` and so with the default settings it will be: `/_oauth/logout`.

You can use the `logout-redirect` config option to redirect users to another URL following logout (note: the user will not have a valid auth cookie after being logged out).

Note: This only clears the auth cookie from the users browser and as this service is stateless, it does not invalidate the cookie against future use. So if the cookie was recorded, for example, it could continue to be used for the duration of the cookie lifetime.

## Copyright

2018 Thom Seddon

## License

[MIT](https://github.com/thomseddon/traefik-forward-auth/blob/master/LICENSE.md)
