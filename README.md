
# Traefik Forward Auth [![Build Status](https://travis-ci.org/thomseddon/traefik-forward-auth.svg?branch=master)](https://travis-ci.org/thomseddon/traefik-forward-auth)

A minimal forward authentication service that provides Google oauth based login and authentication for the traefik reverse proxy.


## Why?

- Seamlessly overlays any http service with a single endpoint (see: `-url-path` in [Configuration](#configuration))
- Supports multiple domains/subdomains by dynamically generating redirect_uri's
- Allows authentication to persist across multiple domains (see [Cookie Domains](#cookie-domains))
- Supports extended authentication beyond Google token lifetime (see: `-lifetime` in [Configuration](#configuration))

## Quick Start

See the (examples) directory for example docker compose and traefik configuration files that demonstrates the forward authentication configuration for traefik and passing required configuration values to traefik-forward-auth.

## Configuration

The following configuration is supported:


|Flag                   |Type  |Description|
|-----------------------|------|-----------|
|-client-id|string|*Google Client ID (required)|
|-client-secret|string|*Google Client Secret (required)|
|-config|string|Path to config file|
|-cookie-domains|string|Comma separated list of cookie domains|
|-cookie-name|string|Cookie Name (default "_forward_auth")|
|-cookie-secret|string|*Cookie secret (required)|
|-cookie-secure|bool|Use secure cookies (default true)|
|-csrf-cookie-name|string|CSRF Cookie Name (default "_forward_auth_csrf")|
|-direct|bool|Run in direct mode (use own hostname as oppose to <br>X-Forwarded-Host, used for testing/development)
|-domain|string|Comma separated list of email domains to allow|
|-email|string|Comma separated list of emails to allow|
|-lifetime|int|Session length in seconds (default 43200)|
|-url-path|string|Callback URL (default "_oauth")|

Configuration can also be supplied as environment variables (use upper case and swap `-`'s for `_`'s e.g. `-client-id` becomes `CLIENT_ID`)

Configuration can also be supplied via a file, you can specify the location with `-config` flag, the format is `flag value` one per line, e.g. `client-id your-client-id`)

## OAuth Configuration

Head to https://console.developers.google.com & make sure you've switched to the correct email account.

Create a new project then search for and select "Credentials" in the search bar. Fill out the "OAuth Consent Screen" tab.

Click, "Create Credentials" > "OAuth client ID". Select "Web Application", fill in the name of your app, skip "Authorized JavaScript origins" and fill "Authorized redirect URIs" with all the domains you will allow authentication from, appended with the `url-path` (e.g. https://app.test.com/_oauth)

## Cookie Domains

You can supply a comma separated list of cookie domains, if the host of the original request is a subdomain of any given cookie domain, the authentication cookie will set with the given domain.

For example, if cookie domain is `test.com` and a request comes in on `app1.test.com`, the cookie will be set for the whole `test.com` domain. As such, if another request is forwarded for authentication from `app2.test.com`, the original cookie will be sent and so the request will be allowed without further authentication.

Beware however, if using cookie domains whilst running multiple instances of traefik/traefik-forward-auth for the same domain, the cookies will clash. You can fix this by using the same `cookie-secret` in both instances, or using a different `cookie-name` on each.

## Copyright

2018 Thom Seddon

## License

[MIT](https://github.com/thomseddon/traefik-forward-auth/blob/master/LICENSE.md)
