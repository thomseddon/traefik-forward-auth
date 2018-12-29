
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
|-secret|string|*Secret used for signing (required)|
|-config|string|Path to config file|
|-auth-host|string|Central auth login (see below)|
|-cookie-domains|string|Comma separated list of cookie domains (see below)|
|-cookie-name|string|Cookie Name (default "_forward_auth")|
|-cookie-secure|bool|Use secure cookies (default true)|
|-csrf-cookie-name|string|CSRF Cookie Name (default "_forward_auth_csrf")|
|-domain|string|Comma separated list of email domains to allow i.e. user1@domaincom,user2@domain.com,user3@domanin.com|
|-whitelist|string|Comma separated list of email addresses to allow|
|-lifetime|int|Session length in seconds (default 43200)|
|-url-path|string|Callback URL (default "_oauth")|
|-prompt|string|Space separated list of [OpenID prompt options](https://developers.google.com/identity/protocols/OpenIDConnect#prompt)|

Configuration can also be supplied as environment variables (use upper case and swap `-`'s for `_`'s e.g. `-client-id` becomes `CLIENT_ID`)

Configuration can also be supplied via a file, you can specify the location with `-config` flag, the format is `flag value` one per line, e.g. `client-id your-client-id`)

## OAuth Configuration

Head to https://console.developers.google.com & make sure you've switched to the correct email account.

Create a new project then search for and select "Credentials" in the search bar. Fill out the "OAuth Consent Screen" tab.

Click, "Create Credentials" > "OAuth client ID". Select "Web Application", fill in the name of your app, skip "Authorized JavaScript origins" and fill "Authorized redirect URIs" with all the domains you will allow authentication from, appended with the `url-path` (e.g. https://app.test.com/_oauth)

## Usage

The authenticated user is set in the `X-Forwarded-User` header, to pass this on add this to the `authResponseHeaders` as shown [here](https://github.com/thomseddon/traefik-forward-auth/blob/master/example/docker-compose-dev.yml).

## User Restriction

You can restrict who can login with the following parameters:

* `-domain` - Use this to limit logins to a specific domain, e.g. test.com only
* `-whitelist` - Use this to only allow specific users to login e.g. thom@test.com only

Note, if you pass `whitelist` then only this is checked and `domain` is effectively ignored.

## Cookie Domains

You can supply a comma separated list of cookie domains, if the host of the original request is a subdomain of any given cookie domain, the authentication cookie will set with the given domain.

For example, if cookie domain is `test.com` and a request comes in on `app1.test.com`, the cookie will be set for the whole `test.com` domain. As such, if another request is forwarded for authentication from `app2.test.com`, the original cookie will be sent and so the request will be allowed without further authentication.

Beware however, if using cookie domains whilst running multiple instances of traefik/traefik-forward-auth for the same domain, the cookies will clash. You can fix this by using the same `cookie-secret` in both instances, or using a different `cookie-name` on each.

## Operation Modes

#### Overlay

Overlay is the default operation mode, in this mode the authorisation endpoint is overlayed onto any domain. By default the `/_oauth` path is used, this can be customised using the `-url-path` option.

If a request comes in for `www.myapp.com/home` then the user will be redirected to the google login, following this they will be sent back to `www.myapp.com/_oauth`, where their token will be validated (this request will not be forwarded to your application). Following successful authoristion, the user will return to their originally requested url of `www.myapp.com/home`.

As the hostname in the `redirect_uri` is dynamically generated based on the orignal request, every hostname must be permitted in the Google OAuth console (e.g. `www.myappp.com` would need to be added in the above example)

#### Auth Host

This is an optional mode of operation that is useful when dealing with a large number of subdomains, it is activated by using the `-auth-host` config option (see [this example docker-compose.yml](https://github.com/thomseddon/traefik-forward-auth/blob/master/example/docker-compose-auth-host.yml)).

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

## Copyright

2018 Thom Seddon

## License

[MIT](https://github.com/thomseddon/traefik-forward-auth/blob/master/LICENSE.md)
