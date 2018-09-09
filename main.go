
package main

import (
  "fmt"
  "time"
  "strings"
  "net/url"
  "net/http"

  "github.com/namsral/flag"
  "github.com/op/go-logging"
)

// Vars
var fw *ForwardAuth;
var log = logging.MustGetLogger("traefik-forward-auth")

// Primary handler
func handler(w http.ResponseWriter, r *http.Request) {
  if !fw.ShouldValidate(r) {
    // Valid request
    w.WriteHeader(200)
    return
  }

  // Parse uri
  uri, err := url.Parse(r.Header.Get("X-Forwarded-Uri"))
  if err != nil {
    log.Error("Error parsing url")
    http.Error(w, "Service unavailable", 503)
    return
  }

  // Direct mode
  if fw.Direct {
    uri = r.URL
  }

  // Handle callback
  if uri.Path == fw.Path {
    handleCallback(w, r, uri.Query())
    return
  }

  c, err := r.Cookie(fw.CookieName)
  if err != nil {
    // Error indicates no cookie, generate nonce
    err, nonce := fw.Nonce()
    if err != nil {
      log.Error("Error generating nonce")
      http.Error(w, "Service unavailable", 503)
      return
    }

    // Set the CSRF cookie
    http.SetCookie(w, fw.MakeCSRFCookie(r, nonce))
    log.Debug("Set CSRF cookie and redirecting to google login")

    // Forward them on
    http.Redirect(w, r, fw.GetLoginURL(r, nonce), http.StatusTemporaryRedirect)

    return
  }

  // Validate cookie
  valid, email, err := fw.ValidateCookie(r, c)
  if !valid {
    log.Debugf("Invlaid cookie: %s", err)
    http.Error(w, "Not authorized", 401)
    return
  }

  // Validate user
  valid = fw.ValidateEmail(email)
  if !valid {
    log.Debugf("Invalid email: %s", email)
    http.Error(w, "Not authorized", 401)
    return
  }

  // Valid request
  w.WriteHeader(200)
}


// Authenticate user after they have come back from google
func handleCallback(w http.ResponseWriter, r *http.Request, qs url.Values) {
  // Check for CSRF cookie
  csrfCookie, err := r.Cookie(fw.CSRFCookieName)
  if err != nil {
    log.Debug("Missing csrf cookie")
    http.Error(w, "Not authorized", 401)
    return
  }

  // Validate state
  state := qs.Get("state")
  valid, redirect, err := fw.ValidateCSRFCookie(csrfCookie, state)
  if !valid {
    log.Debugf("Invalid oauth state, expected '%s', got '%s'\n", csrfCookie.Value, state)
    http.Error(w, "Not authorized", 401)
    return
  }

  // Clear CSRF cookie
  http.SetCookie(w, fw.ClearCSRFCookie(r))

  // Exchange code for token
  token, err := fw.ExchangeCode(r, qs.Get("code"))
  if err != nil {
    log.Debugf("Code exchange failed with: %s\n", err)
    http.Error(w, "Service unavailable", 503)
    return
  }

  // Get user
  user, err := fw.GetUser(token)
  if err != nil {
    log.Debugf("Error getting user: %s\n", err)
    return
  }

  // Generate cookie
  http.SetCookie(w, fw.MakeCookie(r, user.Email))
  log.Debugf("Generated auth cookie for %s\n", user.Email)

  // Redirect
  http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}


// Main
func main() {
  // Parse options
  flag.String(flag.DefaultConfigFlagname, "", "Path to config file")
  path := flag.String("url-path", "_oauth", "Callback URL")
  lifetime := flag.Int("lifetime", 43200, "Session length in seconds")
  clientId := flag.String("client-id", "", "*Google Client ID (required)")
  clientSecret := flag.String("client-secret", "", "*Google Client Secret (required)")
  cookieName := flag.String("cookie-name", "_forward_auth", "Cookie Name")
  cSRFCookieName := flag.String("csrf-cookie-name", "_forward_auth_csrf", "CSRF Cookie Name")
  cookieDomainList := flag.String("cookie-domains", "", "Comma separated list of cookie domains") //todo
  cookieSecret := flag.String("cookie-secret", "", "*Cookie secret (required)")
  cookieSecure := flag.Bool("cookie-secure", true, "Use secure cookies")
  authDomainList := flag.String("auth-domain", "", "Comma separated list of domains to forward auth for")
  domainList := flag.String("domain", "", "Comma separated list of email domains to allow")
  direct := flag.Bool("direct", false, "Run in direct mode (use own hostname as oppose to X-Forwarded-Host, used for testing/development)")

  flag.Parse()

  // Check for show stopper errors
  err := false
  if *clientId == "" {
    err = true
    log.Critical("client-id must be set")
  }
  if *clientSecret == "" {
    err = true
    log.Critical("client-secret must be set")
  }
  if *cookieSecret == "" {
    err = true
    log.Critical("cookie-secret must be set")
  }
  if err {
    return
  }

  // Parse lists
  var cookieDomains []CookieDomain
  if *cookieDomainList != "" {
    for _, d := range strings.Split(*cookieDomainList, ",") {
      cookieDomain := NewCookieDomain(d)
      cookieDomains = append(cookieDomains, *cookieDomain)
    }
  }

  var authDomain []string
  if *authDomainList != "" {
    authDomain = strings.Split(*authDomainList, ",")
  }

  var domain []string
  if *domainList != "" {
    domain = strings.Split(*domainList, ",")
  }

  // Setup
  fw = &ForwardAuth{
    Path: fmt.Sprintf("/%s", *path),
    Lifetime: time.Second * time.Duration(*lifetime),

    ClientId: *clientId,
    ClientSecret: *clientSecret,
    Scope: "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email",
    LoginURL: &url.URL{
      Scheme: "https",
      Host: "accounts.google.com",
      Path: "/o/oauth2/auth",
    },
    TokenURL: &url.URL{
      Scheme: "https",
      Host: "www.googleapis.com",
      Path: "/oauth2/v3/token",
    },
    UserURL: &url.URL{
      Scheme: "https",
      Host: "www.googleapis.com",
      Path: "/oauth2/v2/userinfo",
    },

    CookieName: *cookieName,
    CSRFCookieName: *cSRFCookieName,
    CookieDomains: cookieDomains,
    CookieSecret: []byte(*cookieSecret),
    CookieSecure: *cookieSecure,

    AuthDomain: authDomain,

    Domain: domain,

    Direct: *direct,
  }

  // Attach handler
  http.HandleFunc("/", handler)

  log.Notice("Litening on :4181")
  log.Notice(http.ListenAndServe(":4181", nil))
}
