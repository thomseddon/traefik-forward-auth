package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Google provider
type Google struct {
	ClientID     string `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret string `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`
	Scope        string
	Prompt       string `long:"prompt" env:"PROMPT" default:"select_account" description:"Space separated list of OpenID prompt options"`
	LoginURL     *url.URL
	UserURL      *url.URL
}

// Name returns the name of the provider
func (g *Google) Name() string {
	return "google"
}

// Setup performs validation and setup
func (g *Google) Setup() error {
	if g.ClientID == "" || g.ClientSecret == "" {
		return errors.New("providers.google.client-id, providers.google.client-secret must be set")
	}

	// Set static values
	g.Scope = "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email"
	g.LoginURL = &url.URL{
		Scheme: "https",
		Host:   "accounts.google.com",
		Path:   "/o/oauth2/auth",
	}
	g.UserURL = &url.URL{
		Scheme: "https",
		Host:   "www.googleapis.com",
		Path:   "/oauth2/v2/userinfo",
	}

	return nil
}

// GetLoginURL provides the login url for the given redirect uri and state
func (g *Google) GetLoginURL(redirectURI, state string) string {
	q := url.Values{}
	q.Set("client_id", g.ClientID)
	q.Set("response_type", "code")
	q.Set("scope", g.Scope)
	if g.Prompt != "" {
		q.Set("prompt", g.Prompt)
	}
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)

	var u url.URL
	u = *g.LoginURL
	u.RawQuery = q.Encode()

	return u.String()
}

// ExchangeCode exchanges the given redirect uri and code for a token
func (g *Google) ExchangeCode(redirectURI, code string) (string, error) {
	ctx := context.Background()

	var conf = &oauth2.Config{
		ClientID:     g.ClientID,
		ClientSecret: g.ClientSecret,
		Endpoint:     google.Endpoint,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"},
		RedirectURL:  redirectURI,
	}

	token, err := conf.Exchange(ctx, code)
	if err != nil {
		log.Fatal(err)
	}
	if err != nil {
		return "", err
	}
	return token.AccessToken, err
}

// GetUser uses the given token and returns a complete provider.User object
func (g *Google) GetUser(token string) (User, error) {
	var user User

	client := &http.Client{}
	req, err := http.NewRequest("GET", g.UserURL.String(), nil)
	if err != nil {
		return user, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return user, err
	}

	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&user)

	return user, err
}
