package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"net/http"
	"net/url"
)

type Reddit struct {
	ClientId     string `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret string `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`
	Scope        string
	Prompt       string `long:"prompt" env:"PROMPT" description:"Space separated list of OpenID prompt options"`

	LoginURL *url.URL
	TokenURL *url.URL
	UserURL  *url.URL
}

type RedditUser struct {
	Id       string `json:"id"`
	Email    string `json:"name"`
	Verified bool   `json:"has_verified_email"`
	Hd       string `json:"hd"`
}

func (r *Reddit) Name() string {
	return "reddit"
}

func (r *Reddit) Validate() error {
	if r.ClientId == "" || r.ClientSecret == "" {
		return errors.New("providers.reddit.client-id, providers.reddit.client-secret must be set")
	}
	return nil
}

func (r *Reddit) GetLoginURL(redirectUri, state string) string {
	q := url.Values{}
	q.Set("client_id", r.ClientId)
	q.Set("response_type", "code")
	q.Set("scope", r.Scope)
	q.Set("redirect_uri", redirectUri)
	q.Set("state", state)
	q.Set("duration", "temporary")

	var u url.URL
	u = *r.LoginURL
	u.RawQuery = q.Encode()

	return u.String()
}

func (r *Reddit) ExchangeCode(redirectUri, code string) (string, error) {
	client := &http.Client{}
    form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", redirectUri)
	form.Set("code", code)
    req, err := http.NewRequest("POST", r.TokenURL.String(), strings.NewReader(form.Encode()))
	req.SetBasicAuth(r.ClientId, r.ClientSecret)

    res, err := client.Do(req)
	if err != nil {
		return "", err
	}

	var token Token
	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&token)

	return token.Token, err
}

func (r *Reddit) GetUser(token string) (User, error) {
	var user User
	var redditUser RedditUser

	client := &http.Client{}
	req, err := http.NewRequest("GET", r.UserURL.String(), nil)
	if err != nil {
		return user, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("User-Agent", "traefik-forward-auth")
	res, err := client.Do(req)
	if err != nil {
		return user, err
	}

	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&redditUser)

	if err != nil {
		return user, err
	}

	redditUser.Email = redditUser.Email + "@reddit.com"

	user = User(redditUser)

	return user, err
}
