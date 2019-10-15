package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type GitHub struct {
	ClientId     string `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret string `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`
	Scope        string `long:"scopes" env:"SCOPES" description:"Oauth Scopes"`
	Prompt       string `long:"prompt" env:"PROMPT" description:"Space separated list of OpenID prompt options"`

	LoginURL *url.URL
	TokenURL *url.URL
	UserURL  *url.URL
}

func (g *GitHub) Name() string {
	return "github"
}

func (g *GitHub) Validate() error {
	if g.ClientId == "" || g.ClientSecret == "" {
		return errors.New("providers.github.client-id, providers.github.client-secret must be set")
	}
	return nil
}

func (g *GitHub) GetLoginURL(redirectUri, state string) string {
	q := url.Values{}
	q.Set("client_id", g.ClientId)
	q.Set("redirect_uri", redirectUri)
	q.Set("scope", strings.Replace(g.Scope, ",", " ",-1))
	if g.Prompt != "" {
		q.Set("prompt", g.Prompt)
	}
	q.Set("state", state)

	var u url.URL
	u = *g.LoginURL
	u.RawQuery = q.Encode()

	return u.String()
}

func (g *GitHub) ExchangeCode(redirectUri, code string) (string, error) {
	form := url.Values{}
	form.Set("client_id", g.ClientId)
	form.Set("client_secret", g.ClientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", redirectUri)

	res, err := http.PostForm(g.TokenURL.String(), form)
	if err != nil {
		return "", err
	}

	var token Token
	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&token)

	return token.Token, err
}

func (g *GitHub) GetUser(token string) (User, error) {
	var user User

	client := &http.Client{}
	req, err := http.NewRequest("GET", g.UserURL.String(), nil)
	if err != nil {
		return user, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("token %s", token))
	res, err := client.Do(req)
	if err != nil {
		return user, err
	}

	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&user)

	return user, err
}
