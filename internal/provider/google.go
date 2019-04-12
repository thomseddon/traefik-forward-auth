package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type Google struct {
	ClientId     string `long:"providers.google.client-id" description:"Client ID"`
	ClientSecret string `long:"providers.google.client-secret" description:"Client Secret" json:"-"`
	Scope        string
	Prompt       string `long:"providers.google.prompt" description:"Space separated list of OpenID prompt options"`

	LoginURL *url.URL
	TokenURL *url.URL
	UserURL  *url.URL
}

func (g *Google) Build() {
	g.LoginURL = &url.URL{
		Scheme: "https",
		Host:   "accounts.google.com",
		Path:   "/o/oauth2/auth",
	}
	g.TokenURL = &url.URL{
		Scheme: "https",
		Host:   "www.googleapis.com",
		Path:   "/oauth2/v3/token",
	}
	g.UserURL = &url.URL{
		Scheme: "https",
		Host:   "www.googleapis.com",
		Path:   "/oauth2/v2/userinfo",
	}
}

func (g *Google) GetLoginURL(redirectUri, state string) string {
	q := url.Values{}
	q.Set("client_id", g.ClientId)
	q.Set("response_type", "code")
	q.Set("scope", g.Scope)
	if g.Prompt != "" {
		q.Set("prompt", g.Prompt)
	}
	q.Set("redirect_uri", redirectUri)
	q.Set("state", state)

	var u url.URL
	u = *g.LoginURL
	u.RawQuery = q.Encode()

	return u.String()
}

func (g *Google) ExchangeCode(redirectUri, code string) (string, error) {
	form := url.Values{}
	form.Set("client_id", g.ClientId)
	form.Set("client_secret", g.ClientSecret)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", redirectUri)
	form.Set("code", code)

	res, err := http.PostForm(g.TokenURL.String(), form)
	if err != nil {
		return "", err
	}

	var token Token
	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&token)

	return token.Token, err
}

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
