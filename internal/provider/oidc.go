package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type OIDC struct {
	ClientID     string `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret string `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`
	Scope        string
	Prompt       string `long:"prompt" env:"PROMPT" description:"Space separated list of OpenID prompt options"`

	LoginURL *url.URL
	TokenURL *url.URL
	UserURL  *url.URL
}

func (oid *OIDC) GetLoginURL(redirectUri, state string) string {
	q := url.Values{}
	q.Set("client_id", oid.ClientID)
	q.Set("response_type", "code")
	q.Set("scope", oid.Scope)
	if oid.Prompt != "" {
		q.Set("prompt", oid.Prompt)
	}
	q.Set("redirect_uri", redirectUri)
	q.Set("state", state)

	var u url.URL
	u = *oid.LoginURL
	u.RawQuery = q.Encode()

	return u.String()
}

func (oid *OIDC) ExchangeCode(redirectUri, code string) (string, error) {
	form := url.Values{}
	form.Set("client_id", oid.ClientID)
	form.Set("client_secret", oid.ClientSecret)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", redirectUri)
	form.Set("code", code)

	res, err := http.PostForm(oid.TokenURL.String(), form)
	if err != nil {
		return "", err
	}

	var token Token
	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&token)

	return token.Token, err
}

func (oid *OIDC) GetUser(token string) (User, error) {
	var user User

	client := &http.Client{}
	req, err := http.NewRequest("GET", oid.UserURL.String(), nil)
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
