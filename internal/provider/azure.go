package provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type Azure struct {
	ClientID     string `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret string `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`
	Prompt       string `long:"prompt" env:"PROMPT" description:"Space separated list of OpenID prompt options"`

	LoginURL *url.URL
	TokenURL *url.URL
	UserURL  *url.URL
}

func (az *Azure) GetLoginURL(redirectURI, state string) string {
	q := url.Values{}
	q.Set("client_id", az.ClientID)
	q.Set("response_type", "code")
	if az.Prompt != "" {
		q.Set("prompt", az.Prompt)
	}
	q.Set("response_mode", "query")
	q.Set("scope", "openid%20offline_access%20profile")
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)

	var u url.URL
	u = *az.LoginURL
	u.RawQuery = q.Encode()

	return u.String()
}

func (az *Azure) ExchangeCode(redirectURI, code string) (string, error) {
	form := url.Values{}
	form.Set("client_id", az.ClientID)
	form.Set("client_secret", az.ClientSecret)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", redirectURI)
	form.Set("code", code)

	res, err := http.PostForm(az.TokenURL.String(), form)
	if err != nil {
		return "", err
	}

	var token Token
	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&token)

	return token.Token, err
}

func (az *Azure) GetUser(token string) (User, error) {
	var user AzureUser

	client := &http.Client{}
	req, err := http.NewRequest("GET", az.UserURL.String(), nil)
	if err != nil {
		return User{}, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	res, err := client.Do(req)
	if err != nil {
		return User{}, err
	}

	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&user)

	return User{Id: user.Id, Email: user.Email}, err
}
