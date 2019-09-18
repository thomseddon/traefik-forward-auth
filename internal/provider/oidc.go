package provider

import (
	"net/url"
)

type OIDC struct {
	ClientId     string `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret string `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`
	Scope        string
	Prompt       string `long:"prompt" env:"PROMPT" description:"Space separated list of OpenID prompt options"`

	LoginURL *url.URL
	TokenURL *url.URL
	UserURL  *url.URL
}

func (o *OIDC) Name() string {
	return "oidc"
}

func (o *OIDC) Validate() error {
	// TODO
	return nil
}

func (o *OIDC) GetLoginURL(redirectUri, state string) string {
	return "http://oidc.com"
	// q := url.Values{}
	// q.Set("client_id", g.ClientId)
	// q.Set("response_type", "code")
	// q.Set("scope", g.Scope)
	// if g.Prompt != "" {
	// 	q.Set("prompt", g.Prompt)
	// }
	// q.Set("redirect_uri", redirectUri)
	// q.Set("state", state)

	// var u url.URL
	// u = *g.LoginURL
	// u.RawQuery = q.Encode()

	// return u.String()
}

func (o *OIDC) ExchangeCode(redirectUri, code string) (string, error) {
	return "token", nil
	// form := url.Values{}
	// form.Set("client_id", g.ClientId)
	// form.Set("client_secret", g.ClientSecret)
	// form.Set("grant_type", "authorization_code")
	// form.Set("redirect_uri", redirectUri)
	// form.Set("code", code)

	// res, err := http.PostForm(g.TokenURL.String(), form)
	// if err != nil {
	// 	return "", err
	// }

	// var token Token
	// defer res.Body.Close()
	// err = json.NewDecoder(res.Body).Decode(&token)

	// return token.Token, err
}

func (o *OIDC) GetUser(token string) (User, error) {
	var user User
	return user, nil

	// client := &http.Client{}
	// req, err := http.NewRequest("GET", g.UserURL.String(), nil)
	// if err != nil {
	// 	return user, err
	// }

	// req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	// res, err := client.Do(req)
	// if err != nil {
	// 	return user, err
	// }

	// defer res.Body.Close()
	// err = json.NewDecoder(res.Body).Decode(&user)

	// return user, err
}
