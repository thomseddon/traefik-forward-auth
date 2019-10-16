package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
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
	TeamsURL *url.URL
}

type GitHubUser struct {
	Id       int    `json:"id"`
	Username string `json:"login"`
	Email    string `json:"email"`
	Teams    []string
}

type GitHubOrg struct {
	Id     int    `json:"id"`
	Login  string `json:"login"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Avatar string `json:"avatar_url"`
}

type GitHubTeam struct {
	Id           int    `json:"id"`
	Name         string `json:"name"`
	Slug         string `json:"slug"`
	Description  string `json:"description"`
	Organization GitHubOrg
}

func (u GitHubUser) ToUser() User {
	var user User

	user.Id = strconv.Itoa(u.Id)
	user.Email = u.Email
	user.Hd = strings.Split(u.Email, "@")[1]
	return user
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
	q.Set("scope", strings.Replace(g.Scope, ",", " ", -1))
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

	defer res.Body.Close()

	if res.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return "", err
		}
		bodyString := string(bodyBytes)
		values, err := url.ParseQuery(bodyString)
		if err != nil {
			return "", err
		}

		if values.Get("access_token") == "" {
			return "", errors.New("invalid response from server: " + bodyString)
		}
		return values.Get("access_token"), nil
	}

	return "", errors.New("server returned " + res.Status)
}

func (g *GitHub) GetAuthMethod(token string) (url.Values, error) {
	var ghUser GitHubUser
	var authMethod = url.Values{}

	client := &http.Client{}
	req, err := http.NewRequest("GET", g.UserURL.String(), nil)
	if err != nil {
		return authMethod, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("token %s", token))
	res, err := client.Do(req)
	if err != nil {
		return authMethod, err
	}

	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&ghUser)

	// Get Teams
	var teams []GitHubTeam
	req, err = http.NewRequest("GET", g.TeamsURL.String(), nil)
	if err != nil {
		return authMethod, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("token %s", token))
	res, err = client.Do(req)
	if err != nil {
		return authMethod, err
	}

	defer res.Body.Close()
	err = json.NewDecoder(res.Body).Decode(&teams)

	var teamsS []string

	for _, team := range teams {
		teamsS = append(teamsS, strconv.Itoa(team.Id))
	}

	ghUser.Teams = teamsS

	if err == nil {
		authMethod.Add("user", ghUser.Username)
		authMethod.Add("teams", strings.Join(ghUser.Teams, ","))
	}

	return authMethod, err
}
