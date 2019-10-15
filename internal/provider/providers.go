package provider

type Providers struct {
	Google Google `group:"Google Provider" namespace:"google" env-namespace:"GOOGLE"`
	GitHub GitHub `group:"Github Provider" namespace:"github" env-namespace:"GITHUB"`
	OIDC   OIDC   `group:"ODIC Provider" namespace:"odic" env-namespace:"ODIC"`
}

type Provider interface {
	Name() string
	GetLoginURL(redirectUri, state string) string
	ExchangeCode(redirectUri, code string) (string, error)
	GetUser(token string) (User, error)
	Validate() error
}

type Token struct {
	Token string `json:"access_token"`
}

type User struct {
	Id       string `json:"id"`
	Email    string `json:"email"`
	Verified bool   `json:"verified_email"`
	Hd       string `json:"hd"`
}
