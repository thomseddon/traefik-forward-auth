package provider

type Providers struct {
	Google Google `group:"Google Provider"`
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
