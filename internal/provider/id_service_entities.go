package provider

type Token struct {
	Token string `json:"access_token"`
}

type User struct {
	Id       string `json:"id"`
	Email    string `json:"email"`
	Verified bool   `json:"verified_email"`
	Hd       string `json:"hd"`
}

// AzureUser stores the unmarshalled json response from userinfo endpoint of Microsoft Identity Platform
type AzureUser struct {
	Id    string `json:"oid"`
	Email string `json:"upn"`
}
