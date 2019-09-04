package provider

//AuthProvider is the interface every Auth provider should implement
type AuthProvider interface {
	GetLoginURL(redirectURI, state string) string
	ExchangeCode(redirectURI, code string) (string, error)
	GetUser(token string) (User, error)
}
