package cookie

import (
	"errors"
	"net/http"
	"time"
)

// CookieStore interface defines methods for setting and getting cookies
type CookieStore interface {
	SetCookie(name, value string, opts ...CookieOption)
	GetCookie(name string) (string, error)
	DeleteCookie(name string)
}

// CookieOption is a function type that modifies cookie attributes
type CookieOption func(*http.Cookie)

// WithMaxAge sets the max age of the cookie
func WithMaxAge(seconds int) CookieOption {
	return func(c *http.Cookie) {
		c.MaxAge = seconds
	}
}

// WithSameSite sets the SameSite attribute of the cookie
func WithSameSite(v http.SameSite) CookieOption {
	return func(c *http.Cookie) {
		c.SameSite = v
	}
}

// CookieStoreImpl is a concrete implementation of the CookieStore interface
type CookieStoreImpl struct {
	writer  http.ResponseWriter
	request *http.Request
	secure  bool
}

// NewCookieStore creates a new instance of CookieStoreImpl
func NewCookieStore(w http.ResponseWriter, r *http.Request, secure bool) *CookieStoreImpl {
	return &CookieStoreImpl{
		writer:  w,
		request: r,
		secure:  secure,
	}
}

// SetCookie sets a cookie with the given name, value, and attributes
func (c *CookieStoreImpl) SetCookie(name, value string, opts ...CookieOption) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Secure:   c.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	// Apply any provided options
	for _, opt := range opts {
		opt(cookie)
	}

	http.SetCookie(c.writer, cookie)
}

// DeleteCookie removes a cookie with the given name
func (c *CookieStoreImpl) DeleteCookie(name string) {
	cookie := &http.Cookie{
		Name:    name,
		Value:   "",
		Path:    "/",
		MaxAge:  -1,
		Expires: time.Unix(0, 0),
	}

	http.SetCookie(c.writer, cookie)
}

// GetCookie retrieves the value of the cookie with the given name
func (c *CookieStoreImpl) GetCookie(name string) (string, error) {
	cookie, err := c.request.Cookie(name)
	if err != nil {
		return "", errors.New("cookie not found")
	}
	return cookie.Value, nil
}
