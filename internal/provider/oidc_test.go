package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/thomseddon/traefik-forward-auth/internal/cookie"
	"gopkg.in/square/go-jose.v2"
)

// MockCookieStore is a mock implementation of the CookieStore interface
type MockCookieStore struct {
	mock.Mock
}

func (m *MockCookieStore) SetCookie(name, value string, opts ...cookie.CookieOption) {
	m.Called(name, value)
}

func (m *MockCookieStore) GetCookie(name string) (string, error) {
	args := m.Called(name)
	return args.String(0), args.Error(1)
}

func (m *MockCookieStore) DeleteCookie(name string) {
	m.Called(name)
}

// Tests

func TestOIDCName(t *testing.T) {
	p := OIDC{}
	assert.Equal(t, "oidc", p.Name())
}

func TestOIDCSetup(t *testing.T) {
	assert := assert.New(t)
	p := OIDC{}

	err := p.Setup()
	if assert.Error(err) {
		assert.Equal(
			"providers.oidc.issuer-url, providers.oidc.client-id, providers.oidc.client-secret must be set",
			err.Error(),
		)
	}

	p.IssuerURL = "url"

	err = p.Setup()
	if assert.Error(err) {
		assert.Equal("providers.oidc.client-id, providers.oidc.client-secret must be set", err.Error())
	}

	p.ClientID = "id"

	err = p.Setup()
	if assert.Error(err) {
		assert.Equal("providers.oidc.client-secret must be set", err.Error())
	}
}

func TestOIDCGetLoginURL(t *testing.T) {
	assert := assert.New(t)

	provider, server, serverURL, _ := setupOIDCTest(t, nil)
	defer server.Close()

	mockCookieStore := new(MockCookieStore)

	// Use mock.Anything for all parameters since we're passing cookie options now
	mockCookieStore.On("SetCookie", cookieNameNonce, mock.Anything, mock.Anything).Return()
	mockCookieStore.On("SetCookie", cookieNamePkceCode, mock.Anything, mock.Anything).Return()

	// Check URL without PKCE
	loginUrl, _ := provider.GetLoginURL("http://example.com/_oauth", "state", mockCookieStore)
	uri, err := url.Parse(loginUrl)
	assert.Nil(err)
	assert.Equal(serverURL.Scheme, uri.Scheme)
	assert.Equal(serverURL.Host, uri.Host)
	assert.Equal("/auth", uri.Path)

	// Check query string
	qs := uri.Query()

	// Capture the nonce from the cookie store
	capturedNonce := qs.Get("nonce")
	expectedQs := url.Values{
		"client_id":     []string{"idtest"},
		"redirect_uri":  []string{"http://example.com/_oauth"},
		"response_type": []string{"code"},
		"scope":         []string{"openid profile email"},
		"state":         []string{"state"},
		"nonce":         []string{capturedNonce},
	}
	assert.Equal(expectedQs, qs)

	// Test with PkceRequired config option
	provider.PkceRequired = true

	// Check URL with PKCE
	loginUrl, _ = provider.GetLoginURL("http://example.com/_oauth", "state", mockCookieStore)
	uri, err = url.Parse(loginUrl)
	assert.Nil(err)
	assert.Equal(serverURL.Scheme, uri.Scheme)
	assert.Equal(serverURL.Host, uri.Host)
	assert.Equal("/auth", uri.Path)

	// Check query string
	qs = uri.Query()

	// Capture the nonce and code challenge from the query string
	capturedNonce = qs.Get("nonce")
	capturedCodeChallenge := qs.Get("code_challenge")

	expectedQs = url.Values{
		"client_id":             []string{"idtest"},
		"code_challenge":        []string{capturedCodeChallenge},
		"code_challenge_method": []string{"S256"},
		"redirect_uri":          []string{"http://example.com/_oauth"},
		"response_type":         []string{"code"},
		"scope":                 []string{"openid profile email"},
		"state":                 []string{"state"},
		"nonce":                 []string{capturedNonce},
	}
	assert.Equal(expectedQs, qs)

	// Test with resource config option
	provider.Resource = "resourcetest"

	// Check URL with resource
	loginUrl, _ = provider.GetLoginURL("http://example.com/_oauth", "state", mockCookieStore)
	uri, err = url.Parse(loginUrl)
	assert.Nil(err)
	assert.Equal(serverURL.Scheme, uri.Scheme)
	assert.Equal(serverURL.Host, uri.Host)
	assert.Equal("/auth", uri.Path)

	// Check query string
	qs = uri.Query()
	expectedQs = url.Values{
		"client_id":     []string{"idtest"},
		"redirect_uri":  []string{"http://example.com/_oauth"},
		"response_type": []string{"code"},
		"scope":         []string{"openid profile email"},
		"state":         []string{"state"},
		"resource":      []string{"resourcetest"},
	}
	assert.Equal(expectedQs, qs)

	// Ensure the underlying config is not modified
	assert.Equal("", provider.Config.RedirectURL)

	// Verify that SetCookie was called as expected
	mockCookieStore.AssertCalled(t, "SetCookie", cookieNameNonce, mock.Anything, mock.Anything)
	if provider.PkceRequired {
		mockCookieStore.AssertCalled(t, "SetCookie", cookieNamePkceCode, mock.Anything, mock.Anything)
	}
}

func TestOIDCExchangeCode(t *testing.T) {
	assert := assert.New(t)

	mockCookieStore := new(MockCookieStore)

	// Simulate the behavior of the cookie store
	mockCookieStore.On("GetCookie", cookieNamePkceCode).Return("mockPkceCode", nil)
	mockCookieStore.On("GetCookie", cookieNameNonce).Return("mockNonce", nil)
	mockCookieStore.On("DeleteCookie", cookieNamePkceCode).Return()
	mockCookieStore.On("DeleteCookie", cookieNameNonce).Return()

	provider, server, _, _ := setupOIDCTest(
		t, map[string]map[string]string{
			"token": {
				"code":          "code",
				"grant_type":    "authorization_code",
				"redirect_uri":  "http://example.com/_oauth",
				"code_verifier": "mockPkceCode", // Add PKCE verifier
			},
		},
	)
	defer server.Close()

	// Enable PKCE for the test
	provider.PkceRequired = true

	token, err := provider.ExchangeCode("http://example.com/_oauth", "code", mockCookieStore)
	assert.NoError(err)
	assert.NotEmpty(token)

	// Verify cookie store interactions
	mockCookieStore.AssertCalled(t, "GetCookie", cookieNamePkceCode)
	mockCookieStore.AssertCalled(t, "GetCookie", cookieNameNonce)
	mockCookieStore.AssertCalled(t, "DeleteCookie", cookieNamePkceCode)
	mockCookieStore.AssertCalled(t, "DeleteCookie", cookieNameNonce)
}

func TestOIDCGetUser(t *testing.T) {
	assert := assert.New(t)

	provider, server, serverURL, key := setupOIDCTest(t, nil)
	defer server.Close()

	// Generate JWT
	token := key.sign(
		t, []byte(`{
		"iss": "`+serverURL.String()+`",
		"exp":`+strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)+`,
		"aud": "idtest",
		"sub": "1",
		"email": "example@example.com",
		"email_verified": true
	}`),
	)

	// Get user
	user, err := provider.GetUser(token)
	assert.Nil(err)
	assert.Equal("example@example.com", user.Email)
}

// Utils

// setOIDCTest creates a key, OIDCServer and initilises an OIDC provider
func setupOIDCTest(t *testing.T, bodyValues map[string]map[string]string) (*OIDC, *httptest.Server, *url.URL, *rsaKey) {
	// Generate key
	key, err := newRSAKey()
	if err != nil {
		t.Fatal(err)
	}

	body := make(map[string]string)
	if bodyValues != nil {
		// URL encode bodyValues into body
		for method, values := range bodyValues {
			q := url.Values{}
			for k, v := range values {
				q.Set(k, v)
			}
			body[method] = q.Encode()
		}
	}

	// Set up oidc server
	server, serverURL := NewOIDCServer(t, key, body)

	// Setup provider
	p := OIDC{
		ClientID:     "idtest",
		ClientSecret: "sectest",
		IssuerURL:    serverURL.String(),
	}

	// Initialise config/verifier
	err = p.Setup()
	if err != nil {
		t.Fatal(err)
	}

	return &p, server, serverURL, key
}

// OIDCServer is used in the OIDC Tests to mock an OIDC server
type OIDCServer struct {
	t    *testing.T
	url  *url.URL
	body map[string]string // method -> body
	key  *rsaKey
}

func NewOIDCServer(t *testing.T, key *rsaKey, body map[string]string) (*httptest.Server, *url.URL) {
	handler := &OIDCServer{t: t, key: key, body: body}
	server := httptest.NewServer(handler)
	handler.url, _ = url.Parse(server.URL)
	return server, handler.url
}

func (s *OIDCServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)

	if r.URL.Path == "/.well-known/openid-configuration" {
		// Open id config
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(
			w, `{
            "issuer":"`+s.url.String()+`",
            "authorization_endpoint":"`+s.url.String()+`/auth",
            "token_endpoint":"`+s.url.String()+`/token",
            "jwks_uri":"`+s.url.String()+`/jwks"
        }`,
		)
	} else if r.URL.Path == "/token" {
		// Token request
		// Check body
		if b, ok := s.body["token"]; ok {
			if b != string(body) {
				s.t.Fatal("Unexpected request body, expected", b, "got", string(body))
			}
		}

		// Create a signed JWT token for testing
		idToken := s.key.sign(s.t, []byte(`{
            "iss": "`+s.url.String()+`",
            "sub": "test_subject",
            "aud": "idtest",
            "exp": `+strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)+`,
            "iat": `+strconv.FormatInt(time.Now().Unix(), 10)+`,
            "nonce": "mockNonce"
        }`))

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
            "access_token": "123456789",
            "id_token": "%s"
        }`, idToken)
	} else if r.URL.Path == "/jwks" {
		// Key request
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"keys":[`+s.key.publicJWK(s.t)+`]}`)
	} else {
		s.t.Fatal("Unrecognised request: ", r.URL, string(body))
	}
}

// rsaKey is used in the OIDCServer tests to sign and verify requests
type rsaKey struct {
	key     *rsa.PrivateKey
	alg     jose.SignatureAlgorithm
	jwkPub  *jose.JSONWebKey
	jwkPriv *jose.JSONWebKey
}

func newRSAKey() (*rsaKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 1028)
	if err != nil {
		return nil, err
	}

	return &rsaKey{
		key: key,
		alg: jose.RS256,
		jwkPub: &jose.JSONWebKey{
			Key:       key.Public(),
			Algorithm: string(jose.RS256),
		},
		jwkPriv: &jose.JSONWebKey{
			Key:       key,
			Algorithm: string(jose.RS256),
		},
	}, nil
}

func (k *rsaKey) publicJWK(t *testing.T) string {
	b, err := k.jwkPub.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}

	return string(b)
}

// sign creates a JWS using the private key from the provided payload.
func (k *rsaKey) sign(t *testing.T, payload []byte) string {
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: k.alg,
			Key:       k.key,
		}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	data, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return data
}
