package provider

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
)

// Utilities

type TokenServerHandler struct{
	Body string
}

func NewTokenServer(params map[string]string) (*httptest.Server, *url.URL) {
	var body string
	if len(params) > 0 {
		q := url.Values{}
		for k, v := range params {
			q.Set(k, v)
		}
		body = q.Encode()
	} else {
		body = ""
	}

	handler := &TokenServerHandler{
		Body: body,
	}

	server := httptest.NewServer(handler)
	URL, _ := url.Parse(server.URL)
	return server, URL
}

func (t *TokenServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	if r.Method == "POST" && (t.Body == "" || string(body) == t.Body) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"123456789","id_token":"id_123456789"}`)
	} else {
		http.Error(w, "Token server recieved bad request", http.StatusBadRequest)
	}
}

type UserServerHandler struct{}

func NewUserServer() (*httptest.Server, *url.URL) {
	handler := &UserServerHandler{}
	server := httptest.NewServer(handler)
	URL, _ := url.Parse(server.URL)
	return server, URL
}

func (t *UserServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	fmt.Println(string(body))
	fmt.Fprint(w, `{
    "id":"1",
    "email":"example@example.com",
    "verified_email":true,
    "hd":"example.com"
  }`)
}
