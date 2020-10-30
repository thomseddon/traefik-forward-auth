package provider

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/muly/go-oidc"
)

func TestOIDC_GetUserFromCode(t *testing.T) {
	ms := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Path : ", r.URL.Path)
		if strings.Contains(r.URL.Path, "/as/token.oauth2/?code=") {
			w.Write([]byte(`{"access_token":"aodifuvboadifubv"}`))
		}
		if strings.Contains(r.URL.Path, "/idp/userinfo.openid") {
			w.Write([]byte(`{"id":"user_id","email":"user@domain.com"}`))
		}
	}))
	defer ms.Close()

	type fields struct {
		OAuthProvider          OAuthProvider
		IssuerURL              string
		ClientID               string
		ClientSecret           string
		provider               *oidc.Provider
		verifier               *oidc.IDTokenVerifier
		UserURL                *url.URL
		APIAccessTokenEndpoint *url.URL
	}
	type args struct {
		code        string
		redirectURI string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    User
		wantErr bool
	}{
		{
			name: "test1",
			fields: fields{
				APIAccessTokenEndpoint: &url.URL{
					Scheme: "http",
					Host:   ms.Listener.Addr().String(),
					Path:   "/as/token.oauth2/?code=",
				},
				UserURL: &url.URL{
					Scheme: "http",
					Host:   ms.Listener.Addr().String(),
					Path:   "/idp/userinfo.openid",
				},
			},
			args: args{
				code:        "9WFt1LbLRt46ISEfUGiXqVL7JE25Ee2CegwAAAEx",
				redirectURI: "https%3A%2F%2Fauth.bizapps-mock.cisco.com%2Fcallback",
			},
			want:    User{ID: "user_id", Email: "user@domain.com"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &OIDC{
				OAuthProvider:          tt.fields.OAuthProvider,
				IssuerURL:              tt.fields.IssuerURL,
				ClientID:               tt.fields.ClientID,
				ClientSecret:           tt.fields.ClientSecret,
				provider:               tt.fields.provider,
				verifier:               tt.fields.verifier,
				UserURL:                tt.fields.UserURL,
				APIAccessTokenEndpoint: tt.fields.APIAccessTokenEndpoint,
			}
			got, err := o.GetUserFromCode(tt.args.code, tt.args.redirectURI)
			if (err != nil) != tt.wantErr {
				t.Errorf("OIDC.GetUserFromCode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("OIDC.GetUserFromCode() = %v, want %v", got, tt.want)
			}
		})
	}
}

//var ms *httptest.Server

// func setupSubTest(t *testing.T) func(t *testing.T) {
// 	ms = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		fmt.Println("Path : ", r.URL.Path)
// 		if strings.Contains(r.URL.Path, "/as/token.oauth2/?code=") {
// 			w.Write([]byte(`{"access_token":"aodifuvboadifubv"}`))
// 		}
// 		if strings.Contains(r.URL.Path, "/idp/userinfo.openid") {
// 			w.Write([]byte(`{"id":"user_id","email":"user@domain.com"}`))
// 		}
// 	}))
// 	defer ms.Close()

// 	return func(t *testing.T) {}
// }

// func teardownSubTest(t *testing.T) func(t *testing.T) {
// 	defer ms.Close()
// 	return func(t *testing.T) {}
// }
