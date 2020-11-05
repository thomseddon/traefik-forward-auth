package tfa

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/containous/traefik/v2/pkg/rules"
	"github.com/rajasoun/traefik-forward-auth/internal/provider"
	"github.com/sirupsen/logrus"
)

type Server struct {
	router *rules.Router
}

func NewServer() *Server {
	s := &Server{}
	s.buildRoutes()
	return s
}

func (s *Server) buildRoutes() {
	var err error
	s.router, err = rules.NewRouter()
	if err != nil {
		log.Fatal(err)
	}

	// Let's build a router
	for name, rule := range config.Rules {
		matchRule := rule.formattedRule()
		if rule.Action == "allow" {
			s.router.AddRoute(matchRule, 1, s.AllowHandler(name))
		} else {
			s.router.AddRoute(matchRule, 1, s.AuthHandler(rule.Provider, name))
		}
	}

	// Add callback handler
	s.router.Handle(config.Path, s.AuthCallbackHandler())

	// Add a default handler
	if config.DefaultAction == "allow" {
		s.router.NewRoute().Handler(s.AllowHandler("default"))
	} else {
		s.router.NewRoute().Handler(s.AuthHandler(config.DefaultProvider, "default"))
	}
}

func (s *Server) RootHandler(w http.ResponseWriter, r *http.Request) {
	// Modify request
	r.Method = r.Header.Get("X-Forwarded-Method")
	r.Host = r.Header.Get("X-Forwarded-Host")
	r.URL, _ = url.Parse(r.Header.Get("X-Forwarded-Uri"))

	// Pass to mux
	s.router.ServeHTTP(w, r)
}

// Handler that allows requests
func (s *Server) AllowHandler(rule string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logger(r, rule, "Allowing request")
		w.WriteHeader(200)
	}
}

// Authenticate requests
func (s *Server) AuthHandler(providerName, rule string) http.HandlerFunc {
	p, _ := config.GetConfiguredProvider(providerName)

	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, rule, "Authenticating request")

		// Get auth cookie
		c, err := r.Cookie(config.CookieName)
		if err != nil {
			s.authRedirect(logger, w, r, p)
			return
		}

		// Validate cookie
		email, err := ValidateCookie(r, c)
		if err != nil {
			if err.Error() == "Cookie has expired" {
				logger.Info("Cookie has expired")
				s.authRedirect(logger, w, r, p)
			} else {
				logger.Errorf("Invalid cookie: %v", err)
				http.Error(w, "Not authorized", 401)
			}
			return
		}

		// Validate user
		valid := ValidateEmail(email)
		if !valid {
			logger.WithFields(logrus.Fields{
				"email": email,
			}).Errorf("Invalid email")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Valid request
		logger.Debugf("Allowing valid request ")
		w.Header().Set("X-Forwarded-User", email)
		w.WriteHeader(200)
	}
}

// AuthCallbackHandler handle's auth callback
func (s *Server) AuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "default", "Handling callback")

		// Check for CSRF cookie
		c, err := r.Cookie(config.CSRFCookieName)
		if err != nil {
			logger.Warn("Missing csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Validate state
		valid, providerName, redirect, err := ValidateCSRFCookie(r, c)
		if !valid {
			logger.Warnf("Error validating csrf cookie: %v", err)
			http.Error(w, "Not authorized", 401)
			return
		}

		// Get provider
		p, err := config.GetConfiguredProvider(providerName)
		if err != nil {
			logger.Warnf("Invalid provider in csrf cookie: %s, %v", providerName, err)
			http.Error(w, "Not authorized", 401)
			return
		}

		// Clear CSRF cookie
		http.SetCookie(w, ClearCSRFCookie(r))

		b, err := httputil.DumpRequest(r, true)
		if err != nil {
			logger.Warnf("httputil.DumpRequest: %v", err)
			http.Error(w, "Not authorized", 401)
			return
		}
		logger.Warnf("request dump: %s", string(b))

		redirectURI := r.URL.Query().Get("redirect_uri")
		if redirectURI == "" {
			redirectURI = "https%3A%2F%2Fauth.bizapps-mock.cisco.com%2Fcallback"
		}

		user, err := p.GetUserFromCode(r.URL.Query().Get("code"), redirectURI)
		if err != nil {
			logger.Warnf("GetUserFromCode: %v", err)
			http.Error(w, "Not authorized", 401)
			return
		}

		logger.Debug("User ID--------------------------------------------------->" + user.ID)
		logger.Debug("User Email--------------------------------------------------->" + user.Email)
		logger.Debug("User FirstName--------------------------------------------------->" + user.FirstName)
		logger.Debug("User LastName--------------------------------------------------->" + user.LastName)
		// Generate cookie
		http.SetCookie(w, MakeCookie(r, user.Email))
		http.SetCookie(w, MakeCookie(r, user.ID))
		http.SetCookie(w, MakeUserCookie(r, fmt.Sprintf("%s|%s|%s", user.Email, user.FirstName, user.LastName)))

		logger.WithFields(logrus.Fields{
			"user_Email": user.Email,
			"user_ID":    user.ID,
		}).Infof("Generated auth cookie")

		// Redirect
		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
	}
}

func (s *Server) authRedirect(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, p provider.Provider) {
	// Error indicates no cookie, generate nonce
	err, nonce := Nonce()
	if err != nil {
		logger.Errorf("Error generating nonce, %v", err)
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Set the CSRF cookie
	http.SetCookie(w, MakeCSRFCookie(r, nonce))
	logger.Debug("Set CSRF cookie and redirecting to OIDC login")

	// Forward them on
	loginUrl := p.GetLoginURL(redirectUri(r), MakeState(r, p, nonce))
	http.Redirect(w, r, loginUrl, http.StatusTemporaryRedirect)

	logger.Debug("Done")
	return
}

func (s *Server) logger(r *http.Request, rule, msg string) *logrus.Entry {
	// Create logger
	logger := log.WithFields(logrus.Fields{
		"source_ip": r.Header.Get("X-Forwarded-For"),
	})

	// Log request
	logger.WithFields(logrus.Fields{
		"rule":    rule,
		"headers": r.Header,
	}).Debug(msg)

	return logger
}
