package tfa

import (
	"net/http"
	"net/url"

	"github.com/containous/traefik/pkg/rules"
	"github.com/sirupsen/logrus"

	"strings"
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
		if rule.Action == "allow" {
			s.router.AddRoute(rule.formattedRule(), 1, s.AllowHandler(name))
		} else {
			s.router.AddRoute(rule.formattedRule(), 1, s.AuthHandler(name))
		}
	}

	// Add callback handler
	s.router.Handle(config.Path, s.AuthCallbackHandler())

	// Add a default handler
	if config.DefaultAction == "allow" {
		s.router.NewRoute().Handler(s.AllowHandler("default"))
	} else {
		s.router.NewRoute().Handler(s.AuthHandler("default"))
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
func (s *Server) AuthHandler(rule string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, rule, "Authenticating request")

		// Get auth cookie
		c, err := r.Cookie(config.CookieName)
		if err != nil {
			s.authRedirect(logger, w, r)
			return
		}

		// Validate cookie
		email, err := ValidateCookie(r, c)
		if err != nil {
			if err.Error() == "Cookie has expired" {
				logger.Info("Cookie has expired")
				s.authRedirect(logger, w, r)
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

// Handle auth callback
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
		valid, redirect, err := ValidateCSRFCookie(r, c)
		if !valid {
			logger.Warnf("Error validating csrf cookie: %v", err)
			http.Error(w, "Not authorized", 401)
			return
		}

		// Clear CSRF cookie
		http.SetCookie(w, ClearCSRFCookie(r))

		// Exchange code for token
		token, err := ExchangeCode(r)
		if err != nil {
			logger.Errorf("Code exchange failed with: %v", err)
			http.Error(w, "Service unavailable", 503)
			return
		}

		// Get user
		user, err := GetUser(token)
		if err != nil {
			logger.Errorf("Error getting user: %s", err)
			return
		}

		//Validate redirect
		allowedHostForRedirect := redirectBase(r)
		if !strings.HasPrefix(redirect+"/", allowedHostForRedirect+"/") {
			logger.Errorf("Redirection %v does not match the redirectBase", redirect)
			http.Error(w, "Not authorized", 401)
			return
		}

		// Generate cookie
		http.SetCookie(w, MakeCookie(r, user.Email))
		logger.WithFields(logrus.Fields{
			"user": user.Email,
		}).Infof("Generated auth cookie")

		// Redirect
		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
	}
}

func (s *Server) authRedirect(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) {
	// Error indicates no cookie, generate nonce
	err, nonce := Nonce()
	if err != nil {
		logger.Errorf("Error generating nonce, %v", err)
		http.Error(w, "Service unavailable", 503)
		return
	}

	// Set the CSRF cookie
	http.SetCookie(w, MakeCSRFCookie(r, nonce))
	logger.Debug("Set CSRF cookie and redirecting to google login")

	// Forward them on
	http.Redirect(w, r, GetLoginURL(r, nonce), http.StatusTemporaryRedirect)

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
