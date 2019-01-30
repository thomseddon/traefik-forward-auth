package main

import (
	// "fmt"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type Server struct {
	mux *mux.Router
}

func NewServer() *Server {
	s := &Server{}
	s.buildRoutes()
	return s
}

func (s *Server) buildRoutes() {
	s.mux = mux.NewRouter()

	// Let's build a server
	for _, rules := range config.Rules {
		// fmt.Printf("Rule: %s\n", name)
		for _, match := range rules.Match {
			s.attachHandler(&match, rules.Action)
		}
	}

	// Add callback handler
	s.mux.Handle(config.Path, s.AuthCallbackHandler())

	// Add a default handler
	s.mux.NewRoute().Handler(s.AuthHandler())
}

func (s *Server) RootHandler(w http.ResponseWriter, r *http.Request) {
	// Modify request
	r.URL, _ = url.Parse(r.Header.Get("X-Forwarded-Uri"))

	// Pass to mux
	s.mux.ServeHTTP(w, r)
}

// Handler that allows requests
func (s *Server) AllowHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logger(r, "Allowing request")
		w.WriteHeader(200)
	}
}

// Authenticate requests
func (s *Server) AuthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "Authenticating request")

		// Get auth cookie
		c, err := r.Cookie(config.CookieName)
		if err != nil {
			// Error indicates no cookie, generate nonce
			err, nonce := fw.Nonce()
			if err != nil {
				logger.Errorf("Error generating nonce, %v", err)
				http.Error(w, "Service unavailable", 503)
				return
			}

			// Set the CSRF cookie
			http.SetCookie(w, fw.MakeCSRFCookie(r, nonce))
			logger.Debug("Set CSRF cookie and redirecting to google login")

			// Forward them on
			http.Redirect(w, r, fw.GetLoginURL(r, nonce), http.StatusTemporaryRedirect)

			return
		}

		// Validate cookie
		valid, email, err := fw.ValidateCookie(r, c)
		if !valid {
			logger.Errorf("Invalid cookie: %v", err)
			http.Error(w, "Not authorized", 401)
			return
		}

		// Validate user
		valid = fw.ValidateEmail(email)
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
		logger := s.logger(r, "Handling callback")

		// Check for CSRF cookie
		c, err := r.Cookie(config.CSRFCookieName)
		if err != nil {
			logger.Warn("Missing csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Validate state
		valid, redirect, err := fw.ValidateCSRFCookie(r, c)
		if !valid {
			logger.Warnf("Error validating csrf cookie: %v", err)
			http.Error(w, "Not authorized", 401)
			return
		}

		// Clear CSRF cookie
		http.SetCookie(w, fw.ClearCSRFCookie(r))

		// Exchange code for token
		token, err := fw.ExchangeCode(r)
		if err != nil {
			logger.Errorf("Code exchange failed with: %v", err)
			http.Error(w, "Service unavailable", 503)
			return
		}

		// Get user
		user, err := fw.GetUser(token)
		if err != nil {
			logger.Errorf("Error getting user: %s", err)
			return
		}

		// Generate cookie
		http.SetCookie(w, fw.MakeCookie(r, user.Email))
		logger.WithFields(logrus.Fields{
			"user": user.Email,
		}).Infof("Generated auth cookie")

		// Redirect
		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
	}
}

// Build a handler for a given matcher
func (s *Server) attachHandler(m *Match, action string) {
	// Build a new route matcher
	route := s.mux.NewRoute()

	for _, host := range m.Host {
		route.Host(host)
	}

	for _, pathPrefix := range m.PathPrefix {
		route.PathPrefix(pathPrefix)
	}

	for _, header := range m.Header {
		if len(header) != 2 {
			panic("todo")
		}

		route.Headers(header[0], header[1])
	}

	// Add handler to new route
	if action == "allow" {
		route.Handler(s.AllowHandler())
	} else {
		route.Handler(s.AuthHandler())
	}
}

func (s *Server) logger(r *http.Request, msg string) *logrus.Entry {
	// Create logger
	logger := log.WithFields(logrus.Fields{
		"RemoteAddr": r.RemoteAddr,
	})

	// Log request
	logger.WithFields(logrus.Fields{
		"Headers": r.Header,
	}).Debugf(msg)

	return logger
}
