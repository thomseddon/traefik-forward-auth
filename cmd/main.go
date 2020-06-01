package main

import (
	"net/http"

	internal "github.com/thomseddon/traefik-forward-auth/internal"
)

// Main
func main() {
	// Parse options
	config := internal.NewGlobalConfig()

	// Setup logger
	log := internal.NewDefaultLogger()

	// Perform config validation
	config.Validate()

	// Build server
	server := internal.NewServer()

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	// Start
	log.WithField("config", config).Debug("Starting with config")
	log.Info("Listening on :4181")
	log.Info(http.ListenAndServe(":4181", nil))
}
