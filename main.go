package main

import (
	"encoding/json"
	"net/http"

	"github.com/sirupsen/logrus"
)

// Vars
var fw *ForwardAuth
var log logrus.FieldLogger
var config *Config

// Main
func main() {
	// Parse config
	config = NewParsedConfig()

	// Setup logger
	log = NewLogger()

	// Perform config checks
	config.Checks()

	// Build forward auth handler
	fw = NewForwardAuth()

	// Build server
	server := NewServer()

	// Create docker client
	if config.DockerEnabled {
		docker := NewDockerClient(server)
		server.addRulesProvider(docker)
		server.BuildRoutes() // rebuild
	}

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	// Start
	jsonConf, _ := json.Marshal(config)
	log.Debugf("Starting with options: %s", string(jsonConf))
	log.Info("Listening on :4181")
	log.Info(http.ListenAndServe(":4181", nil))
}
