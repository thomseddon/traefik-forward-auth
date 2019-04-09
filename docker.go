package main

import (
	"context"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"
)

const labelPrefix = "forward-auth."

type DockerClient struct {
	docker *client.Client
	server *Server
}

func NewDockerClient(server *Server) *DockerClient {
	cli, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}

	dc := &DockerClient{
		docker: cli,
		server: server,
	}

	// dynamically manage routes for container events
	messages, _ := dc.docker.Events(context.Background(), types.EventsOptions{})
	go dc.handleEvents(messages)

	return dc
}

// handleEvents handles container start/die events to reconfigure server routes
func (dc *DockerClient) handleEvents(messages <-chan events.Message) {
	for {
		select {
		case m := <-messages:
			if m.Type == "container" &&
				(m.Status == "start" || m.Status == "destroy") &&
				dc.containerLabeled(m.Actor.Attributes) {
				log.Debugf("Received %s event for labeled container %s", m.Status, m.Actor.ID[:10])
				dc.server.BuildRoutes()
			}
		}
	}
}

func (dc *DockerClient) Rules() (rules []Rules) {
	containers, err := dc.docker.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		log.Error(err)
		return rules
	}

	for _, container := range containers {
		if dc.containerLabeled(container.Labels) {
			log.Debugf("Found labeled container %s (%s)", container.ID[:10], container.Image)
			rule := dc.getCountainerRule(container.ID, container.Labels)
			log.Debug(rule)
			rules = append(rules, rule)
		}
	}

	log.Debug(rules)
	return rules
}

// AddCountainerRoutes creates routes according to the container's labels
func (dc *DockerClient) getCountainerRule(id string, labels map[string]string) Rules {
	action := labels[labelPrefix+"action"]
	if action == "" {
		action = "auth"
		log.Warnf("Container %s is missing action label - assuming \"%s\"", id[:10], action)
	}

	match := &Match{}

	// TODO allow multiple hosts
	if host, ok := labels[labelPrefix+"host"]; ok {
		match.Host = append(match.Host, host)
	}

	// TODO allow multiple hosts
	if pathprefix, ok := labels[labelPrefix+"pathprefix"]; ok {
		match.PathPrefix = append(match.PathPrefix, pathprefix)
	}

	// TODO handle headers
	log.Debugf("Container %s added action %s for route: %v", id[:10], action, match)

	rule := Rules{
		Action: action,
		Match:  []Match{*match},
	}

	return rule
}

// containerLabeled checks if a container is labeled with the "forward-auth" prefix
func (dc *DockerClient) containerLabeled(labels map[string]string) bool {
	for label := range labels {
		if strings.HasPrefix(label, labelPrefix) {
			return true
		}
	}

	return false
}
