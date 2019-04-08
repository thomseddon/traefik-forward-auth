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

	// add routes for existing containers
	if err := dc.inspectContainers(); err != nil {
		panic(err)
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
			if m.Type == "container" {
				log.Debug(m.Status)
				if m.Status == "start" {
					if dc.containerLabeled(m.Actor.Attributes) {
						log.Debugf("Received %s event for labeled container %s", m.Status, m.Actor.ID[:10])
						dc.addCountainerRoutes(m.Actor.ID, m.Actor.Attributes)
					}
				} else if m.Status == "destroy" {
					// destroy event happens after die
					// at this time inspectContainers will no longer find it
					if dc.containerLabeled(m.Actor.Attributes) {
						log.Debugf("Received %s event for labeled container %s", m.Status, m.Actor.ID[:10])
						dc.removeCountainerRoutes()
					}
				}
			}
		}
	}
}

// inspectContainers looks for containers wiht matching prefix.
// If container has matching labels, a route is created
func (dc *DockerClient) inspectContainers() error {
	containers, err := dc.docker.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		return err
	}

	for _, container := range containers {
		if dc.containerLabeled(container.Labels) {
			log.Debugf("Found labeled container %s (%s)", container.ID[:10], container.Image)
			dc.addCountainerRoutes(container.ID, container.Labels)
		}
	}

	return nil
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

// AddCountainerRoutes creates routes according to the container's labels
func (dc *DockerClient) addCountainerRoutes(id string, labels map[string]string) {
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
	dc.server.attachHandler(match, action)
}

// removeCountainerRoutes removes routes by rebuilding the entire route configuration
func (dc *DockerClient) removeCountainerRoutes() {
	// since we cannot remove routes they need be created from scratch
	dc.server.RebuildRoutes()
	// re-add routes for labeled containers
	dc.inspectContainers()
}
