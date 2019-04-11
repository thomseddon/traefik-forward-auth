package main

import (
	"context"
	"fmt"

	"github.com/containous/traefik/pkg/provider/label"
	"github.com/containous/traefik/pkg/rules"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"
)

const labelPrefix = "forward-auth."

type Traefiker struct{}

func (dc *Traefiker) parseHostsFromLabels(labels map[string]string) []string {
	conf, err := label.DecodeConfiguration(labels)
	if err != nil {
		return []string{}
	}

	hosts := make([]string, 0)
	for _, router := range conf.HTTP.Routers {
		if ruleHosts, err := rules.ParseDomains(router.Rule); err == nil {
			for _, host := range ruleHosts {
				hosts = append(hosts, host)
			}
		} else {
			return []string{}
		}
	}

	return hosts
}

type DockerClient struct {
	*Traefiker
	docker *client.Client
	rules  chan<- []Rules
}

func NewDockerClient(rulesChan chan<- []Rules) *DockerClient {
	cli, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}

	dc := &DockerClient{
		docker: cli,
		rules:  rulesChan,
	}

	// initial rules
	dc.updateRules()

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
				(m.Status == "start" || m.Status == "destroy") {
				log.Debugf("Received %s event for labeled container %s", m.Status, m.Actor.ID[:10])
				dc.updateRules()
			}
		}
	}
}

func (dc *DockerClient) updateRules() {
	dc.rules <- dc.collectRules()
}

// collectRules iterates all running containers and collects their rules
func (dc *DockerClient) collectRules() (rules []Rules) {
	containers, err := dc.docker.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		log.Error(err)
		return rules
	}

	for _, container := range containers {
		log.Debugf("Found labeled container %s (%s)", container.ID[:10], container.Image)
		rule, err := dc.getCountainerRule(container.ID, container.Labels)
		if err != nil {
			log.Error(err)
			continue
		}

		rules = append(rules, rule)
	}

	return rules
}

// getCountainerRule derives rule from the container's labels
func (dc *DockerClient) getCountainerRule(id string, labels map[string]string) (Rules, error) {
	action := labels[labelPrefix+"action"]
	if action == "" {
		action = "auth"
	}

	match := &Match{}

	// TODO allow multiple hosts
	if host, ok := labels[labelPrefix+"host"]; ok {
		match.Host = append(match.Host, host)
	} else {
		return Rules{}, fmt.Errorf("Container %s is missing host label, ignoring", id[:10])
	}

	// TODO allow multiple hosts
	if pathprefix, ok := labels[labelPrefix+"pathprefix"]; ok {
		match.PathPrefix = append(match.PathPrefix, pathprefix)
	}

	rule := Rules{
		Action: action,
		Match:  []Match{*match},
	}

	return rule, nil
}
