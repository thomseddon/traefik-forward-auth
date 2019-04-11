package main

import (
	"reflect"
	"sort"
	"testing"
)

func TestTraefikHostsFromLabels(t *testing.T) {
	labels := map[string]string{
		"traefik.http.routers.Router1.rule": "Host(`foo.bar`)||Host(`foo.baz`)",
		"traefik.http.routers.Router2.rule": "Host(`me.too`)",
	}
	expect := []string{"foo.bar", "foo.baz", "me.too"}

	d := Traefiker{}
	hosts := d.parseHostsFromLabels(labels)
	sort.Strings(hosts)

	if !reflect.DeepEqual(hosts, expect) {
		t.Errorf("Could not get host list from labels, got: %v", hosts)
	}
}
