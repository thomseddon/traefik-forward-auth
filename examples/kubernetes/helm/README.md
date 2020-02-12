# Traefik-Foward-Auth Helm Chart

This functionality is in beta and is subject to change. The design and code is less mature than official GA features and is being provided as-is with no warranties. Beta features are not subject to the support SLA of official GA features.

## Requirements

* [Helm](https://helm.sh/) >=2.8.0 and <3.0.0 (see parent [README](https://github.com/elastic/helm-charts/tree/master/README.md) for more details)
* Kubernetes >=1.8
* Minimum cluster requirements include the following to run this chart with default settings. All of these settings are configurable.
  * Three Kubernetes nodes to respect the default "hard" affinity settings
  * 1GB of RAM for the JVM heap

## Usage notes and getting started

* This repo includes a number of [example](https://github.com/elastic/helm-charts/tree/master/elasticsearch/examples) configurations which can be used as a reference. They are also used in the automated testing of this chart
* Automated testing of this chart is currently only run against GKE (Google Kubernetes Engine).
* The chart deploys a statefulset and by default will do an automated rolling update of your cluster. It does this by waiting for the cluster health to become green after each instance is updated. If you prefer to update manually you can set [`updateStrategy: OnDelete`](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/#on-delete)
* It is important to verify that the JVM heap size in `esJavaOpts` and to set the CPU/Memory `resources` to something suitable for your cluster
* To simplify chart and maintenance each set of node groups is deployed as a separate helm release. Take a look at the [multi](https://github.com/elastic/helm-charts/tree/master/elasticsearch/examples/multi) example to get an idea for how this works. Without doing this it isn't possible to resize persistent volumes in a statefulset. By setting it up this way it makes it possible to add more nodes with a new storage size then drain the old ones. It also solves the problem of allowing the user to determine which node groups to update first when doing upgrades or changes.
* We have designed this chart to be very un-opinionated about how to configure Elasticsearch. It exposes ways to set environment variables and mount secrets inside of the container. Doing this makes it much easier for this chart to support multiple versions with minimal changes.


## Installing

### Using Helm repository

* Add the elastic helm charts repo
  ```
  helm repo add elastic https://helm.elastic.co
  ```
* Install it
  ```
  helm install --name elasticsearch elastic/elasticsearch
  ```

### Using master branch

* Clone the git repo
  ```
  git clone git@github.com:elastic/helm-charts.git
  ```
* Install it
  ```
  helm install --name elasticsearch ./helm-charts/elasticsearch
  ```

## Configuration

| Parameter                     | Description                                                                                                                                           | Default                                                                                                                   |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `namespace`                   | This is used to override the namespace.                                                                                                               | `kube-system`                                                                                                           |
| `port`                        | This is used to override the port.                                                                                                                    | `80`                                                                                                           |
| `service.labels`              | Labels to be added to non-headless service.                                                                                                           | `{}`                                                                                                                      |
| `service.annotations`         | Annotations that Kubernetes will use for the service.                                                                                                 | `{}`                                                                                                                      |

## Try it out

In [examples/](https://github.com/elastic/helm-charts/tree/master/elasticsearch/examples) you will find some example configurations. These examples are used for the automated testing of this helm chart


### FAQ

#### How to do X?

Y



