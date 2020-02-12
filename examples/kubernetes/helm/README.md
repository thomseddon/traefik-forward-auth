# Traefik-Foward-Auth Helm Chart

This functionality is in beta and is subject to change.

## Requirements

* [Helm](https://helm.sh/) >=2.8.0 and <3.0.0 
* Kubernetes >=1.8

## Usage notes and getting started

* TODO

## Installing

### Using Helm repository

* Not yet supported. 

### Using master branch

* Clone the git repo
  ```
  git clone git@github.com:thomseddon/traefik-forward-auth.git
  ```
* Install it
  ```
  helm install --name traefik-forward-auth ./traefik-forward-auth/examples/kubernetes/helm --values traefik-foward-auth/exmples/kubernetes/helm/values.yml
  ```

## Configuration

| Parameter                     | Description                                                                                                                                           | Default                                                                                                                   |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `namespace`                   | This is used to override the namespace.                                                                                                               | `kube-system`                                                                                                           |
| `port`                        | This is used to override the port.                                                                                                                    | `80`                                                                                                           |
| `service.labels`              | Labels to be added to non-headless service.                                                                                                           | `{}`                                                                                                                      |
| `service.annotations`         | Annotations that Kubernetes will use for the service.                                                                                                 | `{}`                                                                                                                      |

## Try it out

TODO

### FAQ

#### How to do TODO?

TODO



