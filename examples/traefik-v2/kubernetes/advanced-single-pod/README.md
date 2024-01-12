
# Kubernetes - Advanced Single Pod Example

This is an advanced example of how to deploy traefik and traefik-forward-auth in a single pod. This example is a good starting point for those who already have a manually defined traefik config (e.g. not using helm).

This example uses [Global Authentication](https://github.com/thomseddon/traefik-forward-auth/blob/master/README.md#global-authentication) to apply authentication for the entire `https` entrypoint.

This example also includes SSL via traefik acme/lesencrypt, auth host mode, exposes the traefik dashboard and leverages kustomise. No special config if required for your applications, but a simple example "whoami" application (deployment, service and ingress) is included for completeness.

Example deployment:

```
# Deploy traefik+traefik-forward-auth
kubectl apply -k traefik

# Deploy whoami app
kubectl apply -k whoami
```
