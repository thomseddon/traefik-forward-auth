
# Kubernetes - Advanced Separate Pod Example

This is an advanced example of how to deploy traefik-forward-auth in it's own pod. This example is a good starting point for those who already have traefik deployed (e.g. using helm).

This example uses [Selective Authentication](https://github.com/thomseddon/traefik-forward-auth/blob/master/README.md#selective-ingress-authentication-in-kubernetes) to selectively apply forward authentication to each selective ingress, a simple example "whoami" application (deployment, service and ingress) is included for completeness.

This example leverages kustomise to define Secrets and ConfigMaps, example deployment:

```
# Deploy traefik-forward-auth
kubectl apply -k traefik-forward-auth

# Deploy example whoami app
kubectl apply -k whoami
```
