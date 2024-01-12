# Kubernetes - Advanced Separate Pod Example

This is an advanced example of how to deploy traefik-forward-auth in it's own pod. This example is a good starting point for those who already have traefik deployed (e.g. using helm).

This example uses [Selective Authentication](https://github.com/thomseddon/traefik-forward-auth/blob/master/README.md#selective-ingress-authentication-in-kubernetes) to selectively apply forward authentication to each selective ingresses, for example:

```
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: whoami
  labels:
    app: whoami
spec:
  entryPoints:
    - https
  routes:
  - match: Host(`whoami.example.com`)
    kind: Rule
    services:
      - name: whoami
        port: 80
    middlewares:
      - name: traefik-forward-auth
  tls:
    certresolver: default
```

This example also includes SSL via traefik acme/lesencrypt, auth host mode, and leverages kustomise. A simple example "whoami" application (deployment, service and ingress) is included for completeness.

Example deployment:

```
# Deploy traefik-forward-auth
kubectl apply -k traefik-forward-auth

# Deploy example whoami app
kubectl apply -k whoami
```
