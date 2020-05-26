
# Kubernetes - Simple Separate Pod Example

This is a simple example of how to deploy traefik-forward-auth in it's own pod with minimal configuration. This example is a good starting point for those who already have traefik deployed (e.g. using helm).

This example uses [Selective Authentication](https://github.com/thomseddon/traefik-forward-auth/blob/master/README.md#selective-ingress-authentication-in-kubernetes) to apply forward authentication to selected ingresses. This means ingresses will not be protected by default. Authentication can be applied by adding the `traefik-forward-auth` middleware, for example:

```
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: whoami
  labels:
    app: whoami
spec:
  entryPoints:
    - http
  routes:
  - match: Host(`whoami.example.com`)
    kind: Rule
    services:
      - name: whoami
        port: 80
    middlewares:
      - name: traefik-forward-auth
```

A minimal application example is provided in `k8s-app.yml`.

Example deployment:
```
# Deploy traefik-forward-auth
kubectl apply -f k8s-traefik-forward-auth.yml

# Deploy example whoami app
kubectl apply -f k8s-app.yml
```

Please see the advanced examples for more details.
