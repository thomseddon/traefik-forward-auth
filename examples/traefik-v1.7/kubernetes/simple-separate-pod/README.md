
# Kubernetes - Simple Separate Pod Example

This is a simple example of how to deploy traefik-forward-auth in it's own pod with minimal configuration. This example is a good starting point for those who already have traefik deployed (e.g. using helm).

This example uses annotations to apply authentication to selected ingresses (see `k8s-app.yml`). This means ingresses will not be protected by default, only those with these annotations will require forward authentication. For example:

```
#
# Ingress
#
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: whoami
  labels:
    app: whoami
  annotations:
    kubernetes.io/ingress.class: traefik
    ingress.kubernetes.io/auth-type: forward
    ingress.kubernetes.io/auth-url: http://traefik-forward-auth:4181
    ingress.kubernetes.io/auth-response-headers: X-Forwarded-User
spec:
  rules:
  - host: whoami.example.com
    http:
      paths:
      - backend:
          serviceName: whoami
          servicePort: http
```


Example deployment:
```
# Deploy traefik-forward-auth
kubectl apply -f k8s-traefik-forward-auth.yml

# Deploy example whoami app
kubectl apply -f k8s-app.yml
```

Please see the advanced examples for more details.
