FROM golang:1.13-alpine as builder

# Setup
RUN mkdir -p /go/src/github.com/mindful-dev/traefik-forward-auth
WORKDIR /go/src/github.com/mindful-dev/traefik-forward-auth

# Add libraries
RUN apk add --no-cache git

# Copy & build
ADD . /go/src/github.com/mindful-dev/traefik-forward-auth/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -installsuffix nocgo -o /traefik-forward-auth github.com/thomseddon/traefik-forward-auth/cmd

# Copy into scratch container
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /traefik-forward-auth ./
ENTRYPOINT ["./traefik-forward-auth"]
