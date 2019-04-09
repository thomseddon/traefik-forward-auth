FROM golang:1.10-alpine as builder

# Setup
RUN mkdir -p /go/src/github.com/thomseddon/traefik-forward-auth
WORKDIR /go/src/github.com/thomseddon/traefik-forward-auth

# Add libraries
RUN apk add --no-cache git && \
  go get "github.com/BurntSushi/toml" && \
  go get "github.com/gorilla/mux" && \
  go get "github.com/namsral/flag" && \
  go get "github.com/sirupsen/logrus" && \
  go get "github.com/docker/docker/client" && \
  go get "github.com/docker/docker/api/types" && \
  apk del git

# Copy & build
ADD . /go/src/github.com/thomseddon/traefik-forward-auth/
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix nocgo -o /traefik-forward-auth .

# Copy into scratch container
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /traefik-forward-auth ./
ENTRYPOINT ["./traefik-forward-auth"]
