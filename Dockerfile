FROM --platform=$BUILDPLATFORM golang:1.22-alpine as builder

# Setup
WORKDIR /go/src/github.com/thomseddon/traefik-forward-auth

# Install deps
COPY go.mod /go/src/github.com/thomseddon/traefik-forward-auth/
COPY go.sum /go/src/github.com/thomseddon/traefik-forward-auth/
RUN go mod download

# Copy & build
ADD . /go/src/github.com/thomseddon/traefik-forward-auth/
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0  GOOS=${TARGETOS} GOARCH=${TARGETARCH} GO111MODULE=on go build -a -installsuffix nocgo -o /traefik-forward-auth github.com/thomseddon/traefik-forward-auth/cmd

# Copy into scratch container
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /traefik-forward-auth ./
ENTRYPOINT ["./traefik-forward-auth"]
