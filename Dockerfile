FROM golang:1.13-alpine as builder

# build
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

RUN case "${TARGETVARIANT}" in \
	"armhf") export GOARM='6' ;; \
	"armv7") export GOARM='6' ;; \
	"v6") export GOARM='6' ;; \
	"v7") export GOARM='7' ;; \
	esac;

# Add libraries
RUN apk add --no-cache git make ca-certificates

# Setup
WORKDIR /build

# download modules
COPY go.mod .
COPY go.sum .
RUN go mod download


# Copy & build
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} GO111MODULE=on make build

# Copy into scratch container
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/traefik-forward-auth ./
ENTRYPOINT ["./traefik-forward-auth"]
