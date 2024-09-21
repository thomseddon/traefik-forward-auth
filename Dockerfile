FROM --platform=${BUILDPLATFORM} golang:1-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /out/traefik-forward-auth ./cmd

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/traefik-forward-auth ./
ENTRYPOINT ["./traefik-forward-auth"]
