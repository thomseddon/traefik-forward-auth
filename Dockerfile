FROM alpine AS certs

RUN apk add ca-certificates

# Copy into scratch container
FROM --platform=$TARGETOS/$TARGETARCH alpine
ARG TARGETARCH
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --chmod=755 $TARGETARCH/traefik-forward-auth ./
ENTRYPOINT ["./traefik-forward-auth"]
