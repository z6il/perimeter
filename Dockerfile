# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/perimeter . \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/z6il/perimeter" \
      org.opencontainers.image.description="Self-hosted monitor for unexpected open ports, expiring certificates, DNS changes and new subdomains" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/perimeter /perimeter
COPY --from=build --chown=65532:65532 /out/data /data
ENV PERIMETER_ADDR=:8080 PERIMETER_DATA=/data
VOLUME /data
EXPOSE 8080
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s CMD ["/perimeter", "-healthcheck"]
ENTRYPOINT ["/perimeter"]
