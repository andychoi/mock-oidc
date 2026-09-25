# Multi-stage build: static Go binary on distroless.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /mock-oidc ./cmd/mock-oidc

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /mock-oidc /mock-oidc
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/mock-oidc"]
