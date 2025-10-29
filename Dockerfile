# syntax=docker/dockerfile:1
FROM golang:1.22 AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/as ./cmd/as
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/rs ./cmd/rs || true

FROM gcr.io/distroless/base-debian12
COPY --from=build /bin/as /bin/as
COPY --from=build /bin/rs /bin/rs
EXPOSE 8080 9090
USER 65532:65532
ENTRYPOINT ["/bin/as"]
