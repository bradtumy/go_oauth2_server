# syntax=docker/dockerfile:1
FROM golang:1.24 AS build
WORKDIR /app
COPY go.mod ./
RUN go mod download
RUN apt-get update && apt-get install -y sqlite3 && rm -rf /var/lib/apt/lists/*
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/as ./cmd/as
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /bin/rs ./cmd/rs || true

FROM gcr.io/distroless/base-debian12
COPY --from=build /bin/as /bin/as
COPY --from=build /bin/rs /bin/rs
COPY --from=build /usr/bin/sqlite3 /usr/bin/sqlite3
EXPOSE 8080 9090
USER 65532:65532
CMD ["/bin/as"]
