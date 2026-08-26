# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /app
COPY go.mod ./
RUN go mod download
RUN apk add --no-cache gcc musl-dev sqlite sqlite-dev
COPY . .
RUN CGO_ENABLED=1 go build -o /bin/as ./cmd/as
RUN CGO_ENABLED=1 go build -o /bin/rs ./cmd/rs

FROM alpine:latest
RUN apk add --no-cache ca-certificates sqlite
COPY --from=build /bin/as /bin/as
COPY --from=build /bin/rs /bin/rs
COPY --from=build /app/web /web
EXPOSE 8080 9090
USER 65532:65532
CMD ["/bin/as"]
