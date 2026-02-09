FROM golang:1.24-alpine AS build

WORKDIR /app

COPY go.mod ./
COPY main.go ./

RUN CGO_ENABLED=0 go build -o /bin/oauth-client main.go

FROM alpine:latest

RUN apk add --no-cache ca-certificates

COPY --from=build /bin/oauth-client /bin/oauth-client

EXPOSE 5555

CMD ["/bin/oauth-client"]
