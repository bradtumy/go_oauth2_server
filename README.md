# Go OAuth2 Server

A lightweight OAuth2 Authorization Server implemented in Go, designed for educational use, prototyping, and building secure authentication workflows.

## Overview

This project demonstrates a minimal yet functional OAuth2 Authorization Server using Go. It handles standard OAuth2 flows and can be used to issue and validate access tokens for protected resources.

Built using:
- [Go (Golang)](https://golang.org/)
- [go-oauth2](https://github.com/go-oauth2/oauth2) library
- [gorilla/mux](https://github.com/gorilla/mux) for routing

## Features

- Authorization Code Grant support
- Token issuance via `/token` endpoint
- Sample client credential flow
- JWT token generation and validation
- In-memory token and client storage (can be extended)
- Sample HTML UI for testing authorization flow

## Project Structure

```bash
.
├── main.go # Entry point
├── handler.go # HTTP handlers
├── server.go # OAuth2 server config and setup
├── store.go # Client and token store implementations
├── templates/ # HTML templates for UI
└── static/ # Static files (JS, CSS)
```

## Getting Started

### Prerequisites

- Go 1.20+ installed
- Git

### Clone & Run

```bash
git clone https://github.com/bradtumy/go_oauth2_server.git
cd go_oauth2_server
go run main.go
```

The server will start on http://localhost:9096.


### Testing the Flow

Visit http://localhost:9096/authorize in your browser.
Provide client_id, response_type, and redirect_uri.
Complete the authorization form.
Get redirected with an authorization code.
Exchange the code for a token at /token.

## Example cURL Token Request
```bash
curl -X POST http://localhost:9096/token \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=http://localhost:9094/callback" \
  -u "client_id:client_secret"
```

## Future Enhancements

* Persistent storage (e.g. PostgreSQL, Redis)
* PKCE and other OAuth2 extensions
* Improved user authentication
* OpenID Connect support

## License

MIT

## Author

Brad Tumy – @bradtumy