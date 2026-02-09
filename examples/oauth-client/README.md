# OAuth Client Demo

A simple OAuth 2.0 client that demonstrates the authorization code flow with PKCE.

## Run the Client

```bash
cd examples/oauth-client
go run main.go
```

The client will start on http://localhost:5555

## How to Use

1. Make sure the Authorization Server is running (via Docker or locally on port 8080)

2. Start the OAuth client:
   ```bash
   cd examples/oauth-client
   go run main.go
   ```

3. Open your browser to http://localhost:5555

4. Click "Login with OAuth"

5. You'll be redirected to the authorization server to login (if not already logged in)

6. Review and approve the consent page

7. You'll be redirected back to the client with your access token displayed

## What It Does

- **PKCE Support**: Generates code verifier and challenge for secure authorization
- **State Parameter**: Uses random state for CSRF protection
- **Token Exchange**: Automatically exchanges authorization code for access tokens
- **Visual Feedback**: Shows all tokens in an easy-to-read format

## Configuration

Edit the variables at the top of `main.go` to customize:

```go
clientID     = "human-web"
authURL      = "http://localhost:8080/oauth2/authorize"
tokenURL     = "http://localhost:8080/oauth2/token"
redirectURI  = "http://localhost:5555/callback"
scope        = "tickets.read"
```
