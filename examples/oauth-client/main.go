package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var (
	clientID    = getEnv("CLIENT_ID", "human-web")
	authURL     = getEnv("AUTH_URL", "http://localhost:8080/oauth2/authorize")
	tokenURL    = getEnv("TOKEN_URL", "http://localhost:8080/oauth2/token")
	redirectURI = getEnv("REDIRECT_URI", "http://localhost:5555/callback")
	scope       = getEnv("SCOPE", "tickets.read")
	rsURL       = getEnv("RS_URL", "http://localhost:9090")

	// Store PKCE verifier and state per session (in production, use proper session management)
	codeVerifier string
	state        string
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func main() {
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)

	log.Println("OAuth client running on http://localhost:5555")
	log.Println("Visit http://localhost:5555 to start the OAuth flow")
	log.Fatal(http.ListenAndServe(":5555", nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>OAuth Client Demo</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
        }
        .btn {
            display: inline-block;
            padding: 12px 24px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            transition: transform 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
        }
        p {
            color: #666;
            line-height: 1.6;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>OAuth 2.0 Client Demo</h1>
        <p>This demo application shows the OAuth 2.0 authorization code flow with PKCE.</p>
        <p>Click the button below to start the authentication process:</p>
        <a href="/login" class="btn">Login with OAuth</a>
    </div>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	// Generate PKCE code verifier and challenge
	codeVerifier = generateCodeVerifier()
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Generate random state for CSRF protection
	state = generateRandomString(16)

	// Build authorization URL
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", scope)
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")

	authorizationURL := authURL + "?" + params.Encode()

	log.Printf("Redirecting to authorization URL: %s", authorizationURL)
	http.Redirect(w, r, authorizationURL, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	// Extract code and state from query parameters
	code := r.URL.Query().Get("code")
	returnedState := r.URL.Query().Get("state")
	errorCode := r.URL.Query().Get("error")
	errorDesc := r.URL.Query().Get("error_description")

	// Check for OAuth errors
	if errorCode != "" {
		html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Authorization Error</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .error {
            color: #dc2626;
            padding: 15px;
            background: #fee;
            border-radius: 4px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Authorization Error</h1>
        <div class="error">
            <strong>Error:</strong> %s<br>
            <strong>Description:</strong> %s
        </div>
        <a href="/">Try again</a>
    </div>
</body>
</html>`, errorCode, errorDesc)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
		return
	}

	// Validate state
	if returnedState != state {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	if code == "" {
		http.Error(w, "No authorization code received", http.StatusBadRequest)
		return
	}

	log.Printf("Received authorization code: %s", code)

	// Exchange code for tokens
	tokens, err := exchangeCodeForTokens(code)
	if err != nil {
		log.Printf("Token exchange error: %v", err)
		http.Error(w, fmt.Sprintf("Failed to exchange code for tokens: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("Successfully obtained tokens!")
	log.Printf("Access Token: %s", tokens.AccessToken)
	log.Printf("Token Type: %s", tokens.TokenType)
	log.Printf("Expires In: %d seconds", tokens.ExpiresIn)
	if tokens.RefreshToken != "" {
		log.Printf("Refresh Token: %s", tokens.RefreshToken)
	}

	// Decode the access token to show its contents. The refresh token is
	// deliberately not decoded: it is an opaque handle, not a JWT.
	accessTokenClaims := decodeJWT(tokens.AccessToken)

	// Test the token by calling the Resource Server
	rsResponse, rsStatus := callResourceServer(tokens.AccessToken)

	// Display success page
	refreshTokenHTML := ""
	if tokens.RefreshToken != "" {
		refreshTokenHTML = fmt.Sprintf(`
                <div class="label">Refresh Token (opaque handle):</div>
                <div class="token-box">%s</div>
                <div class="metadata">Use this to obtain new access tokens without re-authenticating.
                Unlike the access token, it is not a JWT and carries no claims: it is a random
                identifier the authorization server stores and looks up, which is what lets it be
                revoked and lets replay of a rotated token be detected.</div>`, tokens.RefreshToken)
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorization Successful</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            max-width: 1400px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #059669;
            text-align: center;
        }
        .success {
            color: #059669;
            padding: 15px;
            background: #d1fae5;
            border-radius: 4px;
            margin: 20px 0;
            text-align: center;
        }
        .two-column {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-top: 30px;
        }
        .column {
            background: #f9fafb;
            padding: 25px;
            border-radius: 8px;
            border: 2px solid #e5e7eb;
        }
        .column h2 {
            margin-top: 0;
            color: #374151;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            font-size: 20px;
        }
        .token-box {
            background: #fff;
            border: 1px solid #e5e7eb;
            border-radius: 4px;
            padding: 12px;
            margin: 12px 0;
            word-break: break-all;
            font-family: monospace;
            font-size: 13px;
        }
        .json-box {
            white-space: pre-wrap;
            background: #1f2937;
            color: #10b981;
            border: 1px solid #374151;
            max-height: 400px;
            overflow-y: auto;
        }
        .label {
            font-weight: 600;
            color: #374151;
            margin-top: 15px;
            margin-bottom: 5px;
            font-size: 14px;
        }
        .api-call {
            background: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
        }
        .api-success {
            background: #d1fae5;
            border-left: 4px solid #10b981;
        }
        .api-error {
            background: #fee2e2;
            border-left: 4px solid #ef4444;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            margin-left: 10px;
        }
        .status-success {
            background: #d1fae5;
            color: #059669;
        }
        .status-error {
            background: #fee2e2;
            color: #dc2626;
        }
        .metadata {
            font-size: 12px;
            color: #6b7280;
            margin-top: 8px;
        }
        a {
            display: block;
            text-align: center;
            margin-top: 30px;
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>✓ Authorization Successful!</h1>
        <div class="success">
            You have successfully authenticated and obtained access tokens.
        </div>
        
        <div class="two-column">
            <!-- Left Column: Token Information -->
            <div class="column">
                <h2>🎟️ Access Token Details</h2>
                
                <div class="label">Token Type:</div>
                <div class="token-box">%s</div>
                
                <div class="label">Expires In:</div>
                <div class="token-box">%d seconds</div>
                
                <div class="label">Scope:</div>
                <div class="token-box">%s</div>
                
                <div class="label">Access Token (JWT):</div>
                <div class="token-box">%s</div>
                <div class="metadata">Use this token in the Authorization header as "Bearer [token]"</div>
                
                <div class="label">Decoded Claims:</div>
                <div class="token-box json-box">%s</div>
                <div class="metadata">These claims are validated by the Resource Server</div>
                
                %s
            </div>
            
            <!-- Right Column: API Usage -->
            <div class="column">
                <h2>🔐 Using the Token with Resource Server</h2>
                
                <p style="color: #6b7280; font-size: 14px;">The access token was automatically used to call a protected API endpoint:</p>
                
                <div class="api-call %s">
                    <strong>API Request:</strong><br>
                    <code style="font-size: 13px;">GET %s/accounts/12345/orders/export</code><br>
                    <code style="font-size: 13px;">Authorization: Bearer [access_token]</code>
                    <span class="status-badge %s">%s</span>
                </div>
                
                <div class="label">API Response:</div>
                <div class="token-box json-box">%s</div>
                <div class="metadata">%s</div>
            </div>
        </div>
        
        <a href="/">← Start Over</a>
    </div>
</body>
</html>`,
		tokens.TokenType,
		tokens.ExpiresIn,
		tokens.Scope,
		tokens.AccessToken,
		accessTokenClaims,
		refreshTokenHTML,
		func() string {
			if rsStatus >= 200 && rsStatus < 300 {
				return "api-success"
			}
			return "api-error"
		}(),
		rsURL,
		func() string {
			if rsStatus >= 200 && rsStatus < 300 {
				return "status-success"
			}
			return "status-error"
		}(),
		fmt.Sprintf("HTTP %d", rsStatus),
		rsResponse,
		func() string {
			if rsStatus >= 200 && rsStatus < 300 {
				return "✓ Success: The token was validated and the request was authorized"
			}
			return "✗ Error: The request was rejected by the Resource Server"
		}())

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func exchangeCodeForTokens(code string) (*TokenResponse, error) {
	// Prepare token request
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", clientID)
	data.Set("code_verifier", codeVerifier)

	log.Printf("Exchanging code for tokens...")
	log.Printf("Token URL: %s", tokenURL)
	log.Printf("Code: %s", code)
	log.Printf("Code Verifier: %s", codeVerifier)

	// Make token request
	resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse token response
	var tokens TokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokens, nil
}

// generateCodeVerifier generates a random code verifier for PKCE
func generateCodeVerifier() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// generateCodeChallenge generates a code challenge from a verifier using S256
func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// generateRandomString generates a random string for state parameter
func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:length]
}

// getEnv returns the value of an environment variable or a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// decodeJWT decodes a JWT token and returns the payload as formatted JSON
func decodeJWT(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "Invalid JWT format"
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Try standard base64 encoding
		payload, err = base64.RawStdEncoding.DecodeString(parts[1])
		if err != nil {
			return fmt.Sprintf("Failed to decode: %v", err)
		}
	}

	// Pretty print the JSON
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Sprintf("Failed to parse claims: %v", err)
	}

	prettyJSON, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		return string(payload)
	}

	return string(prettyJSON)
}

// callResourceServer makes a request to the Resource Server using the access token
func callResourceServer(accessToken string) (string, int) {
	// Create request to the RS protected endpoint
	req, err := http.NewRequest("GET", rsURL+"/accounts/12345/orders/export", nil)
	if err != nil {
		return fmt.Sprintf("Failed to create request: %v", err), 0
	}

	// Add the Authorization header with the Bearer token
	req.Header.Set("Authorization", "Bearer "+accessToken)

	log.Printf("Calling Resource Server: %s", rsURL+"/accounts/12345/orders/export")

	// Make the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Sprintf("Request failed: %v", err), 0
	}
	defer resp.Body.Close()

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Sprintf("Failed to read response: %v", err), resp.StatusCode
	}

	log.Printf("RS Response Status: %d", resp.StatusCode)

	// Try to pretty-print if it's JSON
	var jsonData interface{}
	if err := json.Unmarshal(body, &jsonData); err == nil {
		prettyJSON, err := json.MarshalIndent(jsonData, "", "  ")
		if err == nil {
			return string(prettyJSON), resp.StatusCode
		}
	}

	return string(body), resp.StatusCode
}
