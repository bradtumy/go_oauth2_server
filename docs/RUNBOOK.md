# Tokenator Runbook

## Key rotation

### Recommended setup
1. Store RSA private keys on disk and load them via `AS_SIGNING_KEYS_DIR`.
2. Name each key file as `<kid>.pem` (for example `2025-01.pem`).
3. Set `AS_SIGNING_KEY_ID` to the active `kid`.
4. Optionally set `AS_SIGNING_KEY_ROTATION_SECONDS` to periodically reload keys from disk.

### Rotation procedure
1. Generate a new RSA key pair and write the private key to `AS_SIGNING_KEYS_DIR` (e.g., `2025-02.pem`).
2. Update `AS_SIGNING_KEY_ID` to the new `kid` and restart the AS (or wait for the reload interval).
3. Keep the previous key files in the directory for an overlap window so existing tokens continue to validate.
4. After the overlap window expires (e.g., > max access token TTL), remove the old key files.

## Incident response

### Revoke a client
1. Disable or delete the client via the admin API (`DELETE /admin/clients/{client_id}`).
2. Rotate signing keys if you suspect token leakage or signing key compromise.
3. Invalidate refresh tokens by revoking the refresh family (`POST /oauth2/revoke` with `token_type_hint=refresh_token`).

### Suspected refresh token theft
1. Revoke the affected refresh token family using `/oauth2/revoke`.
2. Require the user/client to re-authenticate and re-consent.
3. Review logs for repeated reuse errors.

## Backup and restore

- **SQLite client registry** (`AS_CLIENTS_DB`): back up the SQLite database file regularly.
- **In-memory codes/refresh tokens**: ephemeral; persisting them requires external storage (not yet implemented).
- **Signing keys**: back up `AS_SIGNING_KEYS_DIR` and store keys in a secret manager or HSM for production.

