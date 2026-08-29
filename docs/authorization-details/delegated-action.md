# Delegated action authorization details

Tokenator registers this Rich Authorization Request type for its delegated-action examples:

`https://github.com/bradtumy/tokenator/authorization-details/delegated-action`

The type uses the RFC 9396 common fields `locations`, `actions`, and `identifier`. All three are required. It also permits an optional `constraints` object for restrictions defined and enforced by the target API, such as amount, currency, category, time, or record-count limits.

```json
[
  {
    "type": "https://github.com/bradtumy/tokenator/authorization-details/delegated-action",
    "locations": ["https://merchant.example/mcp"],
    "actions": ["purchase.propose", "purchase.execute"],
    "identifier": "merchant:office-supply-sandbox",
    "constraints": {
      "max_amount": 100,
      "currency": "USD"
    }
  }
]
```

## Processing rules

1. Tokenator rejects an unknown type, unknown top-level field, malformed field, or missing required field with `invalid_authorization_details`.
2. Tokenator intersects requested actions with the acting agent's registered capabilities.
3. The token response and access-token claim contain the granted, potentially narrowed `authorization_details`, not the original request.
4. Resource servers enforce those granted details against every API operation.
5. The private `perm` claim is retained temporarily as a derived compatibility projection. It is not the authoritative grant.

The original `agent-action` type remains registered as a deprecated compatibility alias for existing Tokenator examples. New integrations must use the URI-identified type above.

The type URI is a stable identifier. Clients compare it as an exact string and do not need to dereference it at runtime.
