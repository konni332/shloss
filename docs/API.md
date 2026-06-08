# API

This document describes the Shloss API, including routes, JSON objects, status codes and error cases

## V1

All the given routes in this document need to be prefixed with `/v1`. For example the route `/.well-known/jwks.json` needs to be used as `/v1/.well-known/jwks.json`.

## Well known

### GET `/.well-known/jwks.json`

Returns the JSON Web Key Set (JWKS) used to verify JWTs issued by the service.

---

### Request Body

_None_

---

### Response Body (200 OK)

```json
{
  "keys": [
    {
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "<base64url modulus>",
      "e": "AQAB",
      "kid": "<key identifier>"
    }
  ]
}
```

---

### Response Fields

#### JWK

| Field | Type   | Description                                                 |
| ----- | ------ | ----------------------------------------------------------- |
| kty   | string | Key type. Always `RSA`.                                     |
| alg   | string | Signing algorithm. Always `RS256`.                          |
| use   | string | Key usage. Always `sig`.                                    |
| n     | string | RSA modulus encoded as Base64URL.                           |
| e     | string | RSA exponent encoded as Base64URL.                          |
| kid   | string | Key identifier used to select the correct verification key. |

---

### Status Codes

| Code | Meaning                     |
| ---- | --------------------------- |
| 200  | JWKS successfully retrieved |

---

### Notes

- JWT consumers should use the `kid` claim in the JWT header to select the appropriate key from the JWKS.
- The JWKS may contain multiple keys during key rotation.
- All keys are intended for signature verification only.

---

## Auth

### POST `/auth/service`

Authenticates a service using an API key and returns an opaque access token.

---

### Request Body

```json
{
  "rawKey": "service-api-key"
}
```

---

### Response Body (200 OK)

```json
{
  "token": "opaque-token"
}
```

---

### Status Codes

| Code | Meaning                            |
| ---- | ---------------------------------- |
| 200  | Service authenticated successfully |
| 401  | Invalid API key                    |

---

### Notes

- The provided API key must be valid and not revoked.
- The returned token can be used to authenticate subsequent requests.
- The token format is opaque and should be treated as an uninterpreted string.

---

### POST `/auth/register`

Creates a new password-based user account or registers a new API key.

---

### Request Body

Password registration:

```json
{
  "kind": "password",
  "username": "alice",
  "password": "secret-password"
}
```

API key registration:

```json
{
  "kind": "apiKey",
  "name": "production-service",
  "keyPrefix": "prod",
  "expiresAt": "2026-12-31T23:59:59Z"
}
```

---

### Response Body (200 OK)

Password registration:

```json
{
  "kind": "password",
  "userId": "550e8400-e29b-41d4-a716-446655440000"
}
```

API key registration:

```json
{
  "kind": "apiKey",
  "userId": "550e8400-e29b-41d4-a716-446655440000",
  "rawKey": "generated-api-key"
}
```

---

### Status Codes

| Code | Meaning                 |
| ---- | ----------------------- |
| 200  | Registration successful |
| 409  | Username already exists |
| 500  | Internal server error   |

---

### Notes

- `expiresAt` is optional.
- `rawKey` is only returned when creating an API key.
- Clients should store `rawKey` securely, as it may not be retrievable again.

---

### POST `/auth/login`

Authenticates a user and returns an access token.

---

### Request Body

Password credentials with JWT token and refresh token:

```json
{
  "credentials": {
    "kind": "password",
    "username": "alice",
    "password": "secret-password"
  },
  "ipAddress": "203.0.113.10",
  "userAgent": "Mozilla/5.0",
  "tokenKind": {
    "kind": "jwt",
    "claims": {
      "role": "admin"
    }
  },
  "refreshExpiry": "2026-12-31T23:59:59Z"
}
```

Password credentials with opaque token:

```json
{
  "credentials": {
    "kind": "password",
    "username": "alice",
    "password": "secret-password"
  },
  "tokenKind": {
    "kind": "opaque",
    "expiresAt": "2026-12-31T23:59:59Z"
  }
}
```

API key credentials with JWT token:

```json
{
  "credentials": {
    "kind": "api-key",
    "fullKey": "sk_live_xxxxxxxxxxxxxxxxx"
  },
  "tokenKind": {
    "kind": "jwt",
    "claims": {
      "role": "service"
    }
  }
}
```

---

### Response Body (200 OK)

Without refresh token:

```json
{
  "userId": "550e8400-e29b-41d4-a716-446655440000",
  "token": "access-token"
}
```

With refresh token:

```json
{
  "userId": "550e8400-e29b-41d4-a716-446655440000",
  "token": "access-token",
  "refreshToken": "refresh-token"
}
```

---

### Status Codes

| Code | Meaning                   |
| ---- | ------------------------- |
| 200  | Authentication successful |
| 401  | Invalid credentials       |
| 500  | Internal server error     |

---

### Notes

- `ipAddress` and `userAgent` are optional.
- `refreshExpiry` is optional.
- Providing `refreshExpiry` requests issuance of a refresh token with the specified expiration time.
- Omitting `refreshExpiry` disables refresh token issuance.
- JWT tokens include the supplied custom claims.
- Opaque tokens expire at the specified `expiresAt` timestamp.
- Credentials can be provided using either a username/password pair or an API key.

---

### POST `/auth/refresh`

Rotates a refresh token and issues a new access token.

---

### Request Body

```json
{
  "refreshToken": "existing-refresh-token",
  "tokenType": {
    "kind": "jwt",
    "claims": {
      "role": "admin"
    }
  }
}
```

or:

```json
{
  "refreshToken": "existing-refresh-token",
  "tokenType": {
    "kind": "opaque",
    "expiresAt": "2026-12-31T23:59:59Z"
  }
}
```

---

### Response Body (200 OK)

Invalid refresh token:

```json
{
  "status": "invalid"
}
```

Valid refresh token (JWT issued):

```json
{
  "status": "valid",
  "newRefresh": "new-refresh-token",
  "newToken": "new-jwt-token"
}
```

Valid refresh token (opaque issued):

```json
{
  "status": "valid",
  "newRefresh": "new-refresh-token",
  "newToken": "new-opaque-token"
}
```

---

### Status Codes

| Code | Meaning                                      |
| ---- | -------------------------------------------- |
| 200  | Refresh attempt processed (valid or invalid) |
| 500  | Internal server error                        |

---

### Notes

- A refresh token is **single-use** and is rotated on every successful request.
- If the refresh token is invalid or expired, the response will still return `200 OK` with `"status": "invalid"`.
- `tokenType` controls the format of the newly issued access token.
- JWT tokens may include custom claims provided in the request.
- Opaque tokens are stored and validated server-side.

---

## Token

### POST `/tokens/validate`

Validates an access token and returns the associated user if valid.

---

### Request Body

```json
{
  "token": "access-token",
  "kind": "jwt"
}
```

or

```json
{
  "token": "access-token",
  "kind": "opaque"
}
```

---

### Response Body (200 OK)

Invalid token:

```json
{
  "status": "invalid"
}
```

Valid token:

```json
{
  "status": "valid",
  "userId": "550e8400-e29b-41d4-a716-446655440000"
}
```

---

### Status Codes

| Code | Meaning                            |
| ---- | ---------------------------------- |
| 200  | Token processed (valid or invalid) |
| 500  | Internal server error              |

---

### Notes

- `kind` selects the validation strategy:
  - `jwt` → signature verification using JWKS / decoding key
  - `opaque` → database-backed validation

- Invalid tokens return `200 OK` with `status: invalid` (no error semantics).
- Valid tokens return the associated `userId`.

## Users

### DELETE `/users/{user_id}`

Deletes a user account.

---

#### Request Parameters

| Parameter | Type | Description              |
| --------- | ---- | ------------------------ |
| user_id   | UUID | ID of the user to delete |

---

#### Request Body

_None_

---

#### Response Body

_None_

---

#### Status Codes

| Code | Meaning                   |
| ---- | ------------------------- |
| 200  | User successfully deleted |
| 404  | User not found            |
| 500  | Internal server error     |

---

#### Notes

- Deleting a user removes all associated data depending on database cascade rules (sessions, credentials, tokens).
- This operation is irreversible.

---

### Password

#### POST `/users/{user_id}/password`

Changes the password for a user account.

---

##### Request Parameters

| Parameter | Type | Description                                 |
| --------- | ---- | ------------------------------------------- |
| user_id   | UUID | Target user whose password is being updated |

---

##### Request Body

```json
{
  "newPassword": "new-strong-password"
}
```

---

##### Response Body

_None_

---

##### Status Codes

| Code | Meaning                                |
| ---- | -------------------------------------- |
| 200  | Password successfully updated          |
| 404  | No password credentials found for user |
| 500  | Internal server error                  |

---

##### Notes

- The password is hashed server-side before storage.
- This endpoint updates an existing password credential; it does not create a new user.
- If no password credential exists for the user, a `404` is returned.
- Existing sessions are not automatically revoked by this operation (unless enforced elsewhere).

---

### Username

#### POST `/users/{user_id}/username`

Changes the username associated with a user’s password credentials.

---

##### Request Parameters

| Parameter | Type | Description                                 |
| --------- | ---- | ------------------------------------------- |
| user_id   | UUID | Target user whose username is being updated |

---

##### Request Body

```json
{
  "newUsername": "new_name"
}
```

---

##### Response Body

_None_

---

##### Status Codes

| Code | Meaning                       |
| ---- | ----------------------------- |
| 200  | Username successfully updated |
| 409  | Username already taken        |
| 500  | Internal server error         |

---

##### Notes

- Username must be unique across all password credentials.
- If the new username already exists, the request fails with `409 Conflict`.
- This operation only affects password-based credentials, not API keys or other identity mechanisms.

### Api-Key

#### DELETE `/users/{user_id}/api-key/all`

Revokes all API keys associated with a user.

---

##### Request Parameters

| Parameter | Type | Description                                |
| --------- | ---- | ------------------------------------------ |
| user_id   | UUID | Target user whose API keys will be revoked |

---

##### Request Body

_None_

---

##### Response Body

_None_

---

##### Status Codes

| Code | Meaning                           |
| ---- | --------------------------------- |
| 200  | All API keys successfully revoked |
| 500  | Internal server error             |

---

##### Notes

- This operation marks all API keys for the user as revoked.
- Revoked keys can no longer be used for authentication.
- This does not delete keys from the database; it updates their revocation state.

---

#### POST `/users/{user_id}/api-key`

Creates a new API key for a user.

---

##### Request Parameters

| Parameter | Type | Description                                 |
| --------- | ---- | ------------------------------------------- |
| user_id   | UUID | Target user for whom the API key is created |

---

##### Request Body

```json
{
  "name": "production-service",
  "keyPrefix": "prod",
  "expiresAt": "2026-12-31T23:59:59Z"
}
```

---

##### Response Body

```json
{
  "key": "generated-full-api-key"
}
```

---

##### Status Codes

| Code | Meaning                      |
| ---- | ---------------------------- |
| 200  | API key successfully created |
| 500  | Internal server error        |

---

##### Notes

- `expiresAt` is optional; if omitted, the key does not expire.
- The returned `key` is only shown once and cannot be retrieved again.
- The stored value is hashed; only the prefix is stored in plaintext for identification.
- Clients must securely store the returned key immediately after creation.

---

#### DELETE `/users/{user_id}/api-key`

Revokes a specific API key belonging to a user.

---

##### Request Parameters

| Parameter | Type | Description                               |
| --------- | ---- | ----------------------------------------- |
| user_id   | UUID | Target user whose API key will be revoked |

---

##### Request Body

```json
{
  "key": "full-api-key"
}
```

---

##### Response Body

_None_

---

##### Status Codes

| Code | Meaning                      |
| ---- | ---------------------------- |
| 200  | API key successfully revoked |
| 500  | Internal server error        |

---

##### Notes

- The provided API key must belong to the specified user.
- The API key is identified by its secret value and revoked by its hashed representation.
- Revoked API keys can no longer be used for authentication.
- This operation does not delete the key from the database; it updates its revocation state.

---

#### DELETE `/users/{user_id}/sessions/{session_id}`

Revokes a specific session belonging to a user.

---

##### Request Parameters

| Parameter  | Type | Description          |
| ---------- | ---- | -------------------- |
| user_id    | UUID | Owner of the session |
| session_id | UUID | Session to revoke    |

---

##### Request Body

_None_

---

##### Response Body

_None_

---

##### Status Codes

| Code | Meaning                                  |
| ---- | ---------------------------------------- |
| 200  | Session successfully revoked             |
| 404  | Session not found for the specified user |
| 500  | Internal server error                    |

---

##### Notes

- The specified session must belong to the specified user.
- Revoked sessions can no longer be used for authentication.
- This operation updates the session's revocation state rather than deleting the session record.

---

#### DELETE `/users/{user_id}/sessions`

Revokes all sessions and tokens associated with a user.

---

##### Request Parameters

| Parameter | Type | Description                                    |
| --------- | ---- | ---------------------------------------------- |
| user_id   | UUID | User whose sessions and tokens will be revoked |

---

##### Request Body

_None_

---

##### Response Body

_None_

---

##### Status Codes

| Code | Meaning                                      |
| ---- | -------------------------------------------- |
| 200  | All sessions and tokens successfully revoked |
| 500  | Internal server error                        |

---

##### Notes

- Revokes all sessions belonging to the user.
- Revokes all refresh tokens belonging to the user.
- Revokes all opaque tokens belonging to the user.
- Existing access and refresh credentials become unusable after revocation.
- This operation updates revocation state rather than deleting records.

---

#### GET `/users/{user_id}/sessions`

Returns all sessions belonging to a user.

---

##### Request Parameters

| Parameter | Type | Description                          |
| --------- | ---- | ------------------------------------ |
| user_id   | UUID | User whose sessions will be returned |

---

##### Request Body

_None_

---

##### Response Body

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "userId": "550e8400-e29b-41d4-a716-446655440000",
    "ipAddress": "203.0.113.10",
    "userAgent": "Mozilla/5.0",
    "createdAt": "2026-01-01T12:00:00Z",
    "expiresAt": "2026-01-31T12:00:00Z",
    "revokedAt": null
  }
]
```

---

##### Status Codes

| Code | Meaning                         |
| ---- | ------------------------------- |
| 200  | Sessions successfully retrieved |
| 500  | Internal server error           |

---

##### Notes

- Returns a JSON array of session objects.
- If the user has no sessions, an empty array (`[]`) is returned.
- Session object fields correspond to the server's session model.
- `revokedAt` is `null` for active sessions.

---
