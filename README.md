# shloss

A focused, self-hosted authentication server written in Rust. Shloss handles user credentials, session management, and token issuance so your services don't have to.

## Philosophy

Most applications need authentication, but building it correctly is tedious and easy to get wrong. Shloss is designed to be a small, trustworthy auth layer that sits in front of your services and does one thing well: verify that a user is who they claim to be, and hand back a token that proves it.

The design is deliberately minimal. Shloss does not try to be an identity provider, an OAuth server, or an all-in-one user management platform. It is an authentication server. Your services register users, request logins, validate tokens, and manage sessions through a simple HTTP API. Everything else is your business.

A key principle is that Shloss never makes authorization decisions. It tells you who someone is, not what they are allowed to do. Claims in JWTs are defined entirely by the requesting service, and Shloss signs whatever it is given as long as the user credentials check out.

## How it works

Services authenticate to Shloss using API keys configured by an admin. Once authenticated, a service can register users, log them in, and request tokens on their behalf.

On a successful login, Shloss creates a session and returns the token type the service requested: either a short-lived opaque token (validated by looking it up in the database) or a JWT (validated by the requesting service using Shloss's public key). Refresh tokens can be requested alongside either token type to allow re-issuing tokens without requiring the user to log in again.

JWTs are stateless. Once issued, Shloss has no record of them. The signing key is RSA and the public key is exposed at a standard JWKS endpoint so services can verify tokens themselves without calling back to Shloss on every request.

Opaque tokens and refresh tokens are stateful and stored in the database. They can be revoked individually, by session, or across all sessions for a user.

## Intended use

```
your service  -->  POST /v1/services/login       authenticate as a service
your service  -->  POST /v1/users/register        register a new user
your service  -->  POST /v1/users/login           log a user in, get a token back
your service  -->  POST /v1/tokens/validate       check whether a token is valid
your service  -->  POST /v1/tokens/refresh        rotate a refresh token, get a new token
your service  -->  GET  /v1/sessions/{user_id}    list active sessions for a user
your service  -->  GET  /.well-known/jwks.json    fetch the public key to verify JWTs locally
```

The typical flow looks like this:

1. A user tries to log in to your application.
2. Your service sends their credentials to `POST /v1/users/login` along with the token type you want.
3. Shloss verifies the credentials and returns a token and optionally a refresh token.
4. Your service gives the token to the user and stores the `user_id` that comes back.
5. On subsequent requests, your service validates the token with Shloss (opaque) or verifies it locally using the JWKS public key (JWT).
6. When the token expires, your service uses the refresh token to get a new one without asking the user to log in again.

## Configuration

Shloss is configured through a `shloss.toml` file, environment variables, or both. Environment variables take precedence and use the `SHLOSS_` prefix with `__` as a separator for nested values.

A minimal `shloss.toml`:

```toml
database_url = "postgresql:///shloss"
host = "127.0.0.1"
port = 3000

```

The RSA private key is passed as an environment variable and never written to disk by Shloss:

```bash
export SHLOSS_PRIVATE_KEY="$(cat private.pem)"
```

You can generate a key with:

```bash
openssl genrsa -out private.pem 4096
```

## Service credentials

Services authenticate using API keys managed through the `shloss-cli` tool. Keys are stored as SHA-256 hashes in a `client_credentials.toml` file. The raw key is shown once on generation and never stored.

```bash
# create a fresh client_credentials.toml with a first service key
shloss-cli generate-config -n myservice

# add a key for an additional service
shloss-cli generate-key -n anotherservice
```

The generated key is prefixed with `shloss_` and should be passed as a Bearer token when calling the API:

```
Authorization: Bearer shloss_<key>
```

## Credentials and tokens

Users can be registered with a password or an API key. Both credential types can coexist.

Passwords are hashed with Argon2. API keys and all token types are randomly generated 32-byte values hashed with SHA-256. The distinction is intentional: Argon2 is designed for low-entropy human-chosen secrets. Machine-generated random bytes do not need it.

Three token types are supported:

- **Opaque tokens** are short-lived, stored in the database, and validated by calling `POST /v1/tokens/validate`. They can be revoked at any time.
- **JWTs** are stateless and signed with RS256. Claims are defined by the requesting service. Shloss sets the `sub` field to the authenticated `user_id` and signs everything else as given. Expiry is the service's responsibility.
- **Refresh tokens** are long-lived, stored in the database, and used to rotate to a new token without re-authenticating. Each rotation invalidates the old refresh token and issues a new one with the same remaining lifetime.

## Running

```bash
# run database migrations
cargo sqlx migrate run

# start the server
cargo run --bin shloss
```

The server binds to `host:port` as configured and is ready to accept requests once it logs `shloss: ready`.

## AI Notice

AI was used for Documentation. All application logic is handwritten.

## License

MIT

## Roadmap

- Structured logging with `tracing` across all API endpoints and auth operations
- Official client library to make integrating with Shloss from other Rust services straightforward
