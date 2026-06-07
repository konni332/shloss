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

## API

For information about the API endpoint have a look at the [API](docs/API.md) documentation.

## Typical flow

1. A user tries to log in to your application.
2. Your service sends their credentials to `POST /v1/auth/login` along with the token type you want.
3. Shloss verifies the credentials and returns a token, a `userId`, and optionally a refresh token.
4. Your service gives the token to the user and stores the `userId` alongside your application data.
5. On subsequent requests, your service validates the token with Shloss (opaque) or verifies it locally using the JWKS public key (JWT).
6. When the token expires, your service uses the refresh token to get a new one without asking the user to log in again.

The `userId` is the stable identifier for a user across all operations. Your service receives it on registration and login, and uses it for all session, token, and user management calls.

## Configuration

Shloss is configured through a `shloss.toml` file, environment variables, or both. Environment variables take precedence and use the `SHLOSS_` prefix.

A minimal `shloss.toml`:

```toml
database_url = "postgresql:///shloss"
host = "127.0.0.1"
port = 3000
```

All three fields have defaults and the file itself is optional. The defaults are shown above.

The RSA keys are passed as environment variables and never written to disk by Shloss:

```bash
export SHLOSS_PRIVATE_KEY="$(cat private.pem)"
export SHLOSS_PUBLIC_KEY="$(cat public.pem)"
```

You can generate keys with:

```bash
openssl genrsa -out private.pem 4096
openssl rsa -in private.pem -pubout -out public.pem
```

## Service credentials

Services authenticate using API keys managed through the `shloss-cli` tool. Keys are stored as SHA-256 hashes in a `client_credentials.toml` file. The raw key is shown once on generation and never stored.

```bash
# create a fresh client_credentials.toml with a first service key
shloss-cli generate-config -n myservice

# add a key for an additional service
shloss-cli generate-key -n anotherservice

# rotate a serivce key without changing the vault_id or loosing any associated data
shloss-cli rotate-key -n myservice
```

The generated key is prefixed with `shloss_` and should be passed as a Bearer token when calling the API:

```
Authorization: Bearer shloss_<key>
```

## Credentials and tokens

Users can be registered with a password or an API key.

Passwords are hashed with Argon2. API keys and all token types are randomly generated 32-byte values hashed with SHA-256. The distinction is intentional: Argon2 is designed for low-entropy human-chosen secrets. Machine-generated random bytes do not need it.

Three token types are supported:

- **Opaque tokens** are short-lived, stored in the database, and validated by calling `POST /v1/tokens/validate`. They can be revoked at any time.
- **JWTs** are stateless and signed with RS256. Claims are defined by the requesting service. Shloss sets the `sub` field to the authenticated `user_id` and signs everything else as given. Expiry is the service's responsibility.
- **Refresh tokens** are long-lived, stored in the database, and used to rotate to a new token without re-authenticating. Each rotation invalidates the old refresh token and issues a new one preserving the original lifetime.

## Vaults

Vaults provide tenant isolation for multi-service deployments. Each service operates within its own vault, and all data (users, sessions, credentials, and tokens) is scoped to that vault. Services cannot read or modify data belonging to another vault.

The vault is derived implicitly from the service's API key. When a service authenticates, Shloss resolves the vault associated with that key and applies it to every subsequent operation. No vault identifier is ever passed explicitly in requests.

This means the same username can exist in multiple vaults without conflict, a user_id from one vault is meaningless to another, and tokens issued in one vault cannot be validated or rotated by another.

Vaults are configured by an admin in `client_credentials.toml`. Each service key has a `vault_id` field which is generated once by `shloss-cli` and never changes. One key maps to one vault.

```toml
[[keys]]
name = "foomail"
hash = "a3f2c1..."
vault_id = "123e4567-e89b-12d3-a456-426614174000"

[[keys]]
name = "barservice"
hash = "9d4e2b..."
vault_id = "987fbc97-4bed-5078-af07-9141ba07c9f3"
```

If a `vault_id` is changed after users have been registered, all data associated with the old vault becomes inaccessible. Treat vault IDs as permanent.

## Running

```bash
# run database migrations
cargo sqlx migrate run

# start the server
cargo run --bin shloss
```

The server binds to `host:port` as configured and is ready to accept requests once it logs `listening`.

## AI Notice

AI was used for documentation. All application logic is handwritten.

## License

MIT

## Roadmap to 1.0.0

- Official client library to make integrating with Shloss easy. A Rust version is planned, but perhaps libraries in other languages will be added.
- Deployment setups/templates to securely deploy a Shloss instance.
- Pentesting of both core application logic and the deployment setup.
