# Basic JWKS Server

A small educational JWKS server written in Go using only the standard library.

## Requirements implemented

- Generates RSA key pairs with unique `kid` values and expiry timestamps.
- Serves HTTP on port `8080`.
- `GET /.well-known/jwks.json` returns only unexpired public keys in JWKS format.
- `POST /auth` returns an RS256-signed JWT with a matching `kid` header.
- `POST /auth?expired=true` returns a JWT signed by the expired key with an expired `exp` claim.
- No request body or real user authentication is required for `/auth`.
- Unit tests cover the JWKS endpoint, normal JWTs, expired JWTs, signatures, and HTTP methods.

## Run

```bash
go run .
```

The server starts at:

```text
http://localhost:8080
```

## Manual checks

```bash
curl http://localhost:8080/.well-known/jwks.json
curl -X POST http://localhost:8080/auth
curl -X POST "http://localhost:8080/auth?expired=true"
```

## Tests and coverage

```bash
go test ./... -cover
```

For a detailed coverage report:

```bash
go test ./... -coverprofile=coverage.out
go tool cover -func=coverage.out
```

## Lint / formatting

```bash
gofmt -w .
go vet ./...
```

## Gradebot

Start this server in one terminal:

```bash
go run .
```

Then run the provided CSCE3550 client in another terminal using its Project 1 command and port 8080.
