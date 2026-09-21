package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

const rsaKeyBits = 2048

type signingKey struct {
	Kid       string
	Private   *rsa.PrivateKey
	ExpiresAt time.Time
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

type app struct {
	validKey   signingKey
	expiredKey signingKey
	now        func() time.Time
}

func newSigningKey(expiresAt time.Time) (signingKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return signingKey{}, fmt.Errorf("generate RSA key: %w", err)
	}

	kidBytes := make([]byte, 16)
	if _, err := rand.Read(kidBytes); err != nil {
		return signingKey{}, fmt.Errorf("generate kid: %w", err)
	}

	return signingKey{
		Kid:       base64.RawURLEncoding.EncodeToString(kidBytes),
		Private:   privateKey,
		ExpiresAt: expiresAt,
	}, nil
}

func newApp(now func() time.Time) (*app, error) {
	current := now()

	validKey, err := newSigningKey(current.Add(24 * time.Hour))
	if err != nil {
		return nil, err
	}

	expiredKey, err := newSigningKey(current.Add(-24 * time.Hour))
	if err != nil {
		return nil, err
	}

	return &app{
		validKey:   validKey,
		expiredKey: expiredKey,
		now:        now,
	}, nil
}

func publicJWK(key signingKey) jwk {
	publicKey := key.Private.PublicKey

	exponentBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(exponentBytes, uint32(publicKey.E))
	for len(exponentBytes) > 1 && exponentBytes[0] == 0 {
		exponentBytes = exponentBytes[1:]
	}

	return jwk{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: key.Kid,
		N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(exponentBytes),
	}
}

func encodeSegment(v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func createJWT(key signingKey, issuedAt, expiresAt time.Time) (string, error) {
	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": key.Kid,
	}
	claims := map[string]any{
		"sub": "fake-user",
		"iat": issuedAt.Unix(),
		"exp": expiresAt.Unix(),
	}

	headerPart, err := encodeSegment(header)
	if err != nil {
		return "", fmt.Errorf("encode JWT header: %w", err)
	}
	claimsPart, err := encodeSegment(claims)
	if err != nil {
		return "", fmt.Errorf("encode JWT claims: %w", err)
	}

	signingInput := headerPart + "." + claimsPart
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key.Private, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (a *app) jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	current := a.now()
	keys := make([]jwk, 0, 1)
	if a.validKey.ExpiresAt.After(current) {
		keys = append(keys, publicJWK(a.validKey))
	}
	if a.expiredKey.ExpiresAt.After(current) {
		keys = append(keys, publicJWK(a.expiredKey))
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwksResponse{Keys: keys}); err != nil {
		http.Error(w, "failed to encode JWKS", http.StatusInternalServerError)
	}
}

func (a *app) authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	current := a.now()
	key := a.validKey
	expiresAt := current.Add(time.Hour)

	if _, present := r.URL.Query()["expired"]; present {
		key = a.expiredKey
		expiresAt = current.Add(-time.Hour)
	}

	token, err := createJWT(key, current, expiresAt)
	if err != nil {
		http.Error(w, "failed to create token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/jwt")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(token))
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", a.jwksHandler)
	mux.HandleFunc("/auth", a.authHandler)
	return mux
}

func main() {
	a, err := newApp(time.Now)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("JWKS server listening on http://localhost:8080")
	if err := http.ListenAndServe(":8080", a.routes()); err != nil {
		log.Fatal(err)
	}
}
