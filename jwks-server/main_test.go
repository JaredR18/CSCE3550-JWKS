package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testApp(t *testing.T) (*app, time.Time) {
	t.Helper()
	fixed := time.Unix(1_700_000_000, 0).UTC()
	a, err := newApp(func() time.Time { return fixed })
	if err != nil {
		t.Fatalf("newApp failed: %v", err)
	}
	return a, fixed
}

func decodeJWTPart(t *testing.T, part string, target any) {
	t.Helper()
	data, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatalf("decode JWT part: %v", err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal JWT part: %v", err)
	}
}

func verifyJWTSignature(t *testing.T, token string, pub *rsa.PublicKey) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT should have 3 parts, got %d", len(parts))
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func TestJWKSOnlyReturnsUnexpiredKeys(t *testing.T) {
	a, _ := testApp(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	res := httptest.NewRecorder()

	a.routes().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.Code)
	}
	if got := res.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected application/json, got %q", got)
	}

	var body jwksResponse
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JWKS JSON: %v", err)
	}
	if len(body.Keys) != 1 {
		t.Fatalf("expected 1 unexpired key, got %d", len(body.Keys))
	}

	key := body.Keys[0]
	if key.Kid != a.validKey.Kid || key.Kty != "RSA" || key.Use != "sig" || key.Alg != "RS256" {
		t.Fatalf("unexpected JWK metadata: %+v", key)
	}
	if key.Kid == a.expiredKey.Kid {
		t.Fatal("expired key must not be served")
	}

	modulusBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		t.Fatalf("bad modulus encoding: %v", err)
	}
	if new(big.Int).SetBytes(modulusBytes).Cmp(a.validKey.Private.PublicKey.N) != 0 {
		t.Fatal("JWK modulus does not match public key")
	}
	if key.E != "AQAB" {
		t.Fatalf("expected exponent AQAB, got %q", key.E)
	}
}

func TestJWKSRejectsWrongMethod(t *testing.T) {
	a, _ := testApp(t)
	req := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)
	res := httptest.NewRecorder()

	a.routes().ServeHTTP(res, req)
	if res.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", res.Code)
	}
}

func TestAuthReturnsValidJWT(t *testing.T) {
	a, fixed := testApp(t)
	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	res := httptest.NewRecorder()

	a.routes().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	token := strings.TrimSpace(res.Body.String())
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT should have 3 parts, got %d", len(parts))
	}

	var header map[string]any
	decodeJWTPart(t, parts[0], &header)
	if header["alg"] != "RS256" || header["kid"] != a.validKey.Kid {
		t.Fatalf("unexpected JWT header: %#v", header)
	}

	var claims map[string]any
	decodeJWTPart(t, parts[1], &claims)
	if int64(claims["exp"].(float64)) != fixed.Add(time.Hour).Unix() {
		t.Fatalf("unexpected exp: %#v", claims["exp"])
	}
	if claims["sub"] != "fake-user" {
		t.Fatalf("unexpected sub: %#v", claims["sub"])
	}

	verifyJWTSignature(t, token, &a.validKey.Private.PublicKey)
}

func TestAuthExpiredParameterReturnsExpiredJWT(t *testing.T) {
	a, fixed := testApp(t)
	req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", nil)
	res := httptest.NewRecorder()

	a.routes().ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.Code)
	}
	token := strings.TrimSpace(res.Body.String())
	parts := strings.Split(token, ".")

	var header map[string]any
	decodeJWTPart(t, parts[0], &header)
	if header["kid"] != a.expiredKey.Kid {
		t.Fatalf("expected expired kid %q, got %#v", a.expiredKey.Kid, header["kid"])
	}

	var claims map[string]any
	decodeJWTPart(t, parts[1], &claims)
	exp := int64(claims["exp"].(float64))
	if exp >= fixed.Unix() {
		t.Fatalf("expected expired token, exp=%d now=%d", exp, fixed.Unix())
	}

	verifyJWTSignature(t, token, &a.expiredKey.Private.PublicKey)
}

func TestAuthRejectsWrongMethod(t *testing.T) {
	a, _ := testApp(t)
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	res := httptest.NewRecorder()

	a.routes().ServeHTTP(res, req)
	if res.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", res.Code)
	}
}

func TestBareExpiredQueryParameterIsRecognized(t *testing.T) {
	a, _ := testApp(t)
	req := httptest.NewRequest(http.MethodPost, "/auth?expired", nil)
	res := httptest.NewRecorder()

	a.routes().ServeHTTP(res, req)
	parts := strings.Split(strings.TrimSpace(res.Body.String()), ".")
	var header map[string]any
	decodeJWTPart(t, parts[0], &header)
	if header["kid"] != a.expiredKey.Kid {
		t.Fatal("presence of expired query parameter should select expired key")
	}
}

func TestJWKSCanReturnNoKeysAfterExpiry(t *testing.T) {
	a, fixed := testApp(t)
	a.now = func() time.Time { return fixed.Add(48 * time.Hour) }
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	res := httptest.NewRecorder()

	a.routes().ServeHTTP(res, req)
	var body jwksResponse
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(body.Keys) != 0 {
		t.Fatalf("expected no unexpired keys, got %d", len(body.Keys))
	}
}

func TestEncodeSegmentRejectsUnsupportedValue(t *testing.T) {
	if _, err := encodeSegment(func() {}); err == nil {
		t.Fatal("expected JSON encoding error for unsupported value")
	}
}

func TestJWKSIncludesEveryUnexpiredKey(t *testing.T) {
	a, fixed := testApp(t)
	a.expiredKey.ExpiresAt = fixed.Add(time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	res := httptest.NewRecorder()

	a.routes().ServeHTTP(res, req)

	var body jwksResponse
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(body.Keys) != 2 {
		t.Fatalf("expected 2 unexpired keys, got %d", len(body.Keys))
	}
}

func TestCreateJWTReturnsSigningErrorForInvalidKey(t *testing.T) {
	badKey := signingKey{
		Kid: "bad-key",
		Private: &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: big.NewInt(3233), E: 17},
			D:         big.NewInt(2753),
			Primes:    []*big.Int{big.NewInt(61), big.NewInt(53)},
		},
	}
	fixed := time.Unix(1_700_000_000, 0)
	if _, err := createJWT(badKey, fixed, fixed.Add(time.Hour)); err == nil {
		t.Fatal("expected signing error")
	}
}

func TestAuthReturns500WhenSigningFails(t *testing.T) {
	a, _ := testApp(t)
	a.validKey.Private = &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: big.NewInt(3233), E: 17},
		D:         big.NewInt(2753),
		Primes:    []*big.Int{big.NewInt(61), big.NewInt(53)},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	res := httptest.NewRecorder()

	a.routes().ServeHTTP(res, req)
	if res.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", res.Code)
	}
}
