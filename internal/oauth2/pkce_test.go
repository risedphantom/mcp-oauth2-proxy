package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestVerifyPKCES256_Valid(t *testing.T) {
	// RFC 7636 Appendix B test vector
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	if !VerifyPKCES256(verifier, challenge) {
		t.Errorf("expected valid PKCE verification for verifier=%q challenge=%q", verifier, challenge)
	}
}

func TestVerifyPKCES256_KnownVector(t *testing.T) {
	// Known test: verifier "abc123" -> SHA256 -> base64url
	verifier := "abc123"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	if !VerifyPKCES256(verifier, challenge) {
		t.Error("expected valid PKCE verification")
	}
}

func TestVerifyPKCES256_WrongVerifier(t *testing.T) {
	verifier := "correct-verifier"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	if VerifyPKCES256("wrong-verifier", challenge) {
		t.Error("expected PKCE verification to fail with wrong verifier")
	}
}

func TestVerifyPKCES256_WrongChallenge(t *testing.T) {
	if VerifyPKCES256("some-verifier", "definitely-not-a-valid-challenge") {
		t.Error("expected PKCE verification to fail with wrong challenge")
	}
}

func TestVerifyPKCES256_EmptyInputs(t *testing.T) {
	if VerifyPKCES256("", "some-challenge") {
		t.Error("expected failure with empty verifier")
	}
	if VerifyPKCES256("some-verifier", "") {
		t.Error("expected failure with empty challenge")
	}
	if VerifyPKCES256("", "") {
		t.Error("expected failure with both empty")
	}
}
