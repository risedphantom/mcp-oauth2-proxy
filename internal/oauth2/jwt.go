package oauth2

import (
	"context"
	"fmt"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// JWTValidator validates JWT tokens using JWKS fetched from a remote endpoint.
type JWTValidator struct {
	kf keyfunc.Keyfunc
}

// NewJWTValidator creates a JWTValidator that fetches and caches JWKS from the given URI.
func NewJWTValidator(ctx context.Context, jwksURI string) (*JWTValidator, error) {
	kf, err := keyfunc.NewDefaultCtx(ctx, []string{jwksURI})
	if err != nil {
		return nil, fmt.Errorf("creating JWKS keyfunc: %w", err)
	}
	return &JWTValidator{kf: kf}, nil
}

// Validate parses and validates the JWT token string.
// It verifies the signature against the JWKS keys and checks expiration.
func (v *JWTValidator) Validate(tokenString string) error {
	if v == nil {
		return nil
	}

	parser := jwt.NewParser(jwt.WithExpirationRequired())

	_, err := parser.Parse(tokenString, v.kf.Keyfunc)
	if err != nil {
		return fmt.Errorf("token validation failed: %w", err)
	}
	return nil
}
