package oauth2

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"slices"
	"sync"
	"time"
)

// Client represents a dynamically registered OAuth2 client.
type Client struct {
	ClientID         string
	ClientSecretHash [32]byte
	RedirectURIs     []string
	ClientName       string
	GrantTypes       []string
	CreatedAt        time.Time
}

// AuthSession holds state for an in-progress authorization flow between the MCP client and Keycloak.
type AuthSession struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string // client's original state
	CodeChallenge       string
	CodeChallengeMethod string
	KCState             string // random state sent to Keycloak
	CreatedAt           time.Time
}

// AuthCode maps a proxy-issued authorization code to the Keycloak tokens obtained during the callback.
type AuthCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	KCAccessToken       string
	KCRefreshToken      string
	KCIDToken           string
	KCExpiresIn         int
	KCTokenType         string
	CreatedAt           time.Time
	Used                bool
}

// Store is a thread-safe in-memory store for OAuth2 clients, authorization sessions, and codes.
type Store struct {
	mu           sync.RWMutex
	clients      map[string]*Client
	authSessions map[string]*AuthSession // keyed by KCState
	authCodes    map[string]*AuthCode    // keyed by Code

	clientTTL  time.Duration
	sessionTTL time.Duration
	codeTTL    time.Duration

	stopCleanup chan struct{}
}

// NewStore creates a new Store and starts a background cleanup goroutine.
func NewStore(clientTTL, sessionTTL, codeTTL time.Duration) *Store {
	s := &Store{
		clients:      make(map[string]*Client),
		authSessions: make(map[string]*AuthSession),
		authCodes:    make(map[string]*AuthCode),
		clientTTL:    clientTTL,
		sessionTTL:   sessionTTL,
		codeTTL:      codeTTL,
		stopCleanup:  make(chan struct{}),
	}
	go s.cleanup()
	return s
}

// Close stops the background cleanup goroutine.
func (s *Store) Close() {
	close(s.stopCleanup)
}

// PutClient stores a new client and returns the generated client ID and plaintext secret.
func (s *Store) PutClient(redirectURIs []string, clientName string, grantTypes []string) (clientID, clientSecret string, err error) {
	clientID, err = randomHex(16)
	if err != nil {
		return "", "", fmt.Errorf("generating client_id: %w", err)
	}
	clientSecret, err = randomHex(32)
	if err != nil {
		return "", "", fmt.Errorf("generating client_secret: %w", err)
	}

	c := &Client{
		ClientID:         clientID,
		ClientSecretHash: sha256.Sum256([]byte(clientSecret)),
		RedirectURIs:     redirectURIs,
		ClientName:       clientName,
		GrantTypes:       grantTypes,
		CreatedAt:        time.Now(),
	}

	s.mu.Lock()
	s.clients[clientID] = c
	s.mu.Unlock()

	return clientID, clientSecret, nil
}

// GetClient returns the client with the given ID, or nil if not found or expired.
func (s *Store) GetClient(clientID string) *Client {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clients[clientID]
	if !ok {
		return nil
	}
	if time.Since(c.CreatedAt) > s.clientTTL {
		return nil
	}
	return c
}

// ValidateClientCredentials checks that the client exists and the secret matches.
func (s *Store) ValidateClientCredentials(clientID, clientSecret string) bool {
	c := s.GetClient(clientID)
	if c == nil {
		return false
	}
	h := sha256.Sum256([]byte(clientSecret))
	return subtle.ConstantTimeCompare(h[:], c.ClientSecretHash[:]) == 1
}

// HasRedirectURI checks whether the given redirect URI is registered for the client.
func (s *Store) HasRedirectURI(clientID, uri string) bool {
	c := s.GetClient(clientID)
	if c == nil {
		return false
	}
	return slices.Contains(c.RedirectURIs, uri)
}

// PutAuthSession stores an authorization session keyed by kcState.
func (s *Store) PutAuthSession(session *AuthSession) {
	s.mu.Lock()
	s.authSessions[session.KCState] = session
	s.mu.Unlock()
}

// PopAuthSession retrieves and deletes the authorization session for the given kcState (single-use).
func (s *Store) PopAuthSession(kcState string) *AuthSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.authSessions[kcState]
	if !ok {
		return nil
	}
	delete(s.authSessions, kcState)
	if time.Since(sess.CreatedAt) > s.sessionTTL {
		return nil
	}
	return sess
}

// PutAuthCode stores an authorization code.
func (s *Store) PutAuthCode(code *AuthCode) {
	s.mu.Lock()
	s.authCodes[code.Code] = code
	s.mu.Unlock()
}

// ConsumeAuthCode retrieves and marks the authorization code as used (single-use).
// Returns nil if the code is not found, expired, or already used.
func (s *Store) ConsumeAuthCode(code string) *AuthCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, ok := s.authCodes[code]
	if !ok {
		return nil
	}
	if ac.Used {
		return nil
	}
	if time.Since(ac.CreatedAt) > s.codeTTL {
		delete(s.authCodes, code)
		return nil
	}
	ac.Used = true
	return ac
}

// GenerateCode creates a random authorization code.
func GenerateCode() (string, error) {
	return randomHex(32)
}

// GenerateState creates a random state parameter.
func GenerateState() (string, error) {
	return randomHex(16)
}

// cleanup periodically removes expired entries.
func (s *Store) cleanup() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCleanup:
			return
		case <-ticker.C:
			s.purgeExpired()
		}
	}
}

func (s *Store) purgeExpired() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, c := range s.clients {
		if now.Sub(c.CreatedAt) > s.clientTTL {
			delete(s.clients, id)
		}
	}
	for state, sess := range s.authSessions {
		if now.Sub(sess.CreatedAt) > s.sessionTTL {
			delete(s.authSessions, state)
		}
	}
	for code, ac := range s.authCodes {
		if now.Sub(ac.CreatedAt) > s.codeTTL {
			delete(s.authCodes, code)
		}
	}
}

// randomHex generates n random bytes and returns them as a hex string.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
