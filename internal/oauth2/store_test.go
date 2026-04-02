package oauth2

import (
	"testing"
	"time"
)

func TestStore_PutAndGetClient(t *testing.T) {
	s := NewStore(time.Hour, 10*time.Minute, 5*time.Minute)
	defer s.Close()

	id, secret, err := s.PutClient([]string{"http://localhost/callback"}, "test-client", []string{"authorization_code"})
	if err != nil {
		t.Fatalf("PutClient: %v", err)
	}
	if id == "" || secret == "" {
		t.Fatal("expected non-empty client_id and client_secret")
	}

	c := s.GetClient(id)
	if c == nil {
		t.Fatal("expected to find client")
	}
	if c.ClientName != "test-client" {
		t.Errorf("expected client name test-client, got %s", c.ClientName)
	}
	if len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != "http://localhost/callback" {
		t.Errorf("unexpected redirect URIs: %v", c.RedirectURIs)
	}
}

func TestStore_GetClient_NotFound(t *testing.T) {
	s := NewStore(time.Hour, 10*time.Minute, 5*time.Minute)
	defer s.Close()

	if c := s.GetClient("nonexistent"); c != nil {
		t.Error("expected nil for nonexistent client")
	}
}

func TestStore_GetClient_Expired(t *testing.T) {
	s := NewStore(1*time.Millisecond, 10*time.Minute, 5*time.Minute)
	defer s.Close()

	id, _, err := s.PutClient([]string{"http://localhost/callback"}, "test", []string{"authorization_code"})
	if err != nil {
		t.Fatalf("PutClient: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	if c := s.GetClient(id); c != nil {
		t.Error("expected nil for expired client")
	}
}

func TestStore_ValidateClientCredentials(t *testing.T) {
	s := NewStore(time.Hour, 10*time.Minute, 5*time.Minute)
	defer s.Close()

	id, secret, _ := s.PutClient([]string{"http://localhost/callback"}, "test", []string{"authorization_code"})

	if !s.ValidateClientCredentials(id, secret) {
		t.Error("expected valid credentials")
	}
	if s.ValidateClientCredentials(id, "wrong-secret") {
		t.Error("expected invalid credentials with wrong secret")
	}
	if s.ValidateClientCredentials("wrong-id", secret) {
		t.Error("expected invalid credentials with wrong id")
	}
}

func TestStore_HasRedirectURI(t *testing.T) {
	s := NewStore(time.Hour, 10*time.Minute, 5*time.Minute)
	defer s.Close()

	id, _, _ := s.PutClient([]string{"http://localhost/callback", "http://localhost/cb2"}, "test", []string{"authorization_code"})

	if !s.HasRedirectURI(id, "http://localhost/callback") {
		t.Error("expected to find registered redirect URI")
	}
	if !s.HasRedirectURI(id, "http://localhost/cb2") {
		t.Error("expected to find second registered redirect URI")
	}
	if s.HasRedirectURI(id, "http://localhost/other") {
		t.Error("expected not to find unregistered redirect URI")
	}
}

func TestStore_AuthSession_PutAndPop(t *testing.T) {
	s := NewStore(time.Hour, 10*time.Minute, 5*time.Minute)
	defer s.Close()

	sess := &AuthSession{
		ClientID:            "client1",
		RedirectURI:         "http://localhost/callback",
		Scope:               "openid",
		State:               "client-state",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		KCState:             "kc-state-123",
		CreatedAt:           time.Now(),
	}
	s.PutAuthSession(sess)

	popped := s.PopAuthSession("kc-state-123")
	if popped == nil {
		t.Fatal("expected to pop auth session")
	}
	if popped.ClientID != "client1" {
		t.Errorf("expected client1, got %s", popped.ClientID)
	}

	// Second pop should return nil (single-use)
	if s.PopAuthSession("kc-state-123") != nil {
		t.Error("expected nil on second pop (single-use)")
	}
}

func TestStore_AuthSession_Expired(t *testing.T) {
	s := NewStore(time.Hour, 1*time.Millisecond, 5*time.Minute)
	defer s.Close()

	sess := &AuthSession{
		KCState:   "kc-state-expired",
		CreatedAt: time.Now(),
	}
	s.PutAuthSession(sess)

	time.Sleep(5 * time.Millisecond)

	if s.PopAuthSession("kc-state-expired") != nil {
		t.Error("expected nil for expired session")
	}
}

func TestStore_AuthCode_PutAndConsume(t *testing.T) {
	s := NewStore(time.Hour, 10*time.Minute, 5*time.Minute)
	defer s.Close()

	ac := &AuthCode{
		Code:          "code-123",
		ClientID:      "client1",
		RedirectURI:   "http://localhost/callback",
		CodeChallenge: "challenge",
		KCAccessToken: "kc-access-token",
		CreatedAt:     time.Now(),
	}
	s.PutAuthCode(ac)

	consumed := s.ConsumeAuthCode("code-123")
	if consumed == nil {
		t.Fatal("expected to consume auth code")
	}
	if consumed.KCAccessToken != "kc-access-token" {
		t.Errorf("expected kc-access-token, got %s", consumed.KCAccessToken)
	}

	// Second consume should return nil (single-use)
	if s.ConsumeAuthCode("code-123") != nil {
		t.Error("expected nil on second consume (single-use)")
	}
}

func TestStore_AuthCode_Expired(t *testing.T) {
	s := NewStore(time.Hour, 10*time.Minute, 1*time.Millisecond)
	defer s.Close()

	ac := &AuthCode{
		Code:      "code-expired",
		CreatedAt: time.Now(),
	}
	s.PutAuthCode(ac)

	time.Sleep(5 * time.Millisecond)

	if s.ConsumeAuthCode("code-expired") != nil {
		t.Error("expected nil for expired code")
	}
}

func TestStore_AuthCode_NotFound(t *testing.T) {
	s := NewStore(time.Hour, 10*time.Minute, 5*time.Minute)
	defer s.Close()

	if s.ConsumeAuthCode("nonexistent") != nil {
		t.Error("expected nil for nonexistent code")
	}
}

func TestGenerateCode(t *testing.T) {
	code, err := GenerateCode()
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if len(code) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("expected 64 char code, got %d", len(code))
	}
}

func TestGenerateState(t *testing.T) {
	state, err := GenerateState()
	if err != nil {
		t.Fatalf("GenerateState: %v", err)
	}
	if len(state) != 32 { // 16 bytes = 32 hex chars
		t.Errorf("expected 32 char state, got %d", len(state))
	}
}
