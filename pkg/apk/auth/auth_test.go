package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"testing"
)

type successAuth struct{}

func (s successAuth) AddAuth(_ context.Context, req *http.Request) error {
	req.SetBasicAuth("user", "pass")
	return nil
}

type failAuth struct{}

func (f failAuth) AddAuth(_ context.Context, req *http.Request) error {
	return errors.New("failed to add auth")
}

func TestMultiAuthenticator(t *testing.T) {
	tests := []struct {
		name       string
		auths      []Authenticator
		expectAuth bool
		expectErr  bool
	}{
		{
			name:       "success auth first",
			auths:      []Authenticator{successAuth{}, failAuth{}},
			expectAuth: true,
			expectErr:  false,
		},
		{
			name:       "fail auth first",
			auths:      []Authenticator{failAuth{}, successAuth{}},
			expectAuth: true,
			expectErr:  false,
		},
		{
			name:       "all fail auth",
			auths:      []Authenticator{failAuth{}, failAuth{}},
			expectAuth: false,
			expectErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			multiAuth := MultiAuthenticator(tt.auths...)
			req, _ := http.NewRequest("GET", "http://example.com", nil)
			err := multiAuth.AddAuth(context.Background(), req)

			if tt.expectErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("did not expect error but got: %v", err)
			}

			user, pass, ok := req.BasicAuth()
			if tt.expectAuth && !ok {
				t.Errorf("expected auth but got none")
			}
			if !tt.expectAuth && ok {
				t.Errorf("did not expect auth but got user: %s, pass: %s", user, pass)
			}
		})
	}
}

// TestRefreshCGRAuthResetsTokenCache validates that RefreshCGRAuth resets the
// rate limiter and cached token, enabling fresh authentication after a 401.
// This is the fix for expired tokens in builds exceeding the 60-minute TTL.
func TestRefreshCGRAuthResetsTokenCache(t *testing.T) {
	// Build a JWT with an identity in the sub claim
	identity := "ce2d1984a010471142503340d670612d63ffb9f6/ac92e3a8b3865440"
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, `{"sub":"%s"}`, identity))
	jwtToken := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString([]byte("sig"))

	t.Setenv("HTTP_AUTH", fmt.Sprintf("basic:apk.cgr.dev:user:%s", jwtToken))

	// Simulate cached state: tok is set and rate limiter has fired
	tok = "expired-token"

	// RefreshCGRAuth should reset the cache (chainctl won't run in test, but cache reset is what matters)
	RefreshCGRAuth(context.Background())

	// After refresh, tok should be cleared to force fresh token fetch
	if tok != "" {
		t.Errorf("RefreshCGRAuth() did not clear cached token, got %q", tok)
	}
}
