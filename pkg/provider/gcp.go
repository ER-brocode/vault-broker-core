package provider

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ER-brocode/vault-broker-core/pkg/lease"
)

// GCPIAMClient abstracts GCP IAM Credentials API for generating OAuth2 access tokens and signing.
type GCPIAMClient interface {
	GenerateAccessToken(ctx context.Context, serviceAccountEmail string, delegates, scopes []string, lifetime time.Duration) (*GCPAccessToken, error)
	RevokeToken(ctx context.Context, accessToken string) error
}

// GCPAccessToken holds ephemeral access token details.
type GCPAccessToken struct {
	AccessToken string
	ExpireTime  time.Time
}

// MockGCPIAMClient provides thread-safe in-memory GCP IAM simulation.
type MockGCPIAMClient struct {
	mu           sync.Mutex
	ActiveTokens map[string]*GCPAccessToken
	RevokedTokens map[string]bool
}

// NewMockGCPIAMClient creates a mock GCP IAM client.
func NewMockGCPIAMClient() *MockGCPIAMClient {
	return &MockGCPIAMClient{
		ActiveTokens:  make(map[string]*GCPAccessToken),
		RevokedTokens: make(map[string]bool),
	}
}

func (m *MockGCPIAMClient) GenerateAccessToken(ctx context.Context, serviceAccountEmail string, delegates, scopes []string, lifetime time.Duration) (*GCPAccessToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tokBytes := make([]byte, 32)
	_, _ = rand.Read(tokBytes)
	tokenStr := "ya29.mock." + hex.EncodeToString(tokBytes)

	token := &GCPAccessToken{
		AccessToken: tokenStr,
		ExpireTime:  time.Now().UTC().Add(lifetime),
	}
	m.ActiveTokens[tokenStr] = token
	return token, nil
}

func (m *MockGCPIAMClient) RevokeToken(ctx context.Context, accessToken string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.ActiveTokens, accessToken)
	m.RevokedTokens[accessToken] = true
	return nil
}

// GCPServiceAccountProvider handles generating dynamic GCP service account OAuth2 tokens.
type GCPServiceAccountProvider struct {
	client GCPIAMClient
}

// NewGCPServiceAccountProvider creates a GCP provider.
func NewGCPServiceAccountProvider(client GCPIAMClient) *GCPServiceAccountProvider {
	if client == nil {
		client = NewMockGCPIAMClient()
	}
	return &GCPServiceAccountProvider{
		client: client,
	}
}

func (p *GCPServiceAccountProvider) Name() string {
	return "gcp-service-account-broker"
}

func (p *GCPServiceAccountProvider) Type() CredentialType {
	return TypeGCPSA
}

// Generate mints a short-lived GCP OAuth2 access token for a designated service account.
func (p *GCPServiceAccountProvider) Generate(ctx context.Context, req Request) (*TemporaryCredentials, lease.RevokeFunc, lease.RotateFunc, error) {
	if req.RoleOrScope == "" {
		return nil, nil, nil, errors.New("GCP service account email or scope is required")
	}

	ttl := req.TTL
	if ttl <= 0 {
		ttl = time.Hour
	}

	scopes := []string{"https://www.googleapis.com/auth/cloud-platform"}
	gcpToken, err := p.client.GenerateAccessToken(ctx, req.RoleOrScope, nil, scopes, ttl)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate GCP access token: %w", err)
	}

	creds := &TemporaryCredentials{
		Type:     TypeGCPSA,
		IssuedTo: req.Identity,
		Attributes: map[string]string{
			"GCP_SERVICE_ACCOUNT": req.RoleOrScope,
			"GCP_ACCESS_TOKEN":    gcpToken.AccessToken,
			"TOKEN_TYPE":          "Bearer",
		},
		TTL:       ttl,
		MaxTTL:    req.MaxTTL,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: gcpToken.ExpireTime,
		Metadata:  req.PolicyTags,
	}

	revokeFn := func(ctx context.Context, l *lease.Lease) error {
		tok := l.Data["GCP_ACCESS_TOKEN"]
		return p.client.RevokeToken(ctx, tok)
	}

	rotateFn := func(ctx context.Context, l *lease.Lease) error {
		newTok, err := p.client.GenerateAccessToken(ctx, req.RoleOrScope, nil, scopes, ttl)
		if err != nil {
			return err
		}
		l.Data["GCP_ACCESS_TOKEN"] = newTok.AccessToken
		l.ExpiresAt = newTok.ExpireTime
		return nil
	}

	return creds, revokeFn, rotateFn, nil
}
