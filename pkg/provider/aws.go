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

// AWSSTSClient defines STS AssumeRole operations abstraction.
type AWSSTSClient interface {
	AssumeRoleWithWebIdentity(ctx context.Context, roleArn, roleSessionName, token string, durationSeconds int32) (*STSCredentials, error)
	RevokeSession(ctx context.Context, roleArn, roleSessionName string) error
}

// STSCredentials holds returned AWS STS tokens.
type STSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

// MockAWSSTSClient is a thread-safe in-memory STS simulator for unit tests and local execution.
type MockAWSSTSClient struct {
	mu             sync.Mutex
	ActiveSessions map[string]*STSCredentials
	RevokedSessions map[string]bool
}

// NewMockAWSSTSClient creates an in-memory AWS STS client simulator.
func NewMockAWSSTSClient() *MockAWSSTSClient {
	return &MockAWSSTSClient{
		ActiveSessions:  make(map[string]*STSCredentials),
		RevokedSessions: make(map[string]bool),
	}
}

func (m *MockAWSSTSClient) AssumeRoleWithWebIdentity(ctx context.Context, roleArn, roleSessionName, token string, durationSeconds int32) (*STSCredentials, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	randBytes := make([]byte, 16)
	_, _ = rand.Read(randBytes)
	accessKey := "ASIA" + hex.EncodeToString(randBytes)[:16]
	secBytes := make([]byte, 20)
	_, _ = rand.Read(secBytes)
	secretKey := hex.EncodeToString(secBytes)

	tokenBytes := make([]byte, 32)
	_, _ = rand.Read(tokenBytes)
	sessToken := hex.EncodeToString(tokenBytes)

	creds := &STSCredentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		SessionToken:    sessToken,
		Expiration:      time.Now().UTC().Add(time.Duration(durationSeconds) * time.Second),
	}

	key := fmt.Sprintf("%s/%s", roleArn, roleSessionName)
	m.ActiveSessions[key] = creds
	return creds, nil
}

func (m *MockAWSSTSClient) RevokeSession(ctx context.Context, roleArn, roleSessionName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s/%s", roleArn, roleSessionName)
	delete(m.ActiveSessions, key)
	m.RevokedSessions[key] = true
	return nil
}

// AWSIAMProvider generates temporary AWS credentials via STS AssumeRole / WebIdentity.
type AWSIAMProvider struct {
	client AWSSTSClient
}

// NewAWSIAMProvider creates an AWSIAMProvider.
func NewAWSIAMProvider(client AWSSTSClient) *AWSIAMProvider {
	if client == nil {
		client = NewMockAWSSTSClient()
	}
	return &AWSIAMProvider{
		client: client,
	}
}

func (p *AWSIAMProvider) Name() string {
	return "aws-iam-sts-broker"
}

func (p *AWSIAMProvider) Type() CredentialType {
	return TypeAWSIAM
}

// Generate issues temporary AWS credentials with STS.
func (p *AWSIAMProvider) Generate(ctx context.Context, req Request) (*TemporaryCredentials, lease.RevokeFunc, lease.RotateFunc, error) {
	if req.RoleOrScope == "" {
		return nil, nil, nil, errors.New("AWS IAM role ARN is required")
	}

	sessionNonce := make([]byte, 8)
	if _, err := rand.Read(sessionNonce); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate session nonce: %w", err)
	}
	sessionName := fmt.Sprintf("vb-%s", hex.EncodeToString(sessionNonce))

	ttlSec := int32(req.TTL.Seconds())
	if ttlSec <= 0 {
		ttlSec = 3600 // default 1 hour
	}

	stsCreds, err := p.client.AssumeRoleWithWebIdentity(ctx, req.RoleOrScope, sessionName, req.Identity, ttlSec)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to assume AWS role: %w", err)
	}

	creds := &TemporaryCredentials{
		Type:     TypeAWSIAM,
		IssuedTo: req.Identity,
		Attributes: map[string]string{
			"AWS_ACCESS_KEY_ID":     stsCreds.AccessKeyID,
			"AWS_SECRET_ACCESS_KEY": stsCreds.SecretAccessKey,
			"AWS_SESSION_TOKEN":     stsCreds.SessionToken,
			"AWS_ROLE_ARN":          req.RoleOrScope,
			"AWS_SESSION_NAME":      sessionName,
		},
		TTL:       req.TTL,
		MaxTTL:    req.MaxTTL,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: stsCreds.Expiration,
		Metadata:  req.PolicyTags,
	}

	revokeFn := func(ctx context.Context, l *lease.Lease) error {
		roleArn := l.Data["AWS_ROLE_ARN"]
		sName := l.Data["AWS_SESSION_NAME"]
		return p.client.RevokeSession(ctx, roleArn, sName)
	}

	rotateFn := func(ctx context.Context, l *lease.Lease) error {
		newCreds, err := p.client.AssumeRoleWithWebIdentity(ctx, req.RoleOrScope, sessionName+"-rot", req.Identity, ttlSec)
		if err != nil {
			return err
		}
		l.Data["AWS_ACCESS_KEY_ID"] = newCreds.AccessKeyID
		l.Data["AWS_SECRET_ACCESS_KEY"] = newCreds.SecretAccessKey
		l.Data["AWS_SESSION_TOKEN"] = newCreds.SessionToken
		l.ExpiresAt = newCreds.Expiration
		return nil
	}

	return creds, revokeFn, rotateFn, nil
}
