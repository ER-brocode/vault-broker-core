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

// DatabaseExecutor abstracts SQL execution for provisioning and revoking ephemeral database users.
type DatabaseExecutor interface {
	CreateDynamicUser(ctx context.Context, username, password, role string, expiration time.Time) error
	DropUser(ctx context.Context, username string) error
	CheckUserExists(ctx context.Context, username string) bool
}

// MockDatabaseExecutor simulates database role and user creation in PostgreSQL or MySQL.
type MockDatabaseExecutor struct {
	mu           sync.Mutex
	ActiveUsers  map[string]string // username -> role
	DroppedUsers map[string]bool
}

// NewMockDatabaseExecutor creates an in-memory SQL user lifecycle simulator.
func NewMockDatabaseExecutor() *MockDatabaseExecutor {
	return &MockDatabaseExecutor{
		ActiveUsers:  make(map[string]string),
		DroppedUsers: make(map[string]bool),
	}
}

func (m *MockDatabaseExecutor) CreateDynamicUser(ctx context.Context, username, password, role string, expiration time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ActiveUsers[username] = role
	delete(m.DroppedUsers, username)
	return nil
}

func (m *MockDatabaseExecutor) DropUser(ctx context.Context, username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.ActiveUsers, username)
	m.DroppedUsers[username] = true
	return nil
}

func (m *MockDatabaseExecutor) CheckUserExists(ctx context.Context, username string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, exists := m.ActiveUsers[username]
	return exists
}

// DatabaseProvider generates dynamic temporary SQL users with auto-expiry.
type DatabaseProvider struct {
	dbType   CredentialType
	executor DatabaseExecutor
	host     string
	port     int
	database string
}

// NewDatabaseProvider initializes a dynamic database credential provider.
func NewDatabaseProvider(dbType CredentialType, host string, port int, dbName string, exec DatabaseExecutor) *DatabaseProvider {
	if exec == nil {
		exec = NewMockDatabaseExecutor()
	}
	return &DatabaseProvider{
		dbType:   dbType,
		executor: exec,
		host:     host,
		port:     port,
		database: dbName,
	}
}

func (p *DatabaseProvider) Name() string {
	return fmt.Sprintf("%s-credential-broker", string(p.dbType))
}

func (p *DatabaseProvider) Type() CredentialType {
	return p.dbType
}

// Generate provisions a short-lived random database username and password with assigned grants.
func (p *DatabaseProvider) Generate(ctx context.Context, req Request) (*TemporaryCredentials, lease.RevokeFunc, lease.RotateFunc, error) {
	if req.RoleOrScope == "" {
		return nil, nil, nil, errors.New("database role or permissions template is required")
	}

	ttl := req.TTL
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}

	userBytes := make([]byte, 6)
	if _, err := rand.Read(userBytes); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate username: %w", err)
	}
	username := fmt.Sprintf("v_ephem_%s", hex.EncodeToString(userBytes))

	passBytes := make([]byte, 16)
	if _, err := rand.Read(passBytes); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate password: %w", err)
	}
	password := hex.EncodeToString(passBytes)

	expiresAt := time.Now().UTC().Add(ttl)
	if err := p.executor.CreateDynamicUser(ctx, username, password, req.RoleOrScope, expiresAt); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create dynamic database user: %w", err)
	}

	creds := &TemporaryCredentials{
		Type:     p.dbType,
		IssuedTo: req.Identity,
		Attributes: map[string]string{
			"DB_HOST":     p.host,
			"DB_PORT":     fmt.Sprintf("%d", p.port),
			"DB_DATABASE": p.database,
			"DB_USERNAME": username,
			"DB_PASSWORD": password,
			"DB_ROLE":     req.RoleOrScope,
		},
		TTL:       ttl,
		MaxTTL:    req.MaxTTL,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
		Metadata:  req.PolicyTags,
	}

	revokeFn := func(ctx context.Context, l *lease.Lease) error {
		u := l.Data["DB_USERNAME"]
		return p.executor.DropUser(ctx, u)
	}

	rotateFn := func(ctx context.Context, l *lease.Lease) error {
		oldUser := l.Data["DB_USERNAME"]
		newUserBytes := make([]byte, 6)
		_, _ = rand.Read(newUserBytes)
		newUsername := fmt.Sprintf("v_ephem_%s", hex.EncodeToString(newUserBytes))

		newPassBytes := make([]byte, 16)
		_, _ = rand.Read(newPassBytes)
		newPassword := hex.EncodeToString(newPassBytes)

		newExpiry := time.Now().UTC().Add(ttl)
		if err := p.executor.CreateDynamicUser(ctx, newUsername, newPassword, req.RoleOrScope, newExpiry); err != nil {
			return err
		}

		// Drop old user
		_ = p.executor.DropUser(ctx, oldUser)

		l.Data["DB_USERNAME"] = newUsername
		l.Data["DB_PASSWORD"] = newPassword
		l.ExpiresAt = newExpiry
		return nil
	}

	return creds, revokeFn, rotateFn, nil
}
