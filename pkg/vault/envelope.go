package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

var (
	ErrKeyNotFound      = errors.New("key encryption key (KEK) not found")
	ErrCiphertextShort  = errors.New("ciphertext too short to contain valid nonce")
	ErrDecryptionFailed = errors.New("envelope decryption failed authentication or integrity check")
	ErrInvalidEnvelope  = errors.New("envelope structure is invalid")
	ErrPayloadCorrupt   = errors.New("decrypted payload corrupted")
)

// EnvelopeCipher defines envelope encryption payload metadata and encrypted components.
type EnvelopePayload struct {
	KeyID             string            `json:"key_id"`
	EncryptedDEK      string            `json:"encrypted_dek"`      // Base64-encoded DEK encrypted under KEK
	DEKNonce          string            `json:"dek_nonce"`          // Base64-encoded nonce for DEK encryption
	Ciphertext        string            `json:"ciphertext"`         // Base64-encoded payload encrypted under DEK
	PayloadNonce      string            `json:"payload_nonce"`      // Base64-encoded nonce for Payload encryption
	Algorithm         string            `json:"algorithm"`          // AES-256-GCM
	KeyDerivationInfo string            `json:"kdf_info,omitempty"` // HKDF info context
	CreatedAt         time.Time         `json:"created_at"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// MasterKeyManager manages Key Encryption Keys (KEKs) and KMS-like master keys.
type MasterKeyManager struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

// NewMasterKeyManager creates a new in-memory master key manager for KEKs.
func NewMasterKeyManager() *MasterKeyManager {
	return &MasterKeyManager{
		keys: make(map[string][]byte),
	}
}

// RegisterKEK registers a 256-bit Key Encryption Key with a given identifier.
func (m *MasterKeyManager) RegisterKEK(keyID string, kek []byte) error {
	if len(kek) != 32 {
		return errors.New("KEK must be exactly 32 bytes (256-bit)")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := make([]byte, 32)
	copy(copied, kek)
	m.keys[keyID] = copied
	return nil
}

// GenerateKEK generates and registers a cryptographically secure 256-bit KEK.
func (m *MasterKeyManager) GenerateKEK(keyID string) ([]byte, error) {
	kek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, kek); err != nil {
		return nil, fmt.Errorf("failed to generate random KEK: %w", err)
	}
	if err := m.RegisterKEK(keyID, kek); err != nil {
		return nil, err
	}
	return kek, nil
}

// GetKEK retrieves a registered KEK by ID.
func (m *MasterKeyManager) GetKEK(keyID string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key, exists := m.keys[keyID]
	if !exists {
		return nil, ErrKeyNotFound
	}
	copied := make([]byte, len(key))
	copy(copied, key)
	return copied, nil
}

// EnvelopeService handles AES-256-GCM envelope encryption and decryption with HKDF key derivation.
type EnvelopeService struct {
	keyManager *MasterKeyManager
}

// NewEnvelopeService returns an initialized EnvelopeService.
func NewEnvelopeService(km *MasterKeyManager) *EnvelopeService {
	return &EnvelopeService{
		keyManager: km,
	}
}

// Encrypt encrypts raw plaintext data using a freshly generated ephemeral Data Encryption Key (DEK).
// The ephemeral DEK is in turn encrypted using the specified Key Encryption Key (KEK).
func (s *EnvelopeService) Encrypt(keyID string, plaintext []byte, metadata map[string]string) (*EnvelopePayload, error) {
	kek, err := s.keyManager.GetKEK(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve KEK: %w", err)
	}

	// 1. Generate a 32-byte ephemeral DEK
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral DEK: %w", err)
	}

	// 2. Encrypt plaintext with DEK using AES-256-GCM
	dekBlock, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize DEK cipher: %w", err)
	}
	dekGCM, err := cipher.NewGCM(dekBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize DEK GCM: %w", err)
	}

	payloadNonce := make([]byte, dekGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, payloadNonce); err != nil {
		return nil, fmt.Errorf("failed to generate payload nonce: %w", err)
	}

	// Additional Authenticated Data (AAD) bound to the envelope key ID
	payloadAAD := []byte(fmt.Sprintf("vault-broker:%s", keyID))
	ciphertext := dekGCM.Seal(nil, payloadNonce, plaintext, payloadAAD)

	// 3. Derive a sub-key for DEK wrapping using HKDF with SHA-256
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate HKDF salt: %w", err)
	}
	kdfInfo := "envelope-dek-wrap-v1"
	hkdfReader := hkdf.New(sha256.New, kek, salt, []byte(kdfInfo))
	derivedKEK := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, derivedKEK); err != nil {
		return nil, fmt.Errorf("failed to derive DEK wrap key: %w", err)
	}

	// 4. Encrypt DEK using derived KEK
	kekBlock, err := aes.NewCipher(derivedKEK)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize KEK cipher: %w", err)
	}
	kekGCM, err := cipher.NewGCM(kekBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize KEK GCM: %w", err)
	}

	dekNonce := make([]byte, kekGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, dekNonce); err != nil {
		return nil, fmt.Errorf("failed to generate DEK nonce: %w", err)
	}

	// Store salt + encrypted DEK together in EncryptedDEK field
	wrappedDEK := kekGCM.Seal(nil, dekNonce, dek, []byte(keyID))
	combinedWrappedDEK := append(salt, wrappedDEK...)

	return &EnvelopePayload{
		KeyID:             keyID,
		EncryptedDEK:      base64.StdEncoding.EncodeToString(combinedWrappedDEK),
		DEKNonce:          base64.StdEncoding.EncodeToString(dekNonce),
		Ciphertext:        base64.StdEncoding.EncodeToString(ciphertext),
		PayloadNonce:      base64.StdEncoding.EncodeToString(payloadNonce),
		Algorithm:         "AES-256-GCM/HKDF-SHA256",
		KeyDerivationInfo: kdfInfo,
		CreatedAt:         time.Now().UTC(),
		Metadata:          metadata,
	}, nil
}

// Decrypt unpacks an EnvelopePayload, unwraps the ephemeral DEK via KEK, and decrypts the ciphertext.
func (s *EnvelopeService) Decrypt(payload *EnvelopePayload) ([]byte, error) {
	if payload == nil {
		return nil, ErrInvalidEnvelope
	}

	kek, err := s.keyManager.GetKEK(payload.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve KEK for decryption: %w", err)
	}

	combinedWrappedDEK, err := base64.StdEncoding.DecodeString(payload.EncryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encrypted DEK: %w", err)
	}
	if len(combinedWrappedDEK) < 16 {
		return nil, errors.New("wrapped DEK payload too short")
	}

	salt := combinedWrappedDEK[:16]
	wrappedDEK := combinedWrappedDEK[16:]

	dekNonce, err := base64.StdEncoding.DecodeString(payload.DEKNonce)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 DEK nonce: %w", err)
	}

	// 1. Re-derive KEK using HKDF with stored salt
	kdfInfo := payload.KeyDerivationInfo
	if kdfInfo == "" {
		kdfInfo = "envelope-dek-wrap-v1"
	}
	hkdfReader := hkdf.New(sha256.New, kek, salt, []byte(kdfInfo))
	derivedKEK := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, derivedKEK); err != nil {
		return nil, fmt.Errorf("failed to re-derive DEK wrap key: %w", err)
	}

	kekBlock, err := aes.NewCipher(derivedKEK)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize KEK cipher: %w", err)
	}
	kekGCM, err := cipher.NewGCM(kekBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize KEK GCM: %w", err)
	}

	// 2. Unwrap DEK
	dek, err := kekGCM.Open(nil, dekNonce, wrappedDEK, []byte(payload.KeyID))
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	// 3. Decrypt ciphertext using unwrapped DEK
	ciphertext, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 ciphertext: %w", err)
	}
	payloadNonce, err := base64.StdEncoding.DecodeString(payload.PayloadNonce)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 payload nonce: %w", err)
	}

	dekBlock, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize DEK cipher: %w", err)
	}
	dekGCM, err := cipher.NewGCM(dekBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize DEK GCM: %w", err)
	}

	payloadAAD := []byte(fmt.Sprintf("vault-broker:%s", payload.KeyID))
	plaintext, err := dekGCM.Open(nil, payloadNonce, ciphertext, payloadAAD)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// MarshalSerializes envelope payload into standard JSON format.
func (p *EnvelopePayload) Marshal() ([]byte, error) {
	return json.Marshal(p)
}

// UnmarshalEnvelopePayload parses JSON bytes into an EnvelopePayload.
func UnmarshalEnvelopePayload(data []byte) (*EnvelopePayload, error) {
	var p EnvelopePayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
