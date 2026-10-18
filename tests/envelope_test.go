package tests

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/ER-brocode/vault-broker-core/pkg/vault"
)

func TestEnvelopeEncryptionCycle(t *testing.T) {
	km := vault.NewMasterKeyManager()
	keyID := "prod/master-kek-2026"

	// 1. Generate master KEK
	_, err := km.GenerateKEK(keyID)
	if err != nil {
		t.Fatalf("failed to generate KEK: %v", err)
	}

	service := vault.NewEnvelopeService(km)

	// 2. Prepare test payload
	originalPlaintext := []byte("topsecret-database-master-password-$%#@!123456789")
	metadata := map[string]string{
		"environment": "production",
		"component":   "vault-broker-core",
	}

	// 3. Encrypt
	envelope, err := service.Encrypt(keyID, originalPlaintext, metadata)
	if err != nil {
		t.Fatalf("envelope encryption failed: %v", err)
	}

	if envelope.Algorithm != "AES-256-GCM/HKDF-SHA256" {
		t.Errorf("unexpected algorithm: %s", envelope.Algorithm)
	}
	if envelope.EncryptedDEK == "" || envelope.Ciphertext == "" {
		t.Fatal("ciphertext or wrapped DEK is empty")
	}

	// 4. Decrypt
	decrypted, err := service.Decrypt(envelope)
	if err != nil {
		t.Fatalf("envelope decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, originalPlaintext) {
		t.Fatalf("decrypted data does not match original! got %s, want %s", string(decrypted), string(originalPlaintext))
	}
}

func TestEnvelopeTamperingDetection(t *testing.T) {
	km := vault.NewMasterKeyManager()
	keyID := "prod/kek-tamper-test"
	_, _ = km.GenerateKEK(keyID)

	service := vault.NewEnvelopeService(km)
	plaintext := []byte("confidential-microservice-token")

	envelope, err := service.Encrypt(keyID, plaintext, nil)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Tamper with ciphertext
	tamperedBytes := []byte(envelope.Ciphertext)
	if tamperedBytes[0] == 'A' {
		tamperedBytes[0] = 'B'
	} else {
		tamperedBytes[0] = 'A'
	}
	envelope.Ciphertext = string(tamperedBytes)

	_, err = service.Decrypt(envelope)
	if err == nil {
		t.Fatal("expected decryption failure due to tampered ciphertext authentication tag, but got nil")
	}
}

func TestShamirSecretSharing(t *testing.T) {
	scheme := vault.NewShamirScheme()

	secret := make([]byte, 32)
	_, _ = rand.Read(secret)

	totalShares := 5
	threshold := 3

	// Split
	shares, err := scheme.Split(secret, totalShares, threshold)
	if err != nil {
		t.Fatalf("Shamir split failed: %v", err)
	}

	if len(shares) != totalShares {
		t.Fatalf("expected %d shares, got %d", totalShares, len(shares))
	}

	// 1. Recombine with exact threshold (3 shares: 0, 2, 4)
	subset1 := []vault.ShamirShare{shares[0], shares[2], shares[4]}
	recovered1, err := scheme.Combine(subset1, threshold)
	if err != nil {
		t.Fatalf("recombination failed with subset 1: %v", err)
	}

	if !bytes.Equal(recovered1, secret) {
		t.Fatalf("recovered secret mismatch: got %x, want %x", recovered1, secret)
	}

	// 2. Recombine with different 3 shares (1, 3, 4)
	subset2 := []vault.ShamirShare{shares[1], shares[3], shares[4]}
	recovered2, err := scheme.Combine(subset2, threshold)
	if err != nil {
		t.Fatalf("recombination failed with subset 2: %v", err)
	}

	if !bytes.Equal(recovered2, secret) {
		t.Fatalf("recovered secret mismatch: got %x, want %x", recovered2, secret)
	}

	// 3. Fail with insufficient shares (2 shares when threshold is 3)
	subsetInsufficient := []vault.ShamirShare{shares[0], shares[1]}
	_, err = scheme.Combine(subsetInsufficient, threshold)
	if err == nil {
		t.Fatal("expected error with insufficient shares, got nil")
	}
}
