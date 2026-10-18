package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
)

// Standard 256-bit prime modulus for finite field arithmetic in Shamir's Secret Sharing (GF(p)).
// p is the prime 2^256 - 189 (the largest prime less than 2^256).
var (
	fieldPrime, _ = new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007913129639747", 10)
)

var (
	ErrInvalidThreshold = errors.New("threshold must be at least 2 and cannot exceed total shares")
	ErrDuplicateShare   = errors.New("duplicate share index detected in Shamir split/combine")
	ErrShareCorrupt     = errors.New("invalid share format or corrupt share point")
	ErrInsufficientPart = errors.New("insufficient shares to reach reconstruction threshold")
)

// ShamirShare represents a single evaluation point (x, f(x)) of the polynomial.
type ShamirShare struct {
	Index uint32 `json:"index"` // X-coordinate (1 <= X <= totalShares)
	Value string `json:"value"` // Hex-encoded Y-coordinate f(x)
	Tag   string `json:"tag"`   // Cryptographic integrity check hash
}

// ShamirScheme handles (k, n) Shamir Secret Sharing over GF(p).
type ShamirScheme struct {
	mu sync.RWMutex
}

// NewShamirScheme instantiates a new ShamirScheme engine.
func NewShamirScheme() *ShamirScheme {
	return &ShamirScheme{}
}

// Split divides a secret (up to 32 bytes) into n shares, requiring threshold k to reconstruct.
func (s *ShamirScheme) Split(secret []byte, totalShares, threshold int) ([]ShamirShare, error) {
	if threshold < 2 || threshold > totalShares {
		return nil, ErrInvalidThreshold
	}
	if len(secret) == 0 || len(secret) > 32 {
		return nil, errors.New("secret must be non-empty and up to 32 bytes")
	}

	// Interpret secret as big.Int in GF(p)
	secretInt := new(big.Int).SetBytes(secret)
	if secretInt.Cmp(fieldPrime) >= 0 {
		return nil, errors.New("secret value exceeds finite field prime")
	}

	// Generate threshold-1 random coefficients: a_1, a_2, ..., a_{k-1}
	// Polynomial: f(x) = secret + a_1*x + a_2*x^2 + ... + a_{k-1}*x^{k-1} mod p
	coefficients := make([]*big.Int, threshold)
	coefficients[0] = secretInt

	for i := 1; i < threshold; i++ {
		coeff, err := rand.Int(rand.Reader, fieldPrime)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random coefficient: %w", err)
		}
		coefficients[i] = coeff
	}

	shares := make([]ShamirShare, totalShares)
	for i := 1; i <= totalShares; i++ {
		x := big.NewInt(int64(i))
		y := evaluatePolynomial(coefficients, x, fieldPrime)

		yBytes := y.Bytes()
		yHex := hex.EncodeToString(yBytes)

		// Compute verification tag
		h := sha256.New()
		h.Write([]byte(fmt.Sprintf("%d:%s", i, yHex)))
		tag := hex.EncodeToString(h.Sum(nil)[:8])

		shares[i-1] = ShamirShare{
			Index: uint32(i),
			Value: yHex,
			Tag:   tag,
		}
	}

	return shares, nil
}

// Combine reconstructs the original secret from any k valid shares using Lagrange interpolation.
func (s *ShamirScheme) Combine(shares []ShamirShare, threshold int) ([]byte, error) {
	if len(shares) < threshold {
		return nil, ErrInsufficientPart
	}

	// Validate shares and eliminate potential duplicates
	seen := make(map[uint32]bool)
	type point struct {
		x *big.Int
		y *big.Int
	}
	points := make([]point, 0, threshold)

	for _, sh := range shares {
		if seen[sh.Index] {
			return nil, ErrDuplicateShare
		}
		seen[sh.Index] = true

		// Check integrity tag
		h := sha256.New()
		h.Write([]byte(fmt.Sprintf("%d:%s", sh.Index, sh.Value)))
		expectedTag := hex.EncodeToString(h.Sum(nil)[:8])
		if sh.Tag != expectedTag {
			return nil, ErrShareCorrupt
		}

		yBytes, err := hex.DecodeString(sh.Value)
		if err != nil {
			return nil, ErrShareCorrupt
		}

		x := big.NewInt(int64(sh.Index))
		y := new(big.Int).SetBytes(yBytes)

		points = append(points, point{x: x, y: y})
		if len(points) == threshold {
			break
		}
	}

	// Lagrange Interpolation at x = 0:
	// secret = sum_{j=0}^{k-1} ( y_j * prod_{m != j} ( -x_m / (x_j - x_m) ) ) mod p
	secret := big.NewInt(0)

	for j := 0; j < threshold; j++ {
		xj := points[j].x
		yj := points[j].y

		numerator := big.NewInt(1)
		denominator := big.NewInt(1)

		for m := 0; m < threshold; m++ {
			if m == j {
				continue
			}
			xm := points[m].x

			// num = num * (-xm) mod p
			negXm := new(big.Int).Neg(xm)
			negXm.Mod(negXm, fieldPrime)
			numerator.Mul(numerator, negXm)
			numerator.Mod(numerator, fieldPrime)

			// den = den * (xj - xm) mod p
			diff := new(big.Int).Sub(xj, xm)
			diff.Mod(diff, fieldPrime)
			denominator.Mul(denominator, diff)
			denominator.Mod(denominator, fieldPrime)
		}

		// Compute modular inverse of denominator
		invDen := new(big.Int).ModInverse(denominator, fieldPrime)
		if invDen == nil {
			return nil, errors.New("failed modular inverse in Shamir interpolation")
		}

		basis := new(big.Int).Mul(numerator, invDen)
		basis.Mod(basis, fieldPrime)

		term := new(big.Int).Mul(yj, basis)
		term.Mod(term, fieldPrime)

		secret.Add(secret, term)
		secret.Mod(secret, fieldPrime)
	}

	secretBytes := secret.Bytes()
	return secretBytes, nil
}

// evaluatePolynomial evaluates f(x) = sum_{i=0}^{deg} c_i * x^i mod p using Horner's method.
func evaluatePolynomial(coefficients []*big.Int, x, p *big.Int) *big.Int {
	deg := len(coefficients) - 1
	result := new(big.Int).Set(coefficients[deg])

	for i := deg - 1; i >= 0; i-- {
		result.Mul(result, x)
		result.Add(result, coefficients[i])
		result.Mod(result, p)
	}

	return result
}
