package s3

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/nacl/secretbox"
	"io"
)

// --- IO Interface and Implementations ---

// IO defines methods for possibly encrypting/decrypting data.
type IO interface {
	// ByteReader takes plaintext, potentially encrypts it, and returns an io.Reader for the (cipher)text
	// along with its length and any error encountered during preparation (e.g., nonce generation).
	ByteReader(plaintext []byte) (reader io.Reader, length int64, err error)
	// WrapReader takes a reader of (cipher)text and returns an io.Reader that yields plaintext.
	WrapReader(ciphertextReader io.Reader) io.Reader
}

// CleartextIO provides IO operations without encryption.
type CleartextIO struct{}

// ByteReader returns a reader for the plaintext and its length.
func (c *CleartextIO) ByteReader(plaintext []byte) (io.Reader, int64, error) {
	return bytes.NewReader(plaintext), int64(len(plaintext)), nil
}

// WrapReader returns the original reader as no decryption is needed.
func (c *CleartextIO) WrapReader(ciphertextReader io.Reader) io.Reader {
	return ciphertextReader
}

// SecretBoxIO provides IO operations with NaCl secretbox encryption.
type SecretBoxIO struct {
	SecretKey [32]byte
}

// ByteReader encrypts plaintext using SecretKey and returns a reader to the ciphertext (nonce + encrypted_data)
// and its total length.
func (sb *SecretBoxIO) ByteReader(plaintext []byte) (io.Reader, int64, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, 0, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Ciphertext will be nonce + sealed_data.
	// secretbox.Seal prepends to the first argument if it has capacity,
	// otherwise allocates. We provide a slice starting with the nonce.
	sealed := secretbox.Seal(nonce[:], plaintext, &nonce, &sb.SecretKey)
	return bytes.NewReader(sealed), int64(len(sealed)), nil
}

// errorReader is a helper to return an error when Read is called.
// This is useful if an error occurs during the setup of a wrapped reader (e.g., reading nonce).
type errorReader struct {
	err error
}

func (er *errorReader) Read(p []byte) (n int, err error) {
	return 0, er.err
}

// WrapReader takes a reader of ciphertext (nonce + encrypted_data) and returns a reader that decrypts on-the-fly.
func (sb *SecretBoxIO) WrapReader(ciphertextReader io.Reader) io.Reader {
	var nonce [24]byte
	// Read exactly 24 bytes for the nonce.
	n, err := io.ReadFull(ciphertextReader, nonce[:])
	if err != nil {
		// Handle cases where stream is too short for a nonce or other read errors.
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return &errorReader{err: fmt.Errorf("failed to read full nonce (short stream): %w", err)}
		}
		return &errorReader{err: fmt.Errorf("failed to read nonce: %w", err)}
	}
	if n != 24 { // Should be caught by ReadFull's ErrUnexpectedEOF, but double check.
		return &errorReader{err: fmt.Errorf("read %d bytes for nonce, expected 24", n)}
	}

	ciphertext, err := io.ReadAll(ciphertextReader)
	if err != nil {
		return &errorReader{err: fmt.Errorf("failed to read ciphertext body: %w", err)}
	}

	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, &sb.SecretKey)
	if !ok {
		return &errorReader{err: errors.New("failed to decrypt data (secretbox.Open failed)")}
	}
	return bytes.NewReader(plaintext)
}
