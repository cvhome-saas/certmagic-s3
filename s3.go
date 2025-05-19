package s3

import (
	"path"
	"strings"
)

// s3ObjectKey constructs the full S3 object key from a CertMagic key and the configured prefix.
func (s *S3Storage) s3ObjectKey(certMagicKey string) string {
	// CertMagic keys are already relative paths, e.g., "certificates/example.com/example.com.crt"
	// We need to ensure they don't have leading slashes before joining with prefix.
	cleanCertMagicKey := strings.TrimPrefix(certMagicKey, "/")
	if s.Prefix == "" {
		return cleanCertMagicKey
	}
	return path.Join(s.Prefix, cleanCertMagicKey)
}

// s3LockKey constructs the S3 key for a lock file corresponding to a CertMagic key.
func (s *S3Storage) s3LockKey(certMagicKey string) string {
	return s.s3ObjectKey(certMagicKey) + ".lock"
}
