package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
	"io"
	"io/fs"
	"path"
	"strings"
	"time"
)

func (s *S3Storage) CertMagicStorage() (certmagic.Storage, error) {
	return s, nil
}

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

// Lock attempts to acquire a lock for the given CertMagic key.
func (s *S3Storage) Lock(ctx context.Context, key string) error {
	lockObjectS3Key := s.s3LockKey(key)
	s.logger.Debug("attempting to lock", zap.String("key", key), zap.String("s3_lock_key", lockObjectS3Key))
	startTime := time.Now()
	lockContent := []byte(startTime.UTC().Format(time.RFC3339Nano)) // Content for the lock file

	for {
		// Check for context cancellation at the beginning of each attempt.
		select {
		case <-ctx.Done():
			s.logger.Debug("lock attempt cancelled by context", zap.String("key", key))
			return ctx.Err()
		default:
		}

		// Check if lock file exists and its status
		headOut, err := s.Client.HeadObject(ctx, &awss3.HeadObjectInput{
			Bucket: aws.String(s.Bucket),
			Key:    aws.String(lockObjectS3Key),
		})

		if err == nil { // Lock file exists
			if headOut.LastModified != nil && time.Since(*headOut.LastModified) < s.lockExpiration {
				s.logger.Debug("lock exists and is active", zap.String("key", key), zap.Time("lock_modified", *headOut.LastModified))
				if time.Since(startTime) > s.lockTimeout {
					return fmt.Errorf("timeout acquiring lock for %s (lock held by another process)", key)
				}
				time.Sleep(s.lockPollInterval) // Wait before retrying
				continue                       // Retry loop
			}
			// Lock file exists but is expired, try to overwrite
			s.logger.Debug("lock exists but is expired, attempting to overwrite", zap.String("key", key))
		} else {
			var nsk *types.NoSuchKey
			var nf *types.NotFound // Some S3-compatibles (like MinIO) return NotFound for HeadObject
			if !(errors.As(err, &nsk) || errors.As(err, &nf)) {
				return fmt.Errorf("checking lock for %s: %w", key, err) // Unexpected error
			}
			// Lock file does not exist, try to create it
			s.logger.Debug("lock does not exist, attempting to create", zap.String("key", key))
		}

		// Attempt to write/overwrite the lock file
		// For more robust locking, consider S3 conditional Puts (If-Match/If-None-Match).
		_, putErr := s.Client.PutObject(ctx, &awss3.PutObjectInput{
			Bucket: aws.String(s.Bucket),
			Key:    aws.String(lockObjectS3Key),
			Body:   bytes.NewReader(lockContent),
		})

		if putErr == nil {
			s.logger.Info("lock acquired", zap.String("key", key))
			return nil // Lock acquired
		}

		s.logger.Error("failed to put lock file, retrying", zap.String("key", key), zap.Error(putErr))
		if time.Since(startTime) > s.lockTimeout {
			return fmt.Errorf("timeout acquiring lock for %s after failed put: %w", key, putErr)
		}
		time.Sleep(s.lockPollInterval) // Wait before retrying
	}
}

// Unlock releases the lock for the given CertMagic key.
func (s *S3Storage) Unlock(ctx context.Context, key string) error {
	lockObjectS3Key := s.s3LockKey(key)
	s.logger.Debug("unlocking", zap.String("key", key), zap.String("s3_lock_key", lockObjectS3Key))
	_, err := s.Client.DeleteObject(ctx, &awss3.DeleteObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(lockObjectS3Key),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			s.logger.Debug("lock file not found on unlock, already released or never existed", zap.String("key", key))
			return nil // Not an error if it's already gone
		}
		return fmt.Errorf("unlocking %s: %w", key, err)
	}
	s.logger.Info("lock released", zap.String("key", key))
	return nil
}

// Store stores the given value at the given CertMagic key.
func (s *S3Storage) Store(ctx context.Context, key string, value []byte) error {
	s3Key := s.s3ObjectKey(key)
	s.logger.Debug("storing", zap.String("key", key), zap.String("s3_key", s3Key), zap.Int("size", len(value)))

	reader, length, err := s.iowrap.ByteReader(value) // Handles encryption if enabled
	if err != nil {
		return fmt.Errorf("preparing data for storing %s: %w", key, err)
	}

	_, err = s.Client.PutObject(ctx, &awss3.PutObjectInput{
		Bucket:        aws.String(s.Bucket),
		Key:           aws.String(s3Key),
		Body:          reader,
		ContentLength: aws.Int64(length), // Important for S3
	})
	if err != nil {
		return fmt.Errorf("storing %s (s3://%s/%s): %w", key, s.Bucket, s3Key, err)
	}
	return nil
}

// Load retrieves the value at the given CertMagic key.
func (s *S3Storage) Load(ctx context.Context, key string) ([]byte, error) {
	s3Key := s.s3ObjectKey(key)
	s.logger.Debug("loading", zap.String("key", key), zap.String("s3_key", s3Key))

	result, err := s.Client.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(s3Key),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return nil, fs.ErrNotExist // CertMagic expects fs.ErrNotExist
		}
		return nil, fmt.Errorf("loading %s (s3://%s/%s): %w", key, s.Bucket, s3Key, err)
	}
	defer result.Body.Close()

	decryptedReader := s.iowrap.WrapReader(result.Body) // Handles decryption
	data, err := io.ReadAll(decryptedReader)
	if err != nil {
		// Check if the error came from our errorReader (e.g., decryption failed)
		var er *errorReader
		if errors.As(err, &er) {
			return nil, fmt.Errorf("reading/decrypting data for %s: %w", key, er.err)
		}
		return nil, fmt.Errorf("reading data for %s: %w", key, err)
	}
	return data, nil
}

// Delete deletes the value at the given CertMagic key.
func (s *S3Storage) Delete(ctx context.Context, key string) error {
	s3Key := s.s3ObjectKey(key)
	s.logger.Debug("deleting", zap.String("key", key), zap.String("s3_key", s3Key))

	_, err := s.Client.DeleteObject(ctx, &awss3.DeleteObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(s3Key),
	})
	if err != nil {
		// CertMagic often doesn't treat "not found" on delete as an error.
		// We log it but return nil to align with typical expectations.
		s.logger.Warn("error deleting object from S3, may or may not be an issue depending on context",
			zap.String("key", key), zap.String("s3_key", s3Key), zap.Error(err))
	}
	return nil // Typically, CertMagic expects nil even if the object didn't exist.
}

// Exists returns true if the given CertMagic key exists.
func (s *S3Storage) Exists(ctx context.Context, key string) bool {
	s3Key := s.s3ObjectKey(key)
	s.logger.Debug("checking exists", zap.String("key", key), zap.String("s3_key", s3Key))

	_, err := s.Client.HeadObject(ctx, &awss3.HeadObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(s3Key),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		var nf *types.NotFound // Some S3-compatibles might return NotFound
		if errors.As(err, &nsk) || errors.As(err, &nf) {
			return false // Key does not exist
		}
		// For other errors, log it and conservatively return false.
		s.logger.Error("error checking existence for key", zap.String("key", key), zap.Error(err))
		return false
	}
	return true // HeadObject succeeded, so key exists
}

// List returns a list of CertMagic keys that match the given prefix.
func (s *S3Storage) List(ctx context.Context, listPrefix string, recursive bool) ([]string, error) {
	// s3ObjectKey will handle adding the main storage prefix.
	// listPrefix is the prefix *within* the CertMagic storage view.
	s3ListPrefix := s.s3ObjectKey(listPrefix)

	// For S3, if listing a "directory", the prefix should usually end with a slash.
	// If listPrefix is empty, s3ListPrefix will be s.Prefix. If s.Prefix is "certs", s3ListPrefix becomes "certs/".
	// If listPrefix is "sites", s3ListPrefix becomes "s.Prefix/sites/".
	if s3ListPrefix != "" && !strings.HasSuffix(s3ListPrefix, "/") {
		s3ListPrefix += "/"
	}
	// If s3ListPrefix was originally empty (meaning s.Prefix and listPrefix were both empty, listing bucket root),
	// it remains empty, which is correct for ListObjectsV2 to list bucket root.

	s.logger.Debug("listing",
		zap.String("certmagic_prefix_arg", listPrefix),
		zap.String("s3_resolved_list_prefix", s3ListPrefix),
		zap.Bool("recursive", recursive))

	var keys []string
	var delimiter *string
	if !recursive {
		delimiter = aws.String("/") // S3's way of listing one level
	}

	paginator := awss3.NewListObjectsV2Paginator(s.Client, &awss3.ListObjectsV2Input{
		Bucket:    aws.String(s.Bucket),
		Prefix:    aws.String(s3ListPrefix),
		Delimiter: delimiter,
	})

	// This is the prefix we need to strip from full S3 keys to get back to CertMagic keys.
	// If s.Prefix is "foo", this will be "foo/". If s.Prefix is "", this will be "".
	stripPrefixFromS3Key := ""
	if s.Prefix != "" {
		stripPrefixFromS3Key = s.Prefix + "/"
	}

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing s3://%s/%s: %w", s.Bucket, s3ListPrefix, err)
		}

		// Add common prefixes (directories) if not recursive
		if !recursive {
			for _, cp := range page.CommonPrefixes {
				if cp.Prefix != nil {
					// S3 common prefixes include the full path. Make it relative to CertMagic root.
					key := strings.TrimPrefix(*cp.Prefix, stripPrefixFromS3Key)
					key = strings.TrimSuffix(key, "/") // CertMagic expects dir names without trailing slash
					if key != "" && !strings.HasSuffix(key, ".lock") {
						keys = append(keys, key)
					}
				}
			}
		}

		// Add objects
		for _, obj := range page.Contents {
			if obj.Key != nil {
				// S3 keys include the full path. Make it relative to CertMagic root.
				// Also, skip the "directory marker" object if S3 returns one (its key is same as prefix).
				if *obj.Key == s3ListPrefix && strings.HasSuffix(s3ListPrefix, "/") {
					continue
				}
				key := strings.TrimPrefix(*obj.Key, stripPrefixFromS3Key)
				if key != "" && !strings.HasSuffix(key, ".lock") {
					keys = append(keys, key)
				}
			}
		}
	}
	return keys, nil
}

// Stat returns information about the given CertMagic key.
func (s *S3Storage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	s3Key := s.s3ObjectKey(key)
	s.logger.Debug("stat", zap.String("key", key), zap.String("s3_key", s3Key))
	var ki certmagic.KeyInfo

	result, err := s.Client.HeadObject(ctx, &awss3.HeadObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(s3Key),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		var nf *types.NotFound
		if errors.As(err, &nsk) || errors.As(err, &nf) {
			return ki, fs.ErrNotExist // CertMagic expects fs.ErrNotExist
		}
		return ki, fmt.Errorf("stat %s (s3://%s/%s): %w", key, s.Bucket, s3Key, err)
	}

	ki.Key = key // CertMagic expects the original, unprefixed key
	if result.ContentLength != nil {
		ki.Size = *result.ContentLength
	}
	if result.LastModified != nil {
		ki.Modified = *result.LastModified
	}
	ki.IsTerminal = true // All S3 objects are considered "files" or terminal nodes
	return ki, nil
}
