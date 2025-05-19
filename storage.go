package s3

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

// S3Storage implements /.Storage using AWS S3.
type S3Storage struct {
	logger *zap.Logger

	Client *awss3.Client
	Bucket string `json:"bucket,omitempty"`
	Region string `json:"region,omitempty"`
	Prefix string `json:"prefix,omitempty"`

	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"` // For S3-compatible services

	EncryptionKey string `json:"encryption_key,omitempty"`
	iowrap        IO

	// Lock configuration
	lockExpiration   time.Duration
	lockPollInterval time.Duration
	lockTimeout      time.Duration
}

// Interface guards
var (
	_ caddy.Provisioner      = (*S3Storage)(nil)
	_ caddy.StorageConverter = (*S3Storage)(nil)
	_ caddyfile.Unmarshaler  = (*S3Storage)(nil)
	_ certmagic.Storage      = (*S3Storage)(nil)
	_ certmagic.Locker       = (*S3Storage)(nil)
)

func init() {
	caddy.RegisterModule(new(S3Storage))
}

// CaddyModule returns the Caddy module information.
func (s *S3Storage) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.storage.s3", // Consider "caddy.storage.aws_s3" if this is a new distinct module
		New: func() caddy.Module {
			return new(S3Storage)
		},
	}
}

// Provision sets up the S3 storage module.
func (s *S3Storage) Provision(ctx caddy.Context) error {
	s.logger = ctx.Logger(s)

	// Defaults for locking
	s.lockExpiration = 2 * time.Minute
	s.lockPollInterval = 1 * time.Second
	s.lockTimeout = 30 * time.Second

	if s.Bucket == "" {
		return fmt.Errorf("s3 storage: bucket must be specified")
	}
	if s.Region == "" && s.Endpoint == "" { // If not using a custom endpoint which might not need a region
		s.logger.Warn("s3 storage: region not specified, relying on SDK discovery. Explicitly setting region is recommended for AWS S3.")
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.TODO(), // Use context.TODO() for one-time setup
		awsconfig.WithRegion(s.Region),
	)
	if err != nil {
		return fmt.Errorf("s3 storage: loading AWS config: %w", err)
	}

	if s.AccessKeyID != "" && s.SecretAccessKey != "" {
		awsCfg.Credentials = aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(s.AccessKeyID, s.SecretAccessKey, ""))
		s.logger.Info("using explicit AWS credentials")
	} else {
		s.logger.Info("using default AWS credential chain (e.g., IAM role, env vars, or shared config)")
	}

	s3ClientOpts := []func(*awss3.Options){}
	if s.Endpoint != "" {
		s3ClientOpts = append(s3ClientOpts, func(o *awss3.Options) {
			o.BaseEndpoint = aws.String(s.Endpoint)
			// For many S3-compatible services, path-style addressing is needed.
			o.UsePathStyle = true // Common for MinIO, Ceph, etc.
			s.logger.Info("using custom S3 endpoint", zap.String("endpoint", s.Endpoint))
		})
	}

	s.Client = awss3.NewFromConfig(awsCfg, s3ClientOpts...)

	// Initialize encryption wrapper
	if len(s.EncryptionKey) == 0 {
		s.logger.Info("clear text certificate storage active")
		s.iowrap = &CleartextIO{}
	} else if len(s.EncryptionKey) != 32 { // NaCl secretbox key size
		return errors.New("encryption key must have exactly 32 bytes for NaCl secretbox")
	} else {
		s.logger.Info("encrypted certificate storage active")
		sb := &SecretBoxIO{}
		copy(sb.SecretKey[:], []byte(s.EncryptionKey))
		s.iowrap = sb
	}

	s.logger.Info("s3 storage provisioned",
		zap.String("bucket", s.Bucket),
		zap.String("region", s.Region),
		zap.String("prefix", s.Prefix),
		zap.Bool("encryption_enabled", len(s.EncryptionKey) > 0),
	)
	return nil
}

// UnmarshalCaddyfile parses the Caddyfile configuration.
func (s *S3Storage) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() { // Consume directive name "s3"
		if d.NextArg() {
			return d.ArgErr() // No args on directive line itself
		}
		for d.NextBlock(0) { // Enter the block
			key := d.Val()
			var value string // Most subdirectives take one value
			if !d.AllArgs(&value) {
				return d.ArgErr()
			}
			switch key {
			case "bucket":
				s.Bucket = value
			case "region":
				s.Region = value
			case "prefix":
				s.Prefix = value
			case "access_key_id":
				s.AccessKeyID = value
			case "secret_access_key":
				s.SecretAccessKey = value
			case "endpoint":
				s.Endpoint = value
			case "encryption_key":
				s.EncryptionKey = value
			default:
				return d.Errf("unrecognized s3 storage subdirective '%s'", key)
			}
		}
	}
	if s.Prefix == "" {
		s.Prefix = "certmagic" // Default prefix
	}
	s.Prefix = strings.Trim(s.Prefix, "/") // Ensure no leading/trailing slashes
	return nil
}
