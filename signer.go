// SPDX-License-Identifier: Apache-2.0

package authorizer

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

const (
	signingService  = "ecr"
	signingTerminal = "aws4_request"
)

// Credentials is the temporary AWS credential material needed by the signer.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// CredentialProvider supplies temporary AWS credentials.
type CredentialProvider interface {
	Retrieve(context.Context) (Credentials, error)
}

// SigningContext contains the credential scope and private key material for
// one signing operation.
type SigningContext struct {
	AccessKeyID  string
	SessionToken string
	Date         string
	Region       string
	Service      string
	Terminal     string

	secretAccessKey string
}

// MessageSigner creates AWS signing contexts and signs RFC 9421 signature
// bases. It is the interface consumed by the Unix-socket server.
type MessageSigner interface {
	NewSigningContext(context.Context, time.Time, []byte) (*SigningContext, error)
	Sign(context.Context, *SigningContext, []byte) ([]byte, error)
}

// Signer derives AWS4 HMAC keys from temporary AWS credentials.
type Signer struct {
	provider CredentialProvider
	region   string
}

// NewSigner creates a signer backed by the provided credential source.
func NewSigner(provider CredentialProvider, region string) (*Signer, error) {
	if provider == nil {
		return nil, errors.New("AWS credential provider is required")
	}
	if strings.TrimSpace(region) == "" {
		return nil, errors.New("AWS signing region is required")
	}
	return &Signer{provider: provider, region: strings.TrimSpace(region)}, nil
}

type sdkCredentialProvider struct {
	provider aws.CredentialsProvider
}

func (p *sdkCredentialProvider) Retrieve(ctx context.Context) (Credentials, error) {
	credentials, err := p.provider.Retrieve(ctx)
	if err != nil {
		return Credentials{}, err
	}
	return Credentials{
		AccessKeyID:     credentials.AccessKeyID,
		SecretAccessKey: credentials.SecretAccessKey,
		SessionToken:    credentials.SessionToken,
	}, nil
}

// NewDefaultSigner loads credentials through the AWS SDK default credential
// chain. The process environment determines which source wins.
func NewDefaultSigner(ctx context.Context, region string) (*Signer, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS default configuration: %w", err)
	}
	return NewSigner(&sdkCredentialProvider{provider: cfg.Credentials}, region)
}

// NewSigningContext retrieves credentials for one request. The default signer
// does not interpret credential handles; the server can validate and consume
// one before calling this method.
func (s *Signer) NewSigningContext(
	ctx context.Context,
	now time.Time,
	credentialContext []byte,
) (*SigningContext, error) {
	if len(credentialContext) != 0 {
		return nil, errors.New("the AWS credential signer does not support a credential context")
	}
	credentials, err := s.provider.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("retrieve AWS credentials: %w", err)
	}
	if credentials.AccessKeyID == "" || credentials.SecretAccessKey == "" {
		return nil, errors.New("AWS access key ID and secret access key are required")
	}
	if credentials.SessionToken == "" {
		return nil, errors.New("request signing requires temporary AWS credentials")
	}
	return &SigningContext{
		AccessKeyID:     credentials.AccessKeyID,
		SessionToken:    credentials.SessionToken,
		Date:            now.UTC().Format("20060102"),
		Region:          s.region,
		Service:         signingService,
		Terminal:        signingTerminal,
		secretAccessKey: credentials.SecretAccessKey,
	}, nil
}

// Sign derives an AWS4 signing key and signs one RFC 9421 signature base.
func (s *Signer) Sign(
	_ context.Context,
	signingContext *SigningContext,
	message []byte,
) ([]byte, error) {
	if signingContext == nil || signingContext.secretAccessKey == "" {
		return nil, errors.New("invalid AWS signing context")
	}
	dateKey := hmacSHA256(
		[]byte("AWS4"+signingContext.secretAccessKey),
		signingContext.Date,
	)
	regionKey := hmacSHA256(dateKey, signingContext.Region)
	serviceKey := hmacSHA256(regionKey, signingContext.Service)
	signingKey := hmacSHA256(serviceKey, signingContext.Terminal)
	return hmacSHA256(signingKey, string(message)), nil
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}
