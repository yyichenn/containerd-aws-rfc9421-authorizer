// SPDX-License-Identifier: Apache-2.0

package authorizer

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
	"time"
)

type staticCredentialProvider struct {
	credentials Credentials
}

func (p staticCredentialProvider) Retrieve(context.Context) (Credentials, error) {
	return p.credentials, nil
}

func TestSignerDerivesAWS4Signature(t *testing.T) {
	const (
		accessKey    = "TESTACCESSKEY"
		secretKey    = "test-secret-access-key"
		sessionToken = "test-session-token"
		region       = "us-east-1"
	)
	signer, err := NewSigner(staticCredentialProvider{credentials: Credentials{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		SessionToken:    sessionToken,
	}}, region)
	if err != nil {
		t.Fatal(err)
	}
	signingContext, err := signer.NewSigningContext(
		context.Background(),
		time.Date(2026, time.August, 24, 12, 0, 0, 0, time.UTC),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("request signature base")
	signature, err := signer.Sign(context.Background(), signingContext, message)
	if err != nil {
		t.Fatal(err)
	}

	dateKey := testHMAC([]byte("AWS4"+secretKey), "20260824")
	regionKey := testHMAC(dateKey, region)
	serviceKey := testHMAC(regionKey, signingService)
	signingKey := testHMAC(serviceKey, signingTerminal)
	expected := testHMAC(signingKey, string(message))
	if !hmac.Equal(signature, expected) {
		t.Fatal("signer returned an unexpected signature")
	}
	if signingContext.AccessKeyID != accessKey ||
		signingContext.SessionToken != sessionToken ||
		signingContext.Region != region {
		t.Fatalf("unexpected signing context %#v", signingContext)
	}
}

func TestSignerRequiresTemporaryCredentials(t *testing.T) {
	signer, err := NewSigner(staticCredentialProvider{credentials: Credentials{
		AccessKeyID:     "TESTACCESSKEY",
		SecretAccessKey: "test-secret-access-key",
	}}, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.NewSigningContext(context.Background(), time.Now(), nil); err == nil {
		t.Fatal("expected credentials without a session token to be rejected")
	}
}

func TestSignerRejectsCredentialContext(t *testing.T) {
	signer, err := NewSigner(staticCredentialProvider{}, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.NewSigningContext(
		context.Background(),
		time.Now(),
		[]byte("unmapped-handle"),
	); err == nil {
		t.Fatal("expected an unmapped credential context to be rejected")
	}
}

func testHMAC(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}
