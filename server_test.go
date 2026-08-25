// SPDX-License-Identifier: Apache-2.0

package authorizer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHandlerSigningContextAndSign(t *testing.T) {
	signer, err := NewSigner(staticCredentialProvider{credentials: Credentials{
		AccessKeyID:     "TESTACCESSKEY",
		SecretAccessKey: "test-secret-access-key",
		SessionToken:    "test-session-token",
	}}, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(signer, WithCredentialContext([]byte("node-role")))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	contextRequest := signingContextRequest{
		UnixTime:          time.Now().Unix(),
		CredentialContext: []byte("node-role"),
	}
	var contextResponse signingContextResponse
	postJSON(t, server.URL+SigningContextPath, contextRequest, &contextResponse, http.StatusOK)
	if contextResponse.ContextID == "" {
		t.Fatal("handler returned an empty signing context ID")
	}
	if contextResponse.AccessKeyID != "TESTACCESSKEY" {
		t.Fatalf("unexpected access key ID %q", contextResponse.AccessKeyID)
	}

	message := []byte("request signature base")
	signRequest := signMessageRequest{
		ContextID: contextResponse.ContextID,
		Message:   base64.StdEncoding.EncodeToString(message),
	}
	var signResponse signMessageResponse
	postJSON(t, server.URL+SignPath, signRequest, &signResponse, http.StatusOK)
	if signResponse.Signature == "" {
		t.Fatal("handler returned an empty signature")
	}

	var errorResult errorResponse
	postJSON(t, server.URL+SignPath, signRequest, &errorResult, http.StatusNotFound)
}

func TestHandlerRejectsUnknownCredentialContext(t *testing.T) {
	signer, err := NewSigner(staticCredentialProvider{}, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(signer, WithCredentialContext([]byte("expected")))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	request := signingContextRequest{
		UnixTime:          time.Now().Unix(),
		CredentialContext: []byte("other"),
	}
	var response errorResponse
	postJSON(t, server.URL+SigningContextPath, request, &response, http.StatusForbidden)
}

func postJSON(
	t *testing.T,
	url string,
	requestValue any,
	responseValue any,
	expectedStatus int,
) {
	t.Helper()
	body := &bytes.Buffer{}
	if err := json.NewEncoder(body).Encode(requestValue); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		url,
		body,
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != expectedStatus {
		t.Fatalf("unexpected status %s", response.Status)
	}
	if err := json.NewDecoder(response.Body).Decode(responseValue); err != nil {
		t.Fatal(err)
	}
}
