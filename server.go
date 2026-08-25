// SPDX-License-Identifier: Apache-2.0

package authorizer

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	SigningContextPath = "/v1/signing-context"
	SignPath           = "/v1/sign"

	maxRequestBody = 1 << 20
	contextTTL     = 5 * time.Minute
)

type signingContextRequest struct {
	UnixTime          int64  `json:"unixTime"`
	CredentialContext []byte `json:"credentialContext,omitempty"`
}

type signingContextResponse struct {
	ContextID    string `json:"contextId"`
	AccessKeyID  string `json:"accessKeyId"`
	SessionToken string `json:"sessionToken"`
	Date         string `json:"date"`
	Region       string `json:"region"`
	Service      string `json:"service"`
	Terminal     string `json:"terminal"`
}

type signMessageRequest struct {
	ContextID string `json:"contextId"`
	Message   string `json:"message"`
}

type signMessageResponse struct {
	Signature string `json:"signature"`
}

type errorResponse struct {
	Message string `json:"message"`
}

type storedSigningContext struct {
	context   *SigningContext
	expiresAt time.Time
}

type handler struct {
	signer MessageSigner
	now    func() time.Time
	random io.Reader

	expectedCredentialContext []byte
	requireCredentialContext  bool

	mu       sync.Mutex
	contexts map[string]storedSigningContext
}

// HandlerOption configures the local signing endpoint.
type HandlerOption func(*handler)

// WithCredentialContext requires an exact opaque handle from containerd. The
// handle selects this process's credential source; it is not itself a secret.
func WithCredentialContext(expected []byte) HandlerOption {
	return func(h *handler) {
		h.expectedCredentialContext = bytes.Clone(expected)
		h.requireCredentialContext = true
	}
}

// NewHandler creates the versioned HTTP API served over a protected Unix
// socket.
func NewHandler(signer MessageSigner, options ...HandlerOption) (http.Handler, error) {
	if signer == nil {
		return nil, errors.New("message signer is required")
	}
	h := &handler{
		signer:   signer,
		now:      time.Now,
		random:   rand.Reader,
		contexts: make(map[string]storedSigningContext),
	}
	for _, option := range options {
		option(h)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(SigningContextPath, h.handleSigningContext)
	mux.HandleFunc(SignPath, h.handleSign)
	return mux, nil
}

func (h *handler) handleSigningContext(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var input signingContextRequest
	if err := decodeJSON(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	requestTime := time.Unix(input.UnixTime, 0).UTC()
	if delta := h.now().UTC().Sub(requestTime); delta < -time.Minute || delta > time.Minute {
		writeError(writer, http.StatusBadRequest, "request time is outside the accepted window")
		return
	}

	credentialContext := input.CredentialContext
	if h.requireCredentialContext {
		if !bytes.Equal(credentialContext, h.expectedCredentialContext) {
			writeError(writer, http.StatusForbidden, "credential context is not recognized")
			return
		}
		credentialContext = nil
	}

	signingContext, err := h.signer.NewSigningContext(
		request.Context(),
		requestTime,
		credentialContext,
	)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, err.Error())
		return
	}
	if err := validateSigningContext(signingContext); err != nil {
		writeError(writer, http.StatusInternalServerError, err.Error())
		return
	}

	contextIDBytes := make([]byte, 24)
	if _, err := io.ReadFull(h.random, contextIDBytes); err != nil {
		writeError(writer, http.StatusInternalServerError, "create signing context ID")
		return
	}
	contextID := base64.RawURLEncoding.EncodeToString(contextIDBytes)

	h.mu.Lock()
	h.removeExpiredContextsLocked(h.now())
	h.contexts[contextID] = storedSigningContext{
		context:   signingContext,
		expiresAt: h.now().Add(contextTTL),
	}
	h.mu.Unlock()

	writeJSON(writer, http.StatusOK, signingContextResponse{
		ContextID:    contextID,
		AccessKeyID:  signingContext.AccessKeyID,
		SessionToken: signingContext.SessionToken,
		Date:         signingContext.Date,
		Region:       signingContext.Region,
		Service:      signingContext.Service,
		Terminal:     signingContext.Terminal,
	})
}

func (h *handler) handleSign(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(writer, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var input signMessageRequest
	if err := decodeJSON(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	message, err := base64.StdEncoding.DecodeString(input.Message)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "message is not valid base64")
		return
	}

	h.mu.Lock()
	h.removeExpiredContextsLocked(h.now())
	storedContext, ok := h.contexts[input.ContextID]
	if ok {
		delete(h.contexts, input.ContextID)
	}
	h.mu.Unlock()
	if !ok {
		writeError(writer, http.StatusNotFound, "signing context was not found or has expired")
		return
	}

	signature, err := h.signer.Sign(request.Context(), storedContext.context, message)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, signMessageResponse{
		Signature: base64.StdEncoding.EncodeToString(signature),
	})
}

func (h *handler) removeExpiredContextsLocked(now time.Time) {
	for contextID, signingContext := range h.contexts {
		if !now.Before(signingContext.expiresAt) {
			delete(h.contexts, contextID)
		}
	}
}

func validateSigningContext(signingContext *SigningContext) error {
	if signingContext == nil {
		return errors.New("message signer returned a nil signing context")
	}
	values := map[string]string{
		"access key ID": signingContext.AccessKeyID,
		"session token": signingContext.SessionToken,
		"date":          signingContext.Date,
		"region":        signingContext.Region,
		"service":       signingContext.Service,
		"terminal":      signingContext.Terminal,
	}
	for name, value := range values {
		if value == "" {
			return fmt.Errorf("message signer returned an empty %s", name)
		}
		if strings.ContainsAny(value, "\";") {
			return fmt.Errorf("message signer returned an invalid %s", name)
		}
	}
	if signingContext.Service != signingService || signingContext.Terminal != signingTerminal {
		return errors.New("message signer returned an unsupported AWS credential scope")
	}
	return nil
}

func decodeJSON(writer http.ResponseWriter, request *http.Request, value any) error {
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBody)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	return nil
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, errorResponse{Message: message})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
