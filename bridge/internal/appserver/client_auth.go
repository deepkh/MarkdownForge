package appserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"time"

	bridgeconfig "localdraftai/bridge/internal/config"
	"localdraftai/bridge/internal/protocol"
)

type ClientClaims struct {
	ClientID string `json:"clientId"`
	Origin   string `json:"origin"`
	Admin    bool   `json:"admin"`
}

type claimsContextKey struct{}

func claimsFromContext(ctx context.Context) (ClientClaims, bool) {
	claims, ok := ctx.Value(claimsContextKey{}).(ClientClaims)
	return claims, ok
}

type authChallenge struct {
	value     []byte
	expiresAt time.Time
	used      bool
	client    bridgeconfig.PairedClient
}

type socketAuth struct {
	mu           sync.RWMutex
	origin       string
	adminSession bool
	challenge    *authChallenge
	claims       *ClientClaims
}

func (s *socketAuth) claimsValue() (ClientClaims, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.claims == nil {
		return ClientClaims{}, false
	}
	return *s.claims, true
}

func (s *socketAuth) setClaims(claims ClientClaims) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.claims = &claims
}

type authBeginParams struct {
	ClientID  string                    `json:"clientId"`
	Name      string                    `json:"name"`
	PublicKey bridgeconfig.PublicKeyJWK `json:"publicKey"`
}

func (s *Server) beginClientAuthentication(state *socketAuth, params json.RawMessage) (any, *protocol.Error) {
	var request authBeginParams
	if err := decodeStrictParams(params, &request); err != nil {
		return nil, protocol.NewError(protocol.InvalidParamsCode, err.Error())
	}
	request.ClientID = strings.TrimSpace(request.ClientID)
	request.Name = strings.TrimSpace(request.Name)
	if request.ClientID == "" || request.Name == "" {
		return nil, protocol.NewError(protocol.InvalidParamsCode, "clientId and name are required")
	}
	client, found, err := s.pairedClientStore.Get(request.ClientID, state.origin)
	if err != nil {
		return nil, protocol.NewStorageError(-32010, "PROVIDER_UNAVAILABLE", "Could not read paired clients.", false, nil)
	}
	if !found && state.origin == s.origin && state.adminSession {
		client, err = s.pairedClientStore.Upsert(bridgeconfig.PairedClient{
			ID: request.ClientID, Name: request.Name, Origin: state.origin, PublicKey: request.PublicKey,
		})
		if err != nil {
			return nil, protocol.NewError(protocol.InvalidParamsCode, err.Error())
		}
		found = true
	}
	if !found {
		if _, err := publicKeyFromJWK(request.PublicKey); err != nil {
			return nil, protocol.NewError(protocol.InvalidParamsCode, err.Error())
		}
		pending, err := s.pairings.create(state.origin, request.ClientID, request.Name, request.PublicKey)
		if err != nil {
			return nil, protocol.NewStorageError(-32040, "PAIRING_RATE_LIMITED", "Too many pairing requests. Try again later.", true, nil)
		}
		return nil, protocol.NewStorageError(-32041, "PAIRING_REQUIRED", "This browser must be approved by the bridge administrator.", true, pending.view())
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, protocol.NewError(protocol.InternalErrorCode, "Could not create authentication challenge")
	}
	state.challenge = &authChallenge{value: challenge, expiresAt: time.Now().UTC().Add(s.config.ChallengeLifetime), client: client}
	return map[string]any{
		"status": "challenge", "challenge": base64.RawURLEncoding.EncodeToString(challenge), "expiresAt": state.challenge.expiresAt,
	}, nil
}

func (s *Server) completeClientAuthentication(state *socketAuth, params json.RawMessage) (any, *protocol.Error) {
	var request struct {
		Signature string `json:"signature"`
	}
	if err := decodeStrictParams(params, &request); err != nil || request.Signature == "" {
		return nil, protocol.NewError(protocol.InvalidParamsCode, "signature is required")
	}
	challenge := state.challenge
	if challenge == nil || challenge.used {
		return nil, protocol.NewStorageError(-32042, "AUTHENTICATION_REQUIRED", "Begin authentication before completing it.", false, nil)
	}
	challenge.used = true
	if !time.Now().Before(challenge.expiresAt) {
		return nil, protocol.NewStorageError(-32042, "AUTHENTICATION_REQUIRED", "The authentication challenge expired.", true, nil)
	}
	signature, err := base64.RawURLEncoding.DecodeString(request.Signature)
	if err != nil || len(signature) != 64 {
		return nil, protocol.NewStorageError(-32042, "AUTHENTICATION_REQUIRED", "The authentication signature is invalid.", false, nil)
	}
	publicKey, err := publicKeyFromJWK(challenge.client.PublicKey)
	if err != nil {
		return nil, protocol.NewStorageError(-32042, "AUTHENTICATION_REQUIRED", "The paired public key is invalid.", false, nil)
	}
	r := new(big.Int).SetBytes(signature[:32])
	sValue := new(big.Int).SetBytes(signature[32:])
	digest := sha256.Sum256(challenge.value)
	if !ecdsa.Verify(publicKey, digest[:], r, sValue) {
		return nil, protocol.NewStorageError(-32042, "AUTHENTICATION_REQUIRED", "The authentication signature is invalid.", false, nil)
	}
	claims := ClientClaims{
		ClientID: challenge.client.ID,
		Origin:   state.origin,
		Admin:    state.origin == s.origin && state.adminSession,
	}
	state.setClaims(claims)
	state.challenge = nil
	_ = s.pairedClientStore.Touch(claims.ClientID, claims.Origin)
	return map[string]any{"status": "authenticated", "claims": claims}, nil
}

func publicKeyFromJWK(jwk bridgeconfig.PublicKeyJWK) (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, errors.New("an ECDSA P-256 public key is required")
	}
	xBytes, errX := base64.RawURLEncoding.DecodeString(jwk.X)
	yBytes, errY := base64.RawURLEncoding.DecodeString(jwk.Y)
	if errX != nil || errY != nil || len(xBytes) != 32 || len(yBytes) != 32 {
		return nil, errors.New("the ECDSA public key coordinates are invalid")
	}
	publicKey := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}
	if !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return nil, errors.New("the ECDSA public key is invalid")
	}
	return publicKey, nil
}

func decodeStrictParams(params json.RawMessage, target any) error {
	if len(params) == 0 {
		params = json.RawMessage("{}")
	}
	decoder := json.NewDecoder(strings.NewReader(string(params)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}
