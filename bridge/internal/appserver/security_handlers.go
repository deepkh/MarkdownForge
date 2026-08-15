package appserver

import (
	"context"
	"encoding/json"
	"time"

	bridgeconfig "localdraftai/bridge/internal/config"
	"localdraftai/bridge/internal/protocol"
)

func requireAdmin(ctx context.Context) *protocol.Error {
	claims, ok := claimsFromContext(ctx)
	if !ok || !claims.Admin {
		return protocol.NewStorageError(-32043, "FORBIDDEN", "Bridge administrator access is required.", false, nil)
	}
	return nil
}

func (s *Server) registerSecurityHandlers() {
	s.router.Register("bridge.security.getSettings", func(ctx context.Context, _ json.RawMessage) (any, *protocol.Error) {
		if rpcError := requireAdmin(ctx); rpcError != nil {
			return nil, rpcError
		}
		origins, err := s.securityStore.List()
		if err != nil {
			return nil, securityStorageError()
		}
		return map[string]any{
			"publicOrigin":   s.origin,
			"selfOrigin":     s.origin,
			"allowedOrigins": origins,
			"tls":            true,
		}, nil
	})
	s.router.Register("bridge.security.addAllowedOrigin", func(ctx context.Context, params json.RawMessage) (any, *protocol.Error) {
		if rpcError := requireAdmin(ctx); rpcError != nil {
			return nil, rpcError
		}
		var request struct {
			Origin string `json:"origin"`
		}
		if err := decodeStrictParams(params, &request); err != nil {
			return nil, protocol.NewError(protocol.InvalidParamsCode, err.Error())
		}
		normalized, err := bridgeconfig.NormalizeHTTPSOrigin(request.Origin)
		if err != nil || normalized == s.origin {
			return nil, protocol.NewError(protocol.InvalidParamsCode, "a configurable exact HTTPS origin is required")
		}
		origins, err := s.securityStore.Add(normalized)
		if err != nil {
			return nil, securityStorageError()
		}
		return map[string]any{"allowedOrigins": origins}, nil
	})
	s.router.Register("bridge.security.removeAllowedOrigin", func(ctx context.Context, params json.RawMessage) (any, *protocol.Error) {
		if rpcError := requireAdmin(ctx); rpcError != nil {
			return nil, rpcError
		}
		var request struct {
			Origin string `json:"origin"`
		}
		if err := decodeStrictParams(params, &request); err != nil {
			return nil, protocol.NewError(protocol.InvalidParamsCode, err.Error())
		}
		normalized, err := bridgeconfig.NormalizeHTTPSOrigin(request.Origin)
		if err != nil || normalized == s.origin {
			return nil, protocol.NewError(protocol.InvalidParamsCode, "the built-in bridge origin cannot be removed")
		}
		origins, removed, err := s.securityStore.Remove(normalized)
		if err != nil {
			return nil, securityStorageError()
		}
		if removed {
			go func() {
				time.Sleep(25 * time.Millisecond)
				s.closeConnections(func(claims ClientClaims) bool { return !claims.Admin && claims.Origin == normalized })
			}()
		}
		return map[string]any{"allowedOrigins": origins, "removed": removed}, nil
	})
	s.router.Register("bridge.security.listPairedClients", func(ctx context.Context, _ json.RawMessage) (any, *protocol.Error) {
		if rpcError := requireAdmin(ctx); rpcError != nil {
			return nil, rpcError
		}
		clients, err := s.pairedClientStore.List()
		if err != nil {
			return nil, securityStorageError()
		}
		return map[string]any{"clients": clients}, nil
	})
	s.router.Register("bridge.security.revokePairedClient", func(ctx context.Context, params json.RawMessage) (any, *protocol.Error) {
		if rpcError := requireAdmin(ctx); rpcError != nil {
			return nil, rpcError
		}
		var request struct {
			ClientID string `json:"clientId"`
		}
		if err := decodeStrictParams(params, &request); err != nil || request.ClientID == "" {
			return nil, protocol.NewError(protocol.InvalidParamsCode, "clientId is required")
		}
		removed, err := s.pairedClientStore.Remove(request.ClientID)
		if err != nil {
			return nil, securityStorageError()
		}
		if removed {
			go func() {
				time.Sleep(25 * time.Millisecond)
				s.closeConnections(func(claims ClientClaims) bool { return claims.ClientID == request.ClientID })
			}()
		}
		return map[string]bool{"revoked": removed}, nil
	})
	s.router.Register("bridge.security.listPairingRequests", func(ctx context.Context, _ json.RawMessage) (any, *protocol.Error) {
		if rpcError := requireAdmin(ctx); rpcError != nil {
			return nil, rpcError
		}
		return map[string]any{"requests": s.pairings.list()}, nil
	})
	s.router.Register("bridge.security.approvePairingRequest", func(ctx context.Context, params json.RawMessage) (any, *protocol.Error) {
		if rpcError := requireAdmin(ctx); rpcError != nil {
			return nil, rpcError
		}
		var request struct {
			RequestID string `json:"requestId"`
		}
		if err := decodeStrictParams(params, &request); err != nil || request.RequestID == "" {
			return nil, protocol.NewError(protocol.InvalidParamsCode, "requestId is required")
		}
		pending, ok := s.pairings.take(request.RequestID)
		if !ok {
			return nil, protocol.NewStorageError(-32010, "RESOURCE_NOT_FOUND", "The pairing request expired or was not found.", false, nil)
		}
		client, err := s.pairedClientStore.Upsert(bridgeconfig.PairedClient{
			ID: pending.ClientID, Name: pending.Name, Origin: pending.Origin, PublicKey: pending.PublicKey,
		})
		if err != nil {
			return nil, securityStorageError()
		}
		return map[string]any{"client": client}, nil
	})
	s.router.Register("bridge.security.denyPairingRequest", func(ctx context.Context, params json.RawMessage) (any, *protocol.Error) {
		if rpcError := requireAdmin(ctx); rpcError != nil {
			return nil, rpcError
		}
		var request struct {
			RequestID string `json:"requestId"`
		}
		if err := decodeStrictParams(params, &request); err != nil || request.RequestID == "" {
			return nil, protocol.NewError(protocol.InvalidParamsCode, "requestId is required")
		}
		return map[string]bool{"denied": s.pairings.deny(request.RequestID)}, nil
	})
}

func securityStorageError() *protocol.Error {
	return protocol.NewStorageError(-32010, "PROVIDER_UNAVAILABLE", "Could not update bridge security settings.", false, nil)
}

func (s *Server) closeConnections(matches func(ClientClaims) bool) {
	s.connectionMu.Lock()
	targets := make([]interface{ CloseNow() error }, 0)
	for connection, state := range s.connections {
		if claims, authenticated := state.auth.claimsValue(); authenticated && matches(claims) {
			targets = append(targets, connection)
		}
	}
	s.connectionMu.Unlock()
	for _, connection := range targets {
		_ = connection.CloseNow()
	}
}
