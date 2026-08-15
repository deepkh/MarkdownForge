package appserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	bridgeconfig "localdraftai/bridge/internal/config"
	"localdraftai/bridge/internal/protocol"
)

type notification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type browserConnection struct {
	writes *sync.Mutex
	auth   *socketAuth
}

func (s *Server) broadcastNotification(method string, params any) {
	payload, err := json.Marshal(notification{JSONRPC: protocol.Version, Method: method, Params: params})
	if err != nil || int64(len(payload)) > s.config.MaximumMessageSize {
		return
	}
	s.connectionMu.Lock()
	type target struct {
		connection *websocket.Conn
		state      *browserConnection
	}
	targets := make([]target, 0, len(s.connections))
	for connection, state := range s.connections {
		if _, authenticated := state.auth.claimsValue(); authenticated {
			targets = append(targets, target{connection: connection, state: state})
		}
	}
	s.connectionMu.Unlock()
	for _, target := range targets {
		target.state.writes.Lock()
		writeContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = target.connection.Write(writeContext, websocket.MessageText, payload)
		cancel()
		target.state.writes.Unlock()
	}
}

func (s *Server) handleWebSocket(response http.ResponseWriter, request *http.Request) {
	if !strings.EqualFold(request.Host, s.publicHost) {
		http.Error(response, "Unexpected bridge Host", http.StatusForbidden)
		return
	}
	origin, err := s.authorizedOrigin(request.Header.Get("Origin"))
	if err != nil {
		http.Error(response, "Unexpected WebSocket origin", http.StatusForbidden)
		return
	}
	connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	connection.SetReadLimit(s.config.MaximumMessageSize)
	state := &browserConnection{
		writes: &sync.Mutex{},
		auth:   &socketAuth{origin: origin, adminSession: s.sessions.validRequest(request)},
	}
	s.connectionMu.Lock()
	s.connections[connection] = state
	s.connectionMu.Unlock()
	s.logs.Append("info", "websocket", "browser bridge session connected")
	defer func() {
		s.connectionMu.Lock()
		delete(s.connections, connection)
		s.connectionMu.Unlock()
		_ = connection.Close(websocket.StatusNormalClosure, "bridge session closed")
		s.logs.Append("info", "websocket", "browser bridge session disconnected")
	}()
	s.serveWebSocket(request.Context(), connection, state)
}

func (s *Server) authorizedOrigin(value string) (string, error) {
	origin, err := bridgeconfig.NormalizeHTTPSOrigin(value)
	if err != nil {
		return "", err
	}
	if origin == s.origin {
		return origin, nil
	}
	allowed, err := s.securityStore.List()
	if err != nil {
		return "", err
	}
	for _, candidate := range allowed {
		if origin == candidate {
			return origin, nil
		}
	}
	return "", errors.New("origin is not allowed")
}

func (s *Server) serveWebSocket(ctx context.Context, connection *websocket.Conn, state *browserConnection) {
	semaphore := make(chan struct{}, s.config.MaximumConcurrent)
	var calls sync.WaitGroup
	defer calls.Wait()

	writeResponse := func(response protocol.Response) {
		payload, err := json.Marshal(response)
		if err != nil {
			return
		}
		if int64(len(payload)) > s.config.MaximumMessageSize {
			payload, err = json.Marshal(protocol.Failure(response.ID, protocol.NewStorageError(
				-32020,
				"FILE_TOO_LARGE",
				"The bridge response exceeds the JSON message limit.",
				false,
				nil,
			)))
			if err != nil || int64(len(payload)) > s.config.MaximumMessageSize {
				return
			}
		}
		state.writes.Lock()
		defer state.writes.Unlock()
		writeContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = connection.Write(writeContext, websocket.MessageText, payload)
	}

	for {
		messageType, payload, err := connection.Read(ctx)
		if err != nil {
			return
		}
		if messageType != websocket.MessageText {
			_ = connection.Close(websocket.StatusUnsupportedData, "JSON text messages required")
			return
		}
		var request protocol.Request
		if err := json.Unmarshal(payload, &request); err != nil {
			writeResponse(protocol.Failure(nil, protocol.NewError(protocol.ParseErrorCode, "Parse error")))
			continue
		}
		if !request.Valid() {
			writeResponse(protocol.Failure(request.ID, protocol.NewError(protocol.InvalidRequestCode, "Invalid Request")))
			continue
		}
		authenticatedClaims, authenticated := state.auth.claimsValue()
		if !authenticated {
			var result any
			var rpcError *protocol.Error
			switch request.Method {
			case "bridge.auth.begin":
				result, rpcError = s.beginClientAuthentication(state.auth, request.Params)
			case "bridge.auth.complete":
				result, rpcError = s.completeClientAuthentication(state.auth, request.Params)
			default:
				rpcError = protocol.NewStorageError(-32042, "AUTHENTICATION_REQUIRED", "Authenticate this browser before using the bridge.", false, nil)
			}
			if !request.IsNotification() {
				if rpcError != nil {
					writeResponse(protocol.Failure(request.ID, rpcError))
				} else {
					writeResponse(protocol.Success(request.ID, result))
				}
			}
			continue
		}

		semaphore <- struct{}{}
		calls.Add(1)
		go func(request protocol.Request, claims ClientClaims) {
			defer calls.Done()
			defer func() { <-semaphore }()
			defer func() {
				for index := range request.Params {
					request.Params[index] = 0
				}
			}()
			timeout := s.config.OperationTimeout
			if request.Method == "fs.searchText" {
				timeout = s.config.SearchTimeout
			}
			callContext, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			callContext = context.WithValue(callContext, claimsContextKey{}, claims)
			result, rpcError := s.router.Handle(callContext, request)
			if request.IsNotification() {
				return
			}
			if rpcError != nil {
				writeResponse(protocol.Failure(request.ID, rpcError))
				return
			}
			writeResponse(protocol.Success(request.ID, result))
		}(request, authenticatedClaims)
	}
}
