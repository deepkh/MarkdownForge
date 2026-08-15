package appserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coder/websocket"

	bridgeconfig "localdraftai/bridge/internal/config"
	"localdraftai/bridge/internal/logbuffer"
	"localdraftai/bridge/internal/protocol"
	"localdraftai/bridge/internal/remotefs"
	"localdraftai/bridge/internal/sshconn"
)

const (
	BridgeVersion             = "0.2.0"
	ProtocolVersion           = 2
	DefaultListenAddress      = "127.0.0.1:4782"
	DefaultMaximumMessageSize = int64(16 << 20)
	DefaultMaximumConcurrent  = 8
)

type Config struct {
	ListenAddress      string
	PublicOrigin       string
	TLSCertFile        string
	TLSKeyFile         string
	WebRoot            string
	ConfigDir          string
	MaximumMessageSize int64
	MaximumConcurrent  int
	OperationTimeout   time.Duration
	SearchTimeout      time.Duration
	SessionLifetime    time.Duration
	ChallengeLifetime  time.Duration
	PairingLifetime    time.Duration
}

type Server struct {
	config            Config
	httpServer        *http.Server
	handler           http.Handler
	router            *protocol.Router
	logs              *logbuffer.Buffer
	sessions          *sessionStore
	startupToken      string
	origin            string
	publicHost        string
	startedAt         time.Time
	connections       map[*websocket.Conn]*browserConnection
	connectionMu      sync.Mutex
	profileStore      *bridgeconfig.Store
	securityStore     *bridgeconfig.SecurityStore
	pairedClientStore *bridgeconfig.PairedClientStore
	pairings          *pairingManager
	sshManager        *sshconn.Manager
	remoteFS          *remotefs.Service
}

func New(config Config) (*Server, error) {
	if config.ListenAddress == "" {
		config.ListenAddress = DefaultListenAddress
	}
	if err := ValidateListenAddress(config.ListenAddress); err != nil {
		return nil, err
	}
	publicOrigin, err := resolvePublicOrigin(config.ListenAddress, config.PublicOrigin)
	if err != nil {
		return nil, err
	}
	if err := validateTLSConfiguration(config.TLSCertFile, config.TLSKeyFile, publicOrigin); err != nil {
		return nil, err
	}
	config.PublicOrigin = publicOrigin
	if config.WebRoot == "" {
		config.WebRoot = "."
	}
	if config.MaximumMessageSize <= 0 {
		config.MaximumMessageSize = DefaultMaximumMessageSize
	}
	if config.MaximumConcurrent <= 0 {
		config.MaximumConcurrent = DefaultMaximumConcurrent
	}
	if config.OperationTimeout <= 0 {
		config.OperationTimeout = 30 * time.Second
	}
	if config.SearchTimeout <= 0 {
		config.SearchTimeout = 120 * time.Second
	}
	if config.SessionLifetime <= 0 {
		config.SessionLifetime = 12 * time.Hour
	}
	if config.ChallengeLifetime <= 0 {
		config.ChallengeLifetime = 30 * time.Second
	}
	if config.PairingLifetime <= 0 {
		config.PairingLifetime = 5 * time.Minute
	}

	startupToken, err := randomToken(32)
	if err != nil {
		return nil, fmt.Errorf("generate startup token: %w", err)
	}
	static, err := staticHandler(config.WebRoot)
	if err != nil {
		return nil, fmt.Errorf("configure static frontend: %w", err)
	}
	origin := publicOrigin
	parsedOrigin, _ := url.Parse(origin)
	paths, err := bridgeconfig.ResolvePaths(config.ConfigDir)
	if err != nil {
		return nil, fmt.Errorf("resolve bridge configuration paths: %w", err)
	}
	profileStore := bridgeconfig.NewStore(paths)
	securityStore := bridgeconfig.NewSecurityStore(paths)
	pairedClientStore := bridgeconfig.NewPairedClientStore(paths)
	if _, err := securityStore.List(); err != nil {
		return nil, fmt.Errorf("load bridge security settings: %w", err)
	}
	if _, err := pairedClientStore.List(); err != nil {
		return nil, fmt.Errorf("load paired clients: %w", err)
	}
	server := &Server{
		config:            config,
		logs:              logbuffer.New(200),
		router:            protocol.NewRouter(),
		sessions:          newSessionStore(startupToken, config.SessionLifetime),
		startupToken:      startupToken,
		origin:            origin,
		publicHost:        parsedOrigin.Host,
		startedAt:         time.Now().UTC(),
		connections:       make(map[*websocket.Conn]*browserConnection),
		profileStore:      profileStore,
		securityStore:     securityStore,
		pairedClientStore: pairedClientStore,
		pairings:          newPairingManager(config.PairingLifetime),
	}
	server.sshManager = sshconn.NewManager(sshconn.ManagerConfig{
		Store:  profileStore,
		Paths:  paths,
		Events: server.handleSSHEvent,
	})
	server.remoteFS = remotefs.NewService(server.sshManager)
	server.registerBridgeHandlers()
	server.registerSecurityHandlers()
	protocol.RegisterSSHHandlers(server.router, profileStore, paths, server.sshManager)
	protocol.RegisterRemoteFilesystemHandlers(server.router, server.remoteFS)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/session", server.handleSession)
	mux.HandleFunc("/api/health", server.handleHealth)
	mux.HandleFunc("/api/bridge", server.handleWebSocket)
	mux.Handle("/", static)
	server.handler = securityHeaders(mux)
	server.httpServer = &http.Server{
		Handler:           server.handler,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return server, nil
}

func ValidateListenAddress(address string) error {
	_, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	return nil
}

func resolvePublicOrigin(listenAddress, configured string) (string, error) {
	host, _, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return "", fmt.Errorf("invalid listen address: %w", err)
	}
	if configured == "" {
		ip := net.ParseIP(host)
		if host == "" || (ip != nil && ip.IsUnspecified()) {
			return "", errors.New("--public-origin is required for a wildcard listen address")
		}
		configured = "https://" + listenAddress
	}
	normalized, err := bridgeconfig.NormalizeHTTPSOrigin(configured)
	if err != nil {
		return "", fmt.Errorf("invalid public origin: %w", err)
	}
	return normalized, nil
}

func validateTLSConfiguration(certFile, keyFile, publicOrigin string) error {
	if certFile == "" || keyFile == "" {
		return errors.New("--tls-cert and --tls-key are required")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate and key: %w", err)
	}
	if len(certificate.Certificate) == 0 {
		return errors.New("TLS certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse TLS certificate: %w", err)
	}
	parsed, _ := url.Parse(publicOrigin)
	if err := leaf.VerifyHostname(parsed.Hostname()); err != nil {
		return fmt.Errorf("TLS certificate does not cover public origin host %q: %w", parsed.Hostname(), err)
	}
	return nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(response, request)
	})
}

func (s *Server) Handler() http.Handler {
	return s.handler
}

func (s *Server) StartupToken() string {
	return s.startupToken
}

func (s *Server) StartupURL() string {
	return s.origin + "/api/session?token=" + url.QueryEscape(s.startupToken)
}

func (s *Server) Origin() string {
	return s.origin
}

func (s *Server) Serve(listener net.Listener) error {
	s.logs.Append("info", "bridge", "bridge server started")
	err := s.httpServer.ServeTLS(listener, s.config.TLSCertFile, s.config.TLSKeyFile)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.sshManager != nil {
		s.sshManager.Close()
	}
	s.connectionMu.Lock()
	connections := make([]*websocket.Conn, 0, len(s.connections))
	for connection := range s.connections {
		connections = append(connections, connection)
	}
	s.connectionMu.Unlock()
	for _, connection := range connections {
		_ = connection.CloseNow()
	}
	s.logs.Append("info", "bridge", "bridge server stopped")
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) handleSSHEvent(method string, params any) {
	switch value := params.(type) {
	case sshconn.Status:
		s.logs.Append("info", "ssh", fmt.Sprintf("%s: %s", value.Label, value.State))
	case map[string]any:
		if code, ok := value["code"].(string); ok && code != "" {
			s.logs.Append("error", "ssh", fmt.Sprintf("connection error: %s", code))
		}
	}
	s.broadcastNotification(method, params)
}

func (s *Server) registerBridgeHandlers() {
	s.router.Register("bridge.hello", func(ctx context.Context, _ json.RawMessage) (any, *protocol.Error) {
		claims, _ := claimsFromContext(ctx)
		return map[string]any{
			"protocolVersion": ProtocolVersion,
			"bridgeVersion":   BridgeVersion,
			"capabilities": map[string]bool{
				"ssh":          true,
				"sftp":         true,
				"remoteSearch": true,
				"binaryAssets": true,
			},
			"claims": claims,
		}, nil
	})
	s.router.Register("bridge.getStatus", func(_ context.Context, _ json.RawMessage) (any, *protocol.Error) {
		return map[string]any{
			"bridgeVersion":   BridgeVersion,
			"protocolVersion": ProtocolVersion,
			"status":          "ready",
			"startedAt":       s.startedAt,
		}, nil
	})
	s.router.Register("bridge.getLogs", func(_ context.Context, _ json.RawMessage) (any, *protocol.Error) {
		return map[string]any{"entries": s.logs.Entries()}, nil
	})
}

func (s *Server) handleHealth(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		http.Error(response, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(map[string]any{
		"status":          "ok",
		"bridgeVersion":   BridgeVersion,
		"protocolVersion": ProtocolVersion,
	})
}
