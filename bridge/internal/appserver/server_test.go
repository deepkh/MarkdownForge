package appserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	bridgeconfig "localdraftai/bridge/internal/config"
	"localdraftai/bridge/internal/protocol"
	"localdraftai/bridge/internal/testssh"
)

type testBridge struct {
	server   *Server
	listener net.Listener
	done     chan error
	root     string
}

func writeTestCertificate(t *testing.T, directory string) (string, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(directory, "tls-cert.pem")
	keyPath := filepath.Join(directory, "tls-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func testHTTPClient() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

func startTestBridge(t *testing.T, configure func(*Config)) *testBridge {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "local_draft_ai.html"), []byte("<!doctype html><title>test</title>"), 0o644); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := writeTestCertificate(t, root)
	config := Config{
		ListenAddress:    listener.Addr().String(),
		PublicOrigin:     "https://" + listener.Addr().String(),
		TLSCertFile:      certPath,
		TLSKeyFile:       keyPath,
		WebRoot:          root,
		ConfigDir:        filepath.Join(root, "config"),
		OperationTimeout: time.Second,
		SearchTimeout:    time.Second,
	}
	if configure != nil {
		configure(&config)
	}
	server, err := New(config)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	bridge := &testBridge{server: server, listener: listener, done: make(chan error, 1), root: root}
	go func() { bridge.done <- server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		select {
		case <-bridge.done:
		case <-time.After(2 * time.Second):
			t.Error("bridge did not stop")
		}
	})
	return bridge
}

func exchangeSession(t *testing.T, bridge *testBridge) *http.Cookie {
	t.Helper()
	client := testHTTPClient()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := client.Get(startupURL(bridge.server))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("session exchange status = %d", response.StatusCode)
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == sessionCookieName {
			if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
				t.Fatalf("session cookie flags are not strict: %#v", cookie)
			}
			return cookie
		}
	}
	t.Fatal("session cookie was not set")
	return nil
}

func startupURL(server *Server) string {
	return server.Origin() + "/api/session?token=" + url.QueryEscape(server.StartupToken())
}

func dialBridge(t *testing.T, bridge *testBridge, cookie *http.Cookie, origin string) *websocket.Conn {
	t.Helper()
	header := http.Header{}
	if cookie != nil {
		header.Set("Cookie", cookie.String())
	}
	header.Set("Origin", origin)
	connection, response, err := websocket.Dial(context.Background(), strings.Replace(bridge.server.Origin(), "https://", "wss://", 1)+"/api/bridge", &websocket.DialOptions{
		HTTPHeader: header,
		HTTPClient: testHTTPClient(),
	})
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		t.Fatal(err)
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	coordinate := func(value *big.Int) string {
		bytes := value.FillBytes(make([]byte, 32))
		return base64.RawURLEncoding.EncodeToString(bytes)
	}
	beginPayload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": "auth-begin", "method": "bridge.auth.begin",
		"params": map[string]any{"clientId": "test-client", "name": "Test Browser", "publicKey": bridgeconfig.PublicKeyJWK{
			Kty: "EC", Crv: "P-256", X: coordinate(privateKey.X), Y: coordinate(privateKey.Y),
		}},
	})
	begin := rpcCall(t, connection, string(beginPayload))
	if begin.Error != nil {
		t.Fatalf("auth begin error = %#v", begin.Error)
	}
	challengeText := begin.Result.(map[string]any)["challenge"].(string)
	challenge, err := base64.RawURLEncoding.DecodeString(challengeText)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(challenge)
	r, signatureS, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), signatureS.FillBytes(make([]byte, 32))...)
	completePayload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": "auth-complete", "method": "bridge.auth.complete",
		"params": map[string]string{"signature": base64.RawURLEncoding.EncodeToString(signature)},
	})
	complete := rpcCall(t, connection, string(completePayload))
	if complete.Error != nil {
		t.Fatalf("auth complete error = %#v", complete.Error)
	}
	return connection
}

func dialUnauthenticated(t *testing.T, bridge *testBridge, cookie *http.Cookie, origin string) *websocket.Conn {
	t.Helper()
	header := http.Header{}
	if cookie != nil {
		header.Set("Cookie", cookie.String())
	}
	header.Set("Origin", origin)
	connection, response, err := websocket.Dial(context.Background(), strings.Replace(bridge.server.Origin(), "https://", "wss://", 1)+"/api/bridge", &websocket.DialOptions{
		HTTPHeader: header, HTTPClient: testHTTPClient(),
	})
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		t.Fatal(err)
	}
	return connection
}

func testClientKey(t *testing.T) (*ecdsa.PrivateKey, bridgeconfig.PublicKeyJWK) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	coordinate := func(value *big.Int) string {
		return base64.RawURLEncoding.EncodeToString(value.FillBytes(make([]byte, 32)))
	}
	return privateKey, bridgeconfig.PublicKeyJWK{Kty: "EC", Crv: "P-256", X: coordinate(privateKey.X), Y: coordinate(privateKey.Y)}
}

func authBeginCall(t *testing.T, connection *websocket.Conn, id string, publicKey bridgeconfig.PublicKeyJWK) protocol.Response {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": "begin", "method": "bridge.auth.begin",
		"params": map[string]any{"clientId": id, "name": "Test Browser", "publicKey": publicKey},
	})
	return rpcCall(t, connection, string(payload))
}

func authCompleteCall(t *testing.T, connection *websocket.Conn, privateKey *ecdsa.PrivateKey, challengeText string) protocol.Response {
	t.Helper()
	challenge, err := base64.RawURLEncoding.DecodeString(challengeText)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(challenge)
	r, signatureS, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := append(r.FillBytes(make([]byte, 32)), signatureS.FillBytes(make([]byte, 32))...)
	payload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": "complete", "method": "bridge.auth.complete",
		"params": map[string]string{"signature": base64.RawURLEncoding.EncodeToString(signature)},
	})
	return rpcCall(t, connection, string(payload))
}

func rpcCall(t *testing.T, connection *websocket.Conn, payload string) protocol.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := connection.Write(ctx, websocket.MessageText, []byte(payload)); err != nil {
		t.Fatal(err)
	}
	_, message, err := connection.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var response protocol.Response
	if err := json.Unmarshal(message, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestValidateListenAddress(t *testing.T) {
	if err := ValidateListenAddress("127.0.0.1:4782"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateListenAddress("[::1]:4782"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateListenAddress("0.0.0.0:4782"); err != nil {
		t.Fatal(err)
	}
	if _, err := resolvePublicOrigin("0.0.0.0:4782", ""); err == nil {
		t.Fatal("wildcard listener did not require public origin")
	}
}

func TestTLSAndPublicOriginConfiguration(t *testing.T) {
	root := t.TempDir()
	certPath, keyPath := writeTestCertificate(t, root)
	base := Config{ListenAddress: "127.0.0.1:4782", PublicOrigin: "https://127.0.0.1:4782", TLSCertFile: certPath, TLSKeyFile: keyPath, WebRoot: root}
	if _, err := New(Config{ListenAddress: base.ListenAddress, PublicOrigin: base.PublicOrigin, WebRoot: root}); err == nil || !strings.Contains(err.Error(), "tls-cert") {
		t.Fatalf("missing TLS files error = %v", err)
	}
	base.PublicOrigin = "http://127.0.0.1:4782"
	if _, err := New(base); err == nil || !strings.Contains(err.Error(), "public origin") {
		t.Fatalf("HTTP public origin error = %v", err)
	}
	base.PublicOrigin = "https://localhost:4782"
	if _, err := New(base); err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("certificate host mismatch error = %v", err)
	}
}

func TestStartupTokenIsOneTimeAndCookieIsRequired(t *testing.T) {
	bridge := startTestBridge(t, nil)
	cookie := exchangeSession(t, bridge)
	client := testHTTPClient()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Get(startupURL(bridge.server))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reused token status = %d", response.StatusCode)
	}

	_ = cookie
}

func TestWebSocketRejectsMissingAndUnexpectedOrigins(t *testing.T) {
	bridge := startTestBridge(t, nil)
	cookie := exchangeSession(t, bridge)
	for _, origin := range []string{"", "https://evil.example"} {
		request := httptest.NewRequest(http.MethodGet, bridge.server.Origin()+"/api/bridge", nil)
		request.AddCookie(cookie)
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		recorder := httptest.NewRecorder()
		bridge.server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("origin %q status = %d", origin, recorder.Code)
		}
	}
}

func TestHostMismatchAndUnauthenticatedRPCAreRejected(t *testing.T) {
	bridge := startTestBridge(t, nil)
	request := httptest.NewRequest(http.MethodGet, bridge.server.Origin()+"/api/bridge", nil)
	request.Host = "evil.example"
	request.Header.Set("Origin", bridge.server.Origin())
	recorder := httptest.NewRecorder()
	bridge.server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("Host mismatch status = %d", recorder.Code)
	}

	connection := dialUnauthenticated(t, bridge, nil, bridge.server.Origin())
	defer connection.CloseNow()
	response := rpcCall(t, connection, `{"jsonrpc":"2.0","id":"hello","method":"bridge.hello"}`)
	if response.Error == nil || response.Error.Data == nil || response.Error.Data.Code != "AUTHENTICATION_REQUIRED" {
		t.Fatalf("unauthenticated response = %#v", response)
	}
}

func TestChallengeRejectsWrongSignatureAndReplay(t *testing.T) {
	bridge := startTestBridge(t, nil)
	connection := dialUnauthenticated(t, bridge, exchangeSession(t, bridge), bridge.server.Origin())
	defer connection.CloseNow()
	_, publicKey := testClientKey(t)
	wrongKey, _ := testClientKey(t)
	begin := authBeginCall(t, connection, "wrong-signature-client", publicKey)
	if begin.Error != nil {
		t.Fatalf("begin = %#v", begin.Error)
	}
	challenge := begin.Result.(map[string]any)["challenge"].(string)
	wrong := authCompleteCall(t, connection, wrongKey, challenge)
	if wrong.Error == nil || wrong.Error.Data.Code != "AUTHENTICATION_REQUIRED" {
		t.Fatalf("wrong signature = %#v", wrong)
	}
	replay := authCompleteCall(t, connection, wrongKey, challenge)
	if replay.Error == nil || replay.Error.Data.Code != "AUTHENTICATION_REQUIRED" {
		t.Fatalf("challenge replay = %#v", replay)
	}
}

func TestAuthenticationChallengeExpires(t *testing.T) {
	bridge := startTestBridge(t, func(config *Config) { config.ChallengeLifetime = 10 * time.Millisecond })
	connection := dialUnauthenticated(t, bridge, exchangeSession(t, bridge), bridge.server.Origin())
	defer connection.CloseNow()
	privateKey, publicKey := testClientKey(t)
	begin := authBeginCall(t, connection, "expired-client", publicKey)
	if begin.Error != nil {
		t.Fatalf("begin = %#v", begin.Error)
	}
	time.Sleep(20 * time.Millisecond)
	complete := authCompleteCall(t, connection, privateKey, begin.Result.(map[string]any)["challenge"].(string))
	if complete.Error == nil || complete.Error.Data.Code != "AUTHENTICATION_REQUIRED" {
		t.Fatalf("expired challenge = %#v", complete)
	}
}

func TestCrossOriginPairingApprovalCannotGrantAdminAndRevocationRepairs(t *testing.T) {
	bridge := startTestBridge(t, nil)
	cross := dialUnauthenticated(t, bridge, nil, "https://localdraft.ai")
	defer cross.CloseNow()
	privateKey, publicKey := testClientKey(t)
	begin := authBeginCall(t, cross, "cross-client", publicKey)
	if begin.Error == nil || begin.Error.Data.Code != "PAIRING_REQUIRED" {
		t.Fatalf("unknown client begin = %#v", begin)
	}
	details := begin.Error.Data.Details.(map[string]any)
	requestID := details["requestId"].(string)

	admin := dialBridge(t, bridge, exchangeSession(t, bridge), bridge.server.Origin())
	defer admin.CloseNow()
	approvePayload := `{"jsonrpc":"2.0","id":"approve","method":"bridge.security.approvePairingRequest","params":{"requestId":"` + requestID + `"}}`
	if response := rpcCall(t, admin, approvePayload); response.Error != nil {
		t.Fatalf("approve = %#v", response.Error)
	}

	begin = authBeginCall(t, cross, "cross-client", publicKey)
	if begin.Error != nil {
		t.Fatalf("paired begin = %#v", begin.Error)
	}
	complete := authCompleteCall(t, cross, privateKey, begin.Result.(map[string]any)["challenge"].(string))
	if complete.Error != nil {
		t.Fatalf("complete = %#v", complete.Error)
	}
	claims := complete.Result.(map[string]any)["claims"].(map[string]any)
	if claims["admin"].(bool) {
		t.Fatal("cross-origin client became admin")
	}
	forbidden := rpcCall(t, cross, `{"jsonrpc":"2.0","id":"settings","method":"bridge.security.getSettings"}`)
	if forbidden.Error == nil || forbidden.Error.Data.Code != "FORBIDDEN" {
		t.Fatalf("cross-origin admin RPC = %#v", forbidden)
	}

	revoke := rpcCall(t, admin, `{"jsonrpc":"2.0","id":"revoke","method":"bridge.security.revokePairedClient","params":{"clientId":"cross-client"}}`)
	if revoke.Error != nil {
		t.Fatalf("revoke = %#v", revoke.Error)
	}
	time.Sleep(75 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := cross.Read(ctx); err == nil {
		t.Fatal("revoked active client remained connected")
	}

	retry := dialUnauthenticated(t, bridge, nil, "https://localdraft.ai")
	defer retry.CloseNow()
	begin = authBeginCall(t, retry, "cross-client", publicKey)
	if begin.Error == nil || begin.Error.Data.Code != "PAIRING_REQUIRED" {
		t.Fatalf("revoked client did not require pairing = %#v", begin)
	}
}

func TestBridgeHandshakeErrorsAndLogs(t *testing.T) {
	bridge := startTestBridge(t, nil)
	connection := dialBridge(t, bridge, exchangeSession(t, bridge), bridge.server.Origin())
	defer connection.Close(websocket.StatusNormalClosure, "test complete")

	response := rpcCall(t, connection, `{"jsonrpc":"2.0","id":"hello","method":"bridge.hello","params":{}}`)
	if response.Error != nil {
		t.Fatalf("hello error = %#v", response.Error)
	}
	result := response.Result.(map[string]any)
	if result["protocolVersion"].(float64) != ProtocolVersion {
		t.Fatalf("protocol version = %#v", result["protocolVersion"])
	}

	response = rpcCall(t, connection, `{"jsonrpc":"2.0","id":2,"method":"missing.method"}`)
	if response.Error == nil || response.Error.Code != protocol.MethodNotFoundCode {
		t.Fatalf("unknown method response = %#v", response)
	}
	response = rpcCall(t, connection, `{broken`)
	if response.Error == nil || response.Error.Code != protocol.ParseErrorCode {
		t.Fatalf("parse error response = %#v", response)
	}
	response = rpcCall(t, connection, `{"jsonrpc":"2.0","id":"logs","method":"bridge.getLogs"}`)
	if response.Error != nil {
		t.Fatalf("logs error = %#v", response.Error)
	}
}

func TestMessageLimitClosesConnection(t *testing.T) {
	bridge := startTestBridge(t, func(config *Config) { config.MaximumMessageSize = 512 })
	connection := dialBridge(t, bridge, exchangeSession(t, bridge), bridge.server.Origin())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	message := `{"jsonrpc":"2.0","id":"large","method":"bridge.hello","params":{"value":"` + strings.Repeat("x", 512) + `"}}`
	if err := connection.Write(ctx, websocket.MessageText, []byte(message)); err != nil {
		t.Fatal(err)
	}
	_, _, err := connection.Read(ctx)
	if err == nil {
		t.Fatal("oversized message did not close the connection")
	}
}

func TestOversizedResponseReturnsStructuredLimitError(t *testing.T) {
	bridge := startTestBridge(t, func(config *Config) { config.MaximumMessageSize = 512 })
	bridge.server.router.Register("test.largeResponse", func(context.Context, json.RawMessage) (any, *protocol.Error) {
		return map[string]string{"value": strings.Repeat("x", 2048)}, nil
	})
	connection := dialBridge(t, bridge, exchangeSession(t, bridge), bridge.server.Origin())
	defer connection.Close(websocket.StatusNormalClosure, "test complete")
	response := rpcCall(t, connection, `{"jsonrpc":"2.0","id":"large-response","method":"test.largeResponse"}`)
	if response.Error == nil || response.Error.Data == nil || response.Error.Data.Code != "FILE_TOO_LARGE" {
		t.Fatalf("oversized response = %#v", response)
	}
}

func TestConcurrentRPCBound(t *testing.T) {
	bridge := startTestBridge(t, func(config *Config) { config.MaximumConcurrent = 2 })
	started := make(chan struct{}, 3)
	release := make(chan struct{}, 3)
	var mu sync.Mutex
	current := 0
	maximum := 0
	bridge.server.router.Register("test.block", func(ctx context.Context, _ json.RawMessage) (any, *protocol.Error) {
		mu.Lock()
		current++
		if current > maximum {
			maximum = current
		}
		mu.Unlock()
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		mu.Lock()
		current--
		mu.Unlock()
		return map[string]bool{"ok": true}, nil
	})
	connection := dialBridge(t, bridge, exchangeSession(t, bridge), bridge.server.Origin())
	defer connection.Close(websocket.StatusNormalClosure, "test complete")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for index := 1; index <= 3; index++ {
		message := `{"jsonrpc":"2.0","id":` + string(rune('0'+index)) + `,"method":"test.block"}`
		if err := connection.Write(ctx, websocket.MessageText, []byte(message)); err != nil {
			t.Fatal(err)
		}
	}
	for index := 0; index < 2; index++ {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("RPC did not start")
		}
	}
	select {
	case <-started:
		t.Fatal("third RPC exceeded the concurrency bound")
	case <-time.After(50 * time.Millisecond):
	}
	release <- struct{}{}
	release <- struct{}{}
	for index := 0; index < 2; index++ {
		if _, _, err := connection.Read(ctx); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("third RPC did not start after capacity was released")
	}
	release <- struct{}{}
	if _, _, err := connection.Read(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if maximum != 2 {
		t.Fatalf("maximum concurrent calls = %d", maximum)
	}
}

func TestHealthStaticFilesAndGracefulShutdown(t *testing.T) {
	bridge := startTestBridge(t, nil)
	response, err := testHTTPClient().Get(bridge.server.Origin() + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", response.StatusCode)
	}
	response, err = testHTTPClient().Get(bridge.server.Origin() + "/src/local_draft_ai.html")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("static status = %d", response.StatusCode)
	}
	response, err = testHTTPClient().Get(bridge.server.Origin() + "/go.mod")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("unexpected static exposure status = %d", response.StatusCode)
	}

	connection := dialBridge(t, bridge, exchangeSession(t, bridge), bridge.server.Origin())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := bridge.server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	_, _, err = connection.Read(ctx)
	if err == nil {
		t.Fatalf("websocket was not closed during shutdown: %v", err)
	}
}

func TestProfileAndPromptedSSHConnectionRPC(t *testing.T) {
	sshServer, err := testssh.Start(testssh.Options{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer sshServer.Close()
	identityPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := sshServer.WriteIdentityFile(identityPath, nil); err != nil {
		t.Fatal(err)
	}
	host, portText, _ := net.SplitHostPort(sshServer.Address)
	port, _ := strconv.Atoi(portText)
	bridge := startTestBridge(t, nil)
	connection := dialBridge(t, bridge, exchangeSession(t, bridge), bridge.server.Origin())
	defer connection.Close(websocket.StatusNormalClosure, "test complete")
	secretProfileResponse := rpcCall(t, connection, `{"jsonrpc":"2.0","id":"secret-profile","method":"profile.create","params":{"profile":{"label":"Unsafe","host":"127.0.0.1","user":"test","auth":{"password":"must-not-store"}}}}`)
	if secretProfileResponse.Error == nil || secretProfileResponse.Error.Code != protocol.InvalidParamsCode {
		t.Fatalf("secret profile fields were accepted: %#v", secretProfileResponse)
	}
	createPayload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "create-profile",
		"method":  "profile.create",
		"params": map[string]any{
			"profile": map[string]any{
				"label": "RPC SSH",
				"host":  host,
				"port":  port,
				"user":  sshServer.User,
				"auth": map[string]any{
					"useAgent":      false,
					"identityFile":  identityPath,
					"allowPassword": false,
				},
			},
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := connection.Write(ctx, websocket.MessageText, createPayload); err != nil {
		t.Fatal(err)
	}
	_, payload, err := connection.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var createResponse struct {
		Result struct {
			Profile struct {
				ID string `json:"id"`
			} `json:"profile"`
		} `json:"result"`
		Error *protocol.Error `json:"error"`
	}
	if err := json.Unmarshal(payload, &createResponse); err != nil {
		t.Fatal(err)
	}
	if createResponse.Error != nil || createResponse.Result.Profile.ID == "" {
		t.Fatalf("create response = %s", payload)
	}
	connectionID := createResponse.Result.Profile.ID
	connectPayload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "connect",
		"method":  "connection.connect",
		"params":  map[string]string{"connectionId": connectionID},
	})
	if err := connection.Write(ctx, websocket.MessageText, connectPayload); err != nil {
		t.Fatal(err)
	}
	connected := false
	hostPrompted := false
	trustResponded := false
	for !connected || !trustResponded {
		_, payload, err = connection.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var message struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params map[string]any  `json:"params"`
			Result map[string]any  `json:"result"`
			Error  *protocol.Error `json:"error"`
		}
		if err := json.Unmarshal(payload, &message); err != nil {
			t.Fatal(err)
		}
		if message.Method == "connection.hostKeyPrompt" {
			hostPrompted = true
			promptID, _ := message.Params["promptId"].(string)
			responsePayload, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      "trust",
				"method":  "connection.respondToPrompt",
				"params":  map[string]any{"promptId": promptID, "trust": true},
			})
			if err := connection.Write(ctx, websocket.MessageText, responsePayload); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if string(message.ID) == `"connect"` {
			if message.Error != nil || message.Result["state"] != "connected" {
				t.Fatalf("connect response = %s", payload)
			}
			connected = true
		}
		if string(message.ID) == `"trust"` {
			if message.Error != nil {
				t.Fatalf("trust response = %s", payload)
			}
			trustResponded = true
		}
	}
	if !hostPrompted {
		t.Fatal("connection did not request first-use host trust")
	}
	homeResponse := rpcCall(t, connection, `{"jsonrpc":"2.0","id":"home","method":"remote.getHomeDirectory","params":{"connectionId":"`+connectionID+`"}}`)
	if homeResponse.Error != nil {
		t.Fatalf("home response = %#v", homeResponse)
	}
	if err := bridge.server.sshManager.Disconnect(connectionID); err != nil {
		t.Fatal(err)
	}
}
