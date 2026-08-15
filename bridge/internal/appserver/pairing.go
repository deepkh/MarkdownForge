package appserver

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	bridgeconfig "localdraftai/bridge/internal/config"
)

type pairingRequest struct {
	RequestID string
	Code      string
	Origin    string
	ClientID  string
	Name      string
	PublicKey bridgeconfig.PublicKeyJWK
	ExpiresAt time.Time
}

type pairingRequestView struct {
	RequestID string    `json:"requestId"`
	Code      string    `json:"code"`
	Origin    string    `json:"origin"`
	ClientID  string    `json:"clientId"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type pairingManager struct {
	mu       sync.Mutex
	requests map[string]pairingRequest
	lifetime time.Duration
	limit    int
}

func newPairingManager(lifetime time.Duration) *pairingManager {
	if lifetime <= 0 {
		lifetime = 5 * time.Minute
	}
	return &pairingManager{requests: make(map[string]pairingRequest), lifetime: lifetime, limit: 10}
}

func (m *pairingManager) create(origin, clientID, name string, publicKey bridgeconfig.PublicKeyJWK) (pairingRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(time.Now())
	count := 0
	for _, request := range m.requests {
		if request.Origin == origin {
			count++
		}
		if request.Origin == origin && request.ClientID == clientID && request.PublicKey == publicKey {
			return request, nil
		}
	}
	if count >= m.limit {
		return pairingRequest{}, errors.New("too many pending pairing requests")
	}
	requestID, err := randomToken(18)
	if err != nil {
		return pairingRequest{}, err
	}
	var randomValue [4]byte
	if _, err := rand.Read(randomValue[:]); err != nil {
		return pairingRequest{}, err
	}
	code := binary.BigEndian.Uint32(randomValue[:]) % 1000000
	request := pairingRequest{
		RequestID: requestID,
		Code:      sixDigitCode(code),
		Origin:    origin,
		ClientID:  clientID,
		Name:      name,
		PublicKey: publicKey,
		ExpiresAt: time.Now().UTC().Add(m.lifetime),
	}
	m.requests[requestID] = request
	return request, nil
}

func sixDigitCode(value uint32) string {
	const digits = "0123456789"
	result := []byte("000000")
	for index := len(result) - 1; index >= 0; index-- {
		result[index] = digits[value%10]
		value /= 10
	}
	return string(result)
}

func (m *pairingManager) list() []pairingRequestView {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(time.Now())
	views := make([]pairingRequestView, 0, len(m.requests))
	for _, request := range m.requests {
		views = append(views, request.view())
	}
	return views
}

func (m *pairingManager) take(requestID string) (pairingRequest, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.expireLocked(time.Now())
	request, ok := m.requests[requestID]
	if ok {
		delete(m.requests, requestID)
	}
	return request, ok
}

func (m *pairingManager) deny(requestID string) bool {
	_, ok := m.take(requestID)
	return ok
}

func (m *pairingManager) expireLocked(now time.Time) {
	for id, request := range m.requests {
		if !now.Before(request.ExpiresAt) {
			delete(m.requests, id)
		}
	}
}

func (request pairingRequest) view() pairingRequestView {
	return pairingRequestView{
		RequestID: request.RequestID, Code: request.Code, Origin: request.Origin,
		ClientID: request.ClientID, Name: request.Name, ExpiresAt: request.ExpiresAt,
	}
}
