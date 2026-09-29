package entra

import (
	"sort"
	"strings"
	"sync"
)

// ConsentStore holds admin consents (client ID × tenant) in memory, seeded
// from the config.
type ConsentStore struct {
	mu      sync.RWMutex
	seed    []Consent
	granted map[string]Consent
}

// NewConsentStore returns a store holding the seed consents.
func NewConsentStore(seed []Consent) *ConsentStore {
	s := &ConsentStore{seed: append([]Consent(nil), seed...)}
	s.Reset()
	return s
}

func consentKey(clientID, tid string) string { return clientID + "|" + strings.ToLower(tid) }

// Grant records consent of clientID in tenant tid.
func (s *ConsentStore) Grant(clientID, tid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.granted[consentKey(clientID, tid)] = Consent{ClientID: clientID, TID: strings.ToLower(tid)}
}

// Has reports whether clientID has consent in tenant tid.
func (s *ConsentStore) Has(clientID, tid string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.granted[consentKey(clientID, tid)]
	return ok
}

// Reset restores the seed consents.
func (s *ConsentStore) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.granted = map[string]Consent{}
	for _, c := range s.seed {
		s.granted[consentKey(c.ClientID, c.TID)] = Consent{ClientID: c.ClientID, TID: strings.ToLower(c.TID)}
	}
}

// Remove drops one consent (admin revoke).
func (s *ConsentStore) Remove(clientID, tid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.granted, consentKey(clientID, tid))
}

// RemoveTenant drops every consent of a tenant (tenant cascade).
func (s *ConsentStore) RemoveTenant(tid string) {
	tid = strings.ToLower(tid)
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.granted {
		if strings.HasSuffix(k, "|"+tid) {
			delete(s.granted, k)
		}
	}
}

// List returns the consents sorted by tenant, then client ID.
func (s *ConsentStore) List() []Consent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Consent, 0, len(s.granted))
	for _, c := range s.granted {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TID != out[j].TID {
			return out[i].TID < out[j].TID
		}
		return out[i].ClientID < out[j].ClientID
	})
	return out
}
