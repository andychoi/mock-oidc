package entra

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

func mustStore(t *testing.T) *Store {
	t.Helper()
	cfg, err := ParseConfig([]byte(`{
	  "tenants": [
	    {"tid": "11111111-1111-1111-1111-111111111111", "name": "Corp"},
	    {"tid": "22222222-2222-2222-2222-222222222222", "name": "Cust"}
	  ],
	  "consents": [{"clientId": "c1", "tid": "22222222-2222-2222-2222-222222222222"}],
	  "users": [
	    {"username": "jane", "tid": "11111111-1111-1111-1111-111111111111"},
	    {"username": "bob", "tid": "22222222-2222-2222-2222-222222222222"}
	  ]
	}`))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	return NewStore(cfg)
}

func TestStoreTenantValidation(t *testing.T) {
	s := mustStore(t)

	if err := s.CreateTenant(Tenant{TID: "nope"}); err == nil || !strings.Contains(err.Error(), "must be a GUID") {
		t.Errorf("bad guid: %v", err)
	}
	if err := s.CreateTenant(Tenant{TID: "11111111-1111-1111-1111-111111111111"}); err == nil || !strings.Contains(err.Error(), "duplicate tid") {
		t.Errorf("duplicate: %v", err)
	}
	// defaults applied by normalize
	if err := s.CreateTenant(Tenant{TID: "33333333-3333-3333-3333-333333333333"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	tn := s.Snapshot().Tenant("33333333-3333-3333-3333-333333333333")
	if tn == nil || tn.Name != tn.TID || tn.GroupClaimFormat != FormatName || tn.GroupLimit != s.Snapshot().DefaultGroupLimit {
		t.Errorf("defaults not applied: %+v", tn)
	}

	// rename rejected
	if err := s.UpdateTenant("33333333-3333-3333-3333-333333333333", Tenant{TID: "44444444-4444-4444-4444-444444444444"}); err == nil {
		t.Errorf("rename should fail")
	}
	// update fields
	if err := s.UpdateTenant("33333333-3333-3333-3333-333333333333", Tenant{Name: "Third", GroupLimit: 5}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if tn := s.Snapshot().Tenant("33333333-3333-3333-3333-333333333333"); tn == nil || tn.Name != "Third" || tn.GroupLimit != 5 {
		t.Errorf("update not applied: %+v", tn)
	}
	// unknown tenant
	if err := s.UpdateTenant("99999999-9999-9999-9999-999999999999", Tenant{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("update unknown: %v", err)
	}
}

func TestStoreTenantDeleteCascade(t *testing.T) {
	s := mustStore(t)

	if err := s.DeleteTenant("11111111-1111-1111-1111-111111111111"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	c := s.Snapshot()
	if c.Tenant("11111111-1111-1111-1111-111111111111") != nil {
		t.Errorf("tenant still present")
	}
	if u := c.User("11111111-1111-1111-1111-111111111111", "jane"); u != nil {
		t.Errorf("user not cascaded")
	}
	if err := s.DeleteTenant("99999999-9999-9999-9999-999999999999"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete unknown: %v", err)
	}
	// the last tenant cannot be deleted
	if err := s.DeleteTenant("22222222-2222-2222-2222-222222222222"); err == nil || !strings.Contains(err.Error(), "at least one tenant") {
		t.Errorf("last tenant delete: %v", err)
	}
	// consent of a deleted tenant is cascaded out of the snapshot
	s = mustStore(t)
	if err := s.DeleteTenant("22222222-2222-2222-2222-222222222222"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	for _, cs := range s.Snapshot().Consents {
		if cs.TID == "22222222-2222-2222-2222-222222222222" {
			t.Errorf("consent not cascaded: %+v", cs)
		}
	}
}

func TestStoreUserValidation(t *testing.T) {
	s := mustStore(t)
	unknown := "99999999-9999-9999-9999-999999999999"

	if err := s.CreateUser(User{Username: "x", TID: unknown}); err == nil || !strings.Contains(err.Error(), "unknown tid") {
		t.Errorf("unknown tid: %v", err)
	}
	if err := s.CreateUser(User{Username: "jane", TID: "11111111-1111-1111-1111-111111111111"}); err == nil || !strings.Contains(err.Error(), "duplicate username") {
		t.Errorf("duplicate: %v", err)
	}
	if err := s.CreateUser(User{Username: "x", TID: "11111111-1111-1111-1111-111111111111", Error: "boom"}); err == nil || !strings.Contains(err.Error(), "error must be") {
		t.Errorf("bad error: %v", err)
	}
	if err := s.CreateUser(User{Username: "x", TID: "11111111-1111-1111-1111-111111111111", OID: "not-a-guid"}); err == nil || !strings.Contains(err.Error(), "oid must be a GUID") {
		t.Errorf("bad oid: %v", err)
	}
	// oid derived + name defaulted
	if err := s.CreateUser(User{Username: "x", TID: "11111111-1111-1111-1111-111111111111"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	u := s.Snapshot().User("11111111-1111-1111-1111-111111111111", "x")
	if u == nil || u.OID == "" || u.Name != "x" {
		t.Errorf("oid/name defaults: %+v", u)
	}
	// identity immutable
	if err := s.UpdateUser("11111111-1111-1111-1111-111111111111", "x", User{TID: "22222222-2222-2222-2222-222222222222"}); err == nil || !strings.Contains(err.Error(), "tid cannot be changed") {
		t.Errorf("cross-tenant update: %v", err)
	}
	if err := s.UpdateUser("11111111-1111-1111-1111-111111111111", "ghost", User{Name: "g"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("update unknown: %v", err)
	}
	if err := s.DeleteUser("11111111-1111-1111-1111-111111111111", "ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete unknown: %v", err)
	}
	if err := s.DeleteUser("11111111-1111-1111-1111-111111111111", "x"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if u := s.Snapshot().User("11111111-1111-1111-1111-111111111111", "x"); u != nil {
		t.Errorf("user still present")
	}
}

func TestStoreResetAndIsolation(t *testing.T) {
	s := mustStore(t)

	if err := s.CreateTenant(Tenant{TID: "33333333-3333-3333-3333-333333333333"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	before := s.Snapshot()
	s.Reset()

	if s.Snapshot().Tenant("33333333-3333-3333-3333-333333333333") != nil {
		t.Errorf("reset did not restore seed")
	}
	// previously taken snapshots are immutable (deep copy, no shared arrays)
	if before.Tenant("33333333-3333-3333-3333-333333333333") == nil {
		t.Errorf("old snapshot mutated by reset")
	}
}

func TestStoreConcurrentMutateAndSnapshot(t *testing.T) {
	s := mustStore(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tid := []string{
				"33333333-3333-3333-3333-333333333333",
				"44444444-4444-4444-4444-444444444444",
				"55555555-5555-5555-5555-555555555555",
				"66666666-6666-6666-6666-666666666666",
			}[i%4]
			_ = s.CreateTenant(Tenant{TID: tid})
			_ = s.Snapshot().Tenant(tid)
			_ = s.DeleteTenant(tid)
		}(i)
	}
	wg.Wait()
	// seed intact after the storm
	if s.Snapshot().Tenant("11111111-1111-1111-1111-111111111111") == nil {
		t.Errorf("seed tenant lost")
	}
}
