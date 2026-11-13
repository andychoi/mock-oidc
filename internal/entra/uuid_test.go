package entra

import (
	"strings"
	"testing"
)

func TestUUIDv5KnownVector(t *testing.T) {
	// Python docs: uuid.uuid5(uuid.NAMESPACE_DNS, 'python.org')
	dns := mustUUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	if got := UUIDv5(dns, "python.org"); got != "886313e1-3b8a-5372-9b90-0c9aee199e5d" {
		t.Fatalf("UUIDv5 = %s", got)
	}
}

func TestRandomGUIDIsVersion4(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 16; i++ {
		g := RandomGUID()
		if !guidRE.MatchString(g) {
			t.Fatalf("RandomGUID = %q, not a lowercase GUID", g)
		}
		if g[14] != '4' {
			t.Fatalf("RandomGUID = %q, version nibble is not 4", g)
		}
		if seen[g] {
			t.Fatalf("RandomGUID repeated: %s", g)
		}
		seen[g] = true
	}
}

func TestRandomSecretValueShape(t *testing.T) {
	v := RandomSecretValue()
	if len(v) != 3+len("8Q~")+43 { // 3 letters + separator + base64url of 32 bytes
		t.Fatalf("RandomSecretValue = %q, len %d", v, len(v))
	}
	if v[3:6] != "8Q~" {
		t.Fatalf("RandomSecretValue = %q, missing the ~ separator block", v)
	}
	for i := 0; i < 3; i++ {
		if v[i] < 'a' || v[i] > 'z' {
			t.Fatalf("RandomSecretValue = %q, prefix is not lowercase letters", v)
		}
	}
	if strings.ContainsAny(v[6:], "+/") { // base64url never emits the standard alphabet
		t.Fatalf("RandomSecretValue body is not base64url: %q", v)
	}
}

func TestGroupObjectIDStableAndTenantScoped(t *testing.T) {
	a := GroupObjectID("11111111-1111-1111-1111-111111111111", "Admins")
	if a != GroupObjectID("11111111-1111-1111-1111-111111111111", "Admins") {
		t.Error("object ID must be stable")
	}
	if a == GroupObjectID("22222222-2222-2222-2222-222222222222", "Admins") {
		t.Error("object IDs must differ across tenants")
	}
}
