package entra

import "testing"

func TestUUIDv5KnownVector(t *testing.T) {
	// Python docs: uuid.uuid5(uuid.NAMESPACE_DNS, 'python.org')
	dns := mustUUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	if got := UUIDv5(dns, "python.org"); got != "886313e1-3b8a-5372-9b90-0c9aee199e5d" {
		t.Fatalf("UUIDv5 = %s", got)
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
