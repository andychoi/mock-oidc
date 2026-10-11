package entra

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

var claimsNow = time.Unix(1790000000, 0)

func claimsInput(tn *Tenant, u *User, scopes ...string) TokenInput {
	return TokenInput{Origin: "http://h:1", BasePath: "entra", Tenant: tn, User: u, ClientID: "app",
		Nonce: "n1", Scopes: scopes, Now: claimsNow, Expiry: 3600}
}

func corpTenant() *Tenant {
	return &Tenant{TID: tidA, Name: "Corp", Domains: []string{"corp.example"}, GroupClaimFormat: FormatName, GroupLimit: 200}
}

func TestIDTokenClaimsCoreShape(t *testing.T) {
	u := &User{Username: "jane", TID: tidA, OID: "oid-1", Name: "Jane"}
	c := IDTokenClaims(claimsInput(corpTenant(), u, "openid", "profile"))
	want := map[string]any{
		"iss": "http://h:1/entra/" + tidA + "/v2.0", "aud": "app", "tid": tidA, "oid": "oid-1",
		"ver": "2.0", "name": "Jane", "preferred_username": "jane@corp.example", "nonce": "n1",
		"iat": int64(1790000000), "nbf": int64(1790000000), "exp": int64(1790003600),
		"sub": PairwiseSub("app", "oid-1"),
	}
	for k, v := range want {
		if c[k] != v {
			t.Errorf("%s = %v, want %v", k, c[k], v)
		}
	}
	if c["uti"] == "" || c["uti"] == nil {
		t.Error("uti missing")
	}
	for _, absent := range []string{"email", "xms_edov", "amr", "groups", "_claim_names", "_claim_sources"} {
		if _, ok := c[absent]; ok {
			t.Errorf("%s must be absent", absent)
		}
	}
}

func TestPairwiseSubStablePerClientDifferentAcrossClients(t *testing.T) {
	a := PairwiseSub("app-a", "oid-1")
	if a != PairwiseSub("app-a", "oid-1") || a == PairwiseSub("app-b", "oid-1") || len(a) != 43 {
		t.Fatalf("pairwise sub %q", a)
	}
}

func TestEmailNeedsScopeAndEdovAmrWhenConfigured(t *testing.T) {
	no := false
	u := &User{Username: "jane", TID: tidA, OID: "o", Email: "jane@corp.example", EmailVerified: &no, AMR: []string{"pwd", "mfa"}}
	without := IDTokenClaims(claimsInput(corpTenant(), u, "openid"))
	if _, ok := without["email"]; ok {
		t.Error("email must require the email scope")
	}
	with := IDTokenClaims(claimsInput(corpTenant(), u, "openid", "email"))
	if with["email"] != "jane@corp.example" || with["xms_edov"] != false || !reflect.DeepEqual(with["amr"], []string{"pwd", "mfa"}) {
		t.Errorf("claims = %v", with)
	}
	if with["preferred_username"] != "jane@corp.example" {
		t.Errorf("preferred_username = %v", with["preferred_username"])
	}
}

func TestGroupsByFormat(t *testing.T) {
	u := &User{Username: "sam", TID: tidA, OID: "o", Groups: []string{"G1", "G2"}}
	names := IDTokenClaims(claimsInput(corpTenant(), u, "openid"))
	if !reflect.DeepEqual(names["groups"], []string{"G1", "G2"}) {
		t.Errorf("name groups = %v", names["groups"])
	}
	tn := corpTenant()
	tn.GroupClaimFormat = FormatObjectID
	ids := IDTokenClaims(claimsInput(tn, u, "openid"))
	want := []string{GroupObjectID(tidA, "G1"), GroupObjectID(tidA, "G2")}
	if !reflect.DeepEqual(ids["groups"], want) {
		t.Errorf("object_id groups = %v, want %v", ids["groups"], want)
	}
}

func TestGroupOverageBoundary(t *testing.T) {
	tn := corpTenant()
	tn.GroupLimit = 3
	atLimit := &User{Username: "a", TID: tidA, OID: "oid-a", Groups: []string{"G1", "G2", "G3"}}
	if c := IDTokenClaims(claimsInput(tn, atLimit, "openid")); c["groups"] == nil || c["_claim_names"] != nil {
		t.Errorf("at the limit, groups must be emitted: %v", c)
	}
	over := &User{Username: "b", TID: tidA, OID: "oid-b", Groups: []string{"G1", "G2", "G3", "G4"}}
	c := IDTokenClaims(claimsInput(tn, over, "openid"))
	if _, ok := c["groups"]; ok {
		t.Error("over the limit, groups must be omitted")
	}
	if !reflect.DeepEqual(c["_claim_names"], map[string]any{"groups": "src1"}) {
		t.Errorf("_claim_names = %v", c["_claim_names"])
	}
	src := c["_claim_sources"].(map[string]any)["src1"].(map[string]any)
	if ep, _ := src["endpoint"].(string); !strings.Contains(ep, "/users/oid-b/getMemberObjects") {
		t.Errorf("overage endpoint = %v", src["endpoint"])
	}
}

func TestAccessTokenClaims(t *testing.T) {
	u := &User{Username: "jane", TID: tidA, OID: "o"}
	c := AccessTokenClaims(claimsInput(corpTenant(), u, "openid", "profile", "email"))
	if c["aud"] != graphAppID || c["scp"] != "openid profile email" || c["tid"] != tidA {
		t.Errorf("access claims = %v", c)
	}
	if _, ok := c["nonce"]; ok {
		t.Error("access token must not carry nonce")
	}
}

// overageInput builds a claims input for a user over the group limit.
func overageInput(selfHosted bool) TokenInput {
	tn := corpTenant()
	tn.GroupLimit = 1
	u := &User{Username: "many", TID: tidA, OID: "oid-many", Groups: []string{"G1", "G2"}}
	in := claimsInput(tn, u, "openid")
	in.GraphBase = "graph"
	in.OverageSelfHosted = selfHosted
	return in
}

func overageEndpointOf(t *testing.T, in TokenInput) string {
	t.Helper()
	c := IDTokenClaims(in)
	src, ok := c["_claim_sources"].(map[string]any)["src1"].(map[string]any)
	if !ok {
		t.Fatalf("no overage source: %v", c)
	}
	return src["endpoint"].(string)
}

// With the emulated Graph serving getMemberObjects, the overage claim must
// point at us, or a relying party that follows it leaves the test environment.
func TestOverageEndpointPointsAtSelfByDefault(t *testing.T) {
	got := overageEndpointOf(t, overageInput(true))
	want := "http://h:1/entra/graph/v1.0/users/oid-many/getMemberObjects"
	if got != want {
		t.Errorf("endpoint = %q, want %q", got, want)
	}
}

func TestOverageEndpointAtMicrosoftWhenNotSelfHosted(t *testing.T) {
	got := overageEndpointOf(t, overageInput(false))
	want := "https://graph.microsoft.com/v1.0/users/oid-many/getMemberObjects"
	if got != want {
		t.Errorf("endpoint = %q, want %q", got, want)
	}
}

// A self-hosted endpoint needs an origin to be absolute; without one the real
// Graph URL is still a valid answer.
func TestOverageEndpointFallsBackWithoutOrigin(t *testing.T) {
	in := overageInput(true)
	in.Origin = ""
	if got := overageEndpointOf(t, in); !strings.HasPrefix(got, "https://graph.microsoft.com/") {
		t.Errorf("endpoint = %q", got)
	}
}

func TestStripScopePrefix(t *testing.T) {
	cases := map[string]string{
		"openid":                                "openid",
		"https://graph.microsoft.com/User.Read": "User.Read",
		"https://graph.microsoft.com/.default":  ".default",
		"api://11111111-1111-1111-1111-111111111111/access_as_user": "access_as_user",
		"https://graph.microsoft.com":                               "https://graph.microsoft.com",
		"User.Read":                                                 "User.Read",
	}
	for in, want := range cases {
		if got := StripScopePrefix(in); got != want {
			t.Errorf("StripScopePrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

// scp carries API permission names; offline_access governs the grant, not an
// API, so Entra leaves it out.
func TestScpStripsResourcePrefixAndDropsOfflineAccess(t *testing.T) {
	u := &User{Username: "jane", TID: tidA, OID: "o"}
	scopes := []string{"openid", "offline_access", "https://graph.microsoft.com/User.Read",
		"api://11111111-1111-1111-1111-111111111111/access_as_user"}
	c := AccessTokenClaims(claimsInput(corpTenant(), u, scopes...))
	if c["scp"] != "openid User.Read access_as_user" {
		t.Errorf("scp = %v", c["scp"])
	}
}

func TestAccessTokenCarriesAzpAndAppid(t *testing.T) {
	u := &User{Username: "jane", TID: tidA, OID: "o"}
	c := AccessTokenClaims(claimsInput(corpTenant(), u, "openid"))
	if c["azp"] != "app" || c["appid"] != "app" {
		t.Errorf("azp=%v appid=%v, want the client id", c["azp"], c["appid"])
	}
	// The ID token names its audience, not the authorized party.
	id := IDTokenClaims(claimsInput(corpTenant(), u, "openid"))
	for _, absent := range []string{"azp", "appid", "scp"} {
		if _, has := id[absent]; has {
			t.Errorf("%s belongs to the access token only", absent)
		}
	}
}

func TestGivenFamilyNameRolesWidsOnlyWhenConfigured(t *testing.T) {
	bare := &User{Username: "jane", TID: tidA, OID: "o"}
	c := IDTokenClaims(claimsInput(corpTenant(), bare, "openid"))
	for _, absent := range []string{"given_name", "family_name", "roles", "wids"} {
		if _, has := c[absent]; has {
			t.Errorf("%s must be absent when unconfigured", absent)
		}
	}
	full := &User{Username: "jane", TID: tidA, OID: "o", GivenName: "Jane", Surname: "Kim",
		Roles: []string{"Portal.Admin"}, WIDs: []string{"62e90394-69f5-4237-9190-012177145e10"}}
	c = IDTokenClaims(claimsInput(corpTenant(), full, "openid"))
	if c["given_name"] != "Jane" || c["family_name"] != "Kim" {
		t.Errorf("name claims = %v / %v", c["given_name"], c["family_name"])
	}
	if !reflect.DeepEqual(c["roles"], []string{"Portal.Admin"}) ||
		!reflect.DeepEqual(c["wids"], []string{"62e90394-69f5-4237-9190-012177145e10"}) {
		t.Errorf("roles=%v wids=%v", c["roles"], c["wids"])
	}
	// Both appear on the access token too, as Entra emits them.
	a := AccessTokenClaims(claimsInput(corpTenant(), full, "openid"))
	if !reflect.DeepEqual(a["roles"], []string{"Portal.Admin"}) || a["given_name"] != "Jane" {
		t.Errorf("access token = %v", a)
	}
}
