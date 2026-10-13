package entra

import (
	"reflect"
	"testing"
	"time"
)

func orgTokenInput(t *testing.T, clientID, username string) TokenInput {
	t.Helper()
	c := orgConfig(t)
	u := c.User(tidA, username)
	return TokenInput{Origin: "http://mock.test", BasePath: c.BasePath, Tenant: c.Tenant(tidA), User: u,
		ClientID: clientID, Scopes: []string{"openid"}, Now: time.Unix(1700000000, 0), Expiry: 3600,
		MappedClaims: c.MappedClaims(clientID, u)}
}

func TestMappedClaimsInIDTokenOnly(t *testing.T) {
	in := orgTokenInput(t, "iam", "hana")
	id := IDTokenClaims(in)
	if id["org_code"] != "DEPT001" || id["department"] != "HR" {
		t.Errorf("ID token mapped claims: org_code=%v department=%v", id["org_code"], id["department"])
	}
	// The access token's audience is Graph, not the app, so the app's
	// claims-mapping policy does not apply to it.
	at := AccessTokenClaims(in)
	for _, k := range []string{"org_code", "department"} {
		if _, has := at[k]; has {
			t.Errorf("access token carries %s", k)
		}
	}
	// The dynamic groups ride the groups claim of both tokens.
	want := []string{"Static Team", "GRP_DEPT_DEPT001_HRTeam", "GRP_REPORTS_boss"}
	if !reflect.DeepEqual(id["groups"], want) || !reflect.DeepEqual(at["groups"], want) {
		t.Errorf("groups: id=%v at=%v", id["groups"], at["groups"])
	}
}

func TestMappedClaimsScope(t *testing.T) {
	// Another client gets no mapped claims.
	if got := orgTokenInput(t, "other", "hana").MappedClaims; len(got) != 0 {
		t.Errorf("other client = %v", got)
	}
	// Empty attributes are omitted, not emitted as "".
	in := orgTokenInput(t, "iam", "boss")
	if len(in.MappedClaims) != 0 {
		t.Errorf("boss = %v", in.MappedClaims)
	}
	if _, has := IDTokenClaims(in)["org_code"]; has {
		t.Error("empty org_code emitted")
	}
	// An app pinned to another tenant does not map this tenant's users.
	c := orgConfig(t)
	c.Apps[0].TID = tidB
	if got := c.MappedClaims("iam", c.User(tidA, "hana")); len(got) != 0 {
		t.Errorf("cross-tenant app = %v", got)
	}
}
