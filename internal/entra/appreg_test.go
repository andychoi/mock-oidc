package entra

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/andychoi/mock-oidc/internal/jsonx"
	"github.com/andychoi/mock-oidc/internal/routing"
)

// appConfig wraps an apps block in the minimal valid config.
func appConfig(apps string) string {
	return `{
	  "tenants": [{"tid": "` + tidA + `"}],
	  "users": [{"username": "jane", "tid": "` + tidA + `"}],
	  "apps": [` + apps + `]}`
}

func TestAppRegistrationValidation(t *testing.T) {
	cases := map[string]struct{ apps, wantErr string }{
		"duplicate client id": {`{"clientId": "a"}, {"clientId": "a"}`, "duplicate clientId"},
		"bad object id":       {`{"clientId": "a", "objectId": "not-a-guid"}`, "objectId must be a GUID"},
		"bad sign-in audience": {`{"clientId": "a", "tid": "` + tidA + `", "signInAudience": "Both"}`,
			"signInAudience must be"},
		"my org without tid": {`{"clientId": "a", "signInAudience": "` + AudienceMyOrg + `"}`, "requires a tid"},
		"multi orgs with tid": {`{"clientId": "a", "tid": "` + tidA + `", "signInAudience": "` + AudienceMultiOrgs + `"}`,
			"cannot carry a tid"},
		"web http off loopback": {`{"clientId": "a", "redirectUris": [
			{"platform": "web", "uri": "http://app.test/cb"}]}`, "must be https URLs"},
		"spa http off loopback": {`{"clientId": "a", "redirectUris": [
			{"platform": "spa", "uri": "http://app.test/cb"}]}`, "must be https URLs"},
		"mobile https url": {`{"clientId": "a", "redirectUris": [
			{"platform": "mobileAndDesktop", "uri": "https://app.test/cb"}]}`, "must be custom schemes or http loopback"},
		"mobile http off loopback": {`{"clientId": "a", "redirectUris": [
			{"platform": "mobileAndDesktop", "uri": "http://app.test/cb"}]}`, "must be custom schemes or http loopback"},
		"unknown platform": {`{"clientId": "a", "redirectUris": [
			{"platform": "ios", "uri": "https://app.test/cb"}]}`, "platform must be"},
		"duplicate redirect uri": {`{"clientId": "a", "redirectUris": [
			{"uri": "https://a.test/cb"}, {"platform": "spa", "uri": "https://a.test/cb"}]}`, "duplicate redirect uri"},
		"relative uri": {`{"clientId": "a", "redirectUris": [{"uri": "/cb"}]}`, "not an absolute URI"},
		"empty uri":    {`{"clientId": "a", "redirectUris": [{"uri": ""}]}`, "uri is required"},
		"secret bad id": {`{"clientId": "a", "secrets": [
			{"id": "nope", "value": "v", "expires": "2030-01-01T00:00:00Z"}]}`, "id must be a GUID"},
		"secret duplicate id": {`{"clientId": "a", "secrets": [
			{"id": "aaaaaaaa-0000-0000-0000-000000000001", "value": "v", "expires": "2030-01-01T00:00:00Z"},
			{"id": "aaaaaaaa-0000-0000-0000-000000000001", "value": "w", "expires": "2031-01-01T00:00:00Z"}]}`,
			"duplicate secret id"},
		"secret without value": {`{"clientId": "a", "secrets": [
			{"id": "aaaaaaaa-0000-0000-0000-000000000001", "expires": "2030-01-01T00:00:00Z"}]}`, "value is required"},
		"secret bad expires": {`{"clientId": "a", "secrets": [
			{"id": "aaaaaaaa-0000-0000-0000-000000000001", "value": "v", "expires": "in 6 months"}]}`,
			"expires must be an RFC 3339"},
		"secret bad created on": {`{"clientId": "a", "secrets": [
			{"id": "aaaaaaaa-0000-0000-0000-000000000001", "value": "v", "expires": "2030-01-01T00:00:00Z",
			 "createdOn": "yesterday"}]}`, "createdOn must be an RFC 3339"},
		"bad app created on": {`{"clientId": "a", "createdOn": "nope"}`, "createdOn must be an RFC 3339"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(appConfig(tc.apps))); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestAppRegistrationDerivedFields(t *testing.T) {
	cfg := mustConfig(t, appConfig(`{"clientId": "sync", "tid": "`+tidA+`",
	  "redirectUris": [{"uri": "http://localhost:2901/cb"}, {"uri": "https://sync.test/cb"}],
	  "secrets": [{"id": "aaaaaaaa-0000-0000-0000-000000000001", "value": "s", "expires": "2030-01-01T00:00:00Z"}]},
	 {"clientId": "multi", "objectId": "AAAAAAAA-0000-0000-0000-000000000002", "createdOn": "2026-01-02T03:04:05Z"}`))

	sync := cfg.AppByID("sync")
	if sync == nil {
		t.Fatal("sync app missing")
	}
	if sync.Name != "sync" {
		t.Errorf("name = %q, want the clientId fallback", sync.Name)
	}
	if want := UUIDv5(appNamespace, "app:sync"); sync.ObjectID != want {
		t.Errorf("objectId = %q, want the derived %q", sync.ObjectID, want)
	}
	if sync.SignInAudience != AudienceMyOrg {
		t.Errorf("signInAudience = %q, want %q for an app with a tid", sync.SignInAudience, AudienceMyOrg)
	}
	if sync.RedirectURIs[0].Platform != PlatformWeb {
		t.Errorf("empty platform = %q, want the %q default", sync.RedirectURIs[0].Platform, PlatformWeb)
	}

	multi := cfg.AppByID("multi")
	if multi == nil {
		t.Fatal("multi app missing")
	}
	if multi.SignInAudience != AudienceMultiOrgs {
		t.Errorf("signInAudience = %q, want %q for an app without a tid", multi.SignInAudience, AudienceMultiOrgs)
	}
	if multi.ObjectID != "aaaaaaaa-0000-0000-0000-000000000002" {
		t.Errorf("objectId = %q, want the explicit one lowercased", multi.ObjectID)
	}
	if multi.CreatedOn != "2026-01-02T03:04:05Z" {
		t.Errorf("createdOn = %q", multi.CreatedOn)
	}
	if cfg.AppByID("missing") != nil {
		t.Error("AppByID found a client that was never registered")
	}
}

func TestAppRedirectAllowed(t *testing.T) {
	// Without registrations an app keeps the permissive default of every
	// unregistered client.
	free := App{ClientID: "a"}
	if !free.RedirectAllowed("https://anything.test/cb") {
		t.Error("an app without redirect URIs must stay permissive")
	}
	reg := App{ClientID: "a", RedirectURIs: []RedirectURI{{Platform: PlatformWeb, URI: "https://a.test/cb"}}}
	if !reg.RedirectAllowed("https://a.test/cb") {
		t.Error("the registered URI itself must be allowed")
	}
	for _, uri := range []string{"https://a.test/cb/other", "https://evil.test/cb", "https://sub.a.test/cb"} {
		if reg.RedirectAllowed(uri) {
			t.Errorf("RedirectAllowed(%q) = true, want an exact match only", uri)
		}
	}
}

func mustAppStore(t *testing.T) *Store {
	t.Helper()
	cfg, err := ParseConfig([]byte(`{
	  "tenants": [
	    {"tid": "11111111-1111-1111-1111-111111111111", "name": "Corp"},
	    {"tid": "22222222-2222-2222-2222-222222222222", "name": "Cust"}
	  ],
	  "consents": [
	    {"clientId": "keep", "tid": "11111111-1111-1111-1111-111111111111"},
	    {"clientId": "keep", "tid": "22222222-2222-2222-2222-222222222222"},
	    {"clientId": "other", "tid": "22222222-2222-2222-2222-222222222222"}
	  ],
	  "apps": [{"clientId": "keep", "tid": "11111111-1111-1111-1111-111111111111", "name": "Keeper",
	    "secrets": [{"id": "aaaaaaaa-0000-0000-0000-000000000001", "value": "old", "expires": "2030-01-01T00:00:00Z"}]}],
	  "users": [{"username": "jane", "tid": "11111111-1111-1111-1111-111111111111"}]
	}`))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	return NewStore(cfg)
}

func TestStoreAppCRUD(t *testing.T) {
	s := mustAppStore(t)
	now := time.Unix(1790000000, 0)

	created, err := s.CreateApp(App{Name: "Portal", TID: tidA}, now)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !guidRE.MatchString(created.ClientID) {
		t.Errorf("generated clientId %q is not a GUID", created.ClientID)
	}
	if created.Name != "Portal" || created.CreatedOn != now.UTC().Format(time.RFC3339) {
		t.Errorf("created = %+v", created)
	}
	if created.ObjectID != UUIDv5(appNamespace, "app:"+created.ClientID) {
		t.Errorf("objectId = %q, want the derived one", created.ObjectID)
	}
	if created.SignInAudience != AudienceMyOrg {
		t.Errorf("signInAudience = %q", created.SignInAudience)
	}
	if s.Snapshot().AppByID(created.ClientID) == nil {
		t.Error("created app missing from the snapshot")
	}

	if _, err := s.CreateApp(App{ClientID: "keep", TID: tidA}, now); err == nil || !strings.Contains(err.Error(), "duplicate clientId") {
		t.Errorf("duplicate clientId: %v", err)
	}
	fixed, err := s.CreateApp(App{ClientID: "fixed-id", CreatedOn: "2026-01-02T03:04:05Z"}, now)
	if err != nil {
		t.Fatalf("create with explicit fields: %v", err)
	}
	if fixed.ClientID != "fixed-id" || fixed.CreatedOn != "2026-01-02T03:04:05Z" || fixed.SignInAudience != AudienceMultiOrgs {
		t.Errorf("created with explicit fields = %+v", fixed)
	}

	if err := s.UpdateApp("keep", App{ClientID: "nope", TID: tidA}); err == nil || !strings.Contains(err.Error(), "clientId cannot be changed") {
		t.Errorf("clientId change: %v", err)
	}
	if err := s.UpdateApp("keep", App{TID: tidA, Name: "Renamed",
		RedirectURIs: []RedirectURI{{Platform: PlatformSPA, URI: "https://spa.test/cb"}}}); err != nil {
		t.Fatalf("update: %v", err)
	}
	app := s.Snapshot().AppByID("keep")
	if app.Name != "Renamed" || len(app.RedirectURIs) != 1 || app.RedirectURIs[0].Platform != PlatformSPA {
		t.Errorf("update not applied: %+v", app)
	}
	if want := UUIDv5(appNamespace, "app:keep"); app.ObjectID != want {
		t.Errorf("objectId = %q, want the stored %q kept", app.ObjectID, want)
	}
	if len(app.Secrets) != 1 || app.Secrets[0].Value != "old" {
		t.Errorf("secrets not preserved by the update: %+v", app.Secrets)
	}
	if err := s.UpdateApp("ghost", App{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("update unknown app: %v", err)
	}
}

func TestStoreAppSecrets(t *testing.T) {
	s := mustAppStore(t)
	now := time.Unix(1790000000, 0)

	for _, tc := range []struct {
		spec string
		want time.Time
	}{
		{"6m", now.AddDate(0, 6, 0)},
		{"12m", now.AddDate(1, 0, 0)},
		{"24m", now.AddDate(2, 0, 0)},
	} {
		sec, err := s.AddAppSecret("keep", "ci", tc.spec, now)
		if err != nil {
			t.Fatalf("%s: %v", tc.spec, err)
		}
		if sec.Expires != tc.want.UTC().Format(time.RFC3339) {
			t.Errorf("%s expires = %q, want %q", tc.spec, sec.Expires, tc.want.UTC().Format(time.RFC3339))
		}
	}
	sec, err := s.AddAppSecret("keep", "", "2030-06-01T12:00:00Z", now)
	if err != nil {
		t.Fatalf("absolute expiry: %v", err)
	}
	if sec.Expires != "2030-06-01T12:00:00Z" || sec.CreatedOn != now.UTC().Format(time.RFC3339) {
		t.Errorf("secret = %+v", sec)
	}
	if !guidRE.MatchString(sec.ID) {
		t.Errorf("secret id %q is not a GUID", sec.ID)
	}
	if len(sec.Value) < 40 || !strings.Contains(sec.Value, "8Q~") {
		t.Errorf("secret value %q is not Entra-shaped (prefix + 8Q~ + base64url body)", sec.Value)
	}
	if _, err := s.AddAppSecret("keep", "", "7m", now); err == nil || !strings.Contains(err.Error(), "expires must be") {
		t.Errorf("bad expires: %v", err)
	}
	if _, err := s.AddAppSecret("ghost", "", "6m", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("secret on unknown app: %v", err)
	}

	if err := s.DeleteAppSecret("keep", "99999999-9999-9999-9999-999999999999"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown secret: %v", err)
	}
	if err := s.DeleteAppSecret("ghost", sec.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("secret on unknown app: %v", err)
	}
	if err := s.DeleteAppSecret("keep", sec.ID); err != nil {
		t.Fatalf("delete secret: %v", err)
	}
	if got := s.Snapshot().AppByID("keep"); len(got.Secrets) != 4 { // the seed secret plus the three relative ones
		t.Errorf("secrets after delete = %+v", got.Secrets)
	}
}

func TestStoreAppDeleteCascadesSeedConsents(t *testing.T) {
	s := mustAppStore(t)
	if err := s.DeleteApp("keep"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if s.Snapshot().AppByID("keep") != nil {
		t.Error("app still present")
	}
	for _, cs := range s.Snapshot().Consents {
		if cs.ClientID == "keep" {
			t.Errorf("consent not cascaded: %+v", cs)
		}
	}
	found := false
	for _, cs := range s.Snapshot().Consents {
		if cs.ClientID == "other" {
			found = true
		}
	}
	if !found {
		t.Error("the consent of another client was dropped")
	}
	if err := s.DeleteApp("keep"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete unknown app: %v", err)
	}
}

// appAuthorizeURL builds a tenant-A authorize URL for an arbitrary client and
// redirect URI.
func appAuthorizeURL(clientID, redirectURI string) string {
	return "http://mock.test/entra/" + tidA + "/oauth2/v2.0/authorize?response_type=code&client_id=" +
		url.QueryEscape(clientID) + "&redirect_uri=" + url.QueryEscape(redirectURI) + "&scope=openid&state=s"
}

// signInAt posts the picker form at the given authorize URL and returns the
// issued code ("" on failure).
func signInAt(h *Handler, clientID, redirectURI, username string) string {
	resp := serve(h, http.MethodPost, appAuthorizeURL(clientID, redirectURI), "tid="+tidA+"&username="+username)
	loc, err := url.Parse(resp.Header.Get("Location"))
	if resp.Status != http.StatusFound || err != nil {
		return ""
	}
	return loc.Query().Get("code")
}

// redeemAt exchanges a code at the tenant-A token endpoint with an optional
// client_secret.
func redeemAt(h *Handler, clientID, redirectURI, code, secret string) routing.Response {
	form := "grant_type=authorization_code&client_id=" + url.QueryEscape(clientID) +
		"&code=" + url.QueryEscape(code) + "&redirect_uri=" + url.QueryEscape(redirectURI)
	if secret != "" {
		form += "&client_secret=" + url.QueryEscape(secret)
	}
	return serve(h, http.MethodPost, "http://mock.test/entra/"+tidA+"/oauth2/v2.0/token", form)
}

const redirectAppJSON = `{
  "tenants": [{"tid": "` + tidA + `"}],
  "users": [{"username": "jane", "tid": "` + tidA + `"}],
  "apps": [{"clientId": "reg", "tid": "` + tidA + `", "redirectUris": [
    {"platform": "web", "uri": "http://localhost:2901/cb"},
    {"platform": "mobileAndDesktop", "uri": "msal4b1db123-c0de-4a6b-9f4e-2d2f1f5e0c01://auth"}
  ]}]
}`

func TestAuthorizeEnforcesRegisteredRedirectURIs(t *testing.T) {
	h := New(mustConfig(t, redirectAppJSON))

	for _, uri := range []string{"http://localhost:2901/cb", "msal4b1db123-c0de-4a6b-9f4e-2d2f1f5e0c01://auth"} {
		if resp := serve(h, http.MethodGet, appAuthorizeURL("reg", uri), ""); resp.Status != http.StatusOK {
			t.Errorf("GET with registered uri %s: status %d body %s", uri, resp.Status, resp.Body)
		}
	}
	for _, uri := range []string{"https://app.test/cb", "http://localhost:2901/cb/other", "http://localhost:2902/cb"} {
		resp := serve(h, http.MethodGet, appAuthorizeURL("reg", uri), "")
		if resp.Status != http.StatusBadRequest || !strings.Contains(resp.Body, "aadsts50011") {
			t.Errorf("GET with unregistered uri %s: status %d body %s", uri, resp.Status, resp.Body)
		}
	}
	// The gate runs before the picker, so a picker submit is held to it too.
	resp := serve(h, http.MethodPost, appAuthorizeURL("reg", "https://evil.test/cb"), "tid="+tidA+"&username=jane")
	if resp.Status != http.StatusBadRequest || !strings.Contains(resp.Body, "aadsts50011") {
		t.Fatalf("POST with unregistered uri: status %d body %s", resp.Status, resp.Body)
	}
	if code := signInAt(h, "reg", "http://localhost:2901/cb", "jane"); code == "" {
		t.Fatal("sign-in at the registered URI must issue a code")
	}
	// A client with no registration keeps the permissive default.
	if resp := serve(h, http.MethodGet, appAuthorizeURL("stranger", "https://any.test/cb"), ""); resp.Status != http.StatusOK {
		t.Errorf("unregistered client: status %d body %s", resp.Status, resp.Body)
	}
}

// secretAppJSON registers one secret; expires is filled per test.
func secretAppJSON(expires string) string {
	return `{
	  "tenants": [{"tid": "` + tidA + `"}],
	  "users": [{"username": "jane", "tid": "` + tidA + `"}],
	  "apps": [{"clientId": "reg", "tid": "` + tidA + `", "secrets": [
	    {"id": "aaaaaaaa-0000-0000-0000-000000000001", "value": "right-one",
	     "expires": "` + expires + `", "createdOn": "2026-01-02T03:04:05Z"}
	  ]}]
	}`
}

func TestTokenEnforcesRegisteredAppSecrets(t *testing.T) {
	now := time.Unix(1790000000, 0)
	h := New(mustConfig(t, appConfig("")), WithClock(func() time.Time { return now }))

	// An app without secrets stays permissive: no client_secret is sent.
	if code := signInAt(h, "stranger", "http://app.test/cb", "jane"); code == "" {
		t.Fatal("unregistered sign-in failed")
	} else if resp := redeemAt(h, "stranger", "http://app.test/cb", code, ""); resp.Status != http.StatusOK {
		t.Fatalf("unregistered redeem: %d %s", resp.Status, resp.Body)
	}

	h = New(mustConfig(t, secretAppJSON(now.Add(24*time.Hour).UTC().Format(time.RFC3339))),
		WithClock(func() time.Time { return now }))
	for name, secret := range map[string]string{"missing": "", "wrong": "wrong-one"} {
		code := signInAt(h, "reg", "http://app.test/cb", "jane")
		if code == "" {
			t.Fatalf("%s secret: sign-in failed", name)
		}
		resp := redeemAt(h, "reg", "http://app.test/cb", code, secret)
		if resp.Status != http.StatusUnauthorized || !strings.Contains(resp.Body, "invalid_client") ||
			!strings.Contains(resp.Body, "aadsts7000215") {
			t.Errorf("%s secret: %d %s", name, resp.Status, resp.Body)
		}
	}
	if code := signInAt(h, "reg", "http://app.test/cb", "jane"); code == "" {
		t.Fatal("sign-in failed")
	} else if resp := redeemAt(h, "reg", "http://app.test/cb", code, "right-one"); resp.Status != http.StatusOK {
		t.Fatalf("correct secret: %d %s", resp.Status, resp.Body)
	}

	// The Basic-auth password carries the same secret.
	r := httptestNewForm(t, "http://mock.test/entra/"+tidA+"/oauth2/v2.0/token",
		"grant_type=authorization_code&client_id=reg&code="+url.QueryEscape(signInAt(h, "reg", "http://app.test/cb", "jane"))+
			"&redirect_uri="+url.QueryEscape("http://app.test/cb"))
	r.SetBasicAuth("reg", "right-one")
	if resp := h.Handle(mustRequest(t, r)); resp.Status != http.StatusOK {
		t.Fatalf("basic auth with the right password: %d %s", resp.Status, resp.Body)
	}

	// Past the expiry the secret no longer authenticates.
	now = now.Add(25 * time.Hour)
	if code := signInAt(h, "reg", "http://app.test/cb", "jane"); code == "" {
		t.Fatal("sign-in failed after the clock moved")
	} else if resp := redeemAt(h, "reg", "http://app.test/cb", code, "right-one"); resp.Status != http.StatusUnauthorized {
		t.Errorf("expired secret: %d %s", resp.Status, resp.Body)
	}
}

func TestClientCredentialsEnforceAppSecrets(t *testing.T) {
	now := time.Unix(1790000000, 0)
	valid := now.Add(24 * time.Hour).UTC().Format(time.RFC3339)
	h := New(mustConfig(t, `{
	  "graph": {"appOnly": true},
	  "tenants": [{"tid": "`+tidA+`"}],
	  "users": [{"username": "jane", "tid": "`+tidA+`"}],
	  "apps": [{"clientId": "sync", "tid": "`+tidA+`", "roles": ["User.Read.All"], "secrets": [
	    {"id": "aaaaaaaa-0000-0000-0000-000000000001", "value": "right-one", "expires": "`+valid+`"}
	  ]}]
	}`), WithClock(func() time.Time { return now }))

	status, body := clientCreds(t, h, tidA, "grant_type="+defaultScope+"&client_id=sync&client_secret=wrong")
	if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Fatalf("wrong secret: %d %v", status, body)
	}
	if status, body = clientCreds(t, h, tidA, "grant_type="+defaultScope+"&client_id=sync&client_secret=right-one"); status != http.StatusOK {
		t.Fatalf("right secret: %d %v", status, body)
	}

	r := httptestNewForm(t, "http://mock.test/entra/"+tidA+"/oauth2/v2.0/token", "grant_type="+defaultScope)
	r.SetBasicAuth("sync", "right-one")
	if resp := h.Handle(mustRequest(t, r)); resp.Status != http.StatusOK {
		t.Fatalf("basic auth password: %d %s", resp.Status, resp.Body)
	}
}

func TestAppObjAndSnapshotShape(t *testing.T) {
	h := New(mustConfig(t, appConfig(`{"clientId": "reg", "tid": "`+tidA+`", "name": "Portal",
	  "roles": ["User.Read.All"], "claims": [{"name": "emp", "source": "user.employeeid"}],
	  "redirectUris": [{"platform": "spa", "uri": "https://portal.test/cb"}],
	  "secrets": [{"id": "aaaaaaaa-0000-0000-0000-000000000001", "value": "s3cret-value",
	   "expires": "2030-01-01T00:00:00Z", "createdOn": "2026-01-02T03:04:05Z"}],
	  "createdOn": "2026-01-02T03:04:05Z"}`)))

	var snap struct {
		Apps []map[string]any `json:"apps"`
	}
	if err := json.Unmarshal([]byte(jsonx.Render(h.AdminSnapshot())), &snap); err != nil {
		t.Fatal(err)
	}
	if len(snap.Apps) != 1 {
		t.Fatalf("apps = %v", snap.Apps)
	}
	a := snap.Apps[0]
	for _, want := range []string{"clientId", "name", "objectId", "signInAudience", "redirectUris", "roles", "claims", "secrets", "createdOn"} {
		if _, ok := a[want]; !ok {
			t.Errorf("app snapshot entry missing %s: %v", want, a)
		}
	}
	if a["name"] != "Portal" || a["signInAudience"] != AudienceMyOrg || a["createdOn"] != "2026-01-02T03:04:05Z" {
		t.Errorf("app = %v", a)
	}
	uri := a["redirectUris"].([]any)[0].(map[string]any)
	if uri["platform"] != PlatformSPA || uri["uri"] != "https://portal.test/cb" {
		t.Errorf("redirectUris = %v", a["redirectUris"])
	}
	// The deliberate mock divergence: the secret value stays visible.
	sec := a["secrets"].([]any)[0].(map[string]any)
	if sec["value"] != "s3cret-value" || sec["id"] != "aaaaaaaa-0000-0000-0000-000000000001" {
		t.Errorf("secrets = %v", a["secrets"])
	}
}
