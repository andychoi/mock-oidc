package entra

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"

	"github.com/andychoi/mock-oidc/internal/token"
)

// graphAppID is Microsoft Graph's application ID, the audience of the access
// token Entra returns when only OIDC scopes are requested.
const graphAppID = "00000003-0000-0000-c000-000000000000"

// TokenInput carries everything needed to build one sign-in's tokens.
type TokenInput struct {
	// GraphBase and OverageSelfHosted decide where a group-overage claim
	// sends the relying party. They are passed in rather than read from a
	// config so the claim builders stay pure functions of their input.
	GraphBase         string
	OverageSelfHosted bool

	Origin   string // proxy-aware scheme://host[:port]
	BasePath string
	Tenant   *Tenant // the signing-in user's tenant (also for organizations/common)
	User     *User
	ClientID string
	Nonce    string
	Scopes   []string
	Now      time.Time
	Expiry   int64

	// MappedClaims are the app's claims-mapping additions for this user
	// (Config.MappedClaims); they go into the ID token only.
	MappedClaims map[string]string
}

// Issuer is the v2.0 issuer of a tenant: {origin}/{basePath}/{tid}/v2.0.
func Issuer(origin, basePath, tid string) string {
	return origin + "/" + basePath + "/" + tid + "/v2.0"
}

// PairwiseSub is the per-application subject: base64url(SHA-256(clientID:oid)),
// 43 characters, like Entra's pairwise sub.
func PairwiseSub(clientID, oid string) string {
	sum := sha256.Sum256([]byte(clientID + ":" + oid))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// IDTokenClaims builds the v2.0 ID token claims (design §4.1–4.2), including
// the app's mapped claims.
func IDTokenClaims(in TokenInput) map[string]any {
	c := baseClaims(in)
	if in.Nonce != "" {
		c["nonce"] = in.Nonce
	}
	for name, v := range in.MappedClaims {
		c[name] = v
	}
	return c
}

// baseClaims are the claims the ID token and the access token share.
func baseClaims(in TokenInput) map[string]any {
	now := in.Now.Unix()
	c := map[string]any{
		"iss":                Issuer(in.Origin, in.BasePath, in.Tenant.TID),
		"aud":                in.ClientID,
		"iat":                now,
		"nbf":                now,
		"exp":                in.Now.Add(time.Duration(in.Expiry) * time.Second).Unix(),
		"tid":                in.Tenant.TID,
		"oid":                in.User.OID,
		"sub":                PairwiseSub(in.ClientID, in.User.OID),
		"ver":                "2.0",
		"name":               in.User.Name,
		"preferred_username": preferredUsername(in.Tenant, in.User),
		"uti":                token.RandomAuthorizationCode()[:22],
	}
	if in.User.Email != "" && hasScope(in.Scopes, "email") {
		c["email"] = in.User.Email
	}
	if in.User.EmailVerified != nil {
		c["xms_edov"] = *in.User.EmailVerified
	}
	if len(in.User.AMR) > 0 {
		c["amr"] = in.User.AMR
	}
	if in.User.GivenName != "" {
		c["given_name"] = in.User.GivenName
	}
	if in.User.Surname != "" {
		c["family_name"] = in.User.Surname
	}
	if len(in.User.Roles) > 0 {
		c["roles"] = in.User.Roles
	}
	if len(in.User.WIDs) > 0 {
		c["wids"] = in.User.WIDs
	}
	addGroups(c, in)
	return c
}

// AccessTokenClaims builds a Graph-audience access token (RPs must not
// validate it; design §4.3).
func AccessTokenClaims(in TokenInput) map[string]any {
	c := baseClaims(in)
	c["aud"] = graphAppID
	c["scp"] = ScopeValue(in.Scopes)
	// Entra names the client on the access token twice: azp for the
	// authorized party, appid for the application.
	c["azp"] = in.ClientID
	c["appid"] = in.ClientID
	return c
}

// ScopeValue is the access token's scp: the granted scope names with any
// resource prefix stripped (https://graph.microsoft.com/User.Read becomes
// User.Read, as Entra emits), minus the grant-only scopes, which are not API
// permissions. The token response's own "scope" field keeps everything.
func ScopeValue(scopes []string) string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if grantOnlyScopes[s] {
			continue
		}
		if name := StripScopePrefix(s); name != "" {
			out = append(out, name)
		}
	}
	return strings.Join(out, " ")
}

// grantOnlyScopes never appear in scp: they govern the grant, not an API.
var grantOnlyScopes = map[string]bool{"offline_access": true}

// StripScopePrefix removes a resource prefix from a scope identifier:
// api://<guid>/access_as_user and https://graph.microsoft.com/User.Read become
// access_as_user and User.Read; a bare scope such as openid is unchanged.
func StripScopePrefix(scope string) string {
	scheme := strings.Index(scope, "://")
	if scheme == -1 {
		return scope
	}
	if slash := strings.LastIndex(scope, "/"); slash > scheme+2 {
		return scope[slash+1:]
	}
	return scope
}

func preferredUsername(t *Tenant, u *User) string {
	if u.Email != "" {
		return u.Email
	}
	if len(t.Domains) > 0 {
		return u.Username + "@" + t.Domains[0]
	}
	return u.Username
}

// addGroups emits groups (names or object IDs), or the overage markers when
// the user has more groups than the tenant limit.
func addGroups(c map[string]any, in TokenInput) {
	t, groups := in.Tenant, in.User.MemberGroups()
	if len(groups) == 0 {
		return
	}
	if len(groups) > t.GroupLimit {
		c["_claim_names"] = map[string]any{"groups": "src1"}
		c["_claim_sources"] = map[string]any{"src1": map[string]any{
			"endpoint": overageEndpoint(in),
		}}
		return
	}
	vals := make([]string, 0, len(groups))
	for _, g := range groups {
		if t.GroupClaimFormat == FormatObjectID {
			vals = append(vals, GroupObjectID(t.TID, g))
		} else {
			vals = append(vals, g)
		}
	}
	c["groups"] = vals
}

// overageEndpoint is where a relying party resolves a group-overage claim.
// With the emulated Graph serving getMemberObjects it points at us, so the
// claim is actually followable in a test environment; otherwise it names the
// real Graph, which is what Entra emits.
func overageEndpoint(in TokenInput) string {
	if !in.OverageSelfHosted || in.Origin == "" || in.BasePath == "" || in.GraphBase == "" {
		return "https://graph.microsoft.com/v1.0/users/" + in.User.OID + "/getMemberObjects"
	}
	return in.Origin + "/" + in.BasePath + "/" + in.GraphBase + "/v1.0/users/" + in.User.OID + "/getMemberObjects"
}

// MappedClaims returns the claims-mapping additions for clientID's tokens
// about u: every mapped attribute that has a value. An app pinned to a tenant
// maps only that tenant's users.
func (c *Config) MappedClaims(clientID string, u *User) map[string]string {
	t := c.Tenant(u.TID)
	var out map[string]string
	for i := range c.Apps {
		a := &c.Apps[i]
		if a.ClientID != clientID || (a.TID != "" && a.TID != u.TID) {
			continue
		}
		for _, m := range a.Claims {
			if v := claimSources[strings.ToLower(m.Source)](t, u); v != "" {
				if out == nil {
					out = map[string]string{}
				}
				out[m.Name] = v
			}
		}
	}
	return out
}

func hasScope(scopes []string, s string) bool {
	for _, v := range scopes {
		if v == s {
			return true
		}
	}
	return false
}
