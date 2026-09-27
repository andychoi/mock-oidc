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
	Origin   string // proxy-aware scheme://host[:port]
	BasePath string
	Tenant   *Tenant // the signing-in user's tenant (also for organizations/common)
	User     *User
	ClientID string
	Nonce    string
	Scopes   []string
	Now      time.Time
	Expiry   int64
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

// IDTokenClaims builds the v2.0 ID token claims (design §4.1–4.2).
func IDTokenClaims(in TokenInput) map[string]any {
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
	if in.Nonce != "" {
		c["nonce"] = in.Nonce
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
	addGroups(c, in.Tenant, in.User)
	return c
}

// AccessTokenClaims builds a Graph-audience access token (RPs must not
// validate it; design §4.3).
func AccessTokenClaims(in TokenInput) map[string]any {
	c := IDTokenClaims(in)
	delete(c, "nonce")
	c["aud"] = graphAppID
	c["scp"] = strings.Join(in.Scopes, " ")
	return c
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
func addGroups(c map[string]any, t *Tenant, u *User) {
	if len(u.Groups) == 0 {
		return
	}
	if len(u.Groups) > t.GroupLimit {
		c["_claim_names"] = map[string]any{"groups": "src1"}
		c["_claim_sources"] = map[string]any{"src1": map[string]any{
			"endpoint": "https://graph.microsoft.com/v1.0/users/" + u.OID + "/getMemberObjects",
		}}
		return
	}
	vals := make([]string, 0, len(u.Groups))
	for _, g := range u.Groups {
		if t.GroupClaimFormat == FormatObjectID {
			vals = append(vals, GroupObjectID(t.TID, g))
		} else {
			vals = append(vals, g)
		}
	}
	c["groups"] = vals
}

func hasScope(scopes []string, s string) bool {
	for _, v := range scopes {
		if v == s {
			return true
		}
	}
	return false
}
