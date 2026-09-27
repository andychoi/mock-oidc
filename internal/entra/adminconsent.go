package entra

import (
	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
)

func (h *Handler) adminConsentGet(req *oauth2.Request, sc scope) routing.Response {
	if oerr := requireConsentParams(req); oerr != nil {
		return routing.ErrorResponse(oerr)
	}
	return renderPicker(pickerPage{
		Heading:    "Permissions requested by " + req.QueryParam("client_id") + ": sign in as a tenant administrator to accept",
		Action:     req.URL.RequestURI(),
		Submit:     "accept",
		ShowCancel: true,
		Tenants:    h.pickerTenants(sc),
	})
}

func (h *Handler) adminConsentPost(req *oauth2.Request, sc scope) routing.Response {
	if oerr := requireConsentParams(req); oerr != nil {
		return routing.ErrorResponse(oerr)
	}
	redirectURI, state := req.QueryParam("redirect_uri"), req.QueryParam("state")
	if req.FormParam("action") == "cancel" {
		return errorRedirect(redirectURI, state, "access_denied", "AADSTS65004: User declined to consent to access the app.")
	}
	t, u, oerr := h.postedUser(req, sc)
	if oerr != nil {
		return routing.ErrorResponse(oerr)
	}
	if !u.Admin {
		return errorRedirect(redirectURI, state, "access_denied",
			"AADSTS90094: Admin consent is required for the permissions requested by this application. An administrator of the tenant must grant consent.")
	}
	h.consents.Grant(req.QueryParam("client_id"), t.TID)
	return redirectWith(redirectURI, map[string]string{
		"admin_consent": "True",
		"tenant":        t.TID,
		"state":         state,
		"scope":         req.QueryParam("scope"),
	})
}

func requireConsentParams(req *oauth2.Request) *oauth2.Error {
	for _, p := range []string{"client_id", "redirect_uri"} {
		if req.QueryParam(p) == "" {
			return oauth2.MissingParameter(p)
		}
	}
	return nil
}
