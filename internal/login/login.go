// Package login implements the interactive login page handling
// (LoginRequestHandler.kt): a custom HTML file from config, or the built-in
// template; and the login submit (username + optional claims JSON).
package login

import (
	"embed"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"strings"

	"github.com/andychoi/mock-oidc/internal/oauth2"
)

//go:embed templates/login.html.tmpl
var builtinTemplates embed.FS

// Login is the submitted login (username + optional claims JSON string).
type Login struct {
	Username string
	Claims   string
}

// Handler renders the login page and parses login submits.
type Handler struct {
	LoginPagePath string
}

// LoginHTML returns the login page: the configured custom file served as-is,
// or the built-in template.
func (h *Handler) LoginHTML(req *oauth2.Request) (string, *oauth2.Error) {
	if h.LoginPagePath != "" {
		data, err := readFile(h.LoginPagePath)
		if err != nil {
			return "", oauth2.NotFound("The configured loginPagePath '" + h.LoginPagePath + "' is invalid, please ensure that it points to a valid html file")
		}
		return data, nil
	}
	return h.builtinLoginHTML(req)
}

// LoginSubmit extracts the submitted username and claims; the form posts back
// to the same URL so the auth parameters stay in the query string.
func (h *Handler) LoginSubmit(req *oauth2.Request) (Login, *oauth2.Error) {
	username := req.FormParam("username")
	if username == "" {
		return Login{}, oauth2.MissingParameter("username")
	}
	return Login{Username: username, Claims: req.FormParam("claims")}, nil
}

func (h *Handler) builtinLoginHTML(req *oauth2.Request) (string, *oauth2.Error) {
	tmpl, err := template.ParseFS(builtinTemplates, "templates/login.html.tmpl")
	if err != nil {
		return "", oauth2.ServerError(fmt.Sprintf("login template: %v", err))
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, queryParams(req.URL.RawQuery)); err != nil {
		return "", oauth2.ServerError(fmt.Sprintf("login template: %v", err))
	}
	return buf.String(), nil
}

type param struct{ Name, Value string }

// queryParams lists the query parameters in request order with the first value
// of each name, parsed like url.ParseQuery. url.Values is a map, so ranging
// over it would shuffle the page on every request.
func queryParams(rawQuery string) []param {
	var params []param
	seen := map[string]bool{}
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" || strings.Contains(pair, ";") {
			continue
		}
		rawName, rawValue, _ := strings.Cut(pair, "=")
		name, err := url.QueryUnescape(rawName)
		if err != nil || seen[name] {
			continue
		}
		value, err := url.QueryUnescape(rawValue)
		if err != nil {
			continue
		}
		seen[name] = true
		params = append(params, param{name, value})
	}
	return params
}

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
