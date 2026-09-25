// Package login implements the interactive login page handling
// (LoginRequestHandler.kt): a custom HTML file from config, or the built-in
// template; and the login submit (username + optional claims JSON).
package login

import (
	"embed"
	"fmt"
	"html/template"
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
	query := req.URL.Query()
	params := make([]struct{ Name, Value string }, 0, len(query))
	for name, values := range query {
		v := ""
		if len(values) > 0 {
			v = values[0]
		}
		params = append(params, struct{ Name, Value string }{name, v})
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, params); err != nil {
		return "", oauth2.ServerError(fmt.Sprintf("login template: %v", err))
	}
	return buf.String(), nil
}

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
