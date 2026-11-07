package server_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestLoginPageListsParamsInQueryOrder(t *testing.T) {
	ts := newAdminServer(t, `{"interactiveLogin": true}`)
	names := []string{"zeta", "scope", "alpha", "response_type", "mid", "client_id", "redirect_uri", "beta", "state"}
	var q []string
	for _, n := range names {
		v := "v-" + n
		switch n {
		case "response_type":
			v = "code"
		case "redirect_uri":
			v = "http://localhost/cb"
		}
		q = append(q, n+"="+url.QueryEscape(v))
	}
	q = append(q, "zeta=repeat")
	status, _, body := adminDo(t, ts, http.MethodGet, "/default/authorize?"+strings.Join(q, "&"), "")
	if status != http.StatusOK {
		t.Fatalf("status %d: %.200s", status, body)
	}
	var got []string
	for _, line := range strings.Split(body, "\n") {
		if _, rest, ok := strings.Cut(line, `<div class="param"><strong>`); ok {
			name, _, _ := strings.Cut(rest, "</strong>")
			got = append(got, name)
		}
	}
	if strings.Join(got, ",") != strings.Join(names, ",") {
		t.Errorf("params rendered as %v, want query order %v", got, names)
	}
	if strings.Contains(body, "repeat") || !strings.Contains(body, "v-zeta") {
		t.Errorf("repeated param should keep its first value: %.2000s", body)
	}
}
