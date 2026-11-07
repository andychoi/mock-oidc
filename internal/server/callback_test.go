package server_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// Run under -race: concurrent token requests share one regex request mapping.
func TestRegexRequestMappingUnderConcurrentTokenRequests(t *testing.T) {
	ts := newAdminServer(t, `{
	  "interactiveLogin": false,
	  "tokenCallbacks": [{
	    "issuerId": "default",
	    "requestMappings": [
	      {"requestParam": "username", "match": "admin-.*", "claims": {"sub": "${username}", "role": "admin"}}
	    ]
	  }]
	}`)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, ts.URL+"/default/token",
				strings.NewReader("grant_type=password&username=admin-bob&password=p&scope=openid"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth("c", "s")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			var body struct {
				AccessToken string `json:"access_token"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || resp.StatusCode != 200 {
				t.Errorf("status %d, decode err %v", resp.StatusCode, err)
				return
			}
			parts := strings.Split(body.AccessToken, ".")
			if len(parts) != 3 {
				t.Errorf("not a JWT: %q", body.AccessToken)
				return
			}
			payload, err := base64Decode(parts[1])
			if err != nil || !strings.Contains(payload, `"role":"admin"`) {
				t.Errorf("regex mapping did not apply: %s %v", payload, err)
			}
		}()
	}
	wg.Wait()
}
