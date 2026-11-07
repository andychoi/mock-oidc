package token_test

import (
	"sync"
	"testing"

	"github.com/andychoi/mock-oidc/internal/token"
)

// Concurrent first requests for one issuer must draw a single pool key, so
// the next issuer still gets the next deterministic key.
func TestConcurrentFirstSigningKeyDrawsOnePoolKey(t *testing.T) {
	seq, err := token.DefaultKeyProvider("ES256")
	if err != nil {
		t.Fatal(err)
	}
	seq.SigningKey("a")
	wantB := seq.SigningKey("b").EC.X

	for round := 0; round < 20; round++ {
		p, err := token.DefaultKeyProvider("ES256")
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		keys := make([]*token.SigningKey, 32)
		var wg sync.WaitGroup
		for i := range keys {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				keys[i] = p.SigningKey("a")
			}()
		}
		close(start)
		wg.Wait()
		for _, k := range keys {
			if k != keys[0] {
				t.Fatalf("round %d: issuer a got different keys", round)
			}
		}
		if got := p.SigningKey("b").EC.X; got.Cmp(wantB) != 0 {
			t.Fatalf("round %d: issuer b did not get the second pool key", round)
		}
	}
}
