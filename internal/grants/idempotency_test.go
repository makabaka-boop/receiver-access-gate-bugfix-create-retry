package grants_test

// Uncertain-completion integration tests. They run against the same
// two-instance cluster as grants_test.go and exercise the cases where a
// request has committed in the database but its HTTP response was lost:
//
//   - keyed SHARED create whose 201 is dropped: a retry on the other API
//     instance must return the one existing grant (no duplicate) and recover
//     the exact owner token, which must keep working after release/upgrade
//     and across a full fleet restart;
//   - keyed EXCLUSIVE create whose 201 is dropped: the retry must return the
//     caller's own grant (replayed) rather than an undifferentiated BUSY,
//     while unrelated callers still only see BUSY;
//   - same-key concurrent retries across both API instances: exactly one
//     record, identical id and token on every response;
//   - key reuse with a different mode: 422 and no new record;
//   - listings never expose request keys or tokens, so a stranger who can
//     only query the receiver cannot recover the holder token and cannot
//     release or upgrade the grant.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"grantgate/internal/grants"
)

// createKeyed posts a (possibly idempotent) create request.
func createKeyed(t *testing.T, base, rx, mode, key string) (grantView, string, bool, int) {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"mode": mode, "request_key": key})
	resp, err := http.Post(base+"/receivers/"+rx+"/grants", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return grantView{}, "", false, resp.StatusCode
	}
	var out struct {
		grantView
		OwnerToken string `json:"owner_token"`
		Replayed   bool   `json:"replayed"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("create decode: %v", err)
	}
	if out.OwnerToken == "" {
		t.Fatal("create response must carry owner_token")
	}
	if bytes.Contains(raw, []byte("request_key")) {
		t.Fatalf("create response must not echo request_key material beyond input: %s", raw)
	}
	return out.grantView, out.OwnerToken, out.Replayed, resp.StatusCode
}

// postCreateDropResponse simulates "committed in the database, response lost
// on the network": it opens a raw TCP connection, sends a create request,
// waits until the new grant row becomes visible through the API (so the
// transaction has certainly committed), then closes the socket without
// reading a single byte of the response. The server still sees the request
// through to commit; the caller never receives the 201 or the token.
func postCreateDropResponse(t *testing.T, base, rx, mode, key string) {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse base url: %v", err)
	}
	payload, _ := json.Marshal(map[string]string{"mode": mode, "request_key": key})

	conn, err := net.DialTimeout("tcp", u.Host, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", u.Host, err)
	}
	defer conn.Close()
	req := fmt.Sprintf(
		"POST /receivers/%s/grants HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		rx, u.Host, len(payload), payload)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Poll a separate connection until the commit is visible, proving the
	// response was lost after, not before, persistence.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if gs := listGrants(t, base, rx); len(gs) >= 1 {
			return // commit confirmed; drop the socket without reading
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("dropped create on %s never became visible", rx)
}

// TestSharedCreateResponseLost is the headline scenario: a SHARED grant is
// committed but its 201 is lost. A naive retry would insert a second active
// grant whose token the caller never saw, permanently blocking exclusive
// admission. The keyed retry must instead return the single original grant
// and recover its token.
func TestSharedCreateResponseLost(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-lost-shared")
	key := "duty-switch-" + rx

	postCreateDropResponse(t, c.api1.URL, rx, grants.ModeShared, key)

	// Exactly one row exists even though the caller never got a response.
	if gs := listGrants(t, c.api2.URL, rx); len(gs) != 1 {
		t.Fatalf("after dropped response: want 1 grant, got %d (%+v)", len(gs), gs)
	}

	// Retry on the *other* API instance: same grant, same token, flagged
	// replay. No second ACTIVE row is created.
	g, token, replayed, code := createKeyed(t, c.api2.URL, rx, grants.ModeShared, key)
	if code != http.StatusOK || !replayed {
		t.Fatalf("retry: want 200 replayed, got %d replayed=%v", code, replayed)
	}
	if gs := listGrants(t, c.api1.URL, rx); len(gs) != 1 || gs[0].ID != g.ID {
		t.Fatalf("retry must not create a duplicate: %+v", listGrants(t, c.api1.URL, rx))
	}
	if g.Mode != grants.ModeShared || g.Status != grants.StatusActive {
		t.Fatalf("replay returned unexpected grant: %+v", g)
	}

	// The recovered token governs the orphaned grant on either instance.
	if g2, token2, replayed2, code2 := createKeyed(t, c.api1.URL, rx, grants.ModeShared, key); code2 != http.StatusOK || !replayed2 || g2.ID != g.ID || token2 != token {
		t.Fatalf("repeated replay unstable: code=%d replayed=%v ids %s/%s tokens-equal=%v",
			code2, replayed2, g2.ID, g.ID, token2 == token)
	}
	if _, code := releaseGrant(t, c.api2.URL, g.ID, "someone-elses-token"); code != http.StatusForbidden {
		t.Fatalf("stranger must not release the recovered grant: %d", code)
	}
	if _, code := releaseGrant(t, c.api1.URL, g.ID, token); code != http.StatusOK {
		t.Fatalf("recovered token must release the grant: %d", code)
	}

	// Replay now reports the current terminal state but keeps the token.
	g3, token3, replayed3, code3 := createKeyed(t, c.api2.URL, rx, grants.ModeShared, key)
	if code3 != http.StatusOK || !replayed3 || g3.Status != grants.StatusReleased || token3 != token {
		t.Fatalf("replay after release: code=%d replayed=%v grant=%+v token-equal=%v",
			code3, replayed3, g3, token3 == token)
	}
	// The released original is still the unique business result: no new row.
	if gs := listGrants(t, c.api1.URL, rx); len(gs) != 1 || gs[0].Status != grants.StatusReleased {
		t.Fatalf("replay must not resurrect or duplicate: %+v", gs)
	}

	// A fresh business request with a fresh key is admitted normally.
	g4, _, _, code4 := createKeyed(t, c.api2.URL, rx, grants.ModeExclusive, "duty-switch-followup-"+rx)
	if code4 != http.StatusCreated || g4.Status != grants.StatusActive {
		t.Fatalf("new key after resolution: code=%d grant=%+v", code4, g4)
	}
	if gs := listGrants(t, c.api1.URL, rx); len(gs) != 2 {
		t.Fatalf("want released + new active, got %+v", gs)
	}
}

// TestExclusiveCreateResponseLost: the EXCLUSIVE grant committed but the
// caller never saw it. A retry must return that caller's own grant instead
// of a BUSY that could equally mean "someone else holds it"; meanwhile an
// unrelated caller must still receive BUSY and cannot piggyback on the key.
func TestExclusiveCreateResponseLost(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-lost-exclusive")
	key := "duty-exclusive-" + rx

	postCreateDropResponse(t, c.api1.URL, rx, grants.ModeExclusive, key)

	// Unrelated request (different business key, different instance) gets
	// the ordinary conflict and cannot read the winner out of it.
	if _, _, _, code := createKeyed(t, c.api2.URL, rx, grants.ModeShared, "other-business-"+rx); code != http.StatusConflict {
		t.Fatalf("stranger SHARED: want 409, got %d", code)
	}
	if _, _, _, code := createKeyed(t, c.api2.URL, rx, grants.ModeExclusive, "other-business-2-"+rx); code != http.StatusConflict {
		t.Fatalf("stranger EXCLUSIVE: want 409, got %d", code)
	}

	// The owner retries and recognizes its own success rather than BUSY.
	g, token, replayed, code := createKeyed(t, c.api2.URL, rx, grants.ModeExclusive, key)
	if code != http.StatusOK || !replayed {
		t.Fatalf("owner retry: want 200 replayed, got %d %v", code, replayed)
	}
	if g.Mode != grants.ModeExclusive || g.Status != grants.StatusActive {
		t.Fatalf("owner replay grant: %+v", g)
	}
	if gs := listGrants(t, c.api1.URL, rx); len(gs) != 1 || gs[0].ID != g.ID {
		t.Fatalf("exactly one exclusive must exist: %+v", listGrants(t, c.api1.URL, rx))
	}

	// Native exclusive grants still refuse upgrade with the stable 409;
	// the recovered token is what governs release.
	if _, code := upgradeGrant(t, c.api1.URL, g.ID, token); code != http.StatusConflict {
		t.Fatalf("native exclusive upgrade: want 409, got %d", code)
	}

	c.restart(t)

	g2, token2, replayed2, code2 := createKeyed(t, c.api1.URL, rx, grants.ModeExclusive, key)
	if code2 != http.StatusOK || !replayed2 || g2.ID != g.ID || token2 != token {
		t.Fatalf("replay after restart diverged: code=%d replayed=%v %+v vs %s token-equal=%v",
			code2, replayed2, g2, g.ID, token2 == token)
	}
	if _, code := releaseGrant(t, c.api2.URL, g.ID, token); code != http.StatusOK {
		t.Fatalf("recovered token releases after restart: %d", code)
	}
	if _, _, _, code := createKeyed(t, c.api2.URL, rx, grants.ModeExclusive, "next-night-"+rx); code != http.StatusCreated {
		t.Fatalf("receiver must admit a new business request after release: %d", code)
	}
}

// TestSameKeyConcurrentRetries fires the same keyed request many times,
// spread across both API instances, as concurrent retries of one business
// operation. Exactly one grant row may exist, and every response must
// report the same grant id and the same owner token.
func TestSameKeyConcurrentRetries(t *testing.T) {
	c := newCluster(t)

	for _, mode := range []string{grants.ModeShared, grants.ModeExclusive} {
		t.Run(mode, func(t *testing.T) {
			rx := receiver(t, "rx-key-race-"+strings.ToLower(mode))
			key := "concurrent-" + rx
			const contenders = 12

			type result struct {
				id     string
				token  string
				status int
			}
			results := make(chan result, contenders)
			var wg sync.WaitGroup
			for i := 0; i < contenders; i++ {
				base := c.api1.URL
				if i%2 == 1 {
					base = c.api2.URL
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					g, tok, _, code := createKeyed(t, base, rx, mode, key)
					results <- result{id: g.ID, token: tok, status: code}
				}()
			}
			wg.Wait()
			close(results)

			created, replays := 0, 0
			var firstID, firstToken string
			for r := range results {
				switch r.status {
				case http.StatusCreated:
					created++
				case http.StatusOK:
					replays++
				default:
					t.Fatalf("unexpected status %d", r.status)
				}
				if r.id == "" {
					t.Fatal("response carried no grant id")
				}
				if firstID == "" {
					firstID, firstToken = r.id, r.token
				} else if r.id != firstID || r.token != firstToken {
					t.Fatalf("divergent business results: %s/%s vs %s/%s", r.id, firstID, r.token, firstToken)
				}
			}
			if created != 1 || replays != contenders-1 {
				t.Fatalf("want 1 create + %d replays, got %d + %d", contenders-1, created, replays)
			}
			if gs := listGrants(t, c.api1.URL, rx); len(gs) != 1 {
				t.Fatalf("concurrent retries left %d rows, want 1: %+v", len(gs), gs)
			}
			// The one token everyone recovered actually controls it.
			if _, code := releaseGrant(t, c.api2.URL, firstID, firstToken); code != http.StatusOK {
				t.Fatalf("recovered token release: %d", code)
			}
		})
	}
}

// TestSameKeyDifferentModeRejected keeps the key a strict request
// identifier: a replay claiming a different mode is rejected with 422 and
// leaves the original result untouched.
func TestSameKeyDifferentModeRejected(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-key-mode")
	key := "mode-switch-" + rx

	g, token, _, code := createKeyed(t, c.api1.URL, rx, grants.ModeShared, key)
	if code != http.StatusCreated {
		t.Fatalf("initial create: %d", code)
	}
	if _, _, _, code := createKeyed(t, c.api2.URL, rx, grants.ModeExclusive, key); code != http.StatusUnprocessableEntity {
		t.Fatalf("same key, other mode: want 422, got %d", code)
	}
	gs := listGrants(t, c.api2.URL, rx)
	if len(gs) != 1 || gs[0].ID != g.ID || gs[0].Mode != grants.ModeShared || gs[0].Status != grants.StatusActive {
		t.Fatalf("422 must leave the original grant untouched: %+v", gs)
	}
	// The honest replay still works and still yields the same token.
	g2, token2, replayed, code := createKeyed(t, c.api1.URL, rx, grants.ModeShared, key)
	if code != http.StatusOK || !replayed || g2.ID != g.ID || token2 != token {
		t.Fatalf("honest replay broken: code=%d replayed=%v token-equal=%v", code, replayed, token2 == token)
	}
}

// TestListingsNeverExposeCapability verifies the anti-hijack guarantee:
// grant listings expose neither owner tokens nor request keys, and knowledge
// of the list alone is insufficient to release or upgrade anything.
func TestListingsNeverExposeCapability(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-secret")
	key := "nightly-window-" + rx

	g, token, _, code := createKeyed(t, c.api1.URL, rx, grants.ModeShared, key)
	if code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	for _, base := range []string{c.api1.URL, c.api2.URL} {
		resp, err := http.Get(base + "/receivers/" + rx + "/grants")
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		for _, secret := range []string{token, key} {
			if bytes.Contains(raw, []byte(secret)) {
				t.Fatalf("listing via %s leaks credential %q: %s", base, secret, raw)
			}
		}
		if bytes.Contains(raw, []byte("request_key")) || bytes.Contains(raw, []byte("token_digest")) {
			t.Fatalf("listing exposes key fields: %s", raw)
		}
	}
	// Knowing only the grant id from the list cannot operate it.
	if _, code := releaseGrant(t, c.api2.URL, g.ID, key); code != http.StatusForbidden {
		t.Fatalf("presenting request_key as owner_token must not work: %d", code)
	}
	if _, code := upgradeGrant(t, c.api1.URL, g.ID, g.ID); code != http.StatusForbidden {
		t.Fatalf("grant id is not a credential: %d", code)
	}
	if gs := listGrants(t, c.api1.URL, rx); len(gs) != 1 || gs[0].Status != grants.StatusActive {
		t.Fatalf("failed takeovers must leave state untouched: %+v", gs)
	}
}

// TestUpgradeContinuesAfterLostResponse combines the recovery path with the
// existing upgrade state machine: a SHARED grant whose create response was
// lost is recovered, driven into UPGRADE_PENDING alongside a competitor, and
// the reconciled view (also after restart) keeps matching reality.
func TestUpgradeContinuesAfterLostResponse(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-lost-upgrade")
	key := "upgrading-owner-" + rx

	postCreateDropResponse(t, c.api1.URL, rx, grants.ModeShared, key)
	// A second, unrelated shared holder coexists (created the normal way
	// with its own key).
	other, otherTok, _, code := createKeyed(t, c.api2.URL, rx, grants.ModeShared, "competitor-"+rx)
	if code != http.StatusCreated {
		t.Fatalf("competitor create: %d", code)
	}

	// Reconcile the lost create on the other instance, then upgrade.
	g, token, replayed, code := createKeyed(t, c.api2.URL, rx, grants.ModeShared, key)
	if code != http.StatusOK || !replayed {
		t.Fatalf("reconcile: code=%d replayed=%v", code, replayed)
	}
	up, code := upgradeGrant(t, c.api1.URL, g.ID, token)
	if code != http.StatusOK || up.Status != grants.StatusUpgradePending {
		t.Fatalf("upgrade recovered grant: code=%d %+v", code, up)
	}
	// The pending barrier is key-aware: retries of the same create still
	// reconcile to the pending grant instead of sneaking a new row in.
	g2, token2, replayed2, code := createKeyed(t, c.api1.URL, rx, grants.ModeShared, key)
	if code != http.StatusOK || !replayed2 || g2.ID != g.ID || g2.Status != grants.StatusUpgradePending || token2 != token {
		t.Fatalf("replay during pending: code=%d replayed=%v %+v", code, replayed2, g2)
	}
	// A new business key is barred by the pending upgrade, leaving no row.
	if _, _, _, code := createKeyed(t, c.api2.URL, rx, grants.ModeShared, "newcomer-"+rx); code != http.StatusConflict {
		t.Fatalf("barrier: want 409, got %d", code)
	}
	if gs := listGrants(t, c.api1.URL, rx); len(gs) != 2 {
		t.Fatalf("barrier leaked a row: %+v", gs)
	}

	c.restart(t)

	// Reconciliation after restart shows the waiting upgrade unchanged.
	g3, _, replayed3, code := createKeyed(t, c.api2.URL, rx, grants.ModeShared, key)
	if code != http.StatusOK || !replayed3 || g3.Status != grants.StatusUpgradePending {
		t.Fatalf("reconcile after restart: code=%d replayed=%v %+v", code, replayed3, g3)
	}
	// Competitor release promotes the recovered owner atomically.
	if _, code := releaseGrant(t, c.api1.URL, other.ID, otherTok); code != http.StatusOK {
		t.Fatalf("release competitor: %d", code)
	}
	g4, _, replayed4, code := createKeyed(t, c.api2.URL, rx, grants.ModeShared, key)
	if code != http.StatusOK || !replayed4 || g4.Mode != grants.ModeExclusive || g4.Status != grants.StatusActive {
		t.Fatalf("reconcile after promotion: code=%d replayed=%v %+v", code, replayed4, g4)
	}
}

// TestKeylessCreateUnchanged pins backward compatibility: requests without
// a request_key keep minting independent random-token grants, and a BUSY
// response still leaves no record.
func TestKeylessCreateUnchanged(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-keyless")

	g1, tok1, code := createGrant(t, c.api1.URL, rx, grants.ModeShared)
	if code != http.StatusCreated {
		t.Fatalf("first: %d", code)
	}
	g2, tok2, code := createGrant(t, c.api2.URL, rx, grants.ModeShared)
	if code != http.StatusCreated || g2.ID == g1.ID || tok2 == tok1 {
		t.Fatalf("keyless creates must stay independent: code=%d", code)
	}
	if _, _, code := createGrant(t, c.api1.URL, rx, grants.ModeExclusive); code != http.StatusConflict {
		t.Fatalf("busy: %d", code)
	}
	if gs := listGrants(t, c.api2.URL, rx); len(gs) != 2 {
		t.Fatalf("busy left a record: %+v", gs)
	}
}
