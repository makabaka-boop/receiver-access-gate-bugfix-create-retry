package grants_test

// Integration tests run two real API instances (separate http.Servers with
// separate connection pools) against one PostgreSQL database, mirroring the
// multi-process deployment. Set TEST_DATABASE_URL to run them; they are
// skipped otherwise.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"grantgate/internal/grants"

	"github.com/jackc/pgx/v5"
)

type cluster struct {
	store *grants.Store
	api1  *httptest.Server
	api2  *httptest.Server
}

func newCluster(t *testing.T) *cluster {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	open := func() *grants.Store {
		s, err := grants.NewStore(context.Background(), dsn)
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		return s
	}
	c := &cluster{store: open()}
	c.api1 = httptest.NewServer(grants.NewServer(open()))
	c.api2 = httptest.NewServer(grants.NewServer(open()))
	t.Cleanup(func() {
		c.api1.Close()
		c.api2.Close()
		c.store.Close()
	})
	return c
}

// restart simulates a full fleet restart: both API processes are torn down
// and brand-new instances come up against the same database.
func (c *cluster) restart(t *testing.T) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	c.api1.Close()
	c.api2.Close()
	open := func() *grants.Store {
		s, err := grants.NewStore(context.Background(), dsn)
		if err != nil {
			t.Fatalf("reopen store: %v", err)
		}
		return s
	}
	s1, s2 := open(), open()
	c.api1 = httptest.NewServer(grants.NewServer(s1))
	c.api2 = httptest.NewServer(grants.NewServer(s2))
	t.Cleanup(func() {
		c.api1.Close()
		c.api2.Close()
		s1.Close()
		s2.Close()
	})
}

func receiver(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}

// requestKey returns a fresh idempotency key identifying one business
// request across all of its retries.
func requestKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "req-" + hex.EncodeToString(b)
}

type grantView struct {
	ID       string `json:"grant_id"`
	Receiver string `json:"receiver"`
	Mode     string `json:"mode"`
	Status   string `json:"status"`
}

func createGrant(t *testing.T, base, rx, mode string) (grantView, string, int) {
	t.Helper()
	return createGrantKeyed(t, base, rx, mode, "")
}

// createGrantKeyed posts a create request; a non-empty key is sent as
// the Idempotency-Key header identifying the business request.
func createGrantKeyed(t *testing.T, base, rx, mode, key string) (grantView, string, int) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"mode": mode})
	req, err := http.NewRequest(http.MethodPost, base+"/receivers/"+rx+"/grants", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return grantView{}, "", resp.StatusCode
	}
	var out struct {
		grantView
		OwnerToken string `json:"owner_token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("create decode: %v", err)
	}
	if out.OwnerToken == "" {
		t.Fatal("create response must carry owner_token")
	}
	return out.grantView, out.OwnerToken, resp.StatusCode
}

func listGrants(t *testing.T, base, rx string) []grantView {
	t.Helper()
	resp, err := http.Get(base + "/receivers/" + rx + "/grants")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: status %d", resp.StatusCode)
	}
	if bytes.Contains(raw, []byte("token")) {
		t.Fatalf("list response leaks token material: %s", raw)
	}
	var out struct {
		Grants []grantView `json:"grants"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("list decode: %v", err)
	}
	return out.Grants
}

func releaseGrant(t *testing.T, base, id, token string) (grantView, int) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"owner_token": token})
	resp, err := http.Post(base+"/grants/"+id+"/release", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if bytes.Contains(raw, []byte("owner_token")) {
		t.Fatalf("release response leaks token material: %s", raw)
	}
	var g grantView
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(raw, &g); err != nil {
			t.Fatalf("release decode: %v", err)
		}
	}
	return g, resp.StatusCode
}

func upgradeGrant(t *testing.T, base, id, token string) (grantView, int) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"owner_token": token})
	resp, err := http.Post(base+"/grants/"+id+"/upgrade", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if bytes.Contains(raw, []byte("owner_token")) {
		t.Fatalf("upgrade response leaks token material: %s", raw)
	}
	var g grantView
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(raw, &g); err != nil {
			t.Fatalf("upgrade decode: %v", err)
		}
	}
	return g, resp.StatusCode
}

func findGrant(t *testing.T, gs []grantView, id string) grantView {
	t.Helper()
	for _, g := range gs {
		if g.ID == id {
			return g
		}
	}
	t.Fatalf("grant %s missing from %+v", id, gs)
	return grantView{}
}

func TestConcurrentExclusiveRace(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-race")

	const contenders = 16
	codes := make(chan int, contenders)
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		base := c.api1.URL
		if i%2 == 1 {
			base = c.api2.URL
		}
		wg.Add(1)
		go func(b string) {
			defer wg.Done()
			body, _ := json.Marshal(map[string]string{"mode": grants.ModeExclusive})
			resp, err := http.Post(b+"/receivers/"+rx+"/grants", "application/json", bytes.NewReader(body))
			if err != nil {
				codes <- -1
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
			codes <- resp.StatusCode
		}(base)
	}
	wg.Wait()
	close(codes)

	created, busy := 0, 0
	for code := range codes {
		switch code {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			busy++
		default:
			t.Fatalf("unexpected status %d", code)
		}
	}
	if created != 1 || busy != contenders-1 {
		t.Fatalf("want exactly 1 created and %d busy, got %d and %d", contenders-1, created, busy)
	}

	// The surviving grant is visible identically through both instances.
	for _, base := range []string{c.api1.URL, c.api2.URL} {
		gs := listGrants(t, base, rx)
		if len(gs) != 1 || gs[0].Mode != grants.ModeExclusive || gs[0].Status != grants.StatusActive {
			t.Fatalf("via %s: want one ACTIVE EXCLUSIVE grant, got %+v", base, gs)
		}
	}
}

// TestSameKeyRetryReplaysOutcome covers the lost-response case: the
// create committed but its answer never reached the caller. Retrying
// with the same request key — even against the other API process —
// replays the original grant id and owner token instead of minting a
// second grant.
func TestSameKeyRetryReplaysOutcome(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-key")
	key := requestKey(t)

	g1, tok1, code := createGrantKeyed(t, c.api1.URL, rx, grants.ModeShared, key)
	if code != http.StatusCreated {
		t.Fatalf("keyed create: status %d", code)
	}

	// The response is lost; the caller retries with the same key and
	// recovers grant id and token.
	g2, tok2, code := createGrantKeyed(t, c.api2.URL, rx, grants.ModeShared, key)
	if code != http.StatusCreated || g2.ID != g1.ID || tok2 != tok1 {
		t.Fatalf("keyed retry: code=%d grant=%+v (want replay of %s)", code, g2, g1.ID)
	}
	if gs := listGrants(t, c.api1.URL, rx); len(gs) != 1 {
		t.Fatalf("keyed retry must not add a record: %+v", gs)
	}

	// A keyless retry is a different business request and still
	// conflicts with the recovered grant.
	if _, _, code := createGrant(t, c.api1.URL, rx, grants.ModeExclusive); code != http.StatusConflict {
		t.Fatalf("keyless exclusive during recovered grant: want 409, got %d", code)
	}

	// The recovered token releases the recovered grant.
	if g, code := releaseGrant(t, c.api2.URL, g1.ID, tok2); code != http.StatusOK || g.Status != grants.StatusReleased {
		t.Fatalf("release with recovered token: code=%d grant=%+v", code, g)
	}

	// A later replay reflects the grant's current state and still
	// returns the original token.
	g3, tok3, code := createGrantKeyed(t, c.api1.URL, rx, grants.ModeShared, key)
	if code != http.StatusCreated || g3.ID != g1.ID || g3.Status != grants.StatusReleased || tok3 != tok1 {
		t.Fatalf("replay after release: code=%d grant=%+v", code, g3)
	}
}

// TestExclusiveSameKeyRetryBeatsBusy covers the exclusive variant of the
// lost response: without the key the retry would report BUSY against the
// caller's own grant; with the key it replays the caller's own outcome.
func TestExclusiveSameKeyRetryBeatsBusy(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-xkey")
	key := requestKey(t)

	g1, tok1, code := createGrantKeyed(t, c.api1.URL, rx, grants.ModeExclusive, key)
	if code != http.StatusCreated {
		t.Fatalf("keyed exclusive create: status %d", code)
	}
	g2, tok2, code := createGrantKeyed(t, c.api2.URL, rx, grants.ModeExclusive, key)
	if code != http.StatusCreated || g2.ID != g1.ID || tok2 != tok1 {
		t.Fatalf("keyed exclusive retry: code=%d grant=%+v (want replay of %s)", code, g2, g1.ID)
	}
	if gs := listGrants(t, c.api1.URL, rx); len(gs) != 1 {
		t.Fatalf("keyed retry must not add a record: %+v", gs)
	}
	// Someone else's keyless exclusive request still sees BUSY.
	if _, _, code := createGrant(t, c.api2.URL, rx, grants.ModeExclusive); code != http.StatusConflict {
		t.Fatalf("keyless exclusive: want 409, got %d", code)
	}
	if _, code := releaseGrant(t, c.api1.URL, g1.ID, tok2); code != http.StatusOK {
		t.Fatalf("release with recovered token: code=%d", code)
	}
}

// TestConcurrentSameKeyCreate fires the same business request at both
// API processes at once: exactly one grant may be created and every
// retry must observe the same id and token.
func TestConcurrentSameKeyCreate(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-keyrace")
	key := requestKey(t)

	const retries = 12
	type outcome struct {
		id, tok string
		code    int
	}
	outs := make([]outcome, retries)
	var wg sync.WaitGroup
	for i := 0; i < retries; i++ {
		base := c.api1.URL
		if i%2 == 1 {
			base = c.api2.URL
		}
		wg.Add(1)
		go func(b string, slot int) {
			defer wg.Done()
			body, _ := json.Marshal(map[string]string{"mode": grants.ModeShared})
			req, err := http.NewRequest(http.MethodPost, b+"/receivers/"+rx+"/grants", bytes.NewReader(body))
			if err != nil {
				outs[slot] = outcome{code: -1}
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Idempotency-Key", key)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				outs[slot] = outcome{code: -1}
				return
			}
			defer resp.Body.Close()
			raw, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusCreated {
				outs[slot] = outcome{code: resp.StatusCode}
				return
			}
			var out struct {
				grantView
				OwnerToken string `json:"owner_token"`
			}
			if err := json.Unmarshal(raw, &out); err != nil {
				outs[slot] = outcome{code: -1}
				return
			}
			outs[slot] = outcome{out.ID, out.OwnerToken, resp.StatusCode}
		}(base, i)
	}
	wg.Wait()

	for i, o := range outs {
		if o.code != http.StatusCreated || o.id == "" || o.id != outs[0].id || o.tok != outs[0].tok {
			t.Fatalf("retry %d: %+v, want all identical to %+v", i, o, outs[0])
		}
	}
	gs := listGrants(t, c.api1.URL, rx)
	if len(gs) != 1 || gs[0].ID != outs[0].id {
		t.Fatalf("same-key race must leave exactly one grant: %+v", gs)
	}
	if _, code := releaseGrant(t, c.api2.URL, gs[0].ID, outs[0].tok); code != http.StatusOK {
		t.Fatalf("release with raced token: code=%d", code)
	}
}

// TestRequestKeyMismatch rejects a key reused with different parameters
// and leaves no record on either receiver.
func TestRequestKeyMismatch(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-keymix")
	key := requestKey(t)

	if _, _, code := createGrantKeyed(t, c.api1.URL, rx, grants.ModeShared, key); code != http.StatusCreated {
		t.Fatalf("keyed create: status %d", code)
	}
	if _, _, code := createGrantKeyed(t, c.api2.URL, rx, grants.ModeExclusive, key); code != http.StatusConflict {
		t.Fatalf("mode mismatch: want 409, got %d", code)
	}
	other := receiver(t, "rx-keymix-other")
	if _, _, code := createGrantKeyed(t, c.api1.URL, other, grants.ModeShared, key); code != http.StatusConflict {
		t.Fatalf("receiver mismatch: want 409, got %d", code)
	}
	if gs := listGrants(t, c.api1.URL, rx); len(gs) != 1 {
		t.Fatalf("mismatched reuse added a record: %+v", gs)
	}
	if gs := listGrants(t, c.api2.URL, other); len(gs) != 0 {
		t.Fatalf("mismatched reuse on another receiver left records: %+v", gs)
	}
}

// TestBusyOutcomeIsNotRemembered ensures a failed (BUSY) attempt records
// nothing under its key: once the blocker clears, the same key is
// decided afresh and its outcome becomes replayable.
func TestBusyOutcomeIsNotRemembered(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-keybusy")
	key := requestKey(t)

	g, tok, _ := createGrant(t, c.api1.URL, rx, grants.ModeShared)
	if _, _, code := createGrantKeyed(t, c.api2.URL, rx, grants.ModeExclusive, key); code != http.StatusConflict {
		t.Fatalf("exclusive during shared: want 409, got %d", code)
	}
	if _, code := releaseGrant(t, c.api1.URL, g.ID, tok); code != http.StatusOK {
		t.Fatalf("release blocker: code=%d", code)
	}
	x, xtok, code := createGrantKeyed(t, c.api2.URL, rx, grants.ModeExclusive, key)
	if code != http.StatusCreated {
		t.Fatalf("retry after blocker left: want 201, got %d", code)
	}
	x2, xtok2, code := createGrantKeyed(t, c.api1.URL, rx, grants.ModeExclusive, key)
	if code != http.StatusCreated || x2.ID != x.ID || xtok2 != xtok {
		t.Fatalf("replay of retried create: code=%d grant=%+v", code, x2)
	}
}

// TestRequestKeySurvivesRestart restarts the whole fleet between the
// lost response and the retry: the recorded outcome, and the lifecycle
// it unlocks, must be identical afterwards.
func TestRequestKeySurvivesRestart(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-keyrestart")
	key := requestKey(t)

	g1, tok1, code := createGrantKeyed(t, c.api1.URL, rx, grants.ModeShared, key)
	if code != http.StatusCreated {
		t.Fatalf("keyed create: status %d", code)
	}

	c.restart(t)

	// The recorded outcome survives the restart: same grant, same token.
	g2, tok2, code := createGrantKeyed(t, c.api2.URL, rx, grants.ModeShared, key)
	if code != http.StatusCreated || g2.ID != g1.ID || tok2 != tok1 {
		t.Fatalf("replay after restart: code=%d grant=%+v (want replay of %s)", code, g2, g1.ID)
	}
	if gs := listGrants(t, c.api1.URL, rx); len(gs) != 1 {
		t.Fatalf("restart replay must not add a record: %+v", gs)
	}

	// The recovered token still drives the lifecycle: the sole grant
	// upgrades straight to ACTIVE EXCLUSIVE and then releases.
	up, code := upgradeGrant(t, c.api1.URL, g1.ID, tok2)
	if code != http.StatusOK || up.Mode != grants.ModeExclusive || up.Status != grants.StatusActive {
		t.Fatalf("upgrade with recovered token after restart: code=%d grant=%+v", code, up)
	}
	if _, code := releaseGrant(t, c.api2.URL, g1.ID, tok2); code != http.StatusOK {
		t.Fatalf("release after restart: code=%d", code)
	}
}

func TestSharedCoexistence(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-shared")

	g1, tok1, code := createGrant(t, c.api1.URL, rx, grants.ModeShared)
	if code != http.StatusCreated {
		t.Fatalf("first SHARED: status %d", code)
	}
	g2, tok2, code := createGrant(t, c.api2.URL, rx, grants.ModeShared)
	if code != http.StatusCreated {
		t.Fatalf("second SHARED must coexist: status %d", code)
	}
	if g1.ID == g2.ID {
		t.Fatal("shared grants must have distinct ids")
	}

	if _, _, code := createGrant(t, c.api1.URL, rx, grants.ModeExclusive); code != http.StatusConflict {
		t.Fatalf("EXCLUSIVE during active SHARED: want 409, got %d", code)
	}
	if gs := listGrants(t, c.api2.URL, rx); len(gs) != 2 {
		t.Fatalf("conflict must leave no record, got %d grants", len(gs))
	}

	// Release across instances: a token minted by api1 works on api2.
	if g, code := releaseGrant(t, c.api2.URL, g1.ID, tok1); code != http.StatusOK || g.Status != grants.StatusReleased {
		t.Fatalf("release g1: code=%d status=%s", code, g.Status)
	}
	if _, _, code := createGrant(t, c.api1.URL, rx, grants.ModeExclusive); code != http.StatusConflict {
		t.Fatalf("EXCLUSIVE while g2 still active: want 409, got %d", code)
	}
	if _, code := releaseGrant(t, c.api1.URL, g2.ID, tok2); code != http.StatusOK {
		t.Fatalf("release g2: code=%d", code)
	}
	if _, _, code := createGrant(t, c.api2.URL, rx, grants.ModeExclusive); code != http.StatusCreated {
		t.Fatalf("EXCLUSIVE after all released: want 201, got %d", code)
	}

	gs := listGrants(t, c.api1.URL, rx)
	if len(gs) != 3 || gs[0].Status != grants.StatusReleased || gs[1].Status != grants.StatusReleased || gs[2].Status != grants.StatusActive {
		t.Fatalf("unexpected final state: %+v", gs)
	}
}

func TestForbiddenReleaseLeavesStateUntouched(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-forbidden")

	g, token, code := createGrant(t, c.api1.URL, rx, grants.ModeExclusive)
	if code != http.StatusCreated {
		t.Fatalf("create: status %d", code)
	}

	if _, code := releaseGrant(t, c.api2.URL, g.ID, "definitely-wrong-token"); code != http.StatusForbidden {
		t.Fatalf("wrong token: want 403, got %d", code)
	}
	gs := listGrants(t, c.api1.URL, rx)
	if len(gs) != 1 || gs[0].Status != grants.StatusActive {
		t.Fatalf("forbidden release must not change state: %+v", gs)
	}
	// The grant must still gate the receiver.
	if _, _, code := createGrant(t, c.api2.URL, rx, grants.ModeShared); code != http.StatusConflict {
		t.Fatalf("active set changed by forbidden release: want 409, got %d", code)
	}

	if _, code := releaseGrant(t, c.api1.URL, g.ID, token); code != http.StatusOK {
		t.Fatalf("correct token: want 200, got %d", code)
	}
	if gs := listGrants(t, c.api2.URL, rx); len(gs) != 1 || gs[0].Status != grants.StatusReleased {
		t.Fatalf("after release: %+v", gs)
	}
}

func TestStateAndTokensSurviveRestart(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-restart")

	g, token, code := createGrant(t, c.api1.URL, rx, grants.ModeExclusive)
	if code != http.StatusCreated {
		t.Fatalf("create: status %d", code)
	}

	c.restart(t)

	gs := listGrants(t, c.api2.URL, rx)
	if len(gs) != 1 || gs[0].ID != g.ID || gs[0].Status != grants.StatusActive {
		t.Fatalf("state lost across restart: %+v", gs)
	}
	if _, code := releaseGrant(t, c.api2.URL, g.ID, "wrong-token"); code != http.StatusForbidden {
		t.Fatalf("wrong token after restart: want 403, got %d", code)
	}
	if _, code := releaseGrant(t, c.api1.URL, g.ID, token); code != http.StatusOK {
		t.Fatalf("original token after restart: want 200, got %d", code)
	}
	if gs := listGrants(t, c.api1.URL, rx); gs[0].Status != grants.StatusReleased {
		t.Fatalf("release not persisted: %+v", gs)
	}
}

func TestUpgradeWaitsBlocksAndAutoPromotes(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-upgrade")

	g1, tok1, _ := createGrant(t, c.api1.URL, rx, grants.ModeShared)
	g2, tok2, _ := createGrant(t, c.api2.URL, rx, grants.ModeShared)
	g3, tok3, _ := createGrant(t, c.api1.URL, rx, grants.ModeShared)

	// Wrong token: stable 403, grant set untouched.
	if _, code := upgradeGrant(t, c.api2.URL, g2.ID, "forged-token"); code != http.StatusForbidden {
		t.Fatalf("upgrade with wrong token: want 403, got %d", code)
	}
	for _, g := range listGrants(t, c.api1.URL, rx) {
		if g.Status != grants.StatusActive {
			t.Fatalf("forbidden upgrade mutated state: %+v", g)
		}
	}

	// Correct token: ACTIVE SHARED -> UPGRADE_PENDING in place.
	up, code := upgradeGrant(t, c.api1.URL, g2.ID, tok2)
	if code != http.StatusOK || up.Status != grants.StatusUpgradePending || up.Mode != grants.ModeShared {
		t.Fatalf("upgrade: code=%d grant=%+v", code, up)
	}
	if up.ID != g2.ID {
		t.Fatalf("upgrade must keep the record, got new id %s", up.ID)
	}

	// Idempotent retry while waiting.
	again, code := upgradeGrant(t, c.api2.URL, g2.ID, tok2)
	if code != http.StatusOK || again.Status != grants.StatusUpgradePending {
		t.Fatalf("idempotent retry: code=%d grant=%+v", code, again)
	}

	// A second upgrade on the same receiver is refused and changes nothing.
	if _, code := upgradeGrant(t, c.api1.URL, g3.ID, tok3); code != http.StatusConflict {
		t.Fatalf("second upgrade: want 409, got %d", code)
	}

	// The pending upgrade bars new shared and exclusive admissions.
	if _, _, code := createGrant(t, c.api1.URL, rx, grants.ModeShared); code != http.StatusConflict {
		t.Fatalf("SHARED during pending upgrade: want 409, got %d", code)
	}
	if _, _, code := createGrant(t, c.api2.URL, rx, grants.ModeExclusive); code != http.StatusConflict {
		t.Fatalf("EXCLUSIVE during pending upgrade: want 409, got %d", code)
	}
	if gs := listGrants(t, c.api2.URL, rx); len(gs) != 3 {
		t.Fatalf("barrier must leave no record, got %d grants", len(gs))
	}

	// Releasing one competitor is not enough: no intermediate state.
	if _, code := releaseGrant(t, c.api2.URL, g1.ID, tok1); code != http.StatusOK {
		t.Fatalf("release g1: code=%d", code)
	}
	if g := findGrant(t, listGrants(t, c.api1.URL, rx), g2.ID); g.Status != grants.StatusUpgradePending {
		t.Fatalf("promoted too early: %+v", g)
	}

	// The last competitor's release promotes the pending grant atomically.
	if _, code := releaseGrant(t, c.api1.URL, g3.ID, tok3); code != http.StatusOK {
		t.Fatalf("release g3: code=%d", code)
	}
	for _, base := range []string{c.api1.URL, c.api2.URL} {
		g := findGrant(t, listGrants(t, base, rx), g2.ID)
		if g.Mode != grants.ModeExclusive || g.Status != grants.StatusActive {
			t.Fatalf("via %s: want ACTIVE EXCLUSIVE, got %+v", base, g)
		}
	}

	// Idempotent retry after promotion; the original token still governs.
	promoted, code := upgradeGrant(t, c.api2.URL, g2.ID, tok2)
	if code != http.StatusOK || promoted.Mode != grants.ModeExclusive || promoted.Status != grants.StatusActive {
		t.Fatalf("retry after promotion: code=%d grant=%+v", code, promoted)
	}

	// The promoted grant gates the receiver like any exclusive grant.
	if _, _, code := createGrant(t, c.api1.URL, rx, grants.ModeShared); code != http.StatusConflict {
		t.Fatalf("SHARED against promoted exclusive: want 409, got %d", code)
	}
	if _, code := releaseGrant(t, c.api1.URL, g2.ID, tok2); code != http.StatusOK {
		t.Fatalf("release promoted grant: code=%d", code)
	}
	if _, _, code := createGrant(t, c.api2.URL, rx, grants.ModeExclusive); code != http.StatusCreated {
		t.Fatalf("EXCLUSIVE after promoted grant released: want 201, got %d", code)
	}
}

func TestUpgradeImmediatePromotion(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-upgrade-solo")

	g, token, code := createGrant(t, c.api1.URL, rx, grants.ModeShared)
	if code != http.StatusCreated {
		t.Fatalf("create: status %d", code)
	}

	// Sole grant on the receiver: straight to ACTIVE EXCLUSIVE.
	up, code := upgradeGrant(t, c.api2.URL, g.ID, token)
	if code != http.StatusOK || up.Mode != grants.ModeExclusive || up.Status != grants.StatusActive {
		t.Fatalf("immediate upgrade: code=%d grant=%+v", code, up)
	}
	if up.ID != g.ID {
		t.Fatalf("upgrade must reuse the record, got %s", up.ID)
	}
	// Idempotent retry.
	if again, code := upgradeGrant(t, c.api1.URL, g.ID, token); code != http.StatusOK || again.Mode != grants.ModeExclusive {
		t.Fatalf("retry: code=%d grant=%+v", code, again)
	}
	if gs := listGrants(t, c.api1.URL, rx); len(gs) != 1 || gs[0].Mode != grants.ModeExclusive {
		t.Fatalf("list after upgrade: %+v", gs)
	}
	if _, _, code := createGrant(t, c.api2.URL, rx, grants.ModeShared); code != http.StatusConflict {
		t.Fatalf("SHARED against upgraded exclusive: want 409, got %d", code)
	}
}

func TestUpgradeBarrierCancellation(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-upgrade-cancel")

	g1, tok1, _ := createGrant(t, c.api1.URL, rx, grants.ModeShared)
	createGrant(t, c.api2.URL, rx, grants.ModeShared)

	if up, code := upgradeGrant(t, c.api1.URL, g1.ID, tok1); code != http.StatusOK || up.Status != grants.StatusUpgradePending {
		t.Fatalf("upgrade: code=%d grant=%+v", code, up)
	}
	if _, _, code := createGrant(t, c.api2.URL, rx, grants.ModeShared); code != http.StatusConflict {
		t.Fatalf("SHARED during pending upgrade: want 409, got %d", code)
	}

	// Releasing the pending grant itself cancels the upgrade and lifts
	// the barrier: normal admission resumes immediately.
	if g, code := releaseGrant(t, c.api2.URL, g1.ID, tok1); code != http.StatusOK || g.Status != grants.StatusReleased {
		t.Fatalf("release pending grant: code=%d", code)
	}
	if _, _, code := createGrant(t, c.api1.URL, rx, grants.ModeShared); code != http.StatusCreated {
		t.Fatalf("SHARED after cancellation: want 201, got %d", code)
	}
	gs := listGrants(t, c.api2.URL, rx)
	if len(gs) != 3 || gs[0].Status != grants.StatusReleased || gs[1].Status != grants.StatusActive || gs[2].Status != grants.StatusActive {
		t.Fatalf("unexpected state after cancellation: %+v", gs)
	}
}

func TestConcurrentUpgradeRace(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-upgrade-race")

	const contenders = 8
	ids := make([]string, contenders)
	tokens := make([]string, contenders)
	for i := 0; i < contenders; i++ {
		base := c.api1.URL
		if i%2 == 1 {
			base = c.api2.URL
		}
		g, tok, code := createGrant(t, base, rx, grants.ModeShared)
		if code != http.StatusCreated {
			t.Fatalf("create shared %d: status %d", i, code)
		}
		ids[i], tokens[i] = g.ID, tok
	}

	// Every shared owner upgrades at once, split across both API
	// processes: exactly one may win the pending slot.
	codes := make(chan int, contenders)
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		base := c.api1.URL
		if i%2 == 0 {
			base = c.api2.URL
		}
		wg.Add(1)
		go func(b, id, tok string) {
			defer wg.Done()
			body, _ := json.Marshal(map[string]string{"owner_token": tok})
			resp, err := http.Post(b+"/grants/"+id+"/upgrade", "application/json", bytes.NewReader(body))
			if err != nil {
				codes <- -1
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
			codes <- resp.StatusCode
		}(base, ids[i], tokens[i])
	}
	wg.Wait()
	close(codes)

	won, lost := 0, 0
	for code := range codes {
		switch code {
		case http.StatusOK:
			won++
		case http.StatusConflict:
			lost++
		default:
			t.Fatalf("unexpected upgrade status %d", code)
		}
	}
	if won != 1 || lost != contenders-1 {
		t.Fatalf("race: want 1 winner / %d losers, got %d / %d", contenders-1, won, lost)
	}

	// Exactly one UPGRADE_PENDING grant is visible through both APIs.
	var winner string
	for _, base := range []string{c.api1.URL, c.api2.URL} {
		gs := listGrants(t, base, rx)
		pending := 0
		for _, g := range gs {
			if g.Status == grants.StatusUpgradePending {
				pending++
				winner = g.ID
			}
		}
		if len(gs) != contenders || pending != 1 {
			t.Fatalf("via %s: want %d grants with 1 pending, got %+v", base, contenders, gs)
		}
	}

	// Releasing the losers one by one promotes the winner only when the
	// last competitor leaves.
	released := 0
	for i, id := range ids {
		if id == winner {
			continue
		}
		if _, code := releaseGrant(t, c.api1.URL, id, tokens[i]); code != http.StatusOK {
			t.Fatalf("release loser: code=%d", code)
		}
		released++
		g := findGrant(t, listGrants(t, c.api2.URL, rx), winner)
		if released < contenders-1 && g.Status != grants.StatusUpgradePending {
			t.Fatalf("promoted with %d competitors left: %+v", contenders-1-released, g)
		}
	}
	g := findGrant(t, listGrants(t, c.api1.URL, rx), winner)
	if g.Mode != grants.ModeExclusive || g.Status != grants.StatusActive {
		t.Fatalf("winner after last release: %+v", g)
	}
}

func TestUpgradeErrorCases(t *testing.T) {
	c := newCluster(t)

	// Unknown grant id.
	if _, code := upgradeGrant(t, c.api1.URL, "00000000000000000000000000000000", "tok"); code != http.StatusNotFound {
		t.Fatalf("unknown id: want 404, got %d", code)
	}

	// A natively exclusive grant cannot upgrade.
	rxX := receiver(t, "rx-upgrade-native")
	x, xtok, _ := createGrant(t, c.api1.URL, rxX, grants.ModeExclusive)
	if _, code := upgradeGrant(t, c.api2.URL, x.ID, xtok); code != http.StatusConflict {
		t.Fatalf("native exclusive upgrade: want 409, got %d", code)
	}
	if gs := listGrants(t, c.api1.URL, rxX); len(gs) != 1 || gs[0].Mode != grants.ModeExclusive || gs[0].Status != grants.StatusActive {
		t.Fatalf("native exclusive upgrade changed state: %+v", gs)
	}

	// A released grant cannot upgrade.
	rxR := receiver(t, "rx-upgrade-released")
	r, rtok, _ := createGrant(t, c.api2.URL, rxR, grants.ModeShared)
	if _, code := releaseGrant(t, c.api1.URL, r.ID, rtok); code != http.StatusOK {
		t.Fatalf("release: code=%d", code)
	}
	if _, code := upgradeGrant(t, c.api1.URL, r.ID, rtok); code != http.StatusConflict {
		t.Fatalf("released grant upgrade: want 409, got %d", code)
	}
	if gs := listGrants(t, c.api2.URL, rxR); len(gs) != 1 || gs[0].Status != grants.StatusReleased {
		t.Fatalf("released grant upgrade changed state: %+v", gs)
	}
	// The receiver admits new grants normally afterwards.
	if _, _, code := createGrant(t, c.api1.URL, rxR, grants.ModeExclusive); code != http.StatusCreated {
		t.Fatalf("EXCLUSIVE after released upgrade attempt: want 201, got %d", code)
	}
}

func TestUpgradePendingSurvivesRestart(t *testing.T) {
	c := newCluster(t)
	rx := receiver(t, "rx-upgrade-restart")

	g1, tok1, _ := createGrant(t, c.api1.URL, rx, grants.ModeShared)
	g2, tok2, _ := createGrant(t, c.api2.URL, rx, grants.ModeShared)
	if up, code := upgradeGrant(t, c.api1.URL, g1.ID, tok1); code != http.StatusOK || up.Status != grants.StatusUpgradePending {
		t.Fatalf("upgrade: code=%d grant=%+v", code, up)
	}

	c.restart(t)

	// The pending state and the barrier survive a full fleet restart.
	gs := listGrants(t, c.api2.URL, rx)
	if g := findGrant(t, gs, g1.ID); g.Status != grants.StatusUpgradePending {
		t.Fatalf("pending state lost across restart: %+v", g)
	}
	if _, _, code := createGrant(t, c.api1.URL, rx, grants.ModeShared); code != http.StatusConflict {
		t.Fatalf("barrier lost across restart: want 409, got %d", code)
	}
	if _, code := upgradeGrant(t, c.api2.URL, g1.ID, "wrong-token"); code != http.StatusForbidden {
		t.Fatalf("wrong token after restart: want 403, got %d", code)
	}

	// The original tokens still work: releasing the competitor promotes
	// the waiting grant.
	if _, code := releaseGrant(t, c.api1.URL, g2.ID, tok2); code != http.StatusOK {
		t.Fatalf("release competitor after restart: code=%d", code)
	}
	if g := findGrant(t, listGrants(t, c.api2.URL, rx), g1.ID); g.Mode != grants.ModeExclusive || g.Status != grants.StatusActive {
		t.Fatalf("promotion after restart: %+v", g)
	}
}

// TestMigrationFromPreUpgradeSchema loads a database in the pre-upgrade
// schema (two-status CHECK, no upgraded_from_shared column) with a legacy
// row, then lets the store migrate it. Legacy records and their tokens
// must keep working, and legacy shared grants must be upgradable.
func TestMigrationFromPreUpgradeSchema(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)

	legacyToken := "legacy-owner-token"
	digest := sha256.Sum256([]byte(legacyToken))
	if _, err := conn.Exec(ctx, `DROP TABLE IF EXISTS grants`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if _, err := conn.Exec(ctx, `
CREATE TABLE grants (
    seq          BIGSERIAL PRIMARY KEY,
    id           TEXT        NOT NULL UNIQUE,
    receiver     TEXT        NOT NULL,
    mode         TEXT        NOT NULL CHECK (mode IN ('SHARED', 'EXCLUSIVE')),
    status       TEXT        NOT NULL CHECK (status IN ('ACTIVE', 'RELEASED')),
    token_digest BYTEA       NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_at  TIMESTAMPTZ
)`); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	rx := receiver(t, "rx-legacy")
	if _, err := conn.Exec(ctx, `
INSERT INTO grants (id, receiver, mode, status, token_digest)
VALUES ('legacy-grant-id', $1, 'SHARED', 'ACTIVE', $2)`, rx, digest[:]); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}
	conn.Close(ctx)

	// NewStore migrates the legacy schema in place.
	c := newCluster(t)
	gs := listGrants(t, c.api1.URL, rx)
	if len(gs) != 1 || gs[0].ID != "legacy-grant-id" || gs[0].Status != grants.StatusActive {
		t.Fatalf("legacy row after migration: %+v", gs)
	}

	// The legacy token upgrades the legacy grant; with no competitors it
	// is promoted immediately.
	up, code := upgradeGrant(t, c.api2.URL, "legacy-grant-id", legacyToken)
	if code != http.StatusOK || up.Mode != grants.ModeExclusive || up.Status != grants.StatusActive {
		t.Fatalf("upgrade legacy grant: code=%d grant=%+v", code, up)
	}
	// And the same legacy token releases it.
	if g, code := releaseGrant(t, c.api1.URL, "legacy-grant-id", legacyToken); code != http.StatusOK || g.Status != grants.StatusReleased {
		t.Fatalf("release legacy grant: code=%d grant=%+v", code, g)
	}

	// Keyed creates replay on the migrated database too.
	key := requestKey(t)
	kg1, ktok1, code := createGrantKeyed(t, c.api1.URL, rx, grants.ModeShared, key)
	if code != http.StatusCreated {
		t.Fatalf("keyed create on migrated db: status %d", code)
	}
	kg2, ktok2, code := createGrantKeyed(t, c.api2.URL, rx, grants.ModeShared, key)
	if code != http.StatusCreated || kg2.ID != kg1.ID || ktok2 != ktok1 {
		t.Fatalf("keyed replay on migrated db: code=%d grant=%+v", code, kg2)
	}
}
