// Command verify runs the acceptance sequence against two live API
// processes (API1_URL, API2_URL) and exits non-zero on any failure.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var client = &http.Client{Timeout: 10 * time.Second}

type grant struct {
	ID       string `json:"grant_id"`
	Receiver string `json:"receiver"`
	Mode     string `json:"mode"`
	Status   string `json:"status"`
}

func main() {
	api1 := strings.TrimRight(os.Getenv("API1_URL"), "/")
	api2 := strings.TrimRight(os.Getenv("API2_URL"), "/")
	if api1 == "" || api2 == "" {
		log.Fatal("API1_URL and API2_URL are required")
	}
	waitReady(api1)
	waitReady(api2)

	step("shared grants coexist across API processes")
	rx := "rx-verify-" + suffix()
	g1, tok1 := mustCreate(api1, rx, "SHARED", http.StatusCreated)
	g2, tok2 := mustCreate(api2, rx, "SHARED", http.StatusCreated)
	if g1.ID == g2.ID {
		fail("distinct shared grants must have distinct ids")
	}

	step("exclusive request conflicts with active shared grants -> 409 BUSY")
	mustCreate(api1, rx, "EXCLUSIVE", http.StatusConflict)
	grants := mustList(api2, rx)
	if len(grants) != 2 {
		fail("conflicting request must leave no record, got %d grants", len(grants))
	}

	step("release with wrong token -> 403 FORBIDDEN, record untouched")
	mustRelease(api2, g1.ID, "forged-token", http.StatusForbidden)
	if got := findGrant(mustList(api1, rx), g1.ID); got.Status != "ACTIVE" {
		fail("forbidden release mutated grant: status=%s", got.Status)
	}

	step("release with correct token -> RELEASED")
	released := mustRelease(api1, g1.ID, tok1, http.StatusOK)
	if released.Status != "RELEASED" {
		fail("expected RELEASED, got %s", released.Status)
	}

	step("exclusive still blocked while one shared grant remains active")
	mustCreate(api2, rx, "EXCLUSIVE", http.StatusConflict)

	step("exclusive succeeds once all grants are released")
	mustRelease(api1, g2.ID, tok2, http.StatusOK)
	mustCreate(api2, rx, "EXCLUSIVE", http.StatusCreated)

	step("concurrent exclusive race across both APIs yields exactly one winner")
	rx2 := "rx-verify-race-" + suffix()
	const contenders = 12
	var wg sync.WaitGroup
	results := make(chan int, contenders)
	for i := 0; i < contenders; i++ {
		base := api1
		if i%2 == 1 {
			base = api2
		}
		wg.Add(1)
		go func(b string) {
			defer wg.Done()
			_, code, _ := create(b, rx2, "EXCLUSIVE")
			results <- code
		}(base)
	}
	wg.Wait()
	close(results)
	created, busy := 0, 0
	for code := range results {
		switch code {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			busy++
		default:
			fail("unexpected race status %d", code)
		}
	}
	if created != 1 || busy != contenders-1 {
		fail("race: want 1 created / %d busy, got %d / %d", contenders-1, created, busy)
	}
	if n := len(mustList(api1, rx2)); n != 1 {
		fail("race left %d grants, want exactly 1", n)
	}

	step("shared grant upgrades in place: pending, idempotent retry, barrier")
	rx3 := "rx-verify-upg-" + suffix()
	s1, st1 := mustCreate(api1, rx3, "SHARED", http.StatusCreated)
	s2, st2 := mustCreate(api2, rx3, "SHARED", http.StatusCreated)
	s3, st3 := mustCreate(api1, rx3, "SHARED", http.StatusCreated)

	step("upgrade with wrong token -> 403 FORBIDDEN, grant set unchanged")
	mustUpgrade(api2, s1.ID, "forged-token", http.StatusForbidden)
	for _, g := range mustList(api1, rx3) {
		if g.Status != "ACTIVE" {
			fail("forbidden upgrade mutated grant: %+v", g)
		}
	}

	step("first upgrade wins the pending slot; retry is idempotent")
	up := mustUpgrade(api1, s1.ID, st1, http.StatusOK)
	if up.ID != s1.ID || up.Status != "UPGRADE_PENDING" || up.Mode != "SHARED" {
		fail("upgrade: want same record UPGRADE_PENDING SHARED, got %+v", up)
	}
	if again := mustUpgrade(api2, s1.ID, st1, http.StatusOK); again.Status != "UPGRADE_PENDING" {
		fail("idempotent retry: want UPGRADE_PENDING, got %+v", again)
	}

	step("second upgrade on the same receiver -> 409, no change")
	mustUpgrade(api2, s2.ID, st2, http.StatusConflict)

	step("pending upgrade bars new shared and exclusive admissions")
	mustCreate(api1, rx3, "SHARED", http.StatusConflict)
	mustCreate(api2, rx3, "EXCLUSIVE", http.StatusConflict)
	if n := len(mustList(api1, rx3)); n != 3 {
		fail("barrier must leave no record, got %d grants", n)
	}

	step("last competitor's release promotes the pending grant atomically")
	mustRelease(api1, s2.ID, st2, http.StatusOK)
	if got := findGrant(mustList(api2, rx3), s1.ID); got.Status != "UPGRADE_PENDING" {
		fail("promoted too early: %+v", got)
	}
	mustRelease(api2, s3.ID, st3, http.StatusOK)
	promoted := findGrant(mustList(api1, rx3), s1.ID)
	if promoted.Mode != "EXCLUSIVE" || promoted.Status != "ACTIVE" {
		fail("want promoted ACTIVE EXCLUSIVE, got %+v", promoted)
	}
	if got := findGrant(mustList(api2, rx3), s1.ID); got != promoted {
		fail("promotion not consistent across APIs: %+v vs %+v", got, promoted)
	}

	step("upgrade retry after promotion is idempotent; original token still governs")
	if again := mustUpgrade(api1, s1.ID, st1, http.StatusOK); again.Mode != "EXCLUSIVE" || again.Status != "ACTIVE" {
		fail("retry after promotion: %+v", again)
	}
	mustCreate(api2, rx3, "SHARED", http.StatusConflict)

	step("concurrent upgrade race across both APIs yields exactly one winner")
	rx4 := "rx-verify-upgrace-" + suffix()
	const upgraders = 8
	upIDs := make([]string, upgraders)
	upTokens := make([]string, upgraders)
	for i := 0; i < upgraders; i++ {
		base := api1
		if i%2 == 1 {
			base = api2
		}
		g, tok := mustCreate(base, rx4, "SHARED", http.StatusCreated)
		upIDs[i], upTokens[i] = g.ID, tok
	}
	upResults := make(chan int, upgraders)
	for i := 0; i < upgraders; i++ {
		base := api1
		if i%2 == 0 {
			base = api2
		}
		wg.Add(1)
		go func(b, id, tok string) {
			defer wg.Done()
			_, code, _ := upgrade(b, id, tok)
			upResults <- code
		}(base, upIDs[i], upTokens[i])
	}
	wg.Wait()
	close(upResults)
	won, lost := 0, 0
	for code := range upResults {
		switch code {
		case http.StatusOK:
			won++
		case http.StatusConflict:
			lost++
		default:
			fail("unexpected upgrade race status %d", code)
		}
	}
	if won != 1 || lost != upgraders-1 {
		fail("upgrade race: want 1 winner / %d losers, got %d / %d", upgraders-1, won, lost)
	}
	winner := ""
	for _, g := range mustList(api1, rx4) {
		if g.Status == "UPGRADE_PENDING" {
			if winner != "" {
				fail("multiple pending upgrades survived the race")
			}
			winner = g.ID
		}
	}
	if winner == "" {
		fail("upgrade race left no pending winner")
	}
	for i, id := range upIDs {
		if id != winner {
			mustRelease(api1, id, upTokens[i], http.StatusOK)
		}
	}
	if got := findGrant(mustList(api2, rx4), winner); got.Mode != "EXCLUSIVE" || got.Status != "ACTIVE" {
		fail("race winner not promoted after releases: %+v", got)
	}

	step("releasing the pending grant cancels the upgrade and lifts the barrier")
	rx5 := "rx-verify-upgcancel-" + suffix()
	c1, ct1 := mustCreate(api1, rx5, "SHARED", http.StatusCreated)
	mustCreate(api2, rx5, "SHARED", http.StatusCreated)
	if g := mustUpgrade(api1, c1.ID, ct1, http.StatusOK); g.Status != "UPGRADE_PENDING" {
		fail("want UPGRADE_PENDING, got %+v", g)
	}
	mustCreate(api2, rx5, "SHARED", http.StatusConflict)
	mustRelease(api1, c1.ID, ct1, http.StatusOK)
	mustCreate(api2, rx5, "SHARED", http.StatusCreated)

	step("upgrade rejects native exclusive, released and unknown grants")
	rx6 := "rx-verify-upgerr-" + suffix()
	x1, xt1 := mustCreate(api1, rx6, "EXCLUSIVE", http.StatusCreated)
	mustUpgrade(api2, x1.ID, xt1, http.StatusConflict)
	rx7 := "rx-verify-upgrel-" + suffix()
	r1, rt1 := mustCreate(api1, rx7, "SHARED", http.StatusCreated)
	mustRelease(api1, r1.ID, rt1, http.StatusOK)
	mustUpgrade(api2, r1.ID, rt1, http.StatusConflict)
	mustUpgrade(api1, "00000000000000000000000000000000", "tok", http.StatusNotFound)

	step("query responses never leak tokens")
	body := mustListRaw(api1, rx)
	if strings.Contains(body, "token") || strings.Contains(body, tok1) {
		fail("list response leaks token material: %s", body)
	}

	step("uncertain completion: SHARED create commits but its response is lost")
	rx8 := "rx-verify-lost-" + suffix()
	key8 := "duty-switch-" + rx8
	postCreateDropResponse(api1, rx8, "SHARED", key8)
	if n := len(mustList(api2, rx8)); n != 1 {
		fail("lost-response create persisted, want 1 row, got %d", n)
	}
	// Retrying the same business request on the other API instance must
	// reconcile to the single existing grant and recover its token.
	r8 := mustCreateKeyed(api2, rx8, "SHARED", key8, http.StatusOK)
	if !r8.replayed || r8.grant.Status != "ACTIVE" {
		fail("retry of lost create must be a replay, got %+v replayed=%v", r8.grant, r8.replayed)
	}
	if n := len(mustList(api1, rx8)); n != 1 {
		fail("retry inserted a duplicate grant, got %d rows", n)
	}
	// A different caller/key is blocked from exclusive and cannot claim
	// the recovered grant. An unrelated SHARED request is admitted (shared
	// coexistence) but stays a separate grant the original key cannot
	// touch; release it with its own token so later row counts stay exact.
	mustCreateKeyed(api1, rx8, "EXCLUSIVE", "other-business-"+rx8, http.StatusConflict)
	intruder := mustCreateKeyed(api2, rx8, "SHARED", "other-business-2-"+rx8, http.StatusCreated)
	if intruder.grant.ID == r8.grant.ID {
		fail("stranger key resolved to the original grant")
	}
	mustRelease(api2, intruder.grant.ID, r8.token, http.StatusForbidden)
	mustRelease(api1, intruder.grant.ID, intruder.token, http.StatusOK)
	// Key with a different mode is a request-definition conflict.
	mustCreateKeyed(api1, rx8, "EXCLUSIVE", key8, http.StatusUnprocessableEntity)
	if g := findGrant(mustList(api2, rx8), r8.grant.ID); g.Status != "ACTIVE" || g.Mode != "SHARED" {
		fail("conflicting replays must leave the one active row untouched: %+v", g)
	}
	// The recovered token releases the orphaned grant; reconciled view
	// then reports RELEASED without ever creating a second row.
	mustRelease(api1, r8.grant.ID, r8.token, http.StatusOK)
	r8b := mustCreateKeyed(api2, rx8, "SHARED", key8, http.StatusOK)
	if !r8b.replayed || r8b.grant.Status != "RELEASED" || r8b.token != r8.token {
		fail("reconciliation after release diverged: %+v", r8b)
	}
	if g := findGrant(mustList(api1, rx8), r8.grant.ID); g.Status != "RELEASED" {
		fail("replay after release must keep the one original row: %+v", g)
	}
	// Exclusive admission can finally proceed via a fresh business key.
	mustCreateKeyed(api2, rx8, "EXCLUSIVE", "next-night-"+rx8, http.StatusCreated)

	step("uncertain completion: EXCLUSIVE create commits but its response is lost")
	rx9 := "rx-verify-lostx-" + suffix()
	key9 := "duty-exclusive-" + rx9
	postCreateDropResponse(api2, rx9, "EXCLUSIVE", key9)
	// An outsider only sees BUSY and cannot distinguish/take the winner.
	mustCreateKeyed(api1, rx9, "EXCLUSIVE", "intruder-"+rx9, http.StatusConflict)
	mustCreateKeyed(api2, rx9, "SHARED", "intruder2-"+rx9, http.StatusConflict)
	// The owner retries on the other instance and recognizes its own win.
	r9 := mustCreateKeyed(api1, rx9, "EXCLUSIVE", key9, http.StatusOK)
	if !r9.replayed || r9.grant.Mode != "EXCLUSIVE" || r9.grant.Status != "ACTIVE" {
		fail("owner retry must replay the exclusive grant, got %+v", r9.grant)
	}
	if n := len(mustList(api2, rx9)); n != 1 {
		fail("exclusive retry must not duplicate, got %d rows", n)
	}
	mustRelease(api2, r9.grant.ID, r9.token, http.StatusOK)

	step("uncertain completion: same-key concurrent resend across both APIs")
	rx10 := "rx-verify-keyrace-" + suffix()
	key10 := "concurrent-" + rx10
	const resends = 12
	var wg2 sync.WaitGroup
	type resendResult struct {
		id, token string
		code      int
	}
	rr := make(chan resendResult, resends)
	for i := 0; i < resends; i++ {
		base := api1
		if i%2 == 1 {
			base = api2
		}
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			r, code := createKeyed(base, rx10, "SHARED", key10)
			rr <- resendResult{id: r.ID, token: r.token, code: code}
		}()
	}
	wg2.Wait()
	close(rr)
	creates, replays := 0, 0
	var soleID, soleToken string
	for r := range rr {
		switch r.code {
		case http.StatusCreated:
			creates++
		case http.StatusOK:
			replays++
		default:
			fail("concurrent resend: unexpected status %d", r.code)
		}
		if soleID == "" {
			soleID, soleToken = r.id, r.token
		} else if r.id != soleID || r.token != soleToken {
			fail("concurrent resends produced divergent business results")
		}
	}
	if creates != 1 || replays != resends-1 {
		fail("resend race: want 1 create / %d replays, got %d / %d", resends-1, creates, replays)
	}
	if n := len(mustList(api1, rx10)); n != 1 {
		fail("concurrent resends left %d rows, want exactly 1", n)
	}
	// The unique recovered token operates the grant; upgrade proceeds and
	// reconciles from either instance.
	mustUpgrade(api2, soleID, soleToken, http.StatusOK)
	r10 := mustCreateKeyed(api1, rx10, "SHARED", key10, http.StatusOK)
	if !r10.replayed || r10.grant.ID != soleID || r10.grant.Mode != "EXCLUSIVE" || r10.token != soleToken {
		fail("reconciliation after upgrade diverged: %+v", r10)
	}
	mustRelease(api1, soleID, soleToken, http.StatusOK)

	step("uncertain completion: reconciled SHARED grant still upgrades behind a barrier")
	rx11 := "rx-verify-lostupg-" + suffix()
	key11 := "recover-then-upgrade-" + rx11
	postCreateDropResponse(api1, rx11, "SHARED", key11)
	other11 := mustCreateKeyed(api2, rx11, "SHARED", "competitor-"+rx11, http.StatusCreated)
	r11 := mustCreateKeyed(api2, rx11, "SHARED", key11, http.StatusOK)
	up11 := mustUpgrade(api1, r11.grant.ID, r11.token, http.StatusOK)
	if up11.Status != "UPGRADE_PENDING" {
		fail("recovered grant upgrade: want UPGRADE_PENDING, got %+v", up11)
	}
	mustCreateKeyed(api2, rx11, "SHARED", "newcomer-"+rx11, http.StatusConflict)
	// Reconcile mid-wait: same row, same token, pending status.
	r11b := mustCreateKeyed(api1, rx11, "SHARED", key11, http.StatusOK)
	if !r11b.replayed || r11b.grant.Status != "UPGRADE_PENDING" || r11b.token != r11.token {
		fail("reconcile mid-upgrade diverged: %+v", r11b)
	}
	mustRelease(api2, other11.grant.ID, other11.token, http.StatusOK)
	r11c := mustCreateKeyed(api2, rx11, "SHARED", key11, http.StatusOK)
	if r11c.grant.Mode != "EXCLUSIVE" || r11c.grant.Status != "ACTIVE" {
		fail("reconcile after competitor release: want ACTIVE EXCLUSIVE, got %+v", r11c)
	}

	step("uncertain completion: listings never expose request keys or tokens")
	for _, target := range []struct{ rx, key, token string }{
		{rx8, key8, r8.token}, {rx9, key9, r9.token}, {rx10, key10, soleToken},
	} {
		raw := mustListRaw(api1, target.rx) + mustListRaw(api2, target.rx)
		if strings.Contains(raw, target.key) || strings.Contains(raw, target.token) || strings.Contains(raw, "request_key") {
			fail("listing leaks idempotency capability for %s: %s", target.rx, raw)
		}
	}

	fmt.Println("VERIFY OK")
}

func step(format string, args ...any) { log.Printf("STEP: "+format, args...) }

func fail(format string, args ...any) { log.Fatalf("FAIL: "+format, args...) }

func suffix() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func waitReady(base string) {
	deadline := time.Now().Add(90 * time.Second)
	for {
		resp, err := client.Get(base + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(deadline) {
			fail("api at %s not ready", base)
		}
		time.Sleep(time.Second)
	}
}

func create(base, receiver, mode string) (grant, int, string) {
	payload, _ := json.Marshal(map[string]string{"mode": mode})
	resp, err := client.Post(base+"/receivers/"+receiver+"/grants", "application/json", bytes.NewReader(payload))
	if err != nil {
		fail("create: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return grant{}, resp.StatusCode, ""
	}
	var out struct {
		grant
		OwnerToken string `json:"owner_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		fail("create: decode: %v", err)
	}
	if out.OwnerToken == "" {
		fail("create response must carry owner_token exactly once")
	}
	return out.grant, resp.StatusCode, out.OwnerToken
}

func mustCreate(base, receiver, mode string, want int) (grant, string) {
	g, code, token := create(base, receiver, mode)
	if code != want {
		fail("create %s on %s: want %d, got %d", mode, receiver, want, code)
	}
	return g, token
}

func mustList(base, receiver string) []grant {
	body := mustListRaw(base, receiver)
	var out struct {
		Grants []grant `json:"grants"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		fail("list: decode: %v", err)
	}
	return out.Grants
}

func mustListRaw(base, receiver string) string {
	resp, err := client.Get(base + "/receivers/" + receiver + "/grants")
	if err != nil {
		fail("list: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fail("list: want 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func findGrant(grants []grant, id string) grant {
	for _, g := range grants {
		if g.ID == id {
			return g
		}
	}
	fail("grant %s missing from list", id)
	return grant{}
}

func mustRelease(base, id, token string, want int) grant {
	payload, _ := json.Marshal(map[string]string{"owner_token": token})
	resp, err := client.Post(base+"/grants/"+id+"/release", "application/json", bytes.NewReader(payload))
	if err != nil {
		fail("release: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		fail("release %s: want %d, got %d (%s)", id, want, resp.StatusCode, body)
	}
	if strings.Contains(string(body), "owner_token") {
		fail("release response leaks owner_token")
	}
	if want != http.StatusOK {
		return grant{}
	}
	var g grant
	if err := json.Unmarshal(body, &g); err != nil {
		fail("release: decode: %v", err)
	}
	return g
}

func upgrade(base, id, token string) (grant, int, string) {
	payload, _ := json.Marshal(map[string]string{"owner_token": token})
	resp, err := client.Post(base+"/grants/"+id+"/upgrade", "application/json", bytes.NewReader(payload))
	if err != nil {
		fail("upgrade: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "owner_token") {
		fail("upgrade response leaks owner_token")
	}
	if resp.StatusCode != http.StatusOK {
		return grant{}, resp.StatusCode, string(body)
	}
	var g grant
	if err := json.Unmarshal(body, &g); err != nil {
		fail("upgrade: decode: %v", err)
	}
	return g, resp.StatusCode, string(body)
}

func mustUpgrade(base, id, token string, want int) grant {
	g, code, body := upgrade(base, id, token)
	if code != want {
		fail("upgrade %s: want %d, got %d (%s)", id, want, code, body)
	}
	return g
}

type keyedResult struct {
	grant
	token    string
	replayed bool
}

func createKeyed(base, receiver, mode, key string) (keyedResult, int) {
	payload, _ := json.Marshal(map[string]string{"mode": mode, "request_key": key})
	resp, err := client.Post(base+"/receivers/"+receiver+"/grants", "application/json", bytes.NewReader(payload))
	if err != nil {
		fail("keyed create: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return keyedResult{}, resp.StatusCode
	}
	var out struct {
		grant
		OwnerToken string `json:"owner_token"`
		Replayed   bool   `json:"replayed"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		fail("keyed create: decode: %v", err)
	}
	if out.OwnerToken == "" {
		fail("keyed create response must carry owner_token")
	}
	if strings.Contains(string(raw), "request_key") {
		fail("create response must not echo request_key field")
	}
	return keyedResult{grant: out.grant, token: out.OwnerToken, replayed: out.Replayed}, resp.StatusCode
}

func mustCreateKeyed(base, receiver, mode, key string, want int) keyedResult {
	r, code := createKeyed(base, receiver, mode, key)
	if code != want {
		fail("keyed create %s (%s) on %s: want %d, got %d", mode, key, receiver, want, code)
	}
	return r
}

// postCreateDropResponse commits a keyed create on the server while
// abandoning its HTTP response: the raw TCP connection is closed without
// reading only after the new row becomes visible through the listing API,
// proving the commit landed before the network "interruption".
func postCreateDropResponse(base, receiver, mode, key string) {
	u, err := url.Parse(base)
	if err != nil {
		fail("parse base url: %v", err)
	}
	payload, _ := json.Marshal(map[string]string{"mode": mode, "request_key": key})
	conn, err := net.DialTimeout("tcp", u.Host, 5*time.Second)
	if err != nil {
		fail("dial: %v", err)
	}
	defer conn.Close()
	req := fmt.Sprintf(
		"POST /receivers/%s/grants HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		receiver, u.Host, len(payload), payload)
	if _, err := conn.Write([]byte(req)); err != nil {
		fail("write dropped-create request: %v", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if n := len(mustList(base, receiver)); n >= 1 {
			return // committed; close the socket and discard the response
		}
		time.Sleep(25 * time.Millisecond)
	}
	fail("dropped create on %s never committed", receiver)
}
