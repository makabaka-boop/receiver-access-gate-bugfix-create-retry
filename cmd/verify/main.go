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

	step("keyed create: a retry with the same request key replays the original outcome")
	rxK := "rx-verify-key-" + suffix()
	key := "req-" + suffix()
	k1, ktok1 := mustCreateKey(api1, rxK, "SHARED", key, http.StatusCreated)
	k2, ktok2 := mustCreateKey(api2, rxK, "SHARED", key, http.StatusCreated)
	if k2.ID != k1.ID || ktok2 != ktok1 {
		fail("keyed retry: want replay of grant %s with its original token, got %+v", k1.ID, k2)
	}
	if n := len(mustList(api1, rxK)); n != 1 {
		fail("keyed retry must not add a record, got %d grants", n)
	}

	step("response lost after commit: the keyed retry recovers grant and token")
	rxD := "rx-verify-drop-" + suffix()
	dkey := "req-" + suffix()
	dropCreate(api1, rxD, "SHARED", dkey)
	d1, dtok := mustCreateKey(api2, rxD, "SHARED", dkey, http.StatusCreated)
	dg := mustList(api1, rxD)
	if len(dg) != 1 || dg[0].ID != d1.ID {
		fail("lost create must converge to exactly one grant, list=%+v replay=%+v", dg, d1)
	}
	mustCreate(api1, rxD, "EXCLUSIVE", http.StatusConflict) // keyless: someone else's occupancy
	mustRelease(api2, d1.ID, dtok, http.StatusOK)

	step("exclusive create with lost response: keyed retry returns the caller's own grant")
	rxX := "rx-verify-xdrop-" + suffix()
	xkey := "req-" + suffix()
	dropCreate(api1, rxX, "EXCLUSIVE", xkey)
	x1, xtok := mustCreateKey(api2, rxX, "EXCLUSIVE", xkey, http.StatusCreated)
	xg := mustList(api1, rxX)
	if len(xg) != 1 || xg[0].ID != x1.ID || xg[0].Mode != "EXCLUSIVE" {
		fail("lost exclusive create must converge to one EXCLUSIVE grant, list=%+v replay=%+v", xg, x1)
	}
	mustCreate(api1, rxX, "EXCLUSIVE", http.StatusConflict) // keyless: still busy
	mustRelease(api2, x1.ID, xtok, http.StatusOK)
	mustCreate(api1, rxX, "EXCLUSIVE", http.StatusCreated) // receiver freed by the recovered token

	step("concurrent retries with one request key create exactly one grant")
	rxC := "rx-verify-keyrace-" + suffix()
	ckey := "req-" + suffix()
	const retries = 10
	type keyOutcome struct {
		id, tok string
		code    int
	}
	outs := make([]keyOutcome, retries)
	var wgK sync.WaitGroup
	for i := 0; i < retries; i++ {
		base := api1
		if i%2 == 1 {
			base = api2
		}
		wgK.Add(1)
		go func(b string, slot int) {
			defer wgK.Done()
			g, code, tok := createKey(b, rxC, "SHARED", ckey)
			outs[slot] = keyOutcome{g.ID, tok, code}
		}(base, i)
	}
	wgK.Wait()
	for i, o := range outs {
		if o.code != http.StatusCreated || o.id == "" || o.id != outs[0].id || o.tok != outs[0].tok {
			fail("keyed race retry %d: %+v, want all identical to %+v", i, o, outs[0])
		}
	}
	if cg := mustList(api1, rxC); len(cg) != 1 || cg[0].ID != outs[0].id {
		fail("same-key race must leave exactly one grant, got %+v", cg)
	}

	step("a recovered token drives upgrade and release")
	rxU := "rx-verify-keyupg-" + suffix()
	ukey := "req-" + suffix()
	dropCreate(api1, rxU, "SHARED", ukey)
	u1, utok1 := mustCreateKey(api2, rxU, "SHARED", ukey, http.StatusCreated)
	u2, utok2 := mustCreate(api2, rxU, "SHARED", http.StatusCreated)
	if up := mustUpgrade(api1, u1.ID, utok1, http.StatusOK); up.Status != "UPGRADE_PENDING" {
		fail("upgrade with recovered token: want UPGRADE_PENDING, got %+v", up)
	}
	mustRelease(api2, u2.ID, utok2, http.StatusOK)
	if got := findGrant(mustList(api1, rxU), u1.ID); got.Mode != "EXCLUSIVE" || got.Status != "ACTIVE" {
		fail("recovered grant not promoted after competitor release: %+v", got)
	}
	mustRelease(api1, u1.ID, utok1, http.StatusOK)

	step("a request key reused with different parameters is rejected without side effects")
	rxM := "rx-verify-keymix-" + suffix()
	mkey := "req-" + suffix()
	mustCreateKey(api1, rxM, "SHARED", mkey, http.StatusCreated)
	mustCreateKey(api2, rxM, "EXCLUSIVE", mkey, http.StatusConflict)
	mustCreateKey(api1, rxM+"-other", "SHARED", mkey, http.StatusConflict)
	if n := len(mustList(api1, rxM)); n != 1 {
		fail("mismatched reuse must not add records, got %d", n)
	}
	if n := len(mustList(api2, rxM+"-other")); n != 0 {
		fail("mismatched reuse on another receiver must leave nothing, got %d", n)
	}

	step("a replay reflects the grant's current state")
	mustRelease(api1, k1.ID, ktok1, http.StatusOK)
	k3, ktok3 := mustCreateKey(api2, rxK, "SHARED", key, http.StatusCreated)
	if k3.ID != k1.ID || k3.Status != "RELEASED" || ktok3 != ktok1 {
		fail("replay after release: want %s RELEASED with original token, got %+v", k1.ID, k3)
	}

	step("query responses never leak tokens or request keys")
	body := mustListRaw(api1, rx)
	if strings.Contains(body, "token") || strings.Contains(body, tok1) {
		fail("list response leaks token material: %s", body)
	}
	if kbody := mustListRaw(api2, rxK); strings.Contains(kbody, "token") || strings.Contains(kbody, key) {
		fail("list response leaks token or request-key material: %s", kbody)
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
	return createKey(base, receiver, mode, "")
}

// createKey posts a create request; a non-empty key is sent as the
// Idempotency-Key header identifying the business request.
func createKey(base, receiver, mode, key string) (grant, int, string) {
	payload, _ := json.Marshal(map[string]string{"mode": mode})
	req, err := http.NewRequest(http.MethodPost, base+"/receivers/"+receiver+"/grants", bytes.NewReader(payload))
	if err != nil {
		fail("create: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	resp, err := client.Do(req)
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
		fail("create response must carry owner_token")
	}
	return out.grant, resp.StatusCode, out.OwnerToken
}

// dropCreate sends a keyed create request over a raw TCP connection and
// closes it without reading the response, simulating an answer lost in
// the network after the request was submitted. Whether that attempt
// committed is deliberately left uncertain; the keyed retry that
// follows is what must converge the business outcome.
func dropCreate(base, receiver, mode, key string) {
	u, err := url.Parse(base)
	if err != nil {
		fail("drop create: %v", err)
	}
	conn, err := net.DialTimeout("tcp", u.Host, 5*time.Second)
	if err != nil {
		fail("drop create dial: %v", err)
	}
	payload, _ := json.Marshal(map[string]string{"mode": mode})
	if _, err := fmt.Fprintf(conn, "POST /receivers/%s/grants HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nIdempotency-Key: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		receiver, u.Host, key, len(payload), payload); err != nil {
		fail("drop create write: %v", err)
	}
	_ = conn.Close()
	// Let the server finish (commit or roll back) before any retry
	// arrives; the acceptance assertions hold on either path.
	time.Sleep(300 * time.Millisecond)
}

func mustCreate(base, receiver, mode string, want int) (grant, string) {
	g, code, token := create(base, receiver, mode)
	if code != want {
		fail("create %s on %s: want %d, got %d", mode, receiver, want, code)
	}
	return g, token
}

func mustCreateKey(base, receiver, mode, key string, want int) (grant, string) {
	g, code, token := createKey(base, receiver, mode, key)
	if code != want {
		fail("create %s on %s (key %q): want %d, got %d", mode, receiver, key, want, code)
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
