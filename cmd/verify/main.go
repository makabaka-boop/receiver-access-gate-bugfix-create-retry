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
	"net/http"
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
