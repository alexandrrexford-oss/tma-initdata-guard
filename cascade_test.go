package tmaguard

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestWaveCipherSessionTicketAndTamper(t *testing.T) {
	eng, err := NewNativeEngine("")
	if err != nil {
		t.Fatalf("NewNativeEngine: %v", err)
	}

	botToken := "7123456:AAE-test-secret-token"
	now := time.Unix(1_765_000_100, 0).UTC()
	raw := signTestInitData(t, botToken, now.Unix()-10, `{"id":4242,"first_name":"Alex","username":"alexdev"}`)
	nonce := bytes.Repeat([]byte{0x24}, 12)

	v, ticket, err := eng.VerifyAndIssueTicket(raw, botToken, 5*time.Minute, time.Hour, now, nonce)
	if err != nil {
		t.Fatalf("VerifyAndIssueTicket: %v", err)
	}
	if v.User == nil || v.User.ID != 4242 {
		t.Fatalf("unexpected user: %+v", v.User)
	}

	pt, err := eng.OpenSessionTicket(botToken, 4242, ticket, nonce)
	if err != nil {
		t.Fatalf("OpenSessionTicket: %v", err)
	}
	var claims SessionClaims
	if err := json.Unmarshal(pt, &claims); err != nil || claims.UserID != 4242 || claims.Username != "alexdev" {
		t.Fatalf("claims mismatch: %s err=%v", pt, err)
	}

	// Wrong userID AAD binding MUST fail closed
	if _, err := eng.OpenSessionTicket(botToken, 9999, ticket, nonce); err == nil {
		t.Fatal("expected failure on mismatched userID AAD")
	}

	// Tampered ciphertext/tag MUST fail closed
	bad := append([]byte(nil), ticket...)
	bad[len(bad)-1] ^= 0xFF
	if _, err := eng.OpenSessionTicket(botToken, 4242, bad, nonce); err == nil {
		t.Fatal("expected failure on tampered ticket")
	}
}

func TestCompiledMatchingScorer(t *testing.T) {
	eng, err := NewNativeEngine("")
	if err != nil {
		t.Fatalf("NewNativeEngine: %v", err)
	}

	cands := []string{
		"rust go backend architecture almaty synthwave",
		"cooking pastry dessert cake baking",
		"синтвейв алматы го раст разработка", // cross-script phonetic match!
	}
	scores, err := eng.MatchCandidates("almati rust synthwave", cands, nil)
	if err != nil {
		t.Fatalf("MatchCandidates: %v", err)
	}
	if scores[0] <= scores[1] || scores[2] <= scores[1] {
		t.Fatalf("expected relevant tech/cross-script matches > cooking: %+v", scores)
	}
}

func BenchmarkWaveSealTicket(b *testing.B) {
	eng, err := NewNativeEngine("")
	if err != nil {
		b.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x11}, 12)
	payload := []byte(`{"uid":4242,"u":"alexdev","iat":1765000000,"exp":1765003600}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eng.SealSessionTicket("bot-token", 4242, payload, nonce)
	}
}

func BenchmarkWaveOpenTicket(b *testing.B) {
	eng, err := NewNativeEngine("")
	if err != nil {
		b.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x11}, 12)
	payload := []byte(`{"uid":4242,"u":"alexdev","iat":1765000000,"exp":1765003600}`)
	tkt, _ := eng.SealSessionTicket("bot-token", 4242, payload, nonce)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eng.OpenSessionTicket("bot-token", 4242, tkt, nonce)
	}
}

func BenchmarkMatchCandidatesCompiled(b *testing.B) {
	eng, err := NewNativeEngine("")
	if err != nil {
		b.Fatal(err)
	}
	cands := make([]string, 100)
	for i := range cands {
		if i%5 == 0 {
			cands[i] = "rust go almaty backend api systems"
		} else {
			cands[i] = "generic marketing lifestyle content feed"
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = eng.MatchCandidates("almati rust go backend", cands, nil)
	}
}

func BenchmarkMatchCandidatesPureGo(b *testing.B) {
	cands := make([]string, 100)
	for i := range cands {
		if i%5 == 0 {
			cands[i] = "rust go almaty backend api systems"
		} else {
			cands[i] = "generic marketing lifestyle content feed"
		}
	}
	qToks := strings.Fields("almati rust go backend")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scores := make([]int, len(cands))
		for idx, c := range cands {
			sc := 0
			for _, qt := range qToks {
				if strings.Contains(c, qt) {
					sc += 1000
				}
			}
			scores[idx] = sc
		}
		_ = scores
	}
}
