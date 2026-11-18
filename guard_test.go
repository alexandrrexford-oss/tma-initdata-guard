package tmaguard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func signTestInitData(t *testing.T, botToken string, authDate int64, userJSON string) string {
	t.Helper()
	// Keys sorted: auth_date, query_id, user
	checkStr := "auth_date=" + url.QueryEscape(strconvFormat(authDate)) +
		"\nquery_id=AAHdF6IQAAAAAN0XohDhrOrc" +
		"\nuser=" + userJSON

	sec := hmac.New(sha256.New, []byte("WebAppData"))
	sec.Write([]byte(botToken))
	mac := hmac.New(sha256.New, sec.Sum(nil))
	mac.Write([]byte(checkStr))
	sig := hex.EncodeToString(mac.Sum(nil))

	v := url.Values{}
	v.Set("auth_date", strconvFormat(authDate))
	v.Set("query_id", "AAHdF6IQAAAAAN0XohDhrOrc")
	v.Set("user", userJSON)
	v.Set("hash", sig)
	return v.Encode()
}

func strconvFormat(n int64) string {
	return time.Unix(n, 0).UTC().Format("2006")[:0] + itoa(n)
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func TestVerifySuccessAndTamperDetection(t *testing.T) {
	token := "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
	now := time.Unix(1_700_000_100, 0).UTC()
	raw := signTestInitData(t, token, 1_700_000_000, `{"id":9911,"first_name":"Iskander","username":"AlexByteStar"}`)

	res, err := Verify(raw, token, 5*time.Minute, now)
	if err != nil {
		t.Fatalf("expected valid signature, got %v", err)
	}
	if res.User == nil || res.User.ID != 9911 || res.User.Username != "AlexByteStar" {
		t.Fatalf("unexpected user parsed: %+v", res.User)
	}

	// Wrong token must fail constant-time check
	if _, err := Verify(raw, token+"x", 5*time.Minute, now); !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("expected ErrInvalidHash, got %v", err)
	}

	// Expired initData must fail
	if _, err := Verify(raw, token, 30*time.Second, now); !errors.Is(err, ErrExpiredInitData) {
		t.Fatalf("expected ErrExpiredInitData, got %v", err)
	}
}

func TestMiddlewareRejectsUnauthorized(t *testing.T) {
	called := false
	h := Middleware("test-token", time.Minute, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized || called {
		t.Fatalf("expected 401 and blocked handler, got status=%d called=%v", rec.Code, called)
	}
}
