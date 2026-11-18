// Package tmaguard verifies Telegram Mini App initData payloads using HMAC-SHA256
// per Telegram's official WebApp validation specification.
package tmaguard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	ErrEmptyInitData   = errors.New("tmaguard: empty initData")
	ErrEmptyBotToken   = errors.New("tmaguard: empty bot token")
	ErrMissingHash     = errors.New("tmaguard: missing hash parameter")
	ErrInvalidHash     = errors.New("tmaguard: invalid initData signature")
	ErrMissingAuthDate = errors.New("tmaguard: missing auth_date")
	ErrExpiredInitData = errors.New("tmaguard: initData expired")
)

type User struct {
	ID           int64  `json:"id"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name,omitempty"`
	Username     string `json:"username,omitempty"`
	LanguageCode string `json:"language_code,omitempty"`
	IsPremium    bool   `json:"is_premium,omitempty"`
}

type VerifiedData struct {
	AuthDate time.Time
	QueryID  string
	User     *User
	Raw      url.Values
}

// Verify validates raw Telegram WebApp initData against botToken and maxAge at timestamp now.
// Pass maxAge <= 0 to skip expiration checks.
func Verify(rawInitData, botToken string, maxAge time.Duration, now time.Time) (*VerifiedData, error) {
	if strings.TrimSpace(rawInitData) == "" {
		return nil, ErrEmptyInitData
	}
	if strings.TrimSpace(botToken) == "" {
		return nil, ErrEmptyBotToken
	}

	values, err := url.ParseQuery(rawInitData)
	if err != nil {
		return nil, err
	}

	gotHashHex := values.Get("hash")
	if gotHashHex == "" {
		return nil, ErrMissingHash
	}
	gotHash, err := hex.DecodeString(gotHashHex)
	if err != nil || len(gotHash) != sha256.Size {
		return nil, ErrInvalidHash
	}

	keys := make([]string, 0, len(values))
	for k := range values {
		if k == "hash" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(values.Get(k))
	}

	// Secret key = HMAC_SHA256("WebAppData", botToken)
	secretMac := hmac.New(sha256.New, []byte("WebAppData"))
	secretMac.Write([]byte(botToken))
	secretKey := secretMac.Sum(nil)

	dataMac := hmac.New(sha256.New, secretKey)
	dataMac.Write([]byte(b.String()))
	expectedHash := dataMac.Sum(nil)

	if !hmac.Equal(gotHash, expectedHash) {
		return nil, ErrInvalidHash
	}

	authUnixStr := values.Get("auth_date")
	if authUnixStr == "" {
		return nil, ErrMissingAuthDate
	}
	authUnix, err := strconv.ParseInt(authUnixStr, 10, 64)
	if err != nil {
		return nil, ErrMissingAuthDate
	}
	authTime := time.Unix(authUnix, 0).UTC()

	if maxAge > 0 && now.Sub(authTime) > maxAge {
		return nil, ErrExpiredInitData
	}

	var parsedUser *User
	if userJSON := values.Get("user"); userJSON != "" {
		var u User
		if err := json.Unmarshal([]byte(userJSON), &u); err != nil {
			return nil, err
		}
		parsedUser = &u
	}

	return &VerifiedData{
		AuthDate: authTime,
		QueryID:  values.Get("query_id"),
		User:     parsedUser,
		Raw:      values,
	}, nil
}

// Middleware validates the `X-Telegram-Init-Data` header before forwarding to next.
func Middleware(botToken string, maxAge time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get("X-Telegram-Init-Data")
		if _, err := Verify(raw, botToken, maxAge, time.Now().UTC()); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
