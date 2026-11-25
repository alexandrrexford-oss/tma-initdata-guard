//go:build windows

package tmaguard

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	ErrTicketAuthFailed = errors.New("tmaguard: encrypted ticket authentication failed")
	ErrNativeNotFound   = errors.New("tmaguard: native binary not found")
)

type NativeEngine struct {
	dll          *syscall.LazyDLL
	pWave31Seal  *syscall.LazyProc
	pWave31Open  *syscall.LazyProc
	pCascadeSeal *syscall.LazyProc
	pCascadeOpen *syscall.LazyProc
	pMatchScore  *syscall.LazyProc
	buf          []byte
}

func defaultNativePath() (string, error) {
	if p := os.Getenv("PRIMOSTRATA_EDGE_LIB"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	wd, _ := os.Getwd()
	for _, c := range []string{
		filepath.Join(wd, "native", "primostrata_edge.dll"),
		filepath.Join(wd, "primostrata_edge.dll"),
		filepath.Join(wd, "..", "native", "primostrata_edge.dll"),
	} {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", ErrNativeNotFound
}

func NewNativeEngine(libPath string) (*NativeEngine, error) {
	if libPath == "" {
		var err error
		libPath, err = defaultNativePath()
		if err != nil {
			return nil, err
		}
	}
	dll := syscall.NewLazyDLL(libPath)
	if err := dll.Load(); err != nil {
		return nil, err
	}
	return &NativeEngine{
		dll:          dll,
		pWave31Seal:  dll.NewProc("primo_wave31_seal"),
		pWave31Open:  dll.NewProc("primo_wave31_open"),
		pCascadeSeal: dll.NewProc("primo_wave_cascade_seal"),
		pCascadeOpen: dll.NewProc("primo_wave_cascade_open"),
		pMatchScore:  dll.NewProc("primo_match_score_candidates"),
		buf:          make([]byte, 65536),
	}, nil
}

func deriveTicketKey(botToken string) [32]byte {
	return sha256.Sum256([]byte("tma-wave-ticket:" + botToken))
}

func bPtr(b []byte) uintptr {
	if len(b) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&b[0]))
}

func (n *NativeEngine) callWave(proc *syscall.LazyProc, botToken string, userID int64, input, nonce12 []byte, rounds uintptr, authErr error) ([]byte, error) {
	if len(nonce12) != 12 {
		return nil, errors.New("tmaguard: nonce must be 12 bytes")
	}
	key := deriveTicketKey(botToken)
	aad := []byte(fmt.Sprintf("tma:%d", userID))
	var outLen uintptr
	rc, _, _ := proc.Call(
		uintptr(unsafe.Pointer(&key[0])),
		bPtr(nonce12),
		bPtr(aad), uintptr(len(aad)),
		bPtr(input), uintptr(len(input)),
		rounds,
		bPtr(n.buf), uintptr(len(n.buf)),
		uintptr(unsafe.Pointer(&outLen)),
	)
	if int32(rc) == -2 {
		n.buf = make([]byte, outLen)
		rc, _, _ = proc.Call(
			uintptr(unsafe.Pointer(&key[0])),
			bPtr(nonce12),
			bPtr(aad), uintptr(len(aad)),
			bPtr(input), uintptr(len(input)),
			rounds,
			bPtr(n.buf), uintptr(len(n.buf)),
			uintptr(unsafe.Pointer(&outLen)),
		)
	}
	if int32(rc) != 0 {
		if authErr != nil {
			return nil, authErr
		}
		return nil, fmt.Errorf("tmaguard: wave op failed rc=%d", int32(rc))
	}
	out := make([]byte, outLen)
	copy(out, n.buf[:outLen])
	return out, nil
}

// SealSessionTicket encrypts payload using Contour A (default pure WaveCipher31-512 CTR + WaveCipher31-256 MAC, zero ChaCha20).
func (n *NativeEngine) SealSessionTicket(botToken string, userID int64, payload, nonce12 []byte) ([]byte, error) {
	return n.callWave(n.pWave31Seal, botToken, userID, payload, nonce12, 4, nil)
}

// OpenSessionTicket authenticates and decrypts a Contour A pure WaveCipher31 ticket.
func (n *NativeEngine) OpenSessionTicket(botToken string, userID int64, ticket, nonce12 []byte) ([]byte, error) {
	return n.callWave(n.pWave31Open, botToken, userID, ticket, nonce12, 4, ErrTicketAuthFailed)
}

// SealSessionTicketContourB encrypts payload using optional Contour B (WaveCipher31-256 + RFC 8439 ChaCha20-Poly1305 cascade).
func (n *NativeEngine) SealSessionTicketContourB(botToken string, userID int64, payload, nonce12 []byte) ([]byte, error) {
	return n.callWave(n.pCascadeSeal, botToken, userID, payload, nonce12, 8, nil)
}

// OpenSessionTicketContourB authenticates and decrypts a Contour B hybrid cascade ticket.
func (n *NativeEngine) OpenSessionTicketContourB(botToken string, userID int64, ticket, nonce12 []byte) ([]byte, error) {
	return n.callWave(n.pCascadeOpen, botToken, userID, ticket, nonce12, 8, ErrTicketAuthFailed)
}

type SessionClaims struct {
	UserID    int64  `json:"uid"`
	Username  string `json:"u,omitempty"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// VerifyAndIssueTicket verifies Telegram WebApp initData and seals an encrypted session ticket.
func (n *NativeEngine) VerifyAndIssueTicket(rawInitData, botToken string, maxAge, ticketTTL time.Duration, now time.Time, nonce12 []byte) (*VerifiedData, []byte, error) {
	v, err := Verify(rawInitData, botToken, maxAge, now)
	if err != nil {
		return nil, nil, err
	}
	var uid int64
	var uname string
	if v.User != nil {
		uid = v.User.ID
		uname = v.User.Username
	}
	claims, _ := json.Marshal(SessionClaims{
		UserID:    uid,
		Username:  uname,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ticketTTL).Unix(),
	})
	ticket, err := n.SealSessionTicket(botToken, uid, claims, nonce12)
	if err != nil {
		return nil, nil, err
	}
	return v, ticket, nil
}

// MatchCandidates ranks candidate profiles/items against queryTags via the compiled
// PairRes31 + ConduitHex64 + VEC31 matching scorer.
// Optional flags has 3 bytes per candidate: [pairCode(0..3), isSeen(0/1), bounceFlag(0/1)].
func (n *NativeEngine) MatchCandidates(queryTags string, candidates []string, flags []byte) ([]int64, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	qb := []byte(queryTags)
	joined := []byte(strings.Join(candidates, "\n"))
	scores := make([]int64, len(candidates))
	var fPtr uintptr
	if len(flags) >= len(candidates)*3 {
		fPtr = bPtr(flags)
	}
	rc, _, _ := n.pMatchScore.Call(
		bPtr(qb), uintptr(len(qb)),
		bPtr(joined), uintptr(len(joined)),
		fPtr,
		uintptr(len(candidates)),
		uintptr(unsafe.Pointer(&scores[0])),
	)
	if int32(rc) != 0 {
		return nil, fmt.Errorf("tmaguard: match score failed rc=%d", int32(rc))
	}
	return scores, nil
}
