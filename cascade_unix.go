//go:build linux || darwin

package tmaguard

/*
#cgo linux LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>

typedef int32_t (*fn_wave_t)(const uint8_t*, const uint8_t*, const uint8_t*, size_t, const uint8_t*, size_t, uint8_t, uint8_t*, size_t, size_t*);
typedef int32_t (*fn_match_t)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, int64_t*);

static void* tma_open_lib(const char* p) { return dlopen(p, RTLD_NOW); }
static void* tma_sym(void* h, const char* s) { return dlsym(h, s); }
static int32_t call_wave(void* fn, const uint8_t* k, const uint8_t* n, const uint8_t* a, size_t al, const uint8_t* inb, size_t il, uint8_t r, uint8_t* outb, size_t oc, size_t* ol) {
    return ((fn_wave_t)fn)(k, n, a, al, inb, il, r, outb, oc, ol);
}
static int32_t call_match(void* fn, const uint8_t* q, size_t ql, const uint8_t* c, size_t cl, const uint8_t* f, size_t nc, int64_t* out) {
    return ((fn_match_t)fn)(q, ql, c, cl, f, nc, out);
}
*/
import "C"
import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"
)

var (
	ErrTicketAuthFailed = errors.New("tmaguard: encrypted ticket authentication failed")
	ErrNativeNotFound   = errors.New("tmaguard: native binary not found")
)

type NativeEngine struct {
	handle       unsafe.Pointer
	pWave31Seal  unsafe.Pointer
	pWave31Open  unsafe.Pointer
	pCascadeSeal unsafe.Pointer
	pCascadeOpen unsafe.Pointer
	pMatchScore  unsafe.Pointer
	buf          []byte
}

func defaultNativePath() (string, error) {
	if p := os.Getenv("PRIMOSTRATA_EDGE_LIB"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	var names []string
	switch runtime.GOOS {
	case "darwin":
		if runtime.GOARCH == "arm64" {
			names = []string{"libprimostrata_edge_darwin_arm64.dylib", "libprimostrata_edge.dylib"}
		} else {
			names = []string{"libprimostrata_edge_darwin_amd64.dylib", "libprimostrata_edge.dylib"}
		}
	default:
		if runtime.GOARCH == "arm64" {
			names = []string{"libprimostrata_edge_linux_arm64.so", "libprimostrata_edge.so"}
		} else {
			names = []string{"libprimostrata_edge.so", "libprimostrata_edge_linux_amd64.so"}
		}
	}
	wd, _ := os.Getwd()
	for _, name := range names {
		for _, c := range []string{
			filepath.Join(wd, "native", name),
			filepath.Join(wd, name),
			filepath.Join(wd, "..", "native", name),
		} {
			if _, err := os.Stat(c); err == nil {
				return c, nil
			}
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
	cp := C.CString(libPath)
	defer C.free(unsafe.Pointer(cp))
	h := C.tma_open_lib(cp)
	if h == nil {
		return nil, fmt.Errorf("tmaguard: dlopen failed for %s", libPath)
	}
	s1 := C.CString("primo_wave31_seal")
	s2 := C.CString("primo_wave31_open")
	s3 := C.CString("primo_wave_cascade_seal")
	s4 := C.CString("primo_wave_cascade_open")
	s5 := C.CString("primo_match_score_candidates")
	defer func() {
		C.free(unsafe.Pointer(s1))
		C.free(unsafe.Pointer(s2))
		C.free(unsafe.Pointer(s3))
		C.free(unsafe.Pointer(s4))
		C.free(unsafe.Pointer(s5))
	}()
	return &NativeEngine{
		handle:       h,
		pWave31Seal:  C.tma_sym(h, s1),
		pWave31Open:  C.tma_sym(h, s2),
		pCascadeSeal: C.tma_sym(h, s3),
		pCascadeOpen: C.tma_sym(h, s4),
		pMatchScore:  C.tma_sym(h, s5),
		buf:          make([]byte, 65536),
	}, nil
}

func cPtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func deriveTicketKey(botToken string) [32]byte {
	return sha256.Sum256([]byte("tma-wave-ticket:" + botToken))
}

func (n *NativeEngine) callWave(fn unsafe.Pointer, botToken string, userID int64, input, nonce12 []byte, rounds C.uint8_t, authErr error) ([]byte, error) {
	if len(nonce12) != 12 {
		return nil, errors.New("tmaguard: nonce must be 12 bytes")
	}
	key := deriveTicketKey(botToken)
	aad := []byte(fmt.Sprintf("tma:%d", userID))
	var outLen C.size_t
	rc := C.call_wave(fn, (*C.uint8_t)(&key[0]), cPtr(nonce12), cPtr(aad), C.size_t(len(aad)), cPtr(input), C.size_t(len(input)), rounds, cPtr(n.buf), C.size_t(len(n.buf)), &outLen)
	if int32(rc) == -2 {
		n.buf = make([]byte, int(outLen))
		rc = C.call_wave(fn, (*C.uint8_t)(&key[0]), cPtr(nonce12), cPtr(aad), C.size_t(len(aad)), cPtr(input), C.size_t(len(input)), rounds, cPtr(n.buf), C.size_t(len(n.buf)), &outLen)
	}
	if rc != 0 {
		if authErr != nil {
			return nil, authErr
		}
		return nil, fmt.Errorf("tmaguard: wave op failed rc=%d", int32(rc))
	}
	out := make([]byte, int(outLen))
	copy(out, n.buf[:int(outLen)])
	return out, nil
}

func (n *NativeEngine) SealSessionTicket(botToken string, userID int64, payload, nonce12 []byte) ([]byte, error) {
	return n.callWave(n.pWave31Seal, botToken, userID, payload, nonce12, 4, nil)
}

func (n *NativeEngine) OpenSessionTicket(botToken string, userID int64, ticket, nonce12 []byte) ([]byte, error) {
	return n.callWave(n.pWave31Open, botToken, userID, ticket, nonce12, 4, ErrTicketAuthFailed)
}

func (n *NativeEngine) SealSessionTicketContourB(botToken string, userID int64, payload, nonce12 []byte) ([]byte, error) {
	return n.callWave(n.pCascadeSeal, botToken, userID, payload, nonce12, 8, nil)
}

func (n *NativeEngine) OpenSessionTicketContourB(botToken string, userID int64, ticket, nonce12 []byte) ([]byte, error) {
	return n.callWave(n.pCascadeOpen, botToken, userID, ticket, nonce12, 8, ErrTicketAuthFailed)
}

type SessionClaims struct {
	UserID    int64  `json:"uid"`
	Username  string `json:"u,omitempty"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

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

func (n *NativeEngine) MatchCandidates(queryTags string, candidates []string, flags []byte) ([]int64, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	qb := []byte(queryTags)
	joined := []byte(strings.Join(candidates, "\n"))
	scores := make([]int64, len(candidates))
	var fPtr *C.uint8_t
	if len(flags) >= len(candidates)*3 {
		fPtr = cPtr(flags)
	}
	rc := C.call_match(n.pMatchScore, cPtr(qb), C.size_t(len(qb)), cPtr(joined), C.size_t(len(joined)), fPtr, C.size_t(len(candidates)), (*C.int64_t)(unsafe.Pointer(&scores[0])))
	if rc != 0 {
		return nil, fmt.Errorf("tmaguard: match score failed rc=%d", int32(rc))
	}
	return scores, nil
}
