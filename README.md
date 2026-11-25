# tma-initdata-guard

Telegram Mini App `initData` HMAC-SHA256 verification, dual-layer encrypted session tickets (`WaveCipher31-256` + RFC 8439 `ChaCha20-Poly1305`), and compiled cross-script profile/feed matching engine for Go (prebuilt Windows x86_64 `.dll`, Linux x86_64 `.so`, and Linux ARM64 `libprimostrata_edge_linux_arm64.so` binaries included).

## Features

- **`Verify` & `GuardMiddleware`**: zero-dependency Telegram WebApp `initData` HMAC-SHA256 validation, expiration enforcement, and `net/http` middleware.
- **Hybrid Encrypted Session Tickets (`SealSessionTicket` / `OpenSessionTicket`)**: wraps verified `user_id` claims inside a native dual-layer cipher cascade (`WaveCipher31-256` permutation CTR + outer RFC 8439 `ChaCha20-Poly1305` AEAD bound to `tma:{user_id}` AAD).
- **Compiled Matching Engine (`MatchCandidates`)**: native candidate scoring with cross-script Latin/Cyrillic phonetic matching (`almati` ↔ `алматы`, `synthwave` ↔ `синтвейв`) and 2-bit quantized similarity scoring for Telegram Mini App feeds and matchmaking.

## Benchmarks (`go test -v -bench . -benchmem`)

Windows 11 x86_64 (`AMD Ryzen 7 5800H`, `syscall.NewLazyDLL`, `CGO_ENABLED=0`):

- `BenchmarkWaveSealTicket`: **`1,363 ns/op`** (~`733k` sealed tickets/sec)
- `BenchmarkWaveOpenTicket`: **`1,271 ns/op`** (~`786k` verified tickets/sec)
- `BenchmarkMatchCandidatesCompiled`: `101,135 ns/op` for 100 raw unindexed profiles with cross-script phonetic matching

```bash
go test -v -bench . -benchmem ./...
```
