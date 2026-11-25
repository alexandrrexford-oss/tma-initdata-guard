# tma-initdata-guard

Telegram Mini App `initData` HMAC-SHA256 verification, dual-layer encrypted session tickets (`WaveCipher31-256` + RFC 8439 `ChaCha20-Poly1305`), and compiled cross-script profile/feed matching engine for Go (prebuilt Windows x86_64 `.dll`, Linux x86_64 `.so`, and Linux ARM64 `libprimostrata_edge_linux_arm64.so` binaries included).

## Features

- **`Verify` & `GuardMiddleware`**: zero-dependency Telegram WebApp `initData` HMAC-SHA256 validation, expiration enforcement, and `net/http` middleware.
- **Ephemeral Ticket Encryption (`SealSessionTicket` / `OpenSessionTicket` + optional `SealSessionTicketContourB`):** defaults to **Contour A** (pure `WaveCipher31-512` CTR + `WaveCipher31-256` 128-bit MAC, zero ChaCha20), with **Contour B** (`WaveCipher31-256` + RFC 8439 `ChaCha20-Poly1305` hybrid cascade) available as an opt-in call.
- **Compiled Matching Engine (`MatchCandidates`)**: native candidate scoring with cross-script Latin/Cyrillic phonetic matching (`almati` ↔ `алматы`, `synthwave` ↔ `синтвейв`) and 2-bit quantized similarity scoring for Telegram Mini App feeds and matchmaking.

## Benchmarks (`go test -v -bench . -benchmem`)

Windows 11 x86_64 (`AMD Ryzen 7 5800H`, `syscall.NewLazyDLL`, `CGO_ENABLED=0`):

- `BenchmarkWaveSealTicket` (Contour A default): **`1,018 ns/op`** (~`982k` sealed tickets/sec)
- `BenchmarkWaveOpenTicket` (Contour A default): **`1,169 ns/op`** (~`855k` verified tickets/sec)
- `BenchmarkMatchCandidatesCompiled`: `101,135 ns/op` for 100 raw unindexed profiles with cross-script phonetic matching

```bash
go test -v -bench . -benchmem ./...
```
