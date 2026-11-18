# tma-initdata-guard

Zero-dependency Go library and `net/http` middleware for verifying Telegram Mini App `initData` HMAC-SHA256 signatures.

## Features

- Follows Telegram's official `WebAppData` HMAC-SHA256 key derivation and sorted data-check string specification.
- Constant-time signature verification (`crypto/hmac.Equal`).
- Built-in `auth_date` TTL expiration check and `User` JSON parsing.
- Ready-to-use `net/http` middleware (`X-Telegram-Init-Data`).

## Usage

```go
data, err := tmaguard.Verify(rawInitData, botToken, 15*time.Minute, time.Now().UTC())
if err != nil {
    // reject unauthorized request
}
fmt.Println(data.User.ID, data.User.Username)
```

## Tests

```bash
go test -v ./...
```
