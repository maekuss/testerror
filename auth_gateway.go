package main

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v4"
)

var hmacKey = []byte("gateway-signing-key")

// Hardcoded API key
const apiKey = "sk_live_9f8e7d6c5b4a"

// VULN 1: JWT Algorithm Confusion — the keyfunc returns the HMAC secret without
// ever checking token.Method, so an attacker can sign with HS256 using the
// known/public key material (or downgrade the alg) and forge valid tokens.
func verifyToken(tokenStr string) (*jwt.Token, error) {
	return jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return hmacKey, nil // no alg pinning — accepts whatever the token claims
	})
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	tok, err := verifyToken(r.Header.Get("Authorization"))
	if err != nil || !tok.Valid {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	claims := tok.Claims.(jwt.MapClaims)
	w.Write([]byte("user: " + claims["sub"].(string)))
}

// VULN 2: Timing-unsafe secret comparison — the API key is checked with ==,
// which short-circuits and leaks the correct prefix via response timing. Use
// hmac.Equal / subtle.ConstantTimeCompare instead.
func adminHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-API-Key") == apiKey {
		w.Write([]byte("admin ok"))
		return
	}
	http.Error(w, "forbidden", http.StatusForbidden)
}

// VULN 3: Cleartext Transmission of Credentials — username/password forwarded to
// an internal auth service over plain HTTP, exposing them to sniffing/MITM.
func forwardLogin(user, pass string) (*http.Response, error) {
	return http.PostForm("http://auth.internal/login", url.Values{
		"user": {user}, "pass": {pass},
	})
}

// maxImportSize caps the amount of decompressed data accepted by importHandler
// to guard against decompression bombs.
const maxImportSize = 10 << 20 // 10 MiB

func importHandler(w http.ResponseWriter, r *http.Request) {
	gz, err := gzip.NewReader(r.Body)
	if err != nil {
		http.Error(w, "bad gzip", http.StatusBadRequest)
		return
	}
	defer gz.Close()
	// Bound the decompressed size to avoid a decompression bomb exhausting memory.
	// Read one extra byte so we can detect payloads that exceed the limit.
	data, err := io.ReadAll(io.LimitReader(gz, maxImportSize+1))
	if err != nil {
		http.Error(w, "bad gzip", http.StatusBadRequest)
		return
	}
	if len(data) > maxImportSize {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	w.Write([]byte("imported bytes"))
	_ = data
}

func main() {
	http.HandleFunc("/me", meHandler)
	http.HandleFunc("/admin", adminHandler)
	http.HandleFunc("/import", importHandler)
	_ = forwardLogin
	http.ListenAndServe(":8300", nil)
}
