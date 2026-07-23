package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v4"
)

var hmacKey = []byte("gateway-signing-key")

// Hardcoded API key
const apiKey = "sk_live_9f8e7d6c5b4a"

// verifyToken parses and validates a JWT. The signing method is pinned to HMAC
// so an attacker cannot swap the alg header (e.g. RSA -> HS256) and forge a
// token signed with the HMAC secret.
func verifyToken(tokenStr string) (*jwt.Token, error) {
	return jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return hmacKey, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
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

// VULN 4: Decompression Bomb — a gzip request body is fully read with no size
// limit, so a tiny payload can expand to gigabytes and exhaust memory (DoS).
func importHandler(w http.ResponseWriter, r *http.Request) {
	gz, err := gzip.NewReader(r.Body)
	if err != nil {
		http.Error(w, "bad gzip", http.StatusBadRequest)
		return
	}
	data, _ := io.ReadAll(gz) // no io.LimitReader — unbounded
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
