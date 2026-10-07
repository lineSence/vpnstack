package panel

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const pbkdf2Iter = 600000

// HashPassword — PBKDF2-SHA256 (OWASP: 600 000 итераций).
func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	k, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iter, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(k)), nil
}

// CheckPassword сверяет пароль с хешем за постоянное время.
func CheckPassword(hash, pw string) bool {
	p := strings.Split(hash, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" {
		return false
	}
	iter, _ := strconv.Atoi(p[1])
	salt, err1 := base64.RawStdEncoding.DecodeString(p[2])
	want, err2 := base64.RawStdEncoding.DecodeString(p[3])
	if iter <= 0 || err1 != nil || err2 != nil {
		return false
	}
	k, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(k, want) == 1
}

// NewTOTPSecret — секрет TOTP (base32).
func NewTOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// TOTPURI — otpauth:// для приложения-аутентификатора.
func TOTPURI(secret, account string) string {
	return fmt.Sprintf("otpauth://totp/vpnstack:%s?secret=%s&issuer=vpnstack", account, secret)
}

func totpAt(secret string, t int64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t/30))
	h := hmac.New(sha1.New, key)
	h.Write(msg[:])
	s := h.Sum(nil)
	o := s[len(s)-1] & 0x0f
	code := (binary.BigEndian.Uint32(s[o:o+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code)
}

// CheckTOTP — код RFC 6238 с допуском ±1 шаг.
func CheckTOTP(secret, code string) bool {
	now := time.Now().Unix()
	for _, d := range []int64{-30, 0, 30} {
		if c := totpAt(secret, now+d); c != "" && subtle.ConstantTimeCompare([]byte(c), []byte(strings.TrimSpace(code))) == 1 {
			return true
		}
	}
	return false
}
