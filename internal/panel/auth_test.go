package panel

import (
	"testing"
	"time"
)

func TestPassword(t *testing.T) {
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "correct horse") || CheckPassword(h, "wrong") {
		t.Fatal("проверка пароля")
	}
}

func TestTOTP(t *testing.T) {
	// RFC 6238, SHA1, секрет "12345678901234567890", T=59 → 287082 (8 цифр 94287082).
	sec := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if got := totpAt(sec, 59); got != "287082" {
		t.Fatalf("totp=%s", got)
	}
	if !CheckTOTP(sec, totpAt(sec, time.Now().Unix())) {
		t.Fatal("текущий код")
	}
}
