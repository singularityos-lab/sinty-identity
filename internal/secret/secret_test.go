package secret

import (
	"testing"
	"time"
)

func TestPassword(t *testing.T) {
	h, err := HashPassword("Corr3ct horse")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := CheckPassword(h, "Corr3ct horse"); !ok {
		t.Fatal("right password refused")
	}
	if ok, _ := CheckPassword(h, "corr3ct horse"); ok {
		t.Fatal("wrong password accepted")
	}
	if _, err := CheckPassword("plain", "x"); err != ErrFormat {
		t.Fatal("unknown format accepted")
	}
}

func TestTOTPVector(t *testing.T) {
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	cases := map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"}
	for at, want := range cases {
		got, err := TOTPAt(seed, time.Unix(at, 0))
		if err != nil || got != want {
			t.Fatalf("%d: got %s want %s", at, got, want)
		}
	}
}

func TestTOTPReplay(t *testing.T) {
	seed := NewTOTP()
	now := time.Unix(1700000000, 0)
	code, _ := TOTPAt(seed, now)
	step, ok := CheckTOTP(seed, code, now, 0)
	if !ok {
		t.Fatal("current code refused")
	}
	if _, ok := CheckTOTP(seed, code, now, step); ok {
		t.Fatal("a used code was accepted again")
	}
	if _, ok := CheckTOTP(seed, "000000", now, 0); ok && code != "000000" {
		t.Fatal("wrong code accepted")
	}
}
