package secret

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
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const iterations = 600000

var ErrFormat = errors.New("secret: unknown password hash format")

func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	rand.Read(salt)
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", iterations, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

func CheckPassword(hash, password string) (bool, error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false, ErrFormat
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil || n < 100000 {
		return false, ErrFormat
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[2])
	if err != nil {
		return false, ErrFormat
	}
	want, err := enc.DecodeString(parts[3])
	if err != nil {
		return false, ErrFormat
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, n, len(want))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func NewTOTP() string {
	b := make([]byte, 20)
	rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func TOTPAt(seed string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(seed))
	if err != nil {
		return "", err
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(t.Unix()/30))
	m := hmac.New(sha1.New, key)
	m.Write(counter[:])
	sum := m.Sum(nil)
	o := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[o:]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code), nil
}

func CheckTOTP(seed, code string, now time.Time, lastStep int64) (int64, bool) {
	for _, skew := range []int64{0, -1, 1} {
		at := now.Add(time.Duration(skew) * 30 * time.Second)
		step := at.Unix() / 30
		if step <= lastStep {
			continue
		}
		want, err := TOTPAt(seed, at)
		if err == nil && subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return lastStep, false
}

func Token(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
