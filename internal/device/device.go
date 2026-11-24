package device

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/singularityos-lab/sinty-identity/internal/jose"
)

type Signer interface {
	Public() *ecdsa.PublicKey
	SignDigest(digest []byte) ([]byte, error)
}

type SoftwareKey struct {
	key *ecdsa.PrivateKey
}

func NewSoftwareKey() (*SoftwareKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &SoftwareKey{key: k}, nil
}

func LoadSoftwareKey(path string) (*SoftwareKey, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		k, err := NewSoftwareKey()
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(k.key)
		if err != nil {
			return nil, err
		}
		return k, os.WriteFile(path, der, 0o600)
	}
	if err != nil {
		return nil, err
	}
	k, err := x509.ParseECPrivateKey(raw)
	if err != nil {
		return nil, err
	}
	return &SoftwareKey{key: k}, nil
}

func (k *SoftwareKey) Public() *ecdsa.PublicKey {
	return &k.key.PublicKey
}

func (k *SoftwareKey) SignDigest(digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, k.key, digest)
	if err != nil {
		return nil, err
	}
	return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...), nil
}

func ID(s Signer) string {
	return jose.Thumbprint(s.Public())
}

func message(kind string, fields ...string) []byte {
	return []byte("sinty-identity " + kind + " v1\n" + strings.Join(fields, "\n"))
}

func PollMessage(issuer, device string, at int64) []byte {
	return message("poll", issuer, device, strconv.FormatInt(at, 10))
}

func ApproveMessage(issuer, approval, nonce, client, number string, allow bool) []byte {
	verdict := "deny"
	if allow {
		verdict = "allow"
	}
	return message("approve", issuer, approval, nonce, client, number, verdict)
}

func EnrollMessage(issuer, enrollment, newDevice string) []byte {
	return message("enroll", issuer, enrollment, newDevice)
}

func RevokeMessage(issuer, target string, at int64) []byte {
	return message("revoke", issuer, target, strconv.FormatInt(at, 10))
}

func Sign(s Signer, msg []byte) (string, error) {
	sum := sha256.Sum256(msg)
	sig, err := s.SignDigest(sum[:])
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func Verify(pub *ecdsa.PublicKey, msg []byte, sig string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(raw) != 64 {
		return false
	}
	sum := sha256.Sum256(msg)
	return ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:]))
}

type Request struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"`
	Client  string    `json:"client,omitempty"`
	Name    string    `json:"name"`
	Address string    `json:"address,omitempty"`
	Nonce   string    `json:"nonce"`
	Created time.Time `json:"created"`
}

type Client struct {
	Issuer string
	Signer Signer
	HTTP   *http.Client
	Now    func() time.Time
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Issuer+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("%s: %s (%d)", path, e.Error, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) Enroll(ctx context.Context, user, name, kind string) (string, error) {
	var out struct {
		Enrollment string `json:"enrollment"`
	}
	err := c.post(ctx, "/device/enroll", map[string]any{"user": user, "name": name, "kind": kind, "public": jose.PublicJWK(c.Signer.Public())}, &out)
	return out.Enrollment, err
}

func (c *Client) Pending(ctx context.Context) ([]Request, error) {
	at := c.now().Unix()
	sig, err := Sign(c.Signer, PollMessage(c.Issuer, ID(c.Signer), at))
	if err != nil {
		return nil, err
	}
	var out struct {
		Requests []Request `json:"requests"`
	}
	err = c.post(ctx, "/device/pending", map[string]any{"device": ID(c.Signer), "time": at, "sig": sig}, &out)
	return out.Requests, err
}

func (c *Client) Answer(ctx context.Context, r Request, number string, allow bool) error {
	if r.Kind == "enroll" {
		if !allow {
			return c.post(ctx, "/device/enroll/deny", map[string]any{"enrollment": r.ID, "device": ID(c.Signer)}, nil)
		}
		sig, err := Sign(c.Signer, EnrollMessage(c.Issuer, r.ID, r.Nonce))
		if err != nil {
			return err
		}
		return c.post(ctx, "/device/enroll/approve", map[string]any{"enrollment": r.ID, "device": ID(c.Signer), "sig": sig}, nil)
	}
	sig, err := Sign(c.Signer, ApproveMessage(c.Issuer, r.ID, r.Nonce, r.Client, number, allow))
	if err != nil {
		return err
	}
	return c.post(ctx, "/device/approve", map[string]any{"approval": r.ID, "device": ID(c.Signer), "number": number, "allow": allow, "sig": sig}, nil)
}

func (c *Client) Revoke(ctx context.Context, target string) error {
	at := c.now().Unix()
	sig, err := Sign(c.Signer, RevokeMessage(c.Issuer, target, at))
	if err != nil {
		return err
	}
	return c.post(ctx, "/device/revoke", map[string]any{"device": ID(c.Signer), "target": target, "time": at, "sig": sig}, nil)
}
