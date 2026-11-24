package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
)

var ErrInvalid = errors.New("jose: invalid token")

type Key struct {
	ID      string
	Private *ecdsa.PrivateKey
}

func NewKey() (*Key, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Key{ID: Thumbprint(&k.PublicKey), Private: k}, nil
}

func ParseKey(der []byte) (*Key, error) {
	k, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, err
	}
	if k.Curve != elliptic.P256() {
		return nil, ErrInvalid
	}
	return &Key{ID: Thumbprint(&k.PublicKey), Private: k}, nil
}

func (k *Key) Marshal() ([]byte, error) {
	return x509.MarshalECPrivateKey(k.Private)
}

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

func coord(b *big.Int) string {
	return b64(b.FillBytes(make([]byte, 32)))
}

func PublicJWK(p *ecdsa.PublicKey) JWK {
	return JWK{Kty: "EC", Crv: "P-256", X: coord(p.X), Y: coord(p.Y)}
}

func Thumbprint(p *ecdsa.PublicKey) string {
	j := PublicJWK(p)
	raw := `{"crv":"P-256","kty":"EC","x":"` + j.X + `","y":"` + j.Y + `"}`
	sum := sha256.Sum256([]byte(raw))
	return b64(sum[:])
}

func (j JWK) Public() (*ecdsa.PublicKey, error) {
	if j.Kty != "EC" || j.Crv != "P-256" {
		return nil, ErrInvalid
	}
	x, err1 := base64.RawURLEncoding.DecodeString(j.X)
	y, err2 := base64.RawURLEncoding.DecodeString(j.Y)
	if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
		return nil, ErrInvalid
	}
	raw := append([]byte{4}, append(x, y...)...)
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
}

func (k *Key) JWK() JWK {
	j := PublicJWK(&k.Private.PublicKey)
	j.Kid, j.Use, j.Alg = k.ID, "sig", "ES256"
	return j
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func Sign(k *Key, claims any) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": k.ID})
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64(header) + "." + b64(body)
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k.Private, sum[:])
	if err != nil {
		return "", err
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + b64(sig), nil
}

func Verify(token string, keys map[string]*ecdsa.PublicKey, claims any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ErrInvalid
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(raw, &header) != nil || header.Alg != "ES256" {
		return ErrInvalid
	}
	pub := keys[header.Kid]
	if pub == nil {
		return ErrInvalid
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return ErrInvalid
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return ErrInvalid
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ErrInvalid
	}
	return json.Unmarshal(body, claims)
}
