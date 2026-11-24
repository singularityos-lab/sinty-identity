package rp

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/singularityos-lab/sinty-identity/jose"
)

var (
	ErrState  = errors.New("rp: the sign-in answer does not match the request")
	ErrToken  = errors.New("rp: invalid token")
	ErrWeak   = errors.New("rp: the sign-in is weaker than this service needs")
	ErrRemote = errors.New("rp: the identity provider refused the request")
)

type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	MinLevel     int
	HTTP         *http.Client
	Now          func() time.Time
}

type Claims struct {
	Subject  string
	Name     string
	Level    int
	Methods  []string
	AuthTime time.Time
	Expires  time.Time
}

type Request struct {
	URL      string
	State    string
	Nonce    string
	Verifier string
}

type RP struct {
	cfg       Config
	authorize string
	token     string
	jwksURL   string

	mu      sync.Mutex
	keys    map[string]*ecdsa.PublicKey
	fetched time.Time
}

func New(ctx context.Context, cfg Config) (*RP, error) {
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	var d struct {
		Issuer    string   `json:"issuer"`
		Authorize string   `json:"authorization_endpoint"`
		Token     string   `json:"token_endpoint"`
		JWKS      string   `json:"jwks_uri"`
		Methods   []string `json:"code_challenge_methods_supported"`
	}
	if err := getJSON(ctx, cfg.HTTP, cfg.Issuer+"/.well-known/openid-configuration", &d); err != nil {
		return nil, err
	}
	if d.Issuer != cfg.Issuer || !slices.Contains(d.Methods, "S256") {
		return nil, fmt.Errorf("rp: %s is not the provider it claims to be", cfg.Issuer)
	}
	r := &RP{cfg: cfg, authorize: d.Authorize, token: d.Token, jwksURL: d.JWKS}
	if err := r.refresh(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

func getJSON(ctx context.Context, c *http.Client, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s answered %d", ErrRemote, u, resp.StatusCode)
	}
	return json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(v)
}

func (r *RP) refresh(ctx context.Context) error {
	var set struct {
		Keys []jose.JWK `json:"keys"`
	}
	if err := getJSON(ctx, r.cfg.HTTP, r.jwksURL, &set); err != nil {
		return err
	}
	keys := map[string]*ecdsa.PublicKey{}
	for _, k := range set.Keys {
		if pub, err := k.Public(); err == nil && k.Kid != "" {
			keys[k.Kid] = pub
		}
	}
	r.mu.Lock()
	r.keys, r.fetched = keys, r.cfg.Now()
	r.mu.Unlock()
	return nil
}

func token(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (r *RP) Begin(acr ...string) Request {
	req := Request{State: token(24), Nonce: token(24), Verifier: token(32)}
	sum := sha256.Sum256([]byte(req.Verifier))
	q := url.Values{
		"client_id": {r.cfg.ClientID}, "redirect_uri": {r.cfg.RedirectURL}, "response_type": {"code"}, "scope": {"openid"},
		"state": {req.State}, "nonce": {req.Nonce}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
	}
	if len(acr) > 0 {
		q.Set("acr_values", strings.Join(acr, " "))
	}
	req.URL = r.authorize + "?" + q.Encode()
	return req
}

type claims struct {
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	Aud      string   `json:"aud"`
	Exp      int64    `json:"exp"`
	AuthTime int64    `json:"auth_time"`
	Nonce    string   `json:"nonce"`
	Acr      string   `json:"acr"`
	Amr      []string `json:"amr"`
	Name     string   `json:"preferred_username"`
	Scope    string   `json:"scope"`
}

func level(acr string) int {
	var n int
	if _, err := fmt.Sscanf(acr, "sinty:%d", &n); err != nil {
		return 0
	}
	return n
}

func (r *RP) verify(ctx context.Context, raw string) (claims, error) {
	var c claims
	r.mu.Lock()
	keys := r.keys
	stale := r.cfg.Now().Sub(r.fetched) > time.Minute
	r.mu.Unlock()
	err := jose.Verify(raw, keys, &c)
	if err != nil && stale {
		if r.refresh(ctx) == nil {
			r.mu.Lock()
			keys = r.keys
			r.mu.Unlock()
			err = jose.Verify(raw, keys, &c)
		}
	}
	if err != nil {
		return c, ErrToken
	}
	if c.Iss != r.cfg.Issuer || c.Aud != r.cfg.ClientID || c.Sub == "" || r.cfg.Now().Unix() >= c.Exp {
		return c, ErrToken
	}
	if level(c.Acr) < r.cfg.MinLevel {
		return c, ErrWeak
	}
	return c, nil
}

func public(c claims) Claims {
	return Claims{Subject: c.Sub, Name: c.Name, Level: level(c.Acr), Methods: c.Amr, AuthTime: time.Unix(c.AuthTime, 0), Expires: time.Unix(c.Exp, 0)}
}

func (r *RP) Finish(ctx context.Context, req Request, answer url.Values) (Claims, error) {
	if answer.Get("error") != "" {
		return Claims{}, fmt.Errorf("%w: %s", ErrRemote, answer.Get("error"))
	}
	if answer.Get("state") == "" || answer.Get("state") != req.State || (answer.Has("iss") && answer.Get("iss") != r.cfg.Issuer) {
		return Claims{}, ErrState
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {answer.Get("code")}, "redirect_uri": {r.cfg.RedirectURL}, "code_verifier": {req.Verifier}, "client_id": {r.cfg.ClientID}}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, r.token, strings.NewReader(form.Encode()))
	if err != nil {
		return Claims{}, err
	}
	hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if r.cfg.ClientSecret != "" {
		hr.SetBasicAuth(r.cfg.ClientID, r.cfg.ClientSecret)
	}
	resp, err := r.cfg.HTTP.Do(hr)
	if err != nil {
		return Claims{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Claims{}, fmt.Errorf("%w: token endpoint answered %d", ErrRemote, resp.StatusCode)
	}
	var out struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&out); err != nil {
		return Claims{}, err
	}
	c, err := r.verify(ctx, out.IDToken)
	if err != nil {
		return Claims{}, err
	}
	if c.Nonce != req.Nonce || c.Scope != "" {
		return Claims{}, ErrToken
	}
	return public(c), nil
}

func (r *RP) Access(ctx context.Context, bearer string) (Claims, error) {
	c, err := r.verify(ctx, bearer)
	if err != nil {
		return Claims{}, err
	}
	if c.Scope != "openid" {
		return Claims{}, ErrToken
	}
	return public(c), nil
}
