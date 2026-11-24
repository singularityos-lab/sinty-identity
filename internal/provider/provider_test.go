package provider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/singularityos-lab/sinty-identity/device"
	"github.com/singularityos-lab/sinty-identity/internal/secret"
	"github.com/singularityos-lab/sinty-identity/internal/store"
	"github.com/singularityos-lab/sinty-identity/jose"
)

type lab struct {
	t    *testing.T
	srv  *httptest.Server
	p    *Provider
	seed string
	now  time.Time
}

func newLab(t *testing.T) *lab {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	pw, _ := secret.HashPassword("Corr3ct horse")
	cs, _ := secret.HashPassword("it-secret")
	seed := secret.NewTOTP()
	st.Update(func(s *store.State) error {
		s.Users["alice"] = &store.User{Name: "alice", Password: pw, TOTP: seed}
		s.Users["bob"] = &store.User{Name: "bob", Password: pw}
		s.Clients["cloud"] = &store.Client{ID: "cloud", Name: "Sinty Cloud", Redirects: []string{"https://cloud.example/cb"}, MinLevel: store.LevelSecondFactor}
		s.Clients["it"] = &store.Client{ID: "it", Name: "Sinty IT", Secret: cs, Redirects: []string{"https://it.example/cb"}, MinLevel: store.LevelDevice}
		s.Clients["desktop"] = &store.Client{ID: "desktop", Name: "Sinty desktop", Redirects: []string{"http://127.0.0.1/"}, MinLevel: store.LevelSecondFactor, Offline: true}
		s.Clients["tablet"] = &store.Client{ID: "tablet", Name: "Another app", Redirects: []string{"http://127.0.0.1/"}, MinLevel: store.LevelSecondFactor, Offline: true}
		return nil
	})
	srv := httptest.NewUnstartedServer(nil)
	srv.Start()
	p, err := New(srv.URL, st, "")
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = p.Handler()
	t.Cleanup(srv.Close)
	l := &lab{t: t, srv: srv, p: p, seed: seed, now: time.Now()}
	p.Now = func() time.Time { return l.now }
	return l
}

type browser struct {
	l        *lab
	c        *http.Client
	verifier string
}

func (l *lab) browser() *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{l: l, c: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (b *browser) authorize(client, redirect string, extra url.Values) *http.Response {
	b.verifier = secret.Token(32)
	sum := sha256.Sum256([]byte(b.verifier))
	q := url.Values{"client_id": {client}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"openid"},
		"state": {"st8"}, "nonce": {"n0nce"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	for k, v := range extra {
		q[k] = v
	}
	resp, err := b.c.Get(b.l.srv.URL + "/authorize?" + q.Encode())
	if err != nil {
		b.l.t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func (b *browser) flow(client, redirect string) string {
	resp := b.authorize(client, redirect, nil)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || loc.Path != "/login" {
		b.l.t.Fatalf("authorize did not ask to sign in: %d %s", resp.StatusCode, loc)
	}
	return loc.Query().Get("flow")
}

func (b *browser) post(path string, in any) (int, map[string]any) {
	raw, _ := json.Marshal(in)
	req, _ := http.NewRequest(http.MethodPost, b.l.srv.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrfHeader, "1")
	resp, err := b.c.Do(req)
	if err != nil {
		b.l.t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (l *lab) clock() time.Time {
	return l.now
}

func (l *lab) otp() string {
	l.now = l.now.Add(30 * time.Second)
	code, _ := secret.TOTPAt(l.seed, l.now)
	return code
}

func codeOf(t *testing.T, next string) string {
	u, err := url.Parse(next)
	if err != nil || u.Query().Get("state") != "st8" || u.Query().Get("code") == "" {
		t.Fatalf("bad redirect %q", next)
	}
	return u.Query().Get("code")
}

func (b *browser) exchange(client, secretValue, redirect, code, verifier string) (int, map[string]any) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier}, "client_id": {client}}
	req, _ := http.NewRequest(http.MethodPost, b.l.srv.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secretValue != "" {
		req.SetBasicAuth(client, secretValue)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		b.l.t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (l *lab) keys() map[string]*ecdsa.PublicKey {
	resp, err := http.Get(l.srv.URL + "/jwks")
	if err != nil {
		l.t.Fatal(err)
	}
	defer resp.Body.Close()
	var set struct{ Keys []jose.JWK }
	json.NewDecoder(resp.Body).Decode(&set)
	out := map[string]*ecdsa.PublicKey{}
	for _, k := range set.Keys {
		pub, err := k.Public()
		if err != nil {
			l.t.Fatal(err)
		}
		out[k.Kid] = pub
	}
	return out
}

func (l *lab) idToken(tokens map[string]any, aud string) idClaims {
	var c idClaims
	if err := jose.Verify(tokens["id_token"].(string), l.keys(), &c); err != nil {
		l.t.Fatalf("id token: %v", err)
	}
	if c.Iss != l.srv.URL || c.Aud != aud || c.Nonce != "n0nce" || c.Sub == "" {
		l.t.Fatalf("id token claims %+v", c)
	}
	return c
}

func TestPasswordAndSecondFactor(t *testing.T) {
	l := newLab(t)
	b := l.browser()
	flow := b.flow("cloud", "https://cloud.example/cb")
	if s, out := b.post("/login/password", map[string]any{"flow": flow, "user": "alice", "password": "Corr3ct horse"}); s != http.StatusForbidden || out["error"] != "stronger" {
		t.Fatalf("password alone opened a client that needs two factors: %d %v", s, out)
	}
	s, out := b.post("/login/password", map[string]any{"flow": flow, "user": "alice", "password": "Corr3ct horse", "otp": l.otp()})
	if s != http.StatusOK {
		t.Fatalf("password and code refused: %d %v", s, out)
	}
	code := codeOf(t, out["next"].(string))
	if s, _ := b.exchange("cloud", "", "https://cloud.example/cb", code, "wrong-verifier-wrong-verifier-wrong-verifier"); s != http.StatusBadRequest {
		t.Fatal("a wrong PKCE verifier was accepted")
	}
	resp := b.authorize("cloud", "https://cloud.example/cb", nil)
	code = codeOf(t, resp.Header.Get("Location"))
	s, tokens := b.exchange("cloud", "", "https://cloud.example/cb", code, b.verifier)
	if s != http.StatusOK {
		t.Fatalf("token exchange: %d %v", s, tokens)
	}
	c := l.idToken(tokens, "cloud")
	if c.Acr != "sinty:2" || strings.Join(c.Amr, ",") != "pwd,otp" || c.Sub != "alice" {
		t.Fatalf("claims %+v", c)
	}
	if s, _ := b.exchange("cloud", "", "https://cloud.example/cb", code, b.verifier); s != http.StatusBadRequest {
		t.Fatal("an authorization code was used twice")
	}
	req, _ := http.NewRequest(http.MethodGet, l.srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["access_token"].(string))
	r, _ := http.DefaultClient.Do(req)
	var info map[string]any
	json.NewDecoder(r.Body).Decode(&info)
	r.Body.Close()
	if r.StatusCode != http.StatusOK || info["sub"] != "alice" {
		t.Fatalf("userinfo %d %v", r.StatusCode, info)
	}
	req.Header.Set("Authorization", "Bearer "+tokens["id_token"].(string))
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != http.StatusUnauthorized {
		t.Fatal("an ID token was accepted as an access token")
	}
}

func TestAuthorizeRefusals(t *testing.T) {
	l := newLab(t)
	b := l.browser()
	if resp := b.authorize("cloud", "https://evil.example/cb", nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatal("an unregistered redirect address was used")
	}
	resp := b.authorize("cloud", "https://cloud.example/cb", url.Values{"code_challenge_method": {"plain"}})
	if !strings.Contains(resp.Header.Get("Location"), "error=invalid_request") {
		t.Fatal("PKCE plain was accepted")
	}
}

func TestLockout(t *testing.T) {
	l := newLab(t)
	b := l.browser()
	for range lockAfter {
		flow := b.flow("cloud", "https://cloud.example/cb")
		b.post("/login/password", map[string]any{"flow": flow, "user": "alice", "password": "guess", "otp": "000000"})
	}
	flow := b.flow("cloud", "https://cloud.example/cb")
	if s, out := b.post("/login/password", map[string]any{"flow": flow, "user": "alice", "password": "Corr3ct horse", "otp": l.otp()}); s != http.StatusTooManyRequests {
		t.Fatalf("the right password went through during a lockout: %d %v", s, out)
	}
	l.now = l.now.Add(2 * lockBase)
	flow = b.flow("cloud", "https://cloud.example/cb")
	if s, out := b.post("/login/password", map[string]any{"flow": flow, "user": "alice", "password": "Corr3ct horse", "otp": l.otp()}); s != http.StatusOK {
		t.Fatalf("the lock did not expire: %d %v", s, out)
	}
	other := l.browser()
	if s, _ := other.post("/login/password", map[string]any{"flow": other.flow("cloud", "https://cloud.example/cb"), "user": "nobody", "password": "x"}); s != http.StatusUnauthorized {
		t.Fatal("unknown users must look like a wrong password")
	}
}

func TestDevicesEndToEnd(t *testing.T) {
	l := newLab(t)
	ctx := context.Background()
	b := l.browser()
	flow := b.flow("cloud", "https://cloud.example/cb")
	b.post("/login/password", map[string]any{"flow": flow, "user": "alice", "password": "Corr3ct horse", "otp": l.otp()})

	k1, _ := device.NewSoftwareKey()
	d1 := &device.Client{Issuer: l.srv.URL, Signer: k1, Now: l.clock}
	e1, err := d1.Enroll(ctx, "alice", "Laptop", "device")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d1.Pending(ctx); err == nil {
		t.Fatal("an unapproved device was trusted")
	}
	weak := l.browser()
	wf := weak.flow("cloud", "https://cloud.example/cb")
	if s, _ := weak.post("/login/password", map[string]any{"flow": wf, "user": "bob", "password": "Corr3ct horse"}); s != http.StatusForbidden {
		t.Fatal("bob has no second factor and must not reach the cloud")
	}
	if s, out := b.post("/account/enroll/approve", map[string]any{"enrollment": e1}); s != http.StatusOK {
		t.Fatalf("first device not approved from a strong session: %d %v", s, out)
	}

	k2, _ := device.NewSoftwareKey()
	d2 := &device.Client{Issuer: l.srv.URL, Signer: k2, Now: l.clock}
	e2, _ := d2.Enroll(ctx, "alice", "Sinty Key", "key")
	if s, out := b.post("/account/enroll/approve", map[string]any{"enrollment": e2}); s != http.StatusForbidden || out["error"] != "approve_from_device" {
		t.Fatalf("a password session added a second device: %d %v", s, out)
	}
	reqs, err := d1.Pending(ctx)
	if err != nil || len(reqs) != 1 || reqs[0].Kind != "enroll" || reqs[0].Name != "Sinty Key" {
		t.Fatalf("pending enrollment on the first device: %v %+v", err, reqs)
	}
	if err := d1.Answer(ctx, reqs[0], "", true); err != nil {
		t.Fatal(err)
	}
	if _, err := d2.Pending(ctx); err != nil {
		t.Fatalf("the key approved by the laptop is not trusted: %v", err)
	}

	it := l.browser()
	flow = it.flow("it", "https://it.example/cb")
	if s, _ := it.post("/login/password", map[string]any{"flow": flow, "user": "alice", "password": "Corr3ct horse", "otp": l.otp()}); s != http.StatusForbidden {
		t.Fatal("the IT console opened without a device")
	}
	_, out := it.post("/login/device", map[string]any{"flow": flow, "user": "alice"})
	reqs, _ = d2.Pending(ctx)
	if len(reqs) != 1 || reqs[0].Kind != "login" || reqs[0].Name != "Sinty IT" || reqs[0].Address == "" {
		t.Fatalf("login request on the key: %+v", reqs)
	}
	wrong := "00"
	if out["number"] == "00" {
		wrong = "01"
	}
	if err := d2.Answer(ctx, reqs[0], wrong, true); err == nil {
		t.Fatal("a wrong number was accepted")
	}
	if _, st := it.post("/login/status", map[string]any{"approval": out["approval"]}); st["status"] != "denied" {
		t.Fatalf("after a wrong number the browser must see a refusal: %v", st)
	}

	_, out = it.post("/login/device", map[string]any{"flow": flow, "user": "alice"})
	if _, st := it.post("/login/status", map[string]any{"approval": out["approval"]}); st["status"] != "pending" {
		t.Fatalf("status before the answer: %v", st)
	}
	reqs, _ = d1.Pending(ctx)
	evil, _ := device.Sign(k1, device.ApproveMessage("https://evil.example", reqs[0].ID, reqs[0].Nonce, reqs[0].Client, out["number"].(string), true))
	if s, _ := b.post("/device/approve", map[string]any{"approval": reqs[0].ID, "device": device.ID(k1), "number": out["number"], "allow": true, "sig": evil}); s != http.StatusUnauthorized {
		t.Fatal("a signature made for another site was accepted")
	}
	if err := d1.Answer(ctx, reqs[0], out["number"].(string), true); err != nil {
		t.Fatal(err)
	}
	_, st := it.post("/login/status", map[string]any{"approval": out["approval"]})
	if st["status"] != "approved" {
		t.Fatalf("status after the answer: %v", st)
	}
	code := codeOf(t, st["next"].(string))
	if s, _ := it.exchange("it", "wrong", "https://it.example/cb", code, it.verifier); s != http.StatusUnauthorized {
		t.Fatal("a confidential client was accepted with the wrong secret")
	}
	again := it.authorize("it", "https://it.example/cb", nil)
	s, tokens := it.exchange("it", "it-secret", "https://it.example/cb", codeOf(t, again.Header.Get("Location")), it.verifier)
	if s != http.StatusOK {
		t.Fatalf("token for the IT console: %d %v", s, tokens)
	}
	if c := l.idToken(tokens, "it"); c.Acr != "sinty:3" || strings.Join(c.Amr, ",") != "hwk,pin" {
		t.Fatalf("device sign-in claims %+v", c)
	}

	if err := d1.Revoke(ctx, device.ID(k2)); err != nil {
		t.Fatal(err)
	}
	if _, err := d2.Pending(ctx); err == nil {
		t.Fatal("a revoked key still answers")
	}
	k3, _ := device.NewSoftwareKey()
	d3 := &device.Client{Issuer: l.srv.URL, Signer: k3, Now: l.clock}
	e3, _ := d3.Enroll(ctx, "alice", "Stolen", "device")
	sig, _ := device.Sign(k2, device.EnrollMessage(l.srv.URL, e3, device.ID(k3)))
	if s, _ := b.post("/device/enroll/approve", map[string]any{"enrollment": e3, "device": device.ID(k2), "sig": sig}); s != http.StatusUnauthorized {
		t.Fatal("a revoked key approved a new device")
	}
}

func TestRedirectMatches(t *testing.T) {
	cases := []struct {
		reg, given string
		ok         bool
	}{
		{"https://app.example/cb", "https://app.example/cb", true},
		{"https://app.example/cb", "https://app.example/cb2", false},
		{"https://app.example/cb", "https://app.example:444/cb", false},
		{"http://127.0.0.1/cb", "http://127.0.0.1:53111/cb", true},
		{"http://127.0.0.1/cb", "http://127.0.0.1:53111/other", false},
		{"http://127.0.0.1/cb", "http://127.0.0.1.evil.example:53111/cb", false},
		{"http://127.0.0.1/cb", "http://localhost:53111/cb", false},
		{"http://127.0.0.1/cb", "http://user@127.0.0.1:53111/cb", false},
		{"http://127.0.0.1:9/cb", "http://127.0.0.1:10/cb", false},
	}
	for _, c := range cases {
		if RedirectMatches(c.reg, c.given) != c.ok {
			t.Errorf("%s vs %s: want %v", c.reg, c.given, c.ok)
		}
	}
}

func (l *lab) refresh(client, token string) (int, map[string]any) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "client_id": {client}}
	resp, err := http.PostForm(l.srv.URL+"/token", form)
	if err != nil {
		l.t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (l *lab) offlineSignIn(b *browser) map[string]any {
	flow := b.flow("desktop", "http://127.0.0.1:4711/")
	s, out := b.post("/login/password", map[string]any{"flow": flow, "user": "alice", "password": "Corr3ct horse", "otp": l.otp()})
	if s != http.StatusOK {
		l.t.Fatalf("sign-in refused: %d %v", s, out)
	}
	s, tokens := b.exchange("desktop", "", "http://127.0.0.1:4711/", codeOf(l.t, out["next"].(string)), b.verifier)
	if s != http.StatusOK {
		l.t.Fatalf("token exchange: %d %v", s, tokens)
	}
	return tokens
}

func TestRefreshTokens(t *testing.T) {
	l := newLab(t)
	b := l.browser()
	tokens := l.offlineSignIn(b)
	first, _ := tokens["refresh_token"].(string)
	if first == "" {
		t.Fatal("an offline client got no refresh token")
	}
	l.now = l.now.Add(20 * 24 * time.Hour)
	s, out := l.refresh("desktop", first)
	if s != http.StatusOK || out["refresh_token"] == first || out["refresh_token"] == "" {
		t.Fatalf("refresh: %d %v", s, out)
	}
	var c idClaims
	if err := jose.Verify(out["access_token"].(string), l.keys(), &c); err != nil || c.Sub != "alice" || c.Aud != "desktop" || c.Acr != "sinty:2" || c.Scope != "openid" {
		t.Fatalf("refreshed access token %+v %v", c, err)
	}
	second := out["refresh_token"].(string)
	for _, other := range []string{"cloud", "tablet"} {
		if s, _ := l.refresh(other, second); s != http.StatusBadRequest {
			t.Fatalf("%s used a refresh token issued to another client", other)
		}
	}
	s, out = l.refresh("desktop", second)
	if s != http.StatusOK {
		t.Fatalf("a refused attempt by another client spent the token: %d %v", s, out)
	}
	third := out["refresh_token"].(string)
	if s, _ := l.refresh("desktop", first); s != http.StatusBadRequest {
		t.Fatal("a rotated refresh token was accepted again")
	}
	if s, _ := l.refresh("desktop", third); s != http.StatusBadRequest {
		t.Fatal("reusing a rotated token did not revoke its family")
	}

	tokens = l.offlineSignIn(l.browser())
	l.now = l.now.Add(31 * 24 * time.Hour)
	if s, _ := l.refresh("desktop", tokens["refresh_token"].(string)); s != http.StatusBadRequest {
		t.Fatal("an expired refresh token was accepted")
	}

	tokens = l.offlineSignIn(l.browser())
	token := tokens["refresh_token"].(string)
	for range 3 {
		l.now = l.now.Add(29 * 24 * time.Hour)
		if s, out = l.refresh("desktop", token); s != http.StatusOK {
			t.Fatalf("sliding refresh refused: %d %v", s, out)
		}
		token = out["refresh_token"].(string)
	}
	l.now = l.now.Add(5 * 24 * time.Hour)
	if s, _ := l.refresh("desktop", token); s != http.StatusBadRequest {
		t.Fatal("a refresh family outlived its 90 days")
	}

	b = l.browser()
	l.now = l.now.Add(time.Minute)
	flow := b.flow("cloud", "https://cloud.example/cb")
	s, out = b.post("/login/password", map[string]any{"flow": flow, "user": "alice", "password": "Corr3ct horse", "otp": l.otp()})
	if s != http.StatusOK {
		t.Fatalf("cloud sign-in: %d %v", s, out)
	}
	if _, tokens := b.exchange("cloud", "", "https://cloud.example/cb", codeOf(t, out["next"].(string)), b.verifier); tokens["refresh_token"] != nil {
		t.Fatal("a client without offline access got a refresh token")
	}
}

func TestRefreshDropsDeviceLevel(t *testing.T) {
	l := newLab(t)
	token := "device-level-grant"
	l.p.Store.Update(func(s *store.State) error {
		s.Grants[grantKey(token)] = &store.Grant{Family: "f", User: "alice", Client: "desktop", Level: store.LevelDevice, AuthTime: l.now, Started: l.now, Expires: l.now.Add(time.Hour)}
		return nil
	})
	l.now = l.now.Add(time.Hour - time.Minute)
	s, out := l.refresh("desktop", token)
	var c idClaims
	if s != http.StatusOK || jose.Verify(out["access_token"].(string), l.keys(), &c) != nil || c.Acr != "sinty:3" {
		t.Fatalf("recent device sign-in lost its level: %d %+v", s, c)
	}
	l.now = l.now.Add(sessionTTL)
	s, out = l.refresh("desktop", out["refresh_token"].(string))
	if s != http.StatusOK || jose.Verify(out["access_token"].(string), l.keys(), &c) != nil || c.Acr != "sinty:2" {
		t.Fatalf("an old device sign-in kept its level: %d %+v", s, c)
	}
	l.p.Store.Update(func(s *store.State) error {
		s.Users["alice"].LockedUntil = l.now.Add(time.Hour)
		return nil
	})
	if s, _ := l.refresh("desktop", out["refresh_token"].(string)); s != http.StatusBadRequest {
		t.Fatal("a locked user refreshed a token")
	}
}
