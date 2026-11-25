package provider

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/singularityos-lab/sinty-identity/device"
	"github.com/singularityos-lab/sinty-identity/internal/secret"
	"github.com/singularityos-lab/sinty-identity/internal/store"
	"github.com/singularityos-lab/sinty-identity/jose"
)

const (
	cookieName  = "sinty_session"
	flowTTL     = 10 * time.Minute
	approvalTTL = 2 * time.Minute
	codeTTL     = time.Minute
	sessionTTL  = 8 * time.Hour
	tokenTTL    = 10 * time.Minute
	refreshTTL  = 30 * 24 * time.Hour
	familyTTL   = 90 * 24 * time.Hour
	pollSkew    = 2 * time.Minute
	lockAfter   = 5
	lockBase    = time.Minute
	maxLock     = time.Hour
	csrfHeader  = "X-Sinty-Request"
)

var amrs = map[int][]string{
	store.LevelPassword:     {"pwd"},
	store.LevelSecondFactor: {"pwd", "otp"},
	store.LevelDevice:       {"hwk", "pin"},
}

type flow struct {
	client    *store.Client
	redirect  string
	state     string
	nonce     string
	challenge string
	minLevel  int
	expires   time.Time
}

type session struct {
	user     string
	level    int
	authTime time.Time
	expires  time.Time
}

type approval struct {
	id      string
	flow    string
	user    string
	number  string
	nonce   string
	address string
	created time.Time
	verdict string
	device  string
}

type enrollment struct {
	id      string
	device  *store.Device
	created time.Time
}

type code struct {
	flow    *flow
	user    string
	level   int
	auth    time.Time
	expires time.Time
}

type Provider struct {
	Issuer   string
	Services map[string]string
	Store    *store.Store
	UI       string
	Now      func() time.Time

	mu          sync.Mutex
	flows       map[string]*flow
	sessions    map[string]*session
	approvals   map[string]*approval
	enrollments map[string]*enrollment
	codes       map[string]*code
	key         *jose.Key
}

func New(issuer string, st *store.Store, ui string) (*Provider, error) {
	k, err := st.Key()
	if err != nil {
		return nil, err
	}
	return &Provider{
		Issuer: strings.TrimRight(issuer, "/"), Store: st, UI: ui, Now: time.Now,
		flows: map[string]*flow{}, sessions: map[string]*session{}, approvals: map[string]*approval{},
		enrollments: map[string]*enrollment{}, codes: map[string]*code{}, key: k,
	}, nil
}

func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /login/password", p.loginPassword)
	mux.HandleFunc("POST /login/device", p.loginDevice)
	mux.HandleFunc("POST /login/status", p.loginStatus)
	mux.HandleFunc("POST /token", p.token)
	mux.HandleFunc("GET /userinfo", p.userinfo)
	mux.HandleFunc("POST /device/enroll", p.enroll)
	mux.HandleFunc("POST /device/pending", p.pending)
	mux.HandleFunc("POST /device/approve", p.approve)
	mux.HandleFunc("POST /device/enroll/approve", p.enrollApproveByDevice)
	mux.HandleFunc("POST /device/enroll/deny", p.enrollDeny)
	mux.HandleFunc("POST /device/revoke", p.revokeByDevice)
	mux.HandleFunc("POST /account/enroll/approve", p.enrollApproveBySession)
	mux.HandleFunc("GET /login", p.loginPage)
	mux.HandleFunc("GET /login.js", p.loginScript)
	if p.UI != "" {
		mux.Handle("GET /ui/", http.StripPrefix("/ui/", http.FileServer(http.Dir(p.UI))))
	}
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, e string) {
	writeJSON(w, status, map[string]string{"error": e})
}

func readJSON(r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return false
	}
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<16)).Decode(v) == nil
}

func (p *Provider) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                p.Issuer,
		"authorization_endpoint":                p.Issuer + "/authorize",
		"token_endpoint":                        p.Issuer + "/token",
		"userinfo_endpoint":                     p.Issuer + "/userinfo",
		"jwks_uri":                              p.Issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"scopes_supported":                      []string{"openid", "profile"},
		"acr_values_supported":                  []string{Acr(store.LevelPassword), Acr(store.LevelSecondFactor), Acr(store.LevelDevice)},
		"claims_supported":                      []string{"sub", "acr", "amr", "auth_time", "nonce", "preferred_username"},
		"sinty_services":                        p.services(),
	})
}

func (p *Provider) services() map[string]string {
	if p.Services == nil {
		return map[string]string{}
	}
	return p.Services
}

func Acr(level int) string {
	return fmt.Sprintf("sinty:%d", level)
}

func levelOf(acr string) int {
	var n int
	if _, err := fmt.Sscanf(acr, "sinty:%d", &n); err != nil || n < 0 || n > store.LevelDevice {
		return 0
	}
	return n
}

func (p *Provider) jwks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"keys": []jose.JWK{p.key.JWK()}})
}

func redirectError(w http.ResponseWriter, r *http.Request, to, state, e string) {
	u, _ := url.Parse(to)
	q := u.Query()
	q.Set("error", e)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var client *store.Client
	p.Store.View(func(st *store.State) error {
		if c := st.Clients[q.Get("client_id")]; c != nil {
			cp := *c
			client = &cp
		}
		return nil
	})
	redirect := q.Get("redirect_uri")
	if client == nil || !slices.ContainsFunc(client.Redirects, func(r string) bool { return RedirectMatches(r, redirect) }) {
		http.Error(w, "unknown client or redirect address", http.StatusBadRequest)
		return
	}
	state := q.Get("state")
	if q.Get("response_type") != "code" {
		redirectError(w, r, redirect, state, "unsupported_response_type")
		return
	}
	if !slices.Contains(strings.Fields(q.Get("scope")), "openid") {
		redirectError(w, r, redirect, state, "invalid_scope")
		return
	}
	if q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) < 43 {
		redirectError(w, r, redirect, state, "invalid_request")
		return
	}
	need := client.MinLevel
	for _, a := range strings.Fields(q.Get("acr_values")) {
		need = max(need, levelOf(a))
	}
	need = max(need, store.LevelPassword)
	f := &flow{client: client, redirect: redirect, state: state, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), minLevel: need, expires: p.Now().Add(flowTTL)}
	if s := p.session(r); s != nil && s.level >= need && q.Get("prompt") != "login" {
		http.Redirect(w, r, p.finish(f, s), http.StatusFound)
		return
	}
	id := secret.Token(24)
	p.mu.Lock()
	p.gc()
	p.flows[id] = f
	p.mu.Unlock()
	http.Redirect(w, r, "/login?flow="+id, http.StatusFound)
}

func (p *Provider) gc() {
	now := p.Now()
	for k, v := range p.flows {
		if now.After(v.expires) {
			delete(p.flows, k)
		}
	}
	for k, v := range p.sessions {
		if now.After(v.expires) {
			delete(p.sessions, k)
		}
	}
	for k, v := range p.approvals {
		if now.Sub(v.created) > approvalTTL {
			delete(p.approvals, k)
		}
	}
	for k, v := range p.enrollments {
		if now.Sub(v.created) > flowTTL {
			delete(p.enrollments, k)
		}
	}
	for k, v := range p.codes {
		if now.After(v.expires) {
			delete(p.codes, k)
		}
	}
}

func (p *Provider) session(r *http.Request) *session {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.sessions[c.Value]
	if s == nil || p.Now().After(s.expires) {
		return nil
	}
	cp := *s
	return &cp
}

func (p *Provider) startSession(w http.ResponseWriter, user string, level int) *session {
	id := secret.Token(32)
	now := p.Now()
	s := &session{user: user, level: level, authTime: now, expires: now.Add(sessionTTL)}
	p.mu.Lock()
	p.sessions[id] = s
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: id, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(p.Issuer, "https://"), SameSite: http.SameSiteLaxMode, MaxAge: int(sessionTTL / time.Second)})
	return s
}

func (p *Provider) finish(f *flow, s *session) string {
	c := secret.Token(32)
	p.mu.Lock()
	p.codes[c] = &code{flow: f, user: s.user, level: s.level, auth: s.authTime, expires: p.Now().Add(codeTTL)}
	p.mu.Unlock()
	u, _ := url.Parse(f.redirect)
	q := u.Query()
	q.Set("code", c)
	if f.state != "" {
		q.Set("state", f.state)
	}
	q.Set("iss", p.Issuer)
	u.RawQuery = q.Encode()
	return u.String()
}

func (p *Provider) takeFlow(id string) *flow {
	p.mu.Lock()
	defer p.mu.Unlock()
	f := p.flows[id]
	if f == nil || p.Now().After(f.expires) {
		return nil
	}
	return f
}

var errLocked = errors.New("locked")

func (p *Provider) checkPassword(user, password, otp string) (int, error) {
	level := store.LevelNone
	err := p.Store.Update(func(st *store.State) error {
		u := st.Users[user]
		now := p.Now()
		if u == nil {
			secret.CheckPassword("pbkdf2-sha256$600000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", password)
			return nil
		}
		if now.Before(u.LockedUntil) {
			return errLocked
		}
		ok, err := secret.CheckPassword(u.Password, password)
		if err != nil || !ok {
			u.Failures++
			if u.Failures >= lockAfter {
				u.LockedUntil = now.Add(min(lockBase<<min(u.Failures-lockAfter, 6), maxLock))
			}
			return nil
		}
		level = store.LevelPassword
		if u.TOTP != "" && otp != "" {
			step, ok := secret.CheckTOTP(u.TOTP, otp, now, u.TOTPStep)
			if !ok {
				level = store.LevelNone
				u.Failures++
				if u.Failures >= lockAfter {
					u.LockedUntil = now.Add(min(lockBase<<min(u.Failures-lockAfter, 6), maxLock))
				}
				return nil
			}
			u.TOTPStep = step
			level = store.LevelSecondFactor
		}
		u.Failures = 0
		u.LockedUntil = time.Time{}
		return nil
	})
	return level, err
}

func (p *Provider) loginPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Flow     string `json:"flow"`
		User     string `json:"user"`
		Password string `json:"password"`
		OTP      string `json:"otp"`
	}
	if r.Header.Get(csrfHeader) == "" || !readJSON(r, &in) {
		fail(w, http.StatusBadRequest, "invalid_request")
		return
	}
	f := p.takeFlow(in.Flow)
	if f == nil {
		fail(w, http.StatusBadRequest, "expired")
		return
	}
	level, err := p.checkPassword(in.User, in.Password, in.OTP)
	if errors.Is(err, errLocked) {
		fail(w, http.StatusTooManyRequests, "locked")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "server_error")
		return
	}
	if level == store.LevelNone {
		fail(w, http.StatusUnauthorized, "wrong")
		return
	}
	if level < f.minLevel {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "stronger", "need": f.minLevel, "have": level})
		return
	}
	s := p.startSession(w, in.User, level)
	p.mu.Lock()
	delete(p.flows, in.Flow)
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"next": p.finish(f, s)})
}

func clientAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (p *Provider) loginDevice(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Flow string `json:"flow"`
		User string `json:"user"`
	}
	if r.Header.Get(csrfHeader) == "" || !readJSON(r, &in) {
		fail(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if p.takeFlow(in.Flow) == nil {
		fail(w, http.StatusBadRequest, "expired")
		return
	}
	a := &approval{id: secret.Token(18), flow: in.Flow, user: in.User, number: fmt.Sprintf("%02d", rand.IntN(100)), nonce: secret.Token(18), address: clientAddress(r), created: p.Now()}
	p.mu.Lock()
	p.gc()
	p.approvals[a.id] = a
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"approval": a.id, "number": a.number})
}

func (p *Provider) loginStatus(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Approval string `json:"approval"`
	}
	if r.Header.Get(csrfHeader) == "" || !readJSON(r, &in) {
		fail(w, http.StatusBadRequest, "invalid_request")
		return
	}
	p.mu.Lock()
	a := p.approvals[in.Approval]
	var f *flow
	if a != nil {
		f = p.flows[a.flow]
	}
	p.mu.Unlock()
	switch {
	case a == nil || f == nil || p.Now().Sub(a.created) > approvalTTL:
		writeJSON(w, http.StatusOK, map[string]string{"status": "expired"})
	case a.verdict == "":
		writeJSON(w, http.StatusOK, map[string]string{"status": "pending"})
	case a.verdict == "deny":
		p.mu.Lock()
		delete(p.approvals, a.id)
		p.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{"status": "denied"})
	default:
		if store.LevelDevice < f.minLevel {
			writeJSON(w, http.StatusOK, map[string]string{"status": "denied"})
			return
		}
		p.mu.Lock()
		delete(p.approvals, a.id)
		delete(p.flows, a.flow)
		p.mu.Unlock()
		s := p.startSession(w, a.user, store.LevelDevice)
		writeJSON(w, http.StatusOK, map[string]string{"status": "approved", "next": p.finish(f, s)})
	}
}

func (p *Provider) trustedDevice(id string) (*store.Device, *ecdsa.PublicKey) {
	var d *store.Device
	p.Store.View(func(st *store.State) error {
		if x := st.Devices[id]; x != nil && x.Trusted() {
			cp := *x
			d = &cp
		}
		return nil
	})
	if d == nil {
		return nil, nil
	}
	pub, err := d.Public.Public()
	if err != nil {
		return nil, nil
	}
	return d, pub
}

func (p *Provider) pending(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Device string `json:"device"`
		Time   int64  `json:"time"`
		Sig    string `json:"sig"`
	}
	if !readJSON(r, &in) {
		fail(w, http.StatusBadRequest, "invalid_request")
		return
	}
	d, pub := p.trustedDevice(in.Device)
	at := time.Unix(in.Time, 0)
	if d == nil || p.Now().Sub(at).Abs() > pollSkew || !device.Verify(pub, device.PollMessage(p.Issuer, in.Device, in.Time), in.Sig) {
		fail(w, http.StatusUnauthorized, "untrusted")
		return
	}
	out := []device.Request{}
	p.mu.Lock()
	p.gc()
	for _, a := range p.approvals {
		f := p.flows[a.flow]
		if a.user == d.User && a.verdict == "" && f != nil {
			out = append(out, device.Request{ID: a.id, Kind: "login", Client: f.client.ID, Name: f.client.Name, Address: a.address, Nonce: a.nonce, Created: a.created})
		}
	}
	for _, e := range p.enrollments {
		if e.device.User == d.User {
			out = append(out, device.Request{ID: e.id, Kind: "enroll", Name: e.device.Name, Nonce: e.device.ID, Created: e.created})
		}
	}
	p.mu.Unlock()
	slices.SortFunc(out, func(a, b device.Request) int { return a.Created.Compare(b.Created) })
	writeJSON(w, http.StatusOK, map[string]any{"requests": out})
}

func (p *Provider) approve(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Approval string `json:"approval"`
		Device   string `json:"device"`
		Number   string `json:"number"`
		Allow    bool   `json:"allow"`
		Sig      string `json:"sig"`
	}
	if !readJSON(r, &in) {
		fail(w, http.StatusBadRequest, "invalid_request")
		return
	}
	d, pub := p.trustedDevice(in.Device)
	if d == nil {
		fail(w, http.StatusUnauthorized, "untrusted")
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	a := p.approvals[in.Approval]
	if a == nil || a.verdict != "" || a.user != d.User || p.Now().Sub(a.created) > approvalTTL {
		fail(w, http.StatusNotFound, "unknown")
		return
	}
	f := p.flows[a.flow]
	if f == nil {
		fail(w, http.StatusNotFound, "unknown")
		return
	}
	if !device.Verify(pub, device.ApproveMessage(p.Issuer, a.id, a.nonce, f.client.ID, in.Number, in.Allow), in.Sig) {
		fail(w, http.StatusUnauthorized, "bad_signature")
		return
	}
	if in.Allow && subtle.ConstantTimeCompare([]byte(in.Number), []byte(a.number)) != 1 {
		a.verdict = "deny"
		fail(w, http.StatusForbidden, "wrong_number")
		return
	}
	a.device = d.ID
	a.verdict = "deny"
	if in.Allow {
		a.verdict = "allow"
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": a.verdict})
}

var kinds = []string{"device", "key"}

func (p *Provider) enroll(w http.ResponseWriter, r *http.Request) {
	var in struct {
		User   string   `json:"user"`
		Name   string   `json:"name"`
		Kind   string   `json:"kind"`
		Public jose.JWK `json:"public"`
	}
	if !readJSON(r, &in) || !slices.Contains(kinds, in.Kind) || in.Name == "" || len(in.Name) > 64 {
		fail(w, http.StatusBadRequest, "invalid_request")
		return
	}
	pub, err := in.Public.Public()
	if err != nil {
		fail(w, http.StatusBadRequest, "invalid_key")
		return
	}
	id := jose.Thumbprint(pub)
	known := false
	p.Store.View(func(st *store.State) error {
		known = st.Users[in.User] != nil
		if st.Devices[id] != nil {
			known = false
		}
		return nil
	})
	if !known {
		fail(w, http.StatusBadRequest, "refused")
		return
	}
	e := &enrollment{id: secret.Token(18), created: p.Now(), device: &store.Device{ID: id, User: in.User, Name: in.Name, Kind: in.Kind, Public: jose.PublicJWK(pub)}}
	if by := p.firstDeviceGrant(r, in.User); by != "" {
		if err := p.admit(e, by); err != nil {
			fail(w, http.StatusConflict, "conflict")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"device": id, "trusted": true})
		return
	}
	p.mu.Lock()
	p.gc()
	p.enrollments[e.id] = e
	p.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"enrollment": e.id, "device": id})
}

// firstDeviceGrant admits the first device of a person when the enrollment
// carries an access token from a fresh second-factor sign-in on a public
// client, the desktop that is enrolling. Confidential clients are services,
// which must not add devices with a token they received.
func (p *Provider) firstDeviceGrant(r *http.Request, user string) string {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	var c idClaims
	if !ok || jose.Verify(tok, p.Keys(), &c) != nil || c.Iss != p.Issuer || c.Scope != "openid" || c.Sub != user {
		return ""
	}
	now := p.Now()
	if now.Unix() > c.Exp || levelOf(c.Acr) < store.LevelSecondFactor || now.Sub(time.Unix(c.AuthTime, 0)) > flowTTL {
		return ""
	}
	by := ""
	p.Store.View(func(st *store.State) error {
		cl := st.Clients[c.Aud]
		if cl != nil && cl.Secret == "" && len(st.TrustedDevices(user)) == 0 {
			by = "account:" + cl.ID
		}
		return nil
	})
	return by
}

func (p *Provider) admit(e *enrollment, by string) error {
	return p.Store.Update(func(st *store.State) error {
		if st.Devices[e.device.ID] != nil {
			return errors.New("already enrolled")
		}
		d := *e.device
		d.Approved = p.Now()
		d.ApprovedBy = by
		st.Devices[d.ID] = &d
		return nil
	})
}

func (p *Provider) takeEnrollment(id string) *enrollment {
	p.mu.Lock()
	defer p.mu.Unlock()
	e := p.enrollments[id]
	if e == nil || p.Now().Sub(e.created) > flowTTL {
		return nil
	}
	delete(p.enrollments, id)
	return e
}

func (p *Provider) enrollApproveByDevice(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enrollment string `json:"enrollment"`
		Device     string `json:"device"`
		Sig        string `json:"sig"`
	}
	if !readJSON(r, &in) {
		fail(w, http.StatusBadRequest, "invalid_request")
		return
	}
	d, pub := p.trustedDevice(in.Device)
	p.mu.Lock()
	e := p.enrollments[in.Enrollment]
	p.mu.Unlock()
	if d == nil || e == nil || e.device.User != d.User || !device.Verify(pub, device.EnrollMessage(p.Issuer, e.id, e.device.ID), in.Sig) {
		fail(w, http.StatusUnauthorized, "untrusted")
		return
	}
	if p.takeEnrollment(in.Enrollment) == nil {
		fail(w, http.StatusNotFound, "unknown")
		return
	}
	if err := p.admit(e, d.ID); err != nil {
		fail(w, http.StatusConflict, "conflict")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"device": e.device.ID})
}

func (p *Provider) enrollDeny(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enrollment string `json:"enrollment"`
		Device     string `json:"device"`
	}
	if !readJSON(r, &in) {
		fail(w, http.StatusBadRequest, "invalid_request")
		return
	}
	d, _ := p.trustedDevice(in.Device)
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.enrollments[in.Enrollment]; d != nil && e != nil && e.device.User == d.User {
		delete(p.enrollments, in.Enrollment)
	}
	writeJSON(w, http.StatusOK, map[string]string{})
}

func (p *Provider) enrollApproveBySession(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enrollment string `json:"enrollment"`
	}
	s := p.session(r)
	if r.Header.Get(csrfHeader) == "" || !readJSON(r, &in) {
		fail(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if s == nil || s.level < store.LevelSecondFactor {
		fail(w, http.StatusUnauthorized, "stronger")
		return
	}
	p.mu.Lock()
	e := p.enrollments[in.Enrollment]
	p.mu.Unlock()
	if e == nil || e.device.User != s.user {
		fail(w, http.StatusNotFound, "unknown")
		return
	}
	has := false
	p.Store.View(func(st *store.State) error {
		has = len(st.TrustedDevices(s.user)) > 0
		return nil
	})
	if has {
		fail(w, http.StatusForbidden, "approve_from_device")
		return
	}
	if p.takeEnrollment(in.Enrollment) == nil {
		fail(w, http.StatusNotFound, "unknown")
		return
	}
	if err := p.admit(e, "session"); err != nil {
		fail(w, http.StatusConflict, "conflict")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"device": e.device.ID})
}

func (p *Provider) revokeByDevice(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Device string `json:"device"`
		Target string `json:"target"`
		Time   int64  `json:"time"`
		Sig    string `json:"sig"`
	}
	if !readJSON(r, &in) {
		fail(w, http.StatusBadRequest, "invalid_request")
		return
	}
	d, pub := p.trustedDevice(in.Device)
	if d == nil || p.Now().Sub(time.Unix(in.Time, 0)).Abs() > pollSkew || !device.Verify(pub, device.RevokeMessage(p.Issuer, in.Target, in.Time), in.Sig) {
		fail(w, http.StatusUnauthorized, "untrusted")
		return
	}
	err := Revoke(p.Store, d.User, in.Target, p.Now())
	if err != nil {
		fail(w, http.StatusNotFound, "unknown")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"revoked": in.Target})
}

func Revoke(st *store.Store, user, target string, now time.Time) error {
	return st.Update(func(s *store.State) error {
		t := s.Devices[target]
		if t == nil || (user != "" && t.User != user) {
			return store.ErrNotFound
		}
		if t.Revoked.IsZero() {
			t.Revoked = now
		}
		return nil
	})
}

type idClaims struct {
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	Aud      string   `json:"aud"`
	Exp      int64    `json:"exp"`
	Iat      int64    `json:"iat"`
	AuthTime int64    `json:"auth_time"`
	Nonce    string   `json:"nonce,omitempty"`
	Acr      string   `json:"acr"`
	Amr      []string `json:"amr"`
	Name     string   `json:"preferred_username"`
	Scope    string   `json:"scope,omitempty"`
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, http.StatusBadRequest, "invalid_request")
		return
	}
	clientID, clientSecret, basic := r.BasicAuth()
	if !basic {
		clientID, clientSecret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		p.exchangeCode(w, r, clientID, clientSecret)
	case "refresh_token":
		p.exchangeRefresh(w, r, clientID, clientSecret)
	default:
		fail(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func clientAllowed(c *store.Client, clientSecret string) bool {
	if c.Secret == "" {
		return true
	}
	ok, err := secret.CheckPassword(c.Secret, clientSecret)
	return err == nil && ok
}

func (p *Provider) exchangeCode(w http.ResponseWriter, r *http.Request, clientID, clientSecret string) {
	p.mu.Lock()
	c := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	p.mu.Unlock()
	if c == nil || p.Now().After(c.expires) || c.flow.client.ID != clientID || c.flow.redirect != r.PostForm.Get("redirect_uri") {
		fail(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if !clientAllowed(c.flow.client, clientSecret) {
		fail(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(c.flow.challenge)) != 1 {
		fail(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	refresh := ""
	if c.flow.client.Offline {
		var err error
		now := p.Now()
		refresh, err = p.grant(&store.Grant{Family: secret.Token(12), User: c.user, Client: clientID, Level: c.level, AuthTime: c.auth, Started: now})
		if err != nil {
			fail(w, http.StatusInternalServerError, "server_error")
			return
		}
	}
	p.issue(w, clientID, c.user, c.level, c.auth, c.flow.nonce, refresh)
}

func grantKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (p *Provider) grant(g *store.Grant) (string, error) {
	token := secret.Token(32)
	now := p.Now()
	g.Expires = now.Add(refreshTTL)
	if end := g.Started.Add(familyTTL); end.Before(g.Expires) {
		g.Expires = end
	}
	return token, p.Store.Update(func(s *store.State) error {
		for k, old := range s.Grants {
			if now.After(old.Expires) {
				delete(s.Grants, k)
			}
		}
		s.Grants[grantKey(token)] = g
		return nil
	})
}

func (p *Provider) exchangeRefresh(w http.ResponseWriter, r *http.Request, clientID, clientSecret string) {
	now := p.Now()
	var next *store.Grant
	refused := "invalid_grant"
	p.Store.Update(func(s *store.State) error {
		key := grantKey(r.PostForm.Get("refresh_token"))
		g := s.Grants[key]
		c := s.Clients[clientID]
		switch {
		case g == nil:
			return nil
		case c == nil || g.Client != clientID:
			return nil
		case !clientAllowed(c, clientSecret):
			refused = "invalid_client"
			return nil
		case g.Rotated:
			for k, other := range s.Grants {
				if other.Family == g.Family {
					delete(s.Grants, k)
				}
			}
			return nil
		case now.After(g.Expires) || !c.Offline:
			delete(s.Grants, key)
			return nil
		}
		u := s.Users[g.User]
		if u == nil || now.Before(u.LockedUntil) {
			return nil
		}
		g.Rotated = true
		level := g.Level
		if level > store.LevelSecondFactor && now.Sub(g.AuthTime) > sessionTTL {
			level = store.LevelSecondFactor
		}
		next = &store.Grant{Family: g.Family, User: g.User, Client: g.Client, Level: level, AuthTime: g.AuthTime, Started: g.Started}
		return nil
	})
	if next == nil {
		status := http.StatusBadRequest
		if refused == "invalid_client" {
			status = http.StatusUnauthorized
		}
		fail(w, status, refused)
		return
	}
	refresh, err := p.grant(next)
	if err != nil {
		fail(w, http.StatusInternalServerError, "server_error")
		return
	}
	p.issue(w, clientID, next.User, next.Level, next.AuthTime, "", refresh)
}

func (p *Provider) issue(w http.ResponseWriter, clientID, user string, level int, authTime time.Time, nonce, refresh string) {
	now := p.Now()
	claims := idClaims{Iss: p.Issuer, Sub: user, Aud: clientID, Iat: now.Unix(), Exp: now.Add(tokenTTL).Unix(), AuthTime: authTime.Unix(), Nonce: nonce, Acr: Acr(level), Amr: amrs[level], Name: user}
	idToken, err := jose.Sign(p.key, claims)
	if err != nil {
		fail(w, http.StatusInternalServerError, "server_error")
		return
	}
	claims.Nonce = ""
	claims.Scope = "openid"
	access, err := jose.Sign(p.key, claims)
	if err != nil {
		fail(w, http.StatusInternalServerError, "server_error")
		return
	}
	out := map[string]any{"access_token": access, "id_token": idToken, "token_type": "Bearer", "expires_in": int(tokenTTL / time.Second)}
	if refresh != "" {
		out["refresh_token"] = refresh
	}
	writeJSON(w, http.StatusOK, out)
}

func (p *Provider) Keys() map[string]*ecdsa.PublicKey {
	return map[string]*ecdsa.PublicKey{p.key.ID: &p.key.Private.PublicKey}
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	var c idClaims
	if !ok || jose.Verify(tok, p.Keys(), &c) != nil || c.Iss != p.Issuer || c.Scope != "openid" || p.Now().Unix() > c.Exp {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		fail(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sub": c.Sub, "preferred_username": c.Name, "acr": c.Acr})
}

func RedirectMatches(registered, given string) bool {
	if registered == given {
		return true
	}
	r, err1 := url.Parse(registered)
	g, err2 := url.Parse(given)
	if err1 != nil || err2 != nil || r.Scheme != "http" || g.Scheme != "http" || r.Port() != "" {
		return false
	}
	if r.Hostname() != "127.0.0.1" && r.Hostname() != "[::1]" && r.Hostname() != "::1" {
		return false
	}
	return g.Hostname() == r.Hostname() && g.Port() != "" && g.Path == r.Path && g.RawQuery == r.RawQuery && g.Fragment == "" && g.User == nil
}
