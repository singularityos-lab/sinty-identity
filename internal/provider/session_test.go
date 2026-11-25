package provider

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/singularityos-lab/sinty-identity/device"
	agent "github.com/singularityos-lab/sinty-identity/internal/session"
)

type fakeAccounts struct {
	issuer string
	token  string
}

func (f *fakeAccounts) Sinty(context.Context) (*agent.Account, error) {
	if f.issuer == "" {
		return nil, nil
	}
	return &agent.Account{ID: "acct", Issuer: f.issuer, User: "alice", Capability: "files"}, nil
}

func (f *fakeAccounts) Token(context.Context, *agent.Account) (string, error) {
	return f.token, nil
}

func newAgent(l *lab, accounts agent.Accounts, name string) *agent.Agent {
	k, _ := device.NewSoftwareKey()
	return &agent.Agent{Accounts: accounts, Signer: k, Name: name, Now: l.clock}
}

func TestSessionAgent(t *testing.T) {
	l := newLab(t)
	ctx := context.Background()
	tokens := l.offlineSignIn(l.browser())

	none := newAgent(l, &fakeAccounts{}, "Laptop")
	none.Step(ctx)
	if s := none.Status(); s.State != agent.NoAccount {
		t.Fatalf("without an account: %+v", s)
	}

	changes := 0
	laptop := newAgent(l, &fakeAccounts{issuer: l.srv.URL + "/", token: tokens["access_token"].(string)}, "Laptop")
	laptop.Changed = func(agent.Status) { changes++ }
	laptop.Step(ctx)
	if s := laptop.Status(); s.State != agent.Trusted || s.Organization != l.srv.URL || changes != 1 {
		t.Fatalf("first device after a fresh sign-in: %+v changes=%d", s, changes)
	}

	phone := newAgent(l, &fakeAccounts{issuer: l.srv.URL}, "Phone")
	phone.Step(ctx)
	if s := phone.Status(); s.State != agent.Waiting {
		t.Fatalf("a second device without a trusted one's approval: %+v", s)
	}
	phone.Step(ctx)
	laptop.Step(ctx)
	reqs := laptop.Status().Requests
	if len(reqs) != 1 || reqs[0].Kind != "enroll" || reqs[0].Name != "Phone" {
		t.Fatalf("one enrollment for the phone, not one per step: %+v", reqs)
	}
	if err := laptop.Answer(ctx, reqs[0].ID, "", true); err != nil {
		t.Fatal(err)
	}
	if s := laptop.Status(); len(s.Requests) != 0 {
		t.Fatalf("the answered request is still listed: %+v", s.Requests)
	}
	phone.Step(ctx)
	if s := phone.Status(); s.State != agent.Trusted {
		t.Fatalf("the phone after the laptop approved it: %+v", s)
	}

	poller := &device.Client{Issuer: l.srv.URL, Signer: laptop.Signer, Now: l.clock}
	got := make(chan []device.Request, 1)
	started := time.Now()
	go func() {
		r, _ := poller.PendingWait(ctx, 20*time.Second)
		got <- r
	}()
	time.Sleep(300 * time.Millisecond)
	it := l.browser()
	flow := it.flow("it", "https://it.example/cb")
	_, out := it.post("/login/device", map[string]any{"flow": flow, "user": "alice"})
	select {
	case r := <-got:
		if len(r) != 1 || r[0].Kind != "login" || time.Since(started) > 5*time.Second {
			t.Fatalf("the waiting poll did not wake for the sign-in: %+v after %v", r, time.Since(started))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the waiting poll never answered")
	}

	laptop.Step(ctx)
	reqs = laptop.Status().Requests
	if len(reqs) != 1 || reqs[0].Name != "Sinty IT" {
		t.Fatalf("sign-in request on the laptop: %+v", reqs)
	}
	wrong := "00"
	if out["number"] == "00" {
		wrong = "01"
	}
	if err := laptop.Answer(ctx, reqs[0].ID, wrong, true); !errors.Is(err, agent.ErrWrongNumber) {
		t.Fatalf("a wrong number: %v", err)
	}
	if err := laptop.Answer(ctx, reqs[0].ID, out["number"].(string), true); !errors.Is(err, agent.ErrGone) {
		t.Fatalf("a request refused after a wrong number must be gone: %v", err)
	}

	_, out = it.post("/login/device", map[string]any{"flow": flow, "user": "alice"})
	laptop.Step(ctx)
	reqs = laptop.Status().Requests
	if err := laptop.Answer(ctx, reqs[0].ID, " "+out["number"].(string)+" ", true); err != nil {
		t.Fatal(err)
	}
	if _, st := it.post("/login/status", map[string]any{"approval": out["approval"]}); st["status"] != "approved" {
		t.Fatalf("status after the laptop allowed the sign-in: %v", st)
	}
}
