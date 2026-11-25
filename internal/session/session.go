// Package session runs in the person's desktop session. It finds their
// organization account, enrolls this device as one of their sign-in devices
// and keeps the list of sign-ins waiting for an answer.
package session

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/singularityos-lab/sinty-identity/device"
)

const (
	NoAccount = "no-account"
	Waiting   = "waiting"
	Trusted   = "trusted"
	Refused   = "refused"
	Offline   = "offline"
)

var (
	ErrGone        = errors.New("the request is no longer waiting")
	ErrWrongNumber = errors.New("the number does not match the sign-in page")
	ErrNotTrusted  = errors.New("this device is not trusted yet")
)

type Account struct {
	ID         string
	Issuer     string
	User       string
	Capability string
}

type Accounts interface {
	// Sinty returns the organization account, or nil without one.
	Sinty(ctx context.Context) (*Account, error)
	// Token returns an access token of the account.
	Token(ctx context.Context, a *Account) (string, error)
}

type Status struct {
	State        string
	Organization string
	Device       string
	Requests     []device.Request
}

type Agent struct {
	Accounts Accounts
	Signer   device.Signer
	HTTP     *http.Client
	Name     string
	Now      func() time.Time
	Changed  func(Status)
	// Wait is how long a poll of a trusted device waits for a request.
	Wait time.Duration

	mu         sync.Mutex
	status     Status
	client     *device.Client
	enrollment string
	enrolled   time.Time
}

// enrollmentLife matches how long the provider keeps an enrollment.
const enrollmentLife = 10 * time.Minute

func (a *Agent) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Agent) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.status
	s.Requests = slices.Clone(s.Requests)
	return s
}

func (a *Agent) set(s Status) {
	a.mu.Lock()
	same := a.status.State == s.State && a.status.Organization == s.Organization && a.status.Device == s.Device &&
		slices.EqualFunc(a.status.Requests, s.Requests, func(x, y device.Request) bool { return x.ID == y.ID })
	a.status = s
	a.mu.Unlock()
	if !same && a.Changed != nil {
		a.Changed(s)
	}
}

func (a *Agent) clientFor(issuer string) *device.Client {
	a.mu.Lock()
	defer a.mu.Unlock()
	issuer = strings.TrimRight(issuer, "/")
	if a.client == nil || a.client.Issuer != issuer {
		a.client = &device.Client{Issuer: issuer, Signer: a.Signer, HTTP: a.HTTP, Now: a.Now}
		a.enrollment = ""
	}
	return a.client
}

// Step looks at the account and the provider once, without waiting for
// requests.
func (a *Agent) Step(ctx context.Context) {
	a.step(ctx, 0)
}

func (a *Agent) step(ctx context.Context, wait time.Duration) {
	acct, err := a.Accounts.Sinty(ctx)
	if err != nil || acct == nil {
		a.set(Status{State: NoAccount})
		return
	}
	c := a.clientFor(acct.Issuer)
	st := Status{Organization: c.Issuer, Device: device.ID(a.Signer)}
	reqs, err := c.PendingWait(ctx, wait)
	var se *device.StatusError
	switch {
	case err == nil:
		a.mu.Lock()
		a.enrollment = ""
		a.mu.Unlock()
		st.State, st.Requests = Trusted, reqs
		a.set(st)
		return
	case !errors.As(err, &se) || se.Status != http.StatusUnauthorized:
		st.State = Offline
		a.set(st)
		return
	}
	a.mu.Lock()
	waiting := a.enrollment != "" && a.now().Sub(a.enrolled) < enrollmentLife
	a.mu.Unlock()
	if waiting {
		st.State = Waiting
		a.set(st)
		return
	}
	token, _ := a.Accounts.Token(ctx, acct)
	id, trusted, err := c.EnrollWithToken(ctx, token, acct.User, a.Name, "device")
	switch {
	case err == nil && trusted:
		a.step(ctx, 0)
		return
	case err == nil:
		a.mu.Lock()
		a.enrollment, a.enrolled = id, a.now()
		a.mu.Unlock()
		st.State = Waiting
	case errors.As(err, &se):
		st.State = Refused
	default:
		st.State = Offline
	}
	a.set(st)
}

// Retry drops a waiting enrollment and enrolls again, after the person
// signed in again so that a fresh sign-in can trust a first device.
func (a *Agent) Retry(ctx context.Context) {
	a.mu.Lock()
	a.enrollment = ""
	a.mu.Unlock()
	a.Step(ctx)
}

// Answer allows or refuses a waiting request. Allowing asks for the PIN.
func (a *Agent) Answer(ctx context.Context, id, number string, allow bool) error {
	a.mu.Lock()
	c := a.client
	var req *device.Request
	for i := range a.status.Requests {
		if a.status.Requests[i].ID == id {
			r := a.status.Requests[i]
			req = &r
		}
	}
	a.mu.Unlock()
	if c == nil || req == nil {
		return ErrGone
	}
	err := c.Answer(ctx, *req, strings.TrimSpace(number), allow)
	var se *device.StatusError
	if errors.As(err, &se) {
		switch se.Code {
		case "wrong_number":
			err = ErrWrongNumber
		case "unknown":
			err = ErrGone
		case "untrusted":
			err = ErrNotTrusted
		}
	}
	a.Step(ctx)
	return err
}

// Run steps again at once while the device is trusted, since each poll
// waits on the provider, and every interval otherwise. Without an account it
// waits for wake, which the accounts service sends when one is added.
func (a *Agent) Run(ctx context.Context, every time.Duration, wake <-chan struct{}) {
	for {
		step, cancel := context.WithTimeout(ctx, a.Wait+30*time.Second)
		a.step(step, a.Wait)
		cancel()
		var timer <-chan time.Time
		switch a.Status().State {
		case Trusted:
			timer = time.After(time.Second)
		case NoAccount:
		default:
			timer = time.After(every)
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-timer:
		}
	}
}
