package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/singularityos-lab/sinty-identity/internal/jose"
)

const (
	LevelNone = iota
	LevelPassword
	LevelSecondFactor
	LevelDevice
)

type User struct {
	Name        string    `json:"name"`
	Password    string    `json:"password,omitempty"`
	TOTP        string    `json:"totp,omitempty"`
	TOTPStep    int64     `json:"totp_step,omitempty"`
	Failures    int       `json:"failures,omitempty"`
	LockedUntil time.Time `json:"locked_until,omitzero"`
}

type Device struct {
	ID         string    `json:"id"`
	User       string    `json:"user"`
	Name       string    `json:"name"`
	Kind       string    `json:"kind"`
	Public     jose.JWK  `json:"public"`
	Approved   time.Time `json:"approved,omitzero"`
	ApprovedBy string    `json:"approved_by,omitempty"`
	Revoked    time.Time `json:"revoked,omitzero"`
}

func (d *Device) Trusted() bool {
	return !d.Approved.IsZero() && d.Revoked.IsZero()
}

type Client struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Secret    string   `json:"secret,omitempty"`
	Redirects []string `json:"redirects"`
	MinLevel  int      `json:"min_level"`
}

type State struct {
	SigningKey []byte             `json:"signing_key"`
	Users      map[string]*User   `json:"users"`
	Devices    map[string]*Device `json:"devices"`
	Clients    map[string]*Client `json:"clients"`
}

type Store struct {
	path  string
	mu    sync.Mutex
	state State
}

var ErrNotFound = errors.New("store: not found")

func Open(path string) (*Store, error) {
	s := &Store{path: path}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(raw, &s.state); err != nil {
			return nil, err
		}
	}
	if s.state.Users == nil {
		s.state.Users = map[string]*User{}
	}
	if s.state.Devices == nil {
		s.state.Devices = map[string]*Device{}
	}
	if s.state.Clients == nil {
		s.state.Clients = map[string]*Client{}
	}
	if len(s.state.SigningKey) == 0 {
		k, err := jose.NewKey()
		if err != nil {
			return nil, err
		}
		if s.state.SigningKey, err = k.Marshal(); err != nil {
			return nil, err
		}
		if err := s.save(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) Key() (*jose.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return jose.ParseKey(s.state.SigningKey)
}

func (s *Store) View(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(&s.state)
}

func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.state); err != nil {
		return err
	}
	return s.save()
}

func (s *Store) save() error {
	raw, err := json.MarshalIndent(&s.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

func (st *State) TrustedDevices(user string) []*Device {
	var out []*Device
	for _, d := range st.Devices {
		if d.User == user && d.Trusted() {
			out = append(out, d)
		}
	}
	return out
}
