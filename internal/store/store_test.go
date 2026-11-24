package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPersistAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	k1, _ := s.Key()
	if err := s.Update(func(st *State) error {
		st.Users["alice"] = &User{Name: "alice"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state mode %v %v", fi.Mode(), err)
	}
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := again.Key()
	if k1.ID != k2.ID {
		t.Fatal("signing key changed on reload")
	}
	again.View(func(st *State) error {
		if st.Users["alice"] == nil {
			t.Fatal("user lost")
		}
		return nil
	})
}
