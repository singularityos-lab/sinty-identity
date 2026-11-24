package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/singularityos-lab/sinty-identity/device"
	"github.com/singularityos-lab/sinty-identity/internal/provider"
	"github.com/singularityos-lab/sinty-identity/internal/secret"
	"github.com/singularityos-lab/sinty-identity/internal/store"
)

const defaultState = "/var/lib/sinty-identity/state.json"

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  sinty-identity serve -issuer URL [-listen ADDR] [-state FILE] [-ui DIR] [-cert FILE -key FILE]
  sinty-identity user add NAME [-totp]          password is read from standard input
  sinty-identity user totp NAME                 prints a new authenticator seed
  sinty-identity client add ID -name NAME -redirect URL [-redirect URL] [-min-level 1|2|3] [-confidential]
  sinty-identity device list [USER]
  sinty-identity device revoke ID
  sinty-identity agent enroll -issuer URL -key FILE -user NAME -name NAME [-kind device|key]
  sinty-identity agent requests -issuer URL -key FILE
  sinty-identity agent approve -issuer URL -key FILE ID [NUMBER]
  sinty-identity agent deny -issuer URL -key FILE ID
`)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "user":
		err = user(os.Args[2:])
	case "client":
		err = client(os.Args[2:])
	case "device":
		err = devices(os.Args[2:])
	case "agent":
		err = agent(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sinty-identity:", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	issuer := fs.String("issuer", "", "public address of this provider")
	listen := fs.String("listen", ":8443", "address to listen on")
	state := fs.String("state", defaultState, "state file")
	ui := fs.String("ui", "/usr/share/sintyui", "sintyui directory")
	cert := fs.String("cert", "", "TLS certificate")
	key := fs.String("key", "", "TLS key")
	fs.Parse(args)
	if *issuer == "" {
		return errors.New("-issuer is required")
	}
	if !strings.HasPrefix(*issuer, "https://") && !strings.HasPrefix(*issuer, "http://localhost") && !strings.HasPrefix(*issuer, "http://127.0.0.1") {
		return errors.New("the issuer must be https outside of a local test")
	}
	st, err := store.Open(*state)
	if err != nil {
		return err
	}
	p, err := provider.New(*issuer, st, *ui)
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: *listen, Handler: p.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shut)
	}()
	if *cert != "" {
		err = srv.ListenAndServeTLS(*cert, *key)
	} else {
		err = srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func open(path string) (*store.Store, error) {
	if path == "" {
		path = defaultState
	}
	return store.Open(path)
}

func stateFlag(fs *flag.FlagSet) *string {
	return fs.String("state", os.Getenv("SINTY_IDENTITY_STATE"), "state file")
}

func validName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func user(args []string) error {
	if len(args) < 2 {
		usage()
	}
	fs := flag.NewFlagSet("user", flag.ExitOnError)
	state := stateFlag(fs)
	withTOTP := fs.Bool("totp", false, "also create an authenticator seed")
	verb, name := args[0], args[1]
	fs.Parse(args[2:])
	if !validName(name) {
		return fmt.Errorf("invalid user name %q", name)
	}
	st, err := open(*state)
	if err != nil {
		return err
	}
	switch verb {
	case "add":
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return errors.New("no password on standard input")
		}
		password := strings.TrimRight(line, "\r\n")
		if len(password) < 8 {
			return errors.New("the password needs at least 8 characters")
		}
		hash, err := secret.HashPassword(password)
		if err != nil {
			return err
		}
		seed := ""
		if *withTOTP {
			seed = secret.NewTOTP()
		}
		err = st.Update(func(s *store.State) error {
			if s.Users[name] != nil {
				return fmt.Errorf("user %s exists", name)
			}
			s.Users[name] = &store.User{Name: name, Password: hash, TOTP: seed}
			return nil
		})
		if err == nil && seed != "" {
			fmt.Println(seed)
		}
		return err
	case "totp":
		seed := secret.NewTOTP()
		err := st.Update(func(s *store.State) error {
			u := s.Users[name]
			if u == nil {
				return store.ErrNotFound
			}
			u.TOTP, u.TOTPStep = seed, 0
			return nil
		})
		if err == nil {
			fmt.Println(seed)
		}
		return err
	}
	usage()
	return nil
}

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

func client(args []string) error {
	if len(args) < 2 || args[0] != "add" {
		usage()
	}
	id := args[1]
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	state := stateFlag(fs)
	name := fs.String("name", "", "name shown on the sign-in page and on devices")
	level := fs.Int("min-level", store.LevelSecondFactor, "weakest sign-in accepted")
	confidential := fs.Bool("confidential", false, "issue a client secret")
	var redirects list
	fs.Var(&redirects, "redirect", "allowed redirect address")
	fs.Parse(args[2:])
	if !validName(id) || *name == "" || len(redirects) == 0 || *level < store.LevelPassword || *level > store.LevelDevice {
		return errors.New("a client needs an id, a name, a redirect address and a level from 1 to 3")
	}
	for _, r := range redirects {
		if !strings.HasPrefix(r, "https://") && !strings.HasPrefix(r, "http://127.0.0.1") && !strings.HasPrefix(r, "http://localhost") {
			return fmt.Errorf("redirect %s must be https", r)
		}
	}
	st, err := open(*state)
	if err != nil {
		return err
	}
	value, hash := "", ""
	if *confidential {
		value = secret.Token(32)
		if hash, err = secret.HashPassword(value); err != nil {
			return err
		}
	}
	err = st.Update(func(s *store.State) error {
		s.Clients[id] = &store.Client{ID: id, Name: *name, Secret: hash, Redirects: redirects, MinLevel: *level}
		return nil
	})
	if err == nil && value != "" {
		fmt.Println(value)
	}
	return err
}

func devices(args []string) error {
	if len(args) < 1 {
		usage()
	}
	fs := flag.NewFlagSet("device", flag.ExitOnError)
	state := stateFlag(fs)
	verb := args[0]
	fs.Parse(args[1:])
	st, err := open(*state)
	if err != nil {
		return err
	}
	switch verb {
	case "list":
		var out []store.Device
		st.View(func(s *store.State) error {
			for _, d := range s.Devices {
				if fs.NArg() == 0 || d.User == fs.Arg(0) {
					out = append(out, *d)
				}
			}
			return nil
		})
		slices.SortFunc(out, func(a, b store.Device) int { return strings.Compare(a.User+a.Name, b.User+b.Name) })
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	case "revoke":
		if fs.NArg() != 1 {
			usage()
		}
		return provider.Revoke(st, "", fs.Arg(0), time.Now())
	}
	usage()
	return nil
}

func agent(args []string) error {
	if len(args) < 1 {
		usage()
	}
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	issuer := fs.String("issuer", "", "identity provider")
	keyPath := fs.String("key", "", "device key file")
	userName := fs.String("user", "", "user name")
	name := fs.String("name", "", "device name")
	kind := fs.String("kind", "device", "device or key")
	verb := args[0]
	fs.Parse(args[1:])
	if *issuer == "" || *keyPath == "" {
		return errors.New("-issuer and -key are required")
	}
	k, err := device.LoadSoftwareKey(*keyPath)
	if err != nil {
		return err
	}
	c := &device.Client{Issuer: strings.TrimRight(*issuer, "/"), Signer: k}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch verb {
	case "enroll":
		id, err := c.Enroll(ctx, *userName, *name, *kind)
		if err != nil {
			return err
		}
		fmt.Printf("enrollment %s for device %s: approve it from a device you already trust\n", id, device.ID(k))
		return nil
	case "requests":
		reqs, err := c.Pending(ctx)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(reqs)
	case "approve", "deny":
		if fs.NArg() < 1 {
			usage()
		}
		reqs, err := c.Pending(ctx)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(reqs, func(r device.Request) bool { return r.ID == fs.Arg(0) })
		if i < 0 {
			return errors.New("no such request")
		}
		if verb == "approve" && reqs[i].Kind == "login" && fs.NArg() < 2 {
			return errors.New("type the number shown on the sign-in page")
		}
		return c.Answer(ctx, reqs[i], fs.Arg(1), verb == "approve")
	}
	usage()
	return nil
}
