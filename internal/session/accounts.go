package session

import (
	"context"
	"errors"

	"github.com/godbus/dbus/v5"
)

const (
	accountsName  = "dev.sinty.Accounts"
	accountsPath  = dbus.ObjectPath("/dev/sinty/Accounts")
	accountsIface = "dev.sinty.Accounts"
)

// BusAccounts reads the organization account from the desktop accounts
// service on the session bus.
type BusAccounts struct {
	Conn *dbus.Conn
}

func (b *BusAccounts) obj() dbus.BusObject {
	return b.Conn.Object(accountsName, accountsPath)
}

func str(m map[string]dbus.Variant, key string) string {
	s, _ := m[key].Value().(string)
	return s
}

func (b *BusAccounts) Sinty(ctx context.Context) (*Account, error) {
	var list []map[string]dbus.Variant
	if err := b.obj().CallWithContext(ctx, accountsIface+".ListAccounts", 0).Store(&list); err != nil {
		return nil, err
	}
	for _, m := range list {
		if str(m, "provider") != "sinty" || str(m, "server") == "" || str(m, "identity") == "" {
			continue
		}
		a := &Account{ID: str(m, "id"), Issuer: str(m, "server"), User: str(m, "identity")}
		for _, key := range []string{"enabled", "capabilities"} {
			if caps, _ := m[key].Value().([]string); len(caps) > 0 {
				a.Capability = caps[0]
				break
			}
		}
		return a, nil
	}
	return nil, nil
}

func (b *BusAccounts) Token(ctx context.Context, a *Account) (string, error) {
	if a.Capability == "" {
		return "", errors.New("the account grants no service")
	}
	var token string
	var expires int32
	err := b.obj().CallWithContext(ctx, accountsIface+".GetAccessToken", 0, a.ID, a.Capability, false).Store(&token, &expires)
	return token, err
}

// Watch sends on the returned channel whenever an account is added,
// removed or changed.
func (b *BusAccounts) Watch() (<-chan struct{}, error) {
	for _, member := range []string{"AccountAdded", "AccountRemoved", "AccountChanged"} {
		if err := b.Conn.AddMatchSignal(dbus.WithMatchInterface(accountsIface), dbus.WithMatchMember(member)); err != nil {
			return nil, err
		}
	}
	sigs := make(chan *dbus.Signal, 8)
	b.Conn.Signal(sigs)
	wake := make(chan struct{}, 1)
	go func() {
		for s := range sigs {
			if s.Path != accountsPath {
				continue
			}
			select {
			case wake <- struct{}{}:
			default:
			}
		}
	}()
	return wake, nil
}
