package session

import (
	"context"
	"errors"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"

	"github.com/singularityos-lab/sinty-identity/device"
	"github.com/singularityos-lab/sinty-identity/device/keyd"
)

const (
	Name  = "dev.sinty.IdentityAgent1"
	Path  = dbus.ObjectPath("/dev/sinty/IdentityAgent1")
	Iface = "dev.sinty.IdentityAgent1"
)

// Request is a waiting request as the bus carries it.
type Request struct {
	ID      string
	Kind    string
	Name    string
	Address string
	Created int64
}

func busRequests(reqs []device.Request) []Request {
	out := make([]Request, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, Request{ID: r.ID, Kind: r.Kind, Name: r.Name, Address: r.Address, Created: r.Created.Unix()})
	}
	return out
}

type busAgent struct {
	agent *Agent
}

func busError(name string, err error) *dbus.Error {
	return dbus.NewError(Iface+".Error."+name, []any{err.Error()})
}

// Answer allows or refuses a request. number is the one shown on the
// sign-in page; allowing asks the person for their PIN.
func (b *busAgent) Answer(id, number string, allow bool) *dbus.Error {
	ctx, cancel := context.WithTimeout(context.Background(), keyd.ConfirmTimeout+30*time.Second)
	defer cancel()
	err := b.agent.Answer(ctx, id, number, allow)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, keyd.ErrNotConfirmed):
		return busError("NotConfirmed", err)
	case errors.Is(err, keyd.ErrLockedOut):
		return busError("LockedOut", err)
	case errors.Is(err, ErrWrongNumber):
		return busError("WrongNumber", err)
	case errors.Is(err, ErrGone):
		return busError("Gone", err)
	}
	return busError("Failed", err)
}

// Retry enrolls this device again, after the person signed in again.
func (b *busAgent) Retry() *dbus.Error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b.agent.Retry(ctx)
	return nil
}

// Export publishes the agent on conn. Changes to its status update the
// properties and emit PropertiesChanged.
func Export(conn *dbus.Conn, a *Agent, hardware bool) error {
	st := a.Status()
	props, err := prop.Export(conn, Path, prop.Map{Iface: {
		"State":        {Value: st.State, Emit: prop.EmitTrue},
		"Organization": {Value: st.Organization, Emit: prop.EmitTrue},
		"Device":       {Value: st.Device, Emit: prop.EmitTrue},
		"Hardware":     {Value: hardware, Emit: prop.EmitConst},
		"Requests":     {Value: busRequests(st.Requests), Emit: prop.EmitTrue},
	}})
	if err != nil {
		return err
	}
	a.Changed = func(s Status) {
		props.SetMust(Iface, "Organization", s.Organization)
		props.SetMust(Iface, "Device", s.Device)
		props.SetMust(Iface, "Requests", busRequests(s.Requests))
		props.SetMust(Iface, "State", s.State)
	}
	b := &busAgent{agent: a}
	if err := conn.Export(b, Path, Iface); err != nil {
		return err
	}
	node := &introspect.Node{
		Name: string(Path),
		Interfaces: []introspect.Interface{introspect.IntrospectData, prop.IntrospectData, {
			Name:       Iface,
			Methods:    introspect.Methods(b),
			Properties: props.Introspection(Iface),
		}},
	}
	return conn.Export(introspect.NewIntrospectable(node), Path, "org.freedesktop.DBus.Introspectable")
}
