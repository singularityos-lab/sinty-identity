// Package keyd signs with the device key that sinty-keyd keeps for the
// person, inside the TPM when the computer has one. sinty-keyd asks for the
// PIN before signing a message that acts for the person.
package keyd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	name  = "dev.sinty.Key1"
	path  = dbus.ObjectPath("/dev/sinty/Key1")
	iface = "dev.sinty.Key1"
)

var (
	ErrNotConfirmed = errors.New("the person did not confirm with their PIN")
	ErrLockedOut    = errors.New("the security chip is locked after too many wrong attempts")
	ErrWholeMessage = errors.New("sinty-keyd signs whole messages")
)

// ConfirmTimeout bounds how long a signature may wait for the person.
var ConfirmTimeout = 3 * time.Minute

type Key struct {
	obj      dbus.BusObject
	pub      *ecdsa.PublicKey
	Hardware bool
}

// Open returns the caller's key, which sinty-keyd makes on first use.
func Open(conn *dbus.Conn) (*Key, error) {
	obj := conn.Object(name, path)
	var point []byte
	var hw bool
	if err := obj.Call(iface+".IdentityKey", 0).Store(&point, &hw); err != nil {
		return nil, err
	}
	if len(point) != 64 {
		return nil, errors.New("sinty-keyd returned a malformed key")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(point[:32]), Y: new(big.Int).SetBytes(point[32:])}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("sinty-keyd returned a point off the curve")
	}
	return &Key{obj: obj, pub: pub, Hardware: hw}, nil
}

func (k *Key) Public() *ecdsa.PublicKey {
	return k.pub
}

func (k *Key) SignDigest([]byte) ([]byte, error) {
	return nil, ErrWholeMessage
}

func (k *Key) SignMessage(msg []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ConfirmTimeout)
	defer cancel()
	var sig []byte
	err := k.obj.CallWithContext(ctx, iface+".IdentitySign", dbus.FlagAllowInteractiveAuthorization, msg).Store(&sig)
	var de dbus.Error
	if errors.As(err, &de) {
		switch de.Name {
		case iface + ".Error.NotConfirmed":
			return nil, ErrNotConfirmed
		case iface + ".Error.LockedOut":
			return nil, ErrLockedOut
		}
	}
	return sig, err
}
