# sinty-identity

An OpenID Connect provider where a person's Sinty devices are their identity.
The organisation, or the person, hosts it; applications such as Sinty Cloud
and Sinty IT sign in through it and have no login of their own.

## Sign-in levels

Every token says how strong the sign-in was, in `acr` and `amr`:

| Level | `acr` | `amr` | How |
| --- | --- | --- | --- |
| 1 | `sinty:1` | `pwd` | Password |
| 2 | `sinty:2` | `pwd otp` | Password and an authenticator code |
| 3 | `sinty:3` | `hwk pin` | Confirmed on an enrolled Sinty device or Sinty Key |

Each client has a minimum level; a request can raise it with `acr_values`.
Sessions are reused only when they are at least as strong as the request.

## Confirming on a device

The sign-in page shows a two-digit number. The device lists the request with
the application name and the address it came from; the person types the
number and unlocks the device key. The device signs the provider address, the
request, its nonce, the client and the number, so a signature collected by
another site is refused, and a request approved without the number fails.

## Enrolling devices

- The first device of a person is approved from a level 2 session, or
  trusted at once when it enrolls with the access token of a level 2
  sign-in made on that desktop less than ten minutes earlier. Tokens of
  confidential clients, the services, never trust a device.
- Every later device or Sinty Key must be approved by a device already
  trusted; a password session is refused, so a stolen password cannot add
  a device.
- A revoked device stops answering at once and cannot approve new ones.

## Protocol

- Authorization code flow only, PKCE with `S256` required, exact redirect
  addresses (the port of a 127.0.0.1 redirect may vary), single-use codes
  valid for one minute.
- ID and access tokens are ES256 JWTs; the key is published at `/jwks`.
- Five wrong attempts lock a user for one minute, doubling up to one hour.
  Unknown users take as long as known ones and get the same answer.
- Passwords are stored as PBKDF2-SHA256 with 600 000 iterations; client
  secrets the same way.
- Clients registered with `-offline` also get a refresh token. Each one
  works once and is replaced by a new one; presenting a used token again
  revokes every token descended from the same sign-in. A refresh token
  lasts 30 days from its last use and never more than 90 days from the
  sign-in. Tokens refreshed more than 8 hours after a device sign-in carry
  level 2, so services that need level 3 ask for a new confirmation.
- `/.well-known/openid-configuration` lists the organisation's services under
  `sinty_services`, from the `-service` options, so a device finds them from
  the identity address alone.

## Signing in to a service

Services verify sign-ins with the `rp` package:

```go
r, err := rp.New(ctx, rp.Config{Issuer: "https://id.example.org", ClientID: "cloud",
	ClientSecret: secret, RedirectURL: "https://cloud.example.org/cb", MinLevel: 2})
req := r.Begin()
claims, err := r.Finish(ctx, req, callbackQuery)
claims, err = r.Access(ctx, bearerToken)
```

`Finish` checks the state, the issuer, the nonce, the signature and the
level; `Access` accepts only access tokens issued to this client, or to the
clients listed in `Audiences` (for example the service's own command line).

Command-line tools sign in with `rp.LoopbackLogin`, which opens the sign-in
page and waits on a one-time address on 127.0.0.1. Register the client with
the redirect `http://127.0.0.1/cb`: any port is accepted for loopback
addresses, nothing else is.

## Running

```sh
echo 'a long password' | sinty-identity user add alice -totp
sinty-identity client add cloud -name "Sinty Cloud" -redirect https://cloud.example.org/cb -min-level 2
sinty-identity client add it -name "Sinty IT" -redirect https://it.example.org/cb -min-level 3 -confidential
sinty-identity client add desktop -name "Sinty OS" -redirect http://127.0.0.1/ -min-level 2 -offline
sinty-identity serve -issuer https://id.example.org -cert tls.crt -key tls.key \
  -service cloud=https://cloud.example.org -service it=https://it.example.org
```

The sign-in page uses [sintyui](https://github.com/singularityos-lab/sintyui),
served from `-ui` (default `/usr/share/sintyui`).

On a device:

```sh
sinty-identity agent enroll -issuer https://id.example.org -key device.key -user alice -name Laptop
sinty-identity agent requests -issuer https://id.example.org -key device.key
sinty-identity agent approve -issuer https://id.example.org -key device.key REQUEST NUMBER
```

Signing a poll or a refusal does not act for the person; allowing a
sign-in, trusting a device or revoking one does. `device.Acts` tells them
apart, so a key service can ask for the PIN only when it matters.

On a Sinty desktop, `agent session` runs in the person's session. It
reads the organization account from the accounts service, enrolls the
device with the key sinty-keyd keeps for the person, in the TPM when there
is one, and waits for requests. Each poll is held by the provider for up to
25 seconds, so a request reaches the device at once. The agent owns
`dev.sinty.IdentityAgent1` on the session bus, object
`/dev/sinty/IdentityAgent1`:

| Member | Signature | |
|---|---|---|
| `State` | property `s` | `no-account`, `waiting` (for a trusted device to approve this one), `trusted`, `refused` or `offline`. |
| `Organization` / `Device` | property `s` | Provider address and this device's id. |
| `Hardware` | property `b` | Whether the key lives in the TPM. |
| `Requests` | property `a(ssssx)` | Waiting requests: id, kind (`login` or `enroll`), application or device name, address, time created. |
| `Answer(id, number, allow)` | in `ssb` | Allowing asks for the PIN. Errors: `NotConfirmed`, `WrongNumber`, `Gone`, `LockedOut`, `Failed`. |
| `Retry()` | | Enrolls again, after the person signed in again so a fresh sign-in can trust a first device. |

`agent` keeps the device key in a file. On Sinty OS the key belongs in the
TPM, unlocked by the device PIN.

## Licence

GPL-3.0, see LICENSE.
