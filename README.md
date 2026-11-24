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

- The first device of a person is approved from a level 2 session.
- Every later device or Sinty Key must be approved by a device already
  trusted; a password session is refused, so a stolen password cannot add
  a device.
- A revoked device stops answering at once and cannot approve new ones.

## Protocol

- Authorization code flow only, PKCE with `S256` required, exact redirect
  addresses, single-use codes valid for one minute.
- ID and access tokens are ES256 JWTs; the key is published at `/jwks`.
- Five wrong attempts lock a user for one minute, doubling up to one hour.
  Unknown users take as long as known ones and get the same answer.
- Passwords are stored as PBKDF2-SHA256 with 600 000 iterations; client
  secrets the same way.

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
level; `Access` accepts only access tokens issued to this client.

## Running

```sh
echo 'a long password' | sinty-identity user add alice -totp
sinty-identity client add cloud -name "Sinty Cloud" -redirect https://cloud.example.org/cb -min-level 2
sinty-identity client add it -name "Sinty IT" -redirect https://it.example.org/cb -min-level 3 -confidential
sinty-identity serve -issuer https://id.example.org -cert tls.crt -key tls.key
```

The sign-in page uses [sintyui](https://github.com/singularityos-lab/sintyui),
served from `-ui` (default `/usr/share/sintyui`).

On a device:

```sh
sinty-identity agent enroll -issuer https://id.example.org -key device.key -user alice -name Laptop
sinty-identity agent requests -issuer https://id.example.org -key device.key
sinty-identity agent approve -issuer https://id.example.org -key device.key REQUEST NUMBER
```

`agent` keeps the device key in a file. On Sinty OS the key belongs in the
TPM, unlocked by the device PIN.

## Licence

GPL-3.0, see LICENSE.
