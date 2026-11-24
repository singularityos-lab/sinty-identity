# Contributing to sinty-identity

Contributions are welcome under the terms in CLA.md.

```sh
git clone https://github.com/singularityos-lab/sinty-identity
cd sinty-identity
make test
```

- Every sign-in path needs a test that proves it refuses what it must refuse:
  a wrong factor, a replayed code, a signature made for another site, a
  revoked device.
- Run `gofmt` and `go vet ./...` before sending a change.
