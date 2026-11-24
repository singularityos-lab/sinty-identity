PREFIX ?= /usr

.PHONY: all build release test vet install clean

all: build

build:
	go build -o sinty-identity ./cmd/sinty-identity

release:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o sinty-identity ./cmd/sinty-identity

test:
	go test ./...

vet:
	go vet ./...

install: release
	install -Dm755 sinty-identity $(DESTDIR)$(PREFIX)/bin/sinty-identity
	install -Dm644 packaging/sinty-identity.service $(DESTDIR)$(PREFIX)/lib/systemd/system/sinty-identity.service
	install -Dm644 packaging/sinty-identity.conf $(DESTDIR)/etc/default/sinty-identity

clean:
	rm -f sinty-identity
