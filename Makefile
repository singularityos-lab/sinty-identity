PREFIX ?= /usr

.PHONY: all build release test vet install install-agent clean

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

install-agent: release
	install -Dm755 sinty-identity $(DESTDIR)$(PREFIX)/bin/sinty-identity
	install -Dm644 packaging/sinty-identity-agent.desktop $(DESTDIR)/etc/xdg/autostart/sinty-identity-agent.desktop
	install -Dm644 packaging/dev.sinty.IdentityAgent1.service $(DESTDIR)$(PREFIX)/share/dbus-1/services/dev.sinty.IdentityAgent1.service

clean:
	rm -f sinty-identity
