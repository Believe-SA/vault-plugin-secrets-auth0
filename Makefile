PLUGIN  := vault-plugin-secrets-auth0
MOUNT   ?= auth0
VERSION ?= 0.1.0
LDFLAGS := -X github.com/Believe-SA/vault-plugin-secrets-auth0.Version=$(VERSION)
# Never follow an inherited VAULT_ADDR: these targets only talk to the local dev Vault.
export VAULT_ADDR := http://127.0.0.1:8200

.PHONY: build build-linux dist test lint test-vault dev enable up down

build:
	go build -ldflags '$(LDFLAGS)' -o bin/$(PLUGIN) ./cmd/$(PLUGIN)

# Static binary for the Alpine-based Vault image.
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=$$(go env GOARCH) go build -trimpath -ldflags '$(LDFLAGS)' \
		-o bin/linux/$(PLUGIN) ./cmd/$(PLUGIN)

# Static linux binaries and their SHA256 for the Vault plugin catalog.
dist:
	for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' \
			-o dist/linux-$$arch/$(PLUGIN) ./cmd/$(PLUGIN) || exit 1; \
	done
	cd dist && sha256sum linux-*/$(PLUGIN) | tee SHA256SUMS

test:
	go test -race ./...

lint:
	golangci-lint run --timeout 5m ./...

# Integration tests in a real Vault (VAULT_VERSION, default 2.1.1).
test-vault: build-linux
	docker compose up -d --wait vault
	VAULT_TOKEN=root PLUGIN_VERSION=$(VERSION) python3 scripts/test_vault.py; \
		rc=$$?; docker compose down; exit $$rc

# Dev Vault with the plugin directory; run "make enable" in another shell.
dev: build
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./bin

enable: build
	vault plugin register -sha256=$$(sha256sum bin/$(PLUGIN) | cut -d' ' -f1) secret $(PLUGIN)
	vault secrets enable -path=$(MOUNT) $(PLUGIN)

up: build-linux
	docker compose up -d --wait vault
	docker compose run --rm init

down:
	docker compose down
