.PHONY: init update build release test vet integration check-version

# os/arch combinations we ship binaries for (darwin is published as "macos", windows gets .exe)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# version compiled into the binary (shown by "opn version"): VERSION when given, else git describe, else dev.
# The release workflow (.github/workflows/release.yml) sets it the same way to the tag name
BUILD_VERSION = $(or $(VERSION),$(shell git describe --tags --always --dirty 2>/dev/null),dev)
LDFLAGS = -X opnsense-cli/cli.Version=$(BUILD_VERSION)

# $(call cross_build,<suffix>) builds every platform into dist/opn-<os>-<arch><suffix>[.exe]
define cross_build
	@mkdir -p dist
	@set -e; for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		name=$$os; [ "$$os" = "darwin" ] && name=macos; \
		ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		out="dist/opn-$$name-$$arch$(1)$$ext"; \
		echo "building $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o "$$out" . ; \
	done
endef

init:
	go mod tidy
	go mod verify
	go mod vendor

update:
	go get -u
	go mod tidy

test:
	go test ./...

vet:
	go vet ./...

# runs every package below integration/ against a live OPNsense (OPN_URL, or the devcontainer's opnsense-dev)
# -p 1: the packages share one live box, run them one after the other
integration:
	go test -tags integration -p 1 ./integration/... -count=1 -v

build: init
	$(call cross_build,)

check-version:
	@test -n "$(VERSION)" || (echo "VERSION is required, e.g. make release VERSION=1.2.3" && exit 1)

release: check-version init
	$(call cross_build,-$(VERSION))
