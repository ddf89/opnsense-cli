.PHONY: init update build release test vet integration check-version

# os/arch combinations we ship binaries for (darwin is published as "macos", windows gets .exe)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# $(call cross_build,<suffix>) builds every platform into dist/opn-<os>-<arch><suffix>[.exe]
define cross_build
	@mkdir -p dist
	@set -e; for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		name=$$os; [ "$$os" = "darwin" ] && name=macos; \
		ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		out="dist/opn-$$name-$$arch$(1)$$ext"; \
		echo "building $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -o "$$out" . ; \
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

# runs integration/ and integration/system/ against a live OPNsense (the devcontainer's opnsense-dev)
# -p 1: the packages share one live box, run them one after the other
integration:
	go test -tags integration -p 1 ./integration/... -count=1 -v

build: init
	$(call cross_build,)

check-version:
	@test -n "$(VERSION)" || (echo "VERSION is required, e.g. make release VERSION=1.2.3" && exit 1)

release: check-version init
	$(call cross_build,-$(VERSION))
