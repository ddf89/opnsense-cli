#!/usr/bin/env bash
# Installs opn, the OPNsense command line, from the GitHub releases of ddf89/opnsense-cli:
#
#   curl -fsSL https://github.com/ddf89/opnsense-cli/releases/latest/download/install.sh | bash
#
# It picks the binary for this system (Linux incl. WSL on Windows, macOS; amd64 or arm64), checks it against the
# release's SHA256SUMS and installs it as "opn" into a user bin directory (~/.local/bin unless ~/bin is in PATH), no
# sudo needed. Options (also as environment variables), e.g. curl ... | bash -s -- --version 26.7.8:
#
#   --version <tag>   OPN_VERSION       install this release instead of the latest
#   --dir <dir>       OPN_INSTALL_DIR   install into this directory
#
# OPN_REPO (default ddf89/opnsense-cli) and OPN_RELEASE_URL (default https://github.com/$OPN_REPO/releases) point
# to another repository or a mirror with the same layout.

# everything runs from main, called on the last line: a download cut short runs nothing
main() {
    set -euo pipefail

    local version="${OPN_VERSION:-}" dir="${OPN_INSTALL_DIR:-}"
    while [ $# -gt 0 ]; do
        case "$1" in
            --version) [ $# -ge 2 ] || fail "--version needs a release tag"; version="$2"; shift 2 ;;
            --dir) [ $# -ge 2 ] || fail "--dir needs a directory"; dir="$2"; shift 2 ;;
            -h | --help) usage; return 0 ;;
            *) fail "unknown option $1 (use --version <tag> or --dir <dir>)" ;;
        esac
    done

    local os arch asset base
    os="$(detect_os)"
    arch="$(detect_arch "$os")"
    asset="opn-$os-$arch"
    base="${OPN_RELEASE_URL:-https://github.com/${OPN_REPO:-ddf89/opnsense-cli}/releases}"
    if [ -n "$version" ]; then
        base="$base/download/$version"
    else
        base="$base/latest/download"
        version="latest"
    fi
    [ -n "$dir" ] || dir="$(default_dir)"

    local tmp
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/opn-install.XXXXXX")"
    # shellcheck disable=SC2064 # expand now: tmp is local
    trap "rm -rf '$tmp'" EXIT

    info "downloading $asset ($version release)"
    download "$base/$asset" "$tmp/$asset" ||
        fail "could not download $base/$asset (is there an $asset in the $version release?)"
    download "$base/SHA256SUMS" "$tmp/SHA256SUMS" ||
        fail "could not download $base/SHA256SUMS to check the binary"
    verify "$tmp" "$asset"

    chmod 755 "$tmp/$asset"
    mkdir -p "$dir" || fail "can not create $dir"
    # copy next to the target, then rename: a running opn is replaced, never overwritten in place
    cp "$tmp/$asset" "$dir/.opn.$$" || fail "can not write to $dir (use --dir or OPN_INSTALL_DIR)"
    mv -f "$dir/.opn.$$" "$dir/opn"

    local installed
    if ! installed="$("$dir/opn" version 2>/dev/null)"; then
        fail "$dir/opn was installed but does not run on this system"
    fi
    info "installed opn $installed to $dir/opn"
    path_hint "$dir"
    info "next: set OPN_URL, OPN_APIKEY and OPN_APISECRET (or a .env file), then try: opn /check"
    info "shell completion: source <(opn completion bash)  (zsh: source <(opn completion zsh))"
}

usage() {
    cat <<'EOF'
usage: install.sh [--version <tag>] [--dir <dir>]

Installs opn for this system (Linux incl. WSL, macOS; amd64 or arm64) from the GitHub releases into ~/.local/bin
(or ~/bin when only that one is in PATH). --version installs that release instead of the latest, --dir installs
into another directory. The same as environment variables: OPN_VERSION, OPN_INSTALL_DIR.
EOF
}

info() { printf '%s\n' "$*" >&2; }
fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

# detect_os prints linux or macos (the release asset names); Windows works through WSL, which is Linux
detect_os() {
    case "$(uname -s)" in
        Linux)
            if [ -n "${WSL_DISTRO_NAME:-}" ] || grep -qi microsoft /proc/version 2>/dev/null; then
                info "WSL (Windows Subsystem for Linux) detected, installing the Linux binary"
            fi
            echo linux
            ;;
        Darwin) echo macos ;;
        MINGW* | MSYS* | CYGWIN*)
            fail "native Windows shells are not supported, run this in WSL (Windows Subsystem for Linux)" ;;
        *) fail "unsupported operating system $(uname -s), opn is released for Linux (incl. WSL) and macOS" ;;
    esac
}

# detect_arch prints amd64 or arm64; a shell under Rosetta 2 on Apple Silicon reports x86_64, it gets arm64
detect_arch() {
    local machine
    machine="$(uname -m)"
    case "$machine" in
        x86_64 | amd64)
            if [ "$1" = macos ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" = 1 ]; then
                echo arm64
            else
                echo amd64
            fi
            ;;
        aarch64 | arm64) echo arm64 ;;
        *) fail "unsupported architecture $machine, opn is released for amd64 (x86_64) and arm64" ;;
    esac
}

# default_dir is ~/.local/bin, or ~/bin when only that one is in PATH
default_dir() {
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) echo "$HOME/.local/bin" ;;
        *":$HOME/bin:"*) echo "$HOME/bin" ;;
        *) echo "$HOME/.local/bin" ;;
    esac
}

# download fetches url into file with curl or wget, following redirects; fails on HTTP errors
download() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 2 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        fail "neither curl nor wget is installed"
    fi
}

# verify checks the asset in dir against its line in dir/SHA256SUMS
verify() {
    local expected actual
    expected="$(awk -v name="$2" '$2 == name || $2 == "*" name { print $1 }' "$1/SHA256SUMS")"
    [ -n "$expected" ] || fail "$2 is not listed in the release's SHA256SUMS"
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$1/$2" | awk '{ print $1 }')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$1/$2" | awk '{ print $1 }')"
    else
        fail "neither sha256sum nor shasum is installed to check the download"
    fi
    [ "$actual" = "$expected" ] || fail "checksum mismatch for $2, the download is damaged or was tampered with"
}

# path_hint tells how to put dir into PATH when it isn't
path_hint() {
    case ":$PATH:" in
        *":$1:"*) return 0 ;;
    esac
    local profile="$HOME/.profile"
    case "${SHELL:-}" in
        */zsh) profile="$HOME/.zshrc" ;;
        */bash) if [ "$(uname -s)" = Darwin ]; then profile="$HOME/.bash_profile"; else profile="$HOME/.bashrc"; fi ;;
    esac
    info "$1 is not in your PATH yet, add it with:"
    info "  echo 'export PATH=\"$1:\$PATH\"' >> $profile && export PATH=\"$1:\$PATH\""
}

main "$@"
