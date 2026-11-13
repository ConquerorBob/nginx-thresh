#!/bin/sh
# Install sentinel from GitHub Releases.
#
#   curl -fsSL https://raw.githubusercontent.com/ConquerorBob/nginx-sentinel/main/install.sh | sh
#
# Environment:
#   SENTINEL_INSTALL_DIR  destination directory (default: ~/.local/bin)
#   SENTINEL_VERSION      release tag to install (default: latest)

set -eu

REPO="ConquerorBob/nginx-sentinel"
VERSION="${SENTINEL_VERSION:-}"
SYSTEM=0

usage() {
    cat <<'EOF'
Install sentinel from GitHub Releases.

Usage:
  install.sh [--system]

  --system  Install to /usr/local/bin. Must run as root, for example:
              curl -fsSL <installer-url> | sudo sh

Environment:
  SENTINEL_INSTALL_DIR  destination directory
  SENTINEL_VERSION      release tag to install (default: latest)
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --system)
            SYSTEM=1
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            printf 'sentinel installer: unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ "$SYSTEM" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
    printf 'sentinel installer: --system needs root. Run:\n' >&2
    printf '  curl -fsSL https://raw.githubusercontent.com/%s/main/install.sh | sudo sh\n' "$REPO" >&2
    exit 1
fi

if [ -n "${SENTINEL_INSTALL_DIR:-}" ]; then
    INSTALL_DIR="$SENTINEL_INSTALL_DIR"
elif [ "$(id -u)" -eq 0 ]; then
    # sudo's secure_path normally includes /usr/local/bin. Installing there
    # means `sudo sentinel /var/log/nginx/access.log` works.
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="$HOME/.local/bin"
fi

fail() {
    printf 'sentinel installer: %s\n' "$*" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

need curl
need tar
need uname
need mktemp

os="$(uname -s)"
machine="$(uname -m)"

case "$os" in
    Linux)
        platform="unknown-linux-musl"
        ;;
    Darwin)
        platform="apple-darwin"
        ;;
    *)
        fail "unsupported operating system: $os (use the release archive for your platform)"
        ;;
esac

case "$machine" in
    x86_64 | amd64)
        arch="x86_64"
        ;;
    arm64 | aarch64)
        arch="aarch64"
        ;;
    *)
        fail "unsupported architecture: $machine"
        ;;
esac

target="${arch}-${platform}"

if [ -z "$VERSION" ]; then
    VERSION="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest" | sed 's#.*/tag/##')"
    case "$VERSION" in
        "" | */releases)
            fail "could not find a published release"
            ;;
    esac
fi

archive="sentinel-${VERSION}-${target}.tar.gz"
base_url="https://github.com/${REPO}/releases/download/${VERSION}"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

printf 'Downloading %s\n' "$archive"
curl -fsSL "${base_url}/${archive}" -o "${tmpdir}/${archive}"
curl -fsSL "${base_url}/${archive}.sha256" -o "${tmpdir}/${archive}.sha256"

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$tmpdir" && sha256sum -c "${archive}.sha256")
elif command -v shasum >/dev/null 2>&1; then
    (cd "$tmpdir" && shasum -a 256 -c "${archive}.sha256")
else
    fail "no SHA-256 tool found (install coreutils or use the release archive manually)"
fi

tar -xzf "${tmpdir}/${archive}" -C "$tmpdir"
mkdir -p "$INSTALL_DIR"
install -m 0755 "${tmpdir}/sentinel" "${INSTALL_DIR}/sentinel"

printf 'Installed %s\n' "${INSTALL_DIR}/sentinel"
"${INSTALL_DIR}/sentinel" --version

if [ "$(id -u)" -ne 0 ]; then
    printf '\nReading /var/log/nginx/access.log usually needs root. To make `sudo sentinel` work, install system-wide:\n'
    printf '  curl -fsSL https://raw.githubusercontent.com/%s/main/install.sh | sudo sh\n' "$REPO"
fi

case ":${PATH:-}:" in
    *":${INSTALL_DIR}:"*)
        ;;
    *)
        printf '\nAdd this directory to your PATH:\n  export PATH="%s:$PATH"\n' "$INSTALL_DIR"
        ;;
esac
