#!/bin/sh
# Install or update thresh from GitHub Releases.
#
#   curl -fsSL https://raw.githubusercontent.com/ConquerorBob/nginx-thresh/main/install.sh | sh
#
# Environment:
#   THRESH_INSTALL_DIR  destination directory (default: ~/.local/bin)
#   THRESH_VERSION      release tag to install (default: latest)

set -eu

REPO="ConquerorBob/nginx-thresh"
VERSION="${THRESH_VERSION:-}"
SYSTEM=0
CHECK=0
FORCE=0

usage() {
    cat <<'EOF'
Install or update thresh from GitHub Releases.

Usage:
  install.sh [--system] [--check] [--force]

  --system  Install to /usr/local/bin. Must run as root, for example:
              curl -fsSL <installer-url> | sudo sh
  --check   Report the install state and exit. Status 0 means nothing to do,
            1 means an install or update is needed. Writes nothing.
  --force   Reinstall even when the installed version is already current.

Environment:
  THRESH_INSTALL_DIR  destination directory
  THRESH_VERSION      release tag to install (default: latest)
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --system)
            SYSTEM=1
            shift
            ;;
        --check)
            CHECK=1
            shift
            ;;
        --force)
            FORCE=1
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            printf 'thresh installer: unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ "$SYSTEM" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
    printf 'thresh installer: --system needs root. Run:\n' >&2
    printf '  curl -fsSL https://raw.githubusercontent.com/%s/main/install.sh | sudo sh\n' "$REPO" >&2
    exit 1
fi

if [ -n "${THRESH_INSTALL_DIR:-}" ]; then
    INSTALL_DIR="$THRESH_INSTALL_DIR"
elif [ "$(id -u)" -eq 0 ]; then
    # sudo's secure_path normally includes /usr/local/bin. Installing there
    # means `sudo thresh /var/log/nginx/access.log` works.
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="$HOME/.local/bin"
fi

fail() {
    printf 'thresh installer: %s\n' "$*" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

need curl
need tar
need uname
need mktemp
need awk

# --- version helpers --------------------------------------------------------

# 0.1.1-dev+build7 -> 0.1.1
version_core() {
    _vc="${1#v}"
    _vc="${_vc%%+*}"
    printf '%s' "${_vc%%-*}"
}

# 0.1.1-dev+build7 -> dev
version_suffix() {
    _vs="${1#v}"
    _vs="${_vs%%+*}"
    case "$_vs" in
        *-*) printf '%s' "${_vs#*-}" ;;
        *) printf '' ;;
    esac
}

comparable_version() {
    case "$(version_core "$1")" in
        "" | .* | *. | *..* | *[!0-9.]*)
            return 1
            ;;
    esac
    return 0
}

# version_cmp A B -> 1 if A is newer, -1 if A is older, 0 if the same.
# Dots are compared as numbers, so 0.1.10 sits above 0.1.9 everywhere, and a
# plain release outranks the same version carrying a prerelease suffix.
version_cmp() {
    _i=1
    while [ "$_i" -le 3 ]; do
        _x="$(printf '%s.0.0' "$(version_core "$1")" | cut -d. -f"$_i")"
        _y="$(printf '%s.0.0' "$(version_core "$2")" | cut -d. -f"$_i")"
        _x="${_x:-0}"
        _y="${_y:-0}"
        if [ "$_x" -gt "$_y" ]; then
            printf '1'
            return 0
        fi
        if [ "$_x" -lt "$_y" ]; then
            printf '%s' '-1'
            return 0
        fi
        _i=$((_i + 1))
    done
    _xs="$(version_suffix "$1")"
    _ys="$(version_suffix "$2")"
    if [ "$_xs" = "$_ys" ]; then
        printf '0'
    elif [ -z "$_xs" ]; then
        printf '1'
    else
        printf '%s' '-1'
    fi
}

# First line of `thresh --version`, last field: "thresh 0.1.1" -> 0.1.1
read_version() {
    "$1" --version 2>/dev/null | awk 'NR==1 { print $NF }'
}

# --- installed version vs latest release ------------------------------------

if [ -z "$VERSION" ]; then
    VERSION="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest" | sed 's#.*/tag/##')"
    case "$VERSION" in
        "" | */releases)
            fail "could not find a published release"
            ;;
    esac
fi

installed_path=""
if [ -x "${INSTALL_DIR}/thresh" ]; then
    installed_path="${INSTALL_DIR}/thresh"
fi
path_thresh="$(command -v thresh 2>/dev/null)" || path_thresh=""
if [ -z "$installed_path" ] && [ -n "$path_thresh" ]; then
    installed_path="$path_thresh"
fi

installed_version=""
if [ -n "$installed_path" ]; then
    installed_version="$(read_version "$installed_path")"
fi

display="${VERSION#v}"

action="install"
if [ -n "$installed_path" ]; then
    if [ -z "$installed_version" ]; then
        action="replace"
        printf 'Could not read a version from %s, reinstalling it.\n' "$installed_path" >&2
    elif ! comparable_version "$installed_version" || ! comparable_version "$VERSION"; then
        action="replace"
        printf 'Cannot compare "%s" with "%s", reinstalling.\n' "$installed_version" "$display" >&2
    else
        case "$(version_cmp "$installed_version" "$VERSION")" in
            0) action="current" ;;
            -1) action="update" ;;
            1)
                if [ -n "${THRESH_VERSION:-}" ]; then
                    action="downgrade"
                else
                    action="newer"
                fi
                ;;
        esac
    fi
fi

# A second copy elsewhere on PATH: say so, since PATH order picks the winner.
if [ -n "$path_thresh" ] && [ "$path_thresh" != "${INSTALL_DIR}/thresh" ]; then
    printf 'Note: another thresh is installed at %s, so PATH order decides which one runs.\n' "$path_thresh" >&2
fi

if [ "$CHECK" -eq 1 ]; then
    case "$action" in
        current)
            printf 'thresh %s is up to date at %s\n' "$installed_version" "$installed_path"
            exit 0
            ;;
        newer)
            printf 'thresh %s is newer than the latest release (%s), nothing to do\n' "$installed_version" "$display"
            exit 0
            ;;
        install)
            printf 'thresh is not installed, latest release is %s\n' "$display"
            exit 1
            ;;
        update)
            printf 'Update available: %s -> %s\n' "$installed_version" "$display"
            exit 1
            ;;
        downgrade)
            printf 'Downgrade requested by THRESH_VERSION: %s -> %s\n' "$installed_version" "$display"
            exit 1
            ;;
        *)
            printf 'Reinstall needed at %s, latest release is %s\n' "$installed_path" "$display"
            exit 1
            ;;
    esac
fi

case "$action" in
    current)
        if [ "$FORCE" -eq 0 ]; then
            printf 'thresh %s is already up to date at %s\n' "$installed_version" "$installed_path"
            printf 'Run again with --force to reinstall.\n'
            exit 0
        fi
        printf 'Reinstalling thresh %s\n' "$display"
        ;;
    update)
        printf 'Updating thresh %s -> %s\n' "$installed_version" "$display"
        ;;
    downgrade)
        printf 'Downgrading thresh %s -> %s\n' "$installed_version" "$display"
        ;;
    newer)
        if [ "$FORCE" -eq 0 ]; then
            printf 'thresh installer: %s at %s is newer than the latest release (%s)\n' "$installed_version" "$installed_path" "$display" >&2
            printf 'Pass --force to replace it anyway, or set THRESH_VERSION to pick a release.\n' >&2
            exit 1
        fi
        printf 'Replacing thresh %s with %s (--force)\n' "$installed_version" "$display"
        ;;
esac

# --- download and install ---------------------------------------------------

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

archive="thresh-${VERSION}-${target}.tar.gz"
base_url="https://github.com/${REPO}/releases/download/${VERSION}"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

if [ "$action" = "install" ]; then
    printf 'Installing thresh %s\n' "$display"
fi
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
install -m 0755 "${tmpdir}/thresh" "${INSTALL_DIR}/thresh"

printf 'Installed %s\n' "${INSTALL_DIR}/thresh"
"${INSTALL_DIR}/thresh" --version

if [ "$(id -u)" -ne 0 ]; then
    printf '\nReading /var/log/nginx/access.log usually needs root. To make `sudo thresh` work, install system-wide:\n'
    printf '  curl -fsSL https://raw.githubusercontent.com/%s/main/install.sh | sudo sh\n' "$REPO"
fi

case ":${PATH:-}:" in
    *":${INSTALL_DIR}:"*)
        ;;
    *)
        printf '\nAdd this directory to your PATH:\n  export PATH="%s:$PATH"\n' "$INSTALL_DIR"
        ;;
esac
