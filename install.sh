#!/bin/sh
# Vela node installer: dependencies, nginx, Xray, services, enroll.
#
# WHAT: installs the single static `vela-server` binary plus the service
# definitions, provisions nginx (decoy origin) and Xray (REALITY on 443) from
# their vendors, creates the host layout, and enrolls the node.
# WHY the installer owns nginx and Xray too: these nodes exist to run this
# service, and a half-provisioned host (nginx installed, unit missing, config
# elsewhere) is the failure mode that costs hours. Every step is idempotent,
# so the same script upgrades an existing node without re-minting a token.
#
# Usage:
#   ./install.sh --cp <control-plane-url> --node <node-id>
#   ./install.sh --cp <url> --node <id> --token-file <path>
#   ./install.sh --version 0.6.0 --cp <url> --node <id>
#
# The token is read from a hidden prompt (or a 0600 file) and piped to the
# binary on stdin; it never appears in argv, the environment, or a log.
#
# Release layout: this script ships inside vela-server-<version>-linux-<arch>
# .tar.gz next to the binary and the unit files. Run outside that layout it
# downloads the tarball for this machine from the Gitee release.
set -eu

OWNER="realumino"
REPO="lessv"
TAG_PREFIX="node-v"
XRAY_VERSION="${LESSV_XRAY_VERSION:-v26.11.9}"
DEFAULT_NGINX_CONF="/etc/nginx/conf.d/vela-decoy.conf"

CP_URL=""
NODE_ID=""
VERSION=""
TOKEN_FILE=""
RELEASE_BASE=""
NGINX_CONF_PATH="$DEFAULT_NGINX_CONF"
SKIP_NGINX=0
SKIP_XRAY=0
SKIP_ENROLL=0

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

usage() {
    cat >&2 <<'EOF'
usage: install.sh --cp <control-plane-url> --node <node-id> [options]

options:
  --cp <url>            control-plane base URL (required on first install)
  --node <id>           node id minted on the plane (required on first install)
  --token-file <path>   read the node token from this 0600 file instead of a prompt
  --version <x.y.z>     vela-server release to install (default: this bundle's)
  --release-base <url>  override the Gitee release download base
  --xray-version <tag>  Xray release tag to install (default: v26.11.9)
  --skip-nginx          do not install/manage nginx
  --skip-xray           do not install/manage Xray
  --skip-enroll         install files only; keep the existing node.toml
  -h, --help            show this text

The node token is never accepted as an argument; it is prompted for (input
hidden) or read from --token-file.
EOF
}

die() {
    echo "error: $*" >&2
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --cp) CP_URL="${2:-}"; shift 2 ;;
        --node) NODE_ID="${2:-}"; shift 2 ;;
        --token-file) TOKEN_FILE="${2:-}"; shift 2 ;;
        --version) VERSION="${2:-}"; shift 2 ;;
        --release-base) RELEASE_BASE="${2:-}"; shift 2 ;;
        --xray-version) XRAY_VERSION="${2:-}"; shift 2 ;;
        --skip-nginx) SKIP_NGINX=1; shift ;;
        --skip-xray) SKIP_XRAY=1; shift ;;
        --skip-enroll) SKIP_ENROLL=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage; die "unknown argument: $1" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run as root"

# ---------------------------------------------------------------- init system

if [ -d /run/systemd/system ]; then
    INIT="systemd"
elif command -v rc-service >/dev/null 2>&1 && command -v openrc-run >/dev/null 2>&1; then
    INIT="openrc"
else
    die "neither systemd nor OpenRC is running; this installer supports both only"
fi

# ------------------------------------------------------------ release bundle

arch_name() {
    case "$(uname -m)" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l|armv7) echo "armv7" ;;
        *) die "unsupported architecture: $(uname -m)" ;;
    esac
}

latest_version() {
    tag=$(curl -fsSL "https://gitee.com/api/v5/repos/${OWNER}/${REPO}/releases/latest" 2>/dev/null \
        | grep -o "\"tag_name\":\"${TAG_PREFIX}[^\"]*\"" | head -n 1 | cut -d'"' -f4) || true
    [ -n "${tag:-}" ] || return 1
    echo "${tag#${TAG_PREFIX}}"
}

resolve_version() {
    if [ -n "$VERSION" ]; then
        echo "$VERSION"
        return
    fi
    if [ -f "$SCRIPT_DIR/VERSION" ]; then
        tr -d '[:space:]' < "$SCRIPT_DIR/VERSION"
        return
    fi
    latest_version || die "cannot determine the latest release; pass --version"
}

# WHAT: ensure the script runs from a directory that holds the binary and
# the unit files.
#
# WHY re-exec instead of downloading just the binary: the units, the VERSION
# file, and this script itself are part of one release; a standalone copy
# must install exactly what that release shipped.
ensure_bundle() {
    if [ -f "$SCRIPT_DIR/vela-server" ] && [ -d "$SCRIPT_DIR/systemd" ]; then
        BUNDLE_DIR="$SCRIPT_DIR"
        return
    fi
    VERSION=$(resolve_version)
    ARCH=$(arch_name)
    if [ -z "$RELEASE_BASE" ]; then
        RELEASE_BASE="https://gitee.com/${OWNER}/${REPO}/releases/download/${TAG_PREFIX}${VERSION}"
    fi
    NAME="vela-server-${VERSION}-linux-${ARCH}"
    WORK=$(mktemp -d)
    trap 'rm -rf "$WORK"' EXIT
    echo "downloading ${NAME}.tar.gz from ${RELEASE_BASE}" >&2
    curl -fsSL -o "$WORK/bundle.tar.gz" "${RELEASE_BASE}/${NAME}.tar.gz" \
        || die "download failed: ${RELEASE_BASE}/${NAME}.tar.gz"
    curl -fsSL -o "$WORK/SHA256SUMS" "${RELEASE_BASE}/SHA256SUMS" \
        || die "download failed: ${RELEASE_BASE}/SHA256SUMS"
    expected=$(sed -n "s/^\([0-9a-f]\{64\}\) [ *]${NAME}\.tar\.gz$/\1/p" "$WORK/SHA256SUMS" | head -n 1)
    [ -n "$expected" ] || die "SHA256SUMS does not list ${NAME}.tar.gz"
    actual=$(sha256sum "$WORK/bundle.tar.gz" | cut -d' ' -f1)
    [ "$expected" = "$actual" ] || die "sha256 mismatch for ${NAME}.tar.gz"
    mkdir -p "$WORK/extract"
    tar -xzf "$WORK/bundle.tar.gz" -C "$WORK/extract"
    BUNDLE_DIR="$WORK/extract/$NAME"
    [ -f "$BUNDLE_DIR/vela-server" ] || die "release bundle is missing the binary"
    # Archive extraction may not preserve the executable bit (for example
    # when the release tarball was assembled on a non-POSIX host); the
    # checksum already proved the bytes, so fix the mode before use.
    chmod 0755 "$BUNDLE_DIR/vela-server" "$BUNDLE_DIR/install.sh" 2>/dev/null || true
    VERSION=$(tr -d '[:space:]' < "$BUNDLE_DIR/VERSION")
}

# --------------------------------------------------------------- dependencies

install_base_packages() {
    echo "installing base packages" >&2
    if command -v apk >/dev/null 2>&1; then
        apk add --no-cache ca-certificates curl tar unzip >/dev/null
    elif command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq >/dev/null
        apt-get install -y -qq ca-certificates curl tar unzip >/dev/null
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q ca-certificates curl tar unzip >/dev/null
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q ca-certificates curl tar unzip >/dev/null
    else
        die "no supported package manager (apk/apt-get/dnf/yum)"
    fi
}

# WHAT: classify the installed nginx's TLS library for post-quantum support.
#
# WHY this is checked at install time and not only at apply time: vela-server
# refuses to apply a decoy that cannot offer the hybrid group — it fails the
# decoy (`nginx -t` rejects `ssl_ecdh_curve`) rather than silently serving
# classical TLS. Telling the operator now, before the first certificate
# sync, turns a confusing failure into an actionable one.
#
# Prints `ok`, `old`, or `unknown` (LibreSSL/BoringSSL strings).
nginx_pq_state() {
    line=$(nginx -V 2>&1 | grep -oE '(built|running) with OpenSSL [0-9]+\.[0-9]+' | tail -n 1)
    if [ -z "$line" ]; then
        echo unknown
        return 0
    fi
    ver=${line##* }
    major=${ver%%.*}
    minor=${ver#*.}
    if [ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 5 ]; }; then
        echo ok
    else
        echo old
    fi
}

install_nginx() {
    if [ "$SKIP_NGINX" -eq 1 ]; then
        return
    fi
    if ! command -v nginx >/dev/null 2>&1; then
        echo "installing nginx" >&2
        if command -v apk >/dev/null 2>&1; then
            apk add --no-cache nginx >/dev/null
        elif command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx >/dev/null
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y -q nginx >/dev/null
        elif command -v yum >/dev/null 2>&1; then
            yum install -y -q nginx >/dev/null
        else
            die "cannot install nginx on this host"
        fi
    fi
    # The decoy is the only server this host should expose on TLS; strip the
    # vendor default so nginx does not answer on port 80 with a stock page.
    if [ -d /etc/nginx/sites-enabled ]; then
        rm -f /etc/nginx/sites-enabled/default
    fi
    if [ -f /etc/nginx/http.d/default.conf ]; then
        mv /etc/nginx/http.d/default.conf /etc/nginx/http.d/default.conf.disabled
    fi
    if [ -d /etc/nginx/http.d ]; then
        NGINX_CONF_DIR="/etc/nginx/http.d"
    else
        NGINX_CONF_DIR="/etc/nginx/conf.d"
    fi
    NGINX_CONF_PATH="$NGINX_CONF_DIR/vela-decoy.conf"
    mkdir -p "$NGINX_CONF_DIR"
    if ! nginx -t >/dev/null 2>&1; then
        echo "warning: nginx -t fails before the first certificate sync; vela-server will write the decoy config and reload" >&2
    fi
    case "$(nginx_pq_state)" in
        ok) ;;
        old)
            die "nginx links an OpenSSL older than 3.5, so the decoy cannot negotiate
X25519MLKEM768 (post-quantum). Post-quantum TLS is required — vela-server will
not fall back to classical key exchange. Use Debian 13+, Ubuntu 25.10+, or
Alpine 3.22+ (or an nginx built against OpenSSL >= 3.5)."
            ;;
        *)
            echo "warning: cannot determine the nginx TLS library; if it lacks X25519MLKEM768 the node will report a failed decoy apply" >&2
            ;;
    esac
    # The decoy listens on a Unix socket under /dev/shm and Xray relays
    # REALITY handshakes to it; both services run as root here.
    case "$INIT" in
        systemd) systemctl enable nginx >/dev/null 2>&1 || true ;;
        openrc) rc-update add nginx default >/dev/null 2>&1 || true ;;
    esac
}

install_xray() {
    if [ "$SKIP_XRAY" -eq 1 ]; then
        return
    fi
    if command -v xray >/dev/null 2>&1 || [ -x /usr/local/bin/xray ]; then
        return
    fi
    case "$(uname -m)" in
        x86_64|amd64) ASSET="Xray-linux-64.zip" ;;
        aarch64|arm64) ASSET="Xray-linux-arm64-v8a.zip" ;;
        armv7l|armv7) ASSET="Xray-linux-arm32-v7a.zip" ;;
        *) die "unsupported Xray architecture: $(uname -m)" ;;
    esac
    base="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}"
    work=$(mktemp -d)
    echo "installing Xray ${XRAY_VERSION}" >&2
    curl -fsSL -o "$work/xray.zip" "${base}/${ASSET}" || die "cannot download ${base}/${ASSET}"
    if curl -fsSL -o "$work/xray.dgst" "${base}/${ASSET}.dgst" 2>/dev/null; then
        expected=$(sed -n 's/^SHA256=//p' "$work/xray.dgst" | head -n 1)
        if [ -n "$expected" ]; then
            actual=$(sha256sum "$work/xray.zip" | cut -d' ' -f1)
            [ "$expected" = "$actual" ] || die "Xray archive sha256 mismatch"
        fi
    fi
    unzip -q -o "$work/xray.zip" -d "$work/xray"
    install -m 0755 "$work/xray/xray" /usr/local/bin/xray
    rm -rf "$work"
}

# -------------------------------------------------------------------- layout

# WHAT: create the host layout, including the decoy document root.
#
# WHY the page itself is not written here: vela-server owns it as a managed
# artifact (it carries a marker and is refreshed on upgrades unless the
# operator replaced it). The installer only guarantees the directory, so a
# fresh node has its page as soon as the first certificate sync runs.
install_layout() {
    # /var/lib/vela/assets is where vela-server keeps geoip.dat/geosite.dat;
    # the Xray unit exports XRAY_LOCATION_ASSET to it.
    install -d -m 0755 /etc/vela /etc/vela/certs /var/lib/vela /var/lib/vela/assets /var/www/vela-decoy
}

install_binary() {
    install -m 0755 "$BUNDLE_DIR/vela-server" /usr/local/bin/vela-server
}

install_units() {
    case "$INIT" in
        systemd)
            install -d -m 0755 /etc/systemd/system
            install -m 0644 "$BUNDLE_DIR/systemd/vela-server.service" /etc/systemd/system/vela-server.service
            if [ -f /etc/systemd/system/xray.service ] \
                && ! cmp -s /etc/systemd/system/xray.service "$BUNDLE_DIR/systemd/xray.service"; then
                echo "warning: replacing the existing xray.service (backup: /etc/systemd/system/xray.service.vela-backup)" >&2
                cp /etc/systemd/system/xray.service /etc/systemd/system/xray.service.vela-backup
            fi
            install -m 0644 "$BUNDLE_DIR/systemd/xray.service" /etc/systemd/system/xray.service
            # The earlier Python agent pinned the vendor unit through a
            # drop-in; our unit already owns ExecStart, so the drop-in is
            # redundant and would only mask a future edit.
            if [ -f /etc/systemd/system/xray.service.d/99-vela.conf ]; then
                rm -f /etc/systemd/system/xray.service.d/99-vela.conf
                rmdir /etc/systemd/system/xray.service.d 2>/dev/null || true
            fi
            systemctl daemon-reload
            ;;
        openrc)
            install -m 0755 "$BUNDLE_DIR/openrc/vela-server.initd" /etc/init.d/vela-server
            install -m 0755 "$BUNDLE_DIR/openrc/xray.initd" /etc/init.d/xray
            if [ -d /etc/logrotate.d ]; then
                install -m 0644 "$BUNDLE_DIR/openrc/vela-logrotate" /etc/logrotate.d/vela
            fi
            ;;
    esac
}

stop_legacy_agent() {
    case "$INIT" in
        systemd)
            if systemctl list-unit-files lessv-agent.service >/dev/null 2>&1; then
                systemctl disable --now lessv-agent.service >/dev/null 2>&1 || true
                echo "stopped the legacy Python agent (lessv-agent.service)" >&2
            fi
            ;;
        openrc)
            if [ -f /etc/init.d/lessv-agent ]; then
                rc-service lessv-agent stop >/dev/null 2>&1 || true
                rc-update del lessv-agent default >/dev/null 2>&1 || true
                echo "stopped the legacy Python agent (lessv-agent init script)" >&2
            fi
            ;;
    esac
}

# -------------------------------------------------------------------- enroll

enroll_if_needed() {
    if [ "$SKIP_ENROLL" -eq 1 ]; then
        return
    fi
    if [ -f /etc/vela/node.toml ] && grep -q '^token = "' /etc/vela/node.toml; then
        echo "existing /etc/vela/node.toml found; reusing its token (no re-enroll)" >&2
        return
    fi
    [ -n "$CP_URL" ] || die "--cp is required for the first install"
    [ -n "$NODE_ID" ] || die "--node is required for the first install"
    if [ -n "$TOKEN_FILE" ]; then
        [ -r "$TOKEN_FILE" ] || die "cannot read token file: $TOKEN_FILE"
        TOKEN=$(cat "$TOKEN_FILE")
    else
        printf 'Node token (input hidden): ' >&2
        if stty -echo 2>/dev/null; then
            CLEANUP_ECHO=1
        else
            CLEANUP_ECHO=0
        fi
        IFS= read -r TOKEN
        if [ "$CLEANUP_ECHO" -eq 1 ]; then
            stty echo 2>/dev/null || true
        fi
        printf '\n' >&2
    fi
    [ -n "$TOKEN" ] || die "empty token; enroll aborted"
    printf '%s\n' "$TOKEN" | /usr/local/bin/vela-server enroll \
        --cp "$CP_URL" \
        --node "$NODE_ID" \
        --config /etc/vela/node.toml \
        --state /var/lib/vela/state.json \
        --restart-mode "$INIT" \
        --nginx-conf-path "$NGINX_CONF_PATH"
    TOKEN=""
}

# -------------------------------------------------------------------- start

start_services() {
    case "$INIT" in
        systemd)
            systemctl enable vela-server.service >/dev/null
            if [ "$SKIP_XRAY" -eq 0 ]; then
                systemctl enable xray.service >/dev/null
            fi
            systemctl restart vela-server.service
            ;;
        openrc)
            rc-update add vela-server default >/dev/null
            if [ "$SKIP_XRAY" -eq 0 ]; then
                rc-update add xray default >/dev/null
            fi
            rc-service vela-server stop >/dev/null 2>&1 || true
            rc-service vela-server start
            ;;
    esac
}

install_base_packages
ensure_bundle
install_layout
install_nginx
install_xray
install_binary
install_units
stop_legacy_agent
enroll_if_needed
start_services

case "$INIT" in
    systemd) LOG_HINT="journalctl -u vela-server -n 50" ;;
    openrc) LOG_HINT="tail -n 50 /var/log/vela-server.log" ;;
esac
echo "vela-server installed and started (config: /etc/vela/node.toml; logs: $LOG_HINT)"
