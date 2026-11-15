# WHAT: one OCI image carrying the whole node -- vela-server, nginx, Xray, and
# the s6 supervisor that owns the three processes.
#
# WHY one image and not three: the agent restarts Xray and reloads nginx after
# every apply, and it reports one node identity to the control plane. Split
# containers would need the Docker socket inside the container (host-root
# equivalence for the component that parses remote-supplied config) just to
# restart a process.
#
# Build:
#   VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml)
#   docker buildx build --build-arg VERSION="$VERSION" --platform linux/amd64 .
#
# Every assertion below fails the build rather than the first certificate sync.
# Logs go to stdout/stderr; there is no log file and no logrotate.

ARG ALPINE_IMAGE=alpine:3.24
ARG RUST_IMAGE=rust:1.99-alpine3.24

# --------------------------------------------------------------------- builder
FROM ${RUST_IMAGE} AS builder

# WHY no --target and no .cargo/config.toml: this stage already is a musl
# toolchain on the target architecture, so the host triple is the target triple.
# The crate's .cargo/config.toml selects rust-lld with link-self-contained=yes
# for cross builds from a glibc or Windows host; under that config the
# proc-macro cdylibs cannot resolve libgcc_s here, so the native linker is used.
WORKDIR /src
RUN apk add --no-cache build-base
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release \
 && test -x target/release/vela-server \
 && if readelf -l target/release/vela-server | grep -q INTERP; then \
        echo "vela-server is dynamically linked; the image needs a static binary" >&2; \
        exit 1; \
    fi

# ----------------------------------------------------------------------- fetch
# Everything downloaded lands here once, checksum-verified, so the runtime stage
# needs no network and no archive tools.
FROM ${ALPINE_IMAGE} AS fetch

ARG TARGETARCH
ARG XRAY_VERSION=v26.11.9
ARG S6_OVERLAY_VERSION=3.2.3.2

RUN apk add --no-cache curl unzip xz
RUN set -eu; \
    if [ -z "${TARGETARCH:-}" ]; then \
        case "$(uname -m)" in \
            x86_64) TARGETARCH=amd64 ;; \
            aarch64) TARGETARCH=arm64 ;; \
            *) echo "unsupported build architecture: $(uname -m)" >&2; exit 1 ;; \
        esac; \
    fi; \
    case "$TARGETARCH" in \
        amd64) xray_asset=Xray-linux-64.zip; s6_arch=x86_64; \
               s6_sha=e6befcc96a437a3831386ecfc51808c5d3e939dc5fe3c02ae9284599e8aa2408 ;; \
        arm64) xray_asset=Xray-linux-arm64-v8a.zip; s6_arch=aarch64; \
               s6_sha=b17f17a82e7a515c682a91edaf2ffdabb73f891981b6c1fd712115693a2f8b4c ;; \
        *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    xray_base="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}"; \
    curl -fsSL -o /tmp/xray.zip "${xray_base}/${xray_asset}"; \
    curl -fsSL -o /tmp/xray.dgst "${xray_base}/${xray_asset}.dgst"; \
    expected=$(sed -n 's/^SHA2-256=[[:space:]]*//p' /tmp/xray.dgst | head -n 1); \
    [ -n "$expected" ] || { echo "no SHA2-256 in ${xray_asset}.dgst" >&2; exit 1; }; \
    actual=$(sha256sum /tmp/xray.zip | cut -d' ' -f1); \
    [ "$expected" = "$actual" ] || { echo "Xray archive sha256 mismatch" >&2; exit 1; }; \
    mkdir -p /out/xray /out/s6; \
    unzip -q -o /tmp/xray.zip -d /out/xray; \
    s6_base="https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}"; \
    curl -fsSL -o /tmp/s6-noarch.tar.xz "${s6_base}/s6-overlay-noarch.tar.xz"; \
    curl -fsSL -o /tmp/s6-arch.tar.xz "${s6_base}/s6-overlay-${s6_arch}.tar.xz"; \
    echo "5379750ed30a84bbd2e2dd74847ba6b5bd29cd0b2e3ea2ec58049b57eb2eda12  /tmp/s6-noarch.tar.xz" | sha256sum -c -; \
    echo "${s6_sha}  /tmp/s6-arch.tar.xz" | sha256sum -c -; \
    tar -xJf /tmp/s6-noarch.tar.xz -C /out/s6; \
    tar -xJf /tmp/s6-arch.tar.xz -C /out/s6

# --------------------------------------------------------------------- runtime
FROM ${ALPINE_IMAGE} AS runtime

ARG VERSION
ARG XRAY_VERSION=v26.11.9

LABEL org.opencontainers.image.title="vela-server" \
      org.opencontainers.image.description="Vela node reconciler with Xray, the nginx decoy, and s6 supervision" \
      org.opencontainers.image.source="https://github.com/realumino/Vela-Node" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.version="${VERSION}"

# The unit files export this for the Xray service. s6-rc longruns get a minimal
# environment, not the image's, so the run scripts start with
# `#!/command/with-contenv sh` to import it — this variable is how the supervised
# Xray finds geoip.dat/geosite.dat (a config with `geoip:` rules dies without it,
# which is exactly what the plane's geo-block preset renders).
ENV XRAY_LOCATION_ASSET=/var/lib/vela/assets

# WHY a zero kill grace: with s6-linux-init's default (3 s), the final sweep of
# the shutdown procedure kills its own process group, so `docker stop` on any
# image with a supervised longrun is reported as exit 137 even though every
# service stopped cleanly. Every service here is a supervised longrun with its
# own timeout-kill, so nothing needs the sweep to be patient.
ENV S6_KILL_GRACETIME=0

RUN apk add --no-cache nginx \
 && rm -f /etc/nginx/http.d/default.conf \
 && rm -rf /var/www/localhost \
 && sed -i \
      -e 's#^error_log /var/log/nginx/error.log warn;#error_log /dev/stderr warn;#' \
      -e 's#^\([[:space:]]*\)access_log /var/log/nginx/access.log main;#\1access_log /dev/stdout main;#' \
      /etc/nginx/nginx.conf \
 && grep -q '^error_log /dev/stderr warn;' /etc/nginx/nginx.conf \
 && grep -q 'access_log /dev/stdout main;' /etc/nginx/nginx.conf

# The s6 supervision tree, the two binaries, and the three service definitions.
COPY --from=fetch /out/s6/ /
COPY image/s6-overlay/ /etc/s6-overlay/
COPY --from=builder /src/target/release/vela-server /usr/local/bin/vela-server
COPY --from=fetch /out/xray/xray /usr/local/bin/xray
RUN chmod 0755 /etc/s6-overlay/s6-rc.d/*/run

# Assertion 1: the decoy must be able to negotiate X25519MLKEM768, which needs
# OpenSSL >= 3.5 in the library nginx is linked against.
RUN set -eu; \
    ver=$(nginx -V 2>&1 | grep -oE 'OpenSSL [0-9]+\.[0-9]+' | tail -n 1 | cut -d' ' -f2 ); \
    [ -n "$ver" ] || { echo "cannot determine the OpenSSL nginx was built against" >&2; exit 1; }; \
    major=${ver%%.*}; minor=${ver#*.}; \
    if [ "$major" -lt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -lt 5 ]; }; then \
        echo "nginx links OpenSSL $ver; X25519MLKEM768 needs >= 3.5" >&2; exit 1; \
    fi; \
    echo "nginx OpenSSL $ver (post-quantum group available)"

# Assertion 2: nginx configures cleanly with no decoy file yet.
RUN nginx -t

# Assertion 3: Xray is the pinned build.
RUN [ "$(/usr/local/bin/xray version | head -n 1 | awk '{print $2}')" = "${XRAY_VERSION#v}" ]

# Assertion 4: the binary reports the version this image is tagged with.
RUN [ "$(/usr/local/bin/vela-server version)" = "vela-server ${VERSION}" ]

# Assertion 5: both entry points exist and are executable (the node binary's
# static-ness was asserted in the builder, next to the build that produced it).
RUN test -x /usr/local/bin/vela-server && test -x /usr/local/bin/xray

# Documentation only: with host networking nothing is published.
EXPOSE 80 443
VOLUME ["/etc/vela", "/var/lib/vela"]

STOPSIGNAL SIGTERM
ENTRYPOINT ["/init"]