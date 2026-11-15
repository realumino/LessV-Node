# vela-server

The node side of [Vela](https://github.com/realumino/LessV): a static Rust
reconciler that pulls its desired state from the control plane and converges
Xray, the certificate tree, and the nginx decoy on one host — as a bare-metal
install, or as a single OCI image.

This repository was split out of the control plane's tree and carries two
delivery paths that share one binary:

| Path | Artefact | Supervisor |
|---|---|---|
| Container | `ghcr.io/realumino/vela-server` (one image: node, nginx, Xray) | s6-overlay |
| Bare metal | release tarball from Gitee (`install.sh` + units) | systemd or OpenRC |

The node is a reconciler, not a proxy: it holds no listener of its own, never
serves traffic, and its only job is to make the host match the plane.

The pull protocol (endpoints, payloads, the `bearer-v1` token rules) is defined
by the control plane and lives in
[the plane's `docs/PROTOCOL.md`](https://github.com/realumino/LessV/blob/main/docs/PROTOCOL.md);
this repository implements it, it does not own it.

---

## What the image contains

- `vela-server` — the reconciler (static musl binary).
- `xray` — pinned, downloaded at build time and checksum-verified against the
  vendor `.dgst`.
- `nginx` — from Alpine 3.24, built against OpenSSL 3.5 so the decoy can offer
  the post-quantum group `X25519MLKEM768`.
- s6-overlay — supervises the three processes.

Three processes, one runtime coupling: Xray owns `:443` and relays REALITY
handshakes to the nginx decoy over the Unix socket `/dev/shm/lessv-decoy.sock`;
nginx answers plain HTTP on `:80` with a 301. The socket path is a control-plane
constant — do not change it on one node.

The image is one container on purpose. The reconciler restarts Xray and reloads
nginx after every apply, and reports a single node identity (one token, one
applied hash, one certificate manifest) to the plane. Split containers would
need the Docker socket inside the container — host-root equivalence for the
component that parses remote-supplied configuration.

### Image surface

| | |
|---|---|
| Registry | `ghcr.io/realumino/vela-server` |
| Platforms | `linux/amd64`, `linux/arm64` (one index) |
| Tags | `<version>`, `latest`, `sha-<short>` |
| Ports | `80`, `443` — publish exactly these two |
| Volumes | `/etc/vela`, `/var/lib/vela` |
| Environment | none required (`XRAY_LOCATION_ASSET` is preset) |
| Token input | stdin only — never argv, never the environment |

`<version>` is the crate version (`Cargo.toml`), and `vela-server version` run
from the image prints it; the release workflow refuses a `node-v*` tag that
disagrees.

---

## Quickstart

### 1. Enroll the node

Create the node row in the plane first, then run `enroll` against a fresh
volume. It writes `/etc/vela/node.toml` (mode 0600, it holds the node token):

```sh
docker run --rm -it \
  -v vela-etc:/etc/vela \
  --entrypoint /usr/local/bin/vela-server \
  ghcr.io/realumino/vela-server:latest \
  enroll --cp https://cp.example.org --node tokyo01 \
         --restart-mode s6 \
         --nginx-conf-path /etc/nginx/http.d/vela-decoy.conf
```

The token is read from stdin (hidden when stdin is a TTY). `node.toml` is
written before the plane is contacted, so a failed enroll still leaves a
complete file: fix the plane and run enroll again, or just start the container.

`--restart-mode s6` and `--nginx-conf-path` are mandatory in the image. The
default nginx directory is Debian's `/etc/nginx/conf.d`, which Alpine does not
use.

### 2. Start it

```sh
docker compose up -d
docker compose logs -f
```

A converging node logs one INFO line per apply; a healthy steady state logs
almost nothing. The plane's fleet view is the health signal — there is
deliberately no container `HEALTHCHECK`.

### 3. Verify from the inside

```sh
docker exec vela-server /command/s6-svstat -o up,pid /run/service/xray
docker exec vela-server /command/s6-svstat -o up,pid /run/service/nginx
docker exec vela-server /command/s6-svstat -o up,pid /run/service/vela-server
```

Each prints `true <pid>` while the service runs and `false -1` while it does
not.

---

## Volumes

| Volume | Mount | Contents | If you lose it |
|---|---|---|---|
| `vela-etc` | `/etc/vela` | `node.toml` (token), `certs/` (the deployed certificate tree) | re-enroll the node |
| `vela-state` | `/var/lib/vela` | `state.json` (applied hash), `config.json` (live Xray config), `config.last_good`, `assets/` (geodata) | the next poll re-applies from the plane; no re-enroll |

Both are required. `docker compose down -v` deletes them.

The decoy's document root `/var/www/vela-decoy` is *not* a volume: the page is
a managed artefact that follows upgrades, and the reconciler rewrites it only
while its marker comment is present. If you replace the page with your own and
want it to survive `docker compose up --force-recreate`, bind-mount that
directory.

---

## Networking

**Bridge networking with two published ports is the documented default**
(`network_mode: bridge` plus `ports:` for 80 and 443 in `compose.yaml`):

- it behaves the same on every provider and needs nothing but Docker;
- 80/443 are the only ports the host has to expose — the one hard requirement;
- the cost is source addresses: Xray and the decoy see the docker gateway, and
  `detected_ip` reports the container's private address. The plane ignores a
  private literal and shows the address the node reached it from instead, so
  the fleet view stays correct.

If you want the client's real source address to reach Xray and the decoy, use
host networking instead: drop `network_mode` and `ports:` and set
`network_mode: host`. A host network still needs 80/443 free and nothing else
may bind them.

Host-level concerns stay on the host: the firewall, `net.ipv4.tcp_congestion_control`
(BBR), IPv6 reachability, and the plane's address allow-lists all apply to the
container exactly as they would to a bare-metal node.

---

## Runtime modes

`restart_mode` in `node.toml` selects the process supervisor. `auto` is the
default for bare-metal enrollments and resolves in the order systemd → OpenRC →
s6; pin it explicitly when detection is ambiguous.

| `restart_mode` | Detected by | `status()` | `start()` | `restart()` | `reload()` |
|---|---|---|---|---|---|
| `systemd` | `/run/systemd/system` | `systemctl is-active` + `show -p MainPID` | `systemctl start` | `systemctl restart` | `systemctl reload` |
| `openrc` | `/sbin/rc-service` (or `/sbin/openrc-run`) | `rc-service <svc> status` + pidfile/`/proc` | `rc-service <svc> start` | `rc-service <svc> restart` | `rc-service <svc> reload` |
| `s6` | `/run/service` + `s6-svstat` on `PATH` | `s6-svstat -o up,pid,updownfor` + process name | `s6-svc -u` | `s6-svc -r` | `s6-svc -h` (SIGHUP) |
| `auto` | the first of the three that matches | — | — | — | — |

The image enrolls with `restart_mode = "s6"`. s6's reload verb is SIGHUP, which
is exactly what `nginx -s reload` sends; Xray has no reload at all (it handles
only SIGTERM), so every Xray config change is a stop+start.

---

## Operational notes

**Plane-driven Xray updates drift on recreate.** `update_xray` from the plane
replaces `/usr/local/bin/xray` inside the running container. That change lives
in the writable layer, so `docker compose up --force-recreate` (or an upgrade)
returns to the version baked into the image tag. Nothing is silent about it: the
plane's version report follows the binary that is actually running. Treat image
tags, not plane actions, as the durable source of the Xray version.

**Upgrades.** `docker compose pull && docker compose up -d`. Traffic survives;
`vela-etc` and `vela-state` are untouched and the applied hash still matches,
so the node does not re-apply on every recreate.

**Restart policy.** `unless-stopped`: a crash loop inside the container is
absorbed by s6 (which restarts the individual service), not by Docker. A
container that restarts is a container whose PID 1 died — that is a bug worth
reporting.

**Never enroll with the token on the command line.** The binary refuses argv and
the environment on purpose: argv lands in `ps` and shell history.

---

## Troubleshooting

| Symptom | Check |
|---|---|
| Container runs, nothing converges | `docker logs <container>`; if `/etc/vela/node.toml is missing` is printed once, the volume was not mounted or the node was never enrolled |
| `heartbeat failed: … 401` | the token was revoked or the node row was deleted; re-enroll |
| `last_error` on the plane, node keeps serving | the plane's config failed `xray -test`; the previous config is still live |
| Decoy applies fail on `nginx -t` | something replaced the image's nginx with a build against OpenSSL < 3.5 (the PQ group is required, there is no fallback) |
| Services look asleep | `docker exec <container> /command/s6-svstat -o up,pid /run/service/{xray,nginx,vela-server}` |
| Restart one service by hand | `docker exec <container> /command/s6-svc -r /run/service/xray` (or `-u` up, `-d` down, `-h` SIGHUP) |
| `docker stop` is slow | an apply may be in flight (`xray -test` up to 15 s); compose allows 90 s |
| Re-enroll | remove the volume (`docker volume rm vela-etc`) or overwrite `node.toml` with a new `enroll --config` run, then restart |

`/dev/shm` holds only the decoy socket (0 bytes). Docker's default 64 MiB is
plenty.

---

## Building and releasing

### The image

```sh
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml)
docker buildx build --build-arg VERSION="$VERSION" --platform linux/amd64 -t vela-server:test .
```

Build arguments: `VERSION` (no default — the image will not build without it),
`XRAY_VERSION` (default `v26.11.9`), and buildx's `TARGETARCH`, from which the
musl target and the Xray asset name are derived. The s6-overlay tarballs are
pinned by version and sha256.

The build asserts, and fails rather than shipping a broken node:

1. `nginx -V` reports OpenSSL ≥ 3.5 (the post-quantum gate);
2. `nginx -t` succeeds with no decoy file yet;
3. `xray version` is the pinned version;
4. `vela-server version` equals `VERSION`;
5. both binaries are executable and the node binary has no `PT_INTERP` (linked
   in the builder stage, next to the build that produced it).

### Automation

`.github/workflows/image.yml`:

- every push to `main` and every PR builds (no publish) so Dockerfile rot is
  caught early;
- pushing a `node-v<version>` tag tests, verifies the tag against `Cargo.toml`
  and the Dockerfile's `XRAY_VERSION`, builds each architecture on its own
  native runner (`ubuntu-24.04`, `ubuntu-24.04-arm`), and merges the two
  digests into one index with tags `<version>`, `latest`, `sha-<short>`;
- GHCR authentication uses `GITHUB_TOKEN`; no stored secret.

One manual step after the very first publish: GitHub creates the GHCR package as
**private**. Flip it to public once in the package settings (Package settings →
Change visibility).

### Testing before a release

`docs/testing.md` describes every environment this code is exercised in — the
hermetic crate tests, the image build assertions, the stub plane, a real plane
via `wrangler dev`, and a throwaway host with real ports — plus what each one
cannot prove and the failure policy.

### The bare-metal tarball

```sh
node scripts/release_node.mjs [--targets amd64,arm64] [--upload]
```

Builds `vela-server-<version>-linux-<arch>.tar.gz` (binary, `install.sh`,
`VERSION`, `systemd/`, `openrc/`) plus `SHA256SUMS` into `dist/`. `--upload`
publishes to the Gitee release `node-v<version>` and needs `GITEE_TOKEN` (or
`--token-file`); without it the release is manual. The `node-v*` tag namespace
is shared with the image pipeline: one tag, two artefacts.

On the host:

```sh
./install.sh --cp https://cp.example.org --node tokyo01
```

`install.sh` installs nginx, Xray, the unit files, and the host layout, then
runs `vela-server enroll`. See the script's `--help` for the knobs.

---

## Repository layout

```
src/               the reconciler (Rust, static musl binary)
Dockerfile         three stages: crate build, downloads, runtime
image/s6-overlay/  s6 service definitions for nginx, xray, vela-server
compose.yaml       one service, one node
install.sh         bare-metal installer (shared with the tarball)
systemd/ openrc/   unit files for bare-metal installs
scripts/           release tooling (tarball, Gitee)
.github/workflows/ image build and publish
```

## License

AGPL-3.0-or-later. See `LICENSE`.