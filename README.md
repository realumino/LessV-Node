# vela-server

The node side of [Vela](https://github.com/realumino/Vela): a static Rust
reconciler that pulls its desired state from the control plane and converges
Xray, the certificate tree, and the nginx decoy inside one container.

It ships as one thing: the `ghcr.io/realumino/vela-server` image (node, nginx,
Xray, supervised by s6-overlay). Docker or any OCI runtime is the only
supported way to run it — the image is what makes the node reproducible, and
there is no second delivery path to keep in step.

The node is a reconciler, not a proxy: it holds no listener of its own, never
serves traffic, and its only job is to make the host match the plane.

The pull protocol (endpoints, payloads, the `bearer-v1` token rules) is defined
by the control plane and lives in
[the plane's `docs/PROTOCOL.md`](https://github.com/realumino/Vela/blob/main/docs/PROTOCOL.md);
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

`<version>` is the release version, carried by `Cargo.toml` for the crate and
the image together, and `vela-server version` run from the image prints it;
the release workflow refuses a `v<version>` tag that disagrees or is not strict
SemVer (`X.Y.Z` or `X.Y.Z-<pre-release>`, no build metadata — a `+` cannot
appear in an image tag). Pre-releases publish `<version>` and `sha-<short>`
and never move `latest`.

The image is the release unit, so the version belongs to it, not to the crate:

| Bump | Reason |
|---|---|
| MAJOR | protocol or data-format break: an old plane cannot talk to the new server, or a plane migration is irreversible |
| MINOR | backwards-compatible capability: a new endpoint, a new optional field |
| PATCH | contents only: bug fix, Xray bump, nginx bump, base image change |

Any change to image contents bumps at least PATCH — an nginx-only update is a
new tag, never the same number on a different artifact. The components inside
are recorded by `org.opencontainers.image.revision`, the job summary, and
`/usr/share/vela/components.txt`, not by the tag.

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
         --nginx-conf-path /etc/nginx/http.d/vela-decoy.conf
```

The token is read from stdin (hidden when stdin is a TTY). `node.toml` is
written before the plane is contacted, so a failed enroll still leaves a
complete file: fix the plane and run enroll again, or just start the container.

`--nginx-conf-path` is mandatory in the image. The default nginx directory is
Debian's `/etc/nginx/conf.d`, which Alpine does not use. Supervision is always
s6: there is no init system to choose.

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
  a peer's address in the logs is the bridge's. The plane does not track a
  reported address at all — the fleet view answers "when did it last report"
  from the heartbeat.

If you want the client's real source address to reach Xray and the decoy, use
host networking instead: drop `network_mode` and `ports:` and set
`network_mode: host`. A host network still needs 80/443 free and nothing else
may bind them.

Host-level concerns stay on the host: the firewall, `net.ipv4.tcp_congestion_control`
(BBR), IPv6 reachability, and the plane's address allow-lists all apply to the
container exactly as they would to a server running directly on the machine.

---

## Supervision

s6-overlay owns the three processes inside the image:

| Service | Started by | Reload |
|---|---|---|
| `vela-server` | the s6 tree, once `node.toml` exists | — |
| `xray` | the s6 tree, once a live config exists | none: Xray handles only SIGTERM, so a config change is a restart |
| `nginx` | the s6 tree | `s6-svc -h` (SIGHUP), which is what `nginx -s reload` sends |

Liveness is read from `s6-svstat -o up,pid,updownfor` and the supervised
process's name in `/proc/<pid>/comm`; the settle window is what makes a
crash-looping Xray read as *not* survived, so a bad config rolls back. Docker
restarts the container only when PID 1 dies, which is a bug worth reporting.

---

## Operational notes

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
- pushing a `v<version>` tag tests, verifies the tag against
  `Cargo.toml`
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

## Repository layout

```
src/               the reconciler (Rust, static musl binary)
Dockerfile         three stages: crate build, downloads, runtime
image/s6-overlay/  s6 service definitions for nginx, xray, vela-server
compose.yaml       one service, one node
scripts/           a stub plane for local testing
.github/workflows/ image build and publish
```

## License

AGPL-3.0-or-later. See `LICENSE`.