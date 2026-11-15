# Testing this repository

WHAT: every environment in which `vela-server` and its image are exercised, what
each one proves, and what it cannot prove.

WHY this file exists separately from `README.md`: the README is the operator's
manual (install, run, upgrade); this is the contributor's and releaser's manual.
They change for different reasons and are read by different people.

Not here: how the control plane is tested, provisioned, or seeded — see
`docs/dev/testing.md` in [Vela](https://github.com/realumino/LessV). This
repository owns the node; the plane's repo owns the plane.

The contract between the two (protocol number, socket path, nginx config
directory, certificate environments) is defined in
[the plane's `docs/PROTOCOL.md`](https://github.com/realumino/LessV/blob/main/docs/PROTOCOL.md)
and in code here (`PROTOCOL_VERSION` in `src/http.rs`, `DEFAULT_DECOY_SOCKET`
and `DEFAULT_NGINX_CONF` in `src/config.rs`). **It is not restated in this
file** — a second copy would drift from both.

---

## The tiers

Nothing here replaces a tier below it. A change is "done" at the lowest tier
that can observe it; the higher tiers are for integration and release.

| Tier | Environment | Proves | Cost | Runs |
|---|---|---|---|---|
| 0 | hermetic crate tests | logic, parsing, supervisor argv, rollback decisions | seconds | every push (CI) |
| 1 | image build assertions | the artefact the operator pulls is internally consistent | ~3 min | every push (CI) |
| 2 | stub plane + image | apply, cert sync, rollback, recreate, update — deterministically | ~4 min | manual, or CI on demand |
| 3 | real plane (`wrangler dev`) | the plane's *own* renderer drives the agent | minutes | manual |
| 4 | public host + real 443 | REALITY, decoy TLS, host networking, stop/start, upgrades | cents per run | before a release |

Tiers 0–2 need no Cloudflare account, no DNS and no certificates: tier 2
reaches nothing but `127.0.0.1`, and a built image (pulled or local) is its only
other input. Tier 3 needs a plane checkout; tier 4 needs a throwaway host.

---

## Tier 0 — hermetic crate tests

```sh
cargo test --locked                       # the whole suite
cargo build --locked --release --target x86_64-unknown-linux-musl
```

The crate is `std::os::unix`, so the build host is Linux (native, a container,
or WSL). On a musl host the multi-target `.cargo/config.toml` picks `rust-lld`
with `link-self-contained`; on a glibc host with `musl-tools` installed it
links with `musl-gcc`. A static-PIE binary has no `PT_INTERP` — that is the
"no runtime dependency" claim, and the image build asserts it (tier 1).

What the suite covers by design: config parsing and validation, the apply state
machine with fake fetch/test/restart closures, certificate manifest validation
and rollback, nginx config rendering, geodata install/rollback, supervisor argv
per init system, and the `s6-svstat` field parser.

What it cannot cover: anything that needs a real init system, real sockets, or
a real kernel — the s6 verbs, `:80`/`:443` binding, TLS negotiation, container
restart semantics. Those belong to tiers 2–4. **A green tier 0 is not evidence
that the image works**, and that has been true in practice: two defects
(crash-loop read as success, missing `XRAY_LOCATION_ASSET` in the supervised
process) passed every unit test and only appeared on a real host.

## Tier 1 — image build assertions

```sh
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml)
docker build --build-arg VERSION="$VERSION" -t vela-server:test .
```

The build fails, rather than shipping, on any of:

1. `nginx -V` reporting OpenSSL < 3.5 (the post-quantum group requirement);
2. `nginx -t` on the stock config (before any decoy file exists);
3. `xray version` not matching the pinned `XRAY_VERSION`;
4. `vela-server version` not matching `--build-arg VERSION`;
5. either binary missing or not executable.

Plus, in the builder stage: `readelf -l … | grep INTERP` must find nothing.
CI additionally refuses an s6 `run` script that does not start with
`#!/command/with-contenv sh` — a supervised service that silently loses the
image's `ENV` was the defect behind a real production failure mode.

A build without `--build-arg VERSION` must fail at (4). If it succeeds, the
assertion has rotted and the tag is meaningless.

## Tier 2 — stub plane, deterministic phases

The stub answers the five node endpoints with file-backed state, using the
response shapes of `Vela/src/routers/node.ts`:

```sh
STATE=$(mktemp -d)
printf 'test-token' > "$STATE/token"          # whitespace is stripped on read
printf 'node01'     > "$STATE/node"
python3 scripts/dev_stub_plane.py --state-dir "$STATE" --port 8080
```

Then, for each phase, write `$STATE/state.json` and let a node converge against
it. Enroll once (`--cp http://127.0.0.1:8080`, `--nginx-conf-path
/etc/nginx/http.d/vela-decoy.conf`), then run the phases:

| Phase | `state.json` | Expected |
|---|---|---|
| apply | a REALITY config **with a `geoip:` rule** + one cert in `certs` | `applied config <hash>`; report `stage: started, ok: true`; decoy conf rendered, `:443` serves it, `:80` 301 |
| bad config | a config `xray -test` rejects | report `stage: test, ok: false`, `xray_exit_code: 23`; previous config keeps serving |
| dies on bind | a config that passes `-test` and binds `:80` | report `stage: started, ok: false, … rolled back to last-good`; `applied_hash` unchanged |
| recreate | same as apply | 0 applies; decoy conf rewritten after boot; both ports back |
| update | `{"actions":[{"action":"update_xray","version":"v26.10.31"}]}` | report `ok: true, version 26.10.31`; heartbeat reports it |
| recreate again | — | image's pinned Xray is back, heartbeat reports the real version |

The `geoip:` rule in phase 1 is not decoration: a config with only a REALITY
inbound passes even when the supervised Xray cannot read the geodata, which is
how the `XRAY_LOCATION_ASSET` defect survived a full day of testing.

Inspect what the node reported: `$STATE/reports.log`, `actions.log`,
`heartbeats.log`. Reset a phase by overwriting `state.json`; the node picks it
up on the next poll (`--poll-interval 5` keeps this fast).

The stub does not validate anything a real plane validates (tokens, zones,
rendering). It is for the node's behaviour, not the plane's.

## Tier 3 — the plane's own renderer

With a [Vela](https://github.com/realumino/LessV) checkout:

```sh
npx wrangler d1 migrations apply DB --local --persist-to /tmp/vela-dev
npx wrangler dev --port 8788 --persist-to /tmp/vela-dev --ip 0.0.0.0
```

Create a node and mint its token through the admin API, author a config
(`PUT /api/admin/nodes/<id>/config`), set `cert_environment` to `staging`, then
enroll the image with `--cp http://<host>:8788`. The plane test doc details the
API calls.

Why this tier exists next to tier 2: the stub's shapes were copied from the
plane, so it can drift. This tier feeds the agent the *real* renderer's bytes —
validation, merge order, and defaults included — at the cost of needing the
other repository.

Ceiling: no real certificates. Issuance from a local dev Worker would call real
ACME and real DNS; keep `CF_DNS_API_TOKEN` a placeholder locally and expect an
empty certificate manifest. Certificate sync is proved at tier 4.

## Tier 4 — a public host with real ports

Before a release, on a throwaway host (a small VPS reaches the same conclusion
as a big one):

1. `docker compose up -d` with the image under test, volumes as in
   `compose.yaml`, `network_mode: bridge` plus `ports:`.
2. Enroll from a second shell, token on stdin, `--nginx-conf-path
   /etc/nginx/http.d/vela-decoy.conf`.
3. Assert, from **outside** the host:

   ```sh
   curl -sI http://<host>/                          # 301
   openssl s_client -connect <host>:443 -servername <domain> \
     -groups X25519MLKEM768 -tls1_3                 # "Negotiated TLS1.3 group: X25519MLKEM768"
   ```

   and, through a REALITY client (the image's own `xray` binary works):
   a proxied request returns the host's public address. The server log shows
   `accepted tcp:… [reality >> freedom]`.
4. `docker exec <c> /command/s6-svstat -o up,pid,updownfor /run/service/xray`
   — `true <pid> <seconds>`; the pid must belong to `xray`.
5. `docker stop` returns in under ~2 s with exit code **0**; `docker start`
   re-enrolls nothing and both ports come back.
6. `docker compose pull && up -d` with a rebuilt tag: traffic survives, volumes
   retain identity and `applied_hash`.

Host rules: key-only SSH (`sshd -T | grep passwordauthentication` → `no`),
ephemeral instance created for the run and deleted afterwards, node token never
in argv, `cert_environment=staging` on the plane so no production certificate is
ever pulled during a test.

What this tier still cannot prove: that the plane's *authored* config renders
correctly (that is tier 3), and scale (one node is one node).

---

## What a test run needs from you

The image itself holds **no credentials**. It reads one minted node token from
stdin at enroll, writes it to `/etc/vela/node.toml` (0600, inside a volume),
and from then on authenticates only with that. No Cloudflare token, no cloud
provider key, no registry credential is ever needed or accepted by the node.

A node token is the only value in this list that the image itself persists, and
it is exactly as powerful as that one node's rendered config.

| Tier | You need | Scope of the only real credential |
|---|---|---|
| 0 | a Rust toolchain on Linux (or a container) | — |
| 1 | Docker | — |
| 2 | Docker + Python 3 | — (the stub plane is local; token is a literal you write) |
| 3 | a Vela checkout + `npm install` | `.dev.vars` holds *invented* values only: `ADMIN_KEY` (32 random bytes), `KEY_SECRET` (32 random bytes), `CF_DNS_API_TOKEN` = any placeholder, because nothing reaches Cloudflare |
| 4 | one throwaway host; optionally a GHCR read credential | node token, minted by the plane for that one node (re-mint `POST /api/admin/nodes/:id/token` to revoke the old one instantly; deleting the node revokes it too); if the package is private, a token with `read:packages` only |

Sort what you handle into three buckets; if a value fits none of them, it does
not belong in a test:

| Bucket | Here | Loss costs |
|---|---|---|
| disposable — regenerate and move on | the node token (re-mint on the plane, then re-enroll) | one re-enroll |
| you create, know the scope | provider token for a scripted host; registry token if the package is private | reaches real assets — see the scope column below |
| never yours to invent | the node's REALITY private key and certificate keys, generated by the plane and delivered inside `config.json` / the certificate manifest | not applicable — do not author, copy or store them by hand |

In a throwaway environment only the middle row is worth care: the node token
dies with the node row, and the plane's keys die with the volume. The moment you
point a test node at the **production** plane, that stops being true — its token
and REALITY key are production credentials.

If you automate the host (create → test → destroy), the provider credential is
the one to create carefully: for Linode, `linodes:read_write` and nothing else —
no account, volume, firewall or domain scopes. Be aware that this scope is
**account-wide for instances**: the same token can delete the nodes you actually
run. Use a token made for testing (ideally with an expiry) or a restricted
sub-account, and revoke it when the run is over.

A node token is not a lesser credential in the same sense: it carries exactly
one node's rendered config, which includes that node's REALITY private key.
Treat it as that node's root password, and never lift one from a test run into
production.

The full table, ranked by blast radius (including `KEY_SECRET`, `ADMIN_KEY`, the
Cloudflare zone scope and the Access service token) is in
[the plane's `docs/dev/testing.md`](https://github.com/realumino/LessV/blob/main/docs/dev/testing.md#credentials-what-actually-needs-care).

## Fidelity ladder

When building a test environment, match these or expect false confidence:

| Keep identical | Safe to fake |
|---|---|
| the binary and image digest under test | host size, region, provider |
| `workerd`/container restart semantics (`s6`, `docker stop`) | traffic volume, client count |
| nginx and Xray versions (from the same image) | domain names |
| the decoy socket path and nginx config path | certificate authority (LE staging) |
| the protocol version and endpoints | DNS propagation timing |
| certificate *environment* semantics (`staging` pointer) | number of nodes |

## Failure policy

- A test that fails on an unrelated change is quarantined with a linked issue
  in the same commit, never deleted. Deleting loses the signal for good.
- A fixed bug gets a regression test in the same commit — a unit test when the
  cause is logic, a tier 2 phase when the cause is integration.
- Never "fix" a flaky test by raising its timeout or adding a sleep without
  writing down which condition it was waiting for.
- A red tier 1–4 run blocks the release even when tier 0 is green.

## What CI runs today

| Check | Where | Tier |
|---|---|---|
| `cargo test`, musl release build | `.github/workflows/image.yml`, job `test` | 0 |
| s6 run-script shebang guard | same job | 1 |
| image build (both architectures) + the five assertions | jobs `build (amd64/arm64)` | 1 |
| publish + multi-arch index assertion | job `merge`, on `node-v*` tags | 1 |
| tiers 2–4 | **manual**; recorded in the release notes | 2–4 |

Promoting tier 2 into CI is the obvious next step: it needs only Docker and
Python, and it is the only automated check that exercises the supervised
processes at all.
