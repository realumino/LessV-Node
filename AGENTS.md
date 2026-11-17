# AGENTS.md — vela-server

Working rules for coding agents in this repository. Layers on top of the
operator's global agent instructions; where they overlap, the stricter rule
wins.

## What this repo is

The node side of Vela: a static Rust reconciler that pulls its desired state
from the control plane and converges Xray, the certificate tree, and the nginx
decoy inside one container. The deliverable is the
`ghcr.io/realumino/vela-server` image (reconciler, Xray, nginx, s6-overlay),
not the crate; Docker or any OCI runtime is the only supported way to run it.

The node is a reconciler, not a proxy: it holds no listener of its own, never
serves traffic, and its only job is to make the host match the plane. It owns
no wire format — the pull contract belongs to the plane and lives in
[LessV's `docs/PROTOCOL.md`](https://github.com/realumino/Vela/blob/main/docs/PROTOCOL.md);
this tree implements it, it does not define it.

Entry docs, in order: `README.md` (operator manual: enroll, run, upgrade,
volumes, troubleshooting), `docs/testing.md` (test tiers, what each proves,
credentials, failure policy), then the plane's `docs/PROTOCOL.md` (endpoints,
payloads, `bearer-v1` token rules) and `docs/dev/architecture.md`. Read the one
covering the area you are changing, and keep every doc true in the same commit
as the change.

## Related repositories

The project is two public repositories and neither is complete without the
other:

- **[LessV](https://github.com/realumino/Vela)** — the control plane:
  Cloudflare Workers + D1 + Workflows, admin SPA at `/admin`, config
  rendering, certificate issuance, node provisioning. It owns the pull
  contract, the wire field names, and every constant a node must obey.
- **LessV-Node** (this tree) — the node: the crate, the image build, the s6
  service definitions, and the compose file. It implements that contract and
  carries no plane code.

Cross-repo rules:

- A wire change is one change set spanning both trees: the plane's
  `docs/PROTOCOL.md`, `PROTOCOL_VERSION` (`src/routers/node.ts`) and
  `tests/pure/protocol_freeze.test.ts`, this crate's `PROTOCOL_VERSION`
  (`src/http.rs`), and a version bump in `Cargo.toml`. One commit per
  repository, same intent: the crate version is the third value of the plane's
  protocol invariant, and a protocol bump that lands on one side only is a
  broken release.
- A version bump on its own is a release, not a protocol change: it needs no
  plane-side commit, but the `v<version>` tag, the image's `<version>` tag, and
  `Cargo.toml` must agree. The version is the image's, not only the crate's:
  MAJOR is a protocol or data-format break, MINOR an additive capability, and
  any change to image contents (an Xray or nginx bump, a base image change)
  bumps at least PATCH, so two images never share one tag.
- Constants owned by the plane are mirrored in code here, never redefined: the
  decoy socket path and nginx config defaults (`src/config.rs`), the protocol
  number, the `X-Vela-Server` identity header, the certificate environments.
  Changing one is a two-repo change.
- The image is built, tested, and published only here; the plane tree never
  builds it. This tree never builds, tests, or deploys the plane — tier 3 runs
  a plane checkout beside it and does not modify it.

## Repository layout (tracked, public)

- `src/` — the crate: `reconcile.rs` (loop), `apply.rs`/`certs.rs`/`nginx.rs`/
  `geodata.rs` (state machines and rollback), `http.rs` (protocol client),
  `config.rs` (`node.toml` and the plane-owned constants), `supervisor.rs`
  (s6 verbs), plus `xray.rs`, `state.rs`, `stats.rs`, `net.rs`, `util.rs`
- `Dockerfile` — three stages (builder, fetch, runtime) plus the build
  assertions that keep a broken image from shipping
- `image/s6-overlay/` — the s6-rc definitions for the three processes
- `compose.yaml` — the runtime contract for one node: ports, volumes, ulimits,
  stop grace; not a topology
- `scripts/` — development tools, currently the protocol-3 stub plane. Each
  carries a WHAT/WHY header; parameters are neutral placeholders (`<cp-url>`,
  `<node-id>`) — never hardcode hosts, tags, tokens, IPs, or domains
- `docs/testing.md` — contributor and releaser manual
- `.github/workflows/image.yml` — crate baseline, per-architecture builds,
  publish on tag
- `.cargo/config.toml` — linker defaults for cross-compiling to musl

## Local-only paths (gitignored — never commit, never print their values)

- `.plans/` — operator workspace: in-progress plans, run outputs, scratch
  notes. Plans for future work live here, not in the repo root and not in
  `docs/`. It may reference real hosts, tokens, or run data — that is exactly
  why it stays untracked. Never copy such content into tracked files or commit
  messages. When work completes: distill permanent constraints into
  docs/comments, distill automation into `scripts/` or tests, then discard or
  archive the plan locally.
- `target/`, `dist/`, `VERSION` — build output; never edit or commit.

There is no secrets file in this tree: the node's only credential is the token
inside the `/etc/vela` volume, written once by `enroll`. Never add a `.env`, a
token file, or a test fixture that holds a real one.

## Public/local separation

The remote is public. The tracked tree carries current truth only:

- No phase or stage codenames, no execution logs, no run reports, no
  acceptance evidence.
- No real infrastructure identifiers: node hostnames or addresses, certificate
  serials or fingerprints, account handles, absolute local paths, tokens.
- Conclusions worth keeping are distilled into docs or code comments;
  automation worth keeping is distilled into `scripts/` or tests; intermediate
  artifacts are not stored anywhere in the tree. An important but
  non-persistable thing is resolved, not warehoused: if it matters, it gets a
  durable home (repo, VCS history, release notes); if it does not, the thing
  that generates it belongs in the repo instead.

## Documentation and comments

- Operator docs are `README.md`; contributor and releaser docs are
  `docs/testing.md`. Do not add PLAN/WORKBOOK-style files anywhere else in the
  tree.
- Comments state invariants and reasons, self-contained — no references to
  plans, sessions, or files that do not exist in the tree. Files whose
  reasoning is not obvious from the code (Dockerfile, `compose.yaml`, s6 run
  scripts, `scripts/`, non-trivial modules) carry a WHAT/WHY header.
- The wire contract is linked, never restated. A second copy of the protocol
  drifts from the plane's `docs/PROTOCOL.md` without anyone noticing.
- The server is never ahead of the plane: a protocol upgrade ships the new
  plane first, and only a plane that speaks the higher number may raise the
  crate's. On a protocol refusal the server logs the plane's error and keeps
  serving its current config; it never guesses a wire shape it has not
  shipped.
- The operator tables in `README.md` (image surface, ports, volumes, tags,
  troubleshooting) are a contract with whoever runs a node; change them with
  the code that backs them.

## Verification

Baseline before declaring any work done (all green):

```bash
cargo test --locked
cargo build --locked --release --target x86_64-unknown-linux-musl
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml)
docker build --build-arg VERSION="$VERSION" -t vela-server:test .
```

- Tier 0 is hermetic: no network, no plane, no DNS, no Docker. It covers
  parsing, the apply state machine with fake closures, certificate manifest
  validation, nginx rendering, geodata rollback, and supervisor argv.
- Tier 1 is the image build's own assertions (nginx's OpenSSL version,
  `nginx -t`, the pinned Xray version, `vela-server version`, static linking,
  executable binaries). A build without `--build-arg VERSION` must fail at the
  version assertion; if it succeeds, the assertion has rotted.
- The crate is `std::os::unix`: build on Linux (native, a container, or WSL).
- Tiers 2–4 are manual: the stub plane, a real plane via `wrangler dev` (needs
  a LessV checkout), and a throwaway host with real 443. Tier 4 touches real
  ports and DNS: only on explicit operator request, with
  `cert_environment=staging` on the plane. Never point a test node at the
  production plane — its token then carries that node's REALITY key.
- Never weaken an assertion or skip a tier to get a green result. A fixed bug
  gets a regression test in the same commit; a defect in the image or the
  supervised processes belongs in a tier 2 phase, not only a unit test.
- CI runs tier 0 plus the s6 shebang guard and tier 1 for both architectures
  on every push and PR; only a `v*` tag publishes, and the tag must match
  `Cargo.toml`.

## Standing invariants

- Never commit or print credentials: the node token, plane-side secrets
  (`ADMIN_KEY`, `KEY_SECRET`, `CF_DNS_API_TOKEN`), provider tokens, VLESS
  URIs/uuids, REALITY and certificate private keys. The token enters on stdin
  at enroll only — never argv, never the environment (both are readable from
  `ps` and shell history) — is stored 0600, and is never logged.
- One image, three processes, one identity (one token, one applied hash, one
  certificate manifest). Never split container. A separate nginx/Xray
  container would need the Docker socket inside it, which is host-root
  equivalence for the component that parses remote-supplied configuration.
- `vela-server` is a static musl binary with no `PT_INTERP`; the image carries
  nginx, Xray, and the s6 supervisor, so a node has no runtime dependency
  beyond Docker, the image, and its two volumes.
- Every s6 `run`/`finish` script starts with `#!/command/with-contenv sh`.
  Without it the service loses the image's `ENV` (`XRAY_LOCATION_ASSET`) and
  every geodata-backed config fails. CI enforces the shebang.
- `/var/lib/vela/config.json` is server-owned: node configuration changes come
  through the plane API and are rendered by the plane, never edited by hand on
  the host. The same holds for `node.toml`.
- Only an explicit, complete 2xx JSON payload may cause a local change;
  transport errors, non-2xx, empty bodies, and malformed JSON keep the current
  state and back off. A config that fails `xray -test` or dies after start
  rolls back to `config.last_good`.
- The decoy socket path and the nginx config path are plane constants. The
  image's only override is `--nginx-conf-path /etc/nginx/http.d/vela-decoy.conf`
  (Alpine, not Debian's `conf.d`); do not change either on one node.
- The decoy is post-quantum only (`X25519MLKEM768`): nginx must link OpenSSL ≥
  3.5, there is no classical fallback. Do not relax this to make an older base
  image work.
- There is no container `HEALTHCHECK`: the plane's fleet view is the health
  signal. Docker restarts the container only when PID 1 dies, which is a bug
  worth reporting, not a retry mechanism.
- Dependencies stay minimal (`libc`, `miniz_oxide`, `serde`, `serde_json`,
  `sha2`, `ureq`); each addition needs a concrete justification, and nothing
  may add a runtime requirement to the image.

## Working rules

- Investigate before planning: read the code, tests, and docs the task
  touches; verify assumptions by running targeted commands. State verified
  facts, inferences, and unknowns separately.
- Prefer the simplest implementation that is rigorous, reproducible,
  readable, and sufficient. No speculative abstractions; delete dead code.
- Deliver exactly what was requested; treat the operator as technically
  competent; no unsolicited additions or tutorial-style explanations.
- One concern per commit; imperative commit messages without phase prefixes.
- Do not change the plane to fit the node. If the contract itself is wrong, fix
  it in LessV and bump the protocol in the same change set.
- Do not touch operator infrastructure: no enrolling, upgrading, recreating, or
  deleting a live node, and no deploy, migration, or DNS change at the plane.
  Those are operator actions on explicit request.
