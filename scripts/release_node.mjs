/**
 * WHAT: build the lessv-node release artifacts and publish them to a Gitee
 * release.
 *
 * WHY from a clean tree and from one version source: the artifact that lands
 * on a node must be exactly what was committed, and the version in the file
 * name must be the version the binary reports. `Cargo.toml` is the one source;
 * `--version` is not accepted.
 *
 * Output (dist/): for each target
 *   lessv-node-<version>-linux-<arch>.tar.gz  (binary, install.sh, VERSION,
 *                                              systemd/, openrc/)
 * plus SHA256SUMS, install.sh, VERSION and per-tarball .sha256 sidecars.
 *
 * Usage:
 *   node scripts/release_node.mjs [--targets amd64,arm64] [--upload]
 *     [--token-file <path>] [--owner <owner>] [--repo <repo>]
 *
 * The tarball deliberately stays on the Vela Gitee release
 * (gitee.com/realumino/lessv, tag node-v<version>): that is where install.sh
 * and the Alpine cloud-init profile look for it. The same tag also triggers
 * the image pipeline, so one tag publishes two artifacts.
 *
 * Build host: a Linux machine with rustup + the musl targets (musl-gcc), or
 * Windows with the zig wrappers documented in the repository; cross
 * compilation is the caller's environment (CC_<target>/AR_<target>), this
 * script only invokes cargo.
 */

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const DIST = join(REPO_ROOT, "dist");
const TARGETS = {
  amd64: "x86_64-unknown-linux-musl",
  arm64: "aarch64-unknown-linux-musl",
};
const FORBIDDEN_TARBALL_ENTRIES = ["src/", "Cargo", "target/", ".cargo", "image/", "Dockerfile"];

const args = process.argv.slice(2);
const upload = args.includes("--upload");
const flag = (name, fallback = null) => {
  const index = args.indexOf(`--${name}`);
  return index >= 0 ? args[index + 1] ?? fallback : fallback;
};

const owner = flag("owner", "realumino");
const repo = flag("repo", "lessv");
const targets = (flag("targets", "amd64") ?? "amd64")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

/** WHAT: run a command, dying with its output on failure. */
function run(command, commandArgs, options = {}) {
  const result = spawnSync(command, commandArgs, {
    cwd: options.cwd ?? REPO_ROOT,
    encoding: "utf8",
    shell: options.shell ?? process.platform === "win32",
    env: process.env,
  });
  if (result.status !== 0) {
    console.error(
      `${command} ${commandArgs.join(" ")} failed:\n${result.stdout ?? ""}\n${result.stderr ?? ""}`,
    );
    process.exit(1);
  }
  return result.stdout ?? "";
}

/** WHAT: run git and return stdout, dying on failure. */
function git(gitArgs) {
  return run("git", gitArgs);
}

const manifest = readFileSync(join(REPO_ROOT, "Cargo.toml"), "utf8");
const version = manifest.match(/^version = "([^"]+)"/m)?.[1];
if (!version) {
  console.error("cannot parse version from Cargo.toml");
  process.exit(1);
}
if (manifest.match(/^name = "([^"]+)"/m)?.[1] !== "lessv-node") {
  console.error("Cargo.toml package name must be lessv-node");
  process.exit(1);
}

const dirty = git(["status", "--porcelain"]).trim();
if (dirty) {
  console.error("the tree has uncommitted changes — commit first, then release:\n" + dirty);
  process.exit(1);
}
const commit = git(["rev-parse", "HEAD"]).trim();

for (const target of targets) {
  if (!TARGETS[target]) {
    console.error(`unknown target ${target}; expected one of ${Object.keys(TARGETS).join(",")}`);
    process.exit(1);
  }
}

rmSync(DIST, { recursive: true, force: true });
mkdirSync(DIST, { recursive: true });

/**
 * WHAT: copy a shell/unit artifact with LF endings, whatever the build host.
 *
 * WHY: the tarball is assembled on Windows too, and an editor that saved the
 * init script with CRLF turns its `#!` line into an unknown interpreter —
 * OpenRC then answers "Failed executing '/etc/init.d/xray'". The release
 * script is the last place that can guarantee a POSIX file.
 */
function copyPosixText(source, dest) {
  writeFileSync(dest, readFileSync(source, "utf8").replaceAll("\r\n", "\n"));
}

const installScript = join(REPO_ROOT, "install.sh");
const bundled = [
  ["install.sh", installScript, 0o755],
  [join("systemd", "lessv-node.service"), join(REPO_ROOT, "systemd", "lessv-node.service"), 0o644],
  [join("systemd", "xray.service"), join(REPO_ROOT, "systemd", "xray.service"), 0o644],
  [join("openrc", "lessv-node.initd"), join(REPO_ROOT, "openrc", "lessv-node.initd"), 0o755],
  [join("openrc", "xray.initd"), join(REPO_ROOT, "openrc", "xray.initd"), 0o755],
  [join("openrc", "lessv-logrotate"), join(REPO_ROOT, "openrc", "lessv-logrotate"), 0o644],
];

const artifacts = [];

for (const target of targets) {
  const triple = TARGETS[target];
  console.log(`building lessv-node ${version} for ${target} (${triple})`);
  // cwd is the crate root so .cargo/config.toml (rust-lld + self-contained
  // musl linking) applies; cargo reads config relative to the invocation dir.
  run("cargo", ["build", "--release", "--target", triple], { cwd: REPO_ROOT });
  const binary = join(REPO_ROOT, "target", triple, "release", "lessv-node");
  const magic = readFileSync(binary).subarray(0, 4);
  if (!magic.equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) {
    console.error(`${binary} is not an ELF binary`);
    process.exit(1);
  }

  const name = `lessv-node-${version}-linux-${target}`;
  const stage = mkdtempSync(join(DIST, "stage-"));
  const root = join(stage, name);
  mkdirSync(join(root, "systemd"), { recursive: true });
  mkdirSync(join(root, "openrc"), { recursive: true });
  copyFileSync(binary, join(root, "lessv-node"));
  writeFileSync(join(root, "VERSION"), `${version}\n`);
  for (const [relative, source, mode] of bundled) {
    const dest = join(root, relative);
    copyPosixText(source, dest);
    // WHY explicit modes: writeFileSync creates 0644, and a non-executable
    // install.sh or OpenRC init script is a broken artifact -- the operator's
    // `./install.sh` answers "Permission denied" and `rc-service` refuses to
    // run the script at all.
    chmodSync(dest, mode);
  }
  // The installer and the unit files must be executable/served as-is; the
  // tarball carries them at 0755/0644 exactly like the committed tree.
  const tarball = join(DIST, `${name}.tar.gz`);
  // Relative paths on purpose: GNU tar reads an absolute Windows path
  // ("C:/...") as a remote host and refuses to write the archive.
  run("tar", ["-czf", `${name}.tar.gz`, "-C", stage.slice(DIST.length + 1), name], {
    cwd: DIST,
  });
  rmSync(stage, { recursive: true, force: true });

  const listing = run("tar", ["-tzf", `${name}.tar.gz`], { cwd: DIST }).trim().split("\n");
  for (const required of [
    `${name}/lessv-node`,
    `${name}/install.sh`,
    `${name}/VERSION`,
    `${name}/systemd/lessv-node.service`,
    `${name}/openrc/lessv-node.initd`,
  ]) {
    if (!listing.includes(required)) {
      console.error(`${name}.tar.gz is missing ${required}`);
      process.exit(1);
    }
  }
  for (const forbidden of FORBIDDEN_TARBALL_ENTRIES) {
    const leaked = listing.find((entry) => entry.startsWith(`${name}/${forbidden}`));
    if (leaked) {
      console.error(`${name}.tar.gz must not contain ${forbidden}: ${leaked}`);
      process.exit(1);
    }
  }

  const bytes = readFileSync(tarball);
  const sha = createHash("sha256").update(bytes).digest("hex");
  writeFileSync(`${tarball}.sha256`, `${sha}  ${name}.tar.gz\n`);
  artifacts.push({ name: `${name}.tar.gz`, path: tarball, sha });
  console.log(`  dist/${name}.tar.gz (${bytes.length} bytes, sha256 ${sha.slice(0, 16)}…)`);
}

// Standalone installer + version file, so a host can bootstrap without
// knowing the release name: install.sh reads VERSION, then downloads the
// matching tarball and verifies it against SHA256SUMS.
copyPosixText(installScript, join(DIST, "install.sh"));
chmodSync(join(DIST, "install.sh"), 0o755);
writeFileSync(join(DIST, "VERSION"), `${version}\n`);
const sums = [
  ...artifacts.map((artifact) => `${artifact.sha}  ${artifact.name}`),
  `${createHash("sha256").update(readFileSync(join(DIST, "install.sh"))).digest("hex")}  install.sh`,
  `${createHash("sha256").update(readFileSync(join(DIST, "VERSION"))).digest("hex")}  VERSION`,
];
writeFileSync(join(DIST, "SHA256SUMS"), `${sums.join("\n")}\n`);

const releaseFiles = [
  ...artifacts.map((artifact) => join(DIST, artifact.name)),
  join(DIST, "SHA256SUMS"),
  join(DIST, "install.sh"),
  join(DIST, "VERSION"),
];

if (!upload) {
  console.log(`\nbuilt ${releaseFiles.length} files in dist/ (tag node-v${version}, ${commit.slice(0, 12)})`);
  console.log("pass --upload to publish to Gitee");
  process.exit(0);
}

// ------------------------------------------------------------------ Gitee

const tokenFile = flag("token-file");
const token =
  process.env.GITEE_TOKEN?.trim() ||
  (tokenFile
    ? readFileSync(tokenFile, "utf8")
        .split("\n")
        .map((line) => line.match(/^GITEE_TOKEN=(.*)$/)?.[1]?.trim() ?? line.trim())
        .find((value) => value.length > 0)
    : "");
if (!token) {
  console.error("no Gitee token: set GITEE_TOKEN or pass --token-file");
  process.exit(1);
}

const API = "https://gitee.com/api/v5";
const tag = `node-v${version}`;

async function api(method, path, body) {
  const response = await fetch(`${API}${path}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(60_000),
  });
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { raw: text.slice(0, 400) };
  }
  return { status: response.status, data };
}

const repoPath = `/repos/${owner}/${repo}`;

async function findRelease() {
  const result = await api("GET", `${repoPath}/releases/tags/${tag}?access_token=${encodeURIComponent(token)}`);
  if (result.status === 200) {
    return result.data;
  }
  return null;
}

let release = await findRelease();
if (release === null) {
  const created = await api("POST", `${repoPath}/releases`, {
    access_token: token,
    tag_name: tag,
    name: `lessv-node ${version}`,
    body: [
      `Static Linux binaries of the Vela node reconciler ${version}.`,
      "",
      "Assets:",
      "- `lessv-node-<version>-linux-amd64.tar.gz` / `-arm64.tar.gz` (binary, install.sh, units)",
      "- `install.sh`, `VERSION`, `SHA256SUMS`",
      "",
      "Install: download the tarball for the host architecture, verify it",
      "against `SHA256SUMS`, extract it, then run `./install.sh --cp <url> --node <id>`.",
      "",
      "The same tag also publishes the container image `ghcr.io/realumino/lessv-node`.",
    ].join("\n"),
    target_commitish: commit,
    prerelease: false,
  });
  if (created.status !== 201 && created.status !== 200) {
    console.error(`Gitee release creation failed (${created.status}): ${JSON.stringify(created.data)}`);
    process.exit(1);
  }
  release = created.data;
} else {
  console.log(`reusing existing Gitee release ${tag} (id ${release.id})`);
}

const existing = await api(
  "GET",
  `${repoPath}/releases/${release.id}/attach_files?access_token=${encodeURIComponent(token)}&per_page=100`,
);
const existingNames = new Map(
  (existing.status === 200 ? existing.data : []).map((file) => [file.name, file.id]),
);

for (const file of releaseFiles) {
  const name = file.split(/[\\/]/).pop();
  if (existingNames.has(name)) {
    const deleted = await api(
      "DELETE",
      `${repoPath}/releases/${release.id}/attach_files/${existingNames.get(name)}?access_token=${encodeURIComponent(token)}`,
    );
    if (deleted.status !== 204 && deleted.status !== 200) {
      console.error(`cannot replace existing asset ${name} (${deleted.status})`);
      process.exit(1);
    }
  }
  const form = new FormData();
  form.append("access_token", token);
  form.append("file", new Blob([readFileSync(file)]), name);
  const response = await fetch(`${API}${repoPath}/releases/${release.id}/attach_files`, {
    method: "POST",
    body: form,
    signal: AbortSignal.timeout(180_000),
  });
  if (response.status !== 201 && response.status !== 200) {
    console.error(`upload of ${name} failed (${response.status}): ${(await response.text()).slice(0, 400)}`);
    process.exit(1);
  }
  console.log(`uploaded ${name}`);
}

console.log(`published https://gitee.com/${owner}/${repo}/releases/tag/${tag}`);