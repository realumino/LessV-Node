//! nginx decoy site: render the static server blocks from the manifest.
//!
//! WHAT: one `server` block per assigned certificate, listening only on the
//! decoy's Unix socket (REALITY's `dest`), a plain-HTTP `:80` block that
//! redirects to HTTPS, the decoy page, and the `nginx -t` gate.
//! WHY the node owns this file: the certificate paths and the SNI names are
//! exactly the facts the plane delivers, so keeping them in one generated
//! file means a renewal needs no manual nginx edit — the reload after the
//! swap is enough. The form stays static on purpose: Xray owns 443 and this
//! decoy never listens on it.
//!
//! WHY the Unix socket is the only listener: Xray and nginx share the host,
//! so the stolen handshake and every fallback request can stay inside the
//! kernel. It needs no TCP port and cannot be reached from the network even
//! if the firewall is opened. A loopback compatibility listener existed while
//! authored configs still named `127.0.0.1:8443`; the preset and the fleet
//! now use the socket, so the duplicate port is gone.

use std::fs;
use std::path::Path;

use crate::config::Config;
use crate::util::{atomic_write, run_command};

/// WHAT: one certificate as the renderer needs it.
pub struct ServerCert {
    pub domain: String,
    pub path: String,
}

/// WHAT: the post-quantum hybrid group (ML-KEM-768 + X25519).
///
/// WHY this exact list: it is what OpenSSL 3.5+ and BoringSSL negotiate, and
/// the trailing X25519 keeps older clients working. nginx passes the list to
/// the linked TLS library verbatim, so a library without the group fails
/// `nginx -t` — deliberately: post-quantum key exchange is a requirement,
/// not an option, and a host that cannot do it must fail loudly instead of
/// silently serving classical TLS.
pub const PQ_CURVES: &str = "X25519MLKEM768:X25519";

/// WHAT: the marker that makes the decoy page a managed artifact.
///
/// WHY a marker and not a hash: an operator may replace the page with their
/// own. The node rewrites the file only while this marker is present, so a
/// customized page survives upgrades and a managed page follows them.
pub const DECOY_PAGE_MARKER: &str = "<!-- lessv-node-decoy-page -->";

const HEADER: &str = "\
# Managed by lessv-node. Regenerated from GET /api/node/certs on every sync;
# edits are overwritten. Xray owns 443 — this decoy listens on a Unix socket
# (REALITY's dest) only, and redirects plain HTTP on :80 to HTTPS.
";

/// WHAT: the decoy page served at `/`.
///
/// WHY it exists as a generated artifact: the page is part of the cover site,
/// so it must follow upgrades without an operator copying files around. It
/// claims nothing actionable — a generic "secure connection" card, the
/// visitor's own egress address (fetched by the browser, so it shows what the
/// visitor's connection actually exits as), and one link out.
pub const DECOY_PAGE: &str = r##"<!doctype html>
<!-- lessv-node-decoy-page -->
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow, noarchive, nosnippet">
<title>Secure Connection</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{min-height:100vh;display:flex;align-items:center;justify-content:center;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
    background:radial-gradient(circle at 20% 15%,#1f7a4d 0%,#0d3b28 45%,#061d14 100%);
    color:#f2fff8;padding:1.5rem}
  .card{width:min(26rem,100%);text-align:center;padding:2.6rem 2rem;border-radius:22px;
    background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.14);
    box-shadow:0 30px 60px rgba(0,0,0,.45);backdrop-filter:blur(14px)}
  .lock{width:4.2rem;height:4.2rem;margin:0 auto 1.2rem;display:flex;
    align-items:center;justify-content:center;border-radius:50%;
    background:rgba(72,222,138,.14);border:1px solid rgba(72,222,138,.35)}
  .lock svg{width:2.4rem;height:2.4rem;stroke:#63f0a5;fill:none;
    stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
  h1{font-size:1.4rem;font-weight:600;line-height:1.35}
  .tag{display:inline-flex;align-items:center;gap:.4rem;margin-top:1rem;
    padding:.32rem .9rem;border-radius:999px;background:rgba(72,222,138,.16);
    color:#7cf3b3;font-size:.72rem;font-weight:600;letter-spacing:.08em;
    text-transform:uppercase}
  .tag::before{content:"";width:.42rem;height:.42rem;border-radius:50%;
    background:#63f0a5;box-shadow:0 0 8px #63f0a5}
  .meta{margin-top:2rem;padding:1rem 1.1rem;border-radius:14px;
    background:rgba(0,0,0,.28);border:1px solid rgba(255,255,255,.07)}
  .meta-label{font-size:.68rem;letter-spacing:.16em;text-transform:uppercase;
    color:rgba(242,255,248,.55);margin-bottom:.3rem}
  .meta-value{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
    font-size:1.05rem;color:#9fd9ff;word-break:break-all}
  .foot{margin-top:1.6rem;font-size:.74rem;color:rgba(242,255,248,.5);line-height:1.6}
  .foot a{color:#7cf3b3;text-decoration:none;border-bottom:1px solid rgba(124,243,179,.35)}
  .foot a:hover{border-bottom-color:#7cf3b3}
</style>
</head>
<body>
  <main class="card">
    <div class="lock" aria-hidden="true">
      <svg viewBox="0 0 24 24"><rect x="4.5" y="10.5" width="15" height="10" rx="2.4"/><path d="M8 10.5V7.8a4 4 0 0 1 8 0v2.7"/><circle cx="12" cy="15.5" r="1.3"/></svg>
    </div>
    <h1>Your Connection is secure</h1>
    <span class="tag">TLS 1.3 &middot; post-quantum</span>
    <div class="meta">
      <div class="meta-label">Your IP address</div>
      <div class="meta-value" id="ip">&mdash;</div>
    </div>
    <p class="foot">
      Everything after the server hello is encrypted in transit.<br>
      Connection quality and internet trends on
      <a href="https://radar.cloudflare.com/" target="_blank" rel="noopener noreferrer">Cloudflare Radar</a>.
    </p>
  </main>
  <script>
    (async () => {
      const el = document.getElementById("ip");
      for (const url of ["https://api.ipify.org?format=json", "https://api64.ipify.org?format=json"]) {
        try {
          const response = await fetch(url, { cache: "no-store" });
          const data = await response.json();
          if (data && data.ip) { el.textContent = data.ip; return; }
        } catch (error) { /* try the next endpoint */ }
      }
      el.textContent = "unavailable";
    })();
  </script>
</body>
</html>
"##;

/// WHAT: render the decoy configuration for a set of certificates.
///
/// WHY the first block is `default_server`: a TLS ClientHello needs a
/// certificate even when its SNI matches nothing, and the decoy must look
/// like an ordinary site to a scanner. Sorting by domain keeps the file (and
/// therefore reload behavior) stable.
///
/// WHY the curve directive is unconditional: the decoy must always offer
/// the hybrid group. A host whose TLS library is older than OpenSSL 3.5
/// fails `nginx -t` on it, the apply rolls back, and the node reports the
/// failure — there is no classical-only fallback.
pub fn render(cfg: &Config, certs: &[ServerCert]) -> String {
    let certs: Vec<&ServerCert> = {
        let mut sorted: Vec<&ServerCert> = certs.iter().collect();
        sorted.sort_by(|a, b| a.domain.cmp(&b.domain));
        sorted
    };
    let socket = cfg.nginx_socket.display();
    let mut out = String::from(HEADER);
    if !certs.is_empty() {
        // Every assigned name answers plain HTTP with a redirect; the TLS
        // terminator is Xray, so this block never carries a certificate.
        let names: Vec<&str> = certs.iter().map(|cert| cert.domain.as_str()).collect();
        out.push_str(&format!(
            "\nserver {{\n\
             \x20   listen 80 default_server;\n\
             \x20   server_name {names};\n\
             \n\
             \x20   return 301 https://$host$request_uri;\n\
             }}\n",
            names = names.join(" "),
        ));
    }
    for (index, cert) in certs.iter().enumerate() {
        let current = cfg
            .cert_dir
            .join(&cert.path)
            .join("current");
        let default = if index == 0 { " default_server" } else { "" };
        out.push_str(&format!(
            "\nserver {{\n\
             \x20   listen unix:{socket} ssl{default};\n\
             \x20   server_name {domain};\n\
             \n\
             \x20   ssl_certificate     {fullchain};\n\
             \x20   ssl_certificate_key {privkey};\n\
             \x20   ssl_protocols       TLSv1.3;\n\
             \x20   ssl_ecdh_curve      {PQ_CURVES};\n\
             \n\
             \x20   server_tokens off;\n\
             \x20   add_header X-Content-Type-Options nosniff always;\n\
             \x20   add_header X-Frame-Options DENY always;\n\
             \x20   add_header Referrer-Policy no-referrer always;\n\
             \x20   add_header X-Robots-Tag \"noindex, nofollow, noarchive, nosnippet\" always;\n\
             \x20   add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;\n\
             \x20   add_header Content-Security-Policy \"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src https://api.ipify.org https://api64.ipify.org; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\" always;\n\
             \n\
             \x20   root  {root};\n\
             \x20   index index.html;\n\
             \n\
             \x20   location = /robots.txt {{\n\
             \x20       default_type text/plain;\n\
             \x20       add_header X-Robots-Tag \"noindex, nofollow, noarchive, nosnippet\" always;\n\
             \x20       return 200 \"User-agent: *\\nDisallow: /\\n\";\n\
             \x20   }}\n\
             \n\
             \x20   location / {{\n\
             \x20       try_files $uri $uri/ =404;\n\
             \x20   }}\n\
             }}\n",
            domain = cert.domain,
            fullchain = current.join("fullchain.pem").display(),
            privkey = current.join("privkey.pem").display(),
            root = cfg.nginx_root.display(),
        ));
    }
    out
}

/// WHAT: run `nginx -t` and return (ok, bounded output).
pub fn test() -> (bool, String) {
    let result = run_command("nginx", &["-t"], std::time::Duration::from_secs(15));
    let output = if result.output.chars().count() > 500 {
        result.output.chars().take(500).collect()
    } else {
        result.output
    };
    (result.code == 0, output)
}

/// WHAT: write the managed config atomically, returning the previous bytes.
///
/// WHY return the old bytes: a failing `nginx -t` must be able to restore
/// exactly what nginx last accepted, including deleting a file that did not
/// exist before.
pub fn write_config(path: &Path, body: &str) -> Result<Option<Vec<u8>>, String> {
    let previous = fs::read(path).ok();
    atomic_write(path, body.as_bytes(), 0o644)
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    Ok(previous)
}

/// WHAT: put the previous config back (or remove the file if it was new).
pub fn restore_config(path: &Path, previous: Option<&[u8]>) {
    match previous {
        Some(bytes) => {
            let _ = atomic_write(path, bytes, 0o644);
        }
        None => {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cfg() -> Config {
        Config {
            cert_dir: "/etc/lessv/certs".into(),
            nginx_root: "/var/www/lessv-decoy".into(),
            ..Config::default()
        }
    }

    #[test]
    fn renders_one_block_per_certificate() {
        let body = render(
            &sample_cfg(),
            &[
                ServerCert {
                    domain: "b.example.org".to_string(),
                    path: "b.example.org".to_string(),
                },
                ServerCert {
                    domain: "*.example.org".to_string(),
                    path: "wildcard.example.org".to_string(),
                },
            ],
        );
        assert!(body.contains("server_name *.example.org;"));
        assert!(body.contains("server_name b.example.org;"));
        // Wildcard sorts first and is the only default server.
        let wildcard_index = body.find("server_name *.example.org").unwrap();
        let plain_index = body.find("server_name b.example.org").unwrap();
        assert!(wildcard_index < plain_index);
        assert_eq!(body.matches("default_server").count(), 2);
        assert!(body
            .find("listen 80 default_server")
            .unwrap()
            < wildcard_index);
        assert!(body.contains("/etc/lessv/certs/wildcard.example.org/current/fullchain.pem"));
        assert!(body.contains("/etc/lessv/certs/wildcard.example.org/current/privkey.pem"));
        assert!(body.contains("root  /var/www/lessv-decoy;"));
    }

    #[test]
    fn listens_only_on_the_configured_socket_and_tls13() {
        let body = render(&sample_cfg(), &[cert("a.example.org")]);
        assert!(body.contains(
            "listen unix:/dev/shm/lessv-decoy.sock ssl default_server;"
        ));
        assert_eq!(
            body.matches("listen unix:/dev/shm/lessv-decoy.sock ssl")
                .count(),
            1
        );
        assert!(!body.contains("127.0.0.1:8443"));
        assert!(body.contains("ssl_protocols       TLSv1.3;"));
        assert!(body.contains(&format!("ssl_ecdh_curve      {PQ_CURVES};")));
    }

    #[test]
    fn redirects_plain_http_to_every_assigned_name() {
        let body = render(
            &sample_cfg(),
            &[cert("a.example.org"), cert("b.example.org")],
        );
        assert!(body.contains("listen 80 default_server;"));
        assert!(body.contains("server_name a.example.org b.example.org;"));
        assert!(body.contains("return 301 https://$host$request_uri;"));
    }

    #[test]
    fn serves_anti_crawl_headers_and_robots() {
        let body = render(&sample_cfg(), &[cert("a.example.org")]);
        assert!(body.contains("add_header X-Robots-Tag \"noindex, nofollow, noarchive, nosnippet\" always;"));
        assert!(body.contains("add_header X-Content-Type-Options nosniff always;"));
        assert!(body.contains("add_header Referrer-Policy no-referrer always;"));
        assert!(body.contains("location = /robots.txt"));
        assert!(body.contains("default_type text/plain;"));
        assert!(body.contains("server_tokens off;"));
    }

    #[test]
    fn every_block_serves_the_socket() {
        let body = render(
            &sample_cfg(),
            &[cert("a.example.org"), cert("b.example.org")],
        );
        assert_eq!(
            body.matches("listen unix:/dev/shm/lessv-decoy.sock ssl;")
                .count(),
            1
        );
        assert_eq!(body.matches("listen unix:").count(), 2);
    }

    #[test]
    fn empty_manifest_renders_only_the_header() {
        let body = render(&sample_cfg(), &[]);
        assert!(!body.contains("server {"));
        assert!(!body.contains("listen 80"));
        assert!(body.starts_with("# Managed by lessv-node"));
    }

    #[test]
    fn the_decoy_page_is_self_contained_and_marked() {
        assert!(DECOY_PAGE.starts_with("<!doctype html>"));
        assert!(DECOY_PAGE.contains(DECOY_PAGE_MARKER));
        assert!(DECOY_PAGE.contains("Your Connection is secure"));
        assert!(DECOY_PAGE.contains("https://radar.cloudflare.com/"));
        assert!(DECOY_PAGE.contains("api.ipify.org"));
        assert!(!DECOY_PAGE.contains("<link "));
        assert!(!DECOY_PAGE.contains("<script src"));
    }

    fn cert(domain: &str) -> ServerCert {
        ServerCert {
            domain: domain.to_string(),
            path: domain.to_string(),
        }
    }
}
