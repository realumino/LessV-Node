//! Control-plane HTTP client (bearer-v1), one function per node endpoint.
//!
//! WHAT: enroll, heartbeat, config, certs, report, stats.
//! WHY one module: every call must make the same promise — only an explicit,
//! complete 2xx payload may cause a local change; transport errors, non-2xx
//! statuses, empty bodies, and malformed JSON all become one error type the
//! loop treats as "keep serving, back off". The token travels only in the
//! Authorization header and is never logged.

use std::time::Duration;

use serde_json::Value;

use crate::config::Config;
use crate::util::{head, tail};

pub const PROTOCOL_VERSION: u64 = 3;
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const TIMEOUT_SECS: u64 = 10;

#[derive(Debug)]
pub struct HttpError {
    pub message: String,
    pub auth_failed: bool,
    /// WHAT: the plane refused the request on protocol grounds.
    /// WHY its own flag: a protocol refusal names exactly one side as too
    /// old — the plane's detail sentence says which — so the reconcile loop
    /// logs it at ERROR instead of the generic heartbeat failure. Backoff is
    /// deliberately identical: keep serving, retry, let a plane upgrade fix
    /// it in place.
    pub protocol_refused: bool,
}

impl HttpError {
    fn transport(message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            auth_failed: false,
            protocol_refused: false,
        }
    }

    fn with_status(status: u16, message: impl Into<String>) -> Self {
        HttpError {
            message: message.into(),
            auth_failed: status == 401 || status == 403,
            protocol_refused: false,
        }
    }
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for HttpError {}

pub struct NodeClient {
    agent: ureq::Agent,
    base: String,
    node_id: String,
    token: String,
}

impl NodeClient {
    /// WHAT: build the shared agent (10s total timeout, statuses as data).
    ///
    /// WHY statuses as data: 304 and 409 are control flow, not failures; the
    /// client maps them explicitly instead of parsing error strings.
    pub fn new(cfg: &Config) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(TIMEOUT_SECS)))
            .http_status_as_error(false)
            .user_agent(format!("vela-server/{VERSION}"))
            .build();
        NodeClient {
            agent: ureq::Agent::new_with_config(config),
            base: cfg.cp_url.clone(),
            node_id: cfg.node_id.clone(),
            token: cfg.token.clone(),
        }
    }

    fn url(&self, path: &str, query: Option<(&str, &str)>) -> String {
        match query {
            Some((key, value)) => format!("{}{path}?{key}={value}", self.base),
            None => format!("{}{path}", self.base),
        }
    }

    /// WHAT: one JSON round-trip, returning status and the parsed body.
    ///
    /// WHY the 304/empty split lives here: PROTOCOL.md gives 304 "no body"
    /// semantics, and every other non-2xx is an error the loop backs off on.
    fn request(
        &self,
        method: &str,
        path: &str,
        query: Option<(&str, &str)>,
        body: Option<&Value>,
        extra_headers: &[(&str, &str)],
    ) -> Result<(u16, Option<Value>), HttpError> {
        let url = self.url(path, query);
        let payload = body
            .map(|value| serde_json::to_vec(value).unwrap_or_default())
            .unwrap_or_default();
        let headers: Vec<(&str, String)> = std::iter::once(("Authorization", format!("Bearer {}", self.token)))
            .chain(std::iter::once(("X-Vela-Server", self.node_id.clone())))
            .chain(std::iter::once(("Accept", "application/json".to_string())))
            .chain(std::iter::once((
                "Content-Type",
                "application/json".to_string(),
            )))
            .chain(extra_headers.iter().map(|(name, value)| (*name, (*value).to_string())))
            .collect();
        let response = match method {
            "GET" => {
                let mut builder = self.agent.get(&url);
                for (name, value) in &headers {
                    builder = builder.header(*name, value);
                }
                builder.call()
            }
            "POST" => {
                let mut builder = self.agent.post(&url);
                for (name, value) in &headers {
                    builder = builder.header(*name, value);
                }
                builder.send(payload.as_slice())
            }
            other => return Err(HttpError::transport(format!("unsupported method {other}"))),
        }
        .map_err(|error| {
            HttpError::transport(format!("{method} {path} failed: {error}"))
        })?;
        let status = response.status().as_u16();
        let raw = response
            .into_body()
            .read_to_vec()
            .map_err(|error| HttpError::transport(format!("{path}: body read failed: {error}")))?;
        decode(path, status, &raw)
    }
}

/// WHAT: the `detail` string of a plane error envelope, when it is one.
fn detail_text(raw: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(raw).ok()?;
    match value.get("detail")? {
        Value::String(text) => Some(text.clone()),
        _ => None,
    }
}

/// WHAT: map one response to (status, payload) or an HttpError.
///
/// WHY a free function: the response rules are the whole contract and are
/// unit-tested without a socket. A non-2xx carries the response text (which
/// the plane fills with its `detail` envelope) truncated to 500 chars.
fn decode(path: &str, status: u16, raw: &[u8]) -> Result<(u16, Option<Value>), HttpError> {
    if status == 304 {
        return Ok((304, None));
    }
    if !(200..300).contains(&status) {
        let detail = head(&String::from_utf8_lossy(raw), 500);
        let mut error = HttpError::with_status(
            status,
            format!("HTTP {status} {path} {detail}"),
        );
        // WHY 400 + a detail that names a protocol: both protocol refusals
        // the plane sends — the generic below-window shape (`unsupported
        // protocol N`) and the named mismatch above it — are 400s whose
        // detail contains the word. One flag covers both sides of the
        // window, and the loop turns it into the ERROR log line.
        if status == 400 && detail_text(raw).is_some_and(|text| text.contains("protocol")) {
            error.protocol_refused = true;
        }
        return Err(error);
    }
    if raw.is_empty() {
        return Err(HttpError::transport(format!("empty response from {path}")));
    }
    let value: Value = serde_json::from_slice(raw).map_err(|error| {
        HttpError::with_status(
            status,
            format!("malformed JSON from {path}: {error}"),
        )
    })?;
    Ok((status, Some(value)))
}

fn require_object<'a>(
    value: &'a Option<Value>,
    path: &str,
) -> Result<&'a serde_json::Map<String, Value>, HttpError> {
    match value {
        Some(Value::Object(map)) => Ok(map),
        _ => Err(HttpError::transport(format!(
            "malformed response from {path}"
        ))),
    }
}

fn require_field<'a>(
    map: &'a serde_json::Map<String, Value>,
    field: &str,
    path: &str,
) -> Result<&'a Value, HttpError> {
    map.get(field)
        .ok_or_else(|| HttpError::transport(format!("response from {path} missing {field:?}")))
}

impl NodeClient {
    /// WHAT: first contact; idempotent by contract.
    pub fn enroll(&self, info: &Value) -> Result<Value, HttpError> {
        let mut body = info.clone();
        if let Value::Object(map) = &mut body {
            map.insert("protocol".to_string(), Value::from(PROTOCOL_VERSION));
        }
        let (_, payload) = self.request("POST", "/api/node/enroll", None, Some(&body), &[])?;
        require_object(&payload, "/api/node/enroll")?;
        Ok(payload.unwrap_or(Value::Null))
    }

    /// WHAT: the 30s poll — desired hash, any actions, and the plane's own
    /// protocol when the plane names one.
    pub fn heartbeat(&self, heartbeat: &Value) -> Result<HeartbeatReply, HttpError> {
        let mut body = heartbeat.clone();
        if let Value::Object(map) = &mut body {
            map.insert("protocol".to_string(), Value::from(PROTOCOL_VERSION));
        }
        let (_, payload) = self.request("POST", "/api/node/heartbeat", None, Some(&body), &[])?;
        parse_heartbeat(require_object(&payload, "/api/node/heartbeat")?)
    }

    /// WHAT: the exact config bytes for one hash; None means 304.
    pub fn fetch_config(&self, hash: &str) -> Result<Option<Value>, HttpError> {
        let (status, payload) =
            self.request("GET", "/api/node/config", Some(("hash", hash)), None, &[])?;
        if status == 304 {
            return Ok(None);
        }
        let map = require_object(&payload, "/api/node/config")?;
        if let Some(returned) = map.get("hash").and_then(Value::as_str) {
            if returned != hash {
                return Err(HttpError::transport(format!(
                    "config hash mismatch: asked {hash}, got {returned}"
                )));
            }
        }
        let config = map
            .get("config")
            .cloned()
            .ok_or_else(|| HttpError::transport("config response missing config"))?;
        Ok(Some(config))
    }

    /// WHAT: the certificate manifest; None means 304.
    pub fn fetch_certs(&self, etag: Option<&str>) -> Result<Option<Value>, HttpError> {
        let extra: Vec<(&str, &str)> = match etag {
            Some(value) => vec![("If-None-Match", value)],
            None => Vec::new(),
        };
        let (status, payload) = self.request("GET", "/api/node/certs", None, None, &extra)?;
        if status == 304 {
            return Ok(None);
        }
        Ok(payload)
    }

    /// WHAT: record one apply attempt (never retried by this call).
    pub fn report(&self, report: &Value) -> Result<(), HttpError> {
        let mut body = report.clone();
        if let Value::Object(map) = &mut body {
            map.insert("protocol".to_string(), Value::from(PROTOCOL_VERSION));
        }
        self.request("POST", "/api/node/report", None, Some(&body), &[])?;
        Ok(())
    }

    /// WHAT: report the outcome of one maintenance action (never retried).
    pub fn action_report(&self, report: &Value) -> Result<(), HttpError> {
        let mut body = report.clone();
        if let Value::Object(map) = &mut body {
            map.insert("protocol".to_string(), Value::from(PROTOCOL_VERSION));
        }
        self.request("POST", "/api/node/action", None, Some(&body), &[])?;
        Ok(())
    }

    /// WHAT: send absolute counters with a boot id.
    pub fn stats(&self, stats: &Value) -> Result<(), HttpError> {
        let mut body = stats.clone();
        if let Value::Object(map) = &mut body {
            map.insert("protocol".to_string(), Value::from(PROTOCOL_VERSION));
        }
        self.request("POST", "/api/node/stats", None, Some(&body), &[])?;
        Ok(())
    }
}

/// WHAT: one parsed heartbeat reply.
#[derive(Debug, Clone, PartialEq)]
pub struct HeartbeatReply {
    pub desired_hash: Option<String>,
    pub actions: Vec<Action>,
    /// WHAT: the protocol the plane says it speaks, when it says one.
    /// WHY optional: the plane names it in every response since the skew
    /// work; an older plane sends none, and a missing diagnostic must never
    /// fail a heartbeat.
    pub plane_protocol: Option<u64>,
}

/// WHAT: parse one heartbeat reply; unknown fields are ignored.
///
/// WHY a free function: tolerant reading of the reply is a contract
/// property — the plane may add fields in any release — and a pure function
/// pins it without a socket.
pub fn parse_heartbeat(map: &serde_json::Map<String, Value>) -> Result<HeartbeatReply, HttpError> {
    let desired = require_field(map, "desired_hash", "/api/node/heartbeat")?;
    let desired = match desired {
        Value::Null => None,
        Value::String(text) => Some(text.clone()),
        _ => {
            return Err(HttpError::transport(
                "heartbeat desired_hash must be a string or null",
            ))
        }
    };
    let actions = parse_actions(require_field(map, "actions", "/api/node/heartbeat")?)?;
    let plane_protocol = match map.get("protocol") {
        Some(Value::Number(number)) => number.as_u64(),
        _ => None,
    };
    Ok(HeartbeatReply {
        desired_hash: desired,
        actions,
        plane_protocol,
    })
}

/// WHAT: one maintenance command the plane puts on a heartbeat.
///
/// WHY an enum: each variant carries exactly the data its executor needs,
/// and an unknown action is data (logged and ignored) rather than a parse
/// failure that would stop the whole heartbeat.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    RestartXray,
    UpdateGeodata,
    Unknown(String),
}

/// WHAT: parse the heartbeat's `actions` array.
///
/// WHY bare strings are still accepted: protocol 2 phrased actions as
/// strings, and a node that survives a plane rollback costs three lines.
pub fn parse_actions(value: &Value) -> Result<Vec<Action>, HttpError> {
    let items = value
        .as_array()
        .ok_or_else(|| HttpError::transport("heartbeat actions must be a list"))?;
    let mut actions = Vec::new();
    for item in items {
        let named = match item {
            Value::String(name) => Some(name.as_str()),
            Value::Object(map) => {
                let name = map.get("action").and_then(Value::as_str).unwrap_or("");
                Some(name)
            }
            _ => None,
        };
        let Some(name) = named else {
            return Err(HttpError::transport(
                "heartbeat actions must be strings or objects",
            ));
        };
        // WHY update_xray is not a variant any more: Xray ships inside this
        // image, so a binary update is an image update. The plane stopped
        // requesting it; a plane that still does gets the unknown-action path
        // below and the node keeps converging everything else.
        actions.push(match name {
            "restart_xray" => Action::RestartXray,
            "update_geodata" => Action::UpdateGeodata,
            other => Action::Unknown(other.to_string()),
        });
    }
    Ok(actions)
}

/// WHAT: truncate an error string to the 500-char protocol bound.
pub fn bound_error(text: &str) -> String {
    tail(text, 500)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_status_rules() {
        assert_eq!(decode("/x", 304, b"").unwrap().0, 304);
        assert!(decode("/x", 200, b"").unwrap_err().message.contains("empty"));
        let err = decode("/x", 409, br#"{"detail":{"message":"moved"}}"#).unwrap_err();
        assert!(err.message.contains("moved"));
        assert!(!err.auth_failed);
        let err = decode("/x", 401, b"").unwrap_err();
        assert!(err.auth_failed);
        let err = decode("/x", 200, b"not json").unwrap_err();
        assert!(err.message.contains("malformed JSON"));
    }

    #[test]
    fn heartbeat_reply_tolerates_unknown_fields() {
        // WHY: the plane may add fields in any release (it already names its
        // protocol in every response); refusing a poll over an unknown field
        // would make the node the brittle side of the skew.
        let map = serde_json::json!({
            "desired_hash": "abc",
            "actions": [],
            "protocol": 3,
            "some_future_field": {"nested": true},
        });
        let reply = parse_heartbeat(map.as_object().unwrap()).unwrap();
        assert_eq!(reply.desired_hash.as_deref(), Some("abc"));
        assert!(reply.actions.is_empty());
        assert_eq!(reply.plane_protocol, Some(3));

        let old_plane = serde_json::json!({ "desired_hash": null, "actions": [] });
        let reply = parse_heartbeat(old_plane.as_object().unwrap()).unwrap();
        assert_eq!(reply.desired_hash, None);
        assert_eq!(reply.plane_protocol, None);
    }

    #[test]
    fn classifies_a_protocol_refusal() {
        // WHY a str and not a byte literal: byte literals are ASCII-only,
        // and the plane's sentence carries an em-dash.
        let refusal_body = r#"{"detail":"plane speaks protocol 3; node speaks protocol 4 — upgrade the plane first"}"#;
        let refusal = decode("/api/node/heartbeat", 400, refusal_body.as_bytes()).unwrap_err();
        assert!(refusal.protocol_refused);
        assert!(!refusal.auth_failed);
        assert!(refusal.message.contains("upgrade the plane first"));

        let below_window = decode(
            "/api/node/heartbeat",
            400,
            br#"{"detail":"unsupported protocol 2"}"#,
        )
        .unwrap_err();
        assert!(below_window.protocol_refused);

        let other = decode("/x", 400, br#"{"detail":"node not found"}"#).unwrap_err();
        assert!(!other.protocol_refused);
        assert!(!other.auth_failed);

        let non_json_detail = decode("/x", 400, br#"{"detail":[{"msg":"bad"}]}"#).unwrap_err();
        assert!(!non_json_detail.protocol_refused);

        let auth = decode("/x", 401, b"").unwrap_err();
        assert!(auth.auth_failed);
        assert!(!auth.protocol_refused);
    }

    #[test]
    fn parses_action_objects_and_legacy_strings() {
        let actions = parse_actions(&serde_json::json!([
            {"action": "update_geodata"},
            {"action": "restart_xray"},
            "restart_xray",
            {"action": "something_new"},
            {"action": "update_xray", "version": "v26.11.9"}
        ]))
        .unwrap();
        assert_eq!(
            actions,
            vec![
                Action::UpdateGeodata,
                Action::RestartXray,
                Action::RestartXray,
                Action::Unknown("something_new".to_string()),
                Action::Unknown("update_xray".to_string()),
            ]
        );
        assert!(parse_actions(&serde_json::json!({})).is_err());
        assert!(parse_actions(&serde_json::json!([42])).is_err());
    }

    #[test]
    fn error_text_is_bounded() {
        let long = "x".repeat(2000);
        assert_eq!(bound_error(&long).chars().count(), 500);
    }
}
