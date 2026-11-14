//! Traffic statistics: absolute counters plus a boot id.
//!
//! WHY absolute-plus-boot-id: the plane (not the node) accumulates
//! max(0, new - old) deltas, so a retried report can never double-count and a
//! counter reset is explained by a boot-id change. The Xray API reader is a
//! deliberate stub (empty counter map): the transport ships real data the
//! day the plane learns to store it, without a protocol change.

use serde_json::{json, Value};

use crate::state::State;
use crate::util::random_hex;

/// WHAT: mint a fresh Xray boot identifier (32 hex chars).
pub fn new_boot_id() -> String {
    random_hex(16)
}

/// WHAT: build the `/api/node/stats` payload.
pub fn collect(state: &State) -> Value {
    json!({
        "boot_id": state.xray_boot_id,
        "counters": {},
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_shape_is_absolute_with_boot_id() {
        let state = State {
            xray_boot_id: "abc".to_string(),
            ..State::default()
        };
        let payload = collect(&state);
        assert_eq!(payload["boot_id"], json!("abc"));
        assert!(payload["counters"].as_object().unwrap().is_empty());
        assert_eq!(new_boot_id().len(), 32);
    }
}
