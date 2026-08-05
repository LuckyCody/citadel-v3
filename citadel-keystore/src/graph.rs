// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//! Key hierarchy graph — build and render the Root→Domain→KEK→DEK tree.

use crate::types::{KeyId, KeyMetadata, KeyState};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// KeyGraph
// ---------------------------------------------------------------------------

/// A node in the key hierarchy graph.
#[derive(Debug, Clone)]
pub struct GraphNode {
    pub id: KeyId,
    pub name: String,
    pub key_type: String,
    pub state: KeyState,
    pub current_version: u32,
    pub version_count: usize,
    pub wrapping_summary: String,
    pub children: Vec<GraphNode>,
}

/// The full key hierarchy as a forest (multiple roots possible).
#[derive(Debug, Clone)]
pub struct KeyGraph {
    /// Top-level nodes (keys with no parent, or whose parent is not in the set).
    pub roots: Vec<GraphNode>,
    /// Total number of keys in the graph.
    pub total_keys: usize,
}

impl KeyGraph {
    /// Build from a flat list of `KeyMetadata`.
    pub fn build(keys: &[KeyMetadata]) -> Self {
        let total_keys = keys.len();
        let by_id: HashMap<&str, &KeyMetadata> = keys.iter().map(|k| (k.id.as_str(), k)).collect();

        // Determine which keys are children of known parents.
        let _child_ids: std::collections::HashSet<&str> = keys
            .iter()
            .filter_map(|k| k.parent_id.as_ref().map(|pid| pid.as_str()))
            .filter(|pid| by_id.contains_key(pid))
            .collect();

        // Build roots: keys whose parent is not in the set.
        let root_keys: Vec<&KeyMetadata> = keys
            .iter()
            .filter(|k| {
                k.parent_id
                    .as_ref()
                    .map(|pid| !by_id.contains_key(pid.as_str()))
                    .unwrap_or(true)
            })
            .collect();

        let roots: Vec<GraphNode> = root_keys
            .iter()
            .map(|k| build_node(k, &by_id, &mut std::collections::HashSet::new()))
            .collect();

        KeyGraph { roots, total_keys }
    }

    /// Render the tree as an ASCII string.
    ///
    /// Example output:
    /// ```text
    /// Root/default-root v1 [ACTIVE] — external-master-key
    /// └── DomainKek/production v1 [ACTIVE] — external-master-key
    ///     └── Kek/prod-kek-01 v2 [ACTIVE] — key:prod-dom@v1(X25519+ML-KEM...)
    ///         ├── Dek/prod-dek-01 v4 [ACTIVE] — key:prod-kek@v2(...)
    ///         └── Dek/prod-dek-02 v1 [ACTIVE] — key:prod-kek@v2(...)
    /// ```
    pub fn render(&self) -> String {
        let mut out = String::new();
        for (i, root) in self.roots.iter().enumerate() {
            let is_last = i == self.roots.len() - 1;
            render_node(root, "", is_last, &mut out);
        }
        if self.roots.is_empty() {
            out.push_str("(no keys)\n");
        }
        out
    }

    /// Summary line.
    pub fn summary(&self) -> String {
        let root_count = self.roots.len();
        format!("{} total keys, {} root(s)", self.total_keys, root_count)
    }
}

// ---------------------------------------------------------------------------
// Internal builders
// ---------------------------------------------------------------------------

fn build_node<'a>(
    meta: &'a KeyMetadata,
    by_id: &HashMap<&'a str, &'a KeyMetadata>,
    seen: &mut std::collections::HashSet<&'a str>,
) -> GraphNode {
    // Guard against cycles in the parent_id graph.
    if !seen.insert(meta.id.as_str()) {
        return GraphNode {
            id: meta.id.clone(),
            name: format!("{} (CYCLE DETECTED)", meta.name),
            key_type: format!("{}", meta.key_type),
            state: meta.state,
            current_version: meta.current_version,
            version_count: meta.versions.len(),
            wrapping_summary: "CYCLE".into(),
            children: Vec::new(),
        };
    }

    let wrapping_summary = meta
        .current_key_version()
        .map(|kv| kv.effective_wrapping_mode().summary())
        .unwrap_or_else(|| "unknown".into());

    // Find children: keys whose parent_id == this key's id.
    let children: Vec<GraphNode> = by_id
        .values()
        .filter(|k| k.parent_id.as_ref().map(|pid| pid.as_str()) == Some(meta.id.as_str()))
        .map(|k| build_node(k, by_id, seen))
        .collect();

    seen.remove(meta.id.as_str());

    GraphNode {
        id: meta.id.clone(),
        name: meta.name.clone(),
        key_type: format!("{}", meta.key_type),
        state: meta.state,
        current_version: meta.current_version,
        version_count: meta.versions.len(),
        wrapping_summary,
        children,
    }
}

fn render_node(node: &GraphNode, prefix: &str, is_last: bool, out: &mut String) {
    let connector = if is_last { "└── " } else { "├── " };
    let state_str = match node.state {
        KeyState::Active => "ACTIVE",
        KeyState::Pending => "PENDING",
        KeyState::Rotated => "ROTATED",
        KeyState::Expired => "EXPIRED",
        KeyState::Revoked => "REVOKED",
        KeyState::Suspended => "SUSPENDED",
        KeyState::Destroyed => "DESTROYED",
    };

    // Short key ID (first 8 chars).
    let short_id = {
        let s = node.id.as_str();
        &s[..8.min(s.len())]
    };

    let ver_str = if node.version_count > 1 {
        format!("v{} ({} vers)", node.current_version, node.version_count)
    } else {
        format!("v{}", node.current_version)
    };

    out.push_str(&format!(
        "{}{}{}/{} {} [{}] — {}\n",
        prefix, connector, node.key_type, node.name, ver_str, state_str, node.wrapping_summary
    ));

    let child_prefix = if is_last {
        format!("{}    ", prefix)
    } else {
        format!("{}│   ", prefix)
    };

    // Print the short ID below the main line.
    out.push_str(&format!(
        "{}    id: {}\n",
        if is_last {
            format!("{}    ", prefix)
        } else {
            format!("{}│   ", prefix)
        },
        short_id
    ));

    let n = node.children.len();
    for (i, child) in node.children.iter().enumerate() {
        render_node(child, &child_prefix, i == n - 1, out);
    }
}
