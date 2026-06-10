// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Expand OpenShell `access` presets into explicit L7 allow rules (mirrors `openshell-policy` merge).

use openshell_core::proto::{L7Allow, L7Rule, NetworkEndpoint};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L7AllowRule {
    pub method: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L7DenyRuleView {
    pub method: String,
    pub path: String,
}

/// Collect L7 allow rules for an endpoint, expanding `access` when `rules` is empty.
pub fn endpoint_l7_allows(endpoint: &NetworkEndpoint) -> Vec<L7AllowRule> {
    if !endpoint.rules.is_empty() {
        return endpoint
            .rules
            .iter()
            .filter_map(|rule| rule.allow.as_ref())
            .map(|allow| L7AllowRule {
                method: allow.method.clone(),
                path: allow.path.clone(),
            })
            .collect();
    }

    if endpoint.access.is_empty() {
        return Vec::new();
    }

    expand_access_preset(&endpoint.protocol, &endpoint.access)
        .into_iter()
        .map(|rule| {
            let allow = rule.allow.expect("expanded preset always has allow");
            L7AllowRule {
                method: allow.method,
                path: allow.path,
            }
        })
        .collect()
}

pub fn endpoint_l7_denies(endpoint: &NetworkEndpoint) -> Vec<L7DenyRuleView> {
    endpoint
        .deny_rules
        .iter()
        .map(|deny| L7DenyRuleView {
            method: deny.method.clone(),
            path: deny.path.clone(),
        })
        .collect()
}

fn expand_access_preset(protocol: &str, access: &str) -> Vec<L7Rule> {
    let methods = match (protocol, access) {
        (_, "full") => vec!["*"],
        ("websocket", "read-only") => vec!["GET"],
        ("websocket", "read-write") => vec!["GET", "WEBSOCKET_TEXT"],
        (_, "read-only") => vec!["GET", "HEAD", "OPTIONS"],
        (_, "read-write") => vec!["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"],
        _ => return Vec::new(),
    };

    methods
        .into_iter()
        .map(|method| L7Rule {
            allow: Some(L7Allow {
                method: method.to_string(),
                path: "**".to_string(),
                command: String::new(),
                query: Default::default(),
                operation_type: String::new(),
                operation_name: String::new(),
                fields: Vec::new(),
            }),
        })
        .collect()
}
