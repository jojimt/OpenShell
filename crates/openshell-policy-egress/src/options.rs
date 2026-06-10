// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::{CompileError, CompileResult};

/// How sandbox pods reach external networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressTopology {
    /// Sandbox pods may connect only to the NGINX egress gateway, DNS, and OpenShell gateway.
    /// Recommended with standalone NGINX L7 backup.
    ViaNginx,
    /// Sandbox pods may connect directly to resolved policy destinations (coarse L4 backup).
    Direct,
}

/// Inputs that are cluster-specific and cannot be inferred from policy YAML alone.
#[derive(Debug, Clone)]
pub struct CompileOptions {
    pub namespace: String,
    pub sandbox_id: String,
    pub policy_revision: Option<u64>,
    pub topology: EgressTopology,

    /// Cluster DNS resolvers (OpenShift: often the service network CIDR or node DNS).
    pub dns_cidrs: Vec<String>,

    /// OpenShell gateway reachability from sandbox pods.
    pub gateway_host: Option<String>,
    pub gateway_cidrs: Vec<String>,
    pub gateway_port: Option<u16>,

    /// Standalone NGINX egress gateway.
    pub nginx_pod_label_key: String,
    pub nginx_pod_label_value: String,
    pub nginx_listen_port: u16,
    pub nginx_dns_name: String,

    /// Hostname → resolved IPs for standard NetworkPolicy `ipBlock` (Direct / NGINX upstream).
    pub resolved_hosts: BTreeMap<String, Vec<String>>,

    /// When true, sandbox NetworkPolicy matches every OpenShell-managed pod (global policy GitOps).
    pub all_sandboxes: bool,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            namespace: "openshell".to_string(),
            sandbox_id: "sandbox".to_string(),
            policy_revision: None,
            topology: EgressTopology::ViaNginx,
            dns_cidrs: vec!["10.0.0.10/32".to_string()],
            gateway_host: Some("openshell.openshell.svc.cluster.local".to_string()),
            gateway_cidrs: vec!["10.0.0.10/32".to_string()],
            gateway_port: Some(8080),
            nginx_pod_label_key: "app".to_string(),
            nginx_pod_label_value: "openshell-egress-nginx".to_string(),
            nginx_listen_port: 8443,
            nginx_dns_name: "openshell-egress-nginx.openshell.svc.cluster.local".to_string(),
            resolved_hosts: BTreeMap::new(),
            all_sandboxes: false,
        }
    }
}

impl CompileOptions {
    pub fn validate(&self) -> CompileResult<()> {
        if self.namespace.trim().is_empty() {
            return Err(CompileError::InvalidOptions(
                "namespace must not be empty".into(),
            ));
        }
        if self.sandbox_id.trim().is_empty() {
            return Err(CompileError::InvalidOptions(
                "sandbox_id must not be empty".into(),
            ));
        }
        if matches!(self.topology, EgressTopology::ViaNginx)
            && self.nginx_dns_name.trim().is_empty()
        {
            return Err(CompileError::InvalidOptions(
                "nginx_dns_name is required for ViaNginx topology".into(),
            ));
        }
        Ok(())
    }
}
