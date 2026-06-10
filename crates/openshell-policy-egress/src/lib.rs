// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Compile OpenShell effective sandbox policy into external egress artifacts.
//!
//! This crate is a **defense-in-depth backup** when a sandbox is compromised. It does
//! not replace in-sandbox enforcement (Landlock, seccomp, binary-bound proxy, OPA).
//!
//! # OpenShift + standalone NGINX (recommended topology)
//!
//! ```text
//! [sandbox pod] --NetworkPolicy--> only NGINX + DNS + gateway
//!       |
//!       v
//! [NGINX egress] --L7 rules from policy--> upstream APIs
//!       ^
//!       +-- NetworkPolicy on NGINX pod: policy host:port allows
//! ```
//!
//! # Artifacts
//!
//! | Function | Output |
//! |----------|--------|
//! | [`compile_network_policy`] | Per-sandbox Kubernetes `NetworkPolicy` |
//! | [`compile_openshift_egress_firewall`] | OpenShift `EgressFirewall` (FQDN; namespace-scoped) |
//! | [`compile_nginx_network_policy`] | `NetworkPolicy` for NGINX upstream L4 |
//! | [`compile_nginx_conf`] | Standalone `nginx.conf` snippet |
//!
//! # Example
//!
//! ```no_run
//! use openshell_policy::parse_sandbox_policy;
//! use openshell_policy_egress::{
//!     compile_network_policy, compile_nginx_conf, compile_openshift_egress_firewall,
//!     options::{CompileOptions, EgressTopology},
//! };
//!
//! let policy = parse_sandbox_policy(yaml).unwrap();
//! let opts = CompileOptions {
//!     sandbox_id: "my-task".into(),
//!     topology: EgressTopology::ViaNginx,
//!     ..Default::default()
//! };
//! let np = compile_network_policy(&policy, &opts).unwrap();
//! let ef = compile_openshift_egress_firewall(&policy, &opts).unwrap();
//! let ngx = compile_nginx_conf(&policy, &opts).unwrap();
//! ```

mod access;
mod l4;
mod l7;
pub mod options;

pub use l4::{
    collect_l4_destinations, compile_network_policy, compile_nginx_network_policy,
    compile_openshift_egress_firewall, resolve_hosts_from_policy, L4Destination,
};
pub use l7::compile_nginx_conf;
pub use options::{CompileOptions, EgressTopology};

pub type CompileResult<T> = Result<T, CompileError>;

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("invalid compile options: {0}")]
    InvalidOptions(String),
    #[error("no L7 endpoints to compile: {0}")]
    NoL7Endpoints(String),
    #[error("unsupported host pattern for external L7: {0}")]
    UnsupportedHostPattern(String),
}

/// Compile all artifacts from a policy YAML string.
pub fn compile_all_from_yaml(yaml: &str, opts: &CompileOptions) -> CompileResult<CompiledArtifacts> {
    let policy = openshell_policy::parse_sandbox_policy(yaml)
        .map_err(|e| CompileError::InvalidOptions(e.to_string()))?;
    compile_all(&policy, opts)
}

/// Compile all artifacts from a parsed effective policy.
pub fn compile_all(policy: &openshell_core::proto::SandboxPolicy, opts: &CompileOptions) -> CompileResult<CompiledArtifacts> {
    Ok(CompiledArtifacts {
        network_policy: compile_network_policy(policy, opts)?,
        openshift_egress_firewall: compile_openshift_egress_firewall(policy, opts)?,
        nginx_network_policy: compile_nginx_network_policy(policy, opts)?,
        nginx_conf: compile_nginx_conf(policy, opts)?,
    })
}

#[derive(Debug, Clone)]
pub struct CompiledArtifacts {
    pub network_policy: String,
    pub openshift_egress_firewall: String,
    pub nginx_network_policy: String,
    pub nginx_conf: String,
}
