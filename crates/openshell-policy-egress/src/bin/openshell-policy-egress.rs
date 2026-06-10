// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Emit Kubernetes NetworkPolicy YAML from an OpenShell policy file.
//!
//! ```text
//! openshell-policy-egress --policy policy.yaml --sandbox-id baseline
//! openshell-policy-egress --policy policy.yaml --format openshift-egress-firewall
//! ```

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;

use openshell_policy_egress::{
    compile_network_policy, compile_nginx_network_policy, compile_openshift_egress_firewall,
    options::{CompileOptions, EgressTopology}, resolve_hosts_from_policy,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut policy_path = PathBuf::from("policy.yaml");
    let mut sandbox_id = String::from("baseline");
    let mut namespace = String::from("openshell");
    let mut format = String::from("network-policy");
    let mut topology = EgressTopology::ViaNginx;
    let mut revision: Option<u64> = None;
    let mut gateway_cidr = String::from("10.0.0.0/16");
    let mut dns_cidr = String::from("10.0.0.10/32");
    let mut all_sandboxes = false;
    let mut auto_resolve_hosts = false;
    let mut resolved_hosts: BTreeMap<String, Vec<String>> = BTreeMap::new();

    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--policy" => {
                i += 1;
                policy_path = PathBuf::from(args.get(i).ok_or("missing --policy value")?);
            }
            "--sandbox-id" => {
                i += 1;
                sandbox_id = args.get(i).ok_or("missing --sandbox-id value")?.clone();
            }
            "--namespace" => {
                i += 1;
                namespace = args.get(i).ok_or("missing --namespace value")?.clone();
            }
            "--format" => {
                i += 1;
                format = args.get(i).ok_or("missing --format value")?.clone();
            }
            "--topology" => {
                i += 1;
                topology = match args.get(i).ok_or("missing --topology value")?.as_str() {
                    "direct" => EgressTopology::Direct,
                    "via-nginx" => EgressTopology::ViaNginx,
                    other => return Err(format!("unknown topology: {other}").into()),
                };
            }
            "--revision" => {
                i += 1;
                revision = Some(
                    args.get(i)
                        .ok_or("missing --revision value")?
                        .parse()?,
                );
            }
            "--gateway-cidr" => {
                i += 1;
                gateway_cidr = args.get(i).ok_or("missing --gateway-cidr value")?.clone();
            }
            "--dns-cidr" => {
                i += 1;
                dns_cidr = args.get(i).ok_or("missing --dns-cidr value")?.clone();
            }
            "--all-sandboxes" => {
                all_sandboxes = true;
            }
            "--auto-resolve-hosts" => {
                auto_resolve_hosts = true;
            }
            "--resolve-host" => {
                i += 1;
                let pair = args.get(i).ok_or("missing --resolve-host value")?;
                let (host, cidrs) = pair
                    .split_once('=')
                    .ok_or("expected --resolve-host host=cidr[,cidr]")?;
                let host = host.trim().to_lowercase();
                let cidrs: Vec<String> = cidrs
                    .split(',')
                    .map(str::trim)
                    .filter(|c| !c.is_empty())
                    .map(ToString::to_string)
                    .collect();
                if host.is_empty() || cidrs.is_empty() {
                    return Err("invalid --resolve-host: host and at least one cidr required".into());
                }
                resolved_hosts.insert(host, cidrs);
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
        i += 1;
    }

    let yaml = fs::read_to_string(&policy_path)?;
    let policy = openshell_policy::parse_sandbox_policy(&yaml)?;
    if auto_resolve_hosts {
        for (host, cidrs) in resolve_hosts_from_policy(&policy) {
            resolved_hosts.entry(host).or_insert(cidrs);
        }
    }
    let opts = CompileOptions {
        namespace,
        sandbox_id,
        policy_revision: revision,
        topology,
        gateway_host: Some("openshell.openshell.svc.cluster.local".to_string()),
        gateway_cidrs: vec![gateway_cidr],
        gateway_port: Some(8080),
        dns_cidrs: vec![dns_cidr],
        all_sandboxes,
        resolved_hosts,
        ..Default::default()
    };

    let out = match format.as_str() {
        "network-policy" => compile_network_policy(&policy, &opts)?,
        "nginx-network-policy" => compile_nginx_network_policy(&policy, &opts)?,
        "openshift-egress-firewall" => compile_openshift_egress_firewall(&policy, &opts)?,
        other => return Err(format!("unknown format: {other}").into()),
    };
    print!("{out}");
    Ok(())
}

fn print_help() {
    eprintln!(
        r#"openshell-policy-egress — compile OpenShell policy into external egress manifests

Usage:
  openshell-policy-egress --policy policy.yaml [options]

Options:
  --policy <path>           Policy YAML (default: policy.yaml)
  --sandbox-id <id>         Sandbox id label for per-sandbox NetworkPolicy (default: baseline)
  --namespace <ns>          Target namespace (default: openshell)
  --format <name>           network-policy | nginx-network-policy | openshift-egress-firewall
  --topology <name>         via-nginx | direct (default: via-nginx)
  --revision <n>            Policy revision annotation
  --gateway-cidr <cidr>     Cluster service CIDR for gateway (default: 10.0.0.0/16)
  --dns-cidr <cidr>         DNS resolver CIDR (default: 10.0.0.10/32)
  --all-sandboxes           Match all OpenShell-managed pods (global policy GitOps)
  --auto-resolve-hosts      DNS-resolve policy hostnames (use in-cluster for GitOps Jobs)
  --resolve-host <h=cidr>   Manual hostname CIDR override (repeatable; wins over auto-resolve)
"#
    );
}
