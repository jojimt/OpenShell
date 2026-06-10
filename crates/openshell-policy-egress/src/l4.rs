// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! L4 artifacts for OpenShift / Kubernetes.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, ToSocketAddrs};

use openshell_core::driver_utils::{LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID};
use openshell_core::proto::{NetworkEndpoint, SandboxPolicy};

use crate::options::{CompileOptions, EgressTopology};
use crate::CompileResult;

/// A destination extracted from policy for L4 enforcement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct L4Destination {
    pub host: String,
    pub port: u16,
    pub cidrs: Vec<String>,
}

/// Resolve policy endpoint hostnames to CIDRs using the system resolver (cluster DNS in pods).
pub fn resolve_hosts_from_policy(policy: &SandboxPolicy) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();

    for dest in collect_l4_destinations(policy) {
        if dest.host.is_empty() || !dest.cidrs.is_empty() || out.contains_key(&dest.host) {
            continue;
        }
        let port = if dest.port > 0 { dest.port } else { 443 };
        let cidrs = match (dest.host.as_str(), port).to_socket_addrs() {
            Ok(addrs) => addrs
                .map(|addr| ip_to_cidr(addr.ip()))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>(),
            Err(err) => {
                eprintln!("warning: failed to resolve {}: {err}", dest.host);
                continue;
            }
        };
        if !cidrs.is_empty() {
            out.insert(dest.host.clone(), cidrs);
        }
    }

    out
}

fn ip_to_cidr(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}/32"),
        IpAddr::V6(v6) => format!("{v6}/128"),
    }
}

/// Collect unique L4 destinations from effective sandbox policy.
pub fn collect_l4_destinations(policy: &SandboxPolicy) -> Vec<L4Destination> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();

    for rule in policy.network_policies.values() {
        for endpoint in &rule.endpoints {
            for port in endpoint_ports(endpoint) {
                let host = endpoint.host.trim().to_lowercase();
                if host.is_empty() && endpoint.allowed_ips.is_empty() {
                    continue;
                }
                let key = (host.clone(), port);
                if !seen.insert(key) {
                    continue;
                }
                out.push(L4Destination {
                    host,
                    port,
                    cidrs: endpoint.allowed_ips.clone(),
                });
            }
        }
    }

    out
}

fn endpoint_ports(endpoint: &NetworkEndpoint) -> Vec<u16> {
    if !endpoint.ports.is_empty() {
        return endpoint
            .ports
            .iter()
            .map(|p| u16::try_from(*p).unwrap_or(443))
            .collect();
    }
    if endpoint.port > 0 {
        return vec![u16::try_from(endpoint.port).unwrap_or(443)];
    }
    Vec::new()
}

/// Standard Kubernetes `NetworkPolicy` (supported on OpenShift OVN-Kubernetes).
///
/// - [`EgressTopology::ViaNginx`]: sandbox pods may reach only NGINX, DNS, and the gateway.
/// - [`EgressTopology::Direct`]: sandbox pods may reach resolved policy CIDRs plus DNS/gateway.
pub fn compile_network_policy(policy: &SandboxPolicy, opts: &CompileOptions) -> CompileResult<String> {
    opts.validate()?;
    let revision = opts.policy_revision.unwrap_or(0);
    let name = format!(
        "openshell-egress-{}",
        sanitize_k8s_name(&opts.sandbox_id)
    );

    let mut egress_blocks = Vec::new();

    match opts.topology {
        EgressTopology::ViaNginx => {
            egress_blocks.push(format!(
                r#"    - to:
        - podSelector:
            matchLabels:
              {nginx_label_key}: {nginx_label_value}
      ports:
        - protocol: TCP
          port: {nginx_port}"#,
                nginx_label_key = opts.nginx_pod_label_key,
                nginx_label_value = opts.nginx_pod_label_value,
                nginx_port = opts.nginx_listen_port,
            ));
        }
        EgressTopology::Direct => {
            for dest in collect_l4_destinations(policy) {
                for cidr in resolved_cidrs_for_destination(&dest, opts) {
                    egress_blocks.push(format!(
                        r#"    - to:
        - ipBlock:
            cidr: {cidr}
      ports:
        - protocol: TCP
          port: {port}"#,
                        cidr = yaml_quote(&cidr),
                        port = dest.port,
                    ));
                }
            }
        }
    }

    for block in baseline_egress_blocks(opts) {
        egress_blocks.push(block);
    }

    let pod_selector = if opts.all_sandboxes {
        format!(
            r#"    matchLabels:
      {managed_by_key}: {managed_by_value}"#,
            managed_by_key = LABEL_MANAGED_BY,
            managed_by_value = LABEL_MANAGED_BY_VALUE,
        )
    } else {
        format!(
            r#"    matchLabels:
      {managed_by_key}: {managed_by_value}
      {sandbox_id_key}: {sandbox_id}"#,
            managed_by_key = LABEL_MANAGED_BY,
            managed_by_value = LABEL_MANAGED_BY_VALUE,
            sandbox_id_key = LABEL_SANDBOX_ID,
            sandbox_id = yaml_quote(&opts.sandbox_id),
        )
    };

    let yaml = format!(
        r#"# Generated by openshell-policy-egress — backup enforcement only.
# OpenShell revision: {revision}
# Topology: {topology:?}
# Hostnames in policy (resolve for Direct ipBlock mode): {hostnames}
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {name}
  namespace: {namespace}
  labels:
    app.kubernetes.io/part-of: openshell
    openshell.ai/component: egress-backup
    openshell.ai/policy-revision: "{revision}"
spec:
  podSelector:
{pod_selector}
  policyTypes:
    - Egress
  egress:
{egress}
"#,
        revision = revision,
        topology = opts.topology,
        hostnames = hostnames_summary(policy),
        name = name,
        namespace = yaml_quote(&opts.namespace),
        pod_selector = pod_selector,
        egress = egress_blocks.join("\n"),
    );

    Ok(yaml)
}

/// OpenShift OVN [`EgressFirewall`](https://docs.openshift.com/container-platform/latest/networking/ovn_kubernetes_network_provider/configuring-egress-firewall.html)
/// for FQDN-based L4 allows at the namespace level.
///
/// Evaluated in order; place specific Allows before the final Deny.
pub fn compile_openshift_egress_firewall(
    policy: &SandboxPolicy,
    opts: &CompileOptions,
) -> CompileResult<String> {
    opts.validate()?;
    let revision = opts.policy_revision.unwrap_or(0);
    let mut rules = Vec::new();

    if matches!(opts.topology, EgressTopology::ViaNginx) {
        rules.push(format!(
            r#"  - type: Allow
    to:
      dnsName: {dns}"#,
            dns = yaml_quote(&opts.nginx_dns_name),
        ));
    } else {
        for dest in collect_l4_destinations(policy) {
            append_destination_rule(&dest, &mut rules);
        }
    }

    if let Some(gateway_host) = opts.gateway_host.as_deref()
        && is_openshift_egress_dns_name(gateway_host)
    {
        rules.push(format!(
            r#"  - type: Allow
    to:
      dnsName: {host}"#,
            host = yaml_quote(gateway_host),
        ));
    }

    for cidr in &opts.dns_cidrs {
        rules.push(format!(
            r#"  - type: Allow
    to:
      cidrSelector: {cidr}"#,
            cidr = yaml_quote(cidr),
        ));
    }

    for cidr in &opts.gateway_cidrs {
        rules.push(format!(
            r#"  - type: Allow
    to:
      cidrSelector: {cidr}"#,
            cidr = yaml_quote(cidr),
        ));
    }

    rules.push(
        r#"  - type: Deny
    to:
      cidrSelector: 0.0.0.0/0"#
            .to_string(),
    );

    Ok(format!(
        r#"# Generated by openshell-policy-egress — OpenShift EgressFirewall (namespace-scoped).
# Apply once per sandbox namespace or merge rules carefully (one EgressFirewall per namespace).
# OpenShell revision: {revision}
apiVersion: k8s.ovn.org/v1
kind: EgressFirewall
metadata:
  name: openshell-egress-{sandbox}
  namespace: {namespace}
  labels:
    app.kubernetes.io/part-of: openshell
    openshell.ai/component: egress-backup
    openshell.ai/policy-revision: "{revision}"
spec:
  egress:
{rules}
"#,
        revision = revision,
        sandbox = sanitize_k8s_name(&opts.sandbox_id),
        namespace = yaml_quote(&opts.namespace),
        rules = rules.join("\n"),
    ))
}

fn append_destination_rule(dest: &L4Destination, rules: &mut Vec<String>) {
    if dest.host.is_empty() {
        for cidr in &dest.cidrs {
            rules.push(format!(
                r#"  - type: Allow
    to:
      cidrSelector: {cidr}"#,
                cidr = yaml_quote(cidr),
            ));
        }
        return;
    }
    if is_openshift_egress_dns_name(&dest.host) {
        rules.push(format!(
            r#"  - type: Allow
    to:
      dnsName: {host}"#,
            host = yaml_quote(&dest.host),
        ));
    }
}

/// L4 allows for the standalone NGINX egress deployment (upstream destinations).
pub fn compile_nginx_network_policy(
    policy: &SandboxPolicy,
    opts: &CompileOptions,
) -> CompileResult<String> {
    opts.validate()?;
    let revision = opts.policy_revision.unwrap_or(0);
    let mut egress_blocks = Vec::new();

    for dest in collect_l4_destinations(policy) {
        for cidr in resolved_cidrs_for_destination(&dest, opts) {
            egress_blocks.push(format!(
                r#"    - to:
        - ipBlock:
            cidr: {cidr}
      ports:
        - protocol: TCP
          port: {port}"#,
                cidr = yaml_quote(&cidr),
                port = dest.port,
            ));
        }
    }

    for block in baseline_egress_blocks(opts) {
        egress_blocks.push(block);
    }

    Ok(format!(
        r#"# Generated by openshell-policy-egress — NGINX egress deployment L4 backup.
# OpenShell revision: {revision}
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: openshell-egress-nginx-upstream
  namespace: {namespace}
  labels:
    app.kubernetes.io/part-of: openshell
    openshell.ai/component: egress-nginx
    openshell.ai/policy-revision: "{revision}"
spec:
  podSelector:
    matchLabels:
      {nginx_label_key}: {nginx_label_value}
  policyTypes:
    - Egress
  egress:
{egress}
"#,
        revision = revision,
        namespace = yaml_quote(&opts.namespace),
        nginx_label_key = opts.nginx_pod_label_key,
        nginx_label_value = opts.nginx_pod_label_value,
        egress = egress_blocks.join("\n"),
    ))
}

fn baseline_egress_blocks(opts: &CompileOptions) -> Vec<String> {
    let mut blocks = Vec::new();

    for cidr in &opts.dns_cidrs {
        blocks.push(format!(
            r#"    - to:
        - ipBlock:
            cidr: {cidr}
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53"#,
            cidr = yaml_quote(cidr),
        ));
    }

    if let Some(port) = opts.gateway_port {
        for cidr in &opts.gateway_cidrs {
            blocks.push(format!(
                r#"    - to:
        - ipBlock:
            cidr: {cidr}
      ports:
        - protocol: TCP
          port: {port}"#,
                cidr = yaml_quote(cidr),
                port = port,
            ));
        }
    }

    blocks
}

fn resolved_cidrs_for_destination(dest: &L4Destination, opts: &CompileOptions) -> Vec<String> {
    if !dest.cidrs.is_empty() {
        return dest.cidrs.clone();
    }
    if dest.host.is_empty() {
        return Vec::new();
    }
    opts.resolved_hosts
        .get(&dest.host)
        .cloned()
        .unwrap_or_default()
}

fn hostnames_summary(policy: &SandboxPolicy) -> String {
    let hosts: BTreeSet<_> = collect_l4_destinations(policy)
        .into_iter()
        .map(|d| d.host)
        .filter(|h| !h.is_empty())
        .collect();
    if hosts.is_empty() {
        "(none)".to_string()
    } else {
        hosts.into_iter().collect::<Vec<_>>().join(", ")
    }
}

/// OpenShift EgressFirewall `dnsName` must be a DNS name without wildcards.
fn is_openshift_egress_dns_name(host: &str) -> bool {
    !host.is_empty()
        && !host.contains('*')
        && !host.chars().all(|c| c.is_ascii_digit() || c == '.')
        && host.contains('.')
}

fn sanitize_k8s_name(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    let mut out = String::with_capacity(lower.len());
    for ch in lower.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    out.trim_matches('-').chars().take(63).collect()
}

fn yaml_quote(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule, SandboxPolicy};
    use crate::options::{CompileOptions, EgressTopology};

    fn github_policy() -> SandboxPolicy {
        let mut policy = SandboxPolicy {
            version: 1,
            ..Default::default()
        };
        policy.network_policies.insert(
            "github_api".to_string(),
            NetworkPolicyRule {
                name: "github-api-readonly".to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: "api.github.com".to_string(),
                    port: 443,
                    protocol: "rest".to_string(),
                    access: "read-only".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        policy
    }

    #[test]
    fn network_policy_via_nginx_includes_nginx_dns_and_gateway() {
        let opts = CompileOptions {
            namespace: "openshell".to_string(),
            sandbox_id: "sandbox-abc".to_string(),
            topology: EgressTopology::ViaNginx,
            nginx_dns_name: "openshell-egress-nginx.openshell.svc.cluster.local".to_string(),
            gateway_cidrs: vec!["10.0.0.10/32".to_string()],
            gateway_port: Some(8080),
            dns_cidrs: vec!["10.0.0.10/32".to_string()],
            ..Default::default()
        };
        let yaml = compile_network_policy(&github_policy(), &opts).unwrap();
        assert!(yaml.contains("kind: NetworkPolicy"));
        assert!(yaml.contains("openshell.ai/sandbox-id"));
        assert!(yaml.contains("port: 8443"));
        assert!(yaml.contains("port: 8080"));
    }

    #[test]
    fn egress_firewall_emits_dns_allow() {
        let opts = CompileOptions {
            namespace: "openshell".to_string(),
            sandbox_id: "sandbox-abc".to_string(),
            topology: EgressTopology::Direct,
            gateway_host: Some("openshell.openshell.svc.cluster.local".to_string()),
            dns_cidrs: vec!["10.0.0.10/32".to_string()],
            ..Default::default()
        };
        let yaml = compile_openshift_egress_firewall(&github_policy(), &opts).unwrap();
        assert!(yaml.contains("kind: EgressFirewall"));
        assert!(yaml.contains("dnsName: api.github.com"));
        assert!(yaml.contains("cidrSelector: 0.0.0.0/0"));
    }
}
