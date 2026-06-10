# openshell-policy-egress

Compile OpenShell **effective sandbox policy** into external egress controls for
OpenShift / Kubernetes:

| Artifact | Purpose |
|----------|---------|
| `NetworkPolicy` (per sandbox) | L4 backup on sandbox pods |
| `EgressFirewall` (OpenShift OVN) | FQDN L4 backup (namespace-scoped) |
| `NetworkPolicy` (NGINX deployment) | L4 backup for upstream connections |
| `nginx.conf` | L7 backup (HTTP method/path) |

**This does not replace OpenShell.** Binary binding, credential rewrite,
`inference.local`, and full GraphQL/WebSocket semantics remain in the sandbox proxy.

## Recommended topology (OpenShift + standalone NGINX)

```text
 sandbox pod
     |  NetworkPolicy: allow → NGINX:8443, gateway, DNS only
     v
 NGINX egress (standalone Deployment + Service)
     |  nginx.conf: L7 allow/deny from policy
     |  NetworkPolicy: allow → api.github.com:443, ...
     v
 external APIs
```

If a compromised process bypasses the in-sandbox proxy but still uses the cluster
network, it must pass through NGINX (L7) or hit a deny (L4).

## Quick start

```rust
use openshell_policy_egress::{
    compile_all_from_yaml,
    options::{CompileOptions, EgressTopology},
};

let yaml = std::fs::read_to_string("policy.yaml")?;
let opts = CompileOptions {
    namespace: "openshell".into(),
    sandbox_id: "happy-otter".into(),
    policy_revision: Some(42),
    topology: EgressTopology::ViaNginx,
    nginx_dns_name: "openshell-egress-nginx.openshell.svc.cluster.local".into(),
    gateway_cidrs: vec!["10.128.0.1/32".into()],
    gateway_port: Some(8080),
    dns_cidrs: vec!["10.128.0.10/32".into()],
    resolved_hosts: [("api.github.com".into(), vec!["140.82.121.3/32".into()])]
        .into_iter()
        .collect(),
    ..Default::default()
};

let out = compile_all_from_yaml(&yaml, &opts)?;
std::fs::write("networkpolicy-sandbox.yaml", out.network_policy)?;
std::fs::write("egressfirewall.yaml", out.openshift_egress_firewall)?;
std::fs::write("networkpolicy-nginx.yaml", out.nginx_network_policy)?;
std::fs::write("nginx.conf", out.nginx_conf)?;
```

Apply on OpenShift:

```bash
oc apply -f networkpolicy-sandbox.yaml
oc apply -f networkpolicy-nginx.yaml
# EgressFirewall: one per namespace — merge carefully if multiple sandboxes share a namespace
oc apply -f egressfirewall.yaml
# Mount nginx.conf in your egress NGINX Deployment
```

## OpenShift notes

- Standard `NetworkPolicy` is supported on OVN-Kubernetes (OpenShift 4 default).
- `EgressFirewall` (`k8s.ovn.org/v1`) supports **exact** `dnsName` entries — no `*.example.com` wildcards.
- OpenShell sandbox pods use labels `openshell.ai/managed-by=openshell` and `openshell.ai/sandbox-id=<id>`.
- Resolve hostnames to IPs for `ipBlock` rules when not using `EgressFirewall` DNS allows.

## Semantic gaps (accepted for backup layer)

| OpenShell | External backup |
|-----------|-----------------|
| Binary allowlists | Not represented |
| `WEBSOCKET_TEXT` rules | Skipped in NGINX v1 |
| `graphql` operation rules | Not compiled in v1 |
| Wildcard hosts | Rejected for NGINX; use exact hosts or EgressFirewall per-host |
| `enforcement: audit` | External layers always enforce (block) |

## Policy source

Compile from the **effective** policy the gateway delivers (including `_provider_*`
network layers when Providers v2 is enabled). Re-run when `policy_revision` changes.
