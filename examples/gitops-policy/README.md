# GitOps policy sync (Argo CD + OpenShell + in-cluster NetworkPolicy)

This example shows how to:

1. Store **only** `policy.yaml` in git
2. Let Argo CD sync a ConfigMap + PostSync Job into the cluster
3. **In the cluster**, compile and apply NetworkPolicy (with live DNS resolution)
4. Apply the same YAML as a **gateway global policy** (OpenShell enforcement)

OpenShell remains authoritative for binary binding and L7 rules inside the sandbox.
NetworkPolicy is a coarse L4 envelope derived from `network_policies` in the same file.

NetworkPolicy manifests are **not** committed to git — they are generated on each Argo CD
sync by the PostSync Job using cluster DNS.

## Repository layout

```text
openshell-policies/                 # your git repo
├── policy.yaml                     # sole source of truth
├── kustomization.yaml              # Argo CD build root (ConfigMap + k8s manifests)
├── k8s/
│   ├── rbac-policy-syncer.yaml     # ServiceAccount + NetworkPolicy apply permissions
│   └── job-sync-global-policy.yaml # Argo CD PostSync hook
├── argocd/
│   └── application.yaml
├── apply-policy-gitops.sh          # in-cluster: generate NP + apply + global policy
├── sync-global-policy.sh           # openshell policy set --global
└── Dockerfile.policy-syncer        # openshell CLI + openshell-policy-egress + kubectl
```

## 1. Write policy.yaml

Use the same schema as `openshell policy set`. For org-wide baseline, include static
sections and `network_policies`:

```yaml
version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /etc, /var/log]
  read_write: [/sandbox, /tmp]
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_policies:
  github_api:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        access: read-only
    binaries:
      - { path: /usr/bin/curl }
```

## 2. Build the policy-syncer image

Build from the **OpenShell repository root** (the image compiles `openshell-policy-egress`
and bundles the `openshell` CLI):

```bash
cd /path/to/OpenShell
docker build -f examples/gitops-policy/Dockerfile.policy-syncer \
  --build-arg OPENSHELL_VERSION=0.0.58 \
  -t ghcr.io/your-org/openshell-policy-syncer:0.0.58 .
docker push ghcr.io/your-org/openshell-policy-syncer:0.0.58
```

Update the image reference in `k8s/job-sync-global-policy.yaml`.

## 3. Configure cluster CIDRs

Edit `k8s/job-sync-global-policy.yaml` env vars to match your cluster:

| Variable | Example (OpenShift) | Purpose |
|----------|---------------------|---------|
| `GATEWAY_CIDR` | `10.128.0.0/14` | Pod/service network reachability to OpenShell gateway |
| `DNS_CIDR` | `10.128.0.10/32` | Cluster DNS resolver |

Hostname → IP resolution for `network_policies` endpoints happens **inside the Job**
via `--auto-resolve-hosts` (uses the pod's `/etc/resolv.conf` / cluster DNS).

## 4. Argo CD Application

Copy `examples/gitops-policy/` into your own git repo. Edit `argocd/application.yaml`
with your repo URL. Set `spec.source.path` to `.` (repo root), **not** `k8s` — Kustomize
cannot reference `../policy.yaml` from inside `k8s/`.

```bash
kubectl apply -f argocd/application.yaml
```

The ConfigMap uses `disableNameSuffixHash: true` so the Job can mount
`openshell-policy` by exact name (Kustomize's default hash suffix breaks PostSync hooks).

Sync order:

1. ConfigMap (`policy.yaml`) + RBAC apply
2. PostSync Job:
   - `openshell-policy-egress --auto-resolve-hosts` → sandbox + NGINX NetworkPolicies
   - `kubectl apply` generated manifests
   - `openshell policy set --global`

Each sync re-resolves hostnames, so CDN IP changes are picked up without editing git.

## 5. What the PostSync Job does

```text
policy.yaml (ConfigMap)
       │
       ▼
openshell-policy-egress --auto-resolve-hosts
       │  (cluster DNS resolves api.github.com → /32 CIDRs)
       ▼
kubectl apply NetworkPolicy
       │
       ▼
openshell policy set --global
```

### In-cluster gateway endpoint

```text
https://openshell.openshell.svc.cluster.local:8080
```

The Job mounts:

- `/policy/policy.yaml` from ConfigMap
- `/mtls/*` from `openshell-client-tls` secret

## 6. Topology (recommended)

```text
[sandbox pod]  --NetworkPolicy-->  [NGINX egress]  --NetworkPolicy-->  [internet]
       |                                    ^
       +-- OpenShell proxy (authoritative)  |
       +-- global policy.yaml (gateway)     +-- L7 in nginx.conf (optional)
```

Sandbox NetworkPolicy restricts compromised pods to NGINX + gateway + DNS only.
NGINX NetworkPolicy allows only destinations declared in `network_policies`.

## 7. Verify

```bash
openshell policy get --global
kubectl -n openshell get networkpolicy
kubectl -n openshell logs job/openshell-sync-global-policy
openshell sandbox create --name test -- claude
```

## OpenShift EgressFirewall (optional)

For FQDN-based L4 without IP resolution, extend `apply-policy-gitops.sh` to also emit
and apply `openshift-egress-firewall` format (requires `k8s.ovn.org` RBAC). Standard
Kubernetes NetworkPolicy cannot match on hostnames.

## Limitations

| OpenShell policy | In-cluster NetworkPolicy |
|------------------|--------------------------|
| Per-binary rules | Not represented |
| L7 method/path   | Not in NetworkPolicy (add NGINX separately) |
| Hot agent proposals | Out of band; git remains source of truth |
| Per-sandbox policy | Global policy applies to **all** sandboxes |
| Dynamic CDN IPs | Re-resolved each sync; not between syncs |

For per-sandbox policies, replace the global Job with a controller that watches sandbox
CRs and runs `openshell policy set <name>` — not covered in this baseline example.
