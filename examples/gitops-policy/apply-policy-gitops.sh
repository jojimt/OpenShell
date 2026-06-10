#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Argo CD PostSync entrypoint:
#   1. Compile policy.yaml → NetworkPolicy (DNS resolution via cluster resolver)
#   2. kubectl apply generated manifests (not stored in git)
#   3. openshell policy set --global on the gateway

set -eu

POLICY="${OPENSHELL_POLICY_FILE:-/policy/policy.yaml}"
GATEWAY_CIDR="${GATEWAY_CIDR:?GATEWAY_CIDR is required}"
DNS_CIDR="${DNS_CIDR:?DNS_CIDR is required}"
NAMESPACE="${TARGET_NAMESPACE:-openshell}"
GEN="${GENERATED_DIR:-/tmp/openshell-generated}"
EGRESS_BIN="${OPENSHELL_POLICY_EGRESS_BIN:-/usr/local/bin/openshell-policy-egress}"

mkdir -p "${GEN}"

echo "Generating sandbox NetworkPolicy from ${POLICY}..."
"${EGRESS_BIN}" --policy "${POLICY}" --topology via-nginx --all-sandboxes \
  --namespace "${NAMESPACE}" \
  --gateway-cidr "${GATEWAY_CIDR}" --dns-cidr "${DNS_CIDR}" \
  --auto-resolve-hosts > "${GEN}/networkpolicy-sandboxes.yaml"

echo "Generating NGINX upstream NetworkPolicy..."
"${EGRESS_BIN}" --policy "${POLICY}" --format nginx-network-policy \
  --namespace "${NAMESPACE}" \
  --gateway-cidr "${GATEWAY_CIDR}" --dns-cidr "${DNS_CIDR}" \
  --auto-resolve-hosts > "${GEN}/networkpolicy-nginx.yaml"

echo "Applying NetworkPolicy objects in namespace ${NAMESPACE}..."
kubectl apply -f "${GEN}/networkpolicy-sandboxes.yaml"
kubectl apply -f "${GEN}/networkpolicy-nginx.yaml"

echo "Syncing global policy to OpenShell gateway..."
exec /usr/local/bin/sync-global-policy.sh
