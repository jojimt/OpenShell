#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

ENDPOINT="${OPENSHELL_GATEWAY_ENDPOINT:?OPENSHELL_GATEWAY_ENDPOINT is required}"
NAME="${OPENSHELL_GATEWAY_NAME:-incluster}"
POLICY_FILE="${OPENSHELL_POLICY_FILE:-/policy/policy.yaml}"

MTLS_DIR="/root/.config/openshell/gateways/${NAME}/mtls"
mkdir -p "${MTLS_DIR}"
cp /mtls/ca.crt "${MTLS_DIR}/ca.crt"
cp /mtls/tls.crt "${MTLS_DIR}/tls.crt"
cp /mtls/tls.key "${MTLS_DIR}/tls.key"

openshell gateway remove "${NAME}" 2>/dev/null || true
openshell gateway add "${ENDPOINT}" --name "${NAME}" --local
openshell gateway select "${NAME}"
openshell policy set --global --policy "${POLICY_FILE}" --yes
openshell policy get --global --policy-only
