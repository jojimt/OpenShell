#!/usr/bin/env sh
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

ENDPOINT="${OPENSHELL_GATEWAY_ENDPOINT:?OPENSHELL_GATEWAY_ENDPOINT is required}"
NAME="${OPENSHELL_GATEWAY_NAME:-incluster}"
POLICY_FILE="${OPENSHELL_POLICY_FILE:-/policy/policy.yaml}"
OPENSHELL="${OPENSHELL_CLI:-/usr/local/bin/openshell}"

MTLS_DIR="/root/.config/openshell/gateways/${NAME}/mtls"
mkdir -p "${MTLS_DIR}"
cp /mtls/ca.crt "${MTLS_DIR}/ca.crt"
cp /mtls/tls.crt "${MTLS_DIR}/tls.crt"
cp /mtls/tls.key "${MTLS_DIR}/tls.key"

"${OPENSHELL}" gateway remove "${NAME}" 2>/dev/null || true
"${OPENSHELL}" gateway add "${ENDPOINT}" --name "${NAME}" --local
"${OPENSHELL}" gateway select "${NAME}"
"${OPENSHELL}" policy set --global --policy "${POLICY_FILE}" --yes
"${OPENSHELL}" policy get --global -o json
