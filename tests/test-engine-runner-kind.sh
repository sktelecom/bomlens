#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-engine-runner-kind.sh - the engine runner (runner/) on a real cluster.
#
# Creates a kind cluster, pushes the image under test to a local registry so
# it has a digest, and runs bomlens_runner against the cluster through
# kubectl proxy:
#   - a source scan of examples/nodejs: plan, stage 1, stage 2 as Jobs on a
#     shared workspace volume, the result manifest checked, no Job or Pod
#     left, the source tree unchanged;
#   - an image scan of a small public image;
#   - the network labels: a Pod labelled network=none cannot reach the
#     internet under the NetworkPolicy the guide describes, one labelled
#     egress can (so the first check can fail).
#
# Usage: BOMLENS_TEST_IMAGE=<local image tag> tests/test-engine-runner-kind.sh
# Needs docker, kind, kubectl and python3 (3.10+). KEEP_CLUSTER=1 leaves the
# cluster and registry running.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${BOMLENS_TEST_IMAGE:?set BOMLENS_TEST_IMAGE to the image to test}"
CLUSTER="${KIND_CLUSTER:-bomlens-runner}"
REG_NAME="${KIND_REGISTRY:-bomlens-runner-registry}"
REG_PORT="${KIND_REGISTRY_PORT:-5001}"
REG_IMAGE="registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
# kind's default CNI does not enforce NetworkPolicy; Calico does.
CALICO_URL="https://raw.githubusercontent.com/projectcalico/calico/v3.29.3/manifests/calico.yaml"
CALICO_SHA256="9a575859428b822a224dedafc4238555b6b0f910f2abf12983f20f871860914e"
NS=bomlens-scan
PASS=0
FAIL=0

sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; }
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

for tool in docker kind kubectl python3 jq; do
    command -v "$tool" >/dev/null 2>&1 || { echo "[ERROR] $tool is required"; exit 1; }
done

WORK="$(mktemp -d "${KIND_WORK_BASE:-${TMPDIR:-/tmp}}/bomlens-kind.XXXXXX")"
PROXY_PID=""
cleanup() {
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
    if [ -z "${KEEP_CLUSTER:-}" ]; then
        kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
        docker rm -f "$REG_NAME" >/dev/null 2>&1 || true
        # The node wrote these as the scan's users; the host user may not
        # own them all.
        docker run --rm --entrypoint sh -v "$WORK:/w" "$IMAGE" -c 'rm -rf /w/*' >/dev/null 2>&1 || true
        rm -rf "$WORK" 2>/dev/null || true
    else
        echo "Kept: cluster $CLUSTER, registry $REG_NAME, work folder $WORK"
    fi
}
trap cleanup EXIT

WS="$WORK/ws"
mkdir -p "$WS"

echo "== cluster =="
if ! docker inspect "$REG_NAME" >/dev/null 2>&1; then
    docker run -d --restart=no -p "127.0.0.1:${REG_PORT}:5000" --name "$REG_NAME" "$REG_IMAGE" >/dev/null
fi
cat > "$WORK/kind.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = "/etc/containerd/certs.d"
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: $WS
        containerPath: /ws
EOF
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --config "$WORK/kind.yaml"
curl -sSfL -o "$WORK/calico.yaml" "$CALICO_URL"
[ "$(sha < "$WORK/calico.yaml" | cut -d' ' -f1)" = "$CALICO_SHA256" ] || { echo "[ERROR] the Calico manifest checksum differs"; exit 1; }
kubectl apply -f "$WORK/calico.yaml" >/dev/null
kubectl wait --for=condition=Ready nodes --all --timeout=300s >/dev/null
kubectl -n kube-system rollout status daemonset/calico-node --timeout=300s >/dev/null
node="${CLUSTER}-control-plane"
docker exec "$node" mkdir -p "/etc/containerd/certs.d/localhost:${REG_PORT}"
printf '[host."http://%s:5000"]\n' "$REG_NAME" | docker exec -i "$node" cp /dev/stdin "/etc/containerd/certs.d/localhost:${REG_PORT}/hosts.toml"
docker network connect kind "$REG_NAME" 2>/dev/null || true

ref="localhost:${REG_PORT}/bomlens:runner-test"
docker tag "$IMAGE" "$ref"
docker push -q "$ref" >/dev/null
digest="$(docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$ref" | grep "^localhost:${REG_PORT}/bomlens@" | head -1 | cut -d@ -f2)"
[ -n "$digest" ] || { echo "[ERROR] the pushed image has no digest"; exit 1; }
ENGINE="${ref}@${digest}"
echo "engine image: $ENGINE"

kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $NS
  labels:
    pod-security.kubernetes.io/enforce: baseline
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: bomlens-workspace
spec:
  capacity: {storage: 20Gi}
  accessModes: [ReadWriteOnce]
  persistentVolumeReclaimPolicy: Retain
  storageClassName: ""
  hostPath: {path: /ws, type: Directory}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: pvc-workspace
  namespace: $NS
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: ""
  volumeName: bomlens-workspace
  resources: {requests: {storage: 20Gi}}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: bomlens-engine-no-network
  namespace: $NS
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/part-of: bomlens-engine
      bomlens.engine/network: none
  policyTypes: [Ingress, Egress]
  ingress: []
  egress: []
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: bomlens-engine-egress
  namespace: $NS
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/part-of: bomlens-engine
      bomlens.engine/network: egress
  policyTypes: [Ingress, Egress]
  ingress: []
  egress:
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels: {k8s-app: kube-dns}
      ports: [{protocol: UDP, port: 53}, {protocol: TCP, port: 53}]
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16]
EOF
kubectl wait --for=jsonpath='{.status.phase}'=Bound -n "$NS" pvc/pvc-workspace --timeout=60s >/dev/null

kubectl proxy --port=8001 >/dev/null 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 30); do curl -sf http://127.0.0.1:8001/version >/dev/null && break; sleep 1; done

policy() {  # policy <file>
    cat > "$1" <<EOF
{
  "images": {"engine": "$ENGINE"},
  "workspace": {"name": "pvc-workspace", "local_root": "$WS"},
  "uid": $(id -u), "gid": $(id -g),
  "labels": {"example.com/suite": "kind"},
  "stage2_env": {"GENERATE_SECURITY": "false", "ENRICH_EOL": "false"},
  "image_env": {"GENERATE_SECURITY": "false"},
  "kubernetes": {"namespace": "$NS", "poll_interval": 1.0, "request_memory": "256Mi"},
  "limits": {"memory_bytes": 3221225472, "cpus": 2.0}
}
EOF
}
runner() { PYTHONPATH="$ROOT_DIR/runner/src" python3 -m bomlens_runner "$@" --api http://127.0.0.1:8001; }
tree_hash() { (cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 cat | sha | cut -d' ' -f1); }

echo "== source scan =="
mkdir -p "$WS/scan1"
cp -R "$ROOT_DIR/examples/nodejs" "$WS/scan1/src"
before="$(tree_hash "$WS/scan1/src")"
policy "$WORK/policy.json"
set +e
runner source --policy "$WORK/policy.json" --scan-id kind1 --scan-dir "$WS/scan1" --source "$WS/scan1/src" \
    --project demo --version 1.0 > "$WORK/source.json" 2> "$WORK/source.log"
rc=$?
set -e
out="$(jq -r '.output_dir // empty' "$WORK/source.json")"
[ "$rc" = 0 ] && pass "the runner's source scan exits 0" \
    || fail "source scan exit $rc" "$(cat "$WORK/source.json"; tail -20 "$WORK/source.log")"
status="$(jq -r '.run_status' "$WORK/source.json")"
case "$status" in succeeded|succeeded_degraded) pass "run status $status" ;; *) fail "run status $status" ;; esac
[ "$(jq -r '.plan_status + " " + .detected_ecosystem' "$WORK/source.json")" = "ok node" ] \
    && pass "the plan is ok for a Node.js source" || fail "plan: $(jq -c '[.plan_status, .detected_ecosystem]' "$WORK/source.json")"
[ "$(jq -r '.stages.stage1.exit_code' "$WORK/source.json")" = 0 ] && pass "stage 1 exited 0" \
    || fail "stage 1: $(jq -c .stages.stage1 "$WORK/source.json")" "$(grep '^\[cdxgen\]' "$WORK/source.log" | tail -10)"
bom="$out/demo_1.0_bom.json"
n="$(jq '.components | length' "$bom" 2>/dev/null || echo 0)"
[ "${n:-0}" -ge 5 ] && pass "the SBOM has $n components" || fail "the SBOM has ${n:-no} components"
jq -e '[.components[] | select(.name == "express")] | length > 0' "$bom" >/dev/null 2>&1 \
    && pass "express is in the SBOM" || fail "express is missing from the SBOM"
grep -q '^\[cdxgen\] ' "$WORK/source.log" && pass "stage 1 output reached on_log" || fail "no stage 1 lines were logged"
[ "$(tree_hash "$WS/scan1/src")" = "$before" ] && pass "the source tree is unchanged" || fail "the scan changed the source tree"
# A Pod whose container has ended may stay listed for a moment while it is
# removed; what must not be left is a Job, or a container that still runs.
live_pods() {  # live_pods <selector>
    kubectl get pods -n "$NS" -l "$1" --field-selector=status.phase!=Succeeded,status.phase!=Failed -o name \
        2>/dev/null | wc -l | tr -d ' '
}
left="$(kubectl get jobs -n "$NS" -l app.kubernetes.io/part-of=bomlens-engine -o name 2>/dev/null | wc -l | tr -d ' ')"
left=$((left + $(live_pods app.kubernetes.io/part-of=bomlens-engine)))
[ "$left" = 0 ] && pass "no Job or running Pod is left" || fail "$left engine objects left" "$(kubectl get jobs,pods -n "$NS")"

echo "== cancel =="
mkdir -p "$WS/scan3"
cp -R "$ROOT_DIR/examples/nodejs" "$WS/scan3/src"
before3="$(tree_hash "$WS/scan3/src")"
# Started as its own process (not through the shell function), so the
# signal reaches the runner and not a subshell.
PYTHONPATH="$ROOT_DIR/runner/src" python3 -m bomlens_runner source --policy "$WORK/policy.json" --scan-id kind3 \
    --scan-dir "$WS/scan3" --source "$WS/scan3/src" --project demo --version 1.0 --api http://127.0.0.1:8001 \
    > "$WORK/cancel.json" 2> "$WORK/cancel.log" &
rpid=$!
for _ in $(seq 1 120); do
    kubectl get pods -n "$NS" -l app.kubernetes.io/component=engine-stage1 -o name 2>/dev/null | grep -q . && break
    sleep 1
done
kill -TERM "$rpid"
t0=$(date +%s)
wait "$rpid" || true
t1=$(date +%s)
[ "$(jq -r .error "$WORK/cancel.json" 2>/dev/null)" = "ScanCancelled" ] && pass "SIGTERM cancels the scan" \
    || fail "cancel result: $(cat "$WORK/cancel.json")"
[ $((t1 - t0)) -le 60 ] && pass "cancel finished in $((t1 - t0))s" || fail "cancel took $((t1 - t0))s"
left="$(live_pods bomlens.engine/scan=kind3)"
[ "$left" = 0 ] && pass "a cancelled scan leaves no running Pod" || fail "$left Pods left after cancel" "$(kubectl get pods -n "$NS")"
[ "$(tree_hash "$WS/scan3/src")" = "$before3" ] && pass "a scan cancelled in stage 1 leaves the source unchanged" \
    || fail "the cancelled scan changed the source tree" "$(grep -c '' "$WORK/cancel.log") log lines"

echo "== image scan =="
mkdir -p "$WS/scan2"
set +e
runner image --policy "$WORK/policy.json" --scan-id kind2 --scan-dir "$WS/scan2" --target alpine:3.20 \
    --project alpine --version 3.20 > "$WORK/image.json" 2> "$WORK/image.log"
rc=$?
set -e
[ "$rc" = 0 ] && pass "the runner's image scan exits 0" || fail "image scan exit $rc" "$(cat "$WORK/image.json"; tail -20 "$WORK/image.log")"
out="$(jq -r '.output_dir // empty' "$WORK/image.json")"
jq -e '[.components[] | select(.name == "musl")] | length > 0' "$out/alpine_3.20_bom.json" >/dev/null 2>&1 \
    && pass "the image SBOM lists musl" || fail "the image SBOM does not list musl"

echo "== network labels =="
probe() {  # probe <network label>
    local name="probe-$1"
    kubectl run "$name" -n "$NS" --image="$ENGINE" --restart=Never --quiet \
        --labels="app.kubernetes.io/part-of=bomlens-engine,bomlens.engine/network=$1" \
        --command -- sh -c 'curl -sS -m 10 -o /dev/null https://ghcr.io && echo reached || echo blocked' >/dev/null
    kubectl wait -n "$NS" --for=jsonpath='{.status.phase}'=Succeeded "pod/$name" --timeout=120s >/dev/null 2>&1 || true
    kubectl logs -n "$NS" "$name" 2>/dev/null | tail -1
    kubectl delete pod -n "$NS" "$name" --wait=false >/dev/null 2>&1 || true
}
[ "$(probe egress)" = reached ] && pass "an egress Pod reaches the internet" || fail "an egress Pod cannot reach the internet"
[ "$(probe none)" = blocked ] && pass "a network=none Pod is blocked" \
    || fail "a network=none Pod reached the internet (does the CNI enforce NetworkPolicy?)"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
