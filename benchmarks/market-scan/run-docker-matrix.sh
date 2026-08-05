#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 /absolute/path/to/corpus" >&2
  exit 2
fi

CORPUS=$1
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
RESULTS=${RESULTS_DIR:-"$ROOT/benchmarks/market-scan/results/docker"}
IMAGE=skilltrustops-market-bench:local

if [[ ! -d "$CORPUS" ]]; then
  echo "Corpus directory does not exist: $CORPUS" >&2
  exit 2
fi

mkdir -p "$RESULTS"
if [[ ${SKIP_BUILD:-0} != 1 ]]; then
  docker build -f "$ROOT/benchmarks/market-scan/docker/Dockerfile" -t "$IMAGE" "$ROOT"
fi

run_profile() {
  local profile=$1
  local cpus=$2
  local memory=$3
  docker run --rm \
    --cpus "$cpus" \
    --memory "$memory" \
    --memory-swap "$memory" \
    --network none \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=64m \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" \
    -v "$CORPUS:/corpus:ro" \
    -v "$ROOT/skilltrustops.yaml:/policy.yaml:ro" \
    -v "$RESULTS:/results" \
    "$IMAGE" \
    --profile "$profile" \
    --runs 5 \
    --output "/results/$profile.json.gz"
}

# CPU sweep: memory held constant at 1 GiB.
run_profile cpu-025-mem-1g 0.25 1g
run_profile cpu-050-mem-1g 0.50 1g
run_profile cpu-100-mem-1g 1.00 1g
run_profile cpu-200-mem-1g 2.00 1g

# Memory sweep: CPU held constant at one core.
run_profile cpu-100-mem-512m 1.00 512m
run_profile cpu-100-mem-2g 1.00 2g
run_profile cpu-100-mem-3g 1.00 3g

python3 "$ROOT/benchmarks/market-scan/summarize_docker_results.py" "$RESULTS"
