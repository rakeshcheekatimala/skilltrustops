#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BENCH="$ROOT/benchmarks/market-scan"
WORK=${BENCH_WORK_DIR:-"$BENCH/.benchmark-work"}
CORPUS="$WORK/corpus"
RESULTS="$WORK/results"
IMAGE=skilltrustops-market-bench:local

mkdir -p "$WORK" "$RESULTS"
if [[ -n "$(find "$RESULTS" -mindepth 1 -print -quit)" ]]; then
  echo "Results directory is not empty: $RESULTS" >&2
  echo "Set BENCH_WORK_DIR to a new directory for an independent run." >&2
  exit 2
fi
if [[ -d "$CORPUS" ]] && [[ -n "$(find "$CORPUS" -mindepth 1 -print -quit)" ]]; then
  echo "Using existing corpus: $CORPUS"
else
  mkdir -p "$CORPUS"
  docker build -f "$BENCH/docker/Dockerfile" -t "$IMAGE" "$ROOT"
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    --network bridge \
    -v "$CORPUS:/corpus" \
    -v "$BENCH/sources.yaml:/sources.yaml:ro" \
    --entrypoint python \
    "$IMAGE" \
    /opt/benchmark/fetch_corpus.py \
    --sources /sources.yaml \
    --output /corpus
fi

docker build -f "$BENCH/docker/Dockerfile" -t "$IMAGE" "$ROOT"
docker run --rm \
  --user "$(id -u):$(id -g)" \
  --network none \
  -v "$CORPUS:/corpus:ro" \
  -v "$BENCH/corpus.lock.json:/corpus.lock.json:ro" \
  --entrypoint python \
  "$IMAGE" \
  /opt/benchmark/lock_corpus.py \
  /corpus --lock /corpus.lock.json --verify

RESULTS_DIR="$RESULTS" SKIP_BUILD=1 "$BENCH/run-docker-matrix.sh" "$CORPUS"

docker run --rm \
  --user "$(id -u):$(id -g)" \
  --network none \
  -v "$RESULTS:/results" \
  --entrypoint python \
  "$IMAGE" \
  /opt/benchmark/dashboard.py \
  --results /results \
  --output /results/index.html

(
  cd "$RESULTS"
  shasum -a 256 -c ARTIFACTS.sha256
)

echo "REPRODUCED: $RESULTS/index.html"
