# Market skill scan

This benchmark exercises the public Python batch API against temporary snapshots
of public skill repositories. Third-party skill contents are not vendored here.
The source manifest and per-skill lock record immutable commits and SHA-256
digests so the corpus can be reconstructed subject to upstream availability and
licensing.

## Reproduce

The shortest path on a laptop with Docker Desktop or Docker Engine is:

```bash
./benchmarks/market-scan/reproduce.sh
```

It writes a self-contained dashboard and raw evidence to
`benchmarks/market-scan/.benchmark-work/results/`. No LLM or API key is used.

The individual reconstruction steps are:

1. Reconstruct and verify the exact `<owner>/<repository>/.../SKILL.md` corpus:

   ```bash
   python benchmarks/market-scan/fetch_corpus.py \
     --sources benchmarks/market-scan/sources.yaml \
     --output /tmp/skilltrust-corpus
   python benchmarks/market-scan/lock_corpus.py \
     /tmp/skilltrust-corpus \
     --lock benchmarks/market-scan/corpus.lock.json \
     --verify
   ```

2. Run:

   ```bash
   skilltrustops scan <temporary-root> \
     --policy skilltrustops.yaml \
     --format json > market-scan.json
   ```

3. Repeat at least five times and report median total time and latency
   percentiles. Do not merge download time or model/network time into local scan
time.

Open [index.html](index.html) for the granular dashboard. It is self-contained
and works without a server or internet connection.

## Docker resource matrix

Run the same corpus under controlled cgroup limits:

```bash
benchmarks/market-scan/run-docker-matrix.sh /absolute/path/to/corpus
```

The matrix changes one resource at a time:

- CPU: 0.25, 0.5, 1, and 2 cores with memory fixed at 1 GiB.
- Memory: 512 MiB, 1 GiB, 2 GiB, and 3 GiB with CPU fixed at one core.

The image runs without a network, as an unprivileged user, with all capabilities
dropped, a read-only filesystem, and a read-only corpus/policy. Raw results
include every skill/check result for all five runs, cgroup limits, peak cgroup
memory, process RSS, latency percentiles, throughput, tool version, and runtime
metadata. Image build and corpus download time are excluded from scan timing.
The Python base-image digest and runtime dependency versions are pinned in the
Docker build definition.

## Interpretation

`passed` means the configured deterministic checks emitted no finding. `failed`
means at least one finding requires review. It does **not** mean the skill is
malicious, exploitable, useful, or unsafe. This run has not been manually
adjudicated and therefore measures compatibility and scanner throughput, not
precision or recall.

Tessl Registry content was not included because authenticated registry access
was unavailable for this run. The documented skills.sh API also returned HTTP
401 without Vercel OIDC credentials. These are explicit acquisition gaps.
