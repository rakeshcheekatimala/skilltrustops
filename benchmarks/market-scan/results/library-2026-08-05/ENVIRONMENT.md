# Lean whole-package benchmark environment

- Run completed: 2026-08-05
- SkillTrustOps: 0.1.0, rule set `2026.1`
- Python: 3.11.15
- Linux container: arm64, Docker Desktop 28.1.1
- Image ID: `sha256:dc4e82250c26da5861f56c8d6ebafa4c2e959a3f97634735a9c4c24d8668cc50`
- Base image: `python:3.11-slim@sha256:94c50be2dc994b873b55bc123e95e6dbade08095b3dfd790f51c34de3f08cbb7`
- Corpus fingerprint: `58525efef3fec4e86635cf951205f98e88e356d43d6da44bd58dbb1891796f4b`
- Runs: 5 per profile, 7 profiles, 605 skills per run
- Timed network: disabled

The image contains the Python library and dependencies in
`docker/requirements.lock`. It does not contain the historical FastAPI,
Uvicorn, frontend, or backend dependencies. The local image ID is run evidence,
not a public registry digest.

Other Docker workloads were active on the host. Profiles ran sequentially in a
fixed order. These facts make the results reproducible as a procedure, but not
bit-for-bit timing promises for different machines or host load.
