# Benchmark environment lock

- Image ID: `sha256:a28851a2322306b22cd8a6033d7890759e8643ed9dec210854c79bcc1c761b7e`
- Base image: `python:3.12-slim@sha256:646fb0bca3dd3ea1bcc6feb72c17ed16eed6e10cffc732fcc1478bd3e7f02d7b`
- Docker: client/server 28.1.1, Linux arm64, overlayfs
- Docker Desktop allocation: 10 CPUs, 8,218,034,176 bytes memory
- SkillTrustOps: 0.1.0
- Policy SHA-256: `d257f8e083a66ccbb6f1c94a78c78d7cb101b31a3bd7ff46082929f91a432845`
- Corpus entries SHA-256: `58525efef3fec4e86635cf951205f98e88e356d43d6da44bd58dbb1891796f4b`

## Installed Python environment

```text
annotated-doc==0.0.5
annotated-types==0.8.0
anyio==4.14.2
click==8.4.2
fastapi==0.141.1
h11==0.16.0
idna==3.18
markdown-it-py==4.2.0
mdurl==0.1.2
pydantic==2.13.4
pydantic_core==2.46.4
Pygments==2.20.0
PyYAML==6.0.3
rich==14.3.4
shellingham==1.5.4
starlette==1.4.0
typer==0.27.1
typing-inspection==0.4.2
typing_extensions==4.16.0
uvicorn==0.52.1
```

The local image ID is evidence for this run, not a public pull reference. A
publishable release should push the exact multi-architecture image to a registry,
sign it, attach an SBOM/provenance attestation, and replace this ID with the
registry digest.

