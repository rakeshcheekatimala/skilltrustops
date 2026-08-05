FROM python:3.11-slim@sha256:94c50be2dc994b873b55bc123e95e6dbade08095b3dfd790f51c34de3f08cbb7

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/opt/skilltrustops/src

WORKDIR /opt/skilltrustops
COPY pyproject.toml README.md ./
COPY src ./src
COPY benchmarks/market-scan/docker/requirements.lock /opt/requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes \
    -r /opt/requirements.lock

COPY benchmarks/market-scan/run_container_benchmark.py /opt/benchmark/run.py
COPY benchmarks/market-scan/fetch_corpus.py /opt/benchmark/fetch_corpus.py
COPY benchmarks/market-scan/lock_corpus.py /opt/benchmark/lock_corpus.py
COPY benchmarks/market-scan/summarize_docker_results.py /opt/benchmark/summarize.py
COPY benchmarks/market-scan/generate_dashboard.py /opt/benchmark/dashboard.py

ENTRYPOINT ["python", "/opt/benchmark/run.py"]
