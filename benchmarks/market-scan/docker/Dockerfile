FROM python:3.12-slim@sha256:646fb0bca3dd3ea1bcc6feb72c17ed16eed6e10cffc732fcc1478bd3e7f02d7b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/skilltrustops
COPY pyproject.toml README.md ./
COPY src ./src
COPY benchmarks/market-scan/docker/requirements.lock /opt/requirements.lock
RUN pip install --no-cache-dir -r /opt/requirements.lock \
    && pip install --no-cache-dir --no-deps .

COPY benchmarks/market-scan/run_container_benchmark.py /opt/benchmark/run.py
COPY benchmarks/market-scan/fetch_corpus.py /opt/benchmark/fetch_corpus.py
COPY benchmarks/market-scan/lock_corpus.py /opt/benchmark/lock_corpus.py
COPY benchmarks/market-scan/summarize_docker_results.py /opt/benchmark/summarize.py
COPY benchmarks/market-scan/generate_dashboard.py /opt/benchmark/dashboard.py

ENTRYPOINT ["python", "/opt/benchmark/run.py"]
