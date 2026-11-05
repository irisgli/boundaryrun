# Runtime image for untrusted target code, its tests, the black-box probe and static analysis.
# Dependencies are installed at build time; containers run with no network.
# Base pinned by digest so a rebuild cannot silently pull a different layer set.
# Refresh with: docker pull python:3.12-slim && docker image inspect python:3.12-slim --format '{{index .RepoDigests 0}}'
FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30

RUN pip install --no-cache-dir \
        fastapi==0.115.6 \
        uvicorn==0.34.0 \
        httpx==0.28.1 \
        pytest==8.3.4 \
        semgrep==1.101.0 \
        setuptools==75.6.0 \
    && rm -rf /root/.cache

ENV SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0
USER 65534:65534
WORKDIR /work
