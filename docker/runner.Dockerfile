# Runtime image for untrusted target code, its tests, the black-box probe and static analysis.
# Dependencies are installed at build time; containers run with no network.
FROM python:3.12-slim

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
