# Runtime image for untrusted target code, its tests, and the black-box probe.
# Dependencies are installed at build time; containers run with no network.
FROM python:3.12-slim

RUN pip install --no-cache-dir \
        fastapi==0.115.6 \
        uvicorn==0.34.0 \
        httpx==0.28.1 \
        pytest==8.3.4 \
    && rm -rf /root/.cache

USER 65534:65534
WORKDIR /work
