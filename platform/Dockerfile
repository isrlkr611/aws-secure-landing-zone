# syntax=docker/dockerfile:1

# --- builder: resolve Python deps in isolation from the runtime image -----
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# --- runtime ----------------------------------------------------------------
FROM python:3.12-slim

ARG SUBFINDER_VERSION=2.14.0

# nmap for services/port_scan.py. subfinder is fetched as the official
# glibc-linked GitHub release binary rather than copied from
# projectdiscovery/subfinder's own Docker image, which is Alpine/musl-based
# and fails to exec ("no such file or directory", the classic missing
# dynamic-linker symptom) on this Debian-slim base - confirmed by actually
# building and smoke-testing this image, not assumed.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates curl unzip \
    && curl -fsSL -o /tmp/subfinder.zip \
      "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" \
    && unzip -o /tmp/subfinder.zip -d /usr/local/bin subfinder \
    && chmod +x /usr/local/bin/subfinder \
    && rm /tmp/subfinder.zip \
    && apt-get purge -y --auto-remove curl unzip \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

# Non-root, unprivileged user - nmap's -sT (TCP connect scan, see
# app/services/port_scan.py) does not need CAP_NET_RAW, so the container
# runs with no added Linux capabilities at all (see platform/k8s/deployment.yaml
# securityContext, which drops ALL and does not add any back).
RUN useradd --create-home --uid 10001 appuser
WORKDIR /app
COPY app/ ./app/
RUN chown -R appuser:appuser /app
USER 10001

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
