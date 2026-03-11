FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    nmap \
    dnsutils \
    curl \
    ca-certificates \
    sslscan \
    && rm -rf /var/lib/apt/lists/*

# PEP 668: Ubuntu 24.04 blocks system pip — use venv
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY assessment/ ./assessment/

RUN mkdir -p /app/output

ENTRYPOINT ["/opt/venv/bin/python", "-m", "assessment.cli"]
