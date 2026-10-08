FROM python:3.12-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl jq openssl skopeo \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

COPY scripts/ ./scripts/
RUN chmod +x scripts/releasectl scripts/rootctl scripts/smoke.sh \
    && ln -s /workspace/scripts/releasectl /usr/local/bin/releasectl \
    && ln -s /workspace/scripts/rootctl /usr/local/bin/rootctl

CMD ["release-trust-supervisor"]
