# Release Trust Control Plane

This service decides whether a signed OCI release is safe to run. It reads TUF
metadata, verifies the complete multi-platform image and its provenance, checks
the witnessed transparency history, and then records one admission decision that
both replicas can agree on.

The repository includes 2 admission replicas and 2 publishers because release
state is rarely changed by only one process in practice. etcd stores published
metadata and the shared trust journal, PostgreSQL keeps an audit trail, and each
admission replica also has its own durable mirror for short coordination outages.

## Services

- `admission-a` and `admission-b` verify releases and expose `/admit`.
- `publisher-a` and `publisher-b` publish signed TUF metadata with etcd CAS.
- `metadata` serves signed metadata and attestations from etcd.
- `coordination` is the narrow etcd gateway used by admission replicas.
- `bootstrap` creates local signing material and a healthy sample release.
- `registry`, `etcd`, and `postgres` provide OCI, trust, and audit persistence.

The important trust rules are in `docs/security-contract.md`, while
`docs/architecture.md` explains the main data flow. Some of the replica recovery
details are easier to understand from `trust.py`, especially the relationship
between the shared journal and each local mirror.

## Run locally

You need Docker with Compose v2.

```bash
cp .env.example .env
docker compose up --build -d
docker compose ps
```

The default bootstrap is healthy, so both platforms should be admitted:

```bash
make smoke
```

Admission replica A is available on `localhost:8081`, replica B on
`localhost:8083`, metadata on `localhost:8080`, and the 2 publishers on ports
`8082` and `8084`.

To inspect an audit decision, take the `decision_id` from `/admit` and use the
admin token from `.env`:

```bash
curl -H "Authorization: Bearer $(grep '^ADMIN_TOKEN=' .env | cut -d= -f2-)" \
  "http://localhost:8081/decisions/<decision-id>"
```

## Develop without Compose

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e ".[dev]"
make test
make lint
```

Most unit tests use SQLite and mocked service boundaries, so they do not need
Docker. The smoke check does need the full stack.

## Configuration

The common local values are in `.env.example`. Service URLs, storage paths, log
level, publisher token, and admin token can also be set directly through the
environment. The local defaults are convenient for one machine, but the tokens
must be changed before the services are shared.

`SEED_SCENARIO=incident` starts with an incomplete root transition and a mutable
tag that points arm64 at the wrong revision. This mode is useful when practicing
the recovery steps in `docs/operations.md`; normal development should use the
default `healthy` scenario.
