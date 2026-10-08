# Operations

## Routine checks

Start with the process endpoints and then run the release CLI from a container:

```bash
docker compose ps
docker compose exec admission-a releasectl metadata
docker compose exec admission-a releasectl release stable
docker compose exec admission-a releasectl admit linux/amd64
docker compose exec admission-a releasectl admit linux/arm64
```

An admission response includes a `decision_id`. The matching audit row is useful
for seeing which validation stage failed, but the service logs should still be
checked for dependency and reconciliation errors.

## Publishing

Prepare `promotion.json` with repository, immutable index digest, source
revision, and release epoch:

```json
{
  "channel": "stable",
  "repository": "acme/release-api",
  "index_digest": "sha256:...",
  "source_revision": "8f7c2e1...",
  "release_epoch": 2
}
```

Then send it to either publisher:

```bash
curl -H "x-release-token: $PUBLISHER_TOKEN" \
  -H "content-type: application/json" \
  --data-binary @promotion.json \
  http://localhost:8082/promote
```

The publishers may race. Each writes immutable metadata bodies first and moves
the timestamp only through an etcd compare-and-swap, so retrying a request is
safe as long as the release body is unchanged.

## Root rotation

Inspect and verify the current transition before adding signatures:

```bash
docker compose --profile ops run --rm root-operator rootctl inspect 2
docker compose --profile ops run --rm root-operator rootctl verify-chain
```

The new root must satisfy both the old and new thresholds. Signing a draft with
only replacement keys does not authorize old clients to cross the transition.

## Incident seed

Set `SEED_SCENARIO=incident`, remove the local volumes, and start the stack again
to reproduce a bad arm64 tag and an incomplete root transition:

```bash
docker compose down -v
SEED_SCENARIO=incident docker compose up --build -d
```

The approved OCI index already exists by digest. Recovery should not rebuild the
release or replace the pinned root out of band. Add the missing old-root
signatures with `rootctl sign 2 root-old-a` and `rootctl sign 2 root-old-b`,
then verify that admission resolves the digest from signed metadata rather than
the mutable `stable` tag.

## Audit retention

Admission audit rows currently stay in PostgreSQL indefinitely. A retention job
is planned, but until then shared environments should monitor table growth and
archive old decisions according to their own compliance policy.
