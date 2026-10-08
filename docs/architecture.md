# Architecture

The release trust control plane keeps publication and admission separate.
Publishers can move a channel forward, but they cannot make an admission replica
trust it. Admission verifies the signed metadata, OCI graph, provenance, and
transparency checkpoint before it commits the resulting authority.

## Admission flow

1. `admission.py` asks `trust.py` for the release bound to a channel.
2. `trust.py` verifies the TUF root chain and timestamp, snapshot, and targets.
3. `oci.py` fetches the authorized index by digest and closes every platform's
   manifest, config, and layer graph.
4. Provenance is checked against the source revision, workload identity,
   certificate validity, revocation policy, and witnessed log checkpoint.
5. `trust.commit_authorization` atomically adds the TUF versions and transparency
   frontier to the shared authority journal.
6. `audit.py` records the decision and its validation stages in PostgreSQL.

The endpoint returns only after the trust commit and audit row are complete.
Audit storage describes what the service decided, but it is not itself a source
of release authority.

## State boundaries

etcd has 2 independent key spaces:

- `release/` contains immutable target bodies and versioned TUF metadata.
- `artifact-trust/authority` contains the admission replicas' accepted history.

Each admission replica mirrors accepted authority in `/state/trusted-state.json`.
During a coordination outage it can replay a decision already supported by that
mirror, but it cannot advance trust. When coordination returns, the replica
compares commit lineage before it accepts either the journal or its mirror as
newer.

The OCI registry is content-addressed, operator policy is mounted read-only, and
online publisher keys are mounted only into publisher containers. PostgreSQL
contains operational audit data and is not consulted by trust verification.

## Service boundaries

The metadata service has a small API and serves bytes already stored in etcd.
The coordination gateway permits only the etcd range and
transaction calls used by trust reconciliation. Publishers write release
metadata directly to etcd because publication has its own CAS protocol.

The supervisor owns admission process restarts. It still uses Uvicorn's reload
mode, which is useful for local operations but means its process model differs
from the publisher and metadata services.
