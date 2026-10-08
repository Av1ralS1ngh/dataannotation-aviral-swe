# Release platform security contract

This is the standing release-integrity contract for the control plane. Each
rule states a defensive property the admission service must enforce. Conditions
such as replays, forks, and equivocation are hostile repository states the
service must withstand, not actions the operator is asked to perform.

These rules apply to every release, even when the smoke test and the current deployment are green.

## 1. Complete OCI platform closure

The `stable` release contains exactly the required `linux/amd64` and `linux/arm64` platforms. The
admission service must resolve the requested platform from the authorized OCI index and must reject
missing, duplicate, or unexpected platform descriptors. Verifying one architecture is not evidence
about another.

Every required child descriptor must resolve by digest to a real OCI image manifest. The fetched
manifest bytes must match the descriptor's digest and size, and its schema and media type must be
valid. An otherwise authorized index with a dangling, substituted, or malformed child is not a
complete release.

An image manifest is only the root of that platform's runnable content graph. Its configuration
descriptor and every layer descriptor must also resolve in the same repository, and the fetched
blob bytes must match the descriptor's digest and size. The configuration and layer media types
must be valid for an OCI image. Admission must verify this closure for every required platform,
including an unrequested sibling; authorizing an image that the runtime cannot pull is not recovery.

## 2. Exact provenance binding

Every admitted child manifest has an in-toto statement signed by the approved release builder. The
statement's subject must bind the exact child manifest digest and repository being admitted, and its
builder identity and source revision must equal the values authorized by the release target.

A valid signature over an attestation for another digest, repository, workflow, or revision grants
no authority. An in-toto statement may describe a set of subjects, but that set must contain the
exact repository and digest being admitted. Unrelated subjects grant no authority and do not erase
a correct binding.

The authorized source revision is a cross-system invariant, not merely a claim inside provenance.
It must agree among the trusted release target, the signed provenance, and the revision embedded in
each platform's OCI image configuration. Platform information in the image configuration must also
agree with its index descriptor. Rejecting all artifacts is not recovery: a complete, coherent,
correctly signed release must remain usable.

## 3. Signed digests are authoritative

OCI tags are mutable discovery aliases. Deployment authority comes from the index digest recorded in
the currently trusted TUF target. Retargeting `stable` after metadata publication must not change the
artifact admitted for that release. A successful `/admit` response identifies the selected authorized
child in `manifest_digest` and its verified source revision in `source_revision`; clients use these
fields as deployment outputs. Additional diagnostic fields are optional.

## 4. Root-of-trust transition

Existing clients are pinned to `/operator/client/1.root.json`. Root version 2 must be authenticated
by the threshold specified in root version 1 and by the threshold it specifies for itself. The
compromised key named in `/operator/incident.json` must not retain a root role in version 2 or
regain a root role in any later root accepted through this chain. Rejecting such a candidate must
not poison the chain: a correctly signed clean successor must remain usable.

Once a root version is accepted, that version is bound to its canonical signed root body across
both admission replicas. A different root policy at the same version is equivocation and must be
rejected even when it is correctly threshold-signed, unexpired, and contains no compromised key.
Differences only in the signature envelope, such as an additional valid signature over the exact
same signed body, are the same policy and must remain usable. When the repository presents a root
at an already accepted version, silently substituting a cached policy for a different observed
signed body does not reject that equivocation. Rejecting an alternate policy must leave the accepted
root usable, and a correctly signed next version extending it must still advance the chain.

Root updates are accepted one sequential version at a time. If a later root candidate fails, every
earlier authenticated root step remains durably bound across both admission replicas. A failed
later step must not permit a different policy to replace an earlier root at the same version. If
the repository temporarily omits an already accepted root, both replicas must continue using that
accepted policy, and must still compare a restored repository copy with the policy that was
accepted earlier.

Never replace the client's pinned root out of band or trust the highest numbered root without a
verified chain. Every root transition must preserve or strengthen its predecessor's root-role
signature threshold. A fully cross-signed threshold downgrade is still invalid, and rejecting it
must leave the chain able to accept a clean successor at that version.

A threshold counts independent public-key material, not merely different key identifiers. Two
key IDs that encode the same public key provide one signer, even if the same private key produces
valid signatures under both aliases. A root whose numerical threshold is met only by duplicated
key material weakens the effective quorum and must be rejected without poisoning the clean
successor at that version.

## 5. Rollback and freeze resistance

Root, timestamp, snapshot, and targets signatures, expiration times, hashes, lengths, and version
links must be verified. A metadata version older than one already accepted must be rejected even
when its signature is valid. Trusted root state includes its version, canonical signed-body identity,
and enough accepted state to remain usable through the repository behavior described above. Trusted
version state is shared by the admission replicas and survives an admission-service restart.

## 6. Witnessed transparency history

Every provenance bundle carries a checkpoint signed by the release log and both independent
witnesses. All signatures must authorize the exact same checkpoint. History is scoped by the
checkpoint's signed log origin, not by artifact repository or admission process: repositories and
admission replicas using one origin share one durable history, while an independent origin has an
independent history. Origins in this control plane are newly provisioned release streams: an unseen
origin must begin at tree size 1 with no consistency proof. A fully signed larger checkpoint cannot
bootstrap trust by hiding an unaudited prefix. Every later proof must extend the latest accepted
size and root for that origin, not merely an older ancestor. Rejecting either kind of candidate must
leave the accepted frontier unchanged. The artifact entry must have
a valid RFC 6962 SHA-256 inclusion proof to the signed tree root. A larger checkpoint may skip tree
sizes, but it must carry a valid RFC 6962 consistency proof from the last accepted size and root. A
fully signed larger fork or a second root at the same tree size is still equivocation and must be
rejected. Replaying the current checkpoint is idempotent, and a valid extension must remain
available after a rejected fork. Concurrent divergent extensions from one accepted root must not
both succeed or overwrite each other; exactly one history may advance, and a continuation of that
winner must remain usable. A larger accepted checkpoint must not move the entry's release-policy
epoch or integration time backward. A newer TUF release therefore cannot replay a checkpoint from
an older policy epoch.

## 7. Distributed concurrent publication

Publishers run on separate hosts and share only the etcd release metadata store. Concurrent
successful promotions are linearizable: they allocate distinct, monotonically increasing metadata
versions, and every success remains represented in repository history. A process-local lock does
not coordinate another publisher. No update may overwrite a peer's version or combine one release's
targets with another release's snapshot or timestamp. Publishing one channel must preserve other
channels and their immutable release targets.

## 8. Interruption-safe visibility

Publication may stop at any stage. After interruption, a clean client must observe either the
complete previous release or the complete new release, never a partially published mixture.
Retrying the promotion must converge safely, including when another publisher commits first.

## 9. Historical workload identity

Builder attestations use a short-lived certificate issued by the pinned builder authority. Verify
the certificate chain, code-signing purpose, exact workload identity, and attestation signature.
Certificate validity is evaluated at the integration time inside the witnessed checkpoint, not at
the admission server's current wall clock. The checkpoint must bind that time and the exact
certificate fingerprint to the authorized OCI index. An expired certificate that was valid when
its entry was integrated remains usable; a currently valid certificate that was not yet valid at
integration, a certificate transplant, or another workload identity grants no authority.

`/operator/policy.json` also records time-scoped builder-certificate revocations. A matching
certificate remains valid for entries integrated before its `effective_at` time and grants no
authority at or after that instant. Rejecting a post-revocation entry must not advance either TUF
state or the transparency frontier; a valid continuation from the last pre-revocation checkpoint
must remain usable.

## 10. Atomic multi-platform authorization

An OCI index is one release authorization unit, not a collection of independently trusted platform
answers. Before allowing any requested platform or advancing transparency history, admission must
verify every required platform descriptor and every required child's provenance. All children must
bind the same source policy and the exact same witnessed checkpoint. A valid requested child does
not make a release usable when a sibling has invalid provenance or a different checkpoint. Rejecting
such a release must not poison history, and the corrected complete release must remain usable.

## 11. Transactional trusted-state advancement

Durable TUF high-water marks are shared by admission replicas and advance only after the complete
timestamp-to-snapshot-to-targets-to-release-target chain, the requested channel, and the target
object have all verified. Fully signed future metadata with a missing or mismatched target must be
rejected without committing its versions. Once a valid future version is accepted by one replica,
another replica must reject an older repository view as rollback.

Every accepted timestamp, snapshot, and targets version is also durably bound to that role's
canonical signed body across both replicas. A different signed body at an already accepted version
is equivocation and must be rejected even when the alternate timestamp-to-snapshot-to-targets chain
is internally consistent, fully signed, unexpired, and authorizes a valid release. Differences only
outside the signed body, such as JSON envelope serialization, are not equivocation. Rejecting an
alternate chain must leave the accepted chain usable, and a valid next-version chain must still
advance. The version and signed-body bindings for all three roles commit atomically only after the
complete release has verified; concurrent replicas may not accept conflicting same-version chains.

The complete release includes the registry manifests referenced by the authorized index. A signed
metadata chain whose required child is absent or does not match its descriptor must not bind TUF
versions.

## 12. Coordinated trust and replica recovery

The admission replicas have separate local disks and a supported shared coordination endpoint at
`COORDINATION_URL`; they have no direct path to the publication store. Publication and
repository reads continue while that endpoint is interrupted. An acknowledged trust decision must
remain binding across replica restarts, lost replies, stale local disks, and recovery of the shared
coordination service from an older snapshot.

During an outage, a running or restarted replica must continue admitting a complete release only
when that exact root, TUF-role, signed-body, and transparency decision was previously acknowledged
and is supported by its durable recovery state. It must not create a new root step, metadata
binding, release authorization, or transparency extension while isolated. Rejections must not
change accepted state, and requests must complete rather than wait indefinitely.

When coordination returns, neither side may be followed blindly. An older replica must recover the
newer acknowledged shared history before serving it. Conversely, a rolled-back shared snapshot
must not erase a newer acknowledged binding preserved by a replica; otherwise the same signed
version could be replaced by a fork after a routine restore. Reconciliation may restore only a
verifiable continuation of the known history and must converge the replicas before new trust
advances.

The externally visible decision remains indivisible: the timestamp, snapshot, targets, target
object, complete OCI/provenance result, and transparency frontier are either acknowledged together
or not at all. A process may stop after persistence succeeds but before receiving the reply.
Restart and exact retry must converge without exposing a mixture. Each authenticated root step is
also durable before it can authorize the next step, so a later invalid root cannot erase an
accepted intermediate root.
