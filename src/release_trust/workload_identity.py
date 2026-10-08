"""Reusable X.509 workload-identity checks for signed release payloads."""

from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID


def verify_code_signing_envelope(
    certificate_pem,
    authority_pem,
    expected_identity,
    integrated_time,
    expected_fingerprint,
    signatures,
    payload,
):
    """Verify a single-signature payload against its historical workload identity."""
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode())
    authority = x509.load_pem_x509_certificate(authority_pem.encode())
    if certificate.issuer != authority.subject:
        raise ValueError("builder certificate has an untrusted issuer")
    authority.public_key().verify(certificate.signature, certificate.tbs_certificate_bytes)

    identities = certificate.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.UniformResourceIdentifier)
    if identities != [expected_identity]:
        raise ValueError("builder certificate has an unauthorized workload identity")
    usages = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    if ExtendedKeyUsageOID.CODE_SIGNING not in usages:
        raise ValueError("builder certificate is not authorized for code signing")

    observed_time = datetime.fromisoformat(integrated_time.replace("Z", "+00:00"))
    observed_time = observed_time.astimezone(UTC)
    if not certificate.not_valid_before_utc <= observed_time <= certificate.not_valid_after_utc:
        raise ValueError("builder certificate was not valid at log integration time")
    if certificate.fingerprint(hashes.SHA256()).hex() != expected_fingerprint:
        raise ValueError("checkpoint is not bound to this builder certificate")

    if len(signatures) != 1:
        raise ValueError("attestation must carry exactly one builder signature")
    certificate.public_key().verify(bytes.fromhex(signatures[0]["sig"]), payload)
