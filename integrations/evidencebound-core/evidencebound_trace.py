"""Thin EvidenceBound Core -> TRACE v0.2 interoperability adapter.

The adapter re-runs released EvidenceBound verification against explicit current
inputs, authenticates the supplied EvidenceBound signed receipt against that exact
result, and emits a TRACE record only for a current ACTIVE-key ALLOW result.

It does not treat signatures as proof that upstream evidence is truthful.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Mapping

import agentrust_trace
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from evidencebound import (
    ActionDecision,
    ApplicabilityStatus,
    Checkpoint,
    EvidenceRecord,
    IntegrityStatus,
    PolicyBinding,
    ReceiptVerifier,
    SignedProofReceipt,
    SignedReceiptStatus,
    canonical_bytes,
    verify_checkpoint,
    verify_signed_receipt,
)
from evidencebound import __version__ as evidencebound_version

EAT_PROFILE = "tag:agentrust-io.com,2026:trace-v0.2"
SOURCE_REL = "evidencebound-verification"
SOFTWARE_ONLY = "software-only"


class AdapterError(ValueError):
    """Raised when current EvidenceBound state cannot support TRACE emission."""


@dataclass(frozen=True, slots=True)
class TraceContext:
    """TRACE metadata supplied by the caller rather than asserted by EvidenceBound."""

    subject: str
    model_provider: str
    model_id: str
    data_class: str
    runtime_measurement: str
    build_digest: str
    appraisal_verifier: str
    evidence_resolver: str
    evidence_retention: str | None = None


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _require_nonempty(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdapterError(f"{field} must be non-empty")
    return value.strip()


def _require_digest(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise AdapterError(f"{field} must be sha256:<64 lowercase hex>")
    body = value.removeprefix("sha256:")
    if len(body) != 64 or any(ch not in "0123456789abcdef" for ch in body):
        raise AdapterError(f"{field} must be sha256:<64 lowercase hex>")
    return value


def _validate_context(context: TraceContext) -> None:
    subject = _require_nonempty(context.subject, "subject")
    if not (subject.startswith("spiffe://") or subject.startswith("did:")):
        raise AdapterError("subject must be a SPIFFE or DID URI")
    _require_nonempty(context.model_provider, "model_provider")
    _require_nonempty(context.model_id, "model_id")
    _require_nonempty(context.data_class, "data_class")
    _require_digest(context.runtime_measurement, "runtime_measurement")
    _require_digest(context.build_digest, "build_digest")
    verifier = _require_nonempty(context.appraisal_verifier, "appraisal_verifier")
    if ":" not in verifier:
        raise AdapterError("appraisal_verifier must be an absolute URI")
    _require_nonempty(context.evidence_resolver, "evidence_resolver")


def signed_receipt_reference_digest(receipt: SignedProofReceipt) -> str:
    """Digest the exact signed EvidenceBound envelope deterministically."""
    return _sha256(canonical_bytes(receipt.to_dict()))


def policy_binding_digest(checkpoint: Checkpoint) -> str:
    """Digest the exact EvidenceBound PolicyBinding carried by the checkpoint."""
    return _sha256(canonical_bytes(checkpoint.policy.to_dict()))


def emit_trace_record(
    *,
    checkpoint: Checkpoint,
    signed_receipt: SignedProofReceipt,
    evidencebound_verifier: ReceiptVerifier,
    current_evidence: Mapping[str, EvidenceRecord],
    expected_policy: PolicyBinding,
    verification_time: datetime,
    context: TraceContext,
    trace_signing_key: Ed25519PrivateKey,
    issued_at: int | None = None,
) -> dict[str, object]:
    """Emit TRACE only for current, authenticated EvidenceBound ALLOW.

    Sequence:
      1. re-run EvidenceBound verification on explicit current inputs;
      2. verify the signed receipt against that exact recomputed result;
      3. require ACTIVE-key VERIFIED status;
      4. require integrity/applicability VERIFIED and action ALLOW;
      5. sign and schema-validate the TRACE record.
    """
    _validate_context(context)
    if verification_time.tzinfo is None or verification_time.utcoffset() is None:
        raise AdapterError("verification_time must be timezone-aware")

    current = verify_checkpoint(
        checkpoint,
        current_evidence=current_evidence,
        expected_policy=expected_policy,
        prior_receipt=signed_receipt.receipt,
        now=verification_time,
    )

    authenticated = verify_signed_receipt(
        signed_receipt,
        checkpoint,
        evidencebound_verifier,
        verification_result=current,
    )
    if authenticated.status is not SignedReceiptStatus.VERIFIED:
        raise AdapterError(
            "EvidenceBound signed receipt is not an ACTIVE-key VERIFIED binding: "
            f"{authenticated.status.value}"
        )

    if current.integrity is not IntegrityStatus.VERIFIED:
        raise AdapterError(f"EvidenceBound integrity is {current.integrity.value}")
    if current.applicability is not ApplicabilityStatus.VERIFIED:
        raise AdapterError(
            f"EvidenceBound applicability is {current.applicability.value}"
        )
    if current.action is not ActionDecision.ALLOW:
        raise AdapterError(f"EvidenceBound action is {current.action.value}")

    iat = int(time.time()) if issued_at is None else issued_at
    if not isinstance(iat, int) or isinstance(iat, bool):
        raise AdapterError("issued_at must be integer epoch seconds")

    reference: dict[str, object] = {
        "rel": SOURCE_REL,
        "id": checkpoint.checkpoint_id,
        "resolver": context.evidence_resolver,
        "digest": signed_receipt_reference_digest(signed_receipt),
    }
    if context.evidence_retention:
        reference["retention"] = context.evidence_retention

    record: dict[str, object] = {
        "eat_profile": EAT_PROFILE,
        "iat": iat,
        "subject": context.subject,
        "model": {
            "provider": context.model_provider,
            "model_id": context.model_id,
        },
        "runtime": {
            "platform": SOFTWARE_ONLY,
            "measurement": context.runtime_measurement,
        },
        "policy": {
            "bundle_hash": policy_binding_digest(checkpoint),
            "enforcement_mode": "declared",
            "version": checkpoint.policy.version,
        },
        "data_class": context.data_class,
        "build_provenance": {
            "slsa_level": 0,
            "digest": context.build_digest,
        },
        "appraisal": {
            "status": "none",
            "verifier": context.appraisal_verifier,
        },
        "origin": {
            "kind": "third-party-control-plane",
            "producer": f"evidencebound-core/{evidencebound_version}",
            "source_event_id": checkpoint.checkpoint_id,
        },
        "references": [reference],
    }

    signed = agentrust_trace.sign_record(record, trace_signing_key)
    try:
        agentrust_trace.validate_json(signed)
    except Exception as exc:
        raise AdapterError(
            "generated TRACE record failed released schema validation: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    return signed
