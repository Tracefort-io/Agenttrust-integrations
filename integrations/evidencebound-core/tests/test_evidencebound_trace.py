from __future__ import annotations

import hashlib
import importlib.metadata as metadata
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import agentrust_trace
import pytest
from agentrust_trace import generate_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from evidencebound import (
    Checkpoint,
    EvidenceRecord,
    KeyState,
    PolicyBinding,
    ProvenanceRecord,
    SignedReceiptStatus,
    sign_receipt,
    verify_checkpoint,
    verify_signed_receipt,
)
from evidencebound.providers.ed25519 import (
    Ed25519Signer,
    Ed25519VerificationKey,
    Ed25519Verifier,
)

from evidencebound_trace import (
    AdapterError,
    TraceContext,
    emit_trace_record,
    signed_receipt_reference_digest,
)

NOW = datetime(2026, 10, 5, 8, 0, tzinfo=timezone.utc)
ISSUED_AT = int(NOW.timestamp())
POLICY = PolicyBinding("policy.synthetic.transfer", "1")
PROVENANCE = ProvenanceRecord("synthetic-fixture", "urn:fixture:evidence:1")


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def context() -> TraceContext:
    return TraceContext(
        subject="spiffe://example.test/agent/evidencebound-demo",
        model_provider="synthetic",
        model_id="synthetic-model-v1",
        data_class="internal",
        runtime_measurement=digest("synthetic-runtime"),
        build_digest=digest("evidencebound-trace-adapter-fixture"),
        appraisal_verifier="https://evidencebound.org",
        evidence_resolver="EvidenceBound",
    )


def snapshot(*, valid_until: str = "2026-10-06T00:00:00Z") -> EvidenceRecord:
    return EvidenceRecord(
        "e1",
        {"approved": True, "amount": 100},
        PROVENANCE,
        valid_until=valid_until,
    )


def checkpoint(evidence: EvidenceRecord | None = None) -> Checkpoint:
    return Checkpoint(
        "cp-agentrust-1",
        "synthetic-agent",
        (evidence or snapshot(),),
        {"decision": "eligible"},
        POLICY,
    )


def signed_current_allow(
    cp: Checkpoint,
    current: dict[str, EvidenceRecord],
    *,
    key_state: KeyState = KeyState.ACTIVE,
    key_id: str = "eb-key",
    now: datetime = NOW,
):
    result = verify_checkpoint(
        cp,
        current_evidence=current,
        expected_policy=POLICY,
        now=now,
    )
    private = Ed25519PrivateKey.generate()
    signed = sign_receipt(result.receipt, Ed25519Signer(private, key_id))
    verifier = Ed25519Verifier(
        {key_id: Ed25519VerificationKey(private.public_key(), key_state)}
    )
    return result, signed, verifier


def emit(
    cp: Checkpoint,
    signed,
    verifier,
    current,
    *,
    policy: PolicyBinding = POLICY,
    verification_time: datetime = NOW,
    trace_key=None,
):
    return emit_trace_record(
        checkpoint=cp,
        signed_receipt=signed,
        evidencebound_verifier=verifier,
        current_evidence=current,
        expected_policy=policy,
        verification_time=verification_time,
        context=context(),
        trace_signing_key=trace_key or generate_key(),
        issued_at=ISSUED_AT,
    )


def test_released_package_identity_and_no_direct_url_for_evidencebound() -> None:
    assert metadata.version("evidencebound-core") == "0.4.0"
    assert metadata.version("agentrust-trace") == "0.11.0"
    assert metadata.version("agentrust-trace-tests") == "0.6.2"
    dist = metadata.distribution("evidencebound-core")
    assert not any(str(path).endswith("direct_url.json") for path in (dist.files or ()))


def test_positive_current_state_emits_trace() -> None:
    cp = checkpoint()
    current = {"e1": snapshot()}
    _, signed, verifier = signed_current_allow(cp, current)
    record = emit(cp, signed, verifier, current)
    assert record["runtime"]["platform"] == "software-only"
    assert record["policy"]["enforcement_mode"] == "declared"
    assert record["appraisal"]["status"] == "none"
    assert record["origin"]["kind"] == "third-party-control-plane"
    assert record["origin"]["producer"] == "evidencebound-core/0.4.0"
    assert record["references"][0]["rel"] == "evidencebound-verification"
    agentrust_trace.validate_json(record)


def test_changed_evidence_rejected() -> None:
    cp = checkpoint()
    positive = {"e1": snapshot()}
    _, signed, verifier = signed_current_allow(cp, positive)
    changed = {"e1": replace(snapshot(), payload={"approved": True, "amount": 101})}
    with pytest.raises(AdapterError):
        emit(cp, signed, verifier, changed)


def test_stale_evidence_rejected() -> None:
    cp = checkpoint()
    positive = {"e1": snapshot()}
    _, signed, verifier = signed_current_allow(cp, positive)
    stale = {"e1": replace(snapshot(), valid_until="2026-10-04T00:00:00Z")}
    with pytest.raises(AdapterError):
        emit(cp, signed, verifier, stale)


def test_missing_evidence_rejected() -> None:
    cp = checkpoint()
    positive = {"e1": snapshot()}
    _, signed, verifier = signed_current_allow(cp, positive)
    with pytest.raises(AdapterError):
        emit(cp, signed, verifier, {})


def test_refuted_evidence_rejected() -> None:
    cp = checkpoint()
    positive = {"e1": snapshot()}
    _, signed, verifier = signed_current_allow(cp, positive)
    refuted = {"e1": replace(snapshot(), explicitly_refuted=True)}
    with pytest.raises(AdapterError):
        emit(cp, signed, verifier, refuted)


def test_policy_drift_rejected() -> None:
    cp = checkpoint()
    current = {"e1": snapshot()}
    _, signed, verifier = signed_current_allow(cp, current)
    wrong_policy = PolicyBinding(POLICY.policy_id, "2")
    with pytest.raises(AdapterError):
        emit(cp, signed, verifier, current, policy=wrong_policy)


def test_tampered_signed_receipt_rejected() -> None:
    cp = checkpoint()
    current = {"e1": snapshot()}
    result, signed, verifier = signed_current_allow(cp, current)
    tampered = replace(signed, signature="A" * len(signed.signature))
    checked = verify_signed_receipt(
        tampered,
        cp,
        verifier,
        verification_result=result,
    )
    assert checked.status is SignedReceiptStatus.INVALID_SIGNATURE
    with pytest.raises(AdapterError):
        emit(cp, tampered, verifier, current)


def test_unknown_key_rejected() -> None:
    cp = checkpoint()
    current = {"e1": snapshot()}
    result, signed, _ = signed_current_allow(cp, current)
    unknown = Ed25519Verifier({})
    checked = verify_signed_receipt(
        signed,
        cp,
        unknown,
        verification_result=result,
    )
    assert checked.status is SignedReceiptStatus.UNKNOWN_KEY
    with pytest.raises(AdapterError):
        emit(cp, signed, unknown, current)


def test_revoked_key_rejected() -> None:
    cp = checkpoint()
    current = {"e1": snapshot()}
    result, signed, verifier = signed_current_allow(
        cp,
        current,
        key_state=KeyState.REVOKED,
        key_id="eb-revoked",
    )
    checked = verify_signed_receipt(
        signed,
        cp,
        verifier,
        verification_result=result,
    )
    assert checked.status is SignedReceiptStatus.REVOKED_KEY
    with pytest.raises(AdapterError):
        emit(cp, signed, verifier, current)


def test_retired_key_semantics_match_evidencebound_0_4_0() -> None:
    cp = checkpoint()
    current = {"e1": snapshot()}
    result, signed, verifier = signed_current_allow(
        cp,
        current,
        key_state=KeyState.RETIRED,
        key_id="eb-retired",
    )
    checked = verify_signed_receipt(
        signed,
        cp,
        verifier,
        verification_result=result,
    )
    assert checked.status is SignedReceiptStatus.VERIFIED_RETIRED_KEY
    with pytest.raises(AdapterError, match="VERIFIED_RETIRED_KEY"):
        emit(cp, signed, verifier, current)


def test_verification_time_and_timezone_boundary() -> None:
    boundary_evidence = snapshot(valid_until="2026-10-05T08:00:00Z")
    cp = checkpoint(boundary_evidence)
    current = {"e1": boundary_evidence}
    _, signed, verifier = signed_current_allow(cp, current, now=NOW)

    equivalent_offset = datetime(
        2026,
        10,
        5,
        11,
        0,
        tzinfo=timezone(timedelta(hours=3)),
    )
    emit(
        cp,
        signed,
        verifier,
        current,
        verification_time=equivalent_offset,
    )

    with pytest.raises(AdapterError):
        emit(
            cp,
            signed,
            verifier,
            current,
            verification_time=NOW + timedelta(seconds=1),
        )

    with pytest.raises(AdapterError, match="timezone-aware"):
        emit(
            cp,
            signed,
            verifier,
            current,
            verification_time=datetime(2026, 10, 5, 8, 0),
        )


def test_exact_result_receipt_binding() -> None:
    cp = checkpoint()
    current = {"e1": snapshot()}
    _, signed, verifier = signed_current_allow(cp, current)

    changed = {"e1": replace(snapshot(), payload={"approved": True, "amount": 101})}
    changed_result = verify_checkpoint(
        cp,
        current_evidence=changed,
        expected_policy=POLICY,
        prior_receipt=signed.receipt,
        now=NOW,
    )
    checked = verify_signed_receipt(
        signed,
        cp,
        verifier,
        verification_result=changed_result,
    )
    assert checked.status is SignedReceiptStatus.INVALID_BINDING
    with pytest.raises(AdapterError):
        emit(cp, signed, verifier, changed)


def test_trace_reference_binds_exact_signed_receipt() -> None:
    cp = checkpoint()
    current = {"e1": snapshot()}
    _, signed, verifier = signed_current_allow(cp, current)
    record = emit(cp, signed, verifier, current)
    assert record["references"][0]["digest"] == signed_receipt_reference_digest(signed)


def test_trace_record_signature_verifies_with_explicit_signing_key() -> None:
    cp = checkpoint()
    current = {"e1": snapshot()}
    _, signed, verifier = signed_current_allow(cp, current)
    trace_key = generate_key()
    record = emit(cp, signed, verifier, current, trace_key=trace_key)
    checked = agentrust_trace.verify_record(
        record,
        public_key_or_jwk=trace_key.public_key(),
        now=ISSUED_AT,
    )
    assert checked.profile == "tag:agentrust-io.com,2026:trace-v0.2"
    assert checked.trusted_key_thumbprint
