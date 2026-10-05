"""Synthetic released-package EvidenceBound -> TRACE reproduction fixture."""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from agentrust_trace import generate_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from evidencebound import (
    Checkpoint,
    EvidenceRecord,
    KeyState,
    PolicyBinding,
    ProvenanceRecord,
    sign_receipt,
    verify_checkpoint,
)
from evidencebound.providers.ed25519 import (
    Ed25519Signer,
    Ed25519VerificationKey,
    Ed25519Verifier,
)

from evidencebound_trace import AdapterError, TraceContext, emit_trace_record

NOW = datetime(2026, 10, 5, 8, 0, tzinfo=timezone.utc)
POLICY = PolicyBinding("policy.synthetic.transfer", "1")
PROVENANCE = ProvenanceRecord("synthetic-fixture", "urn:fixture:evidence:1")


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def fixture():
    evidence = EvidenceRecord(
        "e1",
        {"approved": True, "amount": 100},
        PROVENANCE,
        valid_until="2026-10-06T00:00:00Z",
    )
    checkpoint = Checkpoint(
        "cp-agentrust-1",
        "synthetic-agent",
        (evidence,),
        {"decision": "eligible"},
        POLICY,
    )
    current = {"e1": evidence}
    result = verify_checkpoint(
        checkpoint,
        current_evidence=current,
        expected_policy=POLICY,
        now=NOW,
    )
    private = Ed25519PrivateKey.generate()
    signed = sign_receipt(result.receipt, Ed25519Signer(private, "eb-active"))
    verifier = Ed25519Verifier(
        {"eb-active": Ed25519VerificationKey(private.public_key(), KeyState.ACTIVE)}
    )
    trace_context = TraceContext(
        subject="spiffe://example.test/agent/evidencebound-demo",
        model_provider="synthetic",
        model_id="synthetic-model-v1",
        data_class="internal",
        runtime_measurement=digest("synthetic-runtime"),
        build_digest=digest("evidencebound-trace-adapter-fixture"),
        appraisal_verifier="https://evidencebound.org",
        evidence_resolver="EvidenceBound",
    )
    return checkpoint, current, signed, verifier, trace_context


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    checkpoint, current, signed, verifier, trace_context = fixture()
    trace = emit_trace_record(
        checkpoint=checkpoint,
        signed_receipt=signed,
        evidencebound_verifier=verifier,
        current_evidence=current,
        expected_policy=POLICY,
        verification_time=NOW,
        context=trace_context,
        trace_signing_key=generate_key(),
    )
    Path(args.out).write_text(
        json.dumps(trace, sort_keys=True, indent=2),
        encoding="utf-8",
    )
    print("POSITIVE=TRACE_EMITTED")

    stale = {"e1": replace(current["e1"], valid_until="2026-10-04T00:00:00Z")}
    try:
        emit_trace_record(
            checkpoint=checkpoint,
            signed_receipt=signed,
            evidencebound_verifier=verifier,
            current_evidence=stale,
            expected_policy=POLICY,
            verification_time=NOW,
            context=trace_context,
            trace_signing_key=generate_key(),
        )
    except AdapterError:
        print("NEGATIVE_STALE=REFUSED")
    else:
        raise SystemExit("negative control failed: stale EvidenceBound state emitted TRACE")


if __name__ == "__main__":
    main()
