# EvidenceBound Core integration with TRACE

This integration re-verifies explicit current EvidenceBound state and signed-receipt binding, then emits a signed TRACE v0.2 record only when the released EvidenceBound verifier returns current `ALLOW` with an ACTIVE verification key.

The acceptance boundary is:

`historical integrity != current applicability`

A previously signed EvidenceBound receipt can remain historically authentic while changed, stale, missing, refuted, or policy-drifted current state is no longer applicable. The adapter therefore re-runs EvidenceBound verification at an explicit verification time before emitting TRACE.

## Released versions reproduced

The acceptance run uses only released EvidenceBound artifacts:

- Python: `3.13.1`
- `evidencebound-core==0.4.0`
- `agentrust-trace==0.11.0`
- `agentrust-trace-tests==0.6.2`

The integration source itself is this directory. EvidenceBound is not installed from GitHub, an editable EvidenceBound checkout, a local wheel, or unreleased source.

## Clean-room reproduction

From the repository root on a machine with Python 3.13.1:

### POSIX shell

```bash
python3 -m venv .venv-evidencebound
. .venv-evidencebound/bin/activate
python -m pip install --upgrade pip==26.2.1
python -m pip install --no-cache-dir \
  "evidencebound-core[crypto]==0.4.0" \
  "agentrust-trace==0.11.0" \
  "agentrust-trace-tests==0.6.2" \
  "pytest==9.1.1"

python - <<'PY'
import importlib.metadata as metadata
import sys

expected = {
    "evidencebound-core": "0.4.0",
    "agentrust-trace": "0.11.0",
    "agentrust-trace-tests": "0.6.2",
}
print("PYTHON=" + sys.version.replace("\n", " "))
for package, version in expected.items():
    actual = metadata.version(package)
    print(f"{package}={actual}")
    assert actual == version

dist = metadata.distribution("evidencebound-core")
assert not any(str(path).endswith("direct_url.json") for path in (dist.files or ()))
print("EVIDENCEBOUND_DIRECT_URL=absent")
PY

python -m pip install --no-deps -e "integrations/evidencebound-core"
python -m pytest integrations/evidencebound-core/tests -q
python integrations/evidencebound-core/examples/emit_record.py \
  --out evidencebound.trace.json

trace-tests report \
  --record evidencebound.trace.json \
  --max-level 2 \
  --json evidencebound-trace-report.json

trace-tests verify \
  --record evidencebound.trace.json \
  --level 0
```

### PowerShell

```powershell
python -m venv .venv-evidencebound
$python = ".\.venv-evidencebound\Scripts\python.exe"
& $python -m pip install --upgrade pip==26.2.1
& $python -m pip install --no-cache-dir `
  "evidencebound-core[crypto]==0.4.0" `
  "agentrust-trace==0.11.0" `
  "agentrust-trace-tests==0.6.2" `
  "pytest==9.1.1"

@'
import importlib.metadata as metadata
import sys

expected = {
    "evidencebound-core": "0.4.0",
    "agentrust-trace": "0.11.0",
    "agentrust-trace-tests": "0.6.2",
}
print("PYTHON=" + sys.version.replace("\n", " "))
for package, version in expected.items():
    actual = metadata.version(package)
    print(f"{package}={actual}")
    assert actual == version

dist = metadata.distribution("evidencebound-core")
assert not any(str(path).endswith("direct_url.json") for path in (dist.files or ()))
print("EVIDENCEBOUND_DIRECT_URL=absent")
'@ | & $python -

& $python -m pip install --no-deps -e "integrations/evidencebound-core"
& $python -m pytest integrations/evidencebound-core/tests -q
& $python integrations/evidencebound-core/examples/emit_record.py `
  --out evidencebound.trace.json

& ".\.venv-evidencebound\Scripts\trace-tests.exe" report `
  --record evidencebound.trace.json `
  --max-level 2 `
  --json evidencebound-trace-report.json

& ".\.venv-evidencebound\Scripts\trace-tests.exe" verify `
  --record evidencebound.trace.json `
  --level 0
```

Expected deterministic integration result:

```text
15 passed
POSITIVE=TRACE_EMITTED
NEGATIVE_STALE=REFUSED
```

The conformance report determines the level rather than assuming one in advance. With the released versions above, the reproduced result is:

```text
Level 0  PASS
Level 1  FAIL
Level 2  FAIL
highest_level_passed = 0
```

Level 1 fails because this integration deliberately declares a software-only runtime and a non-affirming appraisal; the current suite also requires the verifier challenge nonce at Level 1+. Level 2 additionally requires transcript and transparency-anchor evidence that this adapter does not produce.

## What is verified

The deterministic tests cover:

- positive current-state emission;
- changed evidence rejection;
- stale evidence rejection;
- missing evidence rejection;
- explicitly refuted evidence rejection;
- expected-policy drift rejection;
- tampered EvidenceBound signed-receipt rejection;
- unknown EvidenceBound verification-key rejection;
- revoked EvidenceBound verification-key rejection;
- EvidenceBound v0.4.0 retired-key semantics: `VERIFIED_RETIRED_KEY` remains historically verifiable but is refused for fresh TRACE emission;
- EvidenceBound `valid_until` boundary and timezone-equivalent verification instants;
- exact recomputed-result / signed-receipt binding;
- exact signed EvidenceBound envelope digest binding in the TRACE reference;
- TRACE signature verification against the explicit TRACE signing key;
- the current official `agentrust-trace-tests==0.6.2` suite.

At the EvidenceBound v0.4.0 time boundary, evidence is still current when `verification_time == valid_until`; it becomes stale after that instant. Equivalent timezone-aware instants produce the same applicability result. Naive verification times are refused by the adapter.

The emitted TRACE record is a **record-producer, software-only Level 0** record. It sets:

- `runtime.platform: software-only`;
- `policy.enforcement_mode: declared`;
- `appraisal.status: none`;
- `origin.kind: third-party-control-plane`.

The TRACE signature binds the emitted record. The EvidenceBound reference digest binds the exact signed EvidenceBound receipt envelope used for the current verification.

## What this does not claim

This integration does **not** claim:

- TEE or hardware attestation;
- truth of upstream evidence;
- non-bypassability or mandatory mediation of the caller's wider system;
- certification;
- independent appraisal;
- that a historical EvidenceBound signature makes stale or changed evidence currently applicable;
- that caller-supplied model, subject, runtime-measurement, build-digest, or data-class metadata was independently observed by EvidenceBound;
- production safety or guarantees outside the released packages and deterministic fixture exercised here.

A TRACE Level 0 PASS is a conformance result for the emitted record and supplied evidence, not a certification of EvidenceBound or of an entire deployment.

## Files

- `evidencebound_trace.py` — thin current-state verification and TRACE emission adapter.
- `tests/test_evidencebound_trace.py` — deterministic positive, negative-control, binding, key-state, time-boundary, and signature tests.
- `examples/emit_record.py` — synthetic positive fixture plus stale-evidence negative control.
- `integration.yaml` — AgenTrust integration manifest.

The fixture authorities, evidence, policy, subject, model metadata, keys, and outcomes are synthetic.
