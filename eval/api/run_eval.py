"""Run the scan, decide, and redact eval suites against the live API logic."""

from __future__ import annotations

import json
from pathlib import Path

from asr.api.enhanced_pii import install_enhanced_pii
from asr.api.enhanced_scanner import EnhancedScanner
from asr.api.service import decide_tool_use, redact_tool_result

install_enhanced_pii()

EVAL_DIR = Path(__file__).parent


def run_scan_eval() -> dict:
    """Run the scan eval suite."""
    cases = json.loads((EVAL_DIR / "scan_eval.json").read_text())
    scanner = EnhancedScanner()
    passed = 0
    failed = []

    for case in cases:
        inp = case["input"]
        result = scanner.scan(inp["content"], source_type=inp.get("source_type", "text"))
        found_ids = [f.pattern_id for f in result.findings]
        detected = len(found_ids) > 0

        exp = case["expected"]
        exp_detected = exp["detected"]
        exp_ids = exp.get("pattern_ids", [])

        ok = True
        reasons = []

        if detected != exp_detected:
            ok = False
            reasons.append(f"detected={detected}, expected={exp_detected}")

        if exp_detected and exp_ids:
            for eid in exp_ids:
                if eid not in found_ids:
                    ok = False
                    reasons.append(f"missing pattern: {eid}")

        if ok:
            passed += 1
        else:
            failed.append({
                "id": case["id"],
                "scenario": case["scenario"],
                "reasons": reasons,
                "found": found_ids,
                "tags": case.get("tags", []),
            })

    return {"total": len(cases), "passed": passed, "failed": failed}


def run_decide_eval() -> dict:
    """Run the decide eval suite."""
    cases = json.loads((EVAL_DIR / "decide_eval.json").read_text())
    passed = 0
    failed = []

    for case in cases:
        inp = case["input"]
        try:
            result = decide_tool_use(
                tool_name=inp["tool_name"],
                args=inp.get("args", {}),
                capabilities=inp.get("capabilities", []),
                policy=inp.get("policy"),
                policy_preset=inp.get("policy_preset"),
                mode=inp.get("mode"),
                pii_profiles=inp.get("pii_profiles"),
            )
        except Exception as e:
            failed.append({"id": case["id"], "scenario": case["scenario"], "reasons": [f"error: {e}"], "tags": case.get("tags", [])})
            continue

        exp = case["expected"]
        ok = True
        reasons = []

        if "action" in exp and result.get("action") != exp["action"]:
            ok = False
            reasons.append(f"action={result.get('action')}, expected={exp['action']}")

        if "policy_id" in exp and result.get("policy_id") != exp["policy_id"]:
            ok = False
            reasons.append(f"policy_id={result.get('policy_id')}, expected={exp['policy_id']}")

        if "original_action" in exp and result.get("original_action") != exp["original_action"]:
            ok = False
            reasons.append(f"original_action={result.get('original_action')}, expected={exp['original_action']}")

        if "mode" in exp and result.get("mode") != exp["mode"]:
            ok = False
            reasons.append(f"mode={result.get('mode')}, expected={exp['mode']}")

        if "reason_contains" in exp and exp["reason_contains"] not in result.get("reason", ""):
            ok = False
            reasons.append(f"reason={result.get('reason')}, expected to contain={exp['reason_contains']}")

        if ok:
            passed += 1
        else:
            failed.append({
                "id": case["id"],
                "scenario": case["scenario"],
                "reasons": reasons,
                "actual": {k: result.get(k) for k in ["action", "reason", "policy_id", "original_action", "mode"]},
                "tags": case.get("tags", []),
            })

    return {"total": len(cases), "passed": passed, "failed": failed}


def run_redact_eval() -> dict:
    """Run the redact eval suite."""
    cases = json.loads((EVAL_DIR / "redact_eval.json").read_text())
    passed = 0
    failed = []

    for case in cases:
        inp = case["input"]
        try:
            result = redact_tool_result(
                tool_name=inp.get("tool_name", "tool_result"),
                result=inp["result"],
                pii_profiles=inp.get("pii_profiles"),
            )
        except Exception as e:
            failed.append({"id": case["id"], "scenario": case["scenario"], "reasons": [f"error: {e}"], "tags": case.get("tags", [])})
            continue

        exp = case["expected"]
        redacted = result.get("redacted_result", "")
        redacted_str = json.dumps(redacted) if not isinstance(redacted, str) else redacted
        detected = result.get("action") != "allow"

        ok = True
        reasons = []

        if "detected" in exp:
            if detected != exp["detected"]:
                ok = False
                reasons.append(f"detected={detected}, expected={exp['detected']}")

        if "contains" in exp:
            for label in exp["contains"]:
                if label not in redacted_str:
                    ok = False
                    reasons.append(f"missing label: {label} in {redacted_str[:100]}")

        # Confirm the raw sensitive value no longer appears in the output.
        if "absent" in exp:
            for raw_value in exp["absent"]:
                if raw_value in redacted_str:
                    ok = False
                    reasons.append(f"original value still present: {raw_value!r}")

        if "result_type" in exp:
            expected_type = exp["result_type"]
            if expected_type == "dict" and not isinstance(redacted, dict):
                ok = False
                reasons.append(f"type={type(redacted).__name__}, expected=dict")
            elif expected_type == "list" and not isinstance(redacted, list):
                ok = False
                reasons.append(f"type={type(redacted).__name__}, expected=list")

        if ok:
            passed += 1
        else:
            failed.append({
                "id": case["id"],
                "scenario": case["scenario"],
                "reasons": reasons,
                "redacted_preview": redacted_str[:200],
                "tags": case.get("tags", []),
            })

    return {"total": len(cases), "passed": passed, "failed": failed}


if __name__ == "__main__":
    print("=" * 60)
    print("Agent Runtime Security API Eval Set")
    print("=" * 60)

    for name, runner in [("SCAN", run_scan_eval), ("DECIDE", run_decide_eval), ("REDACT", run_redact_eval)]:
        result = runner()
        total = result["total"]
        passed = result["passed"]
        failed_count = len(result["failed"])
        pct = (passed / total * 100) if total else 0

        print(f"\n{'─' * 60}")
        print(f"  {name}: {passed}/{total} passed ({pct:.1f}%)")
        if result["failed"]:
            print(f"  FAILURES ({failed_count}):")
            for f in result["failed"]:
                tags = ", ".join(f.get("tags", []))
                print(f"    [{f['id']}] {f['scenario']}")
                for r in f["reasons"]:
                    print(f"      → {r}")
                if tags:
                    print(f"      tags: {tags}")

    print(f"\n{'=' * 60}")
    scan_r = run_scan_eval()
    decide_r = run_decide_eval()
    redact_r = run_redact_eval()
    total = scan_r["total"] + decide_r["total"] + redact_r["total"]
    passed = scan_r["passed"] + decide_r["passed"] + redact_r["passed"]
    print(f"  TOTAL: {passed}/{total} ({passed/total*100:.1f}%)")
    print("=" * 60)
