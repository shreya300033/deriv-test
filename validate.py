"""
Offline validator for the SDK changelog pipeline artifacts.

Usage:
    python validate.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pipeline import (
    ALLOWED_BREAKING_RISK_LEVELS,
    ALLOWED_CHANGE_TYPES,
    SOURCES_PATH,
    Stage,
)

ROOT = Path(__file__).resolve().parent
PARSED_DIR = ROOT / "parsed_changelogs"
CLASSIFIED_DIR = ROOT / "classified_changes"
OUTPUT_DIR = ROOT / "pipeline_output"
MIGRATION_GUIDES_MD = OUTPUT_DIR / "migration_guides.md"
MIGRATION_VALIDATION_JSON = OUTPUT_DIR / "migration_validation.json"
IMPACT_REPORT_MD = OUTPUT_DIR / "impact_report.md"
LLM_CALLS_JSONL = ROOT / "llm_calls.jsonl"

REQUIRED_IMPACT_SECTIONS = (
    "## Executive Summary",
    "## Breaking Changes by Source",
    "## Codebase Impact",
    "## Migration Guides",
    "## Unaffected Sources",
    "## Security Alerts",
    "## Version Pinning Recommendation",
)

REQUIRED_LLM_CALL_FIELDS = frozenset(
    {
        "stage",
        "source_id",
        "entry_ids",
        "timestamp",
        "provider",
        "model",
        "prompt_hash",
        "input_artifacts",
        "output_artifact",
    }
)


def _load_sources() -> list[dict]:
    if not SOURCES_PATH.is_file():
        return []
    data = json.loads(SOURCES_PATH.read_text(encoding="utf-8"))
    return list(data.get("sources") or [])


def _stage_index(name: str) -> int | None:
    try:
        return int(Stage[name])
    except KeyError:
        return None


def main() -> int:
    errors: list[str] = []
    infos: list[str] = []

    def fail(msg: str) -> None:
        errors.append(msg)

    def ok(msg: str) -> None:
        infos.append(msg)

    # --- 1. Artifact presence ---
    if not PARSED_DIR.is_dir():
        fail(f"Missing or not a directory: {PARSED_DIR}")
    else:
        ok(f"Found directory: {PARSED_DIR}")

    if not CLASSIFIED_DIR.is_dir():
        fail(f"Missing or not a directory: {CLASSIFIED_DIR}")
    else:
        ok(f"Found directory: {CLASSIFIED_DIR}")

    for p, label in (
        (MIGRATION_GUIDES_MD, "migration_guides.md"),
        (MIGRATION_VALIDATION_JSON, "migration_validation.json"),
        (IMPACT_REPORT_MD, "impact_report.md"),
        (LLM_CALLS_JSONL, "llm_calls.jsonl"),
    ):
        if not p.is_file():
            fail(f"Missing required file ({label}): {p}")
        else:
            ok(f"Found file: {p}")

    sources = _load_sources()
    if not sources:
        fail(f"No sources loaded from {SOURCES_PATH} (file missing or empty 'sources').")
    else:
        ok(f"Loaded {len(sources)} source(s) from changelog_sources.json.")

    # --- Per-source parsed + classified files ---
    for src in sources:
        sid = str(src.get("source_id") or "").strip()
        if not sid:
            fail("Source entry missing source_id.")
            continue
        pf = PARSED_DIR / f"{sid}.json"
        if not pf.is_file():
            fail(f"Missing parsed artifact for source {sid!r}: {pf}")
        else:
            try:
                json.loads(pf.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                fail(f"Invalid JSON (parsed): {pf}: {e}")
            else:
                ok(f"Parsed JSON OK: {pf.name}")

        cf = CLASSIFIED_DIR / f"{sid}.json"
        if not cf.is_file():
            fail(f"Missing classification artifact for source {sid!r}: {cf}")
        else:
            try:
                cdata = json.loads(cf.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                fail(f"Invalid JSON (classified): {cf}: {e}")
            else:
                ok(f"Classified JSON OK: {cf.name}")
                rows = cdata.get("classifications")
                if not isinstance(rows, list):
                    fail(f"{cf}: expected top-level 'classifications' list.")
                else:
                    for i, row in enumerate(rows):
                        if not isinstance(row, dict):
                            fail(f"{cf}: classifications[{i}] is not an object.")
                            continue
                        ct = row.get("change_type")
                        br = row.get("breaking_risk")
                        if ct not in ALLOWED_CHANGE_TYPES:
                            fail(f"{cf} entry {row.get('entry_id')!r}: invalid change_type {ct!r}.")
                        if br not in ALLOWED_BREAKING_RISK_LEVELS:
                            fail(f"{cf} entry {row.get('entry_id')!r}: invalid breaking_risk {br!r}.")

    # --- migration_validation.json ---
    if MIGRATION_VALIDATION_JSON.is_file():
        errs_before_mv = len(errors)
        try:
            mv = json.loads(MIGRATION_VALIDATION_JSON.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            fail(f"Invalid JSON: {MIGRATION_VALIDATION_JSON}: {e}")
        else:
            if "valid" not in mv:
                fail(f"{MIGRATION_VALIDATION_JSON}: missing top-level 'valid'.")
            elif not isinstance(mv["valid"], bool):
                fail(f"{MIGRATION_VALIDATION_JSON}: 'valid' must be a boolean.")
            if "validated_functions" not in mv:
                fail(f"{MIGRATION_VALIDATION_JSON}: missing 'validated_functions'.")
            elif not isinstance(mv["validated_functions"], list):
                fail(f"{MIGRATION_VALIDATION_JSON}: 'validated_functions' must be a list.")
            else:
                for j, item in enumerate(mv["validated_functions"]):
                    if not isinstance(item, dict):
                        fail(f"{MIGRATION_VALIDATION_JSON}: validated_functions[{j}] is not an object.")
                        continue
                    for key in ("function_name", "valid_python", "error"):
                        if key not in item:
                            fail(f"{MIGRATION_VALIDATION_JSON}: validated_functions[{j}] missing {key!r}.")
            if len(errors) == errs_before_mv:
                ok("Migration validation schema OK (valid + validated_functions).")

    # --- impact_report.md sections ---
    if IMPACT_REPORT_MD.is_file():
        errs_before_ir = len(errors)
        report_text = IMPACT_REPORT_MD.read_text(encoding="utf-8", errors="replace")
        missing_headings = [h for h in REQUIRED_IMPACT_SECTIONS if h not in report_text]
        for h in missing_headings:
            fail(f"impact_report.md missing required section heading: {h!r}")
        if len(errors) == errs_before_ir:
            ok("impact_report.md contains all required section headings.")

    # --- llm_calls.jsonl ---
    if LLM_CALLS_JSONL.is_file():
        errs_before_llm = len(errors)
        lines = LLM_CALLS_JSONL.read_text(encoding="utf-8", errors="replace").splitlines()
        if not any(ln.strip() for ln in lines):
            fail(f"{LLM_CALLS_JSONL} is empty (expected at least one LLM log line).")
        prev_idx: int | None = None
        for lineno, line in enumerate(lines, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                fail(f"{LLM_CALLS_JSONL} line {lineno}: invalid JSON: {e}")
                continue
            missing = REQUIRED_LLM_CALL_FIELDS - rec.keys()
            if missing:
                fail(f"{LLM_CALLS_JSONL} line {lineno}: missing fields {sorted(missing)}.")
            st = rec.get("stage")
            if not isinstance(st, str):
                fail(f"{LLM_CALLS_JSONL} line {lineno}: 'stage' must be a string.")
            else:
                idx = _stage_index(st)
                if idx is None:
                    fail(f"{LLM_CALLS_JSONL} line {lineno}: unknown stage {st!r}.")
                else:
                    if prev_idx is not None and idx < prev_idx:
                        fail(
                            f"{LLM_CALLS_JSONL} line {lineno}: stage ordering regression "
                            f"({Stage(prev_idx).name} -> {st}); pipeline stages must not move backwards."
                        )
                    prev_idx = idx
            if rec.get("provider") != "groq":
                fail(f"{LLM_CALLS_JSONL} line {lineno}: expected provider 'groq', got {rec.get('provider')!r}.")
            if not isinstance(rec.get("entry_ids"), list):
                fail(f"{LLM_CALLS_JSONL} line {lineno}: 'entry_ids' must be a list.")
            if not isinstance(rec.get("input_artifacts"), list):
                fail(f"{LLM_CALLS_JSONL} line {lineno}: 'input_artifacts' must be a list.")
        if len(errors) == errs_before_llm:
            nrec = sum(1 for ln in lines if ln.strip())
            ok(f"llm_calls.jsonl: {nrec} record(s), fields and stage order OK.")

    # --- Summary output ---
    print()
    for m in infos:
        print(f"  OK  {m}")
    for m in errors:
        print(f"  FAIL  {m}")
    print()

    if errors:
        print(f"Validation failed with {len(errors)} error(s).")
        return 1
    print("Validation passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
