"""
Replayable SDK changelog pipeline: deterministic parsing, Groq classification,
impact analysis, and artifact writes. Stage order is enforced via Stage + _advance.
"""

from __future__ import annotations

import ast
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from enum import IntEnum
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from bs4 import BeautifulSoup, NavigableString, Tag
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

GROQ_MODEL = "llama-3.1-8b-instant"
USER_AGENT = "SDKChangelogPipeline/1.0 (+https://example.local/replay)"
FETCH_TIMEOUT_S = 15
RECENT_DAYS = 90
BODY_MAX_CHARS = 2000
FALLBACK_ENTRY_COUNT = 5

ALLOWED_CHANGE_TYPES = frozenset({"deprecation", "breaking", "enhancement", "bugfix", "security"})
ALLOWED_BREAKING_RISK_LEVELS = frozenset({"critical", "high", "medium", "low", "none"})

_ROOT = Path(__file__).resolve().parent
SOURCES_PATH = _ROOT / "changelog_sources.json"
PARSED_DIR = _ROOT / "parsed_changelogs"
CLASSIFIED_DIR = _ROOT / "classified_changes"
OUTPUT_DIR = _ROOT / "pipeline_output"
CODEBASE_SNIPPET_PATH = _ROOT / "codebase_snippet.py"
LLM_CALLS_JSONL = _ROOT / "llm_calls.jsonl"
ISO_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
HEADER_SPLIT_RE = re.compile(r"^## ", re.MULTILINE)


class Stage(IntEnum):
    INIT = 0
    SOURCES_LOADED = 1
    CHANGELOGS_FETCHED = 2
    ENTRIES_PARSED = 3
    RECENT_ENTRIES_FILTERED = 4
    CHANGES_CLASSIFIED = 5
    HIGH_RISK_STRIPE_CHANGES_SELECTED = 6
    CODEBASE_IMPACT_ANALYSED = 7
    MIGRATION_GUIDES_GENERATED = 8
    MIGRATION_CODE_VALIDATED = 9
    IMPACT_REPORT_WRITTEN = 10
    OPTIONAL_OUTPUTS_GENERATED = 11
    VALIDATION_COMPLETE = 12
    RESULTS_FINALISED = 13


def _utc_today() -> date:
    return datetime.now(timezone.utc).date()


def _default_change_type() -> str:
    return "enhancement"


def _default_breaking_risk() -> str:
    return "medium"


def _normalize_taxonomy(change_type: Any, breaking_risk: Any) -> tuple[str, str]:
    ct = str(change_type).strip().lower() if change_type is not None else _default_change_type()
    br = str(breaking_risk).strip().lower() if breaking_risk is not None else _default_breaking_risk()
    if ct not in ALLOWED_CHANGE_TYPES:
        log.warning("Invalid change_type %r; coercing to %s", change_type, _default_change_type())
        ct = _default_change_type()
    if br not in ALLOWED_BREAKING_RISK_LEVELS:
        log.warning("Invalid breaking_risk %r; coercing to %s", breaking_risk, _default_breaking_risk())
        br = _default_breaking_risk()
    return ct, br


def _coerce_affects_bool(value: Any, *, field_name: str, entry_id: str) -> bool:
    if value is True:
        return True
    if value is False:
        return False
    if isinstance(value, str):
        s = value.strip().lower()
        if s in ("true", "1", "yes", "y"):
            return True
        if s in ("false", "0", "no", "n", ""):
            return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value == 1:
            return True
        if value == 0:
            return False
    log.warning("Invalid %s for entry %s (%r); coercing to False", field_name, entry_id, value)
    return False


def _function_ast_source_fallback(py_source: str, node: ast.AST) -> str:
    lines = py_source.splitlines(keepends=True)
    start = getattr(node, "lineno", 1) - 1
    end_ln = getattr(node, "end_lineno", None)
    if end_ln is None:
        return ""
    return "".join(lines[start:end_ln])


def _extract_functions_from_ast(py_source: str) -> list[dict[str, str]]:
    tree = ast.parse(py_source)
    nodes = sorted(
        (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))),
        key=lambda n: (n.lineno, getattr(n, "col_offset", 0)),
    )
    out: list[dict[str, str]] = []
    for node in nodes:
        seg = ast.get_source_segment(py_source, node)
        if seg is None:
            seg = _function_ast_source_fallback(py_source, node)
        out.append({"function_name": node.name, "source_code": seg})
    return out


def _normalize_related_entry_ids(raw_ids: Any, valid_entry_ids: frozenset[str]) -> list[str]:
    if not isinstance(raw_ids, list):
        return []
    seen: set[str] = set()
    out: list[str] = []
    for x in raw_ids:
        s = str(x).strip()
        if not s:
            continue
        if s not in valid_entry_ids:
            log.warning("related_entry_id %r not in high-risk payload; ignored", x)
            continue
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _normalize_impact_row(item: Any, valid_entry_ids: frozenset[str]) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    fn = str(item.get("function_name") or "").strip()
    if not fn:
        return None
    aff = item.get("affected")
    if aff is True:
        aff_b = True
    elif aff is False:
        aff_b = False
    else:
        log.warning("Invalid affected for function %r (%r); coercing to False", fn, aff)
        aff_b = False
    return {
        "function_name": fn,
        "affected": aff_b,
        "breaking_detail": str(item.get("breaking_detail") or ""),
        "suggested_fix_summary": str(item.get("suggested_fix_summary") or ""),
        "related_entry_ids": _normalize_related_entry_ids(item.get("related_entry_ids"), valid_entry_ids),
    }


def _build_codebase_impact_result(
    raw: dict[str, Any],
    extracted_functions: list[dict[str, str]],
    valid_entry_ids: frozenset[str],
) -> dict[str, Any]:
    items = raw.get("impacts")
    if not isinstance(items, list):
        items = []
    by_fn: dict[str, dict[str, Any]] = {}
    for it in items:
        row = _normalize_impact_row(it, valid_entry_ids)
        if row:
            if row["function_name"] in by_fn:
                log.warning("duplicate impact for function %r; using last", row["function_name"])
            by_fn[row["function_name"]] = row
    impacts: list[dict[str, Any]] = []
    for ex in extracted_functions:
        fn = ex["function_name"]
        if fn in by_fn:
            impacts.append(by_fn[fn])
        else:
            impacts.append(
                {
                    "function_name": fn,
                    "affected": False,
                    "breaking_detail": "",
                    "suggested_fix_summary": "",
                    "related_entry_ids": [],
                }
            )
    return {"impacts": impacts}


def _functions_source_by_name(extracted: list[dict[str, str]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for e in extracted:
        fn = str(e.get("function_name") or "").strip()
        if fn:
            out[fn] = str(e.get("source_code") or "")
    return out


def _migration_guide_llm_schema_instruction() -> str:
    return (
        'Return JSON only: {"before_code": string, "after_code": string, "explanation": string}. '
        "before_code must match the provided before_source byte-for-byte (same text). "
        "explanation must be a single sentence ending with a period. "
        "after_code must be syntactically valid Python 3 when parsed alone with ast.parse; "
        "prefer a complete updated version of the same function (same def line and name) where possible."
    )


def _coerce_migration_llm_response(
    raw: dict[str, Any], *, before_expected: str, function_name: str
) -> tuple[str, str, str]:
    before = str(raw.get("before_code") or "")
    after = str(raw.get("after_code") or "")
    expl = str(raw.get("explanation") or "").strip()
    if before != before_expected:
        log.warning("before_code mismatch for %r; using extracted source", function_name)
        before = before_expected
    if not expl:
        expl = "Update this function for compatibility with the Stripe SDK changes in the changelog."
    if "\n" in expl:
        expl = expl.split("\n", 1)[0].strip()
    if "." in expl:
        expl = expl.split(".", 1)[0].strip() + "."
    else:
        expl = expl.rstrip() + "."
    return before, after, expl


def _python_snippet_parses(code: str) -> bool:
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False


def _ensure_valid_python_after(code: str) -> str:
    c = code.strip()
    if not c:
        log.warning("empty after_code; using minimal valid placeholder")
        return "pass  # TODO: migrate Stripe API usage"
    if _python_snippet_parses(c):
        return c
    log.warning("after_code failed ast.parse; using minimal valid placeholder")
    return "pass  # TODO: migrate Stripe API usage"


def _markdown_migration_section(function_name: str, explanation: str, before: str, after: str) -> str:
    return (
        f"## `{function_name}`\n\n"
        f"{explanation}\n\n"
        "**Before:**\n\n"
        "```python\n"
        f"{before.rstrip()}\n"
        "```\n\n"
        "**After:**\n\n"
        "```python\n"
        f"{after.rstrip()}\n"
        "```\n"
    )


def _extract_after_python_blocks_from_migration_md(md: str) -> list[tuple[str, str]]:
    """For each ``## `name` `` section, return (function_name, after_code) from the **After:** fence."""
    parts = re.split(r"^## `([^`]+)`\s*$", md, flags=re.MULTILINE)
    out: list[tuple[str, str]] = []
    for i in range(1, len(parts), 2):
        fname = parts[i].strip()
        body = parts[i + 1] if i + 1 < len(parts) else ""
        m = re.search(
            r"\*\*After:\*\*\s*\r?\n+```(?:python)?\s*\r?\n(.*?)```",
            body,
            re.DOTALL | re.IGNORECASE,
        )
        if not m:
            out.append((fname, ""))
        else:
            out.append((fname, m.group(1)))
    return out


def _validate_migration_after_blocks(blocks: list[tuple[str, str]]) -> dict[str, Any]:
    validated: list[dict[str, Any]] = []
    for fn, code in blocks:
        c = code.strip()
        if not c:
            validated.append({"function_name": fn, "valid_python": False, "error": "empty After code block"})
            continue
        try:
            ast.parse(c)
            validated.append({"function_name": fn, "valid_python": True, "error": None})
        except SyntaxError as e:
            validated.append({"function_name": fn, "valid_python": False, "error": str(e)})
    all_ok = all(v["valid_python"] for v in validated) if validated else True
    return {"valid": all_ok, "validated_functions": validated}


def _strip_json_fences(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```(?:json)?\s*", "", t, flags=re.IGNORECASE)
        t = re.sub(r"\s*```$", "", t)
    return t.strip()


def _markdown_sections(text: str) -> list[tuple[str, str]]:
    """Deterministic split on ``^## ``; each tuple is (header_line, body)."""
    parts = HEADER_SPLIT_RE.split(text)
    out: list[tuple[str, str]] = []
    for chunk in parts:
        chunk = chunk.strip()
        if not chunk:
            continue
        lines = chunk.splitlines()
        header = lines[0].strip() if lines else ""
        rest = "\n".join(lines[1:]).strip() if len(lines) > 1 else ""
        out.append((header, rest))
    return out


def _html_heading_sections(html: str) -> list[tuple[str, str]]:
    """
    Document-order sections under h1/h2/h3. Body is direct siblings until the next
    heading of any of those levels (same rule as markdown split between headers).
    """
    soup = BeautifulSoup(html, "html.parser")
    heads = soup.find_all(["h1", "h2", "h3"])
    if not heads:
        root_text = soup.get_text("\n", strip=True)
        if not root_text:
            return []
        first, _, rest = root_text.partition("\n")
        first = first.strip()
        body = rest.strip()
        if first:
            return [(first, body)]
        return [("(document)", root_text.strip())]

    out: list[tuple[str, str]] = []
    for h in heads:
        title = h.get_text(" ", strip=True) or "(untitled)"
        pieces: list[str] = []
        for sib in h.next_siblings:
            if isinstance(sib, Tag) and sib.name in ("h1", "h2", "h3"):
                break
            if isinstance(sib, Tag):
                t = sib.get_text("\n", strip=True)
                if t:
                    pieces.append(t)
            elif isinstance(sib, NavigableString):
                t = str(sib).strip()
                if t:
                    pieces.append(t)
        body = "\n".join(pieces).strip()
        out.append((title, body))
    return out


def _normalized_entry(
    *,
    entry_id: str,
    source_id: str,
    source_name: str,
    version_or_date: str,
    change_title: str,
    change_body: str,
) -> dict[str, Any]:
    combined = f"{version_or_date}\n{change_body}" if version_or_date else change_body
    m = ISO_DATE_RE.search(combined)
    published_at: str | None = m.group(0) if m else None
    return {
        "entry_id": entry_id,
        "source_id": source_id,
        "source_name": source_name,
        "version_or_date": version_or_date,
        "published_at": published_at,
        "change_title": change_title,
        "change_body": change_body,
        "change_type_raw": None,
    }


@dataclass
class Pipeline:
    """Ordered changelog pipeline with strict stage transitions."""

    sources_path: Path = field(default_factory=lambda: SOURCES_PATH)
    current_stage: Stage = field(default=Stage.INIT)
    sources: list[dict[str, Any]] = field(default_factory=list)
    raw_bodies: dict[str, str] = field(default_factory=dict)
    parsed_by_source: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    filtered_by_source: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    classified_by_source: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    high_risk_stripe: list[dict[str, Any]] = field(default_factory=list)
    codebase_impact: dict[str, Any] = field(default_factory=dict)
    migration_guides: dict[str, Any] = field(default_factory=dict)
    migration_validation: dict[str, Any] = field(default_factory=dict)
    impact_report_path: Path | None = None
    optional_outputs: dict[str, Any] = field(default_factory=dict)
    final_manifest: dict[str, Any] = field(default_factory=dict)
    _groq: Groq | None = field(default=None, repr=False)

    def _groq_client(self) -> Groq:
        if self._groq is None:
            self._groq = Groq()
        return self._groq

    def _canonical_llm_messages(self, messages: list[dict[str, str]]) -> str:
        return json.dumps(messages, ensure_ascii=True, sort_keys=True, separators=(",", ":"))

    def _llm_prompt_hash(self, messages: list[dict[str, str]]) -> str:
        return hashlib.sha256(self._canonical_llm_messages(messages).encode("utf-8")).hexdigest()

    def _llm_timestamp_utc_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def _append_llm_call_log(
        self,
        *,
        stage: str,
        source_id: str | None,
        entry_ids: list[str],
        messages: list[dict[str, str]],
        input_artifacts: list[str],
        output_artifact: str,
    ) -> None:
        record = {
            "stage": stage,
            "source_id": source_id,
            "entry_ids": entry_ids,
            "timestamp": self._llm_timestamp_utc_iso(),
            "provider": "groq",
            "model": GROQ_MODEL,
            "prompt_hash": self._llm_prompt_hash(messages),
            "input_artifacts": input_artifacts,
            "output_artifact": output_artifact,
        }
        LLM_CALLS_JSONL.parent.mkdir(parents=True, exist_ok=True)
        with LLM_CALLS_JSONL.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n")

    def _impact_related_input_artifacts(self) -> list[str]:
        paths: list[str] = []
        if CODEBASE_SNIPPET_PATH.is_file():
            paths.append(str(CODEBASE_SNIPPET_PATH.resolve()))
        srcs = sorted({str(e.get("source_id")) for e in self.high_risk_stripe if e.get("source_id")})
        paths.extend(str((CLASSIFIED_DIR / f"{s}.json").resolve()) for s in srcs)
        return paths

    def _advance(self, target_stage: Stage) -> None:
        expected = int(self.current_stage) + 1
        if int(target_stage) != expected:
            try:
                legal = Stage(self.current_stage + 1).name
            except ValueError:
                legal = "<none — pipeline complete>"
            raise RuntimeError(
                f"Illegal stage transition: current={self.current_stage.name} ({int(self.current_stage)}), "
                f"target={target_stage.name} ({int(target_stage)}); only advance to {legal} is permitted."
            )
        self.current_stage = target_stage

    def load_sources(self) -> None:
        raw = json.loads(self.sources_path.read_text(encoding="utf-8"))
        self.sources = list(raw.get("sources") or [])
        self._advance(Stage.SOURCES_LOADED)

    def fetch_changelogs(self) -> None:
        for src in self.sources:
            sid = src["source_id"]
            url = src["url"]
            try:
                req = Request(url, headers={"User-Agent": USER_AGENT})
                with urlopen(req, timeout=FETCH_TIMEOUT_S) as resp:
                    self.raw_bodies[sid] = resp.read().decode("utf-8", errors="replace")
            except (HTTPError, URLError, TimeoutError, OSError) as e:
                log.warning("fetch failed for %s (%s): %s", sid, url, e)
                self.raw_bodies[sid] = ""
        self._advance(Stage.CHANGELOGS_FETCHED)

    def parse_entries(self) -> None:
        PARSED_DIR.mkdir(parents=True, exist_ok=True)
        for src in self.sources:
            sid = src["source_id"]
            name = src["name"]
            fmt = str(src.get("format") or "markdown").strip().lower()
            text = self.raw_bodies.get(sid, "")
            if fmt == "html":
                sections = _html_heading_sections(text)
            else:
                sections = _markdown_sections(text)
            entries: list[dict[str, Any]] = []
            for idx, (header, body) in enumerate(sections):
                version_or_date = header
                change_title = header
                change_body = body[:BODY_MAX_CHARS]
                entries.append(
                    _normalized_entry(
                        entry_id=f"{sid}-{idx:03d}",
                        source_id=sid,
                        source_name=name,
                        version_or_date=version_or_date,
                        change_title=change_title,
                        change_body=change_body,
                    )
                )
            self.parsed_by_source[sid] = entries
            out = PARSED_DIR / f"{sid}.json"
            out.write_text(
                json.dumps({"source_id": sid, "source_name": name, "entries": entries}, indent=2),
                encoding="utf-8",
            )
        self._advance(Stage.ENTRIES_PARSED)

    def filter_recent(self) -> None:
        today = _utc_today()
        cutoff = today - timedelta(days=RECENT_DAYS)
        for src in self.sources:
            sid = src["source_id"]
            name = src["name"]
            all_entries = list(self.parsed_by_source.get(sid, []))

            def _entry_date(e: dict[str, Any]) -> date | None:
                pa = e.get("published_at")
                if not pa or not isinstance(pa, str):
                    return None
                try:
                    return date.fromisoformat(pa)
                except ValueError:
                    return None

            recent: list[dict[str, Any]] = []
            for e in all_entries:
                d = _entry_date(e)
                if d is not None and d >= cutoff:
                    recent.append(e)

            chosen = recent
            filter_note = ""
            if not chosen:
                filter_note = "no entries within 90-day window or all published_at null; used first 5 entries"
                chosen = all_entries[:FALLBACK_ENTRY_COUNT]
            if not chosen and not all_entries:
                reason = "no parsed entries after split"
                (PARSED_DIR / f"{sid}_empty.json").write_text(
                    json.dumps({"source_id": sid, "source_name": name, "reason": reason}, indent=2),
                    encoding="utf-8",
                )

            self.filtered_by_source[sid] = chosen
            filt_path = PARSED_DIR / f"{sid}_filtered.json"
            filt_path.write_text(
                json.dumps(
                    {
                        "source_id": sid,
                        "cutoff": cutoff.isoformat(),
                        "today": today.isoformat(),
                        "filter_note": filter_note,
                        "entries": chosen,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        self._advance(Stage.RECENT_ENTRIES_FILTERED)

    def classify_changes(self) -> None:
        CLASSIFIED_DIR.mkdir(parents=True, exist_ok=True)
        client = self._groq_client()
        for src in self.sources:
            sid = src["source_id"]
            entries = self.filtered_by_source.get(sid, [])
            payload = {
                "source_id": sid,
                "source_name": src["name"],
                "entries": [
                    {
                        "entry_id": e["entry_id"],
                        "change_title": e["change_title"],
                        "change_body": e["change_body"],
                        "published_at": e.get("published_at"),
                    }
                    for e in entries
                ],
            }
            system = (
                "You classify changelog entries. Output ONLY valid JSON matching the schema. "
                "Do not invent categories: every change_type must be one of "
                f"{sorted(ALLOWED_CHANGE_TYPES)} and every breaking_risk one of "
                f"{sorted(ALLOWED_BREAKING_RISK_LEVELS)}. "
                "Use boolean values only for affects_auth, affects_billing, affects_data_model."
            )
            user = (
                "Schema: {\"classifications\": [{\"entry_id\": string, \"change_type\": string, "
                "\"breaking_risk\": string, \"affects_auth\": boolean, \"affects_billing\": boolean, "
                "\"affects_data_model\": boolean, \"rationale\": string}]}. "
                "Include one object per input entry_id, in the same order as given. "
                f"Input:\n{json.dumps(payload, indent=2)}"
            )
            messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
            raw = self._groq_chat_json(client, messages)
            items = raw.get("classifications")
            if not isinstance(items, list):
                items = []
            by_id: dict[str, dict[str, Any]] = {}
            for it in items:
                if not isinstance(it, dict):
                    continue
                eid = it.get("entry_id")
                if not isinstance(eid, str):
                    continue
                ct, br = _normalize_taxonomy(it.get("change_type"), it.get("breaking_risk"))
                by_id[eid] = {
                    "entry_id": eid,
                    "change_type": ct,
                    "breaking_risk": br,
                    "affects_auth": _coerce_affects_bool(it.get("affects_auth"), field_name="affects_auth", entry_id=eid),
                    "affects_billing": _coerce_affects_bool(
                        it.get("affects_billing"), field_name="affects_billing", entry_id=eid
                    ),
                    "affects_data_model": _coerce_affects_bool(
                        it.get("affects_data_model"), field_name="affects_data_model", entry_id=eid
                    ),
                    "rationale": str(it.get("rationale") or ""),
                }
            merged: list[dict[str, Any]] = []
            for e in entries:
                eid = e["entry_id"]
                base = dict(e)
                c = by_id.get(eid)
                if c:
                    base.update(
                        {
                            "change_type": c["change_type"],
                            "breaking_risk": c["breaking_risk"],
                            "affects_auth": c["affects_auth"],
                            "affects_billing": c["affects_billing"],
                            "affects_data_model": c["affects_data_model"],
                            "rationale": c["rationale"],
                        }
                    )
                else:
                    ct, br = _normalize_taxonomy(None, None)
                    base.update(
                        {
                            "change_type": ct,
                            "breaking_risk": br,
                            "affects_auth": False,
                            "affects_billing": False,
                            "affects_data_model": False,
                            "rationale": "missing model row; defaulted",
                        }
                    )
                    log.warning("classification missing for %s; defaulted", eid)
                merged.append(base)
            self.classified_by_source[sid] = merged
            out_classified = CLASSIFIED_DIR / f"{sid}.json"
            out_classified.write_text(
                json.dumps({"source_id": sid, "classifications": merged}, indent=2),
                encoding="utf-8",
            )
            self._append_llm_call_log(
                stage=Stage.CHANGES_CLASSIFIED.name,
                source_id=sid,
                entry_ids=[str(e["entry_id"]) for e in entries],
                messages=messages,
                input_artifacts=[str((PARSED_DIR / f"{sid}_filtered.json").resolve())],
                output_artifact=str(out_classified.resolve()),
            )
        self._advance(Stage.CHANGES_CLASSIFIED)

    def _groq_chat_json(self, client: Groq, messages: list[dict[str, str]]) -> dict[str, Any]:
        completion = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=messages,
            response_format={"type": "json_object"},
            temperature=0.2,
        )
        content = completion.choices[0].message.content or "{}"
        content = _strip_json_fences(content)
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            log.warning("Groq returned non-JSON; using empty object")
            return {}

    def select_high_risk_stripe_changes(self) -> None:
        selected: list[dict[str, Any]] = []
        for src in self.sources:
            sid = src["source_id"]
            sname = str(src.get("name") or "").lower()
            is_stripe = "stripe" in sid.lower() or "stripe" in sname
            if not is_stripe:
                continue
            for row in self.classified_by_source.get(sid, []):
                if row.get("breaking_risk") in ("critical", "high"):
                    selected.append(dict(row))
        self.high_risk_stripe = selected
        self._advance(Stage.HIGH_RISK_STRIPE_CHANGES_SELECTED)

    def analyse_codebase_impact(self) -> None:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        impact_path = OUTPUT_DIR / "codebase_impact.json"
        py_src = ""
        if CODEBASE_SNIPPET_PATH.is_file():
            py_src = CODEBASE_SNIPPET_PATH.read_text(encoding="utf-8", errors="replace")
        try:
            extracted = _extract_functions_from_ast(py_src) if py_src.strip() else []
        except SyntaxError as e:
            log.warning("codebase_snippet AST parse failed: %s", e)
            extracted = []

        if not self.high_risk_stripe:
            self.codebase_impact = {
                "impacts": [],
                "explanation": (
                    "No high-risk Stripe-related changelog entries were selected; "
                    "skipping LLM impact analysis. No codebase functions are marked affected."
                ),
            }
            impact_path.write_text(json.dumps(self.codebase_impact, indent=2), encoding="utf-8")
            self._advance(Stage.CODEBASE_IMPACT_ANALYSED)
            return

        valid_ids = frozenset(str(e["entry_id"]) for e in self.high_risk_stripe if e.get("entry_id"))
        payload: dict[str, Any] = {
            "high_risk_stripe_entries": self.high_risk_stripe,
            "extracted_functions": extracted,
        }
        client = self._groq_client()
        system = (
            "You analyse how high-risk Stripe SDK changelog entries may affect the given Python functions. "
            "Use only the provided high_risk_stripe_entries and extracted_functions. "
            "Respond with JSON only matching this schema exactly: "
            '{"impacts": [{"function_name": string, "affected": boolean, "breaking_detail": string, '
            '"suggested_fix_summary": string, "related_entry_ids": array of strings}]}. '
            "Include exactly one object per function in extracted_functions; function_name must match exactly. "
            "related_entry_ids must only use entry_id values present in high_risk_stripe_entries."
        )
        user = json.dumps(payload, indent=2)
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        raw = self._groq_chat_json(client, messages)
        self.codebase_impact = _build_codebase_impact_result(raw, extracted, valid_ids)
        impact_path.write_text(json.dumps(self.codebase_impact, indent=2), encoding="utf-8")
        entry_ids = sorted(valid_ids)
        self._append_llm_call_log(
            stage=Stage.CODEBASE_IMPACT_ANALYSED.name,
            source_id=None,
            entry_ids=entry_ids,
            messages=messages,
            input_artifacts=self._impact_related_input_artifacts(),
            output_artifact=str(impact_path.resolve()),
        )
        self._advance(Stage.CODEBASE_IMPACT_ANALYSED)

    def generate_migration_guides(self) -> None:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        md_path = OUTPUT_DIR / "migration_guides.md"
        py_src = ""
        if CODEBASE_SNIPPET_PATH.is_file():
            py_src = CODEBASE_SNIPPET_PATH.read_text(encoding="utf-8", errors="replace")
        try:
            extracted = _extract_functions_from_ast(py_src) if py_src.strip() else []
        except SyntaxError as e:
            log.warning("codebase_snippet AST parse failed during migration guides: %s", e)
            extracted = []

        ci = self.codebase_impact if isinstance(self.codebase_impact, dict) else {}
        raw_impacts = ci.get("impacts")
        impacts = raw_impacts if isinstance(raw_impacts, list) else []
        by_src = _functions_source_by_name(extracted)
        affected_rows = [x for x in impacts if isinstance(x, dict) and x.get("affected") is True]

        if not affected_rows:
            md_path.write_text(
                "# Migration guides\n\n"
                "_No functions were marked affected in codebase impact analysis; "
                "no migration guides were generated._\n",
                encoding="utf-8",
            )
            self.migration_guides = {"guides": [], "markdown_path": str(md_path.resolve())}
            self._advance(Stage.MIGRATION_GUIDES_GENERATED)
            return

        client = self._groq_client()
        guides: list[dict[str, Any]] = []
        md_parts: list[str] = ["# Migration guides", ""]
        all_hr_ids = sorted({str(e.get("entry_id")) for e in self.high_risk_stripe if e.get("entry_id")})

        for row in sorted(affected_rows, key=lambda r: str(r.get("function_name") or "")):
            fn = str(row.get("function_name") or "").strip()
            if not fn:
                continue
            before_src = by_src.get(fn, "")
            rel = row.get("related_entry_ids")
            rel_ids = frozenset(str(x) for x in rel) if isinstance(rel, list) else frozenset()
            related_entries = [dict(e) for e in self.high_risk_stripe if str(e.get("entry_id", "")) in rel_ids]
            if not related_entries:
                related_entries = list(self.high_risk_stripe)

            payload = {
                "function_name": fn,
                "before_source": before_src,
                "impact": {
                    "breaking_detail": str(row.get("breaking_detail") or ""),
                    "suggested_fix_summary": str(row.get("suggested_fix_summary") or ""),
                },
                "related_changelog_entries": related_entries,
            }
            system = (
                "You write a minimal migration for one Python function affected by Stripe SDK changelog entries. "
                "Use only the JSON payload; do not invent APIs. "
                + _migration_guide_llm_schema_instruction()
            )
            user = json.dumps(payload, indent=2)
            messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
            raw = self._groq_chat_json(client, messages)
            before, after, expl = _coerce_migration_llm_response(raw, before_expected=before_src, function_name=fn)
            after = _ensure_valid_python_after(after)
            log_ids = sorted(rel_ids & frozenset(all_hr_ids)) if rel_ids else []
            if not log_ids:
                log_ids = list(all_hr_ids)
            self._append_llm_call_log(
                stage=Stage.MIGRATION_GUIDES_GENERATED.name,
                source_id=None,
                entry_ids=log_ids,
                messages=messages,
                input_artifacts=self._impact_related_input_artifacts(),
                output_artifact=str(md_path.resolve()),
            )
            md_parts.append(_markdown_migration_section(fn, expl, before, after))
            md_parts.append("")
            primary_eid = log_ids[0] if log_ids else ""
            guides.append(
                {
                    "function_name": fn,
                    "entry_id": primary_eid,
                    "title": f"Migrate `{fn}`",
                    "steps_markdown": expl,
                    "example_code": after,
                    "before_code": before,
                }
            )

        md_path.write_text("\n".join(md_parts).rstrip() + "\n", encoding="utf-8")
        self.migration_guides = {"guides": guides, "markdown_path": str(md_path.resolve())}
        self._advance(Stage.MIGRATION_GUIDES_GENERATED)

    def validate_migration_code(self) -> None:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        md_path = OUTPUT_DIR / "migration_guides.md"
        if md_path.is_file():
            md_text = md_path.read_text(encoding="utf-8", errors="replace")
        else:
            md_text = ""
        blocks = _extract_after_python_blocks_from_migration_md(md_text)
        self.migration_validation = _validate_migration_after_blocks(blocks)
        vpath = OUTPUT_DIR / "migration_validation.json"
        vpath.write_text(json.dumps(self.migration_validation, indent=2), encoding="utf-8")
        self._advance(Stage.MIGRATION_CODE_VALIDATED)

    def write_impact_report(self) -> None:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        path = OUTPUT_DIR / "impact_report.md"
        now = datetime.now(timezone.utc)

        def _src_name(sid: str) -> str:
            for s in self.sources:
                if str(s.get("source_id")) == sid:
                    return str(s.get("name") or sid)
            return sid

        def _esc_cell(val: Any) -> str:
            return str(val if val is not None else "").replace("|", "\\|").replace("\n", " ").strip()[:200]

        source_ids = [str(s["source_id"]) for s in self.sources]
        total_ingested = sum(len(self.parsed_by_source.get(sid, [])) for sid in source_ids)
        recent_count = sum(len(self.filtered_by_source.get(sid, [])) for sid in source_ids)

        high_risk_entry_count = 0
        sources_with_high: set[str] = set()
        for sid in source_ids:
            for r in self.classified_by_source.get(sid, []):
                if r.get("breaking_risk") in ("critical", "high"):
                    high_risk_entry_count += 1
                    sources_with_high.add(sid)

        ci = self.codebase_impact if isinstance(self.codebase_impact, dict) else {}
        raw_impacts = ci.get("impacts")
        impacts_list = raw_impacts if isinstance(raw_impacts, list) else []
        affected_fn_count = sum(
            1 for imp in impacts_list if isinstance(imp, dict) and imp.get("affected") is True
        )

        lines: list[str] = [
            "# SDK changelog impact report",
            "",
            f"**Generated (UTC):** {now.strftime('%Y-%m-%d %H:%M:%S')}Z",
            "",
            "This report aggregates parsed changelogs, classification output, codebase impact analysis, "
            "migration artifacts, and deterministic validation results.",
            "",
            "## Executive Summary",
            "",
            "Key pipeline metrics at the time of report generation:",
            "",
            "| Metric | Count |",
            "| --- | ---: |",
            f"| Total ingested entries (all sources) | {total_ingested} |",
            f"| Recent / filtered entries (post 90-day rule) | {recent_count} |",
            f"| Breaking / high-risk entries (`breaking_risk` critical or high, all sources) | {high_risk_entry_count} |",
            f"| Affected functions (`codebase_impact`, `affected` = true) | {affected_fn_count} |",
            "",
            f"- **Stripe high-risk selection:** {len(self.high_risk_stripe)} entries carried into downstream analysis.",
            f"- **Sources configured:** {len(self.sources)}",
            "",
            "## Breaking Changes by Source",
            "",
        ]

        for src in self.sources:
            sid = str(src.get("source_id") or "")
            name = str(src.get("name") or sid)
            rows = [
                r
                for r in self.classified_by_source.get(sid, [])
                if isinstance(r, dict)
                and (
                    r.get("change_type") == "breaking"
                    or r.get("breaking_risk") in ("critical", "high")
                )
            ]
            lines.append(f"### {_esc_cell(name)} (`{_esc_cell(sid)}`)")
            lines.append("")
            if not rows:
                lines.append("*No breaking-typed or critical/high breaking-risk entries in the filtered window for this source.*")
                lines.append("")
                continue
            lines.append("| Entry ID | Title | Change type | Breaking risk |")
            lines.append("| --- | --- | --- | --- |")
            for r in rows[:50]:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            _esc_cell(r.get("entry_id")),
                            _esc_cell(r.get("change_title")),
                            _esc_cell(r.get("change_type")),
                            _esc_cell(r.get("breaking_risk")),
                        ]
                    )
                    + " |"
                )
            if len(rows) > 50:
                lines.append("")
                lines.append(f"*Showing 50 of {len(rows)} rows for this source.*")
            lines.append("")

        lines.extend(
            [
                "## Codebase Impact",
                "",
            ]
        )
        if not impacts_list:
            lines.append("*No impact rows were produced (empty `impacts` list).*")
        else:
            lines.append("| Function | Affected | Breaking detail | Related entry IDs |")
            lines.append("| --- | --- | --- | --- |")
            for imp in impacts_list:
                if not isinstance(imp, dict):
                    continue
                rel = imp.get("related_entry_ids")
                rel_s = ", ".join(str(x) for x in rel) if isinstance(rel, list) else ""
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            _esc_cell(imp.get("function_name")),
                            _esc_cell(imp.get("affected")),
                            _esc_cell(imp.get("breaking_detail")),
                            _esc_cell(rel_s)[:180],
                        ]
                    )
                    + " |"
                )
        expl = ci.get("explanation")
        if isinstance(expl, str) and expl.strip():
            lines.extend(["", f"> {expl.strip()}", ""])

        lines.extend(
            [
                "## Migration Guides",
                "",
            ]
        )
        mg_path = OUTPUT_DIR / "migration_guides.md"
        lines.append(f"- **Artifact:** `{mg_path.resolve()}`")
        guides = self.migration_guides.get("guides") if isinstance(self.migration_guides, dict) else None
        if isinstance(guides, list) and guides:
            lines.append("")
            lines.append("| Function | Title |")
            lines.append("| --- | --- |")
            for g in guides:
                if not isinstance(g, dict):
                    continue
                lines.append(
                    "| "
                    + " | ".join([_esc_cell(g.get("function_name")), _esc_cell(g.get("title"))])
                    + " |"
                )
        else:
            lines.append("- *No per-function migration guide rows were recorded (see markdown artifact for narrative).*")
        lines.append("")
        mv = self.migration_validation if isinstance(self.migration_validation, dict) else {}
        mv_path = OUTPUT_DIR / "migration_validation.json"
        lines.append(f"- **Validation artifact:** `{mv_path.resolve()}`")
        lines.append(f"- **All \"After\" snippets valid Python (AST):** `{mv.get('valid', False)}`")
        lines.append("")

        lines.extend(
            [
                "## Unaffected Sources",
                "",
                "Sources with **no** classified entries at `breaking_risk` **critical** or **high** in the filtered set:",
                "",
            ]
        )
        unaffected = [s for s in self.sources if str(s.get("source_id")) not in sources_with_high]
        if not unaffected:
            lines.append("*All configured sources have at least one critical/high breaking-risk entry in the filtered window.*")
        else:
            lines.append("| Source | ID |")
            lines.append("| --- | --- |")
            for s in unaffected:
                lines.append(
                    "| "
                    + " | ".join([_esc_cell(s.get("name")), _esc_cell(s.get("source_id"))])
                    + " |"
                )
        lines.append("")

        lines.extend(
            [
                "## Security Alerts",
                "",
            ]
        )
        sec_rows: list[tuple[str, dict[str, Any]]] = []
        for sid in source_ids:
            for r in self.classified_by_source.get(sid, []):
                if isinstance(r, dict) and r.get("change_type") == "security":
                    sec_rows.append((sid, r))
        if not sec_rows:
            lines.append("*No entries classified as `security` in the filtered window.*")
        else:
            lines.append("| Source | Entry ID | Title | Breaking risk |")
            lines.append("| --- | --- | --- | --- |")
            for sid, r in sec_rows[:80]:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            _esc_cell(_src_name(sid)),
                            _esc_cell(r.get("entry_id")),
                            _esc_cell(r.get("change_title")),
                            _esc_cell(r.get("breaking_risk")),
                        ]
                    )
                    + " |"
                )
            if len(sec_rows) > 80:
                lines.append("")
                lines.append(f"*Showing 80 of {len(sec_rows)} security-classified rows.*")
        lines.append("")

        lines.extend(
            [
                "## Version Pinning Recommendation",
                "",
            ]
        )
        if high_risk_entry_count > 0 or len(self.high_risk_stripe) > 0:
            lines.append(
                "Pin Stripe (and related) SDK packages to **known-good minor versions** that you have already "
                "tested against this codebase. Avoid floating semver ranges (`>=`) for those dependencies until "
                "the breaking or high-risk items above are triaged, migration guides are applied, and automated "
                "tests pass. Schedule a deliberate upgrade with a changelog review for each bump."
            )
        else:
            lines.append(
                "No critical/high breaking-risk signals were detected in the filtered changelog window. "
                "Continue routine dependency hygiene: prefer **locked** or **narrow** version ranges in lockfiles, "
                "and re-run this pipeline on a schedule or before major releases."
            )
        lines.append("")

        path.write_text("\n".join(lines), encoding="utf-8")
        self.impact_report_path = path
        self._advance(Stage.IMPACT_REPORT_WRITTEN)

    def generate_optional_outputs(self) -> None:
        opt_dir = OUTPUT_DIR / "optional"
        opt_dir.mkdir(parents=True, exist_ok=True)
        summary = {
            "stage": self.current_stage.name,
            "sources": [s["source_id"] for s in self.sources],
            "high_risk_stripe_count": len(self.high_risk_stripe),
            "artifact_paths": {
                "impact_report": str(self.impact_report_path) if self.impact_report_path else None,
                "parsed_dir": str(PARSED_DIR),
                "classified_dir": str(CLASSIFIED_DIR),
            },
        }
        p = opt_dir / "run_summary.json"
        p.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        self.optional_outputs = {"run_summary": str(p), "summary": summary}
        self._advance(Stage.OPTIONAL_OUTPUTS_GENERATED)

    def complete_validation(self) -> None:
        if not self.impact_report_path or not self.impact_report_path.is_file():
            raise RuntimeError("impact report missing before validation")
        text = self.impact_report_path.read_text(encoding="utf-8")
        if not text.strip():
            raise RuntimeError("impact report is empty")
        self._advance(Stage.VALIDATION_COMPLETE)

    def finalise_results(self) -> None:
        self.final_manifest = {
            "finalised_at": datetime.now(timezone.utc).isoformat(),
            "stage": Stage.RESULTS_FINALISED.name,
            "sources_path": str(self.sources_path.resolve()),
            "optional_outputs": self.optional_outputs,
            "impact_report": str(self.impact_report_path.resolve()) if self.impact_report_path else None,
        }
        out = OUTPUT_DIR / "pipeline_results.json"
        out.write_text(json.dumps(self.final_manifest, indent=2), encoding="utf-8")
        self._advance(Stage.RESULTS_FINALISED)

    def run(self) -> dict[str, Any]:
        """Run all stages in order from INIT to RESULTS_FINALISED."""
        self.load_sources()
        self.fetch_changelogs()
        self.parse_entries()
        self.filter_recent()
        self.classify_changes()
        self.select_high_risk_stripe_changes()
        self.analyse_codebase_impact()
        self.generate_migration_guides()
        self.validate_migration_code()
        self.write_impact_report()
        self.generate_optional_outputs()
        self.complete_validation()
        self.finalise_results()
        return dict(self.final_manifest)


def main() -> None:
    p = Pipeline()
    manifest = p.run()
    log.info("pipeline complete: %s", json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
