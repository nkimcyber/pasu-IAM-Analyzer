"""
cli.py — Command-line interface for the IAM Analyzer.

Usage:
    pasu explain  --file policy.json [--format json|sarif]
    pasu escalate --file policy.json [--format json|sarif]
    pasu scan     --file policy.json [--format json|sarif]
"""

import argparse
import io
import json
import os
import re
import sys
import textwrap

from app.version import get_version
from app.analyzer import (
    HIGH_RISK_ACTIONS,
    MEDIUM_RISK_ACTIONS,
    STRUCTURAL_RULE_COUNT,
    analyze_policy_rules,
    calculate_risk_score,
    escalate_policy,
    escalate_policy_local,
    explain_policy,
    explain_policy_local,
    fix_policy_ai,
    fix_policy_local,
    risk_score_label,
)


def _reconfigure_streams() -> None:
    """Force UTF-8 on stdout/stderr so Unicode characters render on all platforms."""
    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "buffer"):
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ── ANSI color helpers ────────────────────────────────────────────────────────

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_RED    = "\033[31m"
_YELLOW = "\033[33m"
_GREEN  = "\033[32m"
_CYAN   = "\033[36m"
_WHITE  = "\033[97m"


def _supports_color() -> bool:
    """Return True if the terminal supports ANSI color codes."""
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _color(text: str, code: str) -> str:
    if _supports_color():
        return f"{code}{text}{_RESET}"
    return text


def _risk_color(risk_level: str) -> str:
    mapping = {"High": _RED, "Medium": _YELLOW, "Low": _GREEN}
    return mapping.get(risk_level, _WHITE)


def _risk_bar(score: int) -> str:
    """Return a 20-char filled/empty bar colored by risk level, e.g. '████░░░░░░░░░░░░░░░░ 20/100 (Low)'."""
    filled = round(score / 100 * 20)
    empty = 20 - filled
    bar = "\u2588" * filled + "\u2591" * empty
    level = risk_score_label(score)
    color = _risk_color(level)
    return f"{_color(bar, color)} {score}/100 ({level})"

def _highlight_proposed_policy(policy: dict) -> str:
    """Return pretty-printed policy JSON with TODO placeholders and risky wildcard resources highlighted."""
    rendered_policy = json.loads(json.dumps(policy))

    for stmt in rendered_policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue

        resource = stmt.get("Resource")
        if resource == "*":
            stmt["Resource"] = "__PASU_HIGHLIGHT_STAR__"
        elif isinstance(resource, list):
            stmt["Resource"] = [
                "__PASU_HIGHLIGHT_STAR__" if r == "*" else r
                for r in resource
            ]

    rendered = json.dumps(rendered_policy, indent=2)

    if not _supports_color():
        return rendered.replace('"__PASU_HIGHLIGHT_STAR__"', '"*"')

    rendered = rendered.replace(
        '"__PASU_HIGHLIGHT_STAR__"',
        '"' + _color("*", _YELLOW) + '"',
    )

    pattern = r'"(TODO:[^"]+)"'

    def repl(match: re.Match[str]) -> str:
        return '"' + _color(match.group(1), _YELLOW) + '"'

    return re.sub(pattern, repl, rendered)

def _collect_statement_medium_actions(
    policy: dict, risky_actions: set[str]
) -> list[tuple[int, list[str]]]:
    """Return 1-based statement indexes with remaining risky actions."""
    results: list[tuple[int, list[str]]] = []

    for i, stmt in enumerate(policy.get("Statement", []), start=1):
        if stmt.get("Effect") != "Allow":
            continue

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        matched: list[str] = []
        for action in actions:
            if action.lower() in risky_actions:
                matched.append(action)

        if matched:
            results.append((i, matched))

    return results

def _header(title: str) -> str:
    bar = "=" * (len(title) + 4)
    return _color(f"+{bar}+\n|  {title}  |\n+{bar}+", _BOLD)


def _section(label: str) -> str:
    return _color(f"\n{label}", _BOLD + _CYAN)


# ── Banner ────────────────────────────────────────────────────────────────────

def _print_banner() -> None:
    if not _supports_color():
        return

    version = get_version()

    C = "\033[36m"   # cyan   — gate structure
    B = "\033[1m"    # bold   — PASU name
    R = "\033[0m"    # reset
    Y = "\033[33m"   # yellow — tagline
    D = "\033[2m"    # dim    — version

    gate = [
        f"{C}============================{R}",
        f"{C}||        {R}{B}P A S U{R}{C}         ||{R}",
        f"{C}||                        ||{R}",
        f"{C}||======+          +======||{R}",
        f"{C}||      |          |      ||{R}",
        f"{C}||      |          |      ||{R}",
        f"{C}============================{R}",
    ]

    print()
    for line in gate:
        print(line)
    print(f"  {D}pasu v{version}{R}  {Y}Cloud IAM Security Guard{R}")


# ── File loading ──────────────────────────────────────────────────────────────

def _load_policy(path: str) -> str:
    """Load and validate policy JSON from disk.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is not valid JSON.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            content = fh.read()
        json.loads(content)
        return content
    except FileNotFoundError:
        raise FileNotFoundError(f"file not found: {path}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"file is not valid JSON: {exc}")


# ── Error handling ─────────────────────────────────────────────────────────────

def _handle_error(message: str, use_json: bool) -> None:
    """Print an error and exit with code 1.

    JSON mode: writes {"error": ..., "status": "error"} to stdout.
    Text mode: writes a red error message to stderr.
    """
    if use_json:
        print(json.dumps({"error": message, "status": "error"}, indent=2))
    else:
        print(_color(f"Error: {message}", _RED), file=sys.stderr)
    sys.exit(1)


# ── API key guard ─────────────────────────────────────────────────────────────

def _require_api_key(use_json: bool = False) -> None:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        _handle_error(
            "ANTHROPIC_API_KEY environment variable is required for AI analysis. "
            "Run without --ai for local-only analysis.",
            use_json,
        )


# ── Text output formatters ────────────────────────────────────────────────────

def _print_explain(result) -> None:
    print(_header("IAM Policy Explanation"))
    print(_section("Summary"))
    print(f"  {result.summary}")
    print(_section("Details"))
    for item in result.details:
        print(f"  • {item}")


def _extract_wildcard_actions(policy_json: str) -> list[str]:
    """Return wildcard action patterns from Allow statements (e.g. '*', 'iam:*', 's3:*').

    These patterns have unknown scope and belong in the Needs Review section,
    not in confirmed risky findings.
    """
    try:
        parsed = json.loads(policy_json)
    except Exception:
        return []
    seen: set[str] = set()
    wildcards: list[str] = []
    for stmt in parsed.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            lower = action.lower()
            if "*" in lower and lower not in seen:
                seen.add(lower)
                wildcards.append(action)
    return sorted(wildcards)


def _print_escalate(result, policy_json: str | None = None) -> None:
    risk_code = _risk_color(result.risk_level)
    print(_header("Privilege Escalation Report"))
    risk_label = _color(result.risk_level, _BOLD + risk_code)
    print(_section("Risk Level") + f"  {risk_label}")
    print(_section("Risk Score") + f"  {_risk_bar(result.risk_score)}")
    print(_section("Summary"))
    print(f"  {result.summary}")

    # Segment detected actions by evidence quality.
    # HIGH_RISK_ACTIONS are reviewed and confirmed dangerous → Confirmed Risky Actions.
    # MEDIUM_RISK_ACTIONS are context-dependent → Needs Review.
    high_lower: set[str] = {a.lower() for a in HIGH_RISK_ACTIONS}
    confirmed = [a for a in result.detected_actions if a.lower() in high_lower]
    needs_review_detected = [
        a for a in result.detected_actions if a.lower() not in high_lower
    ]

    # Wildcard patterns from the raw policy have unknown scope → Needs Review.
    wildcard_actions: list[str] = (
        _extract_wildcard_actions(policy_json) if policy_json else []
    )

    if confirmed:
        print(_section("Confirmed Risky Actions"))
        print("  Reviewed classification — confirmed dangerous by security research:")
        for action in confirmed:
            print(f"  • {_color(action, risk_code)}")

    # Unknown/unclassified actions are shown separately so users cannot
    # mistake them for either safe or confirmed-risky.
    unknown_actions: list[str] = getattr(result, "unknown_actions", [])

    if needs_review_detected or wildcard_actions or unknown_actions:
        print(_section("Needs Review"))
        print("  Not confirmed risky — unclassified or context-dependent:")
        for action in needs_review_detected:
            print(f"  • {_color(action, _YELLOW)}  [reviewed: medium-risk — context-dependent]")
        for action in wildcard_actions:
            print(f"  • {_color(action, _YELLOW)}  [catalog: wildcard scope — actions not individually risk-assessed]")
        for action in unknown_actions:
            print(
                f"  • {_color(action, _YELLOW)}  "
                "[unclassified: absent from all reviewed risk categories — "
                "added to review_queue.json for triage]"
            )

    composite_findings: list[dict] = getattr(result, "composite_findings", [])
    if composite_findings:
        _SEV_COLOR = {
            "critical": _RED,
            "high": _RED,
            "medium": _YELLOW,
            "low": _GREEN,
        }
        # All field labels align to _COL characters so values start in one column.
        # "    Permissions:  " = 4 indent + 12 label + 1 colon + 1 space = 18 chars
        _COL = 18

        def _field(label: str, value: str) -> str:
            prefix = f"    {label}:"
            return f"{prefix}{' ' * (_COL - len(prefix))}{value}"

        _indent = " " * _COL

        print(_section("High-Risk Permission Patterns"))
        for f in composite_findings:
            sev = f.get("severity", "")
            sev_code = _SEV_COLOR.get(sev, _WHITE)
            rule_label = _color(f"{f['rule_id']}  {f['title']}", _BOLD + sev_code)
            n_required = len(f.get("matched_required", []))
            pattern_type = (
                "Risky in combination" if n_required >= 2
                else "High-risk on its own"
            )
            print(f"\n  {rule_label}")
            print(f"  {pattern_type}")
            print(_field("Risk", sev.upper()))
            print(_field("Confidence", f["confidence"]))
            print(_field("Permissions", ", ".join(f["contributing_actions"])))
            rationale = f.get("rationale", "")
            if rationale:
                wrapped = textwrap.wrap(rationale, width=88 - _COL)
                print(_field("Why", wrapped[0]))
                for line in wrapped[1:]:
                    print(f"{_indent}{line}")
            if f.get("confidence_explanation"):
                print(_field("Evidence", f["confidence_explanation"]))

    if result.findings:
        print(_section("Findings"))
        for i, finding in enumerate(result.findings, 1):
            print(f"\n  [{i}] {_color(finding.action, _BOLD + risk_code)}")
            print(f"      Explanation:      {finding.explanation}")
            print(f"      Escalation path:  {finding.escalation_path}")


def _print_scan(explain_result, escalate_result, policy_json: str | None = None) -> None:
    _print_explain(explain_result)
    print()
    _print_escalate(escalate_result, policy_json=policy_json)


# ── JSON output formatters ────────────────────────────────────────────────────

def _explain_to_json(result) -> dict:
    return {
        "summary": result.summary,
        "details": result.details,
        "status": "success",
    }


def _escalate_to_json(result, rule_findings) -> dict:
    return {
        "risk_level": result.risk_level,
        "risk_score": result.risk_score,
        "detected_actions": result.detected_actions,
        "unknown_actions": getattr(result, "unknown_actions", []),
        "composite_findings": getattr(result, "composite_findings", []),
        "findings": [f.model_dump() for f in result.findings],
        "rule_findings": [f.model_dump() for f in rule_findings],
        "summary": result.summary,
        "status": "success",
    }


def _scan_to_json(explain_result, escalate_result, rule_findings) -> dict:
    return {
        "explain": _explain_to_json(explain_result),
        "escalate": _escalate_to_json(escalate_result, rule_findings),
        "status": "success",
    }


# ── SARIF output formatters ───────────────────────────────────────────────────

def _pascal(text: str) -> str:
    """Convert a phrase to PascalCase: 'Unrestricted resource access' → 'UnrestrictedResourceAccess'."""
    return "".join(w.capitalize() for w in re.split(r"\W+", text) if w)


def _build_sarif(policy_path: str, rule_findings, escalate_result) -> dict:
    """Build a SARIF 2.1.0 document from pasu findings.

    Args:
        policy_path: Path to the policy file (used as artifact URI).
        rule_findings: List of RuleFinding from analyze_policy_rules().
        escalate_result: EscalationResult (may be None for explain-only runs).

    Returns:
        SARIF 2.1.0 dict ready for json.dumps().
    """
    version = get_version()

    _SEV = {"high": "error", "medium": "warning", "low": "note"}

    rules_dict: dict[str, dict] = {}  # rule_id → SARIF rule entry (deduped)
    results: list[dict] = []

    # ── Rule-engine findings (R001–R007) ──────────────────────────────────────
    for finding in rule_findings:
        if finding.rule_id not in rules_dict:
            rules_dict[finding.rule_id] = {
                "id": finding.rule_id,
                "name": _pascal(finding.title),
                "shortDescription": {"text": finding.title},
                "helpUri": "https://pypi.org/project/pasu/",
            }
        results.append({
            "ruleId": finding.rule_id,
            "level": _SEV.get(finding.severity, "note"),
            "message": {"text": finding.description},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": policy_path}}}],
        })

    # ── Detected risky actions (from escalate) ────────────────────────────────
    if escalate_result:
        for action in escalate_result.detected_actions:
            al = action.lower()
            rule_id = "PASU-" + al.replace(":", "-").replace("*", "wildcard").upper()
            level = "error" if al in HIGH_RISK_ACTIONS else "warning"
            if rule_id not in rules_dict:
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": _pascal(f"RiskyAction {action}"),
                    "shortDescription": {"text": f"Risky IAM action: {action}"},
                    "helpUri": "https://pypi.org/project/pasu/",
                }
            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"Policy grants the risky action '{action}'."},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": policy_path}}}],
            })

    run_properties: dict = {}
    if escalate_result is not None:
        run_properties["risk_score"] = escalate_result.risk_score

    run: dict = {
        "tool": {
            "driver": {
                "name": "pasu",
                "version": version,
                "informationUri": "https://pypi.org/project/pasu/",
                "rules": list(rules_dict.values()),
            }
        },
        "results": results,
    }
    if run_properties:
        run["properties"] = run_properties

    return {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
            "sarif-2.1/schema/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [run],
    }


# ── Command handlers ──────────────────────────────────────────────────────────

def cmd_explain(args: argparse.Namespace) -> None:
    use_machine = args.format != "text"  # json or sarif → machine-readable errors
    try:
        policy_json = _load_policy(args.file)
    except (FileNotFoundError, ValueError) as exc:
        _handle_error(str(exc), use_machine)
        return

    try:
        if args.ai:
            _require_api_key(use_machine)
            result = explain_policy(policy_json=policy_json)
        else:
            result = explain_policy_local(policy_json=policy_json)
    except ValueError as exc:
        _handle_error(f"Validation error: {exc}", use_machine)
        return
    except RuntimeError as exc:
        _handle_error(str(exc), use_machine)
        return

    if args.format == "json":
        print(json.dumps(_explain_to_json(result), indent=2))
    elif args.format == "sarif":
        # explain produces no security findings; emit a valid empty-results SARIF
        print(json.dumps(_build_sarif(args.file, [], None), indent=2))
    else:
        _print_explain(result)


def cmd_escalate(args: argparse.Namespace) -> None:
    use_machine = args.format != "text"
    try:
        policy_json = _load_policy(args.file)
    except (FileNotFoundError, ValueError) as exc:
        _handle_error(str(exc), use_machine)
        return

    try:
        if args.ai:
            _require_api_key(use_machine)
            result = escalate_policy(policy_json=policy_json)
        else:
            result = escalate_policy_local(policy_json=policy_json)

        result.risk_level = risk_score_label(result.risk_score)

        need_findings = args.format in ("json", "sarif")
        rule_findings = analyze_policy_rules(policy_json) if need_findings else []
    except ValueError as exc:
        _handle_error(f"Validation error: {exc}", use_machine)
        return
    except RuntimeError as exc:
        _handle_error(str(exc), use_machine)
        return

    if args.format == "json":
        print(json.dumps(_escalate_to_json(result, rule_findings), indent=2))
    elif args.format == "sarif":
        print(json.dumps(_build_sarif(args.file, rule_findings, result), indent=2))
    else:
        _print_escalate(result, policy_json=policy_json)


def cmd_scan(args: argparse.Namespace) -> None:
    use_machine = args.format != "text"
    try:
        policy_json = _load_policy(args.file)
    except (FileNotFoundError, ValueError) as exc:
        _handle_error(str(exc), use_machine)
        return

    try:
        explain_result = explain_policy_local(policy_json=policy_json)
        escalate_result = escalate_policy_local(policy_json=policy_json)

        escalate_result.risk_level = risk_score_label(escalate_result.risk_score)
        
        need_findings = args.format in ("json", "sarif")
        rule_findings = analyze_policy_rules(policy_json) if need_findings else []
        
    except ValueError as exc:
        _handle_error(f"Validation error: {exc}", use_machine)
        return
    except RuntimeError as exc:
        _handle_error(str(exc), use_machine)
        return

    if args.format == "json":
        print(json.dumps(_scan_to_json(explain_result, escalate_result, rule_findings), indent=2))
    elif args.format == "sarif":
        print(json.dumps(_build_sarif(args.file, rule_findings, escalate_result), indent=2))
    else:
        _print_scan(explain_result, escalate_result, policy_json=policy_json)


# ── Fix formatters and handler ────────────────────────────────────────────────

def _fix_to_json(result) -> dict:
    data: dict = {
        "original_risk_level": result.original_risk_level,
        "fixed_risk_level": result.fixed_risk_level,
        "fixed_policy": result.fixed_policy,
        "changes": [
            c.model_dump(by_alias=True, exclude_none=True) for c in result.changes
        ],
        "manual_review_needed": result.manual_review_needed,
        "status": result.status,
        "ai_generated": result.ai_generated,
    }
    if result.ai_generated:
        data["ai_explanation"] = result.ai_explanation
        data["ai_disclaimer"] = result.ai_disclaimer
    return data


def _print_fix(result, output_path: str | None, original_score: int, fixed_score: int) -> None:
    orig_code = _risk_color(result.original_risk_level)
    fixed_code = _risk_color(result.fixed_risk_level)
    header_title = "IAM Policy Fix Report  (AI Mode)" if result.ai_generated else "IAM Policy Fix Report"
    print(_header(header_title))
    print(
        _section("Risk Level")
        + f"  {_color(result.original_risk_level, _BOLD + orig_code)}"
        + f"  →  {_color(result.fixed_risk_level, _BOLD + fixed_code)}"
    )
    print(
        _section("Risk Score")
        + f"  {_risk_bar(original_score)}  →  {_risk_bar(fixed_score)}"
    )

    if result.ai_generated and result.ai_disclaimer:
        print(_section("AI Notice"))
        print(f"  {_color(result.ai_disclaimer, _CYAN)}")

    if result.changes:
        print(_section("Changes Applied"))

        # Group changes by statement index so the user sees one block per statement.
        from collections import defaultdict
        by_stmt: dict[int, list] = defaultdict(list)
        for change in result.changes:
            by_stmt[change.statement_index].append(change)

        resource_wildcard_statement_indexes: list[int] = []
        resource_wildcard_reason: str | None = None

        stmts = result.fixed_policy.get("Statement", [])
        for stmt_idx in sorted(by_stmt):
            # Build a label: "Statement N (SID)" or just "Statement N"
            sid: str | None = None
            if 0 <= stmt_idx < len(stmts):
                sid = stmts[stmt_idx].get("Sid")
            stmt_label = f"Statement {stmt_idx + 1}" + (f" ({sid})" if sid else "")
            print(f"\n  {_color(stmt_label, _BOLD)}")

            for change in by_stmt[stmt_idx]:
                if change.type == "removed_action":
                    print(f"    • Removed {_color(change.action or '', _RED)}: {change.reason}")
                elif change.type in ("scoped_wildcard", "replaced_wildcard"):
                    from_str = _color(change.from_ or "", _YELLOW)
                    to_str = _color(", ".join(change.to or []), _GREEN)
                    print(f"    • {from_str}  →  {to_str}")
                    print(f"        {change.reason}")
                elif change.type == "resource_wildcard_warning":
                    resource_wildcard_statement_indexes.append(change.statement_index)
                    if resource_wildcard_reason is None:
                        resource_wildcard_reason = change.reason or ""

        if resource_wildcard_statement_indexes and resource_wildcard_reason is not None:
            one_based = sorted(set(i + 1 for i in resource_wildcard_statement_indexes))
            stmt_str = ", ".join(str(i) for i in one_based)
            print(
                f"\n  • {_color('WARNING', _YELLOW)}: "
                f"{resource_wildcard_reason} (Statements: {stmt_str})"
            )

        resource_context_note_indexes = sorted(
            set(i + 1 for i in resource_wildcard_statement_indexes)
        )
        if resource_context_note_indexes:
            joined = ", ".join(str(i) for i in resource_context_note_indexes)
            print(
                f"  • {_color('NOTE', _CYAN)}: Wildcard resource remains in Statements {joined} "
                "because PASU cannot safely narrow resources without specific ARN context."
            )

        remaining_medium_actions = _collect_statement_medium_actions(
            result.fixed_policy,
            MEDIUM_RISK_ACTIONS,
        )
        if remaining_medium_actions:
            print(
                f"  • {_color('NOTE', _CYAN)}: Reviewed medium-risk actions remain "
                "(not auto-removed — risk is context-dependent):"
            )
            for statement_index, actions in remaining_medium_actions:
                joined_actions = ", ".join(actions)
                print(f"      • Statement {statement_index}: {joined_actions}")

    if result.manual_review_needed:
        print(_section("Manual Review Required"))
        for note in result.manual_review_needed:
            print(f"  • {_color(note, _YELLOW)}")

    if result.ai_generated and result.ai_explanation:
        print(_section("AI Analysis"))
        print(f"  {result.ai_explanation}")

    print(_section("Proposed Policy"))
    print(_highlight_proposed_policy(result.fixed_policy))

    if output_path:
        print(_section("Saved"))
        print(f"  Fixed policy written to: {output_path}")

def cmd_fix(args: argparse.Namespace) -> None:
    """Fix IAM policies by removing dangerous permissions.

    Modes:
    - Local mode (default): Uses hardcoded SAFE_ALTERNATIVES mapping
    - AI mode (--ai): Uses Claude to infer policy intent and generate least-privilege policy
    """
    use_ai = getattr(args, "ai", False)
    use_machine = args.format != "text"

    if use_ai:
        _require_api_key(use_machine)

    try:
        policy_json = _load_policy(args.file)
    except (FileNotFoundError, ValueError) as exc:
        _handle_error(str(exc), use_machine)
        return

    try:
        result = fix_policy_local(policy_json=policy_json)
        if use_ai:
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            result = fix_policy_ai(policy_json=policy_json, local_result=result, api_key=api_key)
    except (ValueError, RuntimeError) as exc:
        _handle_error(f"Fix failed: {exc}", use_machine)
        return

    original_score = calculate_risk_score(policy_json)
    fixed_policy_json = json.dumps(result.fixed_policy)
    fixed_score = calculate_risk_score(fixed_policy_json)

    result.original_risk_level = risk_score_label(original_score)
    result.fixed_risk_level = risk_score_label(fixed_score)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(result.fixed_policy, indent=2))
        except OSError as exc:
            _handle_error(f"Cannot write output file: {exc}", use_machine)
            return

    if args.format == "json":
        fix_data = _fix_to_json(result)
        fix_data["original_risk_score"] = original_score
        fix_data["fixed_risk_score"] = fixed_score
        print(json.dumps(fix_data, indent=2))
    else:
        _print_fix(result, args.output, original_score, fixed_score)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    _reconfigure_streams()
    parser = argparse.ArgumentParser(
        prog="pasu",
        description="Analyze AWS IAM policies for security risks using Claude AI.",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        default=False,
        help="Suppress the banner.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    subparsers.required = True

    _ai_kwargs = dict(
        action="store_true",
        default=False,
        help="Use Claude AI for analysis (requires ANTHROPIC_API_KEY).",
    )
    _format_kwargs = dict(
        choices=["text", "json", "sarif"],
        default="text",
        metavar="FORMAT",
        help="Output format: 'text' (default), 'json', or 'sarif' (SARIF v2.1.0 for GitHub Code Scanning).",
    )

    # explain
    p_explain = subparsers.add_parser(
        "explain",
        help="Explain a policy in plain English.",
    )
    p_explain.add_argument("--file", required=True, metavar="FILE",
                           help="Path to the IAM policy JSON file.")
    p_explain.add_argument("--ai", **_ai_kwargs)
    p_explain.add_argument("--format", **_format_kwargs)
    p_explain.set_defaults(func=cmd_explain)

    # escalate
    p_escalate = subparsers.add_parser(
        "escalate",
        help="Detect privilege escalation risks in a policy.",
    )
    p_escalate.add_argument("--file", required=True, metavar="FILE",
                            help="Path to the IAM policy JSON file.")
    p_escalate.add_argument("--ai", **_ai_kwargs)
    p_escalate.add_argument("--format", **_format_kwargs)
    p_escalate.set_defaults(func=cmd_escalate)

    # scan
    p_scan = subparsers.add_parser(
        "scan",
        help="Run both explain and escalate and show a combined report.",
    )
    p_scan.add_argument("--file", required=True, metavar="FILE",
                        help="Path to the IAM policy JSON file.")
    p_scan.add_argument("--format", **_format_kwargs)
    p_scan.set_defaults(func=cmd_scan)

    # fix
    p_fix = subparsers.add_parser(
        "fix",
        help="Generate a least-privilege replacement for a dangerous policy.",
    )
    p_fix.add_argument("--file", required=True, metavar="FILE",
                       help="Path to the IAM policy JSON file.")
    p_fix.add_argument("--ai", **_ai_kwargs)
    p_fix.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        metavar="FORMAT",
        help="Output format: 'text' (default) or 'json'.",
    )
    p_fix.add_argument(
        "--output", "-o",
        default=None,
        metavar="FILE",
        help="Write the fixed policy JSON to this file.",
    )
    p_fix.set_defaults(func=cmd_fix)

    args = parser.parse_args()
    # Banner is suppressed for machine-readable formats and when -q/--quiet is set
    if not args.quiet and getattr(args, "format", "text") == "text":
        _print_banner()
    args.func(args)


if __name__ == "__main__":
    main()
