"""
cli.py — Command-line interface for the IAM Analyzer.

Usage:
    pasu explain  --file policy.json [--format json]
    pasu escalate --file policy.json [--format json]
    pasu scan     --file policy.json [--format json]
"""

import argparse
import importlib.metadata
import io
import json
import os
import sys

from app.analyzer import (
    HIGH_RISK_ACTIONS,
    MEDIUM_RISK_ACTIONS,
    STRUCTURAL_RULE_COUNT,
    analyze_policy_rules,
    escalate_policy,
    escalate_policy_local,
    explain_policy,
    explain_policy_local,
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


def _header(title: str) -> str:
    bar = "=" * (len(title) + 4)
    return _color(f"+{bar}+\n|  {title}  |\n+{bar}+", _BOLD)


def _section(label: str) -> str:
    return _color(f"\n{label}", _BOLD + _CYAN)


# ── Banner ────────────────────────────────────────────────────────────────────

def _print_banner() -> None:
    if not _supports_color():
        return

    try:
        version = importlib.metadata.version("pasu")
    except importlib.metadata.PackageNotFoundError:
        version = "dev"

    n_high   = len(HIGH_RISK_ACTIONS)
    n_medium = len(MEDIUM_RISK_ACTIONS)
    n_total  = n_high + n_medium + STRUCTURAL_RULE_COUNT

    C = "\033[36m"   # cyan   — gate structure
    B = "\033[1m"    # bold   — PASU name (\033[1m immediately before text, nothing else)
    R = "\033[0m"    # reset
    Y = "\033[33m"   # yellow — tagline
    D = "\033[2m"    # dim    — version / rule count

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
    print(f"  {D}[ {n_total} rules  {n_high} high  {n_medium} medium ]{R}")


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


def _print_escalate(result) -> None:
    risk_code = _risk_color(result.risk_level)
    print(_header("Privilege Escalation Report"))
    risk_label = _color(result.risk_level, _BOLD + risk_code)
    print(_section("Risk Level") + f"  {risk_label}")
    print(_section("Summary"))
    print(f"  {result.summary}")

    if result.detected_actions:
        print(_section("Detected Risky Actions"))
        for action in result.detected_actions:
            print(f"  • {_color(action, risk_code)}")

    if result.findings:
        print(_section("Findings"))
        for i, finding in enumerate(result.findings, 1):
            print(f"\n  [{i}] {_color(finding.action, _BOLD + risk_code)}")
            print(f"      Explanation:      {finding.explanation}")
            print(f"      Escalation path:  {finding.escalation_path}")


def _print_scan(explain_result, escalate_result) -> None:
    _print_explain(explain_result)
    print()
    _print_escalate(escalate_result)


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
        "detected_actions": result.detected_actions,
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


# ── Command handlers ──────────────────────────────────────────────────────────

def cmd_explain(args: argparse.Namespace) -> None:
    use_json = args.format == "json"
    try:
        policy_json = _load_policy(args.file)
    except (FileNotFoundError, ValueError) as exc:
        _handle_error(str(exc), use_json)
        return

    try:
        if args.ai:
            _require_api_key(use_json)
            result = explain_policy(policy_json=policy_json)
        else:
            result = explain_policy_local(policy_json=policy_json)
    except ValueError as exc:
        _handle_error(f"Validation error: {exc}", use_json)
        return
    except RuntimeError as exc:
        _handle_error(str(exc), use_json)
        return

    if use_json:
        print(json.dumps(_explain_to_json(result), indent=2))
    else:
        _print_explain(result)


def cmd_escalate(args: argparse.Namespace) -> None:
    use_json = args.format == "json"
    try:
        policy_json = _load_policy(args.file)
    except (FileNotFoundError, ValueError) as exc:
        _handle_error(str(exc), use_json)
        return

    try:
        if args.ai:
            _require_api_key(use_json)
            result = escalate_policy(policy_json=policy_json)
        else:
            result = escalate_policy_local(policy_json=policy_json)
        rule_findings = analyze_policy_rules(policy_json) if use_json else []
    except ValueError as exc:
        _handle_error(f"Validation error: {exc}", use_json)
        return
    except RuntimeError as exc:
        _handle_error(str(exc), use_json)
        return

    if use_json:
        print(json.dumps(_escalate_to_json(result, rule_findings), indent=2))
    else:
        _print_escalate(result)


def cmd_scan(args: argparse.Namespace) -> None:
    use_json = args.format == "json"
    try:
        policy_json = _load_policy(args.file)
    except (FileNotFoundError, ValueError) as exc:
        _handle_error(str(exc), use_json)
        return

    try:
        if args.ai:
            _require_api_key(use_json)
            explain_result = explain_policy(policy_json=policy_json)
            escalate_result = escalate_policy(policy_json=policy_json)
        else:
            explain_result = explain_policy_local(policy_json=policy_json)
            escalate_result = escalate_policy_local(policy_json=policy_json)
        rule_findings = analyze_policy_rules(policy_json) if use_json else []
    except ValueError as exc:
        _handle_error(f"Validation error: {exc}", use_json)
        return
    except RuntimeError as exc:
        _handle_error(str(exc), use_json)
        return

    if use_json:
        print(json.dumps(_scan_to_json(explain_result, escalate_result, rule_findings), indent=2))
    else:
        _print_scan(explain_result, escalate_result)


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
        choices=["text", "json"],
        default="text",
        metavar="FORMAT",
        help="Output format: 'text' (default) or 'json' (machine-readable, suppresses banner).",
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
    p_scan.add_argument("--ai", **_ai_kwargs)
    p_scan.add_argument("--format", **_format_kwargs)
    p_scan.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    # Banner is suppressed in JSON mode (clean stdout) and when -q/--quiet is set
    if not args.quiet and args.format != "json":
        _print_banner()
    args.func(args)


if __name__ == "__main__":
    main()
