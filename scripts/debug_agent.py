"""
debug_agent.py — Claude Debug Agent for IAM Analyzer Project.

Reads failing pytest output (stack trace), sends it to Claude for a fix,
displays the suggestion, and optionally applies the patch to the target file.

Usage (CI):
    python scripts/debug_agent.py --trace pytest_output.txt --file app/analyzer.py

Usage (interactive):
    python scripts/debug_agent.py --trace pytest_output.txt --file app/analyzer.py --interactive
"""

import argparse
import logging
import os
import sys
import re
import anthropic

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────
MODEL = "claude-sonnet-4-20250514"
MAX_TOKENS = 1024
SYSTEM_PROMPT = (
    "You are a senior Python engineer debugging a FastAPI application called "
    "'IAM Analyzer'. The project uses boto3, anthropic, pydantic, and pytest. "
    "Given a failing test trace and a source file, produce ONLY a corrected "
    "version of the source file — no explanations, no markdown fences, no extra "
    "commentary. Output raw Python only."
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def read_file(path: str) -> str:
    """Read and return the full text of a file.

    Args:
        path: Relative or absolute path to the file.

    Returns:
        File contents as a string.

    Raises:
        SystemExit: If the file cannot be read.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        logger.error("Cannot read '%s': %s", path, exc)
        sys.exit(1)


def write_file(path: str, content: str) -> None:
    """Write content to a file, overwriting existing content.

    Args:
        path: Target file path.
        content: String content to write.

    Raises:
        SystemExit: If the file cannot be written.
    """
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        logger.info("Patch applied to '%s'.", path)
    except OSError as exc:
        logger.error("Cannot write '%s': %s", path, exc)
        sys.exit(1)


def strip_markdown_fences(text: str) -> str:
    """Remove leading/trailing markdown code fences if present.

    Args:
        text: Raw model output that may contain ```python ... ``` fencing.

    Returns:
        Clean Python source.
    """
    pattern = r"^```(?:python)?\n(.*?)```$"
    match = re.match(pattern, text.strip(), re.DOTALL)
    return match.group(1) if match else text.strip()


# ── Core Logic ───────────────────────────────────────────────────────────────

def build_prompt(trace: str, source: str, file_path: str) -> str:
    """Construct the user message sent to Claude.

    Args:
        trace: Full pytest failure output / stack trace.
        source: Current content of the source file being debugged.
        file_path: File name shown in the prompt for context.

    Returns:
        Formatted prompt string.
    """
    return (
        f"## Failing test trace\n```\n{trace}\n```\n\n"
        f"## Source file: {file_path}\n```python\n{source}\n```\n\n"
        "Fix the source file so all tests pass. "
        "Return ONLY the corrected Python source, nothing else."
    )


def request_fix(trace: str, source: str, file_path: str) -> str:
    """Send the trace and source to Claude and return the suggested fix.

    Args:
        trace: Pytest failure output.
        source: Current source file contents.
        file_path: Name of the file being debugged.

    Returns:
        Corrected Python source as a string.

    Raises:
        SystemExit: If the API key is missing or the API call fails.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        logger.error("ANTHROPIC_API_KEY is not set in the environment.")
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)
    prompt = build_prompt(trace, source, file_path)

    logger.info("Sending trace and source to Claude (%s)…", MODEL)
    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
    except anthropic.APIError as exc:
        logger.error("Claude API error: %s", exc)
        sys.exit(1)

    raw = response.content[0].text
    return strip_markdown_fences(raw)


# ── Entry Point ───────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Debug Agent: sends failing test traces to Claude and applies fixes."
    )
    parser.add_argument(
        "--trace",
        required=True,
        help="Path to file containing the pytest failure output / stack trace.",
    )
    parser.add_argument(
        "--file",
        required=True,
        dest="source_file",
        help="Path to the Python source file to be fixed.",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Prompt for approval before applying the patch (default: auto-apply in CI).",
    )
    return parser.parse_args()


def main() -> None:
    """Main entry point for the Debug Agent."""
    args = parse_args()

    trace = read_file(args.trace)
    source = read_file(args.source_file)

    fix = request_fix(trace, source, args.source_file)

    print("\n" + "=" * 72)
    print("SUGGESTED FIX")
    print("=" * 72)
    print(fix)
    print("=" * 72 + "\n")

    if args.interactive:
        answer = input("Apply this fix? [y/N]: ").strip().lower()
        if answer != "y":
            logger.info("Fix not applied. Exiting.")
            sys.exit(0)

    write_file(args.source_file, fix)


if __name__ == "__main__":
    main()