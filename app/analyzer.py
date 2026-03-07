"""
analyzer.py — Core IAM analysis logic: fetches policy documents and sends
them to Claude for security analysis, and explains pasted policy JSON.
"""

import json
import logging
import os

import anthropic

from app import aws_client
from app.models import AnalysisResult, ExplainResult

logger = logging.getLogger(__name__)

MODEL = "claude-haiku-4-5-20251001"
MAX_TOKENS = 1024

ANALYSIS_SYSTEM_PROMPT = (
    "You are an AWS IAM security expert. "
    "Given an IAM policy document in JSON format, identify: "
    "1) over-permissive actions (e.g. wildcard '*' usage), "
    "2) missing condition keys that should restrict access, "
    "3) resources that are too broadly scoped. "
    "Be concise, structured, and actionable."
)

EXPLAIN_SYSTEM_PROMPT = (
    "You are an AWS IAM expert who explains IAM policies in plain English "
    "to non-technical users. "
    "Given an IAM policy JSON, respond ONLY with a JSON object in this exact format:\n"
    "{\n"
    '  "summary": "<one sentence describing what this policy allows or denies overall>",\n'
    '  "details": [\n'
    '    "<plain English explanation of statement 1>",\n'
    '    "<plain English explanation of statement 2>"\n'
    "  ]\n"
    "}\n"
    "Rules:\n"
    "- summary must be a single sentence, plain English, no jargon.\n"
    "- each details item explains exactly one Statement in simple terms.\n"
    "- never use AWS API action names (e.g. s3:GetObject) in the output — "
    "describe what the action does instead (e.g. 'read files from').\n"
    "- output raw JSON only, no markdown fences, no extra text."
)


def analyze_policy(policy_arn: str, account_id: str) -> AnalysisResult:
    """Fetch an IAM policy and return a Claude-generated security analysis.

    Args:
        policy_arn: Full ARN of the IAM policy.
        account_id: AWS account ID (used for logging context).

    Returns:
        AnalysisResult containing Claude's findings.

    Raises:
        RuntimeError: If AWS retrieval or Claude API call fails.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY environment variable is not set.")

    policy_meta = aws_client.get_policy(policy_arn)
    version_id = policy_meta["DefaultVersionId"]
    policy_document = aws_client.get_policy_document(policy_arn, version_id)
    policy_json = json.dumps(policy_document, indent=2)

    logger.info(
        "Analyzing policy '%s' (account: %s, version: %s).",
        policy_arn,
        account_id,
        version_id,
    )

    client = anthropic.Anthropic(api_key=api_key)
    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=ANALYSIS_SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"Analyze the following IAM policy document:\n\n"
                        f"```json\n{policy_json}\n```"
                    ),
                }
            ],
        )
    except anthropic.APIError as exc:
        logger.error("Claude API call failed for policy '%s': %s", policy_arn, exc)
        raise RuntimeError("Claude analysis failed") from exc

    findings = response.content[0].text
    return AnalysisResult(policy_arn=policy_arn, findings=findings)


def validate_iam_policy(policy: dict) -> None:
    """Validate that a parsed dict looks like a real IAM policy.

    Args:
        policy: Parsed IAM policy dict.

    Raises:
        ValueError: If the structure does not match a valid IAM policy.
    """
    if "Statement" not in policy:
        raise ValueError("Missing required field: 'Statement'.")

    if not isinstance(policy["Statement"], list) or len(policy["Statement"]) == 0:
        raise ValueError("'Statement' must be a non-empty array.")

    for i, stmt in enumerate(policy["Statement"]):
        if not isinstance(stmt, dict):
            raise ValueError(f"Statement[{i}] must be an object.")
        if "Effect" not in stmt:
            raise ValueError(f"Statement[{i}] is missing required field: 'Effect'.")
        if stmt["Effect"] not in ("Allow", "Deny"):
            raise ValueError(f"Statement[{i}] 'Effect' must be 'Allow' or 'Deny'.")
        if "Action" not in stmt and "NotAction" not in stmt:
            raise ValueError(f"Statement[{i}] is missing required field: 'Action'.")
        if "Resource" not in stmt and "NotResource" not in stmt:
            raise ValueError(f"Statement[{i}] is missing required field: 'Resource'.")


def explain_policy(policy_json: str) -> ExplainResult:
    """Explain a pasted IAM policy JSON in plain English.

    Args:
        policy_json: Raw IAM policy JSON string provided by the user.

    Returns:
        ExplainResult containing a one-sentence summary and bullet details.

    Raises:
        ValueError: If policy_json is not valid JSON.
        RuntimeError: If ANTHROPIC_API_KEY is missing or Claude API call fails.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY environment variable is not set.")

    try:
        parsed_input = json.loads(policy_json)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JSON provided.") from exc

    validate_iam_policy(parsed_input)

    client = anthropic.Anthropic(api_key=api_key)
    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=EXPLAIN_SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": f"Explain this IAM policy:\n{policy_json}",
                }
            ],
        )
    except anthropic.APIError as exc:
        logger.error("Claude API call failed during explain: %s", exc)
        raise RuntimeError("Claude explain failed") from exc

    raw = response.content[0].text.strip()

    # Strip markdown code fences if Claude wraps the JSON
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.error("Claude returned non-JSON response: %s", raw)
        raise RuntimeError("Claude returned an unexpected response format.") from exc

    return ExplainResult(
        summary=parsed["summary"],
        details=parsed["details"],
    )