"""
analyzer.py — Core IAM analysis logic: fetches policy documents and sends
them to Claude for security analysis, explains pasted policy JSON, and
detects privilege escalation risks.
"""

import json
import logging
import os

import anthropic

from app import aws_client
from app.models import AnalysisResult, EscalationFinding, EscalationResult, ExplainResult

logger = logging.getLogger(__name__)

MODEL = "claude-haiku-4-5-20251001"
MAX_TOKENS = 1024

# ── Risk action lists ─────────────────────────────────────────────────────────

HIGH_RISK_ACTIONS: set[str] = {
    "iam:passrole",
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:attachrolepolicy",
    "iam:attachuserpolicy",
    "iam:attachgrouppolicy",
    "iam:putuserolicy",
    "iam:putrolepolicy",
    "iam:createrole",
    "iam:updateassumerolepolicy",
}

MEDIUM_RISK_ACTIONS: set[str] = {
    "sts:assumerole",
    "iam:createaccesskey",
}

# Actions that are wildcards covering all IAM or all actions
WILDCARD_PREFIXES: tuple[str, ...] = ("iam:*", "*")

# ── Prompts ───────────────────────────────────────────────────────────────────

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

ESCALATION_SYSTEM_PROMPT = (
    "You are an AWS IAM security expert specializing in privilege escalation detection. "
    "You will be given a list of high-risk IAM actions detected in a policy, "
    "along with the full policy JSON. "
    "For each detected action, respond ONLY with a JSON object in this exact format:\n"
    "{\n"
    '  "summary": "<one sentence overall risk summary>",\n'
    '  "findings": [\n'
    '    {\n'
    '      "action": "<the risky action>",\n'
    '      "explanation": "<what it allows and why it is risky — 2-3 sentences, no jargon>",\n'
    '      "escalation_path": "<simplified path e.g. User → PassRole → EC2 → Admin Role>"\n'
    '    }\n'
    "  ]\n"
    "}\n"
    "Rules:\n"
    "- Do NOT assume the policy grants admin access automatically.\n"
    "- Focus only on the detected actions provided.\n"
    "- Explain the potential escalation scenario, not a guaranteed one.\n"
    "- Use plain English — avoid AWS API jargon where possible.\n"
    "- output raw JSON only, no markdown fences, no extra text."
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _strip_fences(text: str) -> str:
    """Remove markdown code fences from Claude's response if present.

    Args:
        text: Raw model output.

    Returns:
        Clean string with fences removed.
    """
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    return text.strip()


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


def _extract_allowed_actions(policy: dict) -> set[str]:
    """Extract all allowed actions from a policy as a lowercase set.

    Handles string and list Action values, wildcards, and NotAction.

    Args:
        policy: Parsed IAM policy dict.

    Returns:
        Set of lowercase action strings found in Allow statements.
    """
    allowed: set[str] = set()
    for stmt in policy.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            allowed.add(action.lower())
    return allowed


def _detect_risky_actions(allowed_actions: set[str]) -> tuple[list[str], str]:
    """Detect high and medium risk actions from the allowed action set.

    Args:
        allowed_actions: Lowercase set of allowed actions.

    Returns:
        Tuple of (detected_action_list, risk_level).
    """
    # Check for wildcards first
    is_wildcard = any(
        any(a == prefix.lower() or a.startswith("iam:") for prefix in WILDCARD_PREFIXES)
        for a in allowed_actions
        if a in {p.lower() for p in WILDCARD_PREFIXES}
    )

    # Direct wildcard match
    has_full_wildcard = "*" in allowed_actions
    has_iam_wildcard = "iam:*" in allowed_actions

    detected_high = []
    detected_medium = []

    if has_full_wildcard or has_iam_wildcard:
        # Wildcards cover all high and medium risk actions
        detected_high = sorted(HIGH_RISK_ACTIONS)
        detected_medium = sorted(MEDIUM_RISK_ACTIONS)
    else:
        detected_high = sorted(allowed_actions & HIGH_RISK_ACTIONS)
        detected_medium = sorted(allowed_actions & MEDIUM_RISK_ACTIONS)

    detected = detected_high + detected_medium

    if detected_high:
        risk_level = "High"
    elif detected_medium:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return detected, risk_level


# ── Core Functions ────────────────────────────────────────────────────────────

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


def explain_policy(policy_json: str) -> ExplainResult:
    """Explain a pasted IAM policy JSON in plain English.

    Args:
        policy_json: Raw IAM policy JSON string provided by the user.

    Returns:
        ExplainResult containing a one-sentence summary and bullet details.

    Raises:
        ValueError: If policy_json is not valid JSON or not a valid IAM policy.
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

    raw = _strip_fences(response.content[0].text)

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.error("Claude returned non-JSON response: %s", raw)
        raise RuntimeError("Claude returned an unexpected response format.") from exc

    return ExplainResult(
        summary=parsed["summary"],
        details=parsed["details"],
    )


def escalate_policy(policy_json: str) -> EscalationResult:
    """Detect privilege escalation risks in a pasted IAM policy JSON.

    Performs local action detection first (no API cost), then calls Claude
    only if risky actions are found.

    Args:
        policy_json: Raw IAM policy JSON string provided by the user.

    Returns:
        EscalationResult with risk level, detected actions, and findings.

    Raises:
        ValueError: If policy_json is not valid JSON or not a valid IAM policy.
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

    # Step 1 — local detection (free, no API call)
    allowed_actions = _extract_allowed_actions(parsed_input)
    detected, risk_level = _detect_risky_actions(allowed_actions)

    # Step 2 — if no risky actions, return immediately (no Claude call)
    if not detected:
        return EscalationResult(
            risk_level="Low",
            detected_actions=[],
            findings=[],
            summary="No privilege escalation risks detected in this policy.",
        )

    # Step 3 — call Claude only for risky policies
    client = anthropic.Anthropic(api_key=api_key)
    user_message = (
        f"Detected risky actions: {json.dumps(detected)}\n\n"
        f"Full policy:\n{policy_json}"
    )

    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=ESCALATION_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )
    except anthropic.APIError as exc:
        logger.error("Claude API call failed during escalation check: %s", exc)
        raise RuntimeError("Claude escalation check failed") from exc

    raw = _strip_fences(response.content[0].text)

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.error("Claude returned non-JSON response during escalation: %s", raw)
        raise RuntimeError("Claude returned an unexpected response format.") from exc

    findings = [
        EscalationFinding(
            action=f["action"],
            explanation=f["explanation"],
            escalation_path=f["escalation_path"],
        )
        for f in parsed.get("findings", [])
    ]

    return EscalationResult(
        risk_level=risk_level,
        detected_actions=detected,
        findings=findings,
        summary=parsed.get("summary", ""),
    )