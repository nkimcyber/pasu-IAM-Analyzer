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
from app.models import (
    AnalysisResult,
    EscalationFinding,
    EscalationResult,
    ExplainResult,
    FixChange,
    FixResult,
    RuleFinding,
)

logger = logging.getLogger(__name__)

MODEL = "claude-haiku-4-5-20251001"
MAX_TOKENS = 4096

# ── Externalized rule/config loading ─────────────────────────────────────────
from pathlib import Path

def _load_data_file(path: Path):
    """Load JSON or JSON-compatible YAML config data from disk."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RuntimeError(f"Required analyzer config file not found: {path}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # type: ignore
        except Exception as exc:
            raise RuntimeError(
                f"Failed to parse analyzer config file: {path}. "
                "Use JSON-compatible YAML or install PyYAML."
            ) from exc
        try:
            return yaml.safe_load(text)
        except Exception as exc:
            raise RuntimeError(f"Failed to parse analyzer config file: {path}") from exc


def _discover_config_root() -> Path:
    """Find the directory containing app/data and app/rules."""
    env_root = os.getenv("PASU_CONFIG_ROOT")
    if env_root:
        candidate = Path(env_root).resolve()
        if (candidate / "rules").exists() and (candidate / "data").exists():
            return candidate
        if (candidate / "app" / "rules").exists() and (candidate / "app" / "data").exists():
            return candidate / "app"

    here = Path(__file__).resolve().parent
    candidates = [
        here,
        here.parent,
        Path.cwd() / "app",
        Path.cwd(),
    ]
    for candidate in candidates:
        if (candidate / "rules").exists() and (candidate / "data").exists():
            return candidate
    raise RuntimeError(
        "Unable to locate analyzer config directories 'rules/' and 'data/'. "
        "Expected them under app/ or set PASU_CONFIG_ROOT."
    )


def _load_rule_config() -> dict:
    root = _discover_config_root()
    risky = _load_data_file(root / "rules" / "risky_actions.yaml")
    scoring = _load_data_file(root / "rules" / "scoring.yaml")
    fix_profiles = _load_data_file(root / "rules" / "fix_profiles.yaml")
    catalog = _load_data_file(root / "data" / "aws_catalog.json")
    return {
        "root": root,
        "risky": risky,
        "scoring": scoring,
        "fix_profiles": fix_profiles,
        "catalog": catalog,
    }


_RULE_CONFIG = _load_rule_config()
_RISKY_CFG = _RULE_CONFIG["risky"]
_SCORING_CFG = _RULE_CONFIG["scoring"]
_FIX_CFG = _RULE_CONFIG["fix_profiles"]
AWS_CATALOG = _RULE_CONFIG["catalog"]

# ── Risk action lists ─────────────────────────────────────────────────────────
HIGH_RISK_ACTIONS: set[str] = set(_RISKY_CFG["high_risk_actions"])
MEDIUM_RISK_ACTIONS: set[str] = set(_RISKY_CFG["medium_risk_actions"])
WILDCARD_PREFIXES: tuple[str, ...] = ("iam:*", "*")
_CONTEXT_MEDIUM: dict[str, str] = dict(_RISKY_CFG["context_medium_actions"])
STRUCTURAL_RULE_COUNT: int = int(_SCORING_CFG.get("structural_rule_count", 5))
SERVICE_READONLY_ACTIONS: dict[str, list[str]] = {
    svc: list(actions) for svc, actions in _FIX_CFG["service_readonly_actions"].items()
}
_ACTION_DESCRIPTIONS: dict[str, str] = dict(_RISKY_CFG["action_descriptions"])
_SCORE_WEIGHTS: dict[str, int] = {
    k: int(v) for k, v in _SCORING_CFG["weights"].items()
}
_SCORE_BANDS: dict[str, int] = {
    k: int(v) for k, v in _SCORING_CFG["bands"].items()
}
_SCORE_CAP: int = int(_SCORING_CFG.get("score_cap", 100))

# ── Plain-English lookup tables (used by explain_policy_local) ────────────────

SERVICE_DESCRIPTIONS: dict[str, str] = {
    "s3": "S3 (file storage)",
    "ec2": "EC2 (virtual servers)",
    "iam": "IAM (user permissions)",
    "lambda": "Lambda (serverless functions)",
    "rds": "RDS (databases)",
    "dynamodb": "DynamoDB (NoSQL database)",
    "kms": "KMS (encryption keys)",
    "secretsmanager": "Secrets Manager",
    "ssm": "Systems Manager Parameter Store",
    "sts": "STS (temporary credentials)",
    "organizations": "AWS Organizations (account management)",
    "cloudwatch": "CloudWatch (monitoring)",
    "logs": "CloudWatch Logs",
    "sns": "SNS (notifications)",
    "sqs": "SQS (message queues)",
    "cloudformation": "CloudFormation (infrastructure)",
}

# Gerund phrases for common IAM actions — lowercase, used directly in sentences.
# Both Allow ("ALLOWS reading files...") and Deny ("BLOCKS reading files...") use these.
ACTION_DESCRIPTIONS: dict[str, str] = {
    "s3:getobject": "read files from storage",
    "s3:putobject": "upload files to storage",
    "s3:deleteobject": "delete files from storage",
    "s3:listbucket": "list files in a bucket",
    "s3:deletebucket": "delete storage buckets",
    "s3:createbucket": "create storage buckets",
    "s3:putbucketpolicy": "change bucket security policy",
    "s3:putbucketacl": "change bucket access controls",
    "s3:putobjectacl": "change file access controls",
    "ec2:runinstances": "start virtual servers",
    "ec2:terminateinstances": "shut down virtual servers",
    "ec2:stopinstances": "stop virtual servers",
    "ec2:startinstances": "restart virtual servers",
    "ec2:describeinstances": "view virtual server details",
    "iam:passrole": "assign roles to AWS services",
    "iam:createuser": "create new users",
    "iam:deleteuser": "delete users",
    "iam:attachrolepolicy": "attach permission policies to roles",
    "iam:attachuserpolicy": "attach permission policies to users",
    "iam:attachgrouppolicy": "attach permission policies to groups",
    "iam:createpolicyversion": "create new versions of permission policies",
    "iam:setdefaultpolicyversion": "activate a different version of a permission policy",
    "iam:createrole": "create roles",
    "iam:putuserpolicy": "write inline permission policies for users",
    "iam:putrolepolicy": "write inline permission policies for roles",
    "iam:updateassumerolepolicy": "modify role trust policies",
    "lambda:invokefunction": "run serverless functions",
    "lambda:createfunction": "create serverless functions",
    "lambda:updatefunctioncode": "modify serverless function code",
    "lambda:deletefunction": "delete serverless functions",
    "sts:assumerole": "switch to another role",
    "kms:decrypt": "decrypt data using encryption keys",
    "kms:encrypt": "encrypt data",
    "kms:describekey": "inspect encryption key details",
    "kms:createkey": "create encryption keys",
    "secretsmanager:getsecretvalue": "retrieve stored secrets",
    "secretsmanager:createsecret": "create secrets",
    "secretsmanager:deletesecret": "delete secrets",
    "ssm:getparameter": "retrieve stored parameters",
    "ssm:putparameter": "write configuration parameters",
    "rds:copydbsnapshot": "copy database snapshots",
    "rds:createdbsnapshot": "create database snapshots",
    "rds:deletedbinstance": "delete databases",
    "dynamodb:scan": "read all data from a NoSQL table",
    "dynamodb:getitem": "read items from a NoSQL table",
    "dynamodb:putitem": "write items to a NoSQL table",
    "dynamodb:deleteitem": "delete items from a NoSQL table",
    "dynamodb:query": "query data in a NoSQL table",
    "organizations:*": "manage the entire AWS Organization",
}


# ── Plain-English helpers ──────────────────────────────────────────────────────

import re as _re


def _action_phrase(action: str) -> str:
    """Return a lowercase gerund phrase for one IAM action.

    Examples:
        "*"                        → "full administrator access to ALL AWS services"
        "iam:*"                    → "ALL actions in IAM (user permissions)"
        "ec2:*"                    → "ALL actions in EC2 (virtual servers)"
        "s3:GetObject"             → "read files from storage"
        "ec2:DescribeSecurityGroups" → "describe security groups in EC2 (virtual servers)"
    """
    al = action.lower()
    if al == "*":
        return "full administrator access to ALL AWS services"
    if al == "iam:*":
        return "ALL actions in IAM (user permissions)"
    if al.endswith(":*"):
        svc = al.split(":")[0]
        svc_label = SERVICE_DESCRIPTIONS.get(svc, svc.upper())
        return f"ALL actions in {svc_label}"
    if al in ACTION_DESCRIPTIONS:
        return ACTION_DESCRIPTIONS[al]
    # Auto-generate from CamelCase: "ec2:DescribeSecurityGroups" → "describe security groups in EC2 (virtual servers)"
    parts = action.split(":")
    if len(parts) == 2:
        svc, op = parts
        words = _re.sub(r"(?<=[a-z])(?=[A-Z])", " ", op).lower()
        svc_label = SERVICE_DESCRIPTIONS.get(svc.lower(), svc.upper())
        return f"{words} in {svc_label}"
    return action.lower()


def _actions_phrase(actions: list[str]) -> str:
    """Combine IAM actions into a concise human-readable gerund phrase."""
    if not actions:
        return "perform unspecified actions"
    if "*" in [a.lower() for a in actions]:
        return "full administrator access to ALL AWS services"
    phrases: list[str] = []
    seen: set[str] = set()
    for a in actions[:5]:
        p = _action_phrase(a)
        if p not in seen:
            seen.add(p)
            phrases.append(p)
    suffix = f", and {len(actions) - 5} more action(s)" if len(actions) > 5 else ""
    if len(phrases) == 1:
        return phrases[0] + suffix
    return ", ".join(phrases[:-1]) + f", and {phrases[-1]}" + suffix


def _resource_phrase(resources: list[str]) -> tuple[str, bool]:
    """Convert resource ARNs to a readable phrase.

    Returns:
        (phrase, is_wildcard) — is_wildcard is True when Resource is "*".
    """
    if not resources or "*" in resources:
        return "all resources", True
    descriptions: list[str] = []
    for res in resources[:3]:
        if res.startswith("arn:aws:s3:::"):
            path = res[len("arn:aws:s3:::"):]
            bucket = path.split("/")[0]
            if bucket == "*":
                descriptions.append("all S3 buckets")
            else:
                descriptions.append(f"the S3 bucket '{bucket}'")
        elif res.startswith("arn:aws:"):
            parts = res.split(":")
            if len(parts) >= 6:
                svc = parts[2]
                resource_part = ":".join(parts[5:])
                name = resource_part.split("/")[-1]
                svc_label = SERVICE_DESCRIPTIONS.get(svc, svc.upper()).split(" ")[0]
                if name and name != "*":
                    descriptions.append(f"the {svc_label} resource '{name}'")
                else:
                    descriptions.append(f"all {svc_label} resources")
            else:
                descriptions.append(res)
        else:
            descriptions.append(res)
    if len(resources) > 3:
        descriptions.append(f"and {len(resources) - 3} more")
    return ", ".join(descriptions), False


def _explain_statement(stmt: dict) -> str:
    """Generate an 'ALLOWS/BLOCKS ...' sentence for one IAM policy statement."""
    effect = stmt.get("Effect", "Allow")
    has_not_action = "NotAction" in stmt
    has_not_resource = "NotResource" in stmt

    raw_actions = stmt.get("NotAction" if has_not_action else "Action", [])
    if isinstance(raw_actions, str):
        raw_actions = [raw_actions]

    raw_resources = stmt.get("NotResource" if has_not_resource else "Resource", [])
    if isinstance(raw_resources, str):
        raw_resources = [raw_resources]

    actions_lower = [a.lower() for a in raw_actions]
    is_full_wildcard = "*" in actions_lower and not has_not_action
    is_wildcard_resource = "*" in raw_resources and not has_not_resource

    # Full administrator access shortcut
    if effect == "Allow" and is_full_wildcard and is_wildcard_resource:
        return (
            "ALLOWS full administrator access to ALL AWS services and ALL resources. "
            "This is extremely dangerous."
        )

    # Build action phrase
    if has_not_action:
        action_str = f"ALL actions EXCEPT: {_actions_phrase(raw_actions)}"
    else:
        action_str = _actions_phrase(raw_actions)

    # Build resource phrase
    if has_not_resource:
        resource_str = f"everything EXCEPT {_resource_phrase(raw_resources)[0]}"
        is_wild = False
    else:
        resource_str, is_wild = _resource_phrase(raw_resources)

    if effect == "Allow":
        connector = "on" if is_wild else "limited to"
        return f"ALLOWS {action_str}, {connector} {resource_str}."
    else:  # Deny
        # Append service label when there is exactly one service involved
        if not has_not_action:
            services = {a.split(":")[0].lower() for a in raw_actions if ":" in a}
            if len(services) == 1:
                svc = next(iter(services))
                svc_label = SERVICE_DESCRIPTIONS.get(svc, "")
                if svc_label:
                    return f"BLOCKS {action_str} from {svc_label}, on {resource_str}."
        return f"BLOCKS {action_str} on {resource_str}."


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


# ── Local (no-API) Functions ──────────────────────────────────────────────────

def analyze_policy_rules(policy_json: str) -> list[RuleFinding]:
    """Run all local rule categories against a policy and return findings.

    Three categories of rules are evaluated:
      Category 1 — Overly permissive resource patterns (R001, R002)
      Category 2 — Dangerous service actions, including context-aware checks (R003, R004)
      Category 3 — Missing Deny / Condition checks (R005, R006, R007)

    No Claude API call is made. This function works entirely offline.

    Args:
        policy_json: Raw IAM policy JSON string.

    Returns:
        List of RuleFinding objects, one per detected issue across all statements.

    Raises:
        ValueError: If policy_json is not valid JSON or not a valid IAM policy.
    """
    try:
        parsed = json.loads(policy_json)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JSON provided.") from exc

    validate_iam_policy(parsed)

    findings: list[RuleFinding] = []

    for i, stmt in enumerate(parsed["Statement"]):
        effect = stmt.get("Effect")
        has_not_action = "NotAction" in stmt
        has_not_resource = "NotResource" in stmt

        # ── Category 3 (partial): NotAction / NotResource on any Allow ────────
        if effect == "Allow":
            if has_not_action:
                findings.append(RuleFinding(
                    rule_id="R006",
                    severity="high",
                    title="Inverse action grant - allows everything EXCEPT listed actions",
                    description=(
                        "NotAction grants access to all AWS actions except those listed. "
                        "This is almost always overly permissive and difficult to audit."
                    ),
                    statement_index=i,
                ))
            if has_not_resource:
                findings.append(RuleFinding(
                    rule_id="R007",
                    severity="high",
                    title="Inverse resource grant - allows access to everything EXCEPT listed resources",
                    description=(
                        "NotResource grants access to all resources except those listed. "
                        "This is almost always overly permissive and difficult to audit."
                    ),
                    statement_index=i,
                ))

        # Categories 1 and 2 require Effect=Allow with a plain Action list
        if effect != "Allow" or has_not_action:
            continue

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        actions_lower_set = {a.lower() for a in actions}

        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        resources_set = set(resources)

        condition = stmt.get("Condition")
        has_full_wildcard = "*" in actions_lower_set
        has_unrestricted_resource = "*" in resources_set

        # ── Category 1: Overly permissive resource patterns ───────────────────

        # R001: Resource: * with any action
        if has_unrestricted_resource:
            findings.append(RuleFinding(
                rule_id="R001",
                severity="high",
                title="Unrestricted resource access",
                description=(
                    "This statement allows actions on all resources ('*'). "
                    "Restrict to specific ARNs to follow least privilege."
                ),
                statement_index=i,
            ))

        # R002: Access to all S3 buckets via broad ARN patterns
        _S3_ALL = {"arn:aws:s3:::*", "arn:aws:s3:::*/*"}
        if resources_set & _S3_ALL:
            findings.append(RuleFinding(
                rule_id="R002",
                severity="high",
                title="Access to all S3 buckets",
                description=(
                    "This statement grants access to all S3 buckets. "
                    "Restrict to specific bucket ARNs."
                ),
                statement_index=i,
            ))

        # ── Category 2: Dangerous service actions ─────────────────────────────

        matched_high = HIGH_RISK_ACTIONS.copy() if has_full_wildcard else (
            actions_lower_set & HIGH_RISK_ACTIONS
        )
        matched_medium = MEDIUM_RISK_ACTIONS.copy() if has_full_wildcard else (
            actions_lower_set & MEDIUM_RISK_ACTIONS
        )

        for action in sorted(matched_high):
            findings.append(RuleFinding(
                rule_id="R003",
                severity="high",
                title=f"Dangerous action: {action}",
                description=_ACTION_DESCRIPTIONS.get(
                    action,
                    f"The action '{action}' can be used for privilege escalation.",
                ),
                statement_index=i,
            ))

        for action in sorted(matched_medium):
            findings.append(RuleFinding(
                rule_id="R004",
                severity="medium",
                title=f"Sensitive action: {action}",
                description=_ACTION_DESCRIPTIONS.get(
                    action,
                    f"The action '{action}' grants access to sensitive data or capabilities.",
                ),
                statement_index=i,
            ))

        # Context-dependent medium risk: only flagged when Resource is unrestricted
        if has_unrestricted_resource or has_full_wildcard:
            for action_lower in sorted(actions_lower_set):
                if action_lower in _CONTEXT_MEDIUM:
                    findings.append(RuleFinding(
                        rule_id="R004",
                        severity="medium",
                        title=f"Broad data access: {action_lower} on all resources",
                        description=_CONTEXT_MEDIUM[action_lower],
                        statement_index=i,
                    ))

        # ── Category 3: Missing Deny / Condition checks ───────────────────────

        # R005: Sensitive actions without a Condition block
        has_sensitive = bool(matched_high or matched_medium) or (
            has_unrestricted_resource
            and any(a in _CONTEXT_MEDIUM for a in actions_lower_set)
        )
        if has_sensitive and not condition:
            findings.append(RuleFinding(
                rule_id="R005",
                severity="medium",
                title="No conditions restrict this permission",
                description=(
                    "Sensitive actions are allowed without any Condition block. "
                    "Add conditions such as aws:RequestedRegion or aws:PrincipalAccount "
                    "to limit the scope of this permission."
                ),
                statement_index=i,
            ))

    return findings


def calculate_risk_score(policy_json: str) -> int:
    """Calculate a numeric risk score (0-100) for an IAM policy.

    Scoring rules applied per Allow statement:
    - Each HIGH_RISK_ACTION detected: +8
    - Each MEDIUM_RISK_ACTION detected: +4
    - R001 (Resource: * present): +10
    - R002 (arn:aws:s3:::* or arn:aws:s3:::*/* present): +6
    - R005 (sensitive action without Condition block): +5
    - R006 (NotAction inverse grant): +10
    - R007 (NotResource inverse grant): +10
    - Full admin (Action: * with Resource: *): +30
    - Service wildcard (e.g. s3:*, iam:*): +10 each

    Score is capped at 100.

    Args:
        policy_json: Raw IAM policy JSON string.

    Returns:
        Integer risk score in [0, 100].

    Raises:
        ValueError: If policy_json is not valid JSON or not a valid IAM policy.
    """
    try:
        parsed = json.loads(policy_json)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JSON provided.") from exc

    validate_iam_policy(parsed)

    score = 0
    _S3_ALL = {"arn:aws:s3:::*", "arn:aws:s3:::*/*"}

    for stmt in parsed.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue

        has_not_action = "NotAction" in stmt
        has_not_resource = "NotResource" in stmt

        # R006: NotAction inverse grant
        if has_not_action:
            score += _SCORE_WEIGHTS["not_action"]
        # R007: NotResource inverse grant
        if has_not_resource:
            score += _SCORE_WEIGHTS["not_resource"]

        if has_not_action:
            continue  # cannot evaluate specific actions further

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        actions_lower = {a.lower() for a in actions}

        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        resources_set = set(resources)

        has_full_wildcard_action = "*" in actions_lower
        has_full_wildcard_resource = "*" in resources_set
        condition = stmt.get("Condition")

        # Full admin bonus: Action:* with Resource:*
        if has_full_wildcard_action and has_full_wildcard_resource:
            score += _SCORE_WEIGHTS["full_admin"]

        # Service wildcard bonus: +10 per service:* (not counting the bare "*")
        service_wildcards = {
            action for action in actions_lower
            if action != "*" and action.endswith(":*")
        }
        score += len(service_wildcards) * _SCORE_WEIGHTS["service_wildcard"]

        # Action-based scoring: +8 per HIGH, +4 per MEDIUM
        if has_full_wildcard_action:
            matched_high = set(HIGH_RISK_ACTIONS)
            matched_medium = set(MEDIUM_RISK_ACTIONS)
        else:
            matched_high = set(actions_lower & HIGH_RISK_ACTIONS)
            matched_medium = set(actions_lower & MEDIUM_RISK_ACTIONS)

            # Expand service wildcards so iam:* and s3:* reflect the risky actions
            # they actually include.
            for wildcard in service_wildcards:
                svc = wildcard.split(":")[0]

                matched_high |= {
                    action
                    for action in HIGH_RISK_ACTIONS
                    if action.startswith(f"{svc}:") or action == f"{svc}:*"
                }
                matched_medium |= {
                    action
                    for action in MEDIUM_RISK_ACTIONS
                    if action.startswith(f"{svc}:") or action == f"{svc}:*"
                }

                # Context-dependent medium risk covered by service wildcard
                if has_full_wildcard_resource:
                    matched_medium |= {
                        action
                        for action in _CONTEXT_MEDIUM
                        if action.startswith(f"{svc}:")
                    }

        score += len(matched_high) * _SCORE_WEIGHTS["high_risk_action"]
        score += len(matched_medium) * _SCORE_WEIGHTS["medium_risk_action"]

        # Structural rule scoring
        # R001: Unrestricted resource
        if has_full_wildcard_resource:
            score += _SCORE_WEIGHTS["resource_wildcard"]

        # R002: Access to all S3 buckets
        if resources_set & _S3_ALL:
            score += _SCORE_WEIGHTS["s3_all_buckets"]

        # R005: Sensitive action without Condition
        has_sensitive = (
            has_full_wildcard_action
            or bool(service_wildcards)
            or bool(matched_high)
            or bool(matched_medium)
            or (
                has_full_wildcard_resource
                and any(a in _CONTEXT_MEDIUM for a in actions_lower)
            )
        )
        if has_sensitive and not condition:
            score += _SCORE_WEIGHTS["no_condition_sensitive"]

    return min(score, _SCORE_CAP)


def risk_score_label(score: int) -> str:
    """Return the risk level label for a numeric score.

    Args:
        score: Integer in [0, 100].

    Returns:
        'Low', 'Medium', or 'High'.
    """
    if score <= _SCORE_BANDS["low_max"]:
        return "Low"
    if score <= _SCORE_BANDS["medium_max"]:
        return "Medium"
    return "High"


def _max_risk_level(*levels: str) -> str:
    """Return the highest risk level among Low/Medium/High values."""
    order = {"Low": 0, "Medium": 1, "High": 2}
    return max(levels, key=lambda lvl: order.get(lvl, -1))


def explain_policy_local(policy_json: str) -> ExplainResult:
    """Generate a rule-based plain-English explanation with no Claude API call.

    Args:
        policy_json: Raw IAM policy JSON string.

    Returns:
        ExplainResult with a summary and per-statement details.

    Raises:
        ValueError: If policy_json is not valid JSON or not a valid IAM policy.
    """
    try:
        parsed = json.loads(policy_json)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JSON provided.") from exc

    validate_iam_policy(parsed)

    details = [_explain_statement(stmt) for stmt in parsed["Statement"]]

    has_full_admin = any(
        stmt.get("Effect") == "Allow"
        and stmt.get("Action") in ("*", ["*"])
        and stmt.get("Resource") in ("*", ["*"])
        for stmt in parsed["Statement"]
    )

    if has_full_admin:
        summary = (
            "This policy grants FULL ADMIN ACCESS to every AWS service and "
            "resource in the account. This is extremely dangerous."
        )
    elif len(details) == 1:
        summary = details[0]
    else:
        effects = {s.get("Effect") for s in parsed["Statement"]}
        if effects == {"Allow"}:
            summary = f"This policy allows access across {len(details)} permission(s)."
        else:
            summary = (
                f"This policy has {len(details)} permission(s) with mixed "
                "Allow/Deny effects."
            )

    return ExplainResult(summary=summary, details=details)


def escalate_policy_local(policy_json: str) -> EscalationResult:
    """Run local rule-based privilege escalation detection with no Claude API call.

    Combines action-list matching (_detect_risky_actions) with the full structural
    rule engine (analyze_policy_rules) to produce a richer risk assessment.

    Args:
        policy_json: Raw IAM policy JSON string.

    Returns:
        EscalationResult with risk level and detected actions; findings is always []
        because detailed per-finding analysis requires the --ai flag.

    Raises:
        ValueError: If policy_json is not valid JSON or not a valid IAM policy.
    """
    try:
        parsed = json.loads(policy_json)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JSON provided.") from exc

    validate_iam_policy(parsed)

    # Action-based detection — drives detected_actions
    allowed_actions = _extract_allowed_actions(parsed)
    detected, _ = _detect_risky_actions(allowed_actions)

    # Structural rule engine — all three categories
    rule_findings = analyze_policy_rules(policy_json)

    # Preserve action-based High findings while still reporting the numeric score.
    risk_score = calculate_risk_score(policy_json)
    risk_level = risk_score_label(risk_score)

    n_rules = len(rule_findings)
    rule_note = f", {n_rules} rule finding(s) total" if rule_findings else ""

    if not detected and not rule_findings:
        summary = "No privilege escalation risks detected in this policy."
    elif risk_level == "High":
        summary = (
            f"High privilege escalation risk: {len(detected)} dangerous action(s) detected"
            f"{rule_note}. Run with --ai for detailed analysis."
        )
    else:
        summary = (
            f"Medium privilege escalation risk: {len(detected)} sensitive action(s) detected"
            f"{rule_note}. Run with --ai for detailed analysis."
        )

    return EscalationResult(
        risk_level=risk_level,
        detected_actions=detected,
        findings=[],
        summary=summary,
        risk_score=risk_score,
    )



# ── Fix Function ─────────────────────────────────────────────────────────────

def fix_policy_local(policy_json: str) -> FixResult:
    """Generate a least-privilege replacement for a dangerous IAM policy.

    Transformations applied to Allow statements:
    - ``Action: "*"``          → replaced with a TODO placeholder
    - Service wildcards        → replaced with read-only actions from SERVICE_READONLY_ACTIONS
    - HIGH_RISK_ACTIONS        → removed from the action list
    - ``Resource: "*"``        → kept but flagged with a resource_wildcard_warning change
    - NotAction / NotResource  → flagged for manual review, kept unchanged
    - Deny statements          → kept unchanged (Deny is good for security)

    Args:
        policy_json: Raw IAM policy JSON string.

    Returns:
        FixResult with the fixed policy, list of changes, and manual review notes.

    Raises:
        ValueError: If policy_json is not valid JSON or not a valid IAM policy.
    """
    try:
        parsed = json.loads(policy_json)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JSON provided.") from exc

    validate_iam_policy(parsed)

    original_risk_score = calculate_risk_score(policy_json)
    original_risk_level = risk_score_label(original_risk_score)

    changes: list[FixChange] = []
    manual_review_needed: list[str] = []
    fixed_statements: list[dict] = []

    for i, stmt in enumerate(parsed["Statement"]):
        effect = stmt.get("Effect")
        has_not_action = "NotAction" in stmt
        has_not_resource = "NotResource" in stmt
        sid = stmt.get("Sid")
        statement_label = f"Statement {i + 1} ({sid})" if sid else f"Statement {i + 1}"
        # Deny → keep unchanged
        if effect == "Deny":
            fixed_statements.append(dict(stmt))
            continue

        # NotAction / NotResource → flag for manual review, keep unchanged
        if has_not_action or has_not_resource:
            fixed_statements.append(dict(stmt))
            parts = []
            if has_not_action:
                parts.append("NotAction")
            if has_not_resource:
                parts.append("NotResource")
            manual_review_needed.append(
                f"{statement_label} uses {' and '.join(parts)} — cannot auto-fix, "
                "manual review required"
            )
            continue

        # Allow statement — process actions and resources
        fixed_stmt: dict = {}
        if "Sid" in stmt:
            fixed_stmt["Sid"] = stmt["Sid"]
        fixed_stmt["Effect"] = "Allow"

        raw_actions = stmt.get("Action", [])
        if isinstance(raw_actions, str):
            raw_actions = [raw_actions]

        raw_resources = stmt.get("Resource", [])
        if isinstance(raw_resources, str):
            raw_resources = [raw_resources]

        # ── Process actions ───────────────────────────────────────────────────
        fixed_actions: list[str] = []

        if "*" in raw_actions:
            # Full wildcard → TODO placeholder
            fixed_actions = ["TODO:specify-needed-actions"]
            changes.append(FixChange(
                type="replaced_wildcard",
                statement_index=i,
                from_="*",
                to=["TODO:specify-needed-actions"],
                reason=(
                    "Full action wildcard grants administrator access; "
                    "specify only the actions actually needed"
                ),
            ))
        else:
            seen: set[str] = set()
            for action in raw_actions:
                al = action.lower()
                if al.endswith(":*"):
                    # Service wildcard (e.g. s3:*) → read-only replacements
                    svc = al.split(":")[0]
                    if svc in SERVICE_READONLY_ACTIONS:
                        replacement = SERVICE_READONLY_ACTIONS[svc]
                        changes.append(FixChange(
                            type="scoped_wildcard",
                            statement_index=i,
                            from_=action,
                            to=replacement,
                            reason=(
                                f"Service wildcard replaced with read-only "
                                f"{svc.upper()} actions"
                            ),
                        ))
                        for a in replacement:
                            if a not in seen:
                                seen.add(a)
                                fixed_actions.append(a)
                    else:
                        placeholder = f"TODO:{svc}:specify-needed-actions"
                        changes.append(FixChange(
                            type="replaced_wildcard",
                            statement_index=i,
                            from_=action,
                            to=[placeholder],
                            reason=(
                                f"Service wildcard for unknown service '{svc}'; "
                                "specify only the actions actually needed"
                            ),
                        ))
                        if placeholder not in seen:
                            seen.add(placeholder)
                            fixed_actions.append(placeholder)
                elif al in HIGH_RISK_ACTIONS:
                    # High-risk → remove
                    changes.append(FixChange(
                        type="removed_action",
                        statement_index=i,
                        action=action,
                        reason=_ACTION_DESCRIPTIONS.get(
                            al,
                            f"'{action}' is a privilege escalation risk",
                        ),
                    ))
                else:
                    # Safe action → keep
                    if action not in seen:
                        seen.add(action)
                        fixed_actions.append(action)

            # All actions were removed → placeholder
            if not fixed_actions:
                fixed_actions = ["TODO:specify-needed-actions"]
                manual_review_needed.append(
                    f"{statement_label} had all actions removed. "
                    "Manual review required. "
                    'Replace "TODO:specify-needed-actions" with the minimum safe actions this policy needs.'
                )

        fixed_stmt["Action"] = fixed_actions

        # ── Process resources ─────────────────────────────────────────────────
        fixed_stmt["Resource"] = stmt.get("Resource", [])
        if "*" in raw_resources:
            changes.append(FixChange(
                type="resource_wildcard_warning",
                statement_index=i,
                reason=(
                    "Resource '*' should be replaced with specific resource ARNs "
                    "for least privilege"
                ),
            ))

        if "Condition" in stmt:
            fixed_stmt["Condition"] = stmt["Condition"]

        fixed_statements.append(fixed_stmt)

    fixed_policy = {
        "Version": parsed.get("Version", "2012-10-17"),
        "Statement": fixed_statements,
    }

    fixed_policy_json = json.dumps(fixed_policy)
    fixed_risk_score = calculate_risk_score(fixed_policy_json)
    fixed_risk_level = risk_score_label(fixed_risk_score)

    return FixResult(
        original_risk_level=original_risk_level,
        fixed_risk_level=fixed_risk_level,
        fixed_policy=fixed_policy,
        changes=changes,
        manual_review_needed=manual_review_needed,
    )


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
    detected, _ = _detect_risky_actions(allowed_actions)
    risk_score = calculate_risk_score(policy_json)
    risk_level = risk_score_label(risk_score)

    # Step 2 — if no risky actions, return immediately (no Claude call)
    if not detected:
        return EscalationResult(
            risk_level=risk_level,
            detected_actions=[],
            findings=[],
            summary="No privilege escalation risks detected in this policy.",
            risk_score=risk_score,
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
        risk_score=risk_score,
    )