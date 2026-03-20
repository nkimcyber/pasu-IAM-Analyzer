"""
aws_collector.py — Read-only AWS IAM data collector for profile-based scanning.

Collects users, roles, groups, managed policies, and inline policies from a live
AWS account using boto3 with read-only IAM permissions (iam:Get*, iam:List* only).
Returns policy documents in the JSON string format that the existing scan pipeline
(explain_policy_local / escalate_policy_local) expects.
"""

import json
import logging
import re
from dataclasses import dataclass

import boto3
import botocore.exceptions

logger = logging.getLogger(__name__)


@dataclass
class CollectedPolicy:
    """A single IAM policy document collected from AWS, ready for scanning.

    Attributes:
        name: Human-readable identifier (e.g. 'role/MyRole [inline: AssumePolicy]').
        source: Origin descriptor (e.g. 'managed', 'inline:role', 'inline:user').
        arn: ARN of the managed policy, or empty string for inline policies.
        policy_json: IAM policy document serialised as a JSON string.
        policy_arn: Constructed ARN for the policy resource (role, user, or inline
            policy path). Empty string when account ID is unavailable or in
            --file mode.
    """

    name: str
    source: str
    arn: str
    policy_json: str
    policy_arn: str = ""


def _make_session(profile_name: str) -> boto3.Session:
    """Create a boto3 Session for the given named profile.

    Args:
        profile_name: AWS CLI profile name (must exist in ~/.aws/config).

    Returns:
        Configured boto3 Session.

    Raises:
        RuntimeError: If the profile does not exist or has no resolvable
            credentials (e.g. expired SSO session, missing credential_process
            binary, or incomplete static configuration).
    """
    try:
        session = boto3.Session(profile_name=profile_name)
        # Eagerly validate that the profile is resolvable by touching credentials.
        # ProfileNotFound is raised here, not on the first API call.
        creds = session.get_credentials()
    except botocore.exceptions.ProfileNotFound as exc:
        logger.error("AWS profile '%s' not found: %s", profile_name, exc)
        raise RuntimeError(
            f"AWS profile '{profile_name}' not found. "
            "Check your ~/.aws/config file."
        ) from exc

    if creds is None:
        logger.error(
            "No credentials found for AWS profile '%s'", profile_name
        )
        raise RuntimeError(
            f"No credentials found for profile '{profile_name}'. "
            "Ensure the profile is configured with valid credentials "
            "(e.g. check for an expired SSO session or missing "
            "credential_process binary)."
        )

    return session


def _assume_role(session: boto3.Session, role_arn: str) -> boto3.Session:
    """Assume an IAM role via STS and return a new Session using temporary credentials.

    Args:
        session: Base session used to call sts:AssumeRole.
        role_arn: Full ARN of the role to assume.

    Returns:
        New boto3 Session backed by temporary credentials.

    Raises:
        RuntimeError: On STS ClientError (e.g. access denied, invalid ARN).
    """
    sts = session.client("sts")
    try:
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="pasu-scan",
        )
    except botocore.exceptions.ClientError as exc:
        logger.error("Failed to assume role '%s': %s", role_arn, exc)
        raise RuntimeError(
            f"Could not assume role '{role_arn}': check permissions and role ARN."
        ) from exc

    creds = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


# ── Account identity ──────────────────────────────────────────────────────────


def _get_account_id(session: boto3.Session) -> str | None:
    """Retrieve the AWS account ID for the active session via STS.

    Called once per scan session so that ARNs can be constructed for inline
    policies (which have no pre-existing ARN in the IAM API response).

    Args:
        session: An active boto3 Session whose credentials will be used.

    Returns:
        The 12-digit AWS account ID string, or None if the STS call fails
        (e.g. sts:GetCallerIdentity is denied or network is unreachable).
        Callers should treat None as "account ID unavailable" and omit ARNs.
    """
    try:
        sts = session.client("sts")
        response = sts.get_caller_identity()
        return str(response["Account"])
    except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as exc:
        logger.warning("Failed to retrieve account ID via STS: %s", exc)
        return None


def _build_policy_arn(
    source: str,
    resource_name: str,
    policy_name: str,
    account_id: str,
) -> str:
    """Construct the IAM ARN for a policy resource given its source type.

    ARN formats:
        managed:      returned as-is from the AWS API (caller passes it directly).
        inline:role:  arn:aws:iam::{account_id}:role/{resource_name}/policy/{policy_name}
        inline:user:  arn:aws:iam::{account_id}:user/{resource_name}/policy/{policy_name}
        inline:group: arn:aws:iam::{account_id}:group/{resource_name}/policy/{policy_name}

    Args:
        source: Policy source tag ('inline:role', 'inline:user', 'inline:group').
        resource_name: Name of the IAM role, user, or group that owns the inline policy.
        policy_name: Name of the inline policy document.
        account_id: 12-digit AWS account ID. Must be exactly 12 decimal digits;
            any other value causes the function to return "" rather than emit a
            corrupt ARN.

    Returns:
        Constructed ARN string, or "" if account_id is not a valid 12-digit
        numeric string.
    """
    if not re.fullmatch(r"\d{12}", account_id):
        return ""
    type_map = {
        "inline:role": "role",
        "inline:user": "user",
        "inline:group": "group",
    }
    resource_type = type_map.get(source, "role")
    return (
        f"arn:aws:iam::{account_id}:{resource_type}"
        f"/{resource_name}/policy/{policy_name}"
    )


# ── Managed policy collection ─────────────────────────────────────────────────


def _collect_managed_policies(
    iam: "botocore.client.IAM",
) -> list[CollectedPolicy]:
    """Collect all customer-managed IAM policies and their default documents.

    For managed policies the ARN is returned directly from the AWS API, so
    ``policy_arn`` is set to that same value.

    Args:
        iam: A boto3 IAM client.

    Returns:
        List of CollectedPolicy for each customer-managed policy.

    Raises:
        RuntimeError: On IAM ClientError.
    """
    collected: list[CollectedPolicy] = []
    paginator = iam.get_paginator("list_policies")
    try:
        pages = paginator.paginate(Scope="Local")
        for page in pages:
            for policy_meta in page.get("Policies", []):
                arn: str = policy_meta["Arn"]
                name: str = policy_meta["PolicyName"]
                version_id: str = policy_meta["DefaultVersionId"]
                try:
                    doc_response = iam.get_policy_version(
                        PolicyArn=arn, VersionId=version_id
                    )
                    document: dict = doc_response["PolicyVersion"]["Document"]
                    collected.append(
                        CollectedPolicy(
                            name=f"managed/{name}",
                            source="managed",
                            arn=arn,
                            policy_json=json.dumps(document),
                            policy_arn=arn,
                        )
                    )
                except botocore.exceptions.ClientError as exc:
                    logger.error(
                        "Skipping managed policy '%s' — cannot fetch document: %s",
                        arn,
                        exc,
                    )
    except botocore.exceptions.ClientError as exc:
        logger.error("Failed to list managed policies: %s", exc)
        raise RuntimeError("IAM list_policies failed") from exc

    return collected


# ── Inline policy collection helpers ─────────────────────────────────────────


def _fetch_role_inline_policies(
    iam: "botocore.client.IAM",
    role_name: str,
    account_id: str | None = None,
) -> list[CollectedPolicy]:
    """Fetch all inline policies attached to an IAM role.

    Args:
        iam: A boto3 IAM client.
        role_name: Name of the IAM role.
        account_id: AWS account ID used to construct policy_arn. When None,
            policy_arn is left as an empty string.

    Returns:
        List of CollectedPolicy for each inline policy on the role.
    """
    collected: list[CollectedPolicy] = []
    try:
        response = iam.list_role_policies(RoleName=role_name)
        for policy_name in response.get("PolicyNames", []):
            try:
                doc_response = iam.get_role_policy(
                    RoleName=role_name, PolicyName=policy_name
                )
                document: dict = doc_response["PolicyDocument"]
                constructed_arn = (
                    _build_policy_arn("inline:role", role_name, policy_name, account_id)
                    if account_id
                    else ""
                )
                collected.append(
                    CollectedPolicy(
                        name=f"role/{role_name} [inline: {policy_name}]",
                        source="inline:role",
                        arn="",
                        policy_json=json.dumps(document),
                        policy_arn=constructed_arn,
                    )
                )
            except botocore.exceptions.ClientError as exc:
                logger.error(
                    "Skipping inline policy '%s' on role '%s': %s",
                    policy_name,
                    role_name,
                    exc,
                )
    except botocore.exceptions.ClientError as exc:
        logger.error(
            "Skipping inline policy listing for role '%s': %s", role_name, exc
        )
    return collected


def _fetch_user_inline_policies(
    iam: "botocore.client.IAM",
    user_name: str,
    account_id: str | None = None,
) -> list[CollectedPolicy]:
    """Fetch all inline policies attached to an IAM user.

    Args:
        iam: A boto3 IAM client.
        user_name: Name of the IAM user.
        account_id: AWS account ID used to construct policy_arn. When None,
            policy_arn is left as an empty string.

    Returns:
        List of CollectedPolicy for each inline policy on the user.
    """
    collected: list[CollectedPolicy] = []
    try:
        response = iam.list_user_policies(UserName=user_name)
        for policy_name in response.get("PolicyNames", []):
            try:
                doc_response = iam.get_user_policy(
                    UserName=user_name, PolicyName=policy_name
                )
                document: dict = doc_response["PolicyDocument"]
                constructed_arn = (
                    _build_policy_arn("inline:user", user_name, policy_name, account_id)
                    if account_id
                    else ""
                )
                collected.append(
                    CollectedPolicy(
                        name=f"user/{user_name} [inline: {policy_name}]",
                        source="inline:user",
                        arn="",
                        policy_json=json.dumps(document),
                        policy_arn=constructed_arn,
                    )
                )
            except botocore.exceptions.ClientError as exc:
                logger.error(
                    "Skipping inline policy '%s' on user '%s': %s",
                    policy_name,
                    user_name,
                    exc,
                )
    except botocore.exceptions.ClientError as exc:
        logger.error(
            "Skipping inline policy listing for user '%s': %s", user_name, exc
        )
    return collected


def _fetch_group_inline_policies(
    iam: "botocore.client.IAM",
    group_name: str,
    account_id: str | None = None,
) -> list[CollectedPolicy]:
    """Fetch all inline policies attached to an IAM group.

    Args:
        iam: A boto3 IAM client.
        group_name: Name of the IAM group.
        account_id: AWS account ID used to construct policy_arn. When None,
            policy_arn is left as an empty string.

    Returns:
        List of CollectedPolicy for each inline policy on the group.
    """
    collected: list[CollectedPolicy] = []
    try:
        response = iam.list_group_policies(GroupName=group_name)
        for policy_name in response.get("PolicyNames", []):
            try:
                doc_response = iam.get_group_policy(
                    GroupName=group_name, PolicyName=policy_name
                )
                document: dict = doc_response["PolicyDocument"]
                constructed_arn = (
                    _build_policy_arn(
                        "inline:group", group_name, policy_name, account_id
                    )
                    if account_id
                    else ""
                )
                collected.append(
                    CollectedPolicy(
                        name=f"group/{group_name} [inline: {policy_name}]",
                        source="inline:group",
                        arn="",
                        policy_json=json.dumps(document),
                        policy_arn=constructed_arn,
                    )
                )
            except botocore.exceptions.ClientError as exc:
                logger.error(
                    "Skipping inline policy '%s' on group '%s': %s",
                    policy_name,
                    group_name,
                    exc,
                )
    except botocore.exceptions.ClientError as exc:
        logger.error(
            "Skipping inline policy listing for group '%s': %s", group_name, exc
        )
    return collected


# ── Role / user / group collectors ───────────────────────────────────────────


def _collect_role_policies(
    iam: "botocore.client.IAM",
    account_id: str | None = None,
) -> list[CollectedPolicy]:
    """Collect inline policies from all IAM roles in the account.

    Args:
        iam: A boto3 IAM client.
        account_id: AWS account ID used to construct policy_arn values. When
            None, policy_arn fields are left as empty strings.

    Returns:
        List of CollectedPolicy for each inline role policy found.

    Raises:
        RuntimeError: If the initial list_roles call fails.
    """
    collected: list[CollectedPolicy] = []
    paginator = iam.get_paginator("list_roles")
    try:
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                collected.extend(
                    _fetch_role_inline_policies(iam, role["RoleName"], account_id)
                )
    except botocore.exceptions.ClientError as exc:
        logger.error("Failed to list IAM roles: %s", exc)
        raise RuntimeError("IAM list_roles failed") from exc
    return collected


def _collect_user_policies(
    iam: "botocore.client.IAM",
    account_id: str | None = None,
) -> list[CollectedPolicy]:
    """Collect inline policies from all IAM users in the account.

    Args:
        iam: A boto3 IAM client.
        account_id: AWS account ID used to construct policy_arn values. When
            None, policy_arn fields are left as empty strings.

    Returns:
        List of CollectedPolicy for each inline user policy found.

    Raises:
        RuntimeError: If the initial list_users call fails.
    """
    collected: list[CollectedPolicy] = []
    paginator = iam.get_paginator("list_users")
    try:
        for page in paginator.paginate():
            for user in page.get("Users", []):
                collected.extend(
                    _fetch_user_inline_policies(iam, user["UserName"], account_id)
                )
    except botocore.exceptions.ClientError as exc:
        logger.error("Failed to list IAM users: %s", exc)
        raise RuntimeError("IAM list_users failed") from exc
    return collected


def _collect_group_policies(
    iam: "botocore.client.IAM",
    account_id: str | None = None,
) -> list[CollectedPolicy]:
    """Collect inline policies from all IAM groups in the account.

    Args:
        iam: A boto3 IAM client.
        account_id: AWS account ID used to construct policy_arn values. When
            None, policy_arn fields are left as empty strings.

    Returns:
        List of CollectedPolicy for each inline group policy found.

    Raises:
        RuntimeError: If the initial list_groups call fails.
    """
    collected: list[CollectedPolicy] = []
    paginator = iam.get_paginator("list_groups")
    try:
        for page in paginator.paginate():
            for group in page.get("Groups", []):
                collected.extend(
                    _fetch_group_inline_policies(iam, group["GroupName"], account_id)
                )
    except botocore.exceptions.ClientError as exc:
        logger.error("Failed to list IAM groups: %s", exc)
        raise RuntimeError("IAM list_groups failed") from exc
    return collected


# ── Public entry point ────────────────────────────────────────────────────────


def collect_account_policies(
    profile_name: str,
    role_arn: str | None = None,
) -> list[CollectedPolicy]:
    """Collect all IAM policy documents from an AWS account using a named profile.

    Uses only read-only IAM calls (iam:Get*, iam:List*) and optional
    sts:AssumeRole for cross-account access.

    Collects:
    - Customer-managed policies (default version document)
    - Inline policies on roles, users, and groups

    Args:
        profile_name: AWS CLI profile name to use for authentication.
        role_arn: Optional IAM role ARN to assume before collecting. Useful for
            cross-account scanning. If omitted, the profile credentials are used
            directly.

    Returns:
        List of CollectedPolicy objects, one per policy document found. Empty
        list if the account has no customer-managed or inline policies.

    Raises:
        RuntimeError: If the profile is not found, role assumption fails, or a
            critical IAM list call is denied.
    """
    session = _make_session(profile_name)

    if role_arn:
        session = _assume_role(session, role_arn)

    # Fetch account ID once per session for ARN construction.
    # Failure is non-fatal: inline policy ARNs are omitted if unavailable.
    account_id: str | None = _get_account_id(session)

    iam = session.client("iam")

    collected: list[CollectedPolicy] = []
    collected.extend(_collect_managed_policies(iam))
    collected.extend(_collect_role_policies(iam, account_id))
    collected.extend(_collect_user_policies(iam, account_id))
    collected.extend(_collect_group_policies(iam, account_id))

    logger.info(
        "Collected %d policy documents from AWS account (profile=%s, role=%s)",
        len(collected),
        profile_name,
        role_arn or "none",
    )
    return collected
