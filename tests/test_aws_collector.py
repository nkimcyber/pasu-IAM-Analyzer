"""
test_aws_collector.py — pytest tests for app.aws_collector.

Covers:
- Basic profile scan collects managed and inline policies
- Assume-role flow produces policies from the target account
- Graceful RuntimeError when the named profile does not exist
- Graceful RuntimeError when IAM list_policies is denied (ClientError)
- Empty account returns an empty list (no crash)

All AWS calls are intercepted by moto; no real credentials are needed.
"""

import json
from unittest.mock import MagicMock, patch

import boto3
import botocore.exceptions
import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SIMPLE_POLICY_DOC: dict = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "*",
        }
    ],
}

_ADMIN_POLICY_DOC: dict = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }
    ],
}


# ---------------------------------------------------------------------------
# Fixtures — moto-backed IAM environment
# ---------------------------------------------------------------------------


@pytest.fixture()
def moto_iam():
    """Yield a moto-mocked IAM environment with a managed policy and an inline role."""
    try:
        from moto import mock_aws
    except ImportError:
        pytest.skip("moto is not installed")

    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")

        # Create a customer-managed policy
        iam.create_policy(
            PolicyName="TestManagedPolicy",
            PolicyDocument=json.dumps(_SIMPLE_POLICY_DOC),
        )

        # Create a role with an inline policy
        iam.create_role(
            RoleName="TestRole",
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
        )
        iam.put_role_policy(
            RoleName="TestRole",
            PolicyName="TestRoleInline",
            PolicyDocument=json.dumps(_ADMIN_POLICY_DOC),
        )

        # Create a user with an inline policy
        iam.create_user(UserName="TestUser")
        iam.put_user_policy(
            UserName="TestUser",
            PolicyName="TestUserInline",
            PolicyDocument=json.dumps(_SIMPLE_POLICY_DOC),
        )

        # Create a group with an inline policy
        iam.create_group(GroupName="TestGroup")
        iam.put_group_policy(
            GroupName="TestGroup",
            PolicyName="TestGroupInline",
            PolicyDocument=json.dumps(_SIMPLE_POLICY_DOC),
        )

        yield iam


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_collect_managed_policy(moto_iam: "botocore.client.IAM") -> None:
    """Managed customer policy is collected with the correct source tag."""
    from app.aws_collector import _collect_managed_policies

    results = _collect_managed_policies(moto_iam)

    assert len(results) == 1
    policy = results[0]
    assert policy.source == "managed"
    assert "TestManagedPolicy" in policy.name
    # The policy_json must be valid JSON and match the original document
    doc = json.loads(policy.policy_json)
    assert doc["Statement"][0]["Action"] == ["s3:GetObject"]


def test_collect_role_inline_policy(moto_iam: "botocore.client.IAM") -> None:
    """Inline role policies are collected with the correct source tag."""
    from app.aws_collector import _collect_role_policies

    results = _collect_role_policies(moto_iam)

    assert len(results) == 1
    policy = results[0]
    assert policy.source == "inline:role"
    assert "TestRole" in policy.name
    assert "TestRoleInline" in policy.name
    doc = json.loads(policy.policy_json)
    assert doc["Statement"][0]["Action"] == "*"


def test_collect_user_inline_policy(moto_iam: "botocore.client.IAM") -> None:
    """Inline user policies are collected with the correct source tag."""
    from app.aws_collector import _collect_user_policies

    results = _collect_user_policies(moto_iam)

    assert len(results) == 1
    policy = results[0]
    assert policy.source == "inline:user"
    assert "TestUser" in policy.name


def test_collect_group_inline_policy(moto_iam: "botocore.client.IAM") -> None:
    """Inline group policies are collected with the correct source tag."""
    from app.aws_collector import _collect_group_policies

    results = _collect_group_policies(moto_iam)

    assert len(results) == 1
    policy = results[0]
    assert policy.source == "inline:group"
    assert "TestGroup" in policy.name


def test_collect_account_policies_basic(moto_iam: "botocore.client.IAM") -> None:
    """collect_account_policies returns all policy types from the account."""
    try:
        from moto import mock_aws
    except ImportError:
        pytest.skip("moto is not installed")

    from app.aws_collector import collect_account_policies

    with mock_aws():
        # Re-create the full environment inside collect_account_policies's mocked session
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_policy(
            PolicyName="AnotherManagedPolicy",
            PolicyDocument=json.dumps(_SIMPLE_POLICY_DOC),
        )
        iam.create_role(
            RoleName="AnotherRole",
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
        )
        iam.put_role_policy(
            RoleName="AnotherRole",
            PolicyName="AnotherRoleInline",
            PolicyDocument=json.dumps(_ADMIN_POLICY_DOC),
        )

        # Patch _make_session to return a session that hits the mocked IAM
        real_session = boto3.Session(
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
            aws_session_token="testing",
            region_name="us-east-1",
        )

        with patch("app.aws_collector._make_session", return_value=real_session):
            results = collect_account_policies(profile_name="fake-profile")

    # Managed + inline role → at least 2 results
    assert len(results) >= 2
    sources = {p.source for p in results}
    assert "managed" in sources
    assert "inline:role" in sources


def test_collect_account_policies_assume_role() -> None:
    """When role_arn is provided, _assume_role is called and its session is used."""
    mock_session_after_assume = MagicMock()
    mock_iam_client = MagicMock()

    # Simulate paginator responses returning empty pages (no policies)
    empty_paginator = MagicMock()
    empty_paginator.paginate.return_value = iter([{"Policies": []}])
    empty_role_paginator = MagicMock()
    empty_role_paginator.paginate.return_value = iter([{"Roles": []}])
    empty_user_paginator = MagicMock()
    empty_user_paginator.paginate.return_value = iter([{"Users": []}])
    empty_group_paginator = MagicMock()
    empty_group_paginator.paginate.return_value = iter([{"Groups": []}])

    def _paginator_dispatch(name: str):
        if name == "list_policies":
            return empty_paginator
        if name == "list_roles":
            return empty_role_paginator
        if name == "list_users":
            return empty_user_paginator
        if name == "list_groups":
            return empty_group_paginator
        raise ValueError(f"Unexpected paginator: {name}")

    mock_iam_client.get_paginator.side_effect = _paginator_dispatch
    mock_session_after_assume.client.return_value = mock_iam_client

    with (
        patch("app.aws_collector._make_session") as mock_make,
        patch("app.aws_collector._assume_role", return_value=mock_session_after_assume) as mock_assume,
    ):
        from app.aws_collector import collect_account_policies

        results = collect_account_policies(
            profile_name="base-profile",
            role_arn="arn:aws:iam::999999999999:role/CrossAccountRole",
        )

    mock_make.assert_called_once_with("base-profile")
    mock_assume.assert_called_once()
    # Both the STS client (for account-ID lookup) and the IAM client must be
    # created from the post-assume session.
    mock_session_after_assume.client.assert_any_call("sts")
    mock_session_after_assume.client.assert_any_call("iam")
    assert results == []


def test_profile_not_found_raises_runtime_error() -> None:
    """_make_session raises RuntimeError when the profile does not exist."""
    from app.aws_collector import _make_session

    with pytest.raises(RuntimeError, match="not found"):
        # Use a profile name that will never exist in the test environment.
        # boto3.Session with a non-existent profile raises ProfileNotFound.
        _make_session("__pasu_nonexistent_profile_xyz__")


def test_make_session_none_credentials_raises_runtime_error() -> None:
    """_make_session raises RuntimeError when get_credentials() returns None.

    This covers profiles that exist in config but have no resolvable credentials
    (e.g. expired SSO session, missing credential_process binary, incomplete
    static configuration).  Previously the None propagated to the first API
    call and surfaced as an unhandled botocore traceback.
    """
    from app.aws_collector import _make_session

    mock_session = MagicMock()
    mock_session.get_credentials.return_value = None

    with (
        patch("app.aws_collector.boto3.Session", return_value=mock_session),
        pytest.raises(RuntimeError, match="No credentials found for profile"),
    ):
        _make_session("sso-expired-profile")


def test_make_session_valid_credentials_returns_session() -> None:
    """_make_session returns the session when credentials are present.

    Ensures that the None-check does not accidentally reject a session whose
    get_credentials() returns a non-None Credentials object.
    """
    from app.aws_collector import _make_session

    mock_session = MagicMock()
    mock_creds = MagicMock()  # non-None sentinel
    mock_session.get_credentials.return_value = mock_creds

    with patch("app.aws_collector.boto3.Session", return_value=mock_session):
        result = _make_session("valid-profile")

    assert result is mock_session


def test_assume_role_client_error_raises_runtime_error() -> None:
    """_assume_role raises RuntimeError when STS returns a ClientError."""
    from app.aws_collector import _assume_role

    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_session.client.return_value = mock_sts

    error_response = {
        "Error": {"Code": "AccessDenied", "Message": "User is not authorized"}
    }
    mock_sts.assume_role.side_effect = botocore.exceptions.ClientError(
        error_response, "AssumeRole"
    )

    with pytest.raises(RuntimeError, match="Could not assume role"):
        _assume_role(mock_session, "arn:aws:iam::123456789012:role/Denied")


def test_collect_managed_policies_permission_denied_raises() -> None:
    """_collect_managed_policies raises RuntimeError on list_policies AccessDenied."""
    from app.aws_collector import _collect_managed_policies

    mock_iam = MagicMock()
    mock_paginator = MagicMock()
    error_response = {
        "Error": {"Code": "AccessDenied", "Message": "Denied"}
    }
    mock_paginator.paginate.side_effect = botocore.exceptions.ClientError(
        error_response, "ListPolicies"
    )
    mock_iam.get_paginator.return_value = mock_paginator

    with pytest.raises(RuntimeError, match="IAM list_policies failed"):
        _collect_managed_policies(mock_iam)


def test_empty_account_returns_empty_list() -> None:
    """An account with no policies or principals returns an empty list, not an error."""
    mock_session = MagicMock()
    mock_iam = MagicMock()
    mock_session.client.return_value = mock_iam

    def _empty_paginator(name: str):
        pager = MagicMock()
        key_map = {
            "list_policies": "Policies",
            "list_roles": "Roles",
            "list_users": "Users",
            "list_groups": "Groups",
        }
        pager.paginate.return_value = iter([{key_map[name]: []}])
        return pager

    mock_iam.get_paginator.side_effect = _empty_paginator

    with (
        patch("app.aws_collector._make_session", return_value=mock_session),
    ):
        from app.aws_collector import collect_account_policies

        results = collect_account_policies(profile_name="empty-profile")

    assert results == []


# ---------------------------------------------------------------------------
# Security regression tests — CVE: AssumeRole ClientError leaks caller ARN
# ---------------------------------------------------------------------------


def test_assume_role_error_message_does_not_leak_aws_error_body() -> None:
    """RuntimeError message must NOT contain the raw ClientError body.

    STS AssumeRole failure responses include the caller's account ID and ARN
    in the error body (e.g. 'User: arn:aws:iam::123456789012:user/foo is not
    authorized...'). Embedding {exc} in the RuntimeError message would surface
    this sensitive identity data to stdout/stderr and JSON output.
    """
    from app.aws_collector import _assume_role

    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_session.client.return_value = mock_sts

    # Simulate an AWS error body containing a caller ARN — the attacker-visible string.
    sensitive_message = (
        "User: arn:aws:iam::123456789012:user/alice is not authorized "
        "to perform: sts:AssumeRole on resource: arn:aws:iam::999:role/Target"
    )
    error_response = {
        "Error": {"Code": "AccessDenied", "Message": sensitive_message}
    }
    mock_sts.assume_role.side_effect = botocore.exceptions.ClientError(
        error_response, "AssumeRole"
    )

    with pytest.raises(RuntimeError) as exc_info:
        _assume_role(mock_session, "arn:aws:iam::999:role/Target")

    raised_message = str(exc_info.value)
    # The raw AWS error body (containing account ID and ARN) must NOT appear.
    assert "123456789012" not in raised_message, (
        "Account ID leaked into RuntimeError message"
    )
    assert "alice" not in raised_message, "Caller username leaked into RuntimeError message"
    assert sensitive_message not in raised_message, (
        "Raw AWS error body leaked into RuntimeError message"
    )


def test_assume_role_error_message_is_safe_static_string() -> None:
    """RuntimeError message must be the safe static guidance string, not raw exc.

    Asserts the exact safe wording that provides actionable guidance to the
    operator without disclosing any AWS API response content.
    """
    from app.aws_collector import _assume_role

    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_session.client.return_value = mock_sts

    role_arn = "arn:aws:iam::123456789012:role/MyRole"
    error_response = {
        "Error": {"Code": "AccessDenied", "Message": "User is not authorized"}
    }
    mock_sts.assume_role.side_effect = botocore.exceptions.ClientError(
        error_response, "AssumeRole"
    )

    with pytest.raises(RuntimeError) as exc_info:
        _assume_role(mock_session, role_arn)

    raised_message = str(exc_info.value)
    assert "check permissions and role ARN" in raised_message
    assert role_arn in raised_message


def test_assume_role_exception_chain_is_preserved() -> None:
    """RuntimeError must chain the original ClientError for traceback fidelity.

    The `from exc` chain must be intact so that operators inspecting tracebacks
    or log output can still diagnose the root STS error — even though it is not
    exposed to end users via the message string.
    """
    from app.aws_collector import _assume_role

    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_session.client.return_value = mock_sts

    error_response = {
        "Error": {"Code": "AccessDenied", "Message": "Not authorized"}
    }
    original_exc = botocore.exceptions.ClientError(error_response, "AssumeRole")
    mock_sts.assume_role.side_effect = original_exc

    with pytest.raises(RuntimeError) as exc_info:
        _assume_role(mock_session, "arn:aws:iam::123456789012:role/Target")

    assert exc_info.value.__cause__ is original_exc, (
        "Exception chain broken: RuntimeError.__cause__ must be the original ClientError"
    )


def test_collect_account_policies_no_role_skips_assume() -> None:
    """When role_arn is None, _assume_role is never called."""
    mock_session = MagicMock()
    mock_iam = MagicMock()
    mock_session.client.return_value = mock_iam

    def _empty_paginator(name: str):
        pager = MagicMock()
        key_map = {
            "list_policies": "Policies",
            "list_roles": "Roles",
            "list_users": "Users",
            "list_groups": "Groups",
        }
        pager.paginate.return_value = iter([{key_map[name]: []}])
        return pager

    mock_iam.get_paginator.side_effect = _empty_paginator

    with (
        patch("app.aws_collector._make_session", return_value=mock_session),
        patch("app.aws_collector._assume_role") as mock_assume,
    ):
        from app.aws_collector import collect_account_policies

        collect_account_policies(profile_name="my-profile", role_arn=None)

    mock_assume.assert_not_called()


# ---------------------------------------------------------------------------
# Policy ARN construction — _get_account_id and _build_policy_arn
# ---------------------------------------------------------------------------


def test_get_account_id_returns_account_string() -> None:
    """_get_account_id returns the account ID string on a successful STS call."""
    from app.aws_collector import _get_account_id

    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}
    mock_session.client.return_value = mock_sts

    account_id = _get_account_id(mock_session)

    assert account_id == "123456789012"
    mock_session.client.assert_called_once_with("sts")


def test_get_account_id_returns_none_on_client_error() -> None:
    """_get_account_id returns None silently when STS raises ClientError."""
    from app.aws_collector import _get_account_id

    mock_session = MagicMock()
    mock_sts = MagicMock()
    error_response = {"Error": {"Code": "AccessDenied", "Message": "Denied"}}
    mock_sts.get_caller_identity.side_effect = botocore.exceptions.ClientError(
        error_response, "GetCallerIdentity"
    )
    mock_session.client.return_value = mock_sts

    account_id = _get_account_id(mock_session)

    assert account_id is None


def test_get_account_id_returns_none_on_no_credentials_error() -> None:
    """_get_account_id returns None silently when credentials are absent.

    botocore.exceptions.NoCredentialsError is a BotoCoreError subclass but NOT
    a ClientError subclass.  The previous implementation only caught ClientError,
    so this case would propagate as an unhandled exception and crash the caller.
    """
    from app.aws_collector import _get_account_id

    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.side_effect = botocore.exceptions.NoCredentialsError()
    mock_session.client.return_value = mock_sts

    account_id = _get_account_id(mock_session)

    assert account_id is None


def test_get_account_id_returns_none_on_endpoint_connection_error() -> None:
    """_get_account_id returns None silently when the STS endpoint is unreachable.

    botocore.exceptions.EndpointConnectionError is a BotoCoreError subclass but
    NOT a ClientError subclass (it is raised before an HTTP response exists).
    The previous implementation would let this propagate unhandled.
    """
    from app.aws_collector import _get_account_id

    mock_session = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.side_effect = (
        botocore.exceptions.EndpointConnectionError(endpoint_url="https://sts.amazonaws.com")
    )
    mock_session.client.return_value = mock_sts

    account_id = _get_account_id(mock_session)

    assert account_id is None


def test_build_policy_arn_role_inline() -> None:
    """_build_policy_arn constructs the correct ARN for an inline role policy."""
    from app.aws_collector import _build_policy_arn

    arn = _build_policy_arn("inline:role", "MyRole", "MyPolicy", "123456789012")
    assert arn == "arn:aws:iam::123456789012:role/MyRole/policy/MyPolicy"


def test_build_policy_arn_user_inline() -> None:
    """_build_policy_arn constructs the correct ARN for an inline user policy."""
    from app.aws_collector import _build_policy_arn

    arn = _build_policy_arn("inline:user", "alice", "AlicePolicy", "123456789012")
    assert arn == "arn:aws:iam::123456789012:user/alice/policy/AlicePolicy"


def test_build_policy_arn_group_inline() -> None:
    """_build_policy_arn constructs the correct ARN for an inline group policy."""
    from app.aws_collector import _build_policy_arn

    arn = _build_policy_arn("inline:group", "Devs", "DevPolicy", "123456789012")
    assert arn == "arn:aws:iam::123456789012:group/Devs/policy/DevPolicy"


def test_managed_policy_policy_arn_equals_arn(moto_iam: "botocore.client.IAM") -> None:
    """For managed policies, policy_arn is set to the same value as the AWS ARN."""
    from app.aws_collector import _collect_managed_policies

    results = _collect_managed_policies(moto_iam)

    assert len(results) == 1
    policy = results[0]
    assert policy.policy_arn != ""
    assert policy.policy_arn == policy.arn
    assert policy.policy_arn.startswith("arn:aws:iam::")
    assert "TestManagedPolicy" in policy.policy_arn


def test_inline_role_policy_arn_constructed_with_account_id(
    moto_iam: "botocore.client.IAM",
) -> None:
    """Inline role policy_arn is constructed from account_id when provided."""
    from app.aws_collector import _collect_role_policies

    results = _collect_role_policies(moto_iam, account_id="123456789012")

    assert len(results) == 1
    policy = results[0]
    assert policy.policy_arn == (
        "arn:aws:iam::123456789012:role/TestRole/policy/TestRoleInline"
    )


def test_inline_role_policy_arn_empty_without_account_id(
    moto_iam: "botocore.client.IAM",
) -> None:
    """Inline role policy_arn is empty string when no account_id is available."""
    from app.aws_collector import _collect_role_policies

    results = _collect_role_policies(moto_iam, account_id=None)

    assert len(results) == 1
    assert results[0].policy_arn == ""


def test_collect_account_policies_propagates_account_id() -> None:
    """collect_account_policies calls _get_account_id and passes it to collectors."""
    mock_session = MagicMock()
    mock_iam = MagicMock()
    mock_session.client.return_value = mock_iam

    def _empty_paginator(name: str):
        pager = MagicMock()
        key_map = {
            "list_policies": "Policies",
            "list_roles": "Roles",
            "list_users": "Users",
            "list_groups": "Groups",
        }
        pager.paginate.return_value = iter([{key_map[name]: []}])
        return pager

    mock_iam.get_paginator.side_effect = _empty_paginator

    with (
        patch("app.aws_collector._make_session", return_value=mock_session),
        patch(
            "app.aws_collector._get_account_id", return_value="999888777666"
        ) as mock_get_id,
    ):
        from app.aws_collector import collect_account_policies

        collect_account_policies(profile_name="my-profile")

    mock_get_id.assert_called_once_with(mock_session)


def test_collect_account_policies_sts_failure_does_not_crash() -> None:
    """When _get_account_id returns None, collect_account_policies still succeeds."""
    mock_session = MagicMock()
    mock_iam = MagicMock()
    mock_session.client.return_value = mock_iam

    def _empty_paginator(name: str):
        pager = MagicMock()
        key_map = {
            "list_policies": "Policies",
            "list_roles": "Roles",
            "list_users": "Users",
            "list_groups": "Groups",
        }
        pager.paginate.return_value = iter([{key_map[name]: []}])
        return pager

    mock_iam.get_paginator.side_effect = _empty_paginator

    with (
        patch("app.aws_collector._make_session", return_value=mock_session),
        patch("app.aws_collector._get_account_id", return_value=None),
    ):
        from app.aws_collector import collect_account_policies

        # Must not raise even though account_id is unavailable
        results = collect_account_policies(profile_name="my-profile")

    assert results == []


# ---------------------------------------------------------------------------
# Security regression tests — _build_policy_arn account_id format validation
# ---------------------------------------------------------------------------


def test_build_policy_arn_valid_12_digit_account_id() -> None:
    """_build_policy_arn returns a well-formed ARN for a valid 12-digit account ID."""
    from app.aws_collector import _build_policy_arn

    arn = _build_policy_arn("inline:role", "MyRole", "MyPolicy", "123456789012")

    assert arn == "arn:aws:iam::123456789012:role/MyRole/policy/MyPolicy"


def test_build_policy_arn_invalid_account_id_returns_empty_string() -> None:
    """_build_policy_arn returns '' when account_id is not a 12-digit string.

    This is the vulnerable case: previously any non-empty string was interpolated
    directly into the ARN, silently producing a corrupt ARN.
    """
    from app.aws_collector import _build_policy_arn

    arn = _build_policy_arn("inline:role", "MyRole", "MyPolicy", "bad-value")

    assert arn == ""


def test_build_policy_arn_11_digits_returns_empty_string() -> None:
    """_build_policy_arn returns '' for an 11-digit account ID (too short)."""
    from app.aws_collector import _build_policy_arn

    arn = _build_policy_arn("inline:role", "MyRole", "MyPolicy", "12345678901")

    assert arn == ""


def test_build_policy_arn_13_digits_returns_empty_string() -> None:
    """_build_policy_arn returns '' for a 13-digit account ID (too long)."""
    from app.aws_collector import _build_policy_arn

    arn = _build_policy_arn("inline:role", "MyRole", "MyPolicy", "1234567890123")

    assert arn == ""


def test_build_policy_arn_alphanumeric_returns_empty_string() -> None:
    """_build_policy_arn returns '' when account_id contains non-digit characters."""
    from app.aws_collector import _build_policy_arn

    arn = _build_policy_arn("inline:user", "alice", "AlicePolicy", "1234abcd5678")

    assert arn == ""


def test_build_policy_arn_empty_string_returns_empty_string() -> None:
    """_build_policy_arn returns '' for an empty account_id string."""
    from app.aws_collector import _build_policy_arn

    arn = _build_policy_arn("inline:group", "Devs", "DevPolicy", "")

    assert arn == ""


def test_build_policy_arn_all_zeros_is_valid_format() -> None:
    """_build_policy_arn accepts '000000000000' — structurally valid 12 digits.

    AWS reserves this for certain test/sandbox contexts; the format check must
    not reject it on value grounds, only on structural grounds.
    """
    from app.aws_collector import _build_policy_arn

    arn = _build_policy_arn("inline:role", "MyRole", "MyPolicy", "000000000000")

    assert arn == "arn:aws:iam::000000000000:role/MyRole/policy/MyPolicy"


def test_build_policy_arn_invalid_does_not_produce_corrupt_arn() -> None:
    """A malformed account_id must never appear in the returned ARN string.

    This is the core security property: no corrupt ARN must be emitted.
    """
    from app.aws_collector import _build_policy_arn

    malformed_inputs = [
        "bad-value",
        "12345",
        "1234567890123",
        "abcdefghijkl",
        "12345678901a",
        " 123456789012",  # leading space
        "123456789012 ",  # trailing space
        "123456789012\n",  # newline
    ]
    for bad_id in malformed_inputs:
        result = _build_policy_arn("inline:role", "R", "P", bad_id)
        assert result == "", (
            f"Expected '' for account_id={bad_id!r}, got {result!r}"
        )
        assert bad_id not in result, (
            f"Malformed account_id {bad_id!r} leaked into ARN output"
        )
