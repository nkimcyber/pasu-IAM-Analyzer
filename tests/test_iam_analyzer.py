"""
test_iam_analyzer.py — pytest test suite for the IAM Analyzer Project.

Covers:
- Pydantic model validation
- aws_client helpers (mocked boto3)
- analyzer.analyze_policy (mocked boto3 + Claude)
- analyzer.explain_policy (mocked Claude)
- FastAPI endpoints via TestClient
- CLI --format json output
"""

import argparse
import contextlib
import io
import json
import sys
from unittest.mock import MagicMock, patch


@contextlib.contextmanager
def _capture_stdout():
    """Replace sys.stdout with a StringIO buffer for the duration of the block."""
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        yield buf
    finally:
        sys.stdout = old

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import (
    AnalysisResult,
    AnalyzeRequest,
    ExplainRequest,
    ExplainResult,
    IAMPolicyResponse,
)

# ── Shared Test Constants ─────────────────────────────────────────────────────

VALID_POLICY_ARN = "arn:aws:iam::123456789012:policy/TestPolicy"
VALID_ACCOUNT_ID = "123456789012"

VALID_POLICY_JSON = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::XYZ/*",
        }
    ],
})

MOCK_POLICY_META = {
    "PolicyName": "TestPolicy",
    "PolicyId": "ANPA000000000000EXAMPLE",
    "Arn": VALID_POLICY_ARN,
    "Path": "/",
    "DefaultVersionId": "v1",
    "AttachmentCount": 1,
    "IsAttachable": True,
}

MOCK_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }
    ],
}

MOCK_CLAUDE_FINDINGS = (
    "1) Over-permissive: wildcard '*' on Action and Resource grants unrestricted access.\n"
    "2) No condition keys present — add aws:RequestedRegion or aws:PrincipalAccount.\n"
    "3) Resource scope is '*' — restrict to specific ARNs."
)

MOCK_EXPLAIN_RESPONSE = {
    "summary": "This policy allows reading files from the S3 bucket XYZ.",
    "details": [
        "Allows reading (downloading) any file stored inside the S3 bucket named XYZ."
    ],
}


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def client():
    return TestClient(app)


# ── AnalyzeRequest Model Tests ────────────────────────────────────────────────

class TestAnalyzeRequest:
    def test_valid_request(self):
        req = AnalyzeRequest(policy_arn=VALID_POLICY_ARN, account_id=VALID_ACCOUNT_ID)
        assert req.policy_arn == VALID_POLICY_ARN
        assert req.account_id == VALID_ACCOUNT_ID

    def test_missing_policy_arn_raises(self):
        with pytest.raises(Exception):
            AnalyzeRequest(account_id=VALID_ACCOUNT_ID)

    def test_missing_account_id_raises(self):
        with pytest.raises(Exception):
            AnalyzeRequest(policy_arn=VALID_POLICY_ARN)


# ── IAMPolicyResponse Model Tests ─────────────────────────────────────────────

class TestIAMPolicyResponse:
    def test_valid_model(self):
        policy = IAMPolicyResponse(**MOCK_POLICY_META)
        assert policy.Arn == VALID_POLICY_ARN
        assert policy.DefaultVersionId == "v1"
        assert policy.AttachmentCount == 1

    def test_missing_required_field_raises(self):
        incomplete = {k: v for k, v in MOCK_POLICY_META.items() if k != "PolicyName"}
        with pytest.raises(Exception):
            IAMPolicyResponse(**incomplete)


# ── AnalysisResult Model Tests ────────────────────────────────────────────────

class TestAnalysisResult:
    def test_valid_result(self):
        result = AnalysisResult(
            policy_arn=VALID_POLICY_ARN,
            findings=MOCK_CLAUDE_FINDINGS,
        )
        assert result.status == "ok"
        assert "wildcard" in result.findings

    def test_default_status_is_ok(self):
        result = AnalysisResult(
            policy_arn=VALID_POLICY_ARN,
            findings="some findings",
        )
        assert result.status == "ok"


# ── ExplainRequest Model Tests ────────────────────────────────────────────────

class TestExplainRequest:
    def test_valid_request(self):
        req = ExplainRequest(policy_json=VALID_POLICY_JSON)
        assert req.policy_json == VALID_POLICY_JSON

    def test_missing_policy_json_raises(self):
        with pytest.raises(Exception):
            ExplainRequest()


# ── ExplainResult Model Tests ─────────────────────────────────────────────────

class TestExplainResult:
    def test_valid_result(self):
        result = ExplainResult(
            summary=MOCK_EXPLAIN_RESPONSE["summary"],
            details=MOCK_EXPLAIN_RESPONSE["details"],
        )
        assert result.status == "ok"
        assert "XYZ" in result.summary
        assert len(result.details) == 1

    def test_default_status_is_ok(self):
        result = ExplainResult(summary="test", details=["detail one"])
        assert result.status == "ok"


# ── aws_client Tests ──────────────────────────────────────────────────────────

class TestGetPolicy:
    @patch("app.aws_client.get_iam_client")
    def test_returns_policy_meta(self, mock_client_fn):
        mock_iam = MagicMock()
        mock_iam.get_policy.return_value = {"Policy": MOCK_POLICY_META}
        mock_client_fn.return_value = mock_iam

        from app.aws_client import get_policy
        result = get_policy(VALID_POLICY_ARN)
        assert result["Arn"] == VALID_POLICY_ARN

    @patch("app.aws_client.get_iam_client")
    def test_raises_runtime_error_on_client_error(self, mock_client_fn):
        import botocore.exceptions
        mock_iam = MagicMock()
        mock_iam.get_policy.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "Not found"}},
            "GetPolicy",
        )
        mock_client_fn.return_value = mock_iam

        from app.aws_client import get_policy
        with pytest.raises(RuntimeError, match="IAM get_policy failed"):
            get_policy(VALID_POLICY_ARN)


class TestGetPolicyDocument:
    @patch("app.aws_client.get_iam_client")
    def test_returns_policy_document(self, mock_client_fn):
        mock_iam = MagicMock()
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {"Document": MOCK_POLICY_DOCUMENT}
        }
        mock_client_fn.return_value = mock_iam

        from app.aws_client import get_policy_document
        doc = get_policy_document(VALID_POLICY_ARN, "v1")
        assert doc["Version"] == "2012-10-17"

    @patch("app.aws_client.get_iam_client")
    def test_raises_runtime_error_on_client_error(self, mock_client_fn):
        import botocore.exceptions
        mock_iam = MagicMock()
        mock_iam.get_policy_version.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "Not found"}},
            "GetPolicyVersion",
        )
        mock_client_fn.return_value = mock_iam

        from app.aws_client import get_policy_document
        with pytest.raises(RuntimeError, match="IAM get_policy_version failed"):
            get_policy_document(VALID_POLICY_ARN, "v1")


class TestListPolicies:
    @patch("app.aws_client.get_iam_client")
    def test_returns_list_of_models(self, mock_client_fn):
        mock_iam = MagicMock()
        mock_iam.list_policies.return_value = {"Policies": [MOCK_POLICY_META]}
        mock_client_fn.return_value = mock_iam

        from app.aws_client import list_policies
        policies = list_policies()
        assert len(policies) == 1
        assert isinstance(policies[0], IAMPolicyResponse)

    @patch("app.aws_client.get_iam_client")
    def test_raises_runtime_error_on_client_error(self, mock_client_fn):
        import botocore.exceptions
        mock_iam = MagicMock()
        mock_iam.list_policies.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
            "ListPolicies",
        )
        mock_client_fn.return_value = mock_iam

        from app.aws_client import list_policies
        with pytest.raises(RuntimeError, match="IAM list_policies failed"):
            list_policies()


# ── analyzer.analyze_policy Tests ────────────────────────────────────────────

class TestAnalyzePolicy:
    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    @patch("app.analyzer.aws_client.get_policy_document")
    @patch("app.analyzer.aws_client.get_policy")
    @patch("app.analyzer.anthropic.Anthropic")
    def test_returns_analysis_result(
        self, mock_anthropic_cls, mock_get_policy, mock_get_doc
    ):
        mock_get_policy.return_value = MOCK_POLICY_META
        mock_get_doc.return_value = MOCK_POLICY_DOCUMENT

        mock_content = MagicMock()
        mock_content.text = MOCK_CLAUDE_FINDINGS
        mock_response = MagicMock()
        mock_response.content = [mock_content]
        mock_anthropic_cls.return_value.messages.create.return_value = mock_response

        from app.analyzer import analyze_policy
        result = analyze_policy(VALID_POLICY_ARN, VALID_ACCOUNT_ID)

        assert isinstance(result, AnalysisResult)
        assert result.policy_arn == VALID_POLICY_ARN
        assert "wildcard" in result.findings

    @patch.dict("os.environ", {}, clear=True)
    def test_raises_if_api_key_missing(self):
        from app.analyzer import analyze_policy
        with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
            analyze_policy(VALID_POLICY_ARN, VALID_ACCOUNT_ID)

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    @patch("app.analyzer.aws_client.get_policy")
    def test_raises_on_aws_failure(self, mock_get_policy):
        mock_get_policy.side_effect = RuntimeError("IAM get_policy failed")

        from app.analyzer import analyze_policy
        with pytest.raises(RuntimeError, match="IAM get_policy failed"):
            analyze_policy(VALID_POLICY_ARN, VALID_ACCOUNT_ID)

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    @patch("app.analyzer.aws_client.get_policy_document")
    @patch("app.analyzer.aws_client.get_policy")
    @patch("app.analyzer.anthropic.Anthropic")
    def test_raises_on_claude_api_failure(
        self, mock_anthropic_cls, mock_get_policy, mock_get_doc
    ):
        import anthropic as anthropic_lib
        mock_get_policy.return_value = MOCK_POLICY_META
        mock_get_doc.return_value = MOCK_POLICY_DOCUMENT
        mock_anthropic_cls.return_value.messages.create.side_effect = (
            anthropic_lib.APIError(
                message="API error",
                request=MagicMock(),
                body=None,
            )
        )

        from app.analyzer import analyze_policy
        with pytest.raises(RuntimeError, match="Claude analysis failed"):
            analyze_policy(VALID_POLICY_ARN, VALID_ACCOUNT_ID)


# ── analyzer.explain_policy Tests ────────────────────────────────────────────

class TestExplainPolicy:
    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    @patch("app.analyzer.anthropic.Anthropic")
    def test_returns_explain_result(self, mock_anthropic_cls):
        mock_content = MagicMock()
        mock_content.text = json.dumps(MOCK_EXPLAIN_RESPONSE)
        mock_response = MagicMock()
        mock_response.content = [mock_content]
        mock_anthropic_cls.return_value.messages.create.return_value = mock_response

        from app.analyzer import explain_policy
        result = explain_policy(VALID_POLICY_JSON)

        assert isinstance(result, ExplainResult)
        assert "XYZ" in result.summary
        assert len(result.details) == 1

    @patch.dict("os.environ", {}, clear=True)
    def test_raises_if_api_key_missing(self):
        from app.analyzer import explain_policy
        with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
            explain_policy(VALID_POLICY_JSON)

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    def test_raises_on_invalid_json(self):
        from app.analyzer import explain_policy
        with pytest.raises(ValueError, match="Invalid JSON"):
            explain_policy("this is not json")

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    def test_raises_on_missing_statement(self):
        from app.analyzer import explain_policy
        with pytest.raises(ValueError, match="Statement"):
            explain_policy(json.dumps({"Version": "2012-10-17"}))

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    def test_raises_on_empty_statement(self):
        from app.analyzer import explain_policy
        with pytest.raises(ValueError, match="non-empty"):
            explain_policy(json.dumps({"Statement": []}))

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    def test_raises_on_missing_effect(self):
        from app.analyzer import explain_policy
        with pytest.raises(ValueError, match="Effect"):
            explain_policy(json.dumps({
                "Statement": [{"Action": "s3:GetObject", "Resource": "*"}]
            }))

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    def test_raises_on_invalid_effect(self):
        from app.analyzer import explain_policy
        with pytest.raises(ValueError, match="Allow.*Deny|Deny.*Allow"):
            explain_policy(json.dumps({
                "Statement": [{"Effect": "Yes", "Action": "s3:GetObject", "Resource": "*"}]
            }))

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    def test_raises_on_missing_action(self):
        from app.analyzer import explain_policy
        with pytest.raises(ValueError, match="Action"):
            explain_policy(json.dumps({
                "Statement": [{"Effect": "Allow", "Resource": "*"}]
            }))

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    def test_raises_on_non_iam_json(self):
        from app.analyzer import explain_policy
        with pytest.raises(ValueError):
            explain_policy(json.dumps({"text": "who are you?"}))

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    @patch("app.analyzer.anthropic.Anthropic")
    def test_raises_on_claude_api_failure(self, mock_anthropic_cls):
        import anthropic as anthropic_lib
        mock_anthropic_cls.return_value.messages.create.side_effect = (
            anthropic_lib.APIError(
                message="API error",
                request=MagicMock(),
                body=None,
            )
        )
        from app.analyzer import explain_policy
        with pytest.raises(RuntimeError, match="Claude explain failed"):
            explain_policy(VALID_POLICY_JSON)

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    @patch("app.analyzer.anthropic.Anthropic")
    def test_raises_on_non_json_claude_response(self, mock_anthropic_cls):
        mock_content = MagicMock()
        mock_content.text = "Sorry, I cannot help with that."
        mock_response = MagicMock()
        mock_response.content = [mock_content]
        mock_anthropic_cls.return_value.messages.create.return_value = mock_response

        from app.analyzer import explain_policy
        with pytest.raises(RuntimeError, match="unexpected response format"):
            explain_policy(VALID_POLICY_JSON)


# ── FastAPI /analyze Endpoint Tests ──────────────────────────────────────────

class TestAnalyzeEndpoint:
    @patch("app.main.analyze_policy")
    def test_analyze_returns_200_with_valid_input(self, mock_analyze, client):
        mock_analyze.return_value = AnalysisResult(
            policy_arn=VALID_POLICY_ARN,
            findings=MOCK_CLAUDE_FINDINGS,
        )
        payload = {"policy_arn": VALID_POLICY_ARN, "account_id": VALID_ACCOUNT_ID}
        response = client.post("/api/v1/analyze", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["policy_arn"] == VALID_POLICY_ARN
        assert "wildcard" in data["findings"]

    def test_analyze_returns_422_on_missing_field(self, client):
        response = client.post("/api/v1/analyze", json={"policy_arn": VALID_POLICY_ARN})
        assert response.status_code == 422

    @patch("app.main.analyze_policy")
    def test_analyze_returns_500_on_runtime_error(self, mock_analyze, client):
        mock_analyze.side_effect = RuntimeError("IAM get_policy failed")
        payload = {"policy_arn": VALID_POLICY_ARN, "account_id": VALID_ACCOUNT_ID}
        response = client.post("/api/v1/analyze", json=payload)
        assert response.status_code == 500
        assert "IAM get_policy failed" in response.json()["detail"]


# ── FastAPI /explain Endpoint Tests ──────────────────────────────────────────

class TestExplainEndpoint:
    @patch("app.main.explain_policy")
    def test_explain_returns_200_with_valid_input(self, mock_explain, client):
        mock_explain.return_value = ExplainResult(
            summary=MOCK_EXPLAIN_RESPONSE["summary"],
            details=MOCK_EXPLAIN_RESPONSE["details"],
        )
        response = client.post(
            "/api/v1/explain",
            json={"policy_json": VALID_POLICY_JSON},
        )
        assert response.status_code == 200
        data = response.json()
        assert "XYZ" in data["summary"]
        assert isinstance(data["details"], list)

    def test_explain_returns_422_on_missing_field(self, client):
        response = client.post("/api/v1/explain", json={})
        assert response.status_code == 422

    @patch("app.main.explain_policy")
    def test_explain_returns_400_on_invalid_json(self, mock_explain, client):
        mock_explain.side_effect = ValueError("Invalid JSON provided.")
        response = client.post(
            "/api/v1/explain",
            json={"policy_json": "not json"},
        )
        assert response.status_code == 400

    @patch("app.main.explain_policy")
    def test_explain_returns_500_on_runtime_error(self, mock_explain, client):
        mock_explain.side_effect = RuntimeError("Claude explain failed")
        response = client.post(
            "/api/v1/explain",
            json={"policy_json": VALID_POLICY_JSON},
        )
        assert response.status_code == 500


# ── Health & UI Endpoint Tests ────────────────────────────────────────────────

class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


# ── escalate_policy Tests ─────────────────────────────────────────────────────

RISKY_POLICY_JSON = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "*",
        }
    ],
})

SAFE_POLICY_JSON = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::my-bucket/*",
        }
    ],
})

MOCK_ESCALATION_RESPONSE = {
    "summary": "This policy contains a high privilege escalation risk.",
    "findings": [
        {
            "action": "iam:passrole",
            "explanation": "Allows passing roles to AWS services which can lead to privilege escalation.",
            "escalation_path": "User → PassRole → EC2 → Admin Role",
        }
    ],
}


class TestEscalatePolicy:
    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    @patch("app.analyzer.anthropic.Anthropic")
    def test_returns_score_aligned_risk_level_for_risky_policy(self, mock_anthropic_cls):
        mock_content = MagicMock()
        mock_content.text = json.dumps(MOCK_ESCALATION_RESPONSE)
        mock_response = MagicMock()
        mock_response.content = [mock_content]
        mock_anthropic_cls.return_value.messages.create.return_value = mock_response

        from app.analyzer import escalate_policy
        result = escalate_policy(RISKY_POLICY_JSON)

        from app.analyzer import risk_score_label
        assert result.risk_level == risk_score_label(result.risk_score)
        assert len(result.detected_actions) > 0
        assert len(result.findings) > 0

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    def test_returns_low_risk_without_api_call_for_safe_policy(self):
        from app.analyzer import escalate_policy
        result = escalate_policy(SAFE_POLICY_JSON)

        assert result.risk_level == "Low"
        assert result.detected_actions == []
        assert result.findings == []

    @patch.dict("os.environ", {}, clear=True)
    def test_raises_if_api_key_missing(self):
        from app.analyzer import escalate_policy
        with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
            escalate_policy(RISKY_POLICY_JSON)

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    def test_raises_on_invalid_json(self):
        from app.analyzer import escalate_policy
        with pytest.raises(ValueError, match="Invalid JSON"):
            escalate_policy("not json")

    @patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"})
    def test_raises_on_non_iam_json(self):
        from app.analyzer import escalate_policy
        with pytest.raises(ValueError):
            escalate_policy(json.dumps({"text": "who are you?"}))


# ── /api/v1/escalate Endpoint Tests ──────────────────────────────────────────

class TestEscalateEndpoint:
    @patch("app.main.escalate_policy")
    def test_escalate_returns_200(self, mock_escalate, client):
        from app.models import EscalationFinding, EscalationResult
        mock_escalate.return_value = EscalationResult(
            risk_level="High",
            detected_actions=["iam:passrole"],
            findings=[
                EscalationFinding(
                    action="iam:passrole",
                    explanation="Can be used to escalate privileges.",
                    escalation_path="User → PassRole → EC2 → Admin Role",
                )
            ],
            summary="High risk detected.",
            risk_score=90,
        )
        response = client.post(
            "/api/v1/escalate",
            json={"policy_json": RISKY_POLICY_JSON},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["risk_level"] == "High"
        assert len(data["findings"]) == 1

    def test_escalate_returns_422_on_missing_field(self, client):
        response = client.post("/api/v1/escalate", json={})
        assert response.status_code == 422

    @patch("app.main.escalate_policy")
    def test_escalate_returns_400_on_invalid_json(self, mock_escalate, client):
        mock_escalate.side_effect = ValueError("Invalid JSON provided.")
        response = client.post(
            "/api/v1/escalate",
            json={"policy_json": "not json"},
        )
        assert response.status_code == 400

    @patch("app.main.escalate_policy")
    def test_escalate_returns_500_on_runtime_error(self, mock_escalate, client):
        mock_escalate.side_effect = RuntimeError("Claude escalation check failed")
        response = client.post(
            "/api/v1/escalate",
            json={"policy_json": RISKY_POLICY_JSON},
        )
        assert response.status_code == 500


# ── analyze_policy_rules Tests ────────────────────────────────────────────────
#
# Shared policy helpers

def _make_policy(effect, action, resource, condition=None, use_not_action=False,
                 use_not_resource=False):
    """Build a minimal IAM policy JSON string for testing."""
    stmt = {"Effect": effect}
    if use_not_action:
        stmt["NotAction"] = action if isinstance(action, list) else [action]
    else:
        stmt["Action"] = action
    if use_not_resource:
        stmt["NotResource"] = resource if isinstance(resource, list) else [resource]
    else:
        stmt["Resource"] = resource
    if condition:
        stmt["Condition"] = condition
    return json.dumps({"Version": "2012-10-17", "Statement": [stmt]})


class TestAnalyzePolicyRulesCategory1:
    """Category 1 — Overly Permissive Resource Patterns."""

    def test_resource_wildcard_raises_r001(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "s3:ListBuckets", "*")
        findings = analyze_policy_rules(policy)
        rule_ids = [f.rule_id for f in findings]
        assert "R001" in rule_ids
        r001 = next(f for f in findings if f.rule_id == "R001")
        assert r001.severity == "high"
        assert r001.statement_index == 0

    def test_specific_resource_does_not_raise_r001(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "s3:GetObject", "arn:aws:s3:::my-bucket/*")
        findings = analyze_policy_rules(policy)
        assert not any(f.rule_id == "R001" for f in findings)

    def test_s3_all_buckets_arn_raises_r002(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "s3:GetObject", "arn:aws:s3:::*")
        findings = analyze_policy_rules(policy)
        rule_ids = [f.rule_id for f in findings]
        assert "R002" in rule_ids
        r002 = next(f for f in findings if f.rule_id == "R002")
        assert r002.severity == "high"

    def test_s3_all_objects_arn_raises_r002(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "s3:GetObject", "arn:aws:s3:::*/*")
        findings = analyze_policy_rules(policy)
        assert any(f.rule_id == "R002" for f in findings)

    def test_specific_s3_bucket_does_not_raise_r002(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "s3:GetObject", "arn:aws:s3:::my-bucket/*")
        findings = analyze_policy_rules(policy)
        assert not any(f.rule_id == "R002" for f in findings)

    def test_deny_statement_with_wildcard_resource_skips_r001(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Deny", "s3:DeleteObject", "*")
        findings = analyze_policy_rules(policy)
        assert not any(f.rule_id == "R001" for f in findings)


class TestAnalyzePolicyRulesCategory2:
    """Category 2 — Dangerous Service Actions."""

    def test_s3_putbucketpolicy_raises_r003_high(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "s3:PutBucketPolicy", "arn:aws:s3:::my-bucket")
        findings = analyze_policy_rules(policy)
        r003 = [f for f in findings if f.rule_id == "R003"]
        assert any("s3:putbucketpolicy" in f.title for f in r003)
        assert all(f.severity == "high" for f in r003)

    def test_lambda_updatefunctioncode_raises_r003_high(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "lambda:UpdateFunctionCode", "*")
        findings = analyze_policy_rules(policy)
        assert any(
            f.rule_id == "R003" and "lambda:updatefunctioncode" in f.title
            for f in findings
        )

    def test_secretsmanager_raises_r004_medium(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "secretsmanager:GetSecretValue",
                              "arn:aws:secretsmanager:us-east-1:123456789012:secret:MySecret")
        findings = analyze_policy_rules(policy)
        r004 = [f for f in findings if f.rule_id == "R004"]
        assert any("secretsmanager:getsecretvalue" in f.title for f in r004)
        assert all(f.severity == "medium" for f in r004)

    def test_ssm_getparameter_raises_r004_medium(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "ssm:GetParameter", "*")
        findings = analyze_policy_rules(policy)
        assert any(
            f.rule_id == "R004" and "ssm:getparameter" in f.title
            for f in findings
        )

    def test_s3_getobject_with_wildcard_resource_raises_r004(self):
        """s3:GetObject is only flagged when Resource is *."""
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "s3:GetObject", "*")
        findings = analyze_policy_rules(policy)
        assert any(
            f.rule_id == "R004" and "s3:getobject" in f.title
            for f in findings
        )

    def test_s3_getobject_with_specific_resource_not_flagged(self):
        """s3:GetObject on a specific ARN must not produce a medium finding."""
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "s3:GetObject", "arn:aws:s3:::my-bucket/*")
        findings = analyze_policy_rules(policy)
        assert not any(
            f.rule_id == "R004" and "s3:getobject" in f.title
            for f in findings
        )

    def test_dynamodb_scan_with_wildcard_resource_raises_r004(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "dynamodb:Scan", "*")
        findings = analyze_policy_rules(policy)
        assert any(
            f.rule_id == "R004" and "dynamodb:scan" in f.title
            for f in findings
        )

    def test_wildcard_action_flags_all_high_risk(self):
        from app.analyzer import analyze_policy_rules, HIGH_RISK_ACTIONS
        policy = _make_policy("Allow", "*", "*")
        findings = analyze_policy_rules(policy)
        found_actions = {f.title.split(": ", 1)[1] for f in findings if f.rule_id == "R003"}
        assert found_actions == HIGH_RISK_ACTIONS

    def test_organizations_wildcard_raises_r003(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "organizations:*", "*")
        findings = analyze_policy_rules(policy)
        assert any(
            f.rule_id == "R003" and "organizations:*" in f.title
            for f in findings
        )


class TestAnalyzePolicyRulesCategory3:
    """Category 3 — Missing Deny / Condition Checks."""

    def test_sensitive_action_without_condition_raises_r005(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "iam:PassRole", "*")
        findings = analyze_policy_rules(policy)
        assert any(f.rule_id == "R005" for f in findings)
        r005 = next(f for f in findings if f.rule_id == "R005")
        assert r005.severity == "medium"

    def test_sensitive_action_with_condition_does_not_raise_r005(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy(
            "Allow", "iam:PassRole", "*",
            condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
        )
        findings = analyze_policy_rules(policy)
        assert not any(f.rule_id == "R005" for f in findings)

    def test_safe_action_without_condition_does_not_raise_r005(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "s3:GetObject", "arn:aws:s3:::my-bucket/*")
        findings = analyze_policy_rules(policy)
        assert not any(f.rule_id == "R005" for f in findings)

    def test_not_action_on_allow_raises_r006(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", ["s3:DeleteObject"], "*", use_not_action=True)
        findings = analyze_policy_rules(policy)
        assert any(f.rule_id == "R006" for f in findings)
        r006 = next(f for f in findings if f.rule_id == "R006")
        assert r006.severity == "high"

    def test_not_action_on_deny_does_not_raise_r006(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Deny", ["s3:DeleteObject"], "*", use_not_action=True)
        findings = analyze_policy_rules(policy)
        assert not any(f.rule_id == "R006" for f in findings)

    def test_not_resource_on_allow_raises_r007(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy(
            "Allow", "s3:GetObject", "arn:aws:s3:::protected-bucket/*",
            use_not_resource=True,
        )
        findings = analyze_policy_rules(policy)
        assert any(f.rule_id == "R007" for f in findings)
        r007 = next(f for f in findings if f.rule_id == "R007")
        assert r007.severity == "high"

    def test_not_resource_on_deny_does_not_raise_r007(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy(
            "Deny", "s3:GetObject", "arn:aws:s3:::protected-bucket/*",
            use_not_resource=True,
        )
        findings = analyze_policy_rules(policy)
        assert not any(f.rule_id == "R007" for f in findings)


class TestAnalyzePolicyRulesGeneral:
    """Cross-cutting tests for analyze_policy_rules."""

    def test_invalid_json_raises_value_error(self):
        from app.analyzer import analyze_policy_rules
        with pytest.raises(ValueError, match="Invalid JSON"):
            analyze_policy_rules("not json")

    def test_non_iam_json_raises_value_error(self):
        from app.analyzer import analyze_policy_rules
        with pytest.raises(ValueError):
            analyze_policy_rules(json.dumps({"foo": "bar"}))

    def test_fully_safe_policy_returns_no_findings(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "s3:GetObject", "arn:aws:s3:::my-bucket/prefix/*")
        findings = analyze_policy_rules(policy)
        assert findings == []

    def test_finding_has_correct_statement_index(self):
        from app.analyzer import analyze_policy_rules
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject",
                 "Resource": "arn:aws:s3:::safe-bucket/*"},
                {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
            ],
        })
        findings = analyze_policy_rules(policy)
        risky = [f for f in findings if f.rule_id in ("R001", "R003", "R005")]
        assert all(f.statement_index == 1 for f in risky)

    def test_rule_finding_model_fields(self):
        from app.analyzer import analyze_policy_rules
        from app.models import RuleFinding
        policy = _make_policy("Allow", "iam:PassRole", "*")
        findings = analyze_policy_rules(policy)
        assert all(isinstance(f, RuleFinding) for f in findings)
        for f in findings:
            assert f.rule_id
            assert f.severity in ("high", "medium", "low")
            assert f.title
            assert f.description
            assert isinstance(f.statement_index, int)


# ── Task 1 extended action coverage tests ─────────────────────────────────────

class TestAnalyzePolicyRulesNewHighRiskActions:
    """Test the expanded HIGH_RISK_ACTIONS entries (Category 2 / R003)."""

    def test_kms_decrypt_raises_r003(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "kms:Decrypt", "*")
        findings = analyze_policy_rules(policy)
        assert any(f.rule_id == "R003" and "kms:decrypt" in f.title for f in findings)

    def test_kms_describekey_raises_r003(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "kms:DescribeKey", "*")
        findings = analyze_policy_rules(policy)
        assert any(f.rule_id == "R003" and "kms:describekey" in f.title for f in findings)

    def test_lambda_createfunction_raises_r003(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "lambda:CreateFunction", "*")
        findings = analyze_policy_rules(policy)
        assert any(f.rule_id == "R003" and "lambda:createfunction" in f.title for f in findings)

    def test_ec2_runinstances_raises_r003(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "ec2:RunInstances", "*")
        findings = analyze_policy_rules(policy)
        assert any(f.rule_id == "R003" and "ec2:runinstances" in f.title for f in findings)

    def test_s3_putbucketacl_raises_r003(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "s3:PutBucketAcl", "arn:aws:s3:::my-bucket")
        findings = analyze_policy_rules(policy)
        assert any(f.rule_id == "R003" and "s3:putbucketacl" in f.title for f in findings)

    def test_s3_putobjectacl_raises_r003(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "s3:PutObjectAcl", "arn:aws:s3:::my-bucket/*")
        findings = analyze_policy_rules(policy)
        assert any(f.rule_id == "R003" and "s3:putobjectacl" in f.title for f in findings)

    def test_iam_updateassumerolepolicy_raises_r003(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "iam:UpdateAssumeRolePolicy", "*")
        findings = analyze_policy_rules(policy)
        assert any(f.rule_id == "R003" and "iam:updateassumerolepolicy" in f.title for f in findings)

    def test_iam_setdefaultpolicyversion_raises_r003(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "iam:SetDefaultPolicyVersion", "*")
        findings = analyze_policy_rules(policy)
        assert any(f.rule_id == "R003" and "iam:setdefaultpolicyversion" in f.title for f in findings)

    def test_iam_createrole_raises_r003(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "iam:CreateRole", "*")
        findings = analyze_policy_rules(policy)
        assert any(f.rule_id == "R003" and "iam:createrole" in f.title for f in findings)

    def test_iam_createpolicyversion_raises_r003(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "iam:CreatePolicyVersion", "*")
        findings = analyze_policy_rules(policy)
        assert any(f.rule_id == "R003" and "iam:createpolicyversion" in f.title for f in findings)


class TestAnalyzePolicyRulesNewMediumRiskActions:
    """Test the expanded MEDIUM_RISK_ACTIONS entries (Category 2 / R004)."""

    def test_rds_copydbsnapshot_raises_r004(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "rds:CopyDBSnapshot", "*")
        findings = analyze_policy_rules(policy)
        assert any(f.rule_id == "R004" and "rds:copydbsnapshot" in f.title for f in findings)

    def test_ec2_describeinstances_raises_r004(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "ec2:DescribeInstances", "*")
        findings = analyze_policy_rules(policy)
        assert any(f.rule_id == "R004" and "ec2:describeinstances" in f.title for f in findings)

    def test_iam_createaccesskey_raises_r004(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "iam:CreateAccessKey", "*")
        findings = analyze_policy_rules(policy)
        assert any(f.rule_id == "R004" and "iam:createaccesskey" in f.title for f in findings)

    def test_sts_assumerole_raises_r004(self):
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "sts:AssumeRole", "*")
        findings = analyze_policy_rules(policy)
        assert any(f.rule_id == "R004" and "sts:assumerole" in f.title for f in findings)

    def test_r003_finding_has_description(self):
        """R003 findings for known actions must include a non-empty description."""
        from app.analyzer import analyze_policy_rules
        policy = _make_policy("Allow", "kms:Decrypt", "*")
        findings = analyze_policy_rules(policy)
        r003 = next(f for f in findings if f.rule_id == "R003" and "kms:decrypt" in f.title)
        assert len(r003.description) > 20


# ── Task 2: explain_policy_local improved output tests ────────────────────────

class TestExplainPolicyLocal:
    """Tests for the human-readable explain_policy_local() rewrite."""

    def test_full_admin_policy_uses_allows_prefix(self):
        from app.analyzer import explain_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        })
        result = explain_policy_local(policy)
        assert "ALLOWS" in result.details[0]
        assert "full administrator access" in result.details[0]
        assert "extremely dangerous" in result.details[0]

    def test_full_admin_summary_warns_about_danger(self):
        from app.analyzer import explain_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        })
        result = explain_policy_local(policy)
        assert "FULL ADMIN ACCESS" in result.summary or "full administrator" in result.summary.lower()

    def test_s3_bucket_name_extracted_in_detail(self):
        from app.analyzer import explain_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-special-bucket/*",
            }],
        })
        result = explain_policy_local(policy)
        assert "my-special-bucket" in result.details[0]

    def test_allow_uses_allows_prefix(self):
        from app.analyzer import explain_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*",
            }],
        })
        result = explain_policy_local(policy)
        assert result.details[0].startswith("ALLOWS")

    def test_allow_specific_resource_uses_limited_to(self):
        from app.analyzer import explain_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*",
            }],
        })
        result = explain_policy_local(policy)
        assert "limited to" in result.details[0]

    def test_deny_statement_uses_blocks_prefix(self):
        from app.analyzer import explain_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Action": "s3:DeleteObject",
                "Resource": "*",
            }],
        })
        result = explain_policy_local(policy)
        assert result.details[0].startswith("BLOCKS")

    def test_deny_includes_service_label(self):
        from app.analyzer import explain_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Action": "s3:DeleteObject",
                "Resource": "*",
            }],
        })
        result = explain_policy_local(policy)
        # Service label should appear for single-service Deny
        assert "S3" in result.details[0] or "storage" in result.details[0]

    def test_wildcard_resource_uses_on_all_resources(self):
        from app.analyzer import explain_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Resource": "*",
            }],
        })
        result = explain_policy_local(policy)
        assert "on all resources" in result.details[0]

    def test_known_action_uses_action_descriptions_phrase(self):
        from app.analyzer import explain_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }],
        })
        result = explain_policy_local(policy)
        assert "retrieve stored secrets" in result.details[0]

    def test_multi_action_verbs_combined(self):
        from app.analyzer import explain_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "arn:aws:s3:::my-bucket/*",
            }],
        })
        result = explain_policy_local(policy)
        detail = result.details[0]
        assert "read files from storage" in detail or "upload files to storage" in detail

    def test_unknown_action_camelcase_fallback(self):
        from app.analyzer import explain_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "ec2:DescribeSecurityGroups",
                "Resource": "*",
            }],
        })
        result = explain_policy_local(policy)
        detail = result.details[0].lower()
        assert "describe" in detail and "security groups" in detail

    def test_service_wildcard_phrase(self):
        from app.analyzer import explain_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "iam:*",
                "Resource": "*",
            }],
        })
        result = explain_policy_local(policy)
        assert "ALL actions in IAM" in result.details[0]

    def test_multi_statement_allow_only_summary(self):
        from app.analyzer import explain_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject",
                 "Resource": "arn:aws:s3:::bucket-a/*"},
                {"Effect": "Allow", "Action": "s3:PutObject",
                 "Resource": "arn:aws:s3:::bucket-b/*"},
            ],
        })
        result = explain_policy_local(policy)
        assert "2" in result.summary
        assert len(result.details) == 2

    def test_mixed_allow_deny_summary(self):
        from app.analyzer import explain_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject",
                 "Resource": "arn:aws:s3:::my-bucket/*"},
                {"Effect": "Deny", "Action": "s3:DeleteObject",
                 "Resource": "*"},
            ],
        })
        result = explain_policy_local(policy)
        assert "mixed" in result.summary.lower() or "Deny" in result.summary

    def test_invalid_json_raises(self):
        from app.analyzer import explain_policy_local
        with pytest.raises(ValueError, match="Invalid JSON"):
            explain_policy_local("not json")

    def test_missing_statement_raises(self):
        from app.analyzer import explain_policy_local
        with pytest.raises(ValueError):
            explain_policy_local(json.dumps({"Version": "2012-10-17"}))


# ── CLI --format json tests ───────────────────────────────────────────────────

_SIMPLE_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                   "Resource": "arn:aws:s3:::my-bucket/*"}],
})

_RISKY_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}],
})


def _make_args(tmp_path, command, policy_text, fmt="json", ai=False):
    """Write a policy file and return an argparse.Namespace for the command."""
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(policy_text)
    return argparse.Namespace(file=str(policy_file), ai=ai, format=fmt)


class TestCliJsonOutput:
    """--format json produces valid, parseable JSON with correct keys."""

    def test_explain_json_has_required_keys(self, tmp_path):
        from app.cli import cmd_explain
        args = _make_args(tmp_path, "explain", _SIMPLE_POLICY)
        with _capture_stdout() as buf:
            cmd_explain(args)
        data = json.loads(buf.getvalue())
        assert data["status"] == "success"
        assert "summary" in data
        assert isinstance(data["details"], list)

    def test_escalate_json_has_required_keys(self, tmp_path):
        from app.cli import cmd_escalate
        args = _make_args(tmp_path, "escalate", _RISKY_POLICY)
        with _capture_stdout() as buf:
            cmd_escalate(args)
        data = json.loads(buf.getvalue())
        assert data["status"] == "success"
        assert "risk_level" in data
        assert "detected_actions" in data
        assert "findings" in data
        assert "rule_findings" in data
        assert "summary" in data

    def test_scan_json_has_nested_explain_and_escalate(self, tmp_path):
        from app.cli import cmd_scan
        args = _make_args(tmp_path, "scan", _SIMPLE_POLICY)
        with _capture_stdout() as buf:
            cmd_scan(args)
        data = json.loads(buf.getvalue())
        assert data["status"] == "success"
        assert data["explain"]["status"] == "success"
        assert data["escalate"]["status"] == "success"
        # jq-style access: .escalate.risk_level
        assert data["escalate"]["risk_level"] in ("High", "Medium", "Low")

    def test_escalate_json_rule_findings_populated_for_risky_policy(self, tmp_path):
        from app.cli import cmd_escalate
        args = _make_args(tmp_path, "escalate", _RISKY_POLICY)
        with _capture_stdout() as buf:
            cmd_escalate(args)
        data = json.loads(buf.getvalue())
        assert len(data["rule_findings"]) > 0
        rf = data["rule_findings"][0]
        assert "rule_id" in rf
        assert "severity" in rf
        assert "title" in rf
        assert "description" in rf
        assert "statement_index" in rf

    def test_escalate_json_rule_findings_empty_for_safe_policy(self, tmp_path):
        from app.cli import cmd_escalate
        args = _make_args(tmp_path, "escalate", _SIMPLE_POLICY)
        with _capture_stdout() as buf:
            cmd_escalate(args)
        data = json.loads(buf.getvalue())
        assert data["rule_findings"] == []

    def test_scan_json_is_jq_parseable(self, tmp_path):
        """Output must contain no ANSI codes, banner text, or decorations."""
        from app.cli import cmd_scan
        args = _make_args(tmp_path, "scan", _RISKY_POLICY)
        with _capture_stdout() as buf:
            cmd_scan(args)
        raw = buf.getvalue()
        # If any ANSI escape codes leaked in, this would raise
        data = json.loads(raw)
        assert data is not None
        # Ensure no ANSI codes in any string values (recursive check on summary)
        assert "\033[" not in data["explain"]["summary"]
        assert "\033[" not in data["escalate"]["summary"]

    def test_json_error_on_missing_file(self, tmp_path):
        from app.cli import cmd_explain
        args = argparse.Namespace(
            file=str(tmp_path / "nonexistent.json"), ai=False, format="json"
        )
        with _capture_stdout() as buf:
            with pytest.raises(SystemExit) as exc_info:
                cmd_explain(args)
        assert exc_info.value.code == 1
        data = json.loads(buf.getvalue())
        assert data["status"] == "error"
        assert "error" in data
        assert "file not found" in data["error"]

    def test_json_error_on_invalid_json_file(self, tmp_path):
        from app.cli import cmd_escalate
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("this is not json")
        args = argparse.Namespace(file=str(bad_file), ai=False, format="json")
        with _capture_stdout() as buf:
            with pytest.raises(SystemExit) as exc_info:
                cmd_escalate(args)
        assert exc_info.value.code == 1
        data = json.loads(buf.getvalue())
        assert data["status"] == "error"

    def test_text_format_does_not_produce_json(self, tmp_path):
        """--format text (default) must not output a JSON object."""
        from app.cli import cmd_explain
        args = _make_args(tmp_path, "explain", _SIMPLE_POLICY, fmt="text")
        with _capture_stdout() as buf:
            cmd_explain(args)
        raw = buf.getvalue()
        # Text output is not a JSON object
        with pytest.raises(json.JSONDecodeError):
            json.loads(raw)


# ── CLI text output structure / snapshot tests ────────────────────────────────

_HIGH_RISK_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}],
})

_MEDIUM_RISK_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}],
})

_MIXED_RISK_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Action": ["iam:PassRole", "sts:AssumeRole"],
                   "Resource": "*"}],
})

_WILDCARD_SCOPE_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
})


class TestCliTextOutputStructure:
    """Snapshot-style tests: verify section presence, order, and category placement."""

    def test_high_risk_action_appears_in_confirmed_section(self, tmp_path):
        """iam:PassRole (HIGH) must appear under 'Confirmed Risky Actions'."""
        from app.cli import cmd_escalate
        args = _make_args(tmp_path, "escalate", _HIGH_RISK_POLICY, fmt="text")
        with _capture_stdout() as buf:
            cmd_escalate(args)
        output = buf.getvalue()
        assert "Confirmed Risky Actions" in output
        # iam:PassRole must be in the confirmed region (before any Needs Review)
        confirmed_idx = output.index("Confirmed Risky Actions")
        needs_review_idx = output.find("Needs Review")
        end = needs_review_idx if needs_review_idx != -1 else len(output)
        confirmed_region = output[confirmed_idx:end]
        assert "iam:passrole" in confirmed_region.lower()

    def test_medium_risk_action_appears_in_needs_review_section(self, tmp_path):
        """sts:AssumeRole (MEDIUM) must appear under 'Needs Review', not 'Confirmed Risky Actions'."""
        from app.cli import cmd_escalate
        args = _make_args(tmp_path, "escalate", _MEDIUM_RISK_POLICY, fmt="text")
        with _capture_stdout() as buf:
            cmd_escalate(args)
        output = buf.getvalue()
        assert "Needs Review" in output
        assert "Confirmed Risky Actions" not in output
        assert "sts:assumerole" in output.lower()

    def test_confirmed_section_precedes_needs_review_section(self, tmp_path):
        """When both sections are present, Confirmed Risky Actions comes first."""
        from app.cli import cmd_escalate
        args = _make_args(tmp_path, "escalate", _MIXED_RISK_POLICY, fmt="text")
        with _capture_stdout() as buf:
            cmd_escalate(args)
        output = buf.getvalue()
        assert "Confirmed Risky Actions" in output, "Expected 'Confirmed Risky Actions' section"
        assert "Needs Review" in output, "Expected 'Needs Review' section"
        assert output.index("Confirmed Risky Actions") < output.index("Needs Review")

    def test_wildcard_action_appears_in_needs_review_not_confirmed(self, tmp_path):
        """Wildcard patterns (e.g. 's3:*') must appear in Needs Review, not Confirmed Risky Actions."""
        from app.cli import cmd_escalate
        args = _make_args(tmp_path, "escalate", _WILDCARD_SCOPE_POLICY, fmt="text")
        with _capture_stdout() as buf:
            cmd_escalate(args)
        output = buf.getvalue()
        assert "Needs Review" in output
        assert "s3:*" in output
        # s3:* must not appear inside a Confirmed Risky Actions block
        confirmed_idx = output.find("Confirmed Risky Actions")
        needs_review_idx = output.find("Needs Review")
        if confirmed_idx != -1 and needs_review_idx != -1:
            confirmed_region = output[confirmed_idx:needs_review_idx]
            assert "s3:*" not in confirmed_region

    def test_section_headers_present_in_escalate_report(self, tmp_path):
        """The escalate text report must contain all three structural markers."""
        from app.cli import cmd_escalate
        args = _make_args(tmp_path, "escalate", _HIGH_RISK_POLICY, fmt="text")
        with _capture_stdout() as buf:
            cmd_escalate(args)
        output = buf.getvalue()
        assert "Privilege Escalation Report" in output
        assert "Risk Level" in output
        assert "Risk Score" in output
        assert "Summary" in output


# ── CLI --format sarif tests ──────────────────────────────────────────────────

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)


class TestCliSarifOutput:
    """--format sarif produces valid SARIF 2.1.0 output."""

    def test_sarif_has_required_schema_fields(self, tmp_path):
        from app.cli import cmd_scan
        args = _make_args(tmp_path, "scan", _RISKY_POLICY, fmt="sarif")
        with _capture_stdout() as buf:
            cmd_scan(args)
        doc = json.loads(buf.getvalue())
        assert doc["$schema"] == _SARIF_SCHEMA
        assert doc["version"] == "2.1.0"
        assert isinstance(doc["runs"], list)
        assert len(doc["runs"]) == 1

    def test_sarif_driver_metadata(self, tmp_path):
        from app.cli import cmd_scan
        args = _make_args(tmp_path, "scan", _RISKY_POLICY, fmt="sarif")
        with _capture_stdout() as buf:
            cmd_scan(args)
        driver = json.loads(buf.getvalue())["runs"][0]["tool"]["driver"]
        assert driver["name"] == "pasu"
        assert "version" in driver
        assert driver["informationUri"] == "https://pypi.org/project/pasu/"
        assert isinstance(driver["rules"], list)

    def test_sarif_high_risk_action_maps_to_error_level(self, tmp_path):
        from app.cli import cmd_escalate
        # iam:PassRole is HIGH_RISK → level "error"
        args = _make_args(tmp_path, "escalate", _RISKY_POLICY, fmt="sarif")
        with _capture_stdout() as buf:
            cmd_escalate(args)
        doc = json.loads(buf.getvalue())
        results = doc["runs"][0]["results"]
        action_results = [r for r in results if "PASU-" in r["ruleId"]]
        assert len(action_results) > 0
        assert all(r["level"] == "error" for r in action_results)

    def test_sarif_medium_risk_action_maps_to_warning_level(self, tmp_path):
        from app.cli import cmd_escalate
        medium_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}],
        })
        args = _make_args(tmp_path, "escalate", medium_policy, fmt="sarif")
        with _capture_stdout() as buf:
            cmd_escalate(args)
        doc = json.loads(buf.getvalue())
        results = doc["runs"][0]["results"]
        action_results = [r for r in results if "PASU-" in r["ruleId"]]
        assert len(action_results) > 0
        assert all(r["level"] == "warning" for r in action_results)

    def test_sarif_rule_finding_severity_mapping(self, tmp_path):
        from app.cli import cmd_escalate
        # iam:PassRole + Resource:* → R001 (high→error), R003 (high→error), R005 (medium→warning)
        args = _make_args(tmp_path, "escalate", _RISKY_POLICY, fmt="sarif")
        with _capture_stdout() as buf:
            cmd_escalate(args)
        doc = json.loads(buf.getvalue())
        results = doc["runs"][0]["results"]
        rule_results = {r["ruleId"]: r["level"] for r in results if not r["ruleId"].startswith("PASU-")}
        assert rule_results.get("R001") == "error"
        assert rule_results.get("R003") == "error"
        assert rule_results.get("R005") == "warning"

    def test_sarif_artifact_location_matches_file_path(self, tmp_path):
        from app.cli import cmd_scan
        args = _make_args(tmp_path, "scan", _RISKY_POLICY, fmt="sarif")
        with _capture_stdout() as buf:
            cmd_scan(args)
        doc = json.loads(buf.getvalue())
        results = doc["runs"][0]["results"]
        assert len(results) > 0
        for result in results:
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            assert str(tmp_path) in uri or "policy.json" in uri

    def test_sarif_rules_list_matches_results(self, tmp_path):
        """Every ruleId in results must have a matching entry in driver.rules."""
        from app.cli import cmd_scan
        args = _make_args(tmp_path, "scan", _RISKY_POLICY, fmt="sarif")
        with _capture_stdout() as buf:
            cmd_scan(args)
        doc = json.loads(buf.getvalue())
        run = doc["runs"][0]
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        for result in run["results"]:
            assert result["ruleId"] in rule_ids

    def test_sarif_explain_produces_empty_results(self, tmp_path):
        """explain --format sarif emits valid SARIF with no findings."""
        from app.cli import cmd_explain
        args = _make_args(tmp_path, "explain", _SIMPLE_POLICY, fmt="sarif")
        with _capture_stdout() as buf:
            cmd_explain(args)
        doc = json.loads(buf.getvalue())
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["results"] == []

    def test_sarif_output_contains_no_ansi_codes(self, tmp_path):
        from app.cli import cmd_scan
        args = _make_args(tmp_path, "scan", _RISKY_POLICY, fmt="sarif")
        with _capture_stdout() as buf:
            cmd_scan(args)
        raw = buf.getvalue()
        assert "\033[" not in raw


# ── fix_policy_local tests ────────────────────────────────────────────────────

_ALL_ACTIONS_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
})

_S3_WILDCARD_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
})

_SAFE_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                   "Resource": "arn:aws:s3:::my-bucket/*"}],
})

_DENY_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}],
})

_NOT_ACTION_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "NotAction": ["s3:DeleteObject"], "Resource": "*"}],
})

_MIXED_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::my-bucket/*"},
        {"Effect": "Allow", "Action": ["s3:GetObject", "iam:PassRole"],
         "Resource": "*"},
    ],
})

_ALL_RISKY_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow",
                   "Action": ["iam:PassRole", "iam:CreatePolicyVersion"],
                   "Resource": "*"}],
})


class TestFixPolicyLocal:
    """Unit tests for fix_policy_local() in analyzer.py."""

    def test_fix_full_wildcard_action_replaced_with_todo(self):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(_ALL_ACTIONS_POLICY)
        stmt = result.fixed_policy["Statement"][0]
        assert stmt["Action"] == ["TODO:specify-needed-actions"]
        replaced = [c for c in result.changes if c.type == "replaced_wildcard"]
        assert len(replaced) == 1
        assert replaced[0].from_ == "*"

    def test_fix_service_wildcard_s3_replaced_with_readonly(self):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(_S3_WILDCARD_POLICY)
        stmt = result.fixed_policy["Statement"][0]
        assert "s3:GetObject" in stmt["Action"]
        assert "s3:ListBucket" in stmt["Action"]
        assert "s3:*" not in stmt["Action"]
        scoped = [c for c in result.changes if c.type == "scoped_wildcard"]
        assert len(scoped) == 1
        assert scoped[0].from_ == "s3:*"
        assert "s3:GetObject" in (scoped[0].to or [])

    def test_fix_high_risk_action_removed(self):
        from app.analyzer import fix_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Action": ["s3:GetObject", "iam:PassRole"],
                           "Resource": "arn:aws:s3:::bucket/*"}],
        })
        result = fix_policy_local(policy)
        stmt = result.fixed_policy["Statement"][0]
        assert "iam:PassRole" not in stmt["Action"]
        assert "s3:GetObject" in stmt["Action"]
        removed = [c for c in result.changes if c.type == "removed_action"]
        assert any("PassRole" in (c.action or "") for c in removed)

    def test_fix_deny_statement_preserved_unchanged(self):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(_DENY_POLICY)
        stmt = result.fixed_policy["Statement"][0]
        assert stmt["Effect"] == "Deny"
        assert stmt["Action"] == "s3:DeleteObject"
        assert result.changes == []
        assert result.manual_review_needed == []

    def test_fix_not_action_flagged_as_manual_review(self):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(_NOT_ACTION_POLICY)
        assert len(result.manual_review_needed) > 0
        assert any("NotAction" in note for note in result.manual_review_needed)
        # Statement kept unchanged
        stmt = result.fixed_policy["Statement"][0]
        assert "NotAction" in stmt

    def test_fix_resource_wildcard_produces_warning_change(self):
        from app.analyzer import fix_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        })
        result = fix_policy_local(policy)
        warnings = [c for c in result.changes if c.type == "resource_wildcard_warning"]
        assert len(warnings) == 1
        assert "specific resource ARNs" in warnings[0].reason

    def test_fix_already_safe_policy_returns_unchanged(self):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(_SAFE_POLICY)
        assert result.changes == []
        assert result.manual_review_needed == []
        stmt = result.fixed_policy["Statement"][0]
        action = stmt["Action"]
        # fix normalises string Actions to lists; accept either form
        assert action == ["s3:GetObject"] or action == "s3:GetObject"
        assert stmt["Resource"] == "arn:aws:s3:::my-bucket/*"

    def test_fix_mixed_policy_only_fixes_dangerous_parts(self):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(_MIXED_POLICY)
        # Statement 0: safe — unchanged
        s0 = result.fixed_policy["Statement"][0]
        assert s0["Action"] == ["s3:GetObject"] or s0["Action"] == "s3:GetObject"
        # Statement 1: iam:PassRole must be gone
        s1 = result.fixed_policy["Statement"][1]
        assert "iam:PassRole" not in s1["Action"]
        # s3:GetObject is safe, should remain
        assert "s3:GetObject" in s1["Action"]

    def test_fix_all_high_risk_actions_replaced_with_placeholder(self):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(_ALL_RISKY_POLICY)
        stmt = result.fixed_policy["Statement"][0]
        # Must not be empty; should have TODO placeholder
        assert len(stmt["Action"]) > 0
        assert any("TODO" in a for a in stmt["Action"])
        assert any("TODO:specify-needed-actions" in note for note in result.manual_review_needed)
        assert any("Manual review required" in note for note in result.manual_review_needed)

    def test_fix_service_wildcard_deduplicates_actions(self):
        from app.analyzer import fix_policy_local
        # s3:* expands to include s3:GetObject; s3:GetObject is also listed → no duplicate
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Action": ["s3:*", "s3:GetObject"],
                           "Resource": "*"}],
        })
        result = fix_policy_local(policy)
        actions = result.fixed_policy["Statement"][0]["Action"]
        assert len(actions) == len(set(actions)), "Duplicate actions found in fixed policy"

    def test_fix_original_and_fixed_risk_levels_reported(self):
        from app.analyzer import fix_policy_local
        result = fix_policy_local(_ALL_ACTIONS_POLICY)
        assert result.original_risk_level in ("High", "Medium", "Low")
        assert result.fixed_risk_level in ("High", "Medium", "Low")
        # After fixing *, risk should drop
        assert result.original_risk_level == "High"

    def test_fix_condition_preserved_on_safe_action(self):
        from app.analyzer import fix_policy_local
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/*",
                "Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
            }],
        })
        result = fix_policy_local(policy)
        stmt = result.fixed_policy["Statement"][0]
        assert "Condition" in stmt
        assert stmt["Condition"]["StringEquals"]["aws:RequestedRegion"] == "us-east-1"

    def test_fix_invalid_json_raises(self):
        from app.analyzer import fix_policy_local
        with pytest.raises(ValueError, match="Invalid JSON"):
            fix_policy_local("not json")

    def test_fix_missing_statement_raises(self):
        from app.analyzer import fix_policy_local
        with pytest.raises(ValueError):
            fix_policy_local(json.dumps({"Version": "2012-10-17"}))


# ── CLI fix command tests ─────────────────────────────────────────────────────

def _make_fix_args(tmp_path, policy_text, fmt="text", output=None):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(policy_text)
    return argparse.Namespace(file=str(policy_file), format=fmt, output=output)


class TestCliFixOutput:
    """Tests for the 'pasu fix' CLI command."""

    def test_fix_json_format_has_required_keys(self, tmp_path):
        from app.cli import cmd_fix
        args = _make_fix_args(tmp_path, _ALL_ACTIONS_POLICY, fmt="json")
        with _capture_stdout() as buf:
            cmd_fix(args)
        data = json.loads(buf.getvalue())
        assert data["status"] == "success"
        assert "original_risk_level" in data
        assert "fixed_risk_level" in data
        assert "fixed_policy" in data
        assert "changes" in data
        assert "manual_review_needed" in data

    def test_fix_json_changes_use_from_key(self, tmp_path):
        from app.cli import cmd_fix
        args = _make_fix_args(tmp_path, _S3_WILDCARD_POLICY, fmt="json")
        with _capture_stdout() as buf:
            cmd_fix(args)
        data = json.loads(buf.getvalue())
        scoped = [c for c in data["changes"] if c["type"] == "scoped_wildcard"]
        assert len(scoped) > 0
        assert "from" in scoped[0]
        assert scoped[0]["from"] == "s3:*"

    def test_fix_output_flag_writes_fixed_policy_to_file(self, tmp_path):
        from app.cli import cmd_fix
        output_file = tmp_path / "fixed.json"
        args = _make_fix_args(tmp_path, _ALL_ACTIONS_POLICY, output=str(output_file))
        with _capture_stdout() as buf:
            cmd_fix(args)
        assert output_file.exists()
        saved = json.loads(output_file.read_text())
        assert "Statement" in saved
        assert "Version" in saved

    def test_fix_text_format_prints_fixed_policy(self, tmp_path):
        from app.cli import cmd_fix
        args = _make_fix_args(tmp_path, _ALL_ACTIONS_POLICY, fmt="text")
        with _capture_stdout() as buf:
            cmd_fix(args)
        output = buf.getvalue()
        # Should contain the JSON policy block and a summary header
        assert "Proposed Policy" in output
        assert "Statement" in output

    def test_fix_json_error_on_missing_file(self, tmp_path):
        from app.cli import cmd_fix
        args = argparse.Namespace(
            file=str(tmp_path / "nonexistent.json"), format="json", output=None
        )
        with _capture_stdout() as buf:
            with pytest.raises(SystemExit) as exc_info:
                cmd_fix(args)
        assert exc_info.value.code == 1
        data = json.loads(buf.getvalue())
        assert data["status"] == "error"

# ── Risk Score Tests ──────────────────────────────────────────────────────────

class TestCalculateRiskScore:
    """Tests for calculate_risk_score() and risk_score_label()."""

    from app.analyzer import calculate_risk_score, risk_score_label

    _FULL_ADMIN_POLICY = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    })

    _SINGLE_HIGH_POLICY = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "arn:aws:iam::123456789012:role/MyRole",
        }],
    })

    _SINGLE_MEDIUM_POLICY = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::123456789012:role/MyRole",
        }],
    })

    _CLEAN_POLICY = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::my-bucket/*",
        }],
    })

    def test_full_admin_scores_80_plus(self):
        from app.analyzer import calculate_risk_score
        score = calculate_risk_score(self._FULL_ADMIN_POLICY)
        assert score >= 80, f"Expected >=80, got {score}"

    def test_full_admin_score_capped_at_100(self):
        from app.analyzer import calculate_risk_score
        score = calculate_risk_score(self._FULL_ADMIN_POLICY)
        assert score == 100

    def test_single_high_risk_action_scores_8_to_20(self):
        from app.analyzer import calculate_risk_score
        score = calculate_risk_score(self._SINGLE_HIGH_POLICY)
        assert 8 <= score <= 20, f"Expected 8-20, got {score}"

    def test_single_medium_risk_action_scores_4_to_10(self):
        from app.analyzer import calculate_risk_score
        score = calculate_risk_score(self._SINGLE_MEDIUM_POLICY)
        assert 4 <= score <= 10, f"Expected 4-10, got {score}"

    def test_clean_policy_scores_zero(self):
        from app.analyzer import calculate_risk_score
        score = calculate_risk_score(self._CLEAN_POLICY)
        assert score == 0

    def test_score_never_exceeds_100(self):
        from app.analyzer import calculate_risk_score
        # Many statements with overlapping high-risk actions
        many_stmts = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"},
                {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
                {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
            ],
        }
        score = calculate_risk_score(json.dumps(many_stmts))
        assert score <= 100

    def test_risk_level_mapping_low(self):
        from app.analyzer import risk_score_label
        assert risk_score_label(0) == "Low"
        assert risk_score_label(20) == "Low"

    def test_risk_level_mapping_medium(self):
        from app.analyzer import risk_score_label
        assert risk_score_label(21) == "Medium"
        assert risk_score_label(50) == "Medium"

    def test_risk_level_mapping_high(self):
        from app.analyzer import risk_score_label
        assert risk_score_label(51) == "High"
        assert risk_score_label(100) == "High"

    def test_score_in_escalate_json_output(self, tmp_path):
        from app.cli import cmd_escalate
        policy_file = tmp_path / "p.json"
        policy_file.write_text(self._FULL_ADMIN_POLICY)
        args = argparse.Namespace(
            file=str(policy_file), format="json", ai=False
        )
        with _capture_stdout() as buf:
            cmd_escalate(args)
        data = json.loads(buf.getvalue())
        assert "risk_score" in data
        assert isinstance(data["risk_score"], int)
        assert data["risk_score"] >= 80

    def test_fix_shows_before_after_score_in_json(self, tmp_path):
        from app.cli import cmd_fix
        policy_file = tmp_path / "p.json"
        policy_file.write_text(self._FULL_ADMIN_POLICY)
        args = argparse.Namespace(
            file=str(policy_file), format="json", output=None
        )
        with _capture_stdout() as buf:
            cmd_fix(args)
        data = json.loads(buf.getvalue())
        assert "original_risk_score" in data
        assert "fixed_risk_score" in data
        assert data["original_risk_score"] > data["fixed_risk_score"]

    def test_fix_shows_before_after_score_in_text(self, tmp_path):
        from app.cli import cmd_fix
        policy_file = tmp_path / "p.json"
        policy_file.write_text(self._FULL_ADMIN_POLICY)
        args = argparse.Namespace(
            file=str(policy_file), format="text", output=None
        )
        with _capture_stdout() as buf:
            cmd_fix(args)
        output = buf.getvalue()
        assert "Risk Score" in output
        assert "→" in output

    def test_sarif_includes_risk_score_in_properties(self, tmp_path):
        from app.cli import cmd_escalate
        policy_file = tmp_path / "p.json"
        policy_file.write_text(self._FULL_ADMIN_POLICY)
        args = argparse.Namespace(
            file=str(policy_file), format="sarif", ai=False
        )
        with _capture_stdout() as buf:
            cmd_escalate(args)
        data = json.loads(buf.getvalue())
        run = data["runs"][0]
        assert "properties" in run
        assert "risk_score" in run["properties"]
        assert run["properties"]["risk_score"] >= 80

    def test_escalate_local_result_has_risk_score_field(self):
        from app.analyzer import escalate_policy_local
        result = escalate_policy_local(self._FULL_ADMIN_POLICY)
        assert hasattr(result, "risk_score")
        assert result.risk_score >= 80

    def test_not_action_adds_r006_score(self):
        from app.analyzer import calculate_risk_score
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "NotAction": ["s3:DeleteObject"],
                "Resource": "*",
            }],
        })
        score = calculate_risk_score(policy)
        assert score >= 10  # R006 alone = 10


# ---------------------------------------------------------------------------
# fix --ai tests
# ---------------------------------------------------------------------------

_LAMBDA_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "DangerousLambda",
        "Effect": "Allow",
        "Action": ["lambda:CreateFunction", "lambda:UpdateFunctionCode"],
        "Resource": "*",
    }],
})

_AI_FIXED_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "LambdaReadOnly",
        "Effect": "Allow",
        "Action": ["lambda:GetFunction", "lambda:ListFunctions"],
        "Resource": "arn:aws:lambda:*:123456789012:function:*",
    }],
}

_AI_RESPONSE_JSON = json.dumps({
    "fixed_policy": _AI_FIXED_POLICY,
    "explanation": "Replaced dangerous Lambda write actions with read-only equivalents.",
})


def _make_mock_anthropic(response_text: str):
    """Return a mock anthropic.Anthropic class whose messages.create() returns response_text."""
    mock_client = MagicMock()
    mock_msg = MagicMock()
    mock_msg.content[0].text = response_text
    mock_client.messages.create.return_value = mock_msg
    mock_cls = MagicMock(return_value=mock_client)
    return mock_cls, mock_client


class TestFixAI:
    """Tests for fix_policy_ai() and cmd_fix --ai integration."""

    def _local_result(self):
        from app.analyzer import fix_policy_local
        return fix_policy_local(_LAMBDA_POLICY)

    # ── fix_policy_ai unit tests ───────────────────────────────────────────

    def test_fix_policy_ai_returns_fixresult_with_ai_generated_true(self):
        from app.analyzer import fix_policy_ai
        mock_cls, _ = _make_mock_anthropic(_AI_RESPONSE_JSON)
        with patch("app.analyzer.anthropic.Anthropic", mock_cls):
            result = fix_policy_ai(
                policy_json=_LAMBDA_POLICY,
                local_result=self._local_result(),
                api_key="fake-key",
            )
        assert result.ai_generated is True

    def test_fix_policy_ai_fixed_policy_comes_from_claude(self):
        from app.analyzer import fix_policy_ai
        mock_cls, _ = _make_mock_anthropic(_AI_RESPONSE_JSON)
        with patch("app.analyzer.anthropic.Anthropic", mock_cls):
            result = fix_policy_ai(
                policy_json=_LAMBDA_POLICY,
                local_result=self._local_result(),
                api_key="fake-key",
            )
        stmt = result.fixed_policy["Statement"][0]
        assert stmt["Resource"] == "arn:aws:lambda:*:123456789012:function:*"
        assert "lambda:GetFunction" in stmt["Action"]

    def test_fix_policy_ai_populates_ai_explanation(self):
        from app.analyzer import fix_policy_ai
        mock_cls, _ = _make_mock_anthropic(_AI_RESPONSE_JSON)
        with patch("app.analyzer.anthropic.Anthropic", mock_cls):
            result = fix_policy_ai(
                policy_json=_LAMBDA_POLICY,
                local_result=self._local_result(),
                api_key="fake-key",
            )
        assert "Lambda" in result.ai_explanation
        assert result.ai_disclaimer != ""

    def test_fix_policy_ai_calls_claude_once(self):
        from app.analyzer import fix_policy_ai
        mock_cls, mock_client = _make_mock_anthropic(_AI_RESPONSE_JSON)
        with patch("app.analyzer.anthropic.Anthropic", mock_cls):
            fix_policy_ai(
                policy_json=_LAMBDA_POLICY,
                local_result=self._local_result(),
                api_key="fake-key",
            )
        mock_client.messages.create.assert_called_once()

    def test_fix_policy_ai_raises_runtime_error_on_api_error(self):
        import anthropic as anthropic_lib
        from app.analyzer import fix_policy_ai
        mock_cls, mock_client = _make_mock_anthropic("")
        mock_client.messages.create.side_effect = anthropic_lib.APIError(
            message="quota exceeded", request=MagicMock(), body=None
        )
        with patch("app.analyzer.anthropic.Anthropic", mock_cls):
            with pytest.raises(RuntimeError, match="Claude fix failed"):
                fix_policy_ai(
                    policy_json=_LAMBDA_POLICY,
                    local_result=self._local_result(),
                    api_key="fake-key",
                )

    def test_fix_policy_ai_raises_on_invalid_json_response(self):
        from app.analyzer import fix_policy_ai
        mock_cls, _ = _make_mock_anthropic("not valid json")
        with patch("app.analyzer.anthropic.Anthropic", mock_cls):
            with pytest.raises(RuntimeError, match="invalid JSON"):
                fix_policy_ai(
                    policy_json=_LAMBDA_POLICY,
                    local_result=self._local_result(),
                    api_key="fake-key",
                )

    def test_fix_policy_ai_raises_on_missing_fixed_policy_key(self):
        from app.analyzer import fix_policy_ai
        bad_response = json.dumps({"explanation": "oops, forgot fixed_policy"})
        mock_cls, _ = _make_mock_anthropic(bad_response)
        with patch("app.analyzer.anthropic.Anthropic", mock_cls):
            with pytest.raises(RuntimeError, match="missing valid 'fixed_policy'"):
                fix_policy_ai(
                    policy_json=_LAMBDA_POLICY,
                    local_result=self._local_result(),
                    api_key="fake-key",
                )

    # ── cmd_fix --ai CLI integration tests ────────────────────────────────

    def test_cmd_fix_ai_text_output_shows_ai_mode_header(self, tmp_path):
        from app.cli import cmd_fix
        args = argparse.Namespace(
            file=str(tmp_path / "p.json"), format="text", output=None, ai=True
        )
        (tmp_path / "p.json").write_text(_LAMBDA_POLICY)
        mock_cls, _ = _make_mock_anthropic(_AI_RESPONSE_JSON)
        env = {"ANTHROPIC_API_KEY": "fake-key"}
        with patch("app.analyzer.anthropic.Anthropic", mock_cls), \
             patch.dict("os.environ", env), \
             _capture_stdout() as buf:
            cmd_fix(args)
        assert "AI Mode" in buf.getvalue()

    def test_cmd_fix_ai_text_output_shows_ai_notice(self, tmp_path):
        from app.cli import cmd_fix
        args = argparse.Namespace(
            file=str(tmp_path / "p.json"), format="text", output=None, ai=True
        )
        (tmp_path / "p.json").write_text(_LAMBDA_POLICY)
        mock_cls, _ = _make_mock_anthropic(_AI_RESPONSE_JSON)
        env = {"ANTHROPIC_API_KEY": "fake-key"}
        with patch("app.analyzer.anthropic.Anthropic", mock_cls), \
             patch.dict("os.environ", env), \
             _capture_stdout() as buf:
            cmd_fix(args)
        output = buf.getvalue()
        assert "AI Notice" in output
        assert "AI Analysis" in output

    def test_cmd_fix_ai_json_output_has_ai_fields(self, tmp_path):
        from app.cli import cmd_fix
        args = argparse.Namespace(
            file=str(tmp_path / "p.json"), format="json", output=None, ai=True
        )
        (tmp_path / "p.json").write_text(_LAMBDA_POLICY)
        mock_cls, _ = _make_mock_anthropic(_AI_RESPONSE_JSON)
        env = {"ANTHROPIC_API_KEY": "fake-key"}
        with patch("app.analyzer.anthropic.Anthropic", mock_cls), \
             patch.dict("os.environ", env), \
             _capture_stdout() as buf:
            cmd_fix(args)
        data = json.loads(buf.getvalue())
        assert data["ai_generated"] is True
        assert "ai_explanation" in data
        assert "ai_disclaimer" in data

    def test_cmd_fix_ai_json_fixed_policy_is_from_claude(self, tmp_path):
        from app.cli import cmd_fix
        args = argparse.Namespace(
            file=str(tmp_path / "p.json"), format="json", output=None, ai=True
        )
        (tmp_path / "p.json").write_text(_LAMBDA_POLICY)
        mock_cls, _ = _make_mock_anthropic(_AI_RESPONSE_JSON)
        env = {"ANTHROPIC_API_KEY": "fake-key"}
        with patch("app.analyzer.anthropic.Anthropic", mock_cls), \
             patch.dict("os.environ", env), \
             _capture_stdout() as buf:
            cmd_fix(args)
        data = json.loads(buf.getvalue())
        stmt = data["fixed_policy"]["Statement"][0]
        assert stmt["Resource"] == "arn:aws:lambda:*:123456789012:function:*"

    def test_cmd_fix_local_mode_has_no_ai_fields_in_text(self, tmp_path):
        """Local fix (no --ai) must not show AI Mode header or AI Notice."""
        from app.cli import cmd_fix
        args = _make_fix_args(tmp_path, _LAMBDA_POLICY, fmt="text")
        with _capture_stdout() as buf:
            cmd_fix(args)
        output = buf.getvalue()
        assert "AI Mode" not in output
        assert "AI Notice" not in output


# ---------------------------------------------------------------------------
# Messaging layer distinction tests (Task 3)
# ---------------------------------------------------------------------------

class TestMessagingLayerDistinctions:
    """Regression tests for three-layer evidence vocabulary in user-facing text.

    Verifies that:
    - R003 findings use 'reviewed high-risk' (not 'dangerous') vocabulary.
    - R004 findings use 'reviewed medium-risk' (not 'sensitive') vocabulary.
    - Escalation summaries use reviewed-classification vocabulary.
    - CLI fix output uses context-dependent wording for medium-risk actions.
    - Unknown actions in the CLI appear in 'Needs Review', not 'Confirmed'.
    """

    # Eight high-risk actions → score 79 → risk_level "High"
    _HIGH_RISK_ONLY_POLICY = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": [
            "iam:PassRole", "iam:CreateRole", "iam:AttachRolePolicy",
            "iam:PutRolePolicy", "iam:CreatePolicyVersion",
            "iam:SetDefaultPolicyVersion", "sts:AssumeRole",
            "iam:AddUserToGroup",
        ], "Resource": "*"}],
    })

    # Two medium-risk-only actions → score 23 → risk_level "Medium"
    # (iam:CreateAccessKey 4 + secretsmanager:GetSecretValue 4 + R001 10 + R005 5 = 23)
    # Neither action is in HIGH_RISK_ACTIONS, so the summary must say "medium-risk".
    _MEDIUM_RISK_ONLY_POLICY = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": [
            "iam:CreateAccessKey", "secretsmanager:GetSecretValue",
        ], "Resource": "*"}],
    })

    # Medium-risk action (not in HIGH_RISK_ACTIONS) → produces R004, kept by fix
    _MEDIUM_RISK_R004_POLICY = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["iam:CreateAccessKey"], "Resource": "*"}],
    })

    def test_r003_title_uses_reviewed_high_risk_vocabulary(self):
        """R003 finding titles must say 'Reviewed high-risk action', not 'Dangerous action'."""
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(self._HIGH_RISK_ONLY_POLICY)
        r003_titles = [f.title for f in findings if f.rule_id == "R003"]
        assert r003_titles, "Expected at least one R003 finding for iam:PassRole"
        for title in r003_titles:
            assert "Reviewed high-risk action" in title, (
                f"R003 title must use reviewed-classification vocabulary; got: {title!r}"
            )
            assert "Dangerous" not in title

    def test_r004_title_uses_reviewed_medium_risk_vocabulary(self):
        """R004 finding titles must say 'Reviewed medium-risk action', not 'Sensitive action'."""
        from app.analyzer import analyze_policy_rules
        findings = analyze_policy_rules(self._MEDIUM_RISK_R004_POLICY)
        r004_titles = [f.title for f in findings if f.rule_id == "R004"]
        assert r004_titles, "Expected at least one R004 finding for iam:CreateAccessKey"
        for title in r004_titles:
            assert "Reviewed medium-risk action" in title, (
                f"R004 title must use reviewed-classification vocabulary; got: {title!r}"
            )
            assert "Sensitive" not in title

    def test_escalation_summary_uses_reviewed_high_risk_vocabulary(self):
        """Escalation summary for High risk must reference 'reviewed high-risk'."""
        from app.analyzer import escalate_policy_local, risk_score_label, calculate_risk_score
        score = calculate_risk_score(self._HIGH_RISK_ONLY_POLICY)
        assert risk_score_label(score) == "High", (
            f"Test setup error: expected High risk score, got {score}"
        )
        result = escalate_policy_local(self._HIGH_RISK_ONLY_POLICY)
        assert result.risk_level == "High"
        assert "reviewed high-risk" in result.summary, (
            f"Escalation summary must use reviewed-classification vocabulary; got: {result.summary!r}"
        )
        assert "dangerous" not in result.summary.lower()

    def test_escalation_summary_uses_reviewed_medium_risk_vocabulary(self):
        """Escalation summary for Medium risk must reference 'reviewed medium-risk'."""
        from app.analyzer import escalate_policy_local, risk_score_label, calculate_risk_score
        score = calculate_risk_score(self._MEDIUM_RISK_ONLY_POLICY)
        assert risk_score_label(score) == "Medium", (
            f"Test setup error: expected Medium risk score, got {score}"
        )
        result = escalate_policy_local(self._MEDIUM_RISK_ONLY_POLICY)
        assert result.risk_level == "Medium"
        assert "reviewed medium-risk" in result.summary, (
            f"Escalation summary must use reviewed-classification vocabulary; got: {result.summary!r}"
        )
        assert "sensitive" not in result.summary.lower()

    def test_fix_output_medium_risk_note_uses_context_dependent_wording(self):
        """_print_fix must say 'context-dependent' for medium-risk retained actions."""
        from app.cli import _print_fix
        from app.analyzer import fix_policy_local, calculate_risk_score
        result = fix_policy_local(self._MEDIUM_RISK_R004_POLICY)
        original_score = calculate_risk_score(self._MEDIUM_RISK_R004_POLICY)
        import json as _json
        fixed_score = calculate_risk_score(_json.dumps(result.fixed_policy))
        with _capture_stdout() as buf:
            _print_fix(result, output_path=None, original_score=original_score, fixed_score=fixed_score)
        output = buf.getvalue()
        assert "context-dependent" in output.lower(), (
            "Medium-risk retention note must explain risk is context-dependent"
        )
