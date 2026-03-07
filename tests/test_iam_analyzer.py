"""
test_iam_analyzer.py — pytest test suite for the IAM Analyzer Project.

Covers:
- Pydantic model validation
- aws_client helpers (mocked boto3)
- analyzer.analyze_policy (mocked boto3 + Claude)
- analyzer.explain_policy (mocked Claude)
- FastAPI endpoints via TestClient
"""

import json
from unittest.mock import MagicMock, patch

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


class TestIndexEndpoint:
    def test_index_returns_html(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "IAM Policy Explainer" in response.text