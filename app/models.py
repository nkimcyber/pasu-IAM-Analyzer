"""
models.py — Pydantic request/response models for the IAM Analyzer Project.
"""

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    """Request body for the /analyze endpoint."""

    policy_arn: str = Field(..., description="Full ARN of the IAM policy to analyze.")
    account_id: str = Field(..., description="AWS account ID owning the policy.")


class IAMPolicyResponse(BaseModel):
    """Parsed representation of an AWS IAM policy list entry."""

    PolicyName: str
    PolicyId: str
    Arn: str
    Path: str
    DefaultVersionId: str
    AttachmentCount: int
    IsAttachable: bool


class AnalysisResult(BaseModel):
    """Response model returned by the /analyze endpoint."""

    policy_arn: str
    findings: str = Field(..., description="Claude's security analysis of the policy.")
    status: str = Field(default="ok")


class ExplainRequest(BaseModel):
    """Request body for the /explain endpoint."""

    policy_json: str = Field(
        ..., description="Raw IAM policy JSON string pasted by the user."
    )


class ExplainResult(BaseModel):
    """Response model returned by the /explain endpoint."""

    summary: str = Field(..., description="One-sentence plain English summary.")
    details: list[str] = Field(
        ..., description="Bullet point list of what each statement does."
    )
    status: str = Field(default="ok")


class EscalationFinding(BaseModel):
    """A single detected privilege escalation finding."""

    action: str = Field(..., description="The risky IAM action detected.")
    explanation: str = Field(..., description="What the action allows and why it is risky.")
    escalation_path: str = Field(..., description="Simplified escalation path string.")


class EscalationResult(BaseModel):
    """Response model returned by the /escalate endpoint."""

    risk_level: str = Field(..., description="Overall risk level: High, Medium, or Low.")
    detected_actions: list[str] = Field(
        ..., description="List of risky actions found in the policy."
    )
    findings: list[EscalationFinding] = Field(
        ..., description="Detailed finding for each detected risky action."
    )
    summary: str = Field(..., description="One-sentence overall risk summary.")
    status: str = Field(default="ok")