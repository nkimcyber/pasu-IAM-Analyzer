"""
main.py — FastAPI application entry point for the IAM Analyzer Project.
"""

import logging
from pathlib import Path

from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from app.analyzer import analyze_policy, escalate_policy, explain_policy
from app.models import AnalysisResult, AnalyzeRequest, EscalationResult, ExplainRequest, ExplainResult

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="IAM Analyzer",
    description="Analyzes AWS IAM policies for security risks using Claude AI.",
    version="0.1.0",
)

# Mount static files if the directory exists
_static_dir = Path(__file__).parent / "static"
if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

router = APIRouter(prefix="/api/v1", tags=["iam"])


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    """Serve the Web UI."""
    html_path = Path(__file__).parent / "static" / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@router.post("/escalate", response_model=EscalationResult)
def escalate(request: ExplainRequest) -> EscalationResult:
    """Detect privilege escalation risks in a pasted IAM policy JSON.

    Args:
        request: ExplainRequest containing the raw policy JSON string.

    Returns:
        EscalationResult with risk level, detected actions, and findings.

    Raises:
        HTTPException 400: If the JSON is invalid or not a valid IAM policy.
        HTTPException 500: On Claude API failure.
    """
    try:
        return escalate_policy(policy_json=request.policy_json)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        logger.error("Escalation check failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/explain", response_model=ExplainResult)
def explain(request: ExplainRequest) -> ExplainResult:
    """Explain a pasted IAM policy JSON in plain English.

    Args:
        request: ExplainRequest containing the raw policy JSON string.

    Returns:
        ExplainResult with a one-sentence summary and bullet point details.

    Raises:
        HTTPException 400: If the JSON is invalid.
        HTTPException 500: On Claude API failure.
    """
    try:
        return explain_policy(policy_json=request.policy_json)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        logger.error("Explain failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/analyze", response_model=AnalysisResult)
def analyze(request: AnalyzeRequest) -> AnalysisResult:
    """Analyze a single IAM policy and return Claude's security findings.

    Args:
        request: AnalyzeRequest containing policy_arn and account_id.

    Returns:
        AnalysisResult with Claude's findings.

    Raises:
        HTTPException 500: On AWS or Claude API failure.
    """
    try:
        return analyze_policy(
            policy_arn=request.policy_arn,
            account_id=request.account_id,
        )
    except RuntimeError as exc:
        logger.error("Analysis failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/health")
def health() -> dict:
    """Health check endpoint.

    Returns:
        JSON dict with status 'ok'.
    """
    return {"status": "ok"}


app.include_router(router)