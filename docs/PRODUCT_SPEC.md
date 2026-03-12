# Pasu — Product Specification

> **Pasu (파수/把守)** — Guardian of your Cloud IAM  
> Project codename: **Moon**

---

## 1. Vision

**One-liner:** A lightweight CLI for analyzing AWS IAM permissions, explaining risky access in plain English, and helping users move toward safer policies.

Pasu is designed for engineers who want a fast, self-serve IAM security workflow without complex setup.

### What Pasu tries to do well
- Explain what an IAM policy actually allows
- Detect risky permissions and privilege escalation paths
- Show a clear risk score
- Generate a safer **proposed policy**
- Tell users what still requires manual review

### Product philosophy
Pasu should be useful on day one:
- install quickly
- run locally
- explain results clearly
- avoid unsafe or misleading “magic fixes”

---

## 2. Current State (post-Phase 1 externalization)

**PyPI:** `https://pypi.org/project/pasu/`  
**Install:** `pip install pasu`

### Shipped Features

#### CLI commands
- `pasu explain --file policy.json` — Explain IAM policies in plain English
- `pasu escalate --file policy.json` — Detect privilege escalation risks
- `pasu scan --file policy.json` — Combined explain + escalate report
- `pasu fix --file policy.json` — Generate a safer **proposed policy**
- All commands support: `--ai`, `--format text|json|sarif`, `-q`

#### Local mode (free, no API key required)
- 30 detection rules
  - 19 high-risk
  - 6 medium-risk
  - 5 structural
- Risk scoring from 0–100 with a visual bar
- Human-readable explanations
- Conservative policy fixing
- JSON and SARIF output for CI/CD integration

#### AI mode (`--ai`, requires Anthropic API key)
- Claude Haiku for deeper analysis
- More detailed natural-language explanations
- Escalation-path-oriented output
- Local analysis first, AI only when needed

#### Infrastructure
- 159 pytest tests passing
- GitHub Actions CI/CD
- PyPI published
- Example GitHub Actions workflow for users
- Rule/scoring/fix data externalized into packaged config files

---

## 3. Rule and Scoring Architecture

Phase 1 moved the local analyzer away from a fully hardcoded rule layout.

### Current packaged analyzer data
- `app/rules/risky_actions.yaml`
- `app/rules/scoring.yaml`
- `app/rules/fix_profiles.yaml`
- `app/data/aws_catalog.json`

### What this changed
- Detection taxonomy is easier to update and review
- Scoring changes are separated from analyzer logic
- Fix profiles are easier to expand without large code edits
- Packaging now explicitly includes rule/data files
- CLI and API contracts remain stable

### What Phase 1 did **not** do
- It did not add a live AWS catalog sync job
- It did not auto-classify new AWS actions into risk tiers
- It did not change Pasu into a full live-account audit platform

---

## 4. What `pasu fix` does today

`pasu fix` is intentionally conservative.

It does **not** promise a perfect final least-privilege policy.  
It generates a safer **proposed policy** and explains what still needs review.

### Current fix behavior
- Removes obvious high-risk actions when safe to do so
- Keeps some medium-risk actions if auto-removing them may break intended access
- Keeps wildcard resources when Pasu cannot safely narrow them without resource-specific context
- Adds warnings and notes to explain why some broad permissions remain
- Adds manual-review guidance when auto-fix cannot safely finish the statement

### Important behavior
The output from `pasu fix` is designed to be:
- reviewable
- explicit
- conservative
- less misleading than an overconfident “auto-remediation” result

### Current output improvements
`pasu fix` currently includes:
- risk level and risk score that use the same scoring basis
- grouped wildcard-resource warnings by statement number
- human-facing statement numbering using 1-based numbering
- `Proposed Policy` wording instead of `Fixed Policy`
- text highlighting for:
  - `TODO:specify-needed-actions`
  - risky `Allow + Resource "*"`
- explanation for why wildcard resources remain
- explanation for which medium-risk actions remain
- manual review messages that include:
  - statement number
  - `Sid` when present
  - the next action the user should take

---

## 5. Example `pasu fix` behavior

A typical `pasu fix` result may:
- remove `iam:PassRole`
- remove `lambda:CreateFunction`
- remove `lambda:UpdateFunctionCode`
- keep `sts:AssumeRole`
- keep `ec2:DescribeInstances`
- keep `secretsmanager:GetSecretValue`
- keep `ssm:GetParameter`
- keep `Resource: "*"` when safe narrowing is not possible
- insert `"TODO:specify-needed-actions"` when all risky actions in a statement were removed

That is expected behavior.

Pasu currently prefers:
- a safer **proposed policy**
- plus warnings and manual review guidance

over:
- an aggressive auto-fix that may silently break intended access

---

## 6. Not Yet Built

- Azure support
- GCP support
- Trust policy analysis expansion
- Batch policy analysis
- Multi-account AWS support (STS AssumeRole workflows)
- Full live-account audit workflows
- Structured logging improvements
- Team workflows / collaboration features
- Hosted web product

---

## 7. Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.11.9 |
| Primary Interface | CLI |
| Web Framework | FastAPI |
| AI Model | Claude Haiku |
| AWS SDK | boto3 |
| Validation | Pydantic |
| Testing | pytest |
| CI/CD | GitHub Actions |
| Package Registry | PyPI |

---

## 8. Near-Term Technical Roadmap

### Phase 1 — AWS CLI hardening
**Status:** Done

Completed:
- Improve policy-fix clarity and safety
- Expand rule coverage
- Improve CI/CD integration outputs
- Improve auditability and test coverage
- Externalize rule/scoring/fix data into packaged files
- Preserve CLI/API behavior while refactoring analyzer internals

### Phase 1.5 — AWS catalog update workflow
**Status:** Next

Planned:
- Add AWS catalog refresh script/workflow
- Generate diffs for new or changed AWS actions
- Surface unclassified actions for human review
- Keep scoring and risk-tier assignment review-based, not fully automatic

### Phase 2 — Azure support and team workflows
- Azure RBAC / Entra ID analysis
- Better workflow support for team usage
- Shared reporting and notifications
- Broader multi-environment support

### Phase 3 — GCP and broader enterprise controls
- GCP IAM support
- Cross-cloud analysis patterns
- Better organizational controls and reporting

---

## 9. Core Principles

### 1. Local-first by default
Users should get useful results without needing a hosted account or API key.

### 2. Explain before impressing
Security tools should explain what is risky, why it matters, and what users should do next.

### 3. Conservative fixes over unsafe automation
Pasu should prefer a reviewable **proposed policy** over an overconfident or destructive auto-remediation.

### 4. Human-readable output matters
Results should be understandable even for people who are not deep IAM experts.

### 5. Clear machine-readable output matters too
JSON and SARIF should remain useful for automation and CI/CD pipelines.

### 6. One cloud problem at a time
Depth and correctness are more important than claiming broad cloud coverage too early.

### 7. Community-first product discipline
The public CLI should solve real user problems before broader platform ambitions are expanded.

---

## 10. Coding Standards

- PEP 484 type annotations on all functions
- Google-style docstrings
- Black formatting (88-char line limit)
- No hardcoded credentials
- All boto3 calls wrapped with `try/except ClientError`
- All Claude API calls wrapped with `try/except APIError`
- ERROR-level logging before re-raise
- Complete file outputs preferred over partial snippets during code generation

---

## 11. Maintainer Notes

This public specification is intentionally focused on:
- current product behavior
- technical direction
- output quality
- safety principles

Additional current note:
- The packaged `aws_catalog.json` is currently a placeholder data layer for future update workflows.
- The next meaningful backend step is AWS catalog sync + diff generation, not full automatic rule classification.