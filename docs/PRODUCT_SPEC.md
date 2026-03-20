# Pasu — Product Specification

> **Pasu (파수/把守)** — Guardian of your Cloud IAM  
> Project codename: **Moon**

---

## 1. Vision

**One-liner:** A lightweight CLI for analyzing AWS IAM permissions, explaining risky access in plain English, and helping users move toward safer policies.

Pasu is designed for engineers who want a fast, self-serve IAM security workflow without complex setup.

### What Pasu tries to do well
- Explain what an IAM policy actually allows
- Detect risky permissions and escalation-related patterns
- Show a clear risk score
- Generate a safer **proposed policy**
- Tell users what still requires manual review

### Product philosophy
Pasu should be useful on day one:
- install quickly
- run locally
- explain results clearly
- avoid unsafe or misleading "magic fixes"

---

## 2. Current State (post-Phase 1 and Phase 1.5 completion, Phase 2 foundation)

**PyPI:** `https://pypi.org/project/pasu/`  
**Install:** `pip install pasu`

### Shipped Features

#### CLI commands
- `pasu explain --file policy.json` — Explain IAM policies in plain English
- `pasu escalate --file policy.json` — Detect privilege escalation risks
- `pasu scan --file policy.json` — Combined explain + escalate report
- `pasu scan --profile <profile>` — Scan IAM roles and users from AWS account
- `pasu fix --file policy.json` — Generate a safer **proposed policy** (local or AI-powered)

#### Current CLI option support
- `explain`, `escalate`, `scan`
  - `--ai`
  - `--format text|json|sarif`
- `scan` with AWS profiles
  - `--profile <profile_name>`
  - `--format text|json|sarif`
  - Output includes Policy ARN for AWS Console navigation
- `fix`
  - `--ai`
  - `--format text|json`
  - `--output` / `-o`
- Global option
  - `-q` / `--quiet`

#### Local mode (free, no API key required)
- 30 detection rules
  - 19 high-risk
  - 6 medium-risk
  - 5 structural
- Risk scoring from 0–100 with a visual bar
- Human-readable explanations
- Conservative policy fixing with SAFE_ALTERNATIVES mapping
  - 25+ dangerous IAM action patterns mapped to safe read-only alternatives
  - Fallback guidance for actions with no safe alternative
- JSON and SARIF output for `explain`, `escalate`, and `scan`
- JSON output for `fix`

#### AI mode (`--ai`, requires Anthropic API key)
- Claude Haiku for deeper analysis
- More detailed natural-language explanations
- Escalation-path-oriented output for risky policies
- `escalate --ai` performs local reviewed-action detection first and skips Claude when no reviewed high-risk actions are found
- `explain --ai` and AI-backed `scan` use Claude for richer output rather than a local-first fallback
- **NEW:** `fix --ai` infers policy intent from structure and generates context-aware least-privilege policies with automatic Condition blocks and ARN scoping

#### AWS CLI Profile Scanning (Phase 2)
- `pasu scan --profile <profile>` scans all IAM roles and users from AWS account
- Reads credentials from local AWS CLI configuration (`~/.aws/credentials` or `~/.aws/config`)
- Requires AWS user to have read-only IAM permissions (e.g., `IAMReadOnlyAccess`)
- All analysis is performed locally; no data is transmitted outside the machine
- Output includes Policy ARN (e.g., `arn:aws:iam::123456789012:role/RoleName`) for direct AWS Console navigation

#### `pasu fix` improvements (Phase 2 foundation)
- **Local mode (default):**
  - Uses SAFE_ALTERNATIVES dictionary to replace dangerous actions with safe read-only alternatives
  - Provides Condition block guidance for actions with no safe alternative
  - Per-statement change tracking in output
  - Fast, works offline

- **AI mode (`--ai`):**
  - Claude infers the policy's intent based on Sids, action combinations, and resource patterns
  - Generates context-aware least-privilege replacement with minimal required permissions
  - Automatically adds appropriate Condition blocks
  - Scopes wildcard resources to specific ARN patterns where possible
  - Includes explanations for each decision
  - Reports on inferred intent confidence level


#### Infrastructure
- 160+ pytest tests passing (includes AI mock tests)
- GitHub Actions CI/CD
- PyPI published
- Example GitHub Actions workflow for users
- Rule/scoring/fix data externalized into packaged config files
- Canonical AWS action catalog snapshot stored in-repo
- Local AWS catalog sync/diff and review-queue generation implemented and validated
- SAFE_ALTERNATIVES mapping for fix remediation

---

## 3. Security & Privacy Model

### Local-first data handling

Pasu reads IAM metadata exclusively from the user's local AWS CLI configuration. When scanning AWS accounts:

- **No data transmission:** All IAM metadata processing happens locally on the user's machine
- **Credentials stay local:** AWS credentials are read from `~/.aws/credentials` or `~/.aws/config` and never transmitted
- **Read-only operations:** Pasu uses boto3 for read-only IAM API calls only (GetRole, ListRoles, etc.)
- **No network calls from Pasu:** The only network activity is boto3's communication with AWS IAM API endpoints
- **User shown in `aws sts get-caller-identity`:** That same AWS user must have read-only IAM permissions

### AI mode exception

`--ai` mode is the only scenario where Pasu transmits data outside the local machine:

- Policy JSON text is sent to Anthropic's Claude API for analysis
- This is **optional** and only occurs when the user explicitly includes `--ai` flag
- Default mode (`--ai` not specified) performs all analysis locally

### Security requirements

The AWS user running Pasu must have read-only IAM permissions:

- Recommended: `IAMReadOnlyAccess` managed policy
- Minimum: permissions to call `iam:List*` and `iam:Get*` operations
- Pasu does not require write permissions

---

## 4. Rule and Scoring Architecture

Phase 1 moved the local analyzer away from a fully hardcoded rule layout.

### Current analyzer rule/data layers

#### Core risk and fix configuration
- `app/rules/risky_actions.yaml`
- `app/rules/scoring.yaml`
- `app/rules/fix_profiles.yaml`

#### Reviewed classification and capability vocabulary
- `app/rules/action_classification.yaml`
- `app/rules/capabilities.yaml`

#### Composite detection layer
- `app/rules/composite_detections.yaml`

#### Catalog and generated review data
- `app/data/aws_catalog.json`
- `app/data/review_queue.json`

#### Fix remediation (Phase 2)
- SAFE_ALTERNATIVES mapping in `pasu/fix.py` (25+ patterns)
- Maps dangerous IAM actions → safe read-only alternatives
- Fallback guidance for actions with no alternative

### What this changed
- Detection taxonomy is easier to update and review
- Scoring changes are separated from analyzer logic
- Fix profiles are easier to expand without large code edits
- Reviewed action classification is now distinct from raw AWS catalog ingestion
- Capability names are controlled through a shared vocabulary
- Composite detections can be added without embedding every relationship in Python logic
- Packaging now explicitly includes rule/data files
- CLI and API contracts remain stable
- Fix remediation uses structured mapping instead of hardcoded logic

### Current boundary of this architecture
- Pasu still does **not** auto-classify new AWS actions into risk tiers
- Reviewed classifications remain a human-governed layer
- Composite detections currently act primarily as review/evidence logic, not as a fully separate end-user reporting surface across every command
- Pasu is still a local-first CLI, not a hosted cloud platform
- AI fix uses Claude for intent inference, not for risk tier assignment

---

## 5. AWS Catalog Sync Foundation

Phase 1.5 adds the local foundation for keeping packaged AWS action metadata current.

### Source of truth
- **AWS Service Authorization Reference only**
- No secondary source is currently used

### Canonical snapshot
- `app/data/aws_catalog.json`

### Review workflow outputs
- `app/data/review_queue.json`
- `reports/aws_catalog_diff.json`
- `reports/aws_catalog_diff.md`

### Schema v1
Top-level structure:
- `version`
- `generated_at`
- `source`
- `actions`

Each action entry stores:
- `service`
- `name`
- `access_level`
- `resource_types`
- `condition_keys`
- `dependent_actions`

### Current local sync script
- `scripts/sync_aws_catalog.py`

### Current script behavior
- Fetches AWS Service Authorization Reference index and service pages
- Discovers service prefixes
- Extracts action metadata into schema v1
- Writes canonical snapshot to `app/data/aws_catalog.json`
- Builds a review queue of actions that still require human classification
- Generates diff/report outputs for both catalog changes and review-queue changes

### Current diff/report behavior
Tracks:
- new actions
- removed actions
- changed access levels
- changed resource types
- changed condition keys
- changed dependent actions
- review queue additions
- review queue removals
- review queue status movement

Also reports:
- `new_unclassified_actions`
- `services_with_new_unclassified_actions`
- `count_summary`
- `queue_diff`

### Important current boundary
This foundation is intentionally **review-based**.
It does **not** automatically assign new AWS actions into Pasu's high/medium/context risk tiers.

---

## 6. What `pasu fix` does today

`pasu fix` is intentionally conservative.

It does **not** promise a perfect final least-privilege policy.  
It generates a safer **proposed policy** and explains what still needs review.

### Local mode behavior
- Uses SAFE_ALTERNATIVES dictionary to map dangerous actions to safe alternatives
  - Example: `lambda:CreateFunction` → `["lambda:GetFunction", "lambda:ListFunctions"]` (read-only)
  - Example: `iam:PassRole` → no safe alternative, provides Condition block guidance
- Removes reviewed high-risk actions only when safe alternatives exist or when the action can be safely removed
- Preserves resource scoping and structure when safe
- Inserts manual-review notes where automation would be guessing
- Runs instantly, no API calls required

### AI mode behavior
- Claude receives the original policy JSON
- Claude analyzes the intent, Sids, action patterns, and resource structure
- Claude generates a context-aware least-privilege replacement
- Claude automatically includes appropriate Condition blocks and ARN patterns
- Claude reports its confidence level for the inferred intent
- Takes 2–3 seconds per policy

### Example: local mode

```bash
pasu fix --file policy.json
```

A typical local `pasu fix` result on this input:

```json
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:PassRole",
        "lambda:CreateFunction",
        "lambda:UpdateFunctionCode",
        "sts:AssumeRole"
      ],
      "Resource": "*"
    }
  ]
}
```

May produce output like:

```
[Proposed policy section: removed actions, changed scope, manual review notes]
...
- remove `lambda:CreateFunction` and `lambda:UpdateFunctionCode` (reviewed classifications allow removal)
- replace with `lambda:GetFunction` and `lambda:ListFunctions` (read-only alternatives)
- keep `iam:PassRole` (no safe alternative, but provide Condition guidance)
- keep `sts:AssumeRole`
- keep `Resource: "*"` when safe narrowing is not possible
- insert manual-review notes where needed
```

### AI mode example
```
pasu fix --file policy.json --ai
```

A typical `pasu fix --ai` result may:
- infer intent as "Lambda deployment pipeline with role assumption"
- report confidence as "high"
- generate context-aware policy that:
  - keeps `lambda:CreateFunction` and `lambda:UpdateFunctionCode` (needed for intent)
  - scopes to `arn:aws:lambda:*:ACCOUNT_ID:function:*` (specific to account)
  - keeps `iam:PassRole` but adds Condition: `{"iam:PassedToService": "lambda.amazonaws.com"}`
  - adds Region restriction: `{"aws:RequestedRegion": ["us-east-1", "ap-northeast-2"]}`
  - includes explanations for each decision

Pasu currently prefers:
- a safer **proposed policy**
- plus warnings and manual review guidance

over:
- an aggressive auto-fix that may silently break intended access

---

## 7. SAFE_ALTERNATIVES Dictionary

Phase 2 introduces a structured mapping of dangerous actions to safe alternatives.

### Current coverage (25+ patterns)

Privilege escalation risks:
- `iam:PassRole` → no safe alternative
- `iam:AttachUserPolicy` → no safe alternative
- `iam:AttachRolePolicy` → no safe alternative
- `iam:PutUserPolicy` → no safe alternative
- `iam:PutRolePolicy` → no safe alternative
- `iam:UpdateAssumeRolePolicy` → no safe alternative

Creation/modification risks:
- `iam:CreateUser` → `["iam:GetUser", "iam:ListUsers"]`
- `iam:CreatePolicy` → `["iam:GetPolicy", "iam:ListPolicies"]`
- `iam:CreateAccessKey` → `["iam:ListAccessKeys"]`
- `iam:CreateLoginProfile` → no safe alternative

Lambda risks:
- `lambda:CreateFunction` → `["lambda:GetFunction", "lambda:ListFunctions"]`
- `lambda:UpdateFunctionCode` → `["lambda:GetFunction"]`
- `lambda:AddPermission` → `["lambda:GetPolicy"]`
- `lambda:CreateEventSourceMapping` → `["lambda:ListEventSourceMappings"]`

EC2 risks:
- `ec2:RunInstances` → `["ec2:DescribeInstances"]`
- `ec2:AuthorizeSecurityGroupIngress` → `["ec2:DescribeSecurityGroups"]`

S3 risks:
- `s3:PutBucketPolicy` → `["s3:GetBucketPolicy"]`
- `s3:PutBucketAcl` → `["s3:GetBucketAcl"]`
- `s3:DeleteBucket` → `["s3:ListBucket"]`

STS/KMS/Org risks:
- `sts:AssumeRole` → provide Condition guidance
- `kms:Decrypt` → `["kms:DescribeKey", "kms:ListKeys"]`
- `kms:CreateGrant` → `["kms:ListGrants"]`
- `organizations:LeaveOrganization` → `["organizations:DescribeOrganization"]`

Glue risks:
- `glue:CreateDevEndpoint` → `["glue:GetDevEndpoints"]`
- `glue:UpdateDevEndpoint` → `["glue:GetDevEndpoints"]`

### Design principles
- Each dangerous action maps to (alternatives_list, guidance_text)
- Empty alternatives_list means no safe read-only alternative exists
- When no alternatives, guidance provides Condition block examples
- All alternatives are read-only operations
- Dictionary is easy to expand without code changes

---

## 8. Not Yet Built

- CLI filtering and refinement (--min-score, --risk-level)
- Interactive shell mode
- OpenAI API support for `--ai` mode
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

## 9. Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.11.9 |
| Primary Interface | CLI |
| Web Framework | FastAPI |
| AI Model | Claude Haiku (`claude-haiku-4-5-20251001`) |
| AWS SDK | boto3 |
| Validation | Pydantic |
| Testing | pytest (with mock support) |
| CI/CD | GitHub Actions |
| Package Registry | PyPI |

---

## 10. Near-Term Technical Roadmap

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
**Status:** Done

Completed:
- Defined AWS catalog source strategy
- Defined schema v1 for canonical action metadata
- Implemented local sync script
- Implemented canonical snapshot writing
- Implemented diff report generation
- Implemented review-queue generation
- Implemented review-queue diff generation
- Implemented unclassified action reporting
- Validated local `--dry-run` and `--write`
- Validated action-only precision for canonical snapshot
- GitHub Actions workflow for scheduled execution (ready)

### Phase 2 — Intelligent fix, AWS profile scanning, and Azure foundation
**Status:** In Progress

Completed:
- SAFE_ALTERNATIVES mapping (25+ dangerous actions)
- `pasu fix --ai` with Claude intent inference
- Context-aware Condition block generation
- ARN pattern scoping in AI fix
- Local fix mode with fallback guidance
- Comprehensive testing (mock + real API)
- AWS CLI profile scanning (`pasu scan --profile <profile>`)
- Policy ARN output for AWS Console navigation
- Security & Privacy documentation
- README and PRODUCT_SPEC updates

Next:
- Expand SAFE_ALTERNATIVES to 40+ patterns (more AWS services)
- Basic CLI filtering (`--min-score`, `--risk-level`)
- OpenAI API support for `--ai` mode (alongside Claude)
- Azure RBAC / Entra ID analysis foundation
- Better workflow support for team usage
- Shared reporting and notifications

### Phase 3 — GCP and broader enterprise controls
- GCP IAM support
- Cross-cloud analysis patterns
- Better organizational controls and reporting

---

## 11. Core Principles

### 1. Local-first by default
Users should get useful results without needing a hosted account or API key.

### 2. Explain before impressing
Security tools should explain what is risky, why it matters, and what users should do next.

### 3. Conservative fixes over unsafe automation
Pasu should prefer a reviewable **proposed policy** over an overconfident or destructive auto-remediation.

### 4. Human-readable output matters
Results should be understandable even for people who are not deep IAM experts.

### 5. Clear machine-readable output matters too
JSON and SARIF should remain useful for automation and CI/CD pipelines where supported by the command.

### 6. One cloud problem at a time
Depth and correctness are more important than claiming broad cloud coverage too early.

### 7. Community-first product discipline
The public CLI should solve real user problems before broader platform ambitions are expanded.

### 8. AI as optional enhancement, not replacement
AI should improve the local experience, not be required. All core functionality works without API keys.

### 9. Security and privacy by default
Local-mode operations should involve no data transmission. AWS credentials stay on the user's machine. Only explicit opt-in features (like `--ai`) transmit data outside the local environment.

---

## 12. Coding Standards

- PEP 484 type annotations on all functions
- Google-style docstrings
- Black formatting (88-char line limit)
- No hardcoded credentials
- All boto3 calls wrapped with `try/except ClientError`
- All Claude API calls wrapped with `try/except APIError`
- ERROR-level logging before re-raise
- Complete file outputs preferred over partial snippets during code generation
- Mock tests for all AI-dependent functionality

---

## 13. Maintainer Notes

This public specification is intentionally focused on:
- current product behavior
- technical direction
- output quality
- safety principles
- security and privacy model

Additional current notes:
- `app/data/aws_catalog.json` is now a real canonical snapshot, not just a placeholder layer.
- `app/data/review_queue.json` is part of the review workflow and should be treated as generated review-state data rather than a replacement for reviewed classification.
- The next meaningful backend step is GitHub Actions automation for scheduled AWS catalog refresh, diff generation, and review-queue updates.
- Risk-tier assignment for new AWS actions remains intentionally human-reviewed.
- SAFE_ALTERNATIVES is the foundation for all fix remediation and can be expanded without code changes.
- `pasu fix --ai` uses Claude Haiku for cost-efficient intent inference; API calls fallback to local mode on error.
- AWS CLI profile scanning reads local credentials and performs all analysis locally; no data is transmitted to Pasu infrastructure or external services beyond AWS IAM API calls.
- Policy ARN output enables direct AWS Console navigation for role/user management.
- Some API metadata in the codebase still carries legacy `IAM Analyzer` naming/version fields and should be aligned with Pasu branding before the next release to avoid documentation drift.
