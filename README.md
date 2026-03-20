# Pasu — AWS IAM Security Analyzer

Detect risky AWS IAM permissions in seconds.

Pasu is a local-first CLI that helps you review IAM policies without standing up cloud infrastructure, connecting an account, or buying a platform. It explains what a policy actually does, flags risky patterns such as privilege escalation, and generates a safer proposed policy with explicit manual-review guidance. Pasu ships as a PyPI package, runs locally by default, supports optional AI analysis, and includes JSON/SARIF output for automation and CI/CD workflows.

## Why use Pasu?

- **Catch privilege escalation fast** — detect risky actions and overly permissive IAM patterns before they ship. Pasu's local mode currently includes 30 detection rules: 19 high-risk, 6 medium-risk, and 5 structural rules.
- **Explain IAM in plain English** — turn raw policy JSON into output that is easier to review and easier to share with non-IAM specialists. `pasu explain` is built for this exact use case.
- **Generate a safer proposal** — `pasu fix` produces a safer proposed policy, keeps risky unknowns visible, and tells you what still needs manual review instead of pretending to fully auto-remediate.
- **Use it locally or in CI** — Pasu supports `--format json` and `--format sarif`, and the project already includes a GitHub Actions workflow example for Code Scanning integration.
---

## Demo

![Pasu Demo](docs/demo_pasu_combined.gif)

---

## Quick Start

### Installation

```bash
pip install pasu
```

Requires Python 3.11+.

### Two ways to use Pasu

#### 1. Analyze IAM policies from a file

```bash
pasu scan --file policy.json
```

Use this to review policy JSON before deployment or during code review.

#### 2. Scan IAM roles and users from your AWS account

```bash
# Requires local AWS CLI credentials (~/.aws/credentials or ~/.aws/config)
# AWS user must have IAMReadOnlyAccess (or equivalent read-only permissions)

pasu scan --profile default
pasu scan --profile my-dev-account
```

Use this to audit live IAM configurations in your AWS account.

---

## How Pasu works

Pasu has two modes:

### Local mode (default — no API key required)

All analysis happens on your machine with four commands:
- `pasu explain` — translates policies into plain English
- `pasu escalate` — detects risky patterns and privilege escalation risks
- `pasu scan` — combines both for a complete report
- `pasu fix` — generates a safer proposed policy

Features:
- 30 detection rules identify dangerous patterns instantly
- Risk scoring from 0–100 with visual bar
- JSON/SARIF output for automation
- No network calls, completely private

### AI mode (`--ai` flag — optional, requires Anthropic API key)

**When to use AI mode:**

AI mode is available for `pasu fix` only and helps generate safer, context-aware policies. It's optional—the default local mode works great for most users.

**What AI mode does:**

Claude reads your policy and infers what it's trying to accomplish. Then it generates a better proposed policy that:
- Keeps only the permissions actually needed
- Automatically adds Condition blocks to restrict access
- Scopes wildcard resources to specific ARNs
- Explains each change made

**AI model support:**
- **Anthropic Claude:** Currently supported
- **OpenAI API:** Planned for future release

**How to enable AI mode:**

1. Get an Anthropic API key from https://console.anthropic.com
2. Set it as an environment variable:

```bash
# Linux / Mac
export ANTHROPIC_API_KEY="sk-..."

# Windows (PowerShell)
$env:ANTHROPIC_API_KEY = "sk-..."
```

3. Use `pasu fix --ai`:

```bash
pasu fix --file policy.json --ai
```

Claude infers the policy's intent and generates a context-aware least-privilege policy with automatic Condition blocks and ARN scoping. Takes 2-3 seconds per call.

---

## Example

### Input policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:PassRole",
        "ec2:RunInstances"
      ],
      "Resource": "*"
    }
  ]
}
```

### Output

```text
Risk Level  Medium

Risk Score  31/100 (Medium)

Summary
  Medium privilege escalation risk: 2 reviewed high-risk action(s) detected, 
  1 composite attack pattern(s) matched, 4 rule finding(s) total. 
  Run with --ai for detailed analysis.

Confirmed Risky Actions
  Reviewed classification — confirmed dangerous by security research:
  • iam:passrole
  • ec2:runinstances
```

**Why this matters:**
- `iam:PassRole` lets a principal delegate an IAM role.
- `ec2:RunInstances` launches compute with an attached role.
- Together, this is **Privilege Escalation via EC2**.

---

## Commands

### Scan a policy file

```bash
pasu scan --file policy.json
```

Runs both explain and escalate together. Fastest way to understand what a policy allows and whether it introduces risky access.

### Scan AWS account (requires AWS CLI)

```bash
pasu scan --profile <profile_name>
```

Scans all IAM roles and users in your AWS account. Output includes Policy ARN for direct AWS Console navigation. Requires the AWS user to have `IAMReadOnlyAccess` (or equivalent read-only IAM permissions).

### Explain what a policy does

```bash
pasu explain --file policy.json
```

Translates IAM policy JSON into plain English. Useful when you need to review permissions quickly or share results with non-technical stakeholders.

### Check for privilege escalation risks

```bash
pasu escalate --file policy.json
```

Scans for risky IAM actions and structural anti-patterns. Returns a risk level and risk score (0–100 with visual bar).

### Generate a safer proposed policy

```bash
pasu fix --file policy.json
```

Generates a safer proposed policy by:
- Replacing dangerous actions with safe read-only alternatives where possible
- Providing Condition block guidance for actions with no safe alternative
- Surfacing what still needs manual review

Works offline, no API key required.

```bash
pasu fix --file policy.json --ai
```

With `--ai`, Claude infers the policy's intent and generates a context-aware least-privilege policy with automatic Condition blocks and ARN scoping.

Save the result to a file:

```bash
pasu fix --file policy.json --output fixed_policy.json
```

---

## What Pasu detects

### High-risk patterns

- Wildcard actions: `"Action": "*"`
- Wildcard resources: `"Resource": "*"`
- IAM privilege-escalation primitives: `iam:PassRole`, `iam:CreatePolicyVersion`, `iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:SetDefaultPolicyVersion`, `iam:UpdateAssumeRolePolicy`
- Code-execution paths: `lambda:CreateFunction`, `lambda:UpdateFunctionCode`, `ec2:RunInstances`
- Public-exposure paths: `s3:PutBucketPolicy`, `s3:PutBucketAcl`, `s3:PutObjectAcl`
- Encryption and org-admin risks: `kms:Decrypt`, `organizations:*`

### Medium-risk and context-dependent patterns

- `sts:AssumeRole`
- `iam:CreateAccessKey`
- `secretsmanager:GetSecretValue`
- `ssm:GetParameter`
- `ec2:DescribeInstances`
- `rds:CopyDBSnapshot`

### Structural issues

- Unrestricted resource access
- `NotAction` / `NotResource` usage
- Sensitive permissions with no `Condition`
- Wildcard service grants: `s3:*`, `iam:*`

---

## Output formats

Pasu supports multiple output formats for different workflows:

```bash
# Human-readable (default)
pasu scan --file policy.json

# JSON (for scripts and automation)
pasu scan --file policy.json --format json

# SARIF (for GitHub Code Scanning)
pasu scan --file policy.json --format sarif
```

### JSON output for CI/CD scripts

```bash
# Extract risk level
pasu scan --file policy.json --format json | jq '.escalate.risk_level'

# List detected risky actions
pasu scan --file policy.json --format json | jq '.escalate.detected_actions[]'

# Fail CI if policy is High risk
RISK=$(pasu scan --file policy.json --format json | jq -r '.escalate.risk_level')
[ "$RISK" = "High" ] && exit 1 || exit 0
```

### SARIF output for GitHub Code Scanning

```bash
pasu scan --file policy.json --format sarif > results.sarif
```

Upload with `github/codeql-action/upload-sarif` and findings appear in **Security → Code scanning**. Repository includes a ready-to-use GitHub Actions workflow example.

---

## Security & Privacy

### Local mode — no security concerns

Pasu runs entirely on your local machine:

- **File analysis:** Policy JSON is analyzed locally only
- **AWS CLI profile scanning:** Reads credentials from your local AWS CLI configuration (`~/.aws/credentials` or `~/.aws/config`)
- **No data transmission:** All analysis happens on your machine; no data leaves unless you explicitly enable `--ai`
- **Read-only operations:** Pasu uses boto3 to read IAM metadata only; it never creates, modifies, or deletes resources

**Requirements:**

The AWS user running `pasu scan --profile <profile>` must have read-only IAM permissions:
- Recommended: `IAMReadOnlyAccess` managed policy
- Minimum: permissions to call `iam:List*` and `iam:Get*` operations
- Pasu does not require write permissions

### AI mode — data transmission only with explicit opt-in

`--ai` mode is the only time Pasu sends data outside your machine:

- Policy JSON text is sent to Anthropic's Claude API for analysis
- This only happens when you explicitly add the `--ai` flag
- Default mode (without `--ai`) performs all analysis locally with zero data transmission

---

## Why "Pasu"?

Pasu (파수/把守) means **guard** or **sentinel** — as in guarding the gate. The name fits the project's goal: helping you keep dangerous permissions out of your cloud IAM layer.

---

## Why Pasu instead of just AWS-native review?

Pasu is optimized for a different workflow:

- **Local-first** — useful before deployment, during code review, or while iterating on policy JSON. Pasu's product direction explicitly prioritizes local-first usage.
- **Fast human-readable explanation** — useful when the main problem is understanding what a policy actually allows.
- **Conservative remediation** — Pasu prefers a reviewable proposed policy plus manual-review notes over overconfident auto-remediation.
- **Automation-friendly output** — JSON and SARIF are first-class outputs for pipelines and code scanning.

---

## Current status

Pasu ships with:

- `pasu explain`, `pasu escalate`, `pasu scan`, `pasu fix` commands
- 30 local detection rules (19 high-risk, 6 medium-risk, 5 structural)
- File analysis and AWS CLI profile scanning
- Policy ARN output for AWS Console navigation
- Local and AI-powered fix modes
- JSON and SARIF output formats
- 160+ passing tests
- GitHub Actions CI/CD integration
- PyPI distribution

---

## Roadmap

Completed:

- [x] CLI tool with local + AI analysis
- [x] PyPI package (`pip install pasu`)
- [x] 30+ detection rules
- [x] JSON and SARIF output
- [x] Safer proposed policy generation (`pasu fix`)
- [x] Context-aware least-privilege with `pasu fix --ai`
- [x] AWS CLI profile scanning
- [x] Policy ARN output

Planned:

- [ ] CLI filtering (`--min-score`, `--risk-level`)
- [ ] Interactive shell mode
- [ ] OpenAI API support for `--ai` mode
- [ ] Azure RBAC / Entra ID support
- [ ] GCP IAM support
- [ ] Team dashboard with shared reports

For the broader product direction, see `docs/PRODUCT_SPEC.md`.

---

## Contributing

Contributions are welcome. Open an issue first to discuss substantial changes.

## License

MIT
