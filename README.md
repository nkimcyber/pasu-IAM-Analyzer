# Pasu — AWS IAM Security Analyzer

Detect risky AWS IAM permissions in seconds.

Pasu is a local-first CLI that helps you review IAM policies without standing up cloud infrastructure, connecting an account, or buying a platform. It explains what a policy actually does, flags risky patterns such as privilege escalation, and generates a safer proposed policy with explicit manual-review guidance. Pasu ships as a PyPI package, runs locally by default, supports optional AI analysis, and includes JSON/SARIF output for automation and CI/CD workflows.

## Why use Pasu?

- **Catch privilege escalation fast** — detect risky actions and overly permissive IAM patterns before they ship. Pasu’s local mode currently includes 30 detection rules: 19 high-risk, 6 medium-risk, and 5 structural rules.
- **Explain IAM in plain English** — turn raw policy JSON into output that is easier to review and easier to share with non-IAM specialists. `pasu explain` is built for this exact use case.
- **Generate a safer proposal** — `pasu fix` produces a safer proposed policy, keeps risky unknowns visible, and tells you what still needs manual review instead of pretending to fully auto-remediate.
- **Use it locally or in CI** — Pasu supports `--format json` and `--format sarif`, and the project already includes a GitHub Actions workflow example for Code Scanning integration.

---

## 10-second Quick Start

```bash
pip install pasu
pasu scan --file policy.json
```

Requires Python 3.11+. Pasu runs locally by default and does not require an API key unless you choose `--ai`.

---

## Example

### Example policy

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

### Typical Pasu output

```text
Privilege Escalation Report

Risk Level  High
Risk Score  60+/100

Confirmed Risky Actions
  • iam:PassRole
  • ec2:RunInstances

Summary
  High privilege escalation risk detected. This policy can delegate a role and launch compute with that role.
```

Why this matters:

- `iam:PassRole` is a core privilege-delegation primitive.
- `ec2:RunInstances` can launch compute with an attached IAM role.
- Together, that combination maps to Pasu’s reviewed composite detection for **Privilege Escalation via EC2 Compute**.

---

## Commands

### Scan a policy

```bash
pasu scan --file policy.json
```

Runs both explain and escalate together. This is the fastest way to understand what a policy allows and whether it introduces risky access. `scan` is one of Pasu’s primary CLI commands.

### Explain what a policy does

```bash
pasu explain --file policy.json
```

Translates IAM policy JSON into plain English. This is useful when you need to review permissions quickly or show the result to non-technical stakeholders.

### Check for privilege escalation risks

```bash
pasu escalate --file policy.json
```

Scans for risky IAM actions and structural anti-patterns, then returns a risk level and risk score. The score is a numeric 0–100 value and the CLI shows a visual risk bar.

### Generate a safer proposed policy

```bash
pasu fix --file policy.json
```

Pasu does **not** claim to produce a perfect least-privilege policy automatically. Instead, it generates a safer proposed policy, removes obvious high-risk actions when safe, preserves important context, and surfaces manual review where automation would be misleading.

Save the result to a file:

```bash
pasu fix --file policy.json --output fixed_policy.json
```

### Get AI-powered analysis

```bash
export ANTHROPIC_API_KEY="sk-..."
pasu scan --file policy.json --ai
```

The `--ai` flag enables Claude-powered natural-language explanations and deeper remediation guidance. Pasu still performs local analysis first; AI is optional.

---

## What Pasu detects

### High-risk patterns

Pasu’s local analyzer looks for high-risk permissions and structures such as:

- wildcard actions like `"Action": "*"`
- wildcard resources like `"Resource": "*"`
- IAM privilege-escalation primitives such as `iam:PassRole`, `iam:CreatePolicyVersion`, `iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:SetDefaultPolicyVersion`, and `iam:UpdateAssumeRolePolicy`
- code-execution paths such as `lambda:CreateFunction`, `lambda:UpdateFunctionCode`, and `ec2:RunInstances`
- public-exposure paths such as `s3:PutBucketPolicy`, `s3:PutBucketAcl`, and `s3:PutObjectAcl`
- encryption and org-admin risks such as `kms:Decrypt` and `organizations:*`

### Medium-risk and context-dependent patterns

Pasu also surfaces context-dependent permissions such as:

- `sts:AssumeRole`
- `iam:CreateAccessKey`
- `secretsmanager:GetSecretValue`
- `ssm:GetParameter`
- `ec2:DescribeInstances`
- `rds:CopyDBSnapshot`

### Structural IAM issues

The local analyzer also flags policy structures that are risky even when the individual action list looks normal:

- unrestricted resource access
- `NotAction`
- `NotResource`
- sensitive permissions with no `Condition`
- wildcard service grants such as `s3:*` or `iam:*`

---

## Why Pasu instead of just AWS-native review?

Pasu is optimized for a different workflow:

- **Local-first** — useful before deployment, during code review, or while iterating on policy JSON. Pasu’s product direction explicitly prioritizes local-first usage.
- **Fast human-readable explanation** — useful when the main problem is understanding what a policy actually allows.
- **Conservative remediation** — Pasu prefers a reviewable proposed policy plus manual-review notes over overconfident auto-remediation.
- **Automation-friendly output** — JSON and SARIF are first-class outputs for pipelines and code scanning.

---

## CI / CD integration

### JSON output for scripts

```bash
# Extract the overall risk level
pasu scan --file policy.json --format json | jq '.escalate.risk_level'

# List detected risky actions
pasu scan --file policy.json --format json | jq '.escalate.detected_actions[]'

# Fail CI if the policy is High risk
RISK=$(pasu scan --file policy.json --format json | jq -r '.escalate.risk_level')
[ "$RISK" = "High" ] && exit 1 || exit 0
```

### SARIF output for GitHub Code Scanning

```bash
pasu scan --file policy.json --format sarif > results.sarif
```

Upload the SARIF file with `github/codeql-action/upload-sarif` and findings will appear in **Security → Code scanning**. The repository already includes a ready-to-use GitHub Actions workflow example.

---

## Demo

![Pasu Demo](docs/demo_pasu_combined.gif)

---

## How it works

Pasu uses a two-step model:

1. **Local detection** — rule-based scanning checks for known dangerous IAM patterns instantly and without network calls.
2. **Optional AI analysis** — with `--ai`, Pasu asks Claude for deeper explanation and remediation guidance. Local analysis still happens first.

### Packaged rule and data files

Pasu’s local analyzer loads rule and scoring data from package-managed files rather than hardcoding everything in one module. Current packaged files include:

- `app/rules/risky_actions.yaml`
- `app/rules/scoring.yaml`
- `app/rules/fix_profiles.yaml`
- `app/data/aws_catalog.json`

### AWS catalog sync foundation

Pasu also includes a local AWS catalog sync workflow that:

- uses the AWS Service Authorization Reference as the source of truth
- builds a canonical `app/data/aws_catalog.json` snapshot
- generates diff reports for review
- surfaces new unclassified actions for human review instead of auto-assigning risk tiers

---

## Current status

Pasu currently ships with:

- `pasu explain`
- `pasu escalate`
- `pasu scan`
- `pasu fix`
- local mode with no API key required
- optional AI mode with Claude
- JSON and SARIF output
- GitHub Actions CI/CD
- PyPI distribution
- packaged rule/scoring/fix data
- canonical AWS action catalog snapshot and local sync/diff tooling
- 159 pytest tests passing

---

## Roadmap

Completed:

- [x] CLI tool with local + AI analysis
- [x] PyPI package (`pip install pasu`)
- [x] more detection rules
- [x] JSON and SARIF output
- [x] `pasu fix` safer proposed policy generation
- [x] externalized rule/scoring/fix data
- [x] AWS catalog sync foundation
- [x] GitHub Actions scheduled AWS catalog sync + diff workflow

Planned:

- [ ] interactive shell mode
- [ ] Azure RBAC / Entra ID support
- [ ] GCP IAM support
- [ ] team dashboard with shared reports

For the broader product direction, see `docs/PRODUCT_SPEC.md`.

---

## Why “Pasu”?

Pasu (파수/把守) means **guard** or **sentinel** — as in guarding the gate. The name fits the project’s goal: helping you keep dangerous permissions out of your cloud IAM layer.

---

## Contributing

Contributions are welcome. Open an issue first to discuss substantial changes.

## License

MIT
