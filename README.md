# Pasu — AWS IAM Security Analyzer

**Scan your live AWS account for dangerous IAM permissions in 30 seconds.**

```bash
pip install pasu
pasu scan --profile default
```

No dashboards. No agents. No cloud connection. Just your local AWS credentials and a terminal.

---

![Pasu Demo](docs/demo_pasu_combined.gif)

---

## What you get in 30 seconds

```
Scanned 12 resources — Critical: 0, High: 3, Medium: 5, Low: 1

============================================================
  Policy ARN: arn:aws:iam::123456789012:role/DeployRole
============================================================

Risk Level  High
Risk Score  ████████████░░░░░░░░  78/100 (High)

Confirmed Risky Actions
  • iam:PassRole
  • iam:CreatePolicyVersion
  • lambda:CreateFunction

High-Risk Permission Patterns
  COMP-002  Privilege Escalation via Serverless Function
  Risk:         CRITICAL
  Permissions:  iam:PassRole, lambda:CreateFunction
  Why:          A principal that can delegate an IAM role and create a Lambda
                function can invoke arbitrary code under that role's permissions.
```

Pasu shows you exactly what's dangerous, why it's dangerous, and where it lives in your account — with direct AWS Console links via Policy ARN.

---

## Scan modes

### Scan your live AWS account

```bash
# Full account scan — all IAM roles and users
pasu scan --profile default

# Target a specific role
pasu scan --profile default --role DeployRole

# Target a specific user
pasu scan --profile default --user ci-bot

# Show all findings including Medium and Low
pasu scan --profile default --all

# Cross-account scanning via assume role
pasu scan --profile default --assume-role arn:aws:iam::999999999999:role/PasuAudit
```

Pasu reads your local AWS CLI credentials (`~/.aws/credentials` or `~/.aws/config`) and makes read-only `iam:List*` / `iam:Get*` calls. Nothing leaves your machine. No data is sent anywhere.

**Requirements:** AWS user must have `IAMReadOnlyAccess` (or `iam:List*` + `iam:Get*` minimum).

### Scan a policy file

```bash
pasu scan --file policy.json
```

Useful for reviewing policies before deployment or during code review — no AWS credentials needed.

---

## All commands

### `pasu scan` — full report

```bash
pasu scan --profile default          # live AWS account
pasu scan --file policy.json         # local file
```

Runs explain + escalation detection together. Shows risk level, risk score, confirmed risky actions, and high-risk permission patterns.

**New in 0.7.0:**
- Summary line always appears first: `Scanned N resources — Critical: X, High: Y, Medium: Z, Low: W`
- By default, detail output is shown only for Critical and High findings
- `--all` flag shows full detail for every severity
- `--role NAME` and `--user NAME` target a single resource
- Policy ARN included in output for direct AWS Console navigation

### `pasu explain` — plain English

```bash
pasu explain --file policy.json
```

Translates IAM policy JSON into plain English. Useful when reviewing permissions quickly or sharing results with non-technical stakeholders.

### `pasu escalate` — privilege escalation check

```bash
pasu escalate --file policy.json
```

Detects risky IAM actions and structural anti-patterns. Returns a risk level and 0–100 risk score with a visual bar.

### `pasu fix` — safer proposed policy

```bash
pasu fix --file policy.json           # local analysis
pasu fix --file policy.json --ai      # Claude-powered least-privilege rewrite
pasu fix --file policy.json --output fixed_policy.json
```

Generates a safer proposed policy. Local mode replaces dangerous actions with safer alternatives and surfaces what still needs manual review. AI mode (`--ai`) uses Claude to infer the policy's intent and generate a context-aware least-privilege policy with automatic Condition blocks and ARN scoping.

**AI mode requires an Anthropic API key:**

```bash
# Linux / Mac
export ANTHROPIC_API_KEY="sk-..."

# Windows (PowerShell)
$env:ANTHROPIC_API_KEY = "sk-..."
```

---

## What Pasu detects

30 local detection rules — no API key required.

**High-risk (19 rules)**
- Wildcard actions and resources (`*`)
- IAM privilege-escalation primitives: `iam:PassRole`, `iam:CreatePolicyVersion`, `iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:SetDefaultPolicyVersion`, `iam:UpdateAssumeRolePolicy`
- Code-execution paths: `lambda:CreateFunction`, `lambda:UpdateFunctionCode`, `ec2:RunInstances`
- Public-exposure paths: `s3:PutBucketPolicy`, `s3:PutBucketAcl`, `s3:PutObjectAcl`
- Encryption and org-admin risks: `kms:Decrypt`, `organizations:*`

**Medium-risk / context-dependent (6 rules)**
- `sts:AssumeRole`, `iam:CreateAccessKey`, `secretsmanager:GetSecretValue`, `ssm:GetParameter`, `ec2:DescribeInstances`, `rds:CopyDBSnapshot`

**Structural issues (5 rules)**
- Unrestricted resource access
- `NotAction` / `NotResource` usage
- Sensitive permissions with no `Condition`
- Wildcard service grants: `s3:*`, `iam:*`

---

## Output formats

```bash
pasu scan --profile default                      # human-readable (default)
pasu scan --profile default --format json        # JSON
pasu scan --file policy.json --format sarif      # SARIF for GitHub Code Scanning
```

### JSON for CI/CD

```bash
# Extract risk level
pasu scan --file policy.json --format json | jq '.escalate.risk_level'

# Fail CI if policy is High risk
RISK=$(pasu scan --file policy.json --format json | jq -r '.escalate.risk_level')
[ "$RISK" = "High" ] && exit 1 || exit 0
```

### SARIF for GitHub Code Scanning

```bash
pasu scan --file policy.json --format sarif > results.sarif
```

Upload with `github/codeql-action/upload-sarif`. Findings appear in **Security → Code scanning**.

---

## Security & privacy

**Local mode (default):** Everything runs on your machine. Policy analysis, AWS credential reads, IAM metadata collection — none of it leaves your machine unless you explicitly use `--ai`.

**AWS profile scanning:** Pasu reads your local AWS CLI config and makes read-only boto3 calls (`iam:List*`, `iam:Get*`). It never creates, modifies, or deletes any AWS resource. Your credentials are never transmitted anywhere.

**AI mode (`--ai`):** The only time data leaves your machine. Policy JSON is sent to Anthropic's Claude API. This only happens when you explicitly add the `--ai` flag.

---

## Why "Pasu"?

Pasu (파수/把守) is Korean for **guard** or **sentinel** — as in guarding the gate. The name fits: Pasu helps you keep dangerous permissions out of your IAM layer before they become incidents.

---

## Current status

- `pasu explain`, `pasu escalate`, `pasu scan`, `pasu fix`
- 30 local detection rules (19 high-risk, 6 medium-risk, 5 structural)
- AWS CLI profile scanning with Policy ARN output
- Targeted scanning (`--role`, `--user`)
- Severity-filtered output with `--all` override
- Local and AI-powered fix modes
- JSON and SARIF output
- 1,200+ passing tests
- GitHub Actions CI/CD integration
- PyPI distribution (`pip install pasu`)

---

## Roadmap

**Completed**
- [x] CLI tool with local + AI analysis
- [x] PyPI package
- [x] 30+ detection rules
- [x] JSON and SARIF output
- [x] `pasu fix` with local and AI modes
- [x] AWS CLI profile scanning
- [x] Policy ARN output
- [x] Targeted scanning (`--role`, `--user`)
- [x] Severity-filtered output + `--all` flag

**Planned**
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
