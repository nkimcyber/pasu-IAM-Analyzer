# Pasu

**The fastest way to find dangerous permissions in your AWS IAM policies.**

Pasu is a lightweight CLI tool that scans IAM policy JSON for security risks and explains them in plain English. No account setup, no cloud agent, no sales call — just `pip install pasu` and go.

```
$ pasu scan --file policy.json

+===============================+
|  Privilege Escalation Report  |
+===============================+

Risk Level: High

Detected Risky Actions:
  - iam:PassRole
  - iam:CreatePolicyVersion
  - iam:AttachRolePolicy

Summary:
  High privilege escalation risk: 3 dangerous action(s) detected.
  Run with --ai for detailed analysis.
```
### Mixed policy analysis
![Pasu Demo - S3 Policy](docs/demo2.gif)

### Dangerous policy detection
![Pasu Demo - Dangerous Policy](docs/demo1.gif)

### Auto-fix dangerous policies
![Pasu Demo - Fix Policy](docs/demo3.gif)
---

## Install

```bash
pip install pasu
```

Requires Python 3.11+

## Usage

### Scan a policy (local analysis, no API key needed)

```bash
pasu scan --file policy.json
```

### Explain what a policy does

```bash
pasu explain --file policy.json
```

### Check for privilege escalation risks

```bash
pasu escalate --file policy.json
```

### Get AI-powered detailed analysis

```bash
export ANTHROPIC_API_KEY="sk-..."
pasu scan --file policy.json --ai
```

The `--ai` flag enables Claude-powered natural language explanations with specific remediation guidance. Without it, Pasu runs entirely locally at zero cost.

---

## What Pasu Detects

**High Risk (19 rules):**
- Wildcard actions (`"Action": "*"`) and wildcard resources (`"Resource": "*"`)
- IAM privilege escalation: iam:PassRole, iam:CreatePolicyVersion, iam:AttachRolePolicy, iam:AttachGroupPolicy, iam:PutRolePolicy, iam:CreateRole, iam:PutGroupPolicy, iam:AddUserToGroup, iam:AttachUserPolicy, iam:PutUserPolicy, iam:CreateLoginProfile, iam:UpdateLoginProfile, iam:SetDefaultPolicyVersion, iam:UpdateAssumeRolePolicy
- S3 public exposure: s3:PutBucketPolicy, s3:PutBucketAcl, s3:PutObjectAcl
- Code execution: lambda:CreateFunction, lambda:UpdateFunctionCode
- Infrastructure control: ec2:RunInstances
- Organization admin: organizations:*
- Encryption keys: kms:Decrypt

**Medium Risk (6 rules):**
- sts:AssumeRole, iam:CreateAccessKey
- Data access: s3:GetObject (with Resource:*), dynamodb:Scan (with Resource:*)
- Secrets access: secretsmanager:GetSecretValue, ssm:GetParameter
- Reconnaissance: ec2:DescribeInstances
- Data exfiltration: rds:CopyDBSnapshot

**Structural Rules (5 rules):**
- Unrestricted resource access (`"Resource": "*"` on any action)
- Inverse action grants (`NotAction` — allows everything EXCEPT listed actions)
- Inverse resource grants (`NotResource`)
- Sensitive actions with no `Condition` block
- Wildcard service grants (`"s3:*"`, `"iam:*"`, etc.)

**With `--ai` flag:**
- Detailed escalation path analysis (e.g., User → PassRole → EC2 → Admin Role)
- Plain English explanation of each finding
- Specific remediation suggestions

---

## How It Works

Pasu uses a two-step analysis approach:

1. **Local detection (free, instant):** Rule-based scanning checks for known dangerous IAM action patterns and overly permissive policies. No network calls, no API keys.

2. **AI analysis (optional, `--ai`):** When risky actions are found, Claude AI provides detailed natural language explanations of *why* each permission is dangerous and *how* to fix it. Claude is only called when the local scan finds something — no unnecessary API costs.

---

## Roadmap

- [x] CLI tool with local + AI analysis
- [x] PyPI package (`pip install pasu`)
- [x] More detection rules (S3 public access, cross-account trust)
- [x] Output formats (--format json / table / sarif)
- [x] `pasu fix` — auto-generate least-privilege replacement policies
- [ ] Azure RBAC / Entra ID support
- [ ] GCP IAM support
- [ ] Team dashboard with shared reports

See [docs/PRODUCT_SPEC.md](docs/PRODUCT_SPEC.md) for the full roadmap.

---

## Why "Pasu"?

Pasu (파수/把守) is Korean for "guard" or "sentinel" — as in 파수꾼 (guard/watchman). Pasu guards the gates of your cloud infrastructure by making sure only the right permissions exist.

---

## CI/CD Integration

### JSON output for scripting

Use `--format json` to pipe results into other tools:

```bash
# Extract just the risk level
pasu scan --file policy.json --format json | jq '.escalate.risk_level'

# List all detected risky actions
pasu scan --file policy.json --format json | jq '.escalate.detected_actions[]'

# Fail CI if risk level is High
RISK=$(pasu scan --file policy.json --format json | jq -r '.escalate.risk_level')
[ "$RISK" = "High" ] && exit 1 || exit 0
```

### SARIF output for GitHub Code Scanning

Use `--format sarif` to generate a [SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) report that GitHub understands natively:

```bash
pasu scan --file policy.json --format sarif > results.sarif
```

Upload the `.sarif` file with the `github/codeql-action/upload-sarif` action and findings will appear in the **Security → Code scanning** tab of your repository, with severity levels mapped automatically (`High` → error, `Medium` → warning).

See [examples/github-actions-workflow.yml](examples/github-actions-workflow.yml) for a ready-to-use GitHub Actions workflow.

---

## Contributing

Contributions are welcome. Please open an issue first to discuss what you'd like to change.

## License

MIT
