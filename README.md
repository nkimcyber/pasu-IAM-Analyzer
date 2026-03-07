# Pasu (파수)

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

**High Risk:**
- Wildcard actions (`"Action": "*"`)
- Wildcard resources (`"Resource": "*"`)
- iam:PassRole, iam:CreatePolicyVersion, iam:AttachRolePolicy, iam:AttachGroupPolicy, iam:PutRolePolicy, iam:CreateRole, iam:PutGroupPolicy, iam:AddUserToGroup, iam:AttachUserPolicy, iam:PutUserPolicy, iam:CreateLoginProfile, iam:UpdateLoginProfile

**Medium Risk:**
- sts:AssumeRole
- iam:CreateAccessKey

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

## Web UI

Pasu also includes a local web interface:

```bash
pip install pasu
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000 — paste any IAM policy JSON to get instant analysis.

---

## API

```bash
# Explain a policy
curl -X POST http://127.0.0.1:8000/api/v1/explain \
  -H "Content-Type: application/json" \
  -d '{"policy_json": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"}'

# Check privilege escalation
curl -X POST http://127.0.0.1:8000/api/v1/escalate \
  -H "Content-Type: application/json" \
  -d '{"policy_json": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"}'
```

---

## Roadmap

- [x] CLI tool with local + AI analysis
- [x] PyPI package (`pip install pasu`)
- [ ] More detection rules (S3 public access, cross-account trust)
- [ ] Output formats (--format json / table / sarif)
- [ ] Azure RBAC / Entra ID support
- [ ] GCP IAM support
- [ ] Team dashboard with shared reports

See [docs/PRODUCT_SPEC.md](docs/PRODUCT_SPEC.md) for the full roadmap.

---

## Why "Pasu"?

Pasu (파수/把守) is Korean for "guard" or "sentinel" — as in 파수꾼 (guard/watchman). Pasu guards the gates of your cloud infrastructure by making sure only the right permissions exist.

---

## Contributing

Contributions are welcome. Please open an issue first to discuss what you'd like to change.

## License

MIT
