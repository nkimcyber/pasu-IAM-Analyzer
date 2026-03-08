# Pasu — Product Specification

> **Pasu (파수/把守)** — Guardian of your Cloud IAM
> Project codename: **Moon**

---

## 1. Vision

**One-liner:** The fastest, lightest tool to scan AWS/Azure/GCP IAM permissions and explain excessive privileges in plain English.

**Positioning:** "Snyk for multi-cloud IAM" — While existing CIEM tools (Wiz, Tenable, Prisma Cloud) are enterprise-only and take weeks to deploy, Pasu lets any developer start with `pip install pasu` in under 5 minutes.

**Differentiator:**
- Existing tools: Detect risks and say "this is dangerous"
- Pasu: Explains *why* it's dangerous and *how* to fix it, using AI-powered natural language

---

## 2. Current State (v0.5.0)

**PyPI:** https://pypi.org/project/pasu/
**Install:** `pip install pasu`

### Shipped Features

**CLI (5 commands):**
- `pasu explain --file policy.json` — Plain English explanation of IAM policies
- `pasu escalate --file policy.json` — Privilege escalation risk detection
- `pasu scan --file policy.json` — Combined explain + escalate report
- `pasu fix --file policy.json` — Auto-generate least-privilege replacement policy
- All commands support: `--ai`, `--format text|json|sarif`, `-q`

**Local mode (free, no API key required):**
- 30 detection rules (19 high-risk, 6 medium-risk, 5 structural)
- Risk scoring (0-100) with visual bar
- Human-readable plain English explanations
- Auto-fix with least-privilege policy generation
- JSON and SARIF output for CI/CD integration

**AI mode (--ai flag, requires Anthropic API key):**
- Claude Haiku (claude-haiku-4-5-20251001) for detailed analysis
- Natural language explanations with escalation path visualization
- Cost-optimized: local detection first, Claude called only when needed

**Infrastructure:**
- 145+ pytest tests (all passing)
- GitHub Actions CI/CD
- PyPI published (v0.5.0)
- GitHub Actions example workflow for users

### Not Yet Built
- User authentication
- Cloud deployment (local only)
- Azure / GCP support
- Batch policy analysis
- Multi-account AWS support (STS AssumeRole)
- Structured logging

---

## 3. Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.11.9 |
| Web Framework | FastAPI |
| AI Model | claude-haiku-4-5-20251001 |
| AWS SDK | boto3 |
| Validation | Pydantic |
| Testing | pytest |
| CI/CD | GitHub Actions |
| Package Registry | PyPI |

---

## 4. Business Model — PLG (Product-Led Growth)

### Strategy
Individual developers start free → adopt within their team → company purchases license.

Reference cases: Snyk, Datadog, HashiCorp (Terraform).

### Pricing (Planned)

| Tier | Price | Target | Features |
|------|-------|--------|----------|
| Free | $0 | Individual developers | CLI local analysis, 1 AWS account, basic reports |
| Pro | $49-99/mo | Teams (2-10) | AI analysis, multi-account, Slack alerts, team dashboard |
| Enterprise | $500-2,000+/mo | Organizations | SSO, RBAC, audit logs, SLA, compliance mapping, dedicated support |

---

## 5. Roadmap

### Phase 1: AWS Only — CLI + Community (Now ~ 6 months)

**Goal:** 500+ GitHub Stars, 1,000 monthly active users

- [x] CLI tool (explain, escalate, scan)
- [x] Local-only mode (no API key required)
- [x] AI mode (--ai flag)
- [x] PyPI release (v0.1.0)
- [x] GitHub repo polish (README + screenshots + GIF demo)
- [x] Expand detection rules (S3 public access, cross-account trust, excessive resource access)
- [x] Output format options (--format json / --format table / --format sarif)
- [x] Open-source public launch
- [x] `pasu fix` — auto-generate least-privilege replacement policies
- [x] Risk scoring (0-100) with visual bar
- [x] GitHub Actions example workflow for users
- [x] CI/CD integration docs (JSON + SARIF)
- [ ] Product Hunt / Hacker News / Reddit launch
- [ ] Technical blog (AWS IAM security content)

### Phase 2: + Azure, Team Features, Monetization (6 ~ 18 months)

**Goal:** 20-50 paying customers, $1,000-5,000 MRR

- [ ] Azure RBAC / Entra ID analysis
- [ ] "Select your CSP" web UI
- [ ] User authentication (Auth0 / AWS Cognito)
- [ ] Web dashboard deployment (AWS Lambda + API Gateway)
- [ ] Team features (member invites, shared dashboard)
- [ ] Slack / Teams notifications
- [ ] Automated weekly security reports
- [ ] Pro plan launch
- [ ] AWS Activate credits application

### Phase 3: + GCP, Enterprise (18 months+)

**Goal:** $100K+ ARR, enterprise customers

- [ ] GCP IAM analysis
- [ ] Cross-cloud comparison view
- [ ] SSO (SAML/OIDC), RBAC
- [ ] SOC 2 / CIS / HIPAA compliance mapping
- [ ] Auto-remediation workflows
- [ ] AWS Marketplace listing
- [ ] Enterprise plan launch
- [ ] SLA + dedicated support

---

## 6. Hosting Plan

| Phase | Infrastructure | Monthly Cost |
|-------|---------------|-------------|
| Phase 1 | GitHub + PyPI + Vercel (landing page) | $0-20 |
| Phase 2 | AWS Lambda + API Gateway + DynamoDB | $50-150 (near $0 with Activate credits) |
| Phase 3 | ECS Fargate + RDS PostgreSQL + ElastiCache | $500-2,000+ |

---

## 7. Competitive Landscape

### Direct Competitors
- **Wiz CIEM** — Agentless, multi-cloud, 1-2 week deployment, $50K+/yr
- **Tenable Cloud Security** (fmr. Ermetic) — Multi-cloud, granular visibility
- **Prisma Cloud CIEM** — Palo Alto, full SDLC coverage
- **Sonrai Security** — Identity graph visualization, 3-6 week deployment
- **Microsoft Entra Permissions Management** — Azure-centric

### How Pasu is Different

| Existing CIEM | Pasu |
|--------------|------|
| 1-6 week deployment | pip install, 5 minutes |
| $50K-$200K+/yr | Free ~ $199/mo |
| Requires sales call | Self-service signup |
| Enterprise-only | Starts with a solo DevOps engineer |
| Does everything (CNAPP) | Does IAM permission analysis exceptionally well |

### Key Risks
- AWS may ship equivalent functionality natively (AWS Security Agent already in preview)
- Low price may signal "cheap = unreliable" in the security market
- Solo developer credibility gap for B2B security tool

---

## 8. Go-to-Market Channels (Phase 1)

- GitHub README (serves as landing page)
- Product Hunt launch
- Hacker News (Show HN)
- Reddit (r/aws, r/devops, r/netsec)
- Dev.to / Medium technical blog
- Twitter/X (AWS security content)
- AWS community meetups

---

## 9. Core Principles

1. **Deliver value without an API key** — Local analysis must be useful on its own
2. **Read-only access only** — Never request write permissions to user's cloud environment
3. **Transparent cost** — Users must be able to predict AI analysis costs
4. **Perfect one CSP before expanding** — Never build 3 CSPs simultaneously
5. **Community first** — User count and feedback before revenue

---

## 10. Coding Standards

- PEP 484 type annotations
- Google-style docstrings
- Black formatting (88 char line limit)
- No hardcoded credentials
- All boto3 calls: try/except ClientError
- All Claude API calls: try/except APIError
- ERROR-level logging before re-raise

---

*Last updated: 2026-03-08*
*Version: 0.5.0*
