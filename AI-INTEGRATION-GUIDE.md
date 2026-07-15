# AI Integration Guide — Azure Policy Assessment Tool

**Version**: Draft — March 2026  
**Applies to**: Get-PolicyAssignments.ps1 v3.1.1+

---

## Table of Contents

1. [What AI Adds (and What It Doesn't Replace)](#1-what-ai-adds-and-what-it-doesnt-replace)
2. [Side-by-Side Output Comparison](#2-side-by-side-output-comparison)
3. [Why Use AI?](#3-why-use-ai)
4. [Prerequisites](#4-prerequisites)
5. [Architecture Overview](#5-architecture-overview)
6. [AI Output Examples](#6-ai-output-examples)

---

## 1. What AI Adds (and What It Doesn't Replace)

### What stays deterministic (unchanged)

Every number, count, compliance state, and risk score continues to come from **Azure Resource Graph** and **rule-based scoring logic** inside the script. AI never invents metrics.

| Component | Source | Changes with AI? |
|---|---|---|
| Assignment counts | ARG query | ❌ No |
| Non-compliant resource counts | ARG compliance state | ❌ No |
| Effect type classification | Policy definition metadata | ❌ No |
| Security/Cost/Risk scoring | Point-based algorithm (`Get-PolicyRecommendation`) | ❌ No |
| CE+ test results (TC1–TC5) | Initiative compliance query | ❌ No |
| YAML delta metrics | Snapshot comparison logic | ❌ No |
| ALZ gap analysis | GitHub ALZ Library comparison | ❌ No |

### What AI adds on top

| Capability | Without AI | With AI |
|---|---|---|
| **Executive narrative** | Raw numbers only — reader interprets | Plain-English paragraph explaining posture, risks, and urgency |
| **Prioritized action plan** | Static template text per effect type | Cross-signal ranked actions (P1/P2/P3) considering all findings together |
| **Trend explanation** | Delta shows "+182 NC" | AI explains "NC increase driven by 2 subscriptions adding untagged storage accounts" |
| **Remediation steps** | "Enable enforcement" (generic) | "Switch `Deploy-MDFC-Config` to Default enforcement at mg-platform scope; verify managed identity has Contributor on target subscriptions" |
| **Control mapping** | CE+ test status only | Maps findings to audit-ready language: "CE control 5.2.1 partially met — 3 resources lack encryption at rest" |
| **Risk correlation** | Independent per-policy scores | "14 audit-only high-security policies + 9 new Key Vault assignments = compounding exposure in network tier" |

---

## 2. Side-by-Side Output Comparison

### A. Executive Summary

**Current output (no AI):**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  EXECUTIVE SUMMARY                                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  Assignments  : 412  (290 Policy | 95 Initiative | 27 Regulatory)          │
│  Non-Compliant: 1284 resources across 73 assignments                       │
│  Enforcement  : 331 enforced | 81 audit-only                              │
│  Scope        : MG: 187 | Sub: 198 | RG: 27                               │
│  Exemptions   : 42 active across 18 assignments                           │
└─────────────────────────────────────────────────────────────────────────────┘

  Top Non-Compliant Assignments:
    1. 426 NC | Configure Azure Defender for servers
    2. 218 NC | Deploy diagnostic settings for Storage Accounts
    3. 187 NC | Require encryption on Data Lake Store accounts
    ...

  High-Security Policies NOT Enforced (14):
    • Microsoft Cloud Security Benchmark (MCSB)
    • Deploy Azure Security Center monitoring
    • Configure Azure Defender for Key Vault
    ...
```

**Same data with AI layer:**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  EXECUTIVE SUMMARY                                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  Assignments  : 412  (290 Policy | 95 Initiative | 27 Regulatory)          │
│  Non-Compliant: 1284 resources across 73 assignments                       │
│  Enforcement  : 331 enforced | 81 audit-only                              │
│  Scope        : MG: 187 | Sub: 198 | RG: 27                               │
│  Exemptions   : 42 active across 18 assignments                           │
└─────────────────────────────────────────────────────────────────────────────┘

  Top Non-Compliant Assignments:
    1. 426 NC | Configure Azure Defender for servers
    2. 218 NC | Deploy diagnostic settings for Storage Accounts
    ...

═══════════════════════════════════════════════════════════════════════════════
  🤖 AI EXECUTIVE INSIGHTS
═══════════════════════════════════════════════════════════════════════════════
  Posture   : 🟠 Needs Improvement
  Confidence: High (all claims validated against computed metrics)

  📋 SITUATION SUMMARY
  Your tenant has 412 policy assignments protecting 5 management groups and
  198 subscriptions. While 80% of assignments are enforced, 14 high-security
  policies remain in audit-only mode — including Microsoft Cloud Security
  Benchmark and 3 Defender for Cloud configurations. This creates a gap where
  non-compliant resources are detected but not blocked or remediated.

  The 1,284 non-compliant resources are concentrated in 2 areas:
  • Server protection (426 NC) — Defender for Servers not fully deployed
  • Storage encryption (218 NC) — diagnostic settings missing on new accounts

  🎯 PRIORITIZED ACTIONS (next 7–14 days)

  P1 — ENFORCE CRITICAL POLICIES (est. 2–4 hours)
  Switch these 5 assignments from DoNotEnforce → Default:
    1. Microsoft Cloud Security Benchmark @ Tenant Root
    2. Configure Azure Defender for Key Vault @ mg-platform
    3. Deploy MDFC for SQL Servers @ mg-landingzones
    4. Require secure transfer for Storage @ Tenant Root
    5. Deploy network watcher for all regions @ mg-connectivity
  → Expected impact: blocks ~60% of new non-compliant deployments

  P1 — REMEDIATE TOP NC RESOURCES (est. 4–8 hours)
  Create remediation tasks for the top 3 DINE assignments:
    • "Configure Azure Defender for servers" — 426 resources
    • "Deploy diagnostic settings for Storage Accounts" — 218 resources
    • "Require encryption on Data Lake Store" — 187 resources
  → Expected NC reduction: ~65% (831 of 1,284 resources)

  P2 — REVIEW EXPIRING EXEMPTIONS (est. 1 hour)
  11 of 42 active exemptions expire within 30 days. Decide per exemption:
    • Renew with documented justification, OR
    • Let expire and remediate the underlying non-compliance

  P3 — CLOSE ALZ GAPS (est. 1–2 days)
  7 recommended Azure Landing Zone policies are missing. Prioritize:
    • Deny-PublicIP (Network Security category)
    • Deploy-DDoS-Protection (Network Security)
    • Audit-UnusedResources (Cost Optimization)

  📊 EVIDENCE BASIS
  Assignments: 412 | NC Resources: 1,284 | High-Risk: 37
  Audit-only high-security: 14 | ALZ gaps: 7 | Expiring exemptions: 11
  All metrics sourced from Azure Resource Graph — no AI-generated numbers.
═══════════════════════════════════════════════════════════════════════════════
```

### B. Quick Assessment

**Current output:**

```
═══════════════════════════════════════════════════════════════
  ⚡ QUICK ASSESSMENT
═══════════════════════════════════════════════════════════════
  Posture: 🟠 Needs Improvement
  Enforcement Rate: 80%
  Non-Compliant Resources: 1284 across 73 assignments

  ⚠️  Top Enforcement Gaps (high-security, not enforced):
    • Microsoft Cloud Security Benchmark [Parameterised]
    • Configure Azure Defender for Key Vault [DeployIfNotExists]
    • Deploy MDFC for SQL Servers [DeployIfNotExists]
    • Require secure transfer for Storage [Deny]
    • Deploy network watcher for all regions [DeployIfNotExists]

  🔴 Top Non-Compliant Assignments:
    426 NC | Configure Azure Defender for servers
    218 NC | Deploy diagnostic settings for Storage Accounts
    187 NC | Require encryption on Data Lake Store accounts
    112 NC | Audit VMs without disaster recovery configured
     89 NC | Deploy Azure Monitor agent for Linux VMs

  💡 Key Actions:
    1. Enable enforcement on 14 high-security audit-only policies
    2. Remediate 1284 non-compliant resources (start with top 5)
    3. Add Deny policies to 3 scope(s) without preventive controls
    4. Review 2 disabled policies — remove or re-enable
═══════════════════════════════════════════════════════════════
```

**With AI — same data, enriched narrative:**

```
═══════════════════════════════════════════════════════════════
  ⚡ QUICK ASSESSMENT
═══════════════════════════════════════════════════════════════
  Posture: 🟠 Needs Improvement
  Enforcement Rate: 80%
  Non-Compliant Resources: 1284 across 73 assignments

  ⚠️  Top Enforcement Gaps (high-security, not enforced):
    • Microsoft Cloud Security Benchmark [Parameterised]
    • Configure Azure Defender for Key Vault [DeployIfNotExists]
    ...

  🔴 Top Non-Compliant Assignments:
    426 NC | Configure Azure Defender for servers
    218 NC | Deploy diagnostic settings for Storage Accounts
    ...

  💡 Key Actions:
    1. Enable enforcement on 14 high-security audit-only policies
    2. Remediate 1284 non-compliant resources (start with top 5)
    3. Add Deny policies to 3 scope(s) without preventive controls
    4. Review 2 disabled policies — remove or re-enable

  🤖 AI INSIGHT:
  The biggest risk multiplier is the combination of 14 unenforced
  high-security policies AND 426 unprotected servers. Defender for
  Servers alone accounts for 33% of all non-compliance. Enforcing
  it at mg-landingzones scope and running a remediation task would
  reduce total NC count by roughly one-third within 24 hours.
═══════════════════════════════════════════════════════════════
```

### C. YAML Delta Comparison

**Current delta output:**

```
═══════════════════════════════════════════════════════════════════════════════
  📊 YAML DELTA ASSESSMENT
═══════════════════════════════════════════════════════════════════════════════
  Previous: 2026-02-18 16:01 (v3.1.0)
  Current:  2026-03-04 14:30 (v3.1.1)
───────────────────────────────────────────────────────────────────────────────
  Assignments  : 412 (+9)
  Non-Compliant: 1284 (+182)
  High Risk    : 37 (+4)
  Enforced     : 331 (+6)

  ➕ NEW ASSIGNMENTS (9):
    + Deploy-MDFC-KeyVault [DeployIfNotExists | mg-platform]
    + Audit-StorageEncryption [Audit | mg-landingzones]
    ...

  ➖ REMOVED ASSIGNMENTS (0)

  🔄 CHANGED ASSIGNMENTS (3):
    ~ Deploy-ASC-Monitoring @ Tenant Root Group
      → Enforcement Mode: DoNotEnforce → Default
    ...

  📈 EFFECT TYPE CHANGES:
    DeployIfNotExists: 84 → 91 (+7)
    Deny: 45 → 45 (0)
    ...

  POSTURE TREND: 📉 DEGRADING
═══════════════════════════════════════════════════════════════════════════════
```

**Same delta with AI narrative:**

```
═══════════════════════════════════════════════════════════════════════════════
  📊 YAML DELTA ASSESSMENT
═══════════════════════════════════════════════════════════════════════════════
  Previous: 2026-02-18 16:01 (v3.1.0)
  Current:  2026-03-04 14:30 (v3.1.1)
───────────────────────────────────────────────────────────────────────────────
  Assignments  : 412 (+9)
  Non-Compliant: 1284 (+182)
  High Risk    : 37 (+4)
  Enforced     : 331 (+6)

  ➕ NEW ASSIGNMENTS (9):
    + Deploy-MDFC-KeyVault [DeployIfNotExists | mg-platform]
    ...

  POSTURE TREND: 📉 DEGRADING

  🤖 AI DELTA INTERPRETATION:
  Despite adding 9 new assignments (positive), non-compliance grew by
  +182 resources — making the overall trend DEGRADING. Root cause analysis:

  1. The 9 new assignments include 7 DINE policies that discovered
     pre-existing non-compliant resources (not new violations).
     These policies are working correctly — the NC spike is a detection
     artifact, not a security regression.

  2. The remaining +12 NC growth comes from 2 subscriptions
     (Sub-Analytics-Prod, Sub-Data-Dev) where new storage accounts
     were deployed without diagnostic settings before the new policies
     were assigned.

  3. The 3 changed assignments (DoNotEnforce → Default) are positive —
     enforcement is increasing. The trend should reverse within 1–2
     assessment cycles once remediation tasks complete.

  Recommended: Create remediation tasks for the 7 new DINE policies.
  Expected outcome: NC count should drop to ~1,100 within 48 hours,
  reversing the DEGRADING trend to STABLE or IMPROVING.
═══════════════════════════════════════════════════════════════════════════════
```

### D. Per-Policy Recommendation

**Current recommendation (deterministic):**

```
Policy: Configure Azure Defender for Key Vault
Effect: DeployIfNotExists | Enforcement: DoNotEnforce | Security: High | Cost: High

Recommendation: "CRITICAL: High-security policy in audit-only mode.
                 Enable enforcement to block non-compliant deployments."
```

**AI-enhanced recommendation:**

```
Policy: Configure Azure Defender for Key Vault
Effect: DeployIfNotExists | Enforcement: DoNotEnforce | Security: High | Cost: High

Recommendation: "CRITICAL: High-security policy in audit-only mode.
                 Enable enforcement to block non-compliant deployments."

🤖 AI Remediation Plan:
  1. Navigate to Azure Portal > Policy > Assignments > "Configure Azure
     Defender for Key Vault" at scope mg-platform
  2. Edit assignment → set Enforcement mode to "Default"
  3. Verify the managed identity has "Key Vault Contributor" role on all
     subscriptions under mg-platform
  4. After enabling, run: Start-AzPolicyComplianceScan
  5. Create a remediation task for the DINE effect to deploy Defender
     on existing Key Vaults (target: 23 Key Vaults currently unprotected)
  6. Expected cost impact: ~$0.20/10,000 transactions per Key Vault/month
     (Azure Defender for Key Vault pricing)
  7. Monitor for 48 hours; expect NC count to drop from 23 → 0
```

### E. Structured JSON Output (machine-readable)

AI also produces a validated JSON payload that can be consumed by automation pipelines, ticketing systems, or dashboards:

```json
{
  "assessmentDate": "2026-03-04T14:30:00Z",
  "posture": "Needs Improvement",
  "confidence": 0.94,
  "evidence": {
    "totalAssignments": 412,
    "nonCompliantResources": 1284,
    "highRiskPolicies": 37,
    "enforcementRate": 0.80,
    "highSecurityDoNotEnforce": 14,
    "alzGaps": 7,
    "expiringExemptions": 11
  },
  "topDrivers": [
    {
      "driver": "Unenforced high-security policies",
      "metric": "14 policies in DoNotEnforce",
      "impactEstimate": "Blocks ~60% of new non-compliant deployments if enforced"
    },
    {
      "driver": "Server protection gap",
      "metric": "426 NC resources under Defender for Servers",
      "impactEstimate": "33% of total NC count in one assignment"
    },
    {
      "driver": "Storage configuration drift",
      "metric": "218 NC resources missing diagnostic settings",
      "impactEstimate": "Affects compliance reporting and incident response"
    }
  ],
  "actions": [
    {
      "id": "ACT-001",
      "priority": "P1",
      "title": "Enforce top 5 high-security audit-only policies",
      "effort": "2-4 hours",
      "expectedNCReduction": 770,
      "owner": "Platform Team",
      "scope": ["Tenant Root", "mg-platform", "mg-landingzones"]
    },
    {
      "id": "ACT-002",
      "priority": "P1",
      "title": "Create remediation tasks for top 3 DINE policies",
      "effort": "4-8 hours",
      "expectedNCReduction": 831,
      "owner": "Security Team",
      "scope": ["mg-landingzones"]
    },
    {
      "id": "ACT-003",
      "priority": "P2",
      "title": "Review 11 expiring exemptions",
      "effort": "1 hour",
      "expectedNCReduction": 0,
      "owner": "Governance Team",
      "scope": ["Tenant-wide"]
    },
    {
      "id": "ACT-004",
      "priority": "P3",
      "title": "Close 7 ALZ policy gaps",
      "effort": "1-2 days",
      "expectedNCReduction": "Unknown until assigned",
      "owner": "Platform Team",
      "scope": ["Tenant Root"]
    }
  ],
  "trend": {
    "direction": "DEGRADING",
    "previous": "STABLE",
    "reason": "NC increase driven by new DINE policy detection artifacts in 2 subscriptions",
    "forecast": "Expected to reverse to STABLE within 1-2 cycles after remediation"
  },
  "disclaimer": "Narrative generated by AI from validated metrics. All numbers sourced from Azure Resource Graph. Verify recommendations against your environment before applying."
}
```

---

## 3. Why Use AI?

### For Platform / Security Engineers

| Pain point today | How AI helps |
|---|---|
| "I see 1,284 NC resources — where do I start?" | AI ranks actions by impact and gives effort estimates |
| "Delta shows +182 NC — is that bad or expected?" | AI explains root causes (detection artifact vs real regression) |
| "14 policies are audit-only — which matter most?" | AI cross-references security impact, scope, and NC count to prioritize |
| "I need to write a remediation ticket" | AI generates specific steps including portal paths, RBAC requirements, and expected outcomes |

### For Managers / Executives

| Pain point today | How AI helps |
|---|---|
| "What does 80% enforcement rate actually mean?" | AI translates metrics into business-risk language |
| "Is our posture getting better or worse?" | AI provides a one-paragraph trend explanation with forecast |
| "What should we fund next quarter?" | AI produces a prioritized action plan with effort and impact estimates |

### For Auditors / Compliance Teams

| Pain point today | How AI helps |
|---|---|
| "Map these findings to CE+ controls" | AI generates audit-ready narratives per control group |
| "Explain why this control is partially met" | AI references specific resource counts and remediation status |
| "Generate an evidence statement" | AI produces a structured paragraph citing exact metrics |

### When NOT to use AI

- **Air-gapped environments** — no API connectivity
- **Strict reproducibility requirements** — AI text may vary slightly between runs (metrics stay identical)
- **Minimal assessment** — if you only need CSV export or raw numbers, AI adds latency and cost
- **Sensitive environments** — if you cannot send policy metadata to an external AI endpoint (use Azure OpenAI with private endpoints to mitigate)

---

## 4. Prerequisites

### 4.1 AI Provider: GitHub Copilot (GitHub Models)

| Provider | Endpoint | Requirement |
|---|---|---|
| **GitHub Models** | `https://models.github.ai/inference/chat/completions` | GitHub token with `Models: read` permission |

> GitHub Models usage is governed by the current billing, quota, and rate-limit terms for your GitHub account or organisation.

### 4.2 Setup

1. **Generate a GitHub Personal Access Token (PAT)**
   ```
   GitHub.com → Settings → Developer settings → Personal access tokens → Fine-grained tokens
   ```
   - Token name: e.g., `policy-assessment-ai`
  - Required permission: **Models: read**

2. **That's it.** No Azure resource, no model deployment, no billing setup.

3. **Endpoint details**
  - **Endpoint**: `https://models.github.ai/inference/chat/completions`
   - **Auth header**: `Authorization: Bearer <your-github-pat>`
  - **Model**: `openai/gpt-4.1` by default; use IDs from the [current catalog](https://github.com/marketplace/models)
   - **API format**: OpenAI-compatible chat completions (`/chat/completions`)

4. **Quick test** (PowerShell)
   ```powershell
   $headers = @{
       'Authorization' = "Bearer $env:GITHUB_TOKEN"
       'Content-Type'  = 'application/json'
      'Accept'        = 'application/vnd.github+json'
      'X-GitHub-Api-Version' = '2026-03-10'
   }
   $body = @{
      model    = 'openai/gpt-4.1'
       messages = @(@{ role = 'user'; content = 'Say hello' })
   } | ConvertTo-Json -Depth 5

  Invoke-RestMethod -Uri 'https://models.github.ai/inference/chat/completions' `
       -Method POST -Headers $headers -Body $body
   ```

5. **Rate limits and billing**
  - Consult the current GitHub Models documentation for account and organisation limits.
  - The assessment typically performs 1–3 inference calls per run.

### 4.3 Script Configuration

```powershell
# Option A: Environment variable (recommended for automation)
$env:GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxx"
.\Get-PolicyAssignments.ps1 -AI Summary

# Option B: Script parameter
.\Get-PolicyAssignments.ps1 -AI Summary -AIKey "ghp_xxxxxxxxxxxxxxxxxxxx"

# Option C: Full analysis with HTML report
$env:GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxx"
.\Get-PolicyAssignments.ps1 -AI Full -Output HTML

# Option D: Use a different model
.\Get-PolicyAssignments.ps1 -AI Summary -AIModel openai/gpt-4.1
```

### 4.4 Cost

| Scenario | Tokens (approx.) | Cost |
|---|---|---|
| Executive summary (`-AI Summary`) | ~2,000 in + ~800 out | Depends on current GitHub Models terms |
| Full analysis (`-AI Full`) | ~8,000 in + ~3,000 out | Depends on current GitHub Models terms |
| Delta interpretation | ~4,000 in + ~1,500 out | Depends on current GitHub Models terms |

> Check the GitHub Models billing and rate-limit documentation before enabling AI in automated or high-volume runs.

### 4.5 Required Permissions

| Component | Permission needed | Why |
|---|---|---|
| GitHub Models | GitHub token with `Models: read` | Authenticate to `models.github.ai` |
| Policy data | Already handled by existing script RBAC | AI reads only computed results, not raw Azure data |
| Network | Outbound HTTPS to `models.github.ai` | API calls |

### 4.6 PowerShell Module Requirements

No additional modules required. The AI integration uses `Invoke-RestMethod` (built into PowerShell 7).

### 4.7 Consistency Controls (built into the design)

| Control | Purpose |
|---|---|
| `temperature: 0` | Minimises randomness in AI output |
| JSON Schema enforcement | AI must return structured output matching a fixed schema — rejects malformed responses |
| Metric validation | Script verifies every number in AI output matches computed values — rejects if mismatch |
| Deterministic fallback | If AI call fails or times out (10s default), script continues with current rule-based output |
| Prompt pinning | System prompt is version-controlled and deterministic — no user input injected into prompt |
| Data redaction | Resource IDs and subscription names can be hashed before sending to AI endpoint |

---

## 5. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Get-PolicyAssignments.ps1                  │
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │ Azure        │    │ Rule-Based   │    │ AI Layer     │   │
│  │ Resource     │───▶│ Scoring &    │───▶│ (Optional)   │   │
│  │ Graph        │    │ Analysis     │    │              │   │
│  │              │    │              │    │ Input:       │   │
│  │ • Assignments│    │ • Security   │    │  Computed    │   │
│  │ • Compliance │    │ • Cost       │    │  metrics     │   │
│  │ • Exemptions │    │ • Risk       │    │  only        │   │
│  │ • NC data    │    │ • ALZ gaps   │    │              │   │
│  │ • CE+ status │    │ • Delta      │    │ Output:      │   │
│  └──────────────┘    └──────────────┘    │  Narrative + │   │
│                             │             │  actions     │   │
│                             ▼             └──────┬───────┘   │
│                      ┌──────────────┐            │           │
│                      │ Console      │◀───────────┘           │
│                      │ CSV / HTML   │                        │
│                      │ YAML         │  AI text injected      │
│                      │ JSON (new)   │  alongside metrics     │
│                      └──────────────┘                        │
└─────────────────────────────────────────────────────────────┘

Key principle: AI receives ONLY pre-computed metrics (numbers, labels,
categories). It never queries Azure directly and never sees raw
resource IDs unless you explicitly enable it.
```

---

## 6. AI Output Examples

### Console: `-AI Summary` mode

```
═══════════════════════════════════════════════════════════════════════════════
  🤖 AI EXECUTIVE INSIGHTS (powered by Azure OpenAI)
═══════════════════════════════════════════════════════════════════════════════
  Overall Posture : 🟠 Needs Improvement
  Confidence      : High (0.94)
  Evidence Window : 412 assignments | 1,284 NC resources | 37 high-risk

  TOP DRIVERS
  1. 14 high-security assignments in DoNotEnforce mode — compliance is
     reported but non-compliant deployments are not blocked.
  2. +182 non-compliant resources vs previous YAML snapshot, concentrated
     in mg-landingzones (storage and compute categories).
  3. 7 Azure Landing Zone recommended policies are missing entirely,
     including Deny-PublicIP and Deploy-DDoS-Protection.

  PRIORITIZED ACTIONS
  ┌────┬─────────────────────────────────────────────────────┬──────────┐
  │ P1 │ Enforce top 5 high-security audit-only policies     │ 2–4 hrs  │
  │ P1 │ Remediate top 3 DINE policies (831 resources)       │ 4–8 hrs  │
  │ P2 │ Review 11 exemptions expiring within 30 days        │ 1 hr     │
  │ P3 │ Close 7 ALZ policy gaps                             │ 1–2 days │
  └────┴─────────────────────────────────────────────────────┴──────────┘

  NOTES
  • All numbers validated against computed assessment data.
  • AI narrative generated via Azure OpenAI (gpt-4o, temperature=0).
  • To disable AI: omit the -AI parameter.
═══════════════════════════════════════════════════════════════════════════════
```

### Console: `-AI Full` mode (adds per-policy remediation)

```
  🤖 AI REMEDIATION PLANS (top 5 high-risk policies)

  1/5  Configure Azure Defender for servers
       Scope: mg-landingzones | Effect: DINE | NC: 426
       ─────────────────────────────────────────────────
       Step 1: Verify Defender for Servers Plan 2 is enabled
               Portal → Defender for Cloud → Environment Settings
       Step 2: Check managed identity permissions
               Required: "Virtual Machine Contributor" on target subscriptions
       Step 3: Run remediation task
               PowerShell: Start-AzPolicyRemediation -Name "remediate-defender-servers" `
                           -PolicyAssignmentId "/providers/..."
       Step 4: Monitor — expect NC → 0 within 24–48 hours
       Cost: ~$15/server/month (Plan 2 pricing)

  2/5  Deploy diagnostic settings for Storage Accounts
       Scope: mg-landingzones | Effect: DINE | NC: 218
       ─────────────────────────────────────────────────
       Step 1: Ensure Log Analytics workspace exists in target region
       Step 2: Verify managed identity has "Monitoring Contributor" role
       Step 3: Run remediation task for existing storage accounts
       Step 4: New storage accounts will be auto-configured by DINE
       Cost: ~$2.76/GB ingested to Log Analytics
  ...
```

### HTML Report: New AI Section

When `-Output HTML` and `-AI Summary` (or `-AI Full`) are used together, the HTML report includes an additional section:

```
Section 9: AI Executive Insights
├── Posture card with trend indicator
├── Top 3 drivers with impact estimates
├── Prioritized action table (sortable, filterable)
├── Delta interpretation (if -DeltaYAML was used)
├── Per-policy remediation cards (if -AI Full)
└── Evidence basis panel (collapsible — shows all metrics used)
```

### YAML Database: AI metadata

When `-Output YAML` and `-AI` are used together, the YAML file includes:

```yaml
aiInsights:
  generatedAt: "2026-03-04T14:30:00Z"
  model: "gpt-4o"
  provider: "AzureOpenAI"
  temperature: 0
  posture: "Needs Improvement"
  confidence: 0.94
  topDrivers:
    - "14 high-security policies in DoNotEnforce mode"
    - "+182 NC resources vs previous snapshot"
    - "7 ALZ recommended policies missing"
  actions:
    - priority: P1
      title: "Enforce top 5 high-security audit-only policies"
      effort: "2-4 hours"
      expectedNCReduction: 770
    - priority: P1
      title: "Create remediation tasks for top 3 DINE policies"
      effort: "4-8 hours"
      expectedNCReduction: 831
  trend:
    direction: DEGRADING
    reason: "Detection artifacts from 7 new DINE policies + storage drift in 2 subscriptions"
    forecast: "Expected reversal to STABLE within 1-2 assessment cycles"
```

---

## Summary: Decision Matrix

| If you need… | Use… |
|---|---|
| Raw metrics for dashboards/SIEM | Current script (no AI) |
| Fast executive briefing for leadership | `-AI Summary` |
| Actionable ticket-ready remediation steps | `-AI Full` |
| Audit narrative for compliance teams | `-AI Full -CEP Full` |
| Delta root-cause analysis | `-AI Summary -DeltaYAML <path>` |
| CI/CD pipeline integration | `-AI Summary -AIOutput JSON` (structured, parseable) |
| Air-gapped or no-API environments | Current script (no AI) — fully functional |

> **Bottom line**: AI doesn't replace the script's deterministic engine. It adds a narrative and prioritization layer that turns raw data into decisions.
