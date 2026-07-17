# What's New in v4.0

Version 4.0.0 is a major deterministic-only reporting release. It removes the generative AI integration and reorganises the HTML report around the decisions and evidence required by each audience.

## Breaking Changes

- GitHub Models parameters, credentials, provider calls, generated narratives, and `aiInsights` YAML output have been removed.
- The former Overview and Executive pages are replaced by a single Summary page.
- The HTML report now uses five audience pages: Summary, CSA / Architect, Engineer, Evidence, and Methodology.
- Report sections are emitted directly into their owning audience page. The previous client-side relocation layer and intermediate host containers no longer exist.

No migration is required for the core Azure assessment parameters. Remove any obsolete AI parameters from saved commands or automation before running v4.0.0.

## Executive Summary

The Summary is designed for leadership and answers four questions:

1. What is happening?
2. What happens if no action is taken?
3. What is expected if action is taken?
4. Which ownership, funding, or risk-acceptance decisions are required?

The first view contains five global measures only: assessment outcome, affected resources, affected subscriptions, critical findings, and evidence status. Assignment ratios are not presented as compliance scores.

Assigned compliance initiatives with evaluated policy states are aggregated in a collapsible Compliance & Landing Zone Results panel. Azure Landing Zone is labelled as inventory coverage, CE+ is included only when its score is measured, and assigned but unevaluated standards are excluded.

## Audience Ownership

- **Summary**: Executive outcome, exposure, measured standards, priority risks and actions, consequences, and leadership decisions.
- **CSA / Architect**: Scope placement, inheritance, control balance, category coverage, governance, Azure Landing Zone, and cost design analysis.
- **Engineer**: Prioritised findings, assignments, affected resources, enforcement gaps, security priorities, and remediation evidence.
- **Evidence**: Collection provenance, source health, evidence counts, and optional snapshot changes.
- **Methodology**: Confidence, sources, collection boundaries, limitations, interpretation guidance, and glossary.

## Report Experience

- Compact report header and single-line metadata.
- Hash-routed audience pages with no DOM relocation.
- Repeated subscription findings grouped in Summary while raw assignment records remain in Engineer.
- Key Findings & Risks and Compliance & Landing Zone Results are closed by default and can be expanded on demand.
- Responsive KPI, disclosure, narrative, and evidence layouts for desktop and mobile.
- Print output continues to expand disclosures so detailed evidence is retained.

## Evidence Semantics

- Non-compliant evaluated assessments use the explicit outcome `Action required`.
- Evidence status is reported separately from posture.
- Framework percentages include their evidence basis and do not establish certification.
- Benefits of remediation remain targets that require a subsequent Azure Policy evaluation.
- Missing permissions, failed queries, and unavailable sources cannot produce a positive posture conclusion.

See [CHANGELOG.md](CHANGELOG.md) for the complete release history and [README.md](README.md) for current usage and report guidance.
