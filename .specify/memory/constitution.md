<!--
Sync Impact Report
- Version: N/A → 1.0.0
- Modified principles: Code Quality & Maintainability; Testing Discipline & Coverage; User Experience Consistency; Performance & Efficiency
- Added sections: Quality Gates & Deliverables; Delivery Workflow & Review
- Removed sections: Placeholder Principle 5
- Templates updated: ✅ .specify/templates/plan-template.md; ✅ .specify/templates/spec-template.md; ✅ .specify/templates/tasks-template.md
- Follow-up TODOs: None
-->

# Speckit Codex Constitution

## Core Principles

### I. Code Quality & Maintainability (NON-NEGOTIABLE)
- Keep changes small and cohesive; avoid dead code and enforce cleanup plans for feature flags.
- Linting and formatting must pass in CI; new patterns or abstractions require a documented rationale.
- Public APIs, data shapes, and behavioral expectations are documented alongside code and kept current.
- Dependencies are pinned, security-scanned, and pruned when unused; risky additions need reviewer approval.
- Pull requests include clear intent, reviewer guidance, and stay within manageable scope to preserve review depth.
Rationale: Predictable, readable code unlocks safe velocity and lowers long-term maintenance cost.

### II. Testing Discipline & Coverage
- Every behavior change ships with automated tests; fixes start by reproducing the failure with a failing test.
- Use a pyramid: unit tests for logic, integration/contract tests for boundaries, and end-to-end tests for critical user flows.
- Baseline coverage is 85% statements/branches for touched areas; exceptions must be explicitly justified in the PR.
- Tests are deterministic, hermetic, and parallel-friendly; no reliance on external state without controlled fixtures.
- CI must run the full relevant suite and block merges on failures; hotfixes add post-hoc tests within one working day.
Rationale: Strong, enforced testing prevents regressions and documents intended behavior.

### III. User Experience Consistency
- User-facing work must align with the shared design system/tokens; bespoke UI requires design approval before merge.
- Each story/spec defines UX acceptance criteria covering happy, empty, loading, and error states with copy and screenshots.
- Accessibility meets WCAG 2.1 AA: keyboard access, focus order, contrast, aria semantics, and motion alternatives.
- Terminology, formatting (dates, numbers, time zones), and error messaging stay consistent and actionable.
- User-facing PRs include a visual diff (screenshots or recordings) and receive UX/design review before release.
Rationale: Consistent, accessible experiences reduce user confusion and supportability burden.

### IV. Performance & Efficiency
- Plans/specs declare measurable budgets; defaults unless superseded: backend p95 <200ms for primary paths, background jobs <2s, UI interactions <100ms, and animations at 60fps.
- New flows add instrumentation for latency, error rates, and resource use; dashboards or logs must make regressions visible.
- Performance-critical paths include regression tests or monitors; releases are blocked if budgets are unmet.
- Prefer efficient algorithms and data access (avoid N+1, reduce allocations); cache or lazy-load with clear invalidation rules.
- Scale-affecting changes require profiling or load validation before launch and a rollback plan if targets slip.
Rationale: Guardrails keep the product fast, resource-responsible, and reliable under growth.

## Quality Gates & Deliverables
- Every plan/spec names owners, test strategy, UX acceptance (incl. accessibility), and performance budgets with measurement approach.
- Code review checklists verify alignment with all principles, updated documentation, and observability/performance hooks.
- Deliverables include refreshed docs (quickstart, README snippets if affected), migration notes, and monitoring/alerting updates for new behavior.
- High-risk changes capture rationale and alternatives; complexity is justified in writing when deviating from defaults.

## Delivery Workflow & Review
- Work flows through spec → plan → tasks with explicit Constitution Check sign-off before implementation starts.
- Tests are written before or alongside code; CI gates enforce linting, tests, and performance/UX checks where applicable.
- User-facing releases require UX/design sign-off; performance-sensitive releases require metrics review against budgets.
- Post-release, monitor defined signals, keep rollback steps ready, and document learnings for future work.

## Governance
- This constitution supersedes other process guidance; conflicts are resolved in favor of these principles.
- Amendments occur via PR with rationale, redlines, and propagation to dependent templates; records of changes are retained.
- Versioning follows SemVer: MAJOR for breaking/removal of principles, MINOR for new principles/sections or materially expanded guidance, PATCH for clarifications/typos.
- Compliance is checked in every PR and via quarterly audits; non-compliance requires remediation plans before shipping.

**Version**: 1.0.0 | **Ratified**: 2025-12-05 | **Last Amended**: 2025-12-05
