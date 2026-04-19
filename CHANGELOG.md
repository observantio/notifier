# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased] - 2026-04-17

### Added

- Added notifier mutation-testing configuration for `mutmut` and selective notifier test execution.

### Changed

- Added Apache license header blocks to notifier regression and middleware tests.

### Fixed

- Cleaned up notifier test assertions and deterministic state handling in edge-case regression tests.
- Hardened URL safety parsing to satisfy strict typing without behavior drift, and restored full notifier `mypy`/`pytest` green status at 100% coverage.
- Refactored alertmanager, incident, Jira, notification, and storage/access call surfaces to typed request/context models while preserving router/runtime behavior.
- Removed remaining strict-design lint violations (`too-many-args`, `too-many-positional-arguments`, `too-many-statements`, etc.) across notifier and restored full `pylint` 10.00/10 with notifier-wide `mypy` + `pytest` green at 100% coverage.

## [v0.0.4] - 2026-04-14

### Added

- Added strict notifier mutation testing support to improve coverage and validation for notification channel workflows.
- Added notifier runtime SSL listener configuration support (`NOTIFIER_SSL_ENABLED`, `NOTIFIER_SSL_CERTFILE`, `NOTIFIER_SSL_KEYFILE`) with startup validation.

### Changed

- Updated notifier `__main__` startup to enable TLS listener mode when SSL runtime settings are provided.
- Improved Alertmanager status parsing compatibility by normalizing sparse `/api/v2/status` payloads before model validation.

### Fixed

- Fixed SendGrid and Resend email provider payload handling and JSON request typing for notification channels.
- Fixed HTML body support and legacy email delivery compatibility in notifier email templates and channel workflows.

## [v0.0.3] - 2026-04-07

### Added

- Added dynamic OpenAPI response inference middleware for internal alertmanager endpoints to keep generated contracts aligned with authenticated runtime behavior.
- Added focused middleware coverage tests for OpenAPI generation paths.

### Changed

- Reworked runtime dependency declaration to standard PEP 621 `dependencies = [...]` syntax in `pyproject.toml`.
- Pinned notifier runtime dependencies to explicit `==` versions for reproducible installs/builds.
- Applied a clean pylint reformat/refactor pass across notifier with safe readability-oriented formatting updates.
- Enforced strict naming consistency for config attributes, module-level state/constants, and related helper/test touchpoints to match pylint policy.
- Removed legacy uppercase alias compatibility paths and migrated code/tests to strict snake_case config naming only.
- Removed permissive naming exceptions in lint config and aligned notifier code to strict naming rules without intended runtime behavior changes.
- Updated notifier app wiring to install custom OpenAPI middleware at startup.
- Tightened alerting request and router validation behavior to improve schema-conformance under contract testing.
- Refined silences operations handling to better match documented response semantics.
- Resolved validation gaps identified by Schemathesis and fuzz-style tests; the provided verification scripts now run fully green (100%).
- Updated alert-rule channel delivery compatibility used by both webhook-triggered notifications and `/rules/{rule_id}/test`:
  - delivery still requires matching rule name (`labels.alertname`), enabled rule, enabled channel, and tenant/org resolution.
  - `private` rules deliver to owner-matching `private` channels only.
  - `group` rules deliver to `private` channels and overlapping `group` channels.
  - `tenant/public` rules deliver to `private`, overlapping `group`, and `public` channels.
  - delivery to another user's `private` channel remains blocked.

## [v0.0.2] - 2026-03-30

### Added

- Added org-scoped PromQL helper endpoints for alert authoring: `/api/alertmanager/metrics/query`, `/api/alertmanager/metrics/labels`, and `/api/alertmanager/metrics/label-values/{label}`.
- Added PromQL evaluation responses with validation state, result type, sample previews, and current value hints for UI validation workflows.

### Changed

- Extended AlertManager service operations to include label-name lookup, label-value lookup, and direct PromQL evaluation against Mimir.
- Improved incident assignment auditing so assignment and unassignment actions are explicitly logged with the acting user.
- Updated incident assignment side effects so auto move-to-in-progress and assignment email notifications only run when an assignee is present.
- Updated incident patch storage handling to respect explicitly provided `assignee` fields, enabling reliable unassign behavior when clearing assignee values.
- Updated pre-commit type/lint hooks to read config from `pyproject.toml` (mypy + pylint), replacing file-specific config path references.
- Switched notifier DB session creation to a cached `sessionmaker` factory with stricter initialization checks and explicit factory teardown on dispose.
- Refined middleware/alert-service implementation details for cleaner lint behavior (structured logging formatting and explicit unused dependency markers).

### Fixed

- Fixed DB session guard behavior for partially-initialized database state (`_engine` present while session factory is missing).
- Fixed resilience and notification-sender edge-case coverage for retry/HTTP error handling paths.

## [v0.0.1] - 2026-03-20

### Added

- Added a tag-driven release workflow so creating a git tag like `vX.Y.Z` publishes a matching versioned image.
- Added GitHub Release creation as part of the same release workflow.
- Added multi-architecture image publishing (`linux/amd64`, `linux/arm64`) for release tags.

### Changed

- Replaced the previous main-branch CI-follow workflow publishing approach with a release-tag-first flow.
- Standardized image tag output to semantic tag version format (`ghcr.io/<owner>/notifier:vX.Y.Z`).

### Notes

- This service now treats git tags as release boundaries.
- For coordinated platform releases, align this tag with the version expected by the main repository manifest.
