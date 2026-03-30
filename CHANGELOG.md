# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

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
