# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

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

