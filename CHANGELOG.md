# Changelog

All notable changes to this package will be documented in this file.

## [1.4.1] - 2026-04-29

### Changed

- Streamlined the PyPI project description for clarity.
- Reorganized the README with feature overview, tool selection guide, quick reference, common mistakes, and troubleshooting sections.
- Added a VS Code MCP client setup example.

## [1.4.0] - 2026-04-29

Clean public baseline release.

### Added

- 11 MCP tools mapping the Karon API surface:
  browse, crawl, scrape, fetch, extract, batch_scrape,
  watch_snapshot, watch_diff, watch_list, credits, pricing.
- Stable, generalized error messages for MCP responses.
- Optional development logging via `KARON_MCP_ENV=development` and
  `KARON_MCP_DEBUG_ERRORS=1` (both required).

### Notes

- 1.4.0 was yanked on 2026-04-29; treat 1.4.1 as the supported public release.
- Earlier public artifacts are superseded by the 1.4.1 release.
