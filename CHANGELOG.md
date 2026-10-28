# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- MCPG-003 no longer reports a warning against sharing secrets ("Do not include any API keys or
  passwords in your query") as an exfiltration request. Found in the [field study](docs/field-study.md).

## [1.0.0] - 2026-10-28

First public release.

### Added

- GitHub Action (`uses: diegoperezg7/mcp-guard@v1`): scans stdio, Streamable HTTP and exported
  JSON targets in-process from a committed bundle, writes SARIF and an optional HTML report,
  appends the Markdown report to the job summary, sets `findings`, `critical`, `high`, `medium`,
  `low`, `verdict`, `sarif-file` and `html-report` outputs and fails according to `fail-on`.
- `npm run build:action`, and a CI check that fails when `dist/action` is stale.
- `action-selftest` workflow that runs the action against the demo servers.
- CLI `mcp-guard scan` over stdio, Streamable HTTP and exported `tools/list` JSON, with 24 rules
  for tool poisoning, shadowing, excessive permissions, secrets, transport and runtime behaviour,
  plus a coverage notice when input limits cut something.
- Optional read-only probe (`--probe`, `--allow-unsafe`) with canary inputs, and an optional LLM
  judge that only annotates MCPG-005 findings.
- Reports: terminal table, JSON, Markdown, SARIF 2.1.0 and a self-contained HTML report, all
  hardened against hostile server-supplied text.
- Input limits per list, field, server inventory and time, reported as MCPG-090 when reached.

### Changed

- Licensed under the Apache License 2.0.

[Unreleased]: https://github.com/diegoperezg7/mcp-guard/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/diegoperezg7/mcp-guard/releases/tag/v1.0.0
