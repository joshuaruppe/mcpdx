# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **CLI: shared flags now work before *or* after the subcommand.** Transport,
  output, and drift flags were only accepted after the subcommand, so
  `mcpdx --insecure audit ...` (the position-independent form curl users expect
  from `-k`) errored out to the usage screen. They are now accepted in either
  position.
- **CLI: repeatable flags no longer drop values across the subcommand.** A
  header or env var passed before the subcommand (e.g. `-H ... audit -H ...`)
  could be silently discarded; `-H`/`-e` values from both sides are now merged.
- **client: tolerate malformed server responses.** A `null`/non-object result
  from `initialize` or a `*/list` call raised an uncaught `AttributeError` and
  aborted the run. Such responses are now handled gracefully — important when
  pointing the tool at hostile or non-conformant servers.
- **fuzz: eliminate SSTI (`7*7=49`) false positives.** The always-on template
  injection canary flagged any tool whose normal output happened to contain
  `49`. Detection is now differential: an indicator that already appears in the
  benign baseline response is not attributed to a payload.
- **transport: cleaner error handling.** A write to a closed local-server stdin
  (`ValueError`) is now surfaced as a `TransportError` instead of an "unexpected
  error", and a failed HTTP *notification* no longer enqueues an orphaned
  synthetic error response.
- **report: graceful handling of malformed saved reports.** `mcpdx report` on a
  valid-JSON report whose findings are missing required fields now renders with
  safe fallbacks instead of crashing with a `TypeError`.
- **report: consistent severity counts.** Finding severities are normalized to a
  canonical level so the summary counts can no longer silently disagree with the
  findings list (e.g. an externally-loaded report using `"High"` or a typo).
- **enum: `--json` now writes UTF-8** (`ensure_ascii=False`), matching the other
  report writers instead of escaping non-ASCII characters.

## [1.1.0]

- Reworked the transport layer and added a probe for detecting vulnerable
  servers.
