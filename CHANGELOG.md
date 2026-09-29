# Changelog

## 2.0.0 — development branch

- Restore the large two-color SecCheck title, original subtitle and author credit;
  remove the slogan. Separate scans and tools, with the full-scan scope stated.
- Check dependencies at interactive startup, including pacfile from pacutils.
  Explain their purpose, offer installation and recheck after a successful transaction.
- Group duplicate rkhunter summary/log warnings and classify prerequisite/baseline
  notices as diagnostics. Keep original logs and unresolved/strong findings.
- Automatically verify supported file warnings against an exact package record
  and an independently calculated SHA-256. Explain SSH warnings using server
  configuration/version. Missing or ambiguous evidence cannot close a warning.
- Preserve explained warnings in details and private reports; add checks.tsv and
  paginated details with meaning, verification and next action.
- Space AUR requests and handle HTTP 429 with one bounded retry respecting
  Retry-After. Persistent rate limits stop further requests and preserve history.
- Native-test follow-up: explain skipped rkhunter checks and execution diagnostics
  in the summary; an exact egrep deprecation notice alone no longer invalidates a
  completed scan. Regex/read errors and skipped tests still limit coverage.
- Keep distinct logs for successive failed AUR requests, including request URLs,
  curl exit codes and original errors. Show connection/data failures in the summary.
- Distinguish an incomplete first AUR scan from a preserved existing baseline.
- Explain how to install missing pacutils and repeat the SHA-256 check.
- English/Italian selection at startup and persistent language through sudo.
- Petrolio terminal interface, responsive tables, count bars, labelled traffic light,
  ASCII and NO_COLOR support, four demonstration scenarios without root.
- Independent module completion and finding priority; failed checks cannot mean clean.
- Removed unsupported compromise percentages and unrelated cross-confirmation.
- Fresh rkhunter/Lynis reports, bounded commands, explicit SHA-256 checks with pacutils.
- Read-only Atomic Arch inspection with dated primary sources and stated coverage.
- Private run reports, TSV exports and sanitized displayed evidence.
- Online AUR maintenance module: outdated flags, orphaned packages, recipe age,
  newer versions, unlisted packages and maintainer/co-maintainer changes since a
  private local baseline. Offline mode and failure-safe snapshot updates.
- Replaced the old parser-only test harness with behavioral regressions and inert
  command-boundary integration fixtures. Tests never delete production reports.

Native Arch Linux and derivative validation is required before a stable release.
