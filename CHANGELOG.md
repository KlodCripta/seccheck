# Changelog

## 2.0.0 — development branch

- Read the SSH root-login setting with lowercase or canonical keyword case in
  both -T and -G output. Preserve value case, original logs and duplicate rejection.
- Recognize rkhunter's padded file-summary columns and merge them with the
  detailed warning, without joining whitespace inside ambiguous paths.
- Retry SSH configuration reading with `sshd -G` after the exact missing-host-key
  failure. Preserve both attempts and explain the configuration-only scope.
- Explain the recognized Lynis reboot warning directly in English/Italian,
  keeping its original evidence and priority.
- Group package-integrity differences by exact path in summary counts and paged
  details, preserving all raw observations and the highest unresolved priority.
  Keep suggestions separate from the remaining-assessment count.
- Show a bounded, sanitized SSH failure excerpt directly in details while keeping
  complete original command logs in the private report directory.
- Add the final s/y confirmation for read-only file/SSH follow-ups using existing
  root permissions; update the private result and exit assessment after checks.
- Add bounded integrity follow-ups; matching hashes never clear timestamp/size
  warnings. Keep ambiguous paths, strong signatures and unavailable checks open.
- Shorten bilingual summaries and explanations. Move raw diagnostics and check
  logs to the full report; keep human-readable details and actions accessible.
- Treat only explicitly explained optional rkhunter skips as exclusions. Preserve
  real prerequisite and grep compatibility errors, including missing baseline causes.

- Remove the campaign-specific Atomic Arch module, indicators and CLI options.
  Full scans now cover four modules; AUR maintenance moves to menu option 5.
- Add EN/IT AUR usage guidance and an inventory-review reminder above 50 confirmed
  AUR matches. The number is not a security threshold.
- Label automatically explained warnings consistently in details and reports.

- Interpret pacman's SHA-256 mismatch as a content difference. Explain permission,
  owner/group and timestamp differences separately, without dismissing any by path.
- Show the exact tool and reason when integrity coverage is incomplete: unreadable
  files, missing MTREE data, unsupported output, timeouts or unexpected exits.
  A detected file difference alone does not make a completed check partial.
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
  in the full report; an exact egrep deprecation notice alone no longer invalidates a
  completed scan. Regex/read errors and unexplained skipped tests still limit coverage.
- Keep distinct logs for successive failed AUR requests, including request URLs,
  curl exit codes and original errors. Retain connection/data failures in the full report.
- Distinguish an incomplete first AUR scan from a preserved existing baseline.
- Explain how to install missing pacutils and repeat the SHA-256 check.
- English/Italian selection at startup and persistent language through sudo.
- Petrolio terminal interface, responsive tables, count bars, labelled traffic light,
  ASCII and NO_COLOR support, four demonstration scenarios without root.
- Independent module completion and finding priority; failed checks cannot mean clean.
- Removed unsupported compromise percentages and unrelated cross-confirmation.
- Fresh rkhunter/Lynis reports, bounded commands, explicit SHA-256 checks with pacutils.
- Private run reports, TSV exports and sanitized displayed evidence.
- Online AUR maintenance module: outdated flags, orphaned packages, recipe age,
  newer versions, unlisted packages and maintainer/co-maintainer changes since a
  private local baseline. Offline mode and failure-safe snapshot updates.
- Replaced the old parser-only test harness with behavioral regressions and inert
  command-boundary integration fixtures. Tests never delete production reports.

Native Arch Linux and derivative validation is required before a stable release.
