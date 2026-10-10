# SecCheck 2.0 development validation

## Automated verification

Verified on 10 October 2026 with the final security-flow source:

- `bash -n seccheck.sh seccheck_test.sh`: passed.
- ShellCheck 0.11.0, warning severity: passed without diagnostics.
- `bash seccheck_test.sh`: **166 tests passed** in 70.826 seconds, no skips.
- Independent review: two report-access/documentation issues reproduced and
  corrected; both targeted terminal regressions passed after the fix.
- Menu and result screenshots captured from actual terminal output and inspected.

The suite covers:

- Three security adapters, fresh reports, unavailable tools, incomplete/error
  exits and scanner output that cannot be interpreted reliably.
- Real terminal interaction for language, dependency installation, follow-up
  consent and existing-root report updates.
- A bounded initial result, separate optional suggestions and technical evidence,
  whole-path grouping/filtering and recognized-message explanations.
- Exact package records, independent SHA-256 checks and metadata differences.
  A changed executable or an unknown path cannot be dismissed by its name.
- Rootkit signatures remaining urgent even when another module completes.
- SSH keyword case, duplicate rejection, missing-host-key fallback and errors.
- /dev list parsing, NUL/ambiguous paths, process identity limits and flagged-tool
  protection. A real fuser integration trial opens only its own temporary file.
- Private report permissions, complete original evidence, interrupted-check
  persistence, narrow terminals, ASCII and NO_COLOR.

The scanners are inert command fixtures; these tests do not certify a real PC.
Existing-root PTY tests are skipped on non-root test accounts. The optional fuser
trial is skipped when the necessary tool or own-process access is unavailable.

## Native validation before release

1. Try English and Italian on Arch and at least one derivative.
2. Start without pacutils: verify that installation is offered and can be declined.
3. Run a complete scan; check the rkhunter/Lynis/pacman/pacutils native formats.
4. Choose automatic analysis and confirm explained items remain in the report.
5. Check the warnings/finish routes, remaining items and optional improvements.
6. Interrupt a scan and an analysis; verify that the private report is preserved.
7. Verify the labels on narrow and normal-width terminals.

A missing rkhunter.dat, real scanner failures or unexplained file changes remain
open. SecCheck does not create a baseline from a merely quiet scan. Checks from a
running system cannot rule out hidden compromise or prove package provenance.
