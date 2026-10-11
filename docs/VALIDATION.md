# SecCheck 2.0 development validation

## Automated verification

Verified on 11 October 2026 with the guided-setup source:

- `bash -n seccheck.sh seccheck_test.sh`: passed.
- ShellCheck 0.11.0, warning severity: passed without diagnostics.
- `bash seccheck_test.sh`: **198 tests passed** in 46.446 seconds, no skips.
- Independent review: native reference format, alias links, exclusive creation,
  configured hashing and flagged indirect helpers corrected with regression tests.
- An isolated rkhunter 1.4.6 run generated a native reference with 122 records;
  its headers, canonical link targets and permission format were checked against
  the implementation. All writes stayed in a private scratch database. This was
  a format check on Ubuntu, not an Arch system scan or package-origin audit.
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
- Separately confirmed initial setup, refusal/EOF, original/repeat evidence,
  changed files, package/alias links, setuid modes, hash-command path preservation,
  incomplete reruns and interrupted setup. Existing/empty references and a
  concurrently created target file, link or directory cannot be overwritten.

The scanners are inert command fixtures; these tests do not certify a real PC.
Existing-root PTY tests are skipped on non-root test accounts. The optional fuser
trial is skipped when the necessary tool or own-process access is unavailable.
The noninteractive baseline guard test checks both account types: root may run
the inert scan; non-root must receive exit 77 and the sudo hint before scanning
or initializing anything. Its original root-only expectation was corrected
after GitHub Actions exposed the mismatch on its unprivileged runner.

## Native validation before release

1. Try English and Italian on Arch and at least one derivative.
2. Start without pacutils: verify that installation is offered and can be declined.
3. Run a complete scan; check the rkhunter/Lynis/pacman/pacutils native formats.
4. Choose automatic analysis and confirm explained items remain in the report.
5. Check the warnings/finish routes, remaining items and optional improvements.
6. Interrupt a scan and an analysis; verify that the private report is preserved.
7. Verify the labels on narrow and normal-width terminals.
8. With an absent initial reference, decline guided setup and then try confirmed
   setup after reviewing the installed system. Verify that only checked files
   are recorded, rkhunter is repeated and independent errors stay visible.

An absent rkhunter.dat stays unresolved until verified, separately confirmed
setup succeeds. Real scanner failures or unexplained file changes remain open.
SecCheck does not create a baseline from a merely quiet scan. Checks from a
running system cannot rule out hidden compromise or prove package provenance.
