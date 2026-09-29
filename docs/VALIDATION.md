# SecCheck 2.0 development validation

## Completed

Latest local suite: **114 tests passing**, Bash syntax checks and ShellCheck 0.11.0
clean after the startup and rkhunter-interpretation corrections (29 September 2026 UTC).

- Regression tests exercise evidence/coverage independently, scanner boundary fixtures,
  missing tools and unknown output, static Atomic Arch reads, private reports,
  EN/IT CLI, real PTY language selection and narrow/ASCII output.
- AUR metadata tests cover current owner/co-owners, outdated/orphan/age/version
  signals, first baseline, observed changes, absent foreign packages, bad responses,
  interrupted writes and snapshot preservation.
- The Petrolio screenshot is captured from the actual program demo in a PTY.
- An independent whole-branch review of commit `5cdf30b` found one critical and
  three important defects. Each was reproduced with an inert regression before
  the fix: isolated Python imports; aggregation of both rkhunter streams;
  rejection of truncated maintainer HTML; explicit depth-limit coverage.
- Its advice-wording finding was also fixed because the result must explain AUR
  maintenance suggestions as well as configuration suggestions.

The tests use temporary fixtures. They do not run real security scanners, inspect
private user homes, change packages or remove existing production reports.

## Decisions and remaining boundaries

1. **Native Arch remains a release gate.** Ubuntu fixture tests cannot certify
   the installed rkhunter/Lynis/pacman/pacutils versions on Arch or a derivative.
   A format or platform difference may require another adapter adjustment.
2. **Malware fixtures stay inert.** Tests verify static matching and parsing without
   obtaining/executing a live payload. Undocumented variants may evade detection.
3. **Live-system limits remain explicit.** Hidden kernel artifacts, a hostile local
   root user and filesystem races are outside the guarantee of a Bash assistant;
   a compromised system may conceal evidence.
4. **Maintainer history consists of observations.** Changes before the first scan
   or between scans cannot be reconstructed reliably. Intermediate transfers may
   go unreported.
5. **Native AUR completion was reported.** The user's later run completed the AUR
   maintenance module and recorded its first snapshot. The supplied output does
   not establish whether a 429 retry was exercised in that run. Proxy failures in
   this environment and controlled fixtures still cover incomplete/error behavior.
6. **AUR advice wording was treated as functional.** The initial text incorrectly
   narrowed all suggestions to configuration. The replacement covers package
   maintenance and settings; the tradeoff is slightly broader wording.

The environment also prohibited changing UID with `runuser`, so that particular
unprivileged-user trial was unavailable. Demo paths require no root operation and
are covered through CLI and PTY tests under the current execution account.

## Before a stable release

On an Arch test machine and at least one derivative, record tool versions and test:

- startup language selection, sudo retention and an unprivileged demo;
- full and individual scans, missing optional tools and interrupted runs;
- genuine changed/missing package files and configuration backups in a disposable VM;
- a successful AUR query, then an offline/error run preserving the snapshot;
- custom user homes/cache paths, traversal bounds and report permissions.

Keep the resulting sanitized raw output as new fixtures when the upstream format
differs. Do not merge/tag/publish this development branch as stable before that pass.

## First native feedback, 28 September 2026

The supplied run reported rkhunter 1.4.6, Lynis 3.1.7, missing pacutils, a completed
static Atomic Arch module, and three failed AUR page requests. The rkhunter excerpt
contains egrep deprecation notices, grep regex warnings and six skipped checks.
Those messages do not diagnose malware. Skipped checks and regex/read problems
remain explicit coverage limits; only the exact egrep forwarding notice is
informational by itself.

The AUR adapter was found to reuse a failed page's log filename because it numbered
requests by successful cache entries. Numbering now counts attempts. The summary
also carries the original curl error instead of only `AUR request failed`, and
correctly distinguishes a missing first baseline from a preserved previous one.
Regression fixtures reproduce successive HTTP/timeout failures, DNS failures,
baseline preservation and the native rkhunter diagnostic patterns.

The later retained curl stderr confirmed HTTP 429 (rate limiting). The request
loop had no pacing and no Retry-After handling. Requests are now spaced, with one
retry after a permitted wait; a persistent limit or an excessive wait stops all
further network requests in that run. Fixtures cover recovery, persistent 429,
numeric and HTTP-date Retry-After, and baseline preservation. The user's subsequent
run at `20260928T140113Z` reported AUR maintenance completed and a first snapshot.
The missing-pacutils run also cannot validate the SHA-256 path on that machine.

The large two-color title, original subtitle and author credit have been restored.
The menu states which five choices form a full scan and separates the other tools.
Interactive startup checks dependencies and offers installation. The older
screenshot's zero-file integrity success and unsupported compromise-probability
score have not been restored.

The user confirmed that Atomic Arch should remain included in full scans (menu
option 1). The module is implemented in SecCheck using documented indicators;
it does not bundle a third-party scanner script. Indicator provenance is recorded
in `docs/INDICATORS.md`.

## rkhunter interpretation and startup follow-up

The later details exposed duplicate summary/log warnings, trailing punctuation in
parsed paths, prerequisite notices counted as suspects, and a generic explanation
repeated for unrelated warnings. New fixtures reproduce those forms. Automatic
follow-ups now check exact package records and file hashes, and query SSH server
configuration/version. The tests cover changed content, changed permissions,
missing/malformed records, unowned files, read errors despite exit zero, unknown
SSH versions, failed configuration queries and strong signatures that must remain
urgent. An adversarial control-character path reproduced a possible retargeting
after display sanitization; that path is now rejected before any file lookup.
Five further regressions cover colon-containing paths, ambiguous hidden-file
separators, directory warnings and script-warning delimiters embedded in a path.
These reproduced checks against an unrelated path prefix. Unambiguous colons are
now preserved; ambiguous forms stay unresolved, and directory warnings never
trigger a regular-file verification.
An independent review also reproduced filename text being mistaken for an SSH
warning or a diagnostic notice. Message-prefix matching now prevents that
misclassification. Two regressions cover five such filenames. The review found no
other concrete important defect in these changes; native integration remains open.

PTY tests cover missing pacfile despite an available paccheck, declined and
accepted installation, failed installation, rechecking installed tools and a demo
that never triggers installation. Only the pacman/sudo command boundary and host
identity are simulated; dependency discovery and UI input are exercised directly.
Report tests preserve explained findings and check results with private permissions.

The new follow-ups still require a native run with pacutils installed. Fixture
success does not certify the user's files, packages or SSH configuration.
