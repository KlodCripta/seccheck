# SecCheck 2.0 development validation

## Completed

Latest local suite: **154 tests passing**, Bash syntax checks and ShellCheck 0.11.0
clean after the native SSH keyword-case fix (6 October 2026 UTC).
The existing-root PTY integration test runs here; it is explicitly skipped when
the test account is not root. Tests use inert scanner commands in both cases.

- Regression tests exercise evidence/coverage independently, scanner boundary fixtures,
  missing tools and unknown output, removal of Atomic Arch routing, private reports,
  EN/IT CLI, real PTY language selection and narrow/ASCII output.
- AUR metadata tests cover current owner/co-owners, outdated/orphan/age/version
  signals, first baseline, observed changes, absent foreign packages, bad responses,
  interrupted writes and snapshot preservation.
- Integrity regressions cover the native pacman message forms, distinct property
  explanations, valid difference exits, missing MTREE data, read failures even with
  successful output, unsupported formats, no results, timeouts and execution errors.
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
2. **Malware fixtures stay inert.** Tests verify parsing and decision boundaries without
   obtaining/executing a live payload. No campaign-specific scanner remains.
3. **Live-system limits remain explicit.** Hidden kernel artifacts, a hostile local
   root user and filesystem races are outside the guarantee of a Bash assistant;
   a compromised system may conceal evidence.
4. **Maintainer history consists of observations.** Changes before the first scan
   or between scans cannot be reconstructed reliably. Intermediate transfers may
   go unreported.
5. **Native AUR completion was reported.** The user's later runs completed the AUR
   maintenance module, recorded its first snapshot and subsequently compared it.
   The supplied output does not establish whether a 429 retry was exercised.
   Proxy failures in
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
- acceptance, decline and interruption of follow-ups, command bounds and report permissions.

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
The menu then stated which five choices formed a full scan and separates the other tools.
Interactive startup checks dependencies and offers installation. The older
screenshot's zero-file integrity success and unsupported compromise-probability
score have not been restored.

At that point the user wanted Atomic Arch included. **This was superseded on
4 October:** the entire campaign-specific scanner and indicator document are now
removed; full scans contain four modules and menu 5 is AUR maintenance.

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

The user's run at `20260929T100329Z` followed the proposed installation of
pacutils 0.15.0-2 and reported six explained warnings. The user also confirmed the
corrected title and menu. This establishes that those paths were reached on that
machine; without their complete evidence, it does not independently certify each
file, package or SSH configuration check.

## Integrity follow-up

That run still reported partial integrity coverage. The supplied excerpt contained
pacman permission, owner/group, timestamp, size and SHA-256 differences; paccheck
stderr was empty, and its last 80 stdout lines were successful SHA-256 summaries.
The earlier stdout and exit codes were not supplied, so this excerpt cannot
establish the reason for partial coverage or prove that every file matched.

It did expose a definite interpretation bug: pacman's `SHA256 checksum mismatch`
was described as a metadata difference. It now receives the content explanation.
Permission, owner/group and timestamp changes also have distinct explanations.
No paths are automatically allowed and no reported differences are silently cleared.

Previously, unknown output and execution failures could leave only a generic
instruction to consult logs. Each now records a diagnostic with its tool, exact
message or exit code. Read failures and missing MTREE data limit coverage instead
of being presented as confirmed file changes. Actual differences with the normal
difference exit code preserve completed coverage. The pacutils source was checked
for its message forms; a read warning can coexist with success output and exit zero,
so the new tests explicitly preserve partial coverage in that case.

The independent review found that an unrecognized reason attached to a file path
still counted as a review finding. Four inert cases reproduced that behavior,
including an I/O error. Unknown reasons now remain coverage diagnostics with their
original evidence, without claiming a detected file change. The complete 126-test
suite passed after the fix. The review identified no other concrete defect in
this patch; pacman's aggregate exit behavior was not independently established
from current source and should be recorded during the native rerun.

The subsequent native run `20261004T164830Z.be65VV` reported integrity completed
with 146 findings and pacman=1/paccheck=1, AUR maintenance completed, and six
explained warnings. This confirms that normal difference exits no longer made
that integrity run incomplete. rkhunter remained incomplete with prerequisite,
regex and skipped-test diagnostics. This feedback is for `72c1fc6`, not for the
new follow-up interface or a stable release.


## Four modules and post-scan verification, 5 October 2026

The user removed Atomic Arch from scope and requested concise, beginner-facing
results plus an explicit **s/y** prompt for SecCheck to verify scanner findings.
Full scan routing, CLI rejection of the removed flags and report module counts
are covered. The AUR reminder counts only confirmed matches and triggers above
50; offline advice remains available.

Follow-up tests cover affirmative/negative/EOF input, initial deferral, real PTY
acceptance with updated private report and exit code, changed contents/permissions,
a timestamp that cannot be cleared by a matching hash, repeated-file comparison
reuse, ambiguous paths and persistent urgent/manual findings. An inert symlink
fixture confirms a flagged SSH executable is not launched for `sshd -V/-T`.

Native rkhunter source/message forms distinguish a documented optional exclusion
from an unexplained skip. Prerequisite causes, including disabled commands, missing
baseline data and commands returning no output, remain report diagnostics. Unknown
skip causes and grep regex warnings still limit coverage. No scanner is patched,
no stderr is suppressed and no `--propupd` baseline is created.

The review reproduced a misleading remaining-assessment count, missing native
prerequisite messages and execution of an SSH binary with its own unresolved
finding. Regression fixtures now cover the corrected behavior. The follow-up review found
no remaining critical or important blocker for this development-branch update.
The additional interruption fixture preserves the report and labels unfinished
checks. Native Arch and
derivative validation of this revision remains the stable-release gate.

## Grouped results after native follow-up, 5 October 2026

The user's `51f01f2` run completed the post-scan prompt. Its aggregate check
results were 113 changed-content observations, 14 metadata differences, 19
nonregular-path observations, 50 manual findings, five matching-file checks,
one modern-SSH check, one unknown SSH result and one unowned file. These are
finding counts, not unique files. The aggregate does not identify which paths
changed, why SSH failed or whether any change was intentional.

Previously the pending-assessment count included suggestions, and a file with
several properties reported by both pacman and paccheck appeared repeatedly.
The summary, priority bars and paginated details now group integrity findings
by exact absolute path. Other findings remain individual; ambiguous paths are
not merged. The highest member priority controls each displayed group. The
underlying assessment, coverage, exit statuses and all original report/TSV
observations are preserved.

Seven regression tests cover counts excluding suggestions, distinct path cards,
all property types, group-based paging, mixed priorities/check results, unchanged
private reports, ambiguous paths and specific missing-tool guidance. An eighth checks bounded, sanitized SSH
failure text in regular Details while retaining the original stderr. The full
142-test suite passed locally. This presentation change does not explain away
the user's differing files or create the missing rkhunter baseline.

A read-only review found no Critical or Important blocker. Its minor finding
about grouped warnings losing their installation advice was reproduced and fixed:
grouping now preserves specific guidance for missing tools.

## Padded warnings and missing SSH keys, 6 October 2026

The user's later details for `20261005T171900Z.oVHFcf` confirmed that grouping
reduced integrity display entries from 146 observations to 47 paths. They also
exposed generic duplicates of egrep/fgrep/ldd summary warnings, an SSH query
failing with `sshd: no hostkeys available -- exiting.`, and a Lynis `KRNL-5830`
reboot warning followed by generic ask-for-help advice.

Fixtures reproduced summary columns separated by several spaces or tabs. Those
summaries previously had no parsed path and could not merge with the detailed
warning. The separator now accepts column padding while leaving whitespace
inside an ambiguous path unresolved. The regression counts every finding,
including empty-object warnings; matching and genuinely changed files are both
covered.

The SSH fallback is limited to that exact missing-key error with exit 1. A second
`sshd -G` query can read settings without loading keys; it cannot establish that a
service is active. Both attempts are retained. Fixtures cover recognized values,
an unsupported option, stderr despite exit zero, duplicate settings, unknown
output and failed exits. Other or combined errors never trigger the fallback.
The existing flagged-executable guard remains in force. No keys are generated.

The known Lynis reboot message now has a direct bilingual save/restart/recheck
action. Its priority and original evidence remain; other IDs or wording do not
inherit this advice. The complete 152-test fixture suite passed in 53.2 seconds.
The missing rkhunter baseline and actual file differences remain unresolved.
These fixes still need the user's native rerun before stable release.

A focused read-only review found one low-severity retry-gate flaw: a truncated
SSH stderr excerpt could hide another error after many blank lines. An oversized
negative fixture reproduced the false retry. SecCheck now rejects oversized
stderr before comparing the complete short diagnostic; that fixture passes.
The reviewer found no other issue in the padded-warning or Lynis changes.

## Native SSH keyword case, 6 October 2026

The first details page for `20261006T195715Z.vNLBGF` confirms that the padded
rkhunter duplicates no longer appear and the Lynis reboot action is displayed.
Integrity still shows 47 grouped paths. The follow-ups finish with six explained
findings and 52 review entries; the rkhunter baseline is still missing or empty.

The configuration-only SSH retry now runs successfully (exit 0), but its output
uses canonical keyword case: `PermitRootLogin`, alongside `Port`, `AddressFamily`
and `UsePAM`. The parser expected only lowercase, so it left a readable setting
unknown. The displayed value is truncated in the 320-byte excerpt, so it does not
establish the complete setting or service activity on that machine.

Two new regressions reproduce canonical, uppercase and mixed-case keywords in
both query modes, with each supported policy. Mixed-case duplicate settings must
remain unknown, and unsupported or uppercase argument values are not normalized
into a successful result. The implementation only folds the keyword comparison;
original arguments and command logs remain unchanged. The native result for this
latest parser fix still needs a rerun.

All 154 fixture tests passed in 55.2 seconds. A focused read-only review approved
the development change with no confirmed issue; its focused checks cover both
SSH query modes, case variants, duplicate keys and invalid arguments.
