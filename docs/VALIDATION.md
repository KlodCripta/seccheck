# SecCheck 2.0 development validation

## Completed

Latest local suite: **77 tests passing**, Bash syntax checks and ShellCheck 0.11.0
clean after the first native-feedback corrections (28 September 2026).

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
5. **Online integration needs a native check.** Public AUR RPC/page samples were
   fetched, but the full module's live trial hit this environment's proxy CONNECT
   timeout and correctly preserved partial coverage and the baseline. Successful
   live querying on the target machine remains to be verified.
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

The underlying cause of the user's three HTTP requests is still unconfirmed:
the supplied excerpt does not contain the individual curl stderr. A native retry
or the retained `aur-page.*.stderr` is needed to distinguish HTTP errors, timeouts,
DNS and TLS problems. No retry policy or network diagnosis is inferred from counts.
The missing-pacutils run also cannot validate the SHA-256 path on that machine.

The user requested restoring the earlier version's clearer section separation,
use of several semantic colors and educational explanations. That interface work
is explicitly scheduled after functional corrections; this patch does not replace
that work. The older screenshot's zero-file integrity success and unsupported
compromise-probability score must not be restored.
