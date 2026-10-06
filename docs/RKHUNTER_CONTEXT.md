# Additional checks after confirmation

After the initial interactive result, **s/y** accepts the follow-up prompt. Enter,
n or EOF declines. The process already has root; it does not invoke sudo again.
Noninteractive scans do not run these follow-ups.

SecCheck keeps the scanner's original stdout, stderr and log. Its interpretation
groups the summary and detailed forms of the same warning across both streams.
File warnings are grouped by the exact parsed path; SSH warnings by the setting.
Spaces or tabs aligning the file-summary columns do not create extra warnings.
Whitespace inside an ambiguous summary path is not removed to force a match.
Unknown warnings remain visible. A hidden-files summary is omitted from the
finding count when individual hidden-file details are available.
SSH and diagnostic handling require recognized message prefixes; words inside a
filename cannot select a different check or turn a file warning into a reminder.

Prerequisite warnings limit coverage. Known indented causes, including a missing
or empty `rkhunter.dat`, are retained as specific diagnostics. The warning about using `--propupd` is a
baseline reminder, not a malware finding. SecCheck does not run `--propupd`.

## File checks

For supported script, hidden-file and file-summary warnings, SecCheck:

1. Requires an identifiable absolute path to an existing regular file. A path
   changed by display sanitization is not used for a filesystem lookup. Colons in
   filenames are preserved; repeated warning/description separators that make a
   path ambiguous prevent automatic verification. Directory warnings never
   trigger a regular-file lookup.
2. Runs `pacfile --check -- PATH` under `LC_ALL=C`, with a timeout and private logs.
3. Requires exactly one matching file record, its package owner, MTREE type,
   mode, UID/GID and a valid SHA-256. Exit zero by itself is not sufficient.
4. Independently hashes the file with `sha256sum` and compares the actual content
   with that exact record. It never executes a flagged file.

Only a matching hash with unchanged type, permissions and ownership explains the
supported warning. A timestamp difference alone does not invalidate this content
comparison. Content or relevant property changes remain open. Missing tools,
read errors, incomplete records and unsupported paths leave verification incomplete.
An unowned file is reported as such; it is not automatically classified as malware.

The result describes agreement with the **local** package database. It cannot
establish that the package source was trustworthy or that the live machine is
uncompromised. Strong rootkit signatures and rkhunter file-property/hash warnings
are not dismissed by this follow-up. The separate integrity module keeps its initial evidence; its own follow-ups are
described below. Symlinks and nonregular files are not given a verified-content result.

Bounds: at most 40 follow-ups and 180 seconds before starting another follow-up;
one in-flight check may finish after that budget. Regular files are limited to
64 MiB. Metadata reads allow 20 seconds, hashing 5 seconds and SSH queries 10
seconds, with the existing forced-termination grace period.

## SSH checks

SecCheck first checks whether the resolved SSH executable has an unresolved
file finding, including through a symlink alias. If so, it does not launch it.

For `PermitRootLogin`, SecCheck reads the general configuration with `sshd -T`.
If its only error is `sshd: no hostkeys available -- exiting.` with exit 1,
SecCheck retries once with `sshd -G`. OpenSSH added this configuration-only mode
in 9.3; it does not load private server keys. The second query has its own
10-second limit and `.config.ssh` / `.config.stderr` logs. The first attempt is
retained. Older servers without `-G`, nonzero exits, stderr or ambiguous settings
leave the warning unresolved. No server keys are generated.
It distinguishes `yes`, `no`, key-only access and forced-command access. Keyword
matching accepts both `permitrootlogin` and `PermitRootLogin` as the same setting,
while its original argument is checked unchanged.
Multiple occurrences, including different keyword capitalization, remain
ambiguous and cannot close the warning. Reading the general configuration does
not establish whether a daemon is listening, whether its launch options use a
different configuration, or how all connection-specific `Match` blocks behave.
Configuration advice remains separate from malware indicators.
After a successful `-G` retry, Details explicitly say that server keys and service
activity were not checked.
If the command fails or returns an unsupported response, regular Details show
its exit code and a sanitized excerpt of at most 320 input bytes. The complete
stdout and stderr remain in the private run directory; an excerpt never changes
the assessment to a successful check.

For the old `Protocol` warning, SecCheck queries **the server** with `sshd -V`.
A recognized OpenSSH version at least 7.6 explains the obsolete protocol-1 test;
unknown versions or failed commands do not. A client version is not substituted
for the server version. No daemon is started, restarted or reconfigured.

## Display and evidence

Details show the warning's meaning, SecCheck's verification and the next action.
The recognized Lynis `KRNL-5830` reboot warning gets a direct save/restart/recheck
action in the selected language. Its original wording and priority remain intact;
SecCheck does not reboot the computer or claim to have checked the kernel itself.
Explained warnings have a separate informational priority and remain in the
report. They do not increase urgent/review/suggestion counters. Pagination keeps
all findings reachable. `checks.tsv` maps verification results to the stable
finding number in `findings.tsv`; `rkh-context.*` retains supporting command output.

## Integrity follow-ups

Up to 80 distinct paths and 180 seconds are checked, with one in-flight operation
allowed to finish. Duplicate property warnings for one file reuse its package
comparison. The same strict regular-file checks and 64 MiB bound apply. A
matching record can explain content, permission and ownership findings; timestamp,
size, link and missing-path observations remain open. Directories/links receive a
bounded `stat` observation without following their targets or declaring their
configuration legitimate. Paths altered by display sanitization are never used.
Unsupported findings are explicitly labelled as requiring review. Lynis advice,
AUR maintenance signals and strong rootkit signatures cannot be approved by a
matching package checksum. No flagged file is executed; no file is removed,
replaced, reconfigured or used to reset a baseline.

The short result displays remaining priorities, explained findings and items that
could not be resolved automatically. Raw evidence, diagnostic causes and check
logs remain in `report.txt`, `checks.tsv` and the original files. Interrupting a
follow-up preserves the report; completing it updates the exit assessment too.

## Optional tests versus incomplete checks

Only a recognized skipped test immediately followed by its known reason is treated
as an exclusion: absent skdet, absent Tripwire data, absent inetd/xinetd configuration,
or unconfigured missing/empty log lists. The exclusion is shown in the summary and
explained in the report. It does not claim those tests ran. Unknown skip causes,
failed prerequisites and scanner errors still limit coverage.

The exact egrep forwarding notice is informational. GNU grep's stray-backslash
warnings are kept as compatibility failures: future behavior is not guaranteed.
SecCheck does not silence these messages, patch installed scanner code or run
`rkhunter --propupd`. The native scan may therefore still be incomplete until the
reported tool/configuration problems are addressed on that machine.

## References

- [rkhunter 1.4.6 source and English messages](https://sources.debian.org/src/rkhunter/1.4.6-13/files/)
- [GNU grep 3.8 compatibility notes](https://lists.gnu.org/archive/html/info-gnu/2022-09/msg00001.html)
- [pacfile manual](https://man.archlinux.org/man/pacfile.1.en)
- [pacfile upstream implementation](https://github.com/andrewgregory/pacutils/blob/master/src/pacfile.c)
- [OpenSSH server manual: -G, -T, -V and Match contexts](https://man.openbsd.org/sshd)
- [OpenSSH configuration manual: keyword and argument case](https://man.openbsd.org/sshd_config)
- [OpenSSH 9.3 release notes: configuration-only -G](https://www.openssh.org/txt/release-9.3)
- [OpenSSH 7.6 release notes: SSH version 1 removed](https://www.openssh.org/txt/release-7.6)

These describe the external interfaces used by SecCheck. Their implementation
code is not included in the module. Native pacutils/rkhunter/OpenSSH output still
needs to be checked on Arch and a derivative before a stable release.
