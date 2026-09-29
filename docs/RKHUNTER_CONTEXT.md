# Automatic interpretation of rkhunter warnings

SecCheck keeps the scanner's original stdout, stderr and log. Its interpretation
groups the summary and detailed forms of the same warning across both streams.
File warnings are grouped by the exact parsed path; SSH warnings by the setting.
Unknown warnings remain visible. A hidden-files summary is omitted from the
finding count when individual hidden-file details are available.
SSH and diagnostic handling require recognized message prefixes; words inside a
filename cannot select a different check or turn a file warning into a reminder.

Prerequisite warnings limit coverage. The warning about using `--propupd` is a
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
are not dismissed by this follow-up. The separate integrity module keeps its own
findings. Symlinks and nonregular files are not given a verified-content result.

Bounds: at most 40 follow-ups and 180 seconds before starting another follow-up;
one in-flight check may finish after that budget. Regular files are limited to
64 MiB. Metadata reads allow 20 seconds, hashing 5 seconds and SSH queries 10
seconds, with the existing forced-termination grace period.

## SSH checks

For `PermitRootLogin`, SecCheck reads the general configuration with `sshd -T`.
It distinguishes `yes`, `no`, key-only access and forced-command access. This does
not establish whether a daemon is listening, whether its launch options use a
different configuration, or how all connection-specific `Match` blocks behave.
Configuration advice remains separate from malware indicators.

For the old `Protocol` warning, SecCheck queries **the server** with `sshd -V`.
A recognized OpenSSH version at least 7.6 explains the obsolete protocol-1 test;
unknown versions or failed commands do not. A client version is not substituted
for the server version. No daemon is started, restarted or reconfigured.

## Display and evidence

Details show the warning's meaning, SecCheck's verification and the next action.
Explained warnings have a separate informational priority and remain in the
report. They do not increase urgent/review/suggestion counters. Pagination keeps
all findings reachable. `checks.tsv` maps verification results to the stable
finding number in `findings.tsv`; `rkh-context.*` retains supporting command output.

## References

- [pacfile manual](https://man.archlinux.org/man/pacfile.1.en)
- [pacfile upstream implementation](https://github.com/andrewgregory/pacutils/blob/master/src/pacfile.c)
- [OpenSSH server manual: -T, -V and Match contexts](https://man.openbsd.org/sshd)
- [OpenSSH 7.6 release notes: SSH version 1 removed](https://www.openssh.org/txt/release-7.6)

These describe the external interfaces used by SecCheck. Their implementation
code is not included in the module. Native pacutils/rkhunter/OpenSSH output still
needs to be checked on Arch and a derivative before a stable release.
