# AUR metadata sources and interpretation

Checked 28 September 2026 (Europe/Rome).

- [Official RPC documentation](https://wiki.archlinux.org/title/Aurweb_RPC_interface)
  and [OpenAPI UI](https://aur.archlinux.org/rpc/swagger).
- [Official aurweb implementation](https://gitlab.archlinux.org/archlinux/aurweb/-/blob/bd0965edd2c568b48c796e1f5d9f1ad5a05ef805/aurweb/rpc.py):
  `get_json_data`, `get_info_json_data`, `subquery` and `_handle_multiinfo_type`.
  Fields include `Maintainer`, `OutOfDate`, `LastModified`, `Version`, `PackageBase`
  and, when returned, `CoMaintainers`.
- [Official package-page template](https://gitlab.archlinux.org/archlinux/aurweb/-/blob/bd0965edd2c568b48c796e1f5d9f1ad5a05ef805/templates/partials/packages/details.html):
  the public `tr.pkgmaint` row displays the primary maintainer and optional
  parenthesized co-maintainer names without requiring an account.
- [ArchWiki AUR guidance](https://wiki.archlinux.org/title/Arch_User_Repository)
  and [submission/maintenance guidance](https://wiki.archlinux.org/title/AUR_submission_guidelines).

The implementation was checked against a live public `yay` RPC response and package
page. In that response `CoMaintainers` was absent, so omission cannot simply be treated
as an empty list. The fallback requires exactly one expected maintainer row and
agreement with the RPC primary maintainer. A challenge/error page means unknown.
No upstream implementation code was copied into SecCheck.

`LastModified` concerns the AUR recipe, not the upstream project's last release,
commit or response to a support request. **365 days is SecCheck's explanatory
review threshold**, not an AUR declaration of abandonment. `OutOfDate` is a user
flag, not a checked vulnerability. Main/co-maintainer changes are observations,
not allegations about a person's intentions.

Snapshots describe observations at scan times. They are not an authoritative
event log, cannot reveal transitions between two scans, and cannot prove who
maintained the exact installed build. First-seen packages establish comparison
data. Reinstalling SecCheck on a machine without its private history starts a
new comparison history. A local root attacker could tamper with that history.

Each HTTP request keeps its own `aur-rpc.N` or `aur-page.N` files: `.request.txt`
identifies the URL, `.raw` stores the bounded response and `.stderr` stores curl's
diagnostic output. `.headers` stores the HTTP response headers. Page numbering
counts attempts, including failures, so a later request cannot overwrite an earlier
failed request's evidence. The summary gives
the curl exit code, original error and log filename with an EN/IT explanation.
`aur-health-diagnostics.tsv` contains these diagnostics separately from findings.

A partial first scan does not create a baseline. A partial later scan preserves
the previous complete snapshot. The interface now states which situation applies.
An HTTP/connection failure is never interpreted as a removed package or maintainer.

Requests start at least 1.1 seconds apart within a scan. This is SecCheck's pacing
policy, not a claim about AUR's current server-side limit. After HTTP 429, SecCheck
honors `Retry-After` seconds or an HTTP date, with a five-second minimum/fallback.
It retries the same URL once, preserving that attempt as `.retry1.*`. A second 429,
a delay longer than 30 seconds, or insufficient remaining scan time stops all
further AUR requests in that run. A long server delay is never shortened to force a
retry. Local processing of metadata already obtained can still finish, but the
module remains partial and the previous baseline is preserved.

The 260-second online budget includes pauses and retries. Large inventories can
reach this limit; the report states that remaining requests were stopped. Split
packages reuse a successfully retrieved page for their package base within the run.

## Scope update, 4 October 2026

AUR maintenance is the fourth module in a full scan and menu option 5. The separate
campaign-specific scanner has been removed. The source checks above, observation
history and failure handling remain the same.

The result includes an EN/IT reminder to install only needed packages, review
PKGBUILD and .install instructions and changes, and check source locations. This
follows the [ArchWiki AUR guidance](https://wiki.archlinux.org/title/Arch_User_Repository).
SecCheck does not audit those scripts or infer safety from active maintenance.

More than 50 confirmed installed AUR matches adds a suggestion to review the
inventory. This is an explicitly labelled SecCheck reminder, not a proven security
threshold. Only packages found in validated RPC responses count; absent foreign
packages do not. A partial query may still trigger the reminder if it has already
confirmed more than 50 matches, while coverage and baseline handling remain partial.
