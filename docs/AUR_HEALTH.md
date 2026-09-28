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
