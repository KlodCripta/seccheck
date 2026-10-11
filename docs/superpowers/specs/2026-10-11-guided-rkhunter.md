# Guided rkhunter setup and title

The approved change keeps the three security modules and the short beginner flow.
The title uses compact filled letters in a frame, SEC red and CHECK cold white;
ASCII and narrow-terminal fallbacks remain readable. No petrolio or AUR module.

After the user accepts additional checks, a missing initial rkhunter
baseline gets a guided setup. Check the full native properties list against
local package records, including Arch symlinks, before offering a separate
confirmation. Explain that a baseline records the present state; it neither
cleans the computer nor proves package origin. Refusal/EOF does not create it.

Only verified files may be registered. Generate a candidate in the private run
directory after confirmation, validate every generated record against the
checked files, then install it only if the original baseline is still absent.
Preserve existing empty files: shell-level replacement cannot atomically ensure
they have not been populated concurrently. Never overwrite an existing baseline.
Errors, limits, changed files,
unowned files and unsupported records block setup with a short explanation.
Preserve native comparison configuration; require compatible SHA-256 for setup.

Repeat rkhunter after successful setup. Preserve the original scan logs and
the results of other modules. Retain unexplained findings from the first scan;
fresh coverage must not hide scanner errors or an interrupted check. Keep
per-file explanations and the evidence needed for technical review.
