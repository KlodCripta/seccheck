# Changelog

## 2.0.0 — development

- Keep the three security checks: rkhunter, Lynis and installed package files.
- Remove the AUR maintenance module, history, online options and Python/curl
  runtime dependencies; remove the earlier Atomic Arch integration.
- Choose one language at startup and retain it through sudo.
- Reduce the main menu to full scan, individual checks and tools.
- Show a short result first; offer automatic analysis, warnings or finish.
- Investigate supported files, SSH settings and reported /dev paths without
  changing the system. Preserve strong indicators and unavailable checks.
- Separate remaining items, optional improvements and explained warnings.
  Filter whole grouped paths, retaining unresolved sibling differences.
- Explain common configuration-file purposes and recognized Lynis messages.
  Match both the test ID and its message before showing specific advice.
- Show full logs only on request; retain private original evidence and TSV reports.
- Use cold white with bold/italic hierarchy, red SEC/white CHECK, and orange/green
  indicators. Keep the large framed title with a narrow-terminal fallback.
- Remove invented infection percentages. Completed checks and finding priorities
  are independent; incomplete scans cannot be reported as clear.
- Preserve interruption handling, bounded external commands, exact-path checks,
  output sanitization, NO_COLOR and ASCII support.

Native Arch and derivative validation is required before a stable release.
