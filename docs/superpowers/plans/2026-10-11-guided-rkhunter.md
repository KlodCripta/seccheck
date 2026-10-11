# Guided rkhunter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve missing initial rkhunter setup through verified, explicitly confirmed initialization, and replace the outlined title.

**Architecture:** Keep the standalone Bash program. Read the effective database directory and complete properties list from the native scan, use bounded package checks, stage and validate an initial baseline, and rerun only rkhunter. Keep original evidence and other modules intact.

**Tech Stack:** Bash 4.4+, Arch pacutils, coreutils, rkhunter, Python unittest fixtures.

**Spec:** `docs/superpowers/specs/2026-10-11-guided-rkhunter.md`

## Global Constraints

- Three security modules; no AUR module or online request.
- Separate explicit confirmation before `--propupd`.
- Local package matches do not establish trusted origin.
- Create-only installation; existing empty files are preserved to avoid replacement races.
- Preserve the configured SHA-256 command path; other methods block setup.
- No existing baseline overwrite; no suppression of unresolved evidence.
- Cold white/red title; orange/green/red assessment; narrow/ASCII support.

## Review Focus

- Native `--list propfiles` returns basenames: never treat it as full paths.
- Symlinks and alias directories on Arch require exact package link metadata and checked target contents.
- Malformed/NUL/oversized lists or baseline records must block initialization.
- Concurrent file/configuration changes must not register unchecked candidate records.
- Reruns must retain initial evidence and expose independent scanner failures.

### Task 1: Guided baseline

**Files:** `seccheck.sh`, `tests/test_baseline.py`, `docs/RKHUNTER_CONTEXT.md`, `README.md`.

**Interfaces:** `sc_offer_baseline` runs after accepted additional checks; `sc_baseline_prepare` sets state and checks; `sc_baseline_create` stages, validates and installs only after confirmation; `sc_baseline_repeat` preserves evidence and repeats rootkit checks.

- [x] Write fixture tests for refusal, checked creation, symlinks, blocking conditions, candidate changes, existing baselines, failed/interrupted reruns and evidence retention.
- [x] Run `python3 -m unittest discover -s tests -p test_baseline.py -v`; reproduce missing/incorrect behavior before fixes.
- [x] Implement the bounded initialization and localized concise explanations; no host baseline writes in development tests.
- [x] Run the targeted tests; all pass. Update documentation to distinguish read-only checks from confirmed setup.

### Task 2: Filled title and delivery

**Files:** `seccheck.sh`, `tests/test_simple_results.py`, `screenshots/*`.

**Interfaces:** `sc_brand` renders the approved title and retains existing palette/fallbacks.

- [x] Replace thin-line letters with compact filled glyphs and render the actual terminal output.
- [x] Verify widths/colors, Bash syntax, ShellCheck and the complete test suite: 198 tests passed on 11 October 2026.
- [x] Obtain an independent final code review; fix significant issues with reproducing tests.
- [ ] Commit, update the existing development branch/PR, verify CI and export a byte-identical uniquely named script. Do not merge or publish a stable release.
