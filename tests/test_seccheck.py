"""Behavioral tests. Fixtures are inert; scanners are replaced only at command boundaries."""
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "seccheck.sh"


class SecCheckCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="seccheck-test-")
        self.addCleanup(self.temp.cleanup)
        self.folder = pathlib.Path(self.temp.name)

    def shell(self, body, **extra_env):
        env = dict(os.environ, SC_TEST_DIR=str(self.folder), NO_COLOR="1", **extra_env)
        result = subprocess.run(["bash", "-c", 'source "$1"\n' + body, "test", str(SCRIPT)],
                                text=True, capture_output=True, env=env, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(result.stderr, "", result.stderr)
        return result.stdout.strip()

    def command(self, name, body):
        bindir = self.folder / "bin"
        bindir.mkdir(exist_ok=True)
        executable = bindir / name
        executable.write_text("#!/usr/bin/env bash\n" + body)
        executable.chmod(0o755)
        return str(bindir) + os.pathsep + os.environ["PATH"]

    def fixture(self, name, content):
        (self.folder / name).write_text(content)


class AdapterTests(SecCheckCase):
    def rkhunter_outputs(self, detailed, standard):
        self.fixture('detailed', detailed)
        self.fixture('standard', standard)
        path = self.command('rkhunter', '[[ "$1" == --version ]] && { echo 1.4.6; exit; }\n'
                            'while (($#)); do if [[ "$1" == --logfile ]]; then cp "$SC_TEST_DIR/detailed" "$2"; shift; fi; shift; done\n'
                            'cat "$SC_TEST_DIR/standard"\n')
        return self.shell('sc_reset rkhunter; SC_RUN_DIR="$SC_TEST_DIR"\n'
                          'sc_run_rkhunter; sc_assess\n'
                          'printf "%s|%s|%s" "${SC_MODULE_STATUS[rkhunter]}" "$SC_ASSESSMENT" "$SC_URGENT"', PATH=path)

    def test_rkhunter_stdout_does_not_erase_skipped_checks_from_log(self):
        out = self.rkhunter_outputs('Checking optional test [ Skipped ]\nSystem checks summary\n',
                                   'System checks summary\n')
        self.assertEqual(out, 'partial|unknown|0')

    def test_rkhunter_stronger_stdout_finding_survives_weaker_log_finding(self):
        out = self.rkhunter_outputs('Warning: Hash value changed: /usr/bin/example\nSystem checks summary\n',
                                   'Warning: Possible rootkit detected\nSystem checks summary\n')
        self.assertEqual(out, 'completed|urgent|1')

    def test_rkhunter_failure_without_output_is_failed(self):
        path = self.command("rkhunter", '[[ "$1" == --version ]] && { echo 1.4.6; exit; }; exit 2\n')
        out = self.shell('sc_reset rkhunter\nSC_RUN_DIR="$SC_TEST_DIR"\nsc_run_rkhunter\n'
                         'sc_assess\nprintf "%s|%s" "${SC_MODULE_STATUS[rkhunter]}" "$SC_ASSESSMENT"', PATH=path)
        self.assertEqual(out, "failed|unknown")

    def test_rkhunter_signature_not_downgraded_by_clean_summary(self):
        self.fixture("rkh.log", "[12:00:00] Warning: Possible rootkit detected\n[12:00:01] System checks summary\n")
        out = self.shell('sc_reset rkhunter\nsc_parse_rkhunter "$SC_TEST_DIR/rkh.log"\n'
                         'sc_assess\nprintf "%s|%s" "$SC_ASSESSMENT" "$SC_URGENT"')
        self.assertEqual(out, "urgent|1")

    def test_rkhunter_indented_bracket_warning_is_not_discarded(self):
        self.fixture("rkh.log", "  Checking for hidden files and directories [ Warning ]\n")
        out = self.shell('sc_reset rkhunter\nsc_parse_rkhunter "$SC_TEST_DIR/rkh.log"\n'
                         'printf "%s" "${#SC_F_MODULE[@]}"')
        self.assertEqual(out, "1")

    def test_rkhunter_missing_completion_stays_partial(self):
        path = self.command("rkhunter", 'echo "Warning: Hidden file found: /tmp/.sample"; exit 1\n')
        out = self.shell('sc_reset rkhunter\nSC_RUN_DIR="$SC_TEST_DIR"\nsc_run_rkhunter\n'
                         'printf "%s" "${SC_MODULE_STATUS[rkhunter]}"', PATH=path)
        self.assertEqual(out, "partial")

    def test_rkhunter_skips_and_grep_compatibility_are_visible_in_summary(self):
        path = self.command('rkhunter', '[[ "$1" == --version ]] && { echo 1.4.6; exit; }\n'
                            'echo "    Running skdet command [ Skipped ]"\n'
                            'echo "    Checking for enabled xinetd services [ Skipped ]"\n'
                            'echo "    Checking for software intrusions [ Skipped ]"\n'
                            'echo "    Checking for enabled inetd services [ Skipped ]"\n'
                            'echo "    Checking for missing log files [ Skipped ]"\n'
                            'echo "    Checking for empty log files [ Skipped ]"\n'
                            'echo "System checks summary"\n'
                            'echo "egrep: warning: egrep is obsolescent; using grep -E" >&2\n'
                            'echo "grep: warning: stray \\ before +" >&2\n')
        out = self.shell('sc_reset rkhunter; SC_RUN_DIR="$SC_TEST_DIR"; SC_LANG=en\n'
                         'sc_run_rkhunter; sc_assess; SC_NO_COLOR=1; sc_ui_init; sc_render_summary\n'
                         'printf "\\n%s|%s" "${SC_MODULE_STATUS[rkhunter]}" "${#SC_F_MODULE[@]}"', PATH=path)
        self.assertIn('skdet', out)
        self.assertIn('xinetd', out)
        self.assertIn('stray', out)
        self.assertIn('compatibility', out)
        self.assertTrue(out.endswith('partial|0'), out)

    def test_egrep_deprecation_alone_does_not_discard_completed_rkhunter_coverage(self):
        path = self.command('rkhunter', '[[ "$1" == --version ]] && { echo 1.4.6; exit; }\n'
                            'echo "System checks summary"\n'
                            'echo "egrep: warning: egrep is obsolescent; using grep -E" >&2\n')
        out = self.shell('sc_reset rkhunter; SC_RUN_DIR="$SC_TEST_DIR"\n'
                         'sc_run_rkhunter; printf "%s" "${SC_MODULE_STATUS[rkhunter]}"', PATH=path)
        self.assertEqual(out, 'completed')

    def test_unknown_rkhunter_stderr_stays_partial_and_is_explained(self):
        path = self.command('rkhunter', '[[ "$1" == --version ]] && { echo 1.4.6; exit; }\n'
                            'echo "System checks summary"\n'
                            'echo "grep: /private/example: Permission denied" >&2\n')
        out = self.shell('sc_reset rkhunter; SC_RUN_DIR="$SC_TEST_DIR"; SC_LANG=en\n'
                         'sc_run_rkhunter; sc_assess; SC_NO_COLOR=1; sc_ui_init; sc_render_summary\n'
                         'printf "\\n%s" "${SC_MODULE_STATUS[rkhunter]}"', PATH=path)
        self.assertIn('Permission denied', out)
        self.assertTrue(out.endswith('partial'), out)

    def test_lynis_structured_report_preserves_full_warning(self):
        self.fixture("lynis.dat", "report_version_major=1\nlynis_version=3.1.7\nreport_datetime_start=start\n"
                     "warning[]=AUTH-9262|Password hash rounds are not configured|details||\n"
                     "suggestion[]=SSH-7408|Consider hardening SSH configuration|||\nreport_datetime_end=end\n")
        out = self.shell('sc_reset lynis\nsc_parse_lynis "$SC_TEST_DIR/lynis.dat"\n'
                         'sc_assess\nprintf "%s|%s|%s" "$SC_REVIEW" "$SC_SUGGESTIONS" "${SC_F_OBJECT[0]}"')
        self.assertEqual(out, "1|1|AUTH-9262")

    def test_lynis_actual_adapter_requires_fresh_complete_report(self):
        path = self.command("lynis", '[[ "$1" == --version ]] && { echo 3.1.7; exit; }; exit 0\n')
        out = self.shell('sc_reset lynis\nSC_RUN_DIR="$SC_TEST_DIR"\nsc_run_lynis\n'
                         'printf "%s" "${SC_MODULE_STATUS[lynis]}"', PATH=path)
        self.assertEqual(out, "failed")

    def test_changed_executable_remains_a_review_finding(self):
        self.fixture("pacman.txt", "warning: demo: /usr/bin/demo (Size mismatch)\ndemo: 100 total files, 1 altered file\n")
        out = self.shell('sc_reset integrity\nsc_parse_integrity "$SC_TEST_DIR/pacman.txt" pacman\n'
                         'sc_assess\nprintf "%s|%s|%s" "$SC_ASSESSMENT" "${SC_F_OBJECT[0]}" "${SC_F_KEY[0]}"')
        self.assertEqual(out, "review|/usr/bin/demo|integrity_metadata")

    def test_missing_file_is_retained_even_when_it_does_not_exist(self):
        self.fixture("pacman.txt", "warning: demo: /usr/bin/nonexistent-seccheck-test (No such file or directory)\n")
        out = self.shell('sc_reset integrity\nsc_parse_integrity "$SC_TEST_DIR/pacman.txt" pacman\n'
                         'printf "%s" "${SC_F_KEY[0]}"')
        self.assertEqual(out, "integrity_missing")

    def test_paccheck_hash_mismatch_with_spaces_is_parsed(self):
        self.fixture("sha.txt", "demo: '/usr/share/a file' sha256sum mismatch (expected abcd)\n")
        out = self.shell('sc_reset integrity\nsc_parse_integrity "$SC_TEST_DIR/sha.txt" paccheck\n'
                         'printf "%s|%s" "${SC_F_OBJECT[0]}" "${SC_F_KEY[0]}"')
        self.assertEqual(out, "/usr/share/a file|integrity_content")

    def test_read_errors_even_with_zero_exit_make_integrity_partial(self):
        path = self.command("pacman", 'echo "demo: 100 total files, 0 altered files"\n')
        self.command("paccheck", 'echo "warning: demo: read error (Permission denied)" >&2; exit 0\n')
        out = self.shell('sc_reset integrity\nSC_RUN_DIR="$SC_TEST_DIR"\nsc_run_integrity\n'
                         'printf "%s" "${SC_MODULE_STATUS[integrity]}"', PATH=path)
        self.assertEqual(out, "partial")

    def test_full_integrity_success_closes_paccheck_stdin(self):
        path = self.command("pacman", 'echo "demo: 100 total files, 0 altered files"\n')
        self.command("paccheck", '[[ -e /proc/$$/fd/0 ]] && { echo "stdin was not closed" >&2; exit 2; }; '
                     'echo "demo: all files match mtree sha256sums"\n')
        out = self.shell('sc_reset integrity\nSC_RUN_DIR="$SC_TEST_DIR"\nsc_run_integrity\n'
                         'printf "%s" "${SC_MODULE_STATUS[integrity]}"', PATH=path)
        self.assertEqual(out, "completed")

    def test_unknown_integrity_format_cannot_mean_success(self):
        path = self.command("pacman", 'echo "A future output format"\n')
        self.command("paccheck", 'echo "demo: all files match mtree sha256sums"\n')
        out = self.shell('sc_reset integrity\nSC_RUN_DIR="$SC_TEST_DIR"\nsc_run_integrity\n'
                         'printf "%s" "${SC_MODULE_STATUS[integrity]}"', PATH=path)
        self.assertEqual(out, "partial")


class AurTests(SecCheckCase):
    def test_depth_limit_does_not_silently_claim_complete_coverage(self):
        root = self.folder / 'cache'
        deep = root.joinpath(*(['nested']*12))
        deep.mkdir(parents=True)
        (deep / 'PKGBUILD').write_text('npm install atomic-lockfile\n')
        out = self.shell('sc_reset aur; sc_aur_init; SC_RUN_DIR="$SC_TEST_DIR"\n'
                         'sc_scan_aur_root "$SC_TEST_DIR/cache" cache\n'
                         'printf "%s" "$SC_AUR_PARTIAL"')
        self.assertEqual(out, '1')

    def test_real_traversal_finds_pacman_install_script_with_spaces(self):
        package = self.folder / 'package with spaces'
        package.mkdir()
        (package / 'install').write_text('npm install atomic-lockfile\n')
        out = self.shell('sc_reset aur; sc_aur_init\nSC_RUN_DIR="$SC_TEST_DIR"\n'
                         'sc_scan_aur_root "$SC_TEST_DIR/package with spaces" cache\n'
                         'printf "%s|%s|%s" "$SC_AUR_COUNT" "$SC_AUR_PARTIAL" "${SC_F_KEY[0]-}"')
        self.assertEqual(out, '1|0|aur_reference')

    def test_custom_home_service_is_inspected(self):
        self.fixture('sample.service', '[Service]\nExecStart=/srv/alice/.cache/helper\nRestart=always\nRestartSec=30\n')
        out = self.shell('sc_reset aur; sc_aur_init\nSC_AUR_HOMES=(/srv/alice)\n'
                         'sc_inspect_aur_file "$SC_TEST_DIR/sample.service" startup\n'
                         'printf "%s" "${SC_F_KEY[0]-}"')
        self.assertEqual(out, 'aur_service')

    def test_untrusted_history_fifo_is_not_opened(self):
        os.mkfifo(self.folder / 'history')
        out = self.shell('sc_reset aur; sc_aur_init\nsc_parse_aur_history "$SC_TEST_DIR/history"\n'
                         'printf "%s" "$SC_AUR_PARTIAL"')
        self.assertEqual(out, '1')

    def test_pkgbuild_is_read_never_executed(self):
        self.fixture("PKGBUILD", 'touch "$SC_TEST_DIR/EXECUTED"\nnpm install atomic-lockfile minimist\n')
        out = self.shell('sc_reset aur\nsc_aur_init\nsc_inspect_aur_file "$SC_TEST_DIR/PKGBUILD" cache\n'
                         'printf "%s|%s" "${SC_F_KEY[0]}" "${SC_F_PRIORITY[0]}"')
        self.assertEqual(out, "aur_reference|review")
        self.assertFalse((self.folder / "EXECUTED").exists())

    def test_similar_benign_name_does_not_match(self):
        self.fixture("package.json", '{"name":"my-atomic-lockfile-wrapper"}\n')
        out = self.shell('sc_reset aur\nsc_aur_init\nsc_inspect_aur_file "$SC_TEST_DIR/package.json" cache\n'
                         'printf "%s" "${#SC_F_MODULE[@]}"')
        self.assertEqual(out, "0")

    def test_manifest_reference_is_not_claimed_as_execution(self):
        self.fixture("package.json", '{"name":"atomic-lockfile","version":"1.4.2","scripts":{"preinstall":"./src/hooks/deps"}}\n')
        out = self.shell('sc_reset aur\nsc_aur_init\nsc_inspect_aur_file "$SC_TEST_DIR/package.json" cache\n'
                         'printf "%s|%s" "${SC_F_KEY[0]}" "${SC_F_CONFIDENCE[0]}"')
        self.assertEqual(out, "aur_reference|observation")

    def test_known_hash_reports_presence_without_executing_file(self):
        self.fixture("deps", "inert fixture")
        path = self.command("sha256sum", 'printf "%s  %s\\n" 6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b "$2"\n')
        out = self.shell('sc_reset aur\nsc_aur_init\nsc_check_known_file "$SC_TEST_DIR/deps"\n'
                         'printf "%s|%s" "${SC_F_KEY[0]}" "${SC_F_PRIORITY[0]}"', PATH=path)
        self.assertEqual(out, "aur_hash|urgent")

    def test_benign_file_real_sha256_does_not_match(self):
        self.fixture("deps", "benign sample\n")
        out = self.shell('sc_reset aur\nsc_aur_init\nsc_check_known_file "$SC_TEST_DIR/deps"\n'
                         'printf "%s" "${#SC_F_MODULE[@]}"')
        self.assertEqual(out, "0")

    def test_symlinks_are_not_followed(self):
        self.fixture("target", "npm install atomic-lockfile\n")
        (self.folder / "PKGBUILD").symlink_to(self.folder / "target")
        out = self.shell('sc_reset aur\nsc_aur_init\nsc_inspect_aur_file "$SC_TEST_DIR/PKGBUILD" cache\n'
                         'printf "%s|%s" "${#SC_F_MODULE[@]}" "$SC_AUR_PARTIAL"')
        self.assertEqual(out, "0|1")

    def test_file_limit_is_reported_as_partial(self):
        (self.folder / "a").mkdir()
        (self.folder / "b").mkdir()
        self.fixture("a/PKGBUILD", "pkgname=a\n")
        self.fixture("b/PKGBUILD", "pkgname=b\n")
        out = self.shell('sc_reset aur\nsc_aur_init\nSC_RUN_DIR="$SC_TEST_DIR"\nSC_AUR_MAX_FILES=1\n'
                         'sc_scan_aur_root "$SC_TEST_DIR" cache\nprintf "%s" "$SC_AUR_PARTIAL"')
        self.assertEqual(out, "1")

    def test_local_user_homes_include_custom_locations(self):
        self.fixture("passwd", "root:x:0:0:root:/root:/bin/bash\nklod:x:1000:1000::/data/klod:/bin/bash\nnobody:x:65534:65534::/nonexistent:/usr/bin/nologin\n")
        out = self.shell('sc_reset aur\nsc_aur_init\nsc_collect_homes "$SC_TEST_DIR/passwd"\n'
                         'printf "%s\\n" "${SC_AUR_HOMES[@]}"')
        self.assertEqual(out.splitlines(), ["/root", "/data/klod"])

    def test_persistence_pattern_is_not_based_on_restart_alone(self):
        self.fixture("normal.service", "[Service]\nExecStart=/usr/bin/normal\nRestart=always\nRestartSec=30\n")
        out = self.shell('sc_reset aur\nsc_aur_init\nsc_inspect_aur_file "$SC_TEST_DIR/normal.service" startup\n'
                         'printf "%s" "${#SC_F_MODULE[@]}"')
        self.assertEqual(out, "0")

    def test_suspicious_persistence_combination_is_preserved(self):
        self.fixture("unknown.service", "[Service]\nExecStart=/var/lib/unknown/worker\nRestart=always\nRestartSec=30\n")
        out = self.shell('sc_reset aur\nsc_aur_init\nsc_inspect_aur_file "$SC_TEST_DIR/unknown.service" startup\n'
                         'printf "%s" "${SC_F_KEY[0]}"')
        self.assertEqual(out, "aur_service")


class EvidenceTests(SecCheckCase):
    def test_failed_empty_modules_are_incomplete(self):
        out = self.shell('sc_reset "rkhunter lynis integrity aur"\n'
                         'for m in "${SC_SELECTED[@]}"; do sc_module_set "$m" failed command_failed; done\n'
                         'sc_assess\nprintf "%s|%s" "$SC_INCOMPLETE" "$SC_ASSESSMENT"')
        self.assertEqual(out, "1|unknown")

    def test_unresolved_signature_survives_successful_integrity(self):
        out = self.shell('sc_reset "rkhunter integrity"\n'
                         'sc_module_set rkhunter completed ""\nsc_module_set integrity completed ""\n'
                         'sc_add_finding rkhunter suspicious urgent unconfirmed "" rkh_signature "Possible rootkit"\n'
                         'sc_assess\nprintf "%s|%s" "$SC_ASSESSMENT" "$SC_URGENT"')
        self.assertEqual(out, "urgent|1")

    def test_hardening_does_not_promote_an_unrelated_file(self):
        out = self.shell('sc_reset "integrity lynis"\n'
                         'sc_module_set integrity completed ""\nsc_module_set lynis completed ""\n'
                         'sc_add_finding integrity integrity review observation /usr/bin/demo integrity_content changed\n'
                         'sc_add_finding lynis hardening suggestion observation AUTH-001 lynis_suggestion advice\n'
                         'sc_assess\nprintf "%s|%s|%s" "$SC_ASSESSMENT" "$SC_REVIEW" "$SC_SUGGESTIONS"')
        self.assertEqual(out, "review|1|1")

    def test_only_selected_modules_count_for_coverage(self):
        out = self.shell('sc_reset "lynis"\nsc_module_set lynis completed ""\nsc_assess\n'
                         'printf "%s|%s|%s" "$SC_INCOMPLETE" "$SC_COMPLETED" "${SC_MODULE_STATUS[aur]}"')
        self.assertEqual(out, "0|1|not-run")

    def test_partial_scan_keeps_urgent_findings(self):
        out = self.shell('sc_reset "aur"\nsc_module_set aur partial unreadable\n'
                         'sc_add_finding aur suspicious urgent match "/a b/deps" aur_hash digest\n'
                         'sc_assess\nprintf "%s|%s" "$SC_INCOMPLETE" "$SC_ASSESSMENT"')
        self.assertEqual(out, "1|urgent")

    def test_identical_evidence_is_deduplicated(self):
        out = self.shell('sc_reset "integrity"\n'
                         'for i in 1 2; do sc_add_finding integrity integrity review observation /usr/bin/demo integrity_content changed; done\n'
                         'printf "%s" "${#SC_F_MODULE[@]}"')
        self.assertEqual(out, "1")

    def test_different_evidence_on_same_file_is_retained(self):
        out = self.shell('sc_reset "integrity"\n'
                         'sc_add_finding integrity integrity review observation /usr/bin/demo integrity_content "size mismatch"\n'
                         'sc_add_finding integrity integrity review observation /usr/bin/demo integrity_content "sha256sum mismatch"\n'
                         'printf "%s" "${#SC_F_MODULE[@]}"')
        self.assertEqual(out, "2")

    def test_control_sequences_are_neutralized(self):
        out = self.shell("sc_text $'evil\\e[31m\\nline\\tX\\rY'")
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\t", out)
        self.assertNotIn("\n", out)
        self.assertNotIn("\r", out)

    def test_source_has_no_traps_or_shell_option_side_effects(self):
        result = subprocess.run(["bash", "-c", 'before=$-; source "$1"; [[ "$before" == "$-" ]] && [[ -z "$(trap -p EXIT)" ]]',
                                 "test", str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_reset_clears_prior_scan_findings(self):
        out = self.shell('sc_reset aur\nsc_add_finding aur suspicious urgent match /x aur_hash x\n'
                         'sc_reset lynis\nprintf "%s|%s" "${#SC_F_MODULE[@]}" "${SC_SELECTED[*]}"')
        self.assertEqual(out, "0|lynis")


if __name__ == "__main__":
    unittest.main()
