"""Native /dev warnings retain exact paths and receive read-only observations."""
import os
import mmap
import pathlib
import shutil
import subprocess
import tempfile

from test_seccheck import SecCheckCase


class DevFollowupTests(SecCheckCase):
    def parse(self, lines, followups=False, **env):
        self.fixture('rkh-dev.log', lines)
        return self.shell(
            'sc_reset rkhunter; SC_RUN_DIR="$SC_TEST_DIR"; SC_LANG=it; sc_ui_init\n'
            'sc_parse_rkhunter "$SC_TEST_DIR/rkh-dev.log"\n'
            'sc_module_set rkhunter completed\n'
            + ('sc_run_followups >/dev/null\n' if followups else '')
            + 'for i in "${!SC_F_KEY[@]}"; do\n'
            'printf "ROW|%s|%s|%s|%s\\n" "${SC_F_PRIORITY[i]}" "${SC_F_KEY[i]}" '
            '"${SC_F_OBJECT[i]}" "${SC_F_CHECK_KEY[i]}"\ndone\n'
            'printf "UNKNOWN|%s\\n" "$SC_PARSE_UNKNOWN"\n'
            'sc_render_details\n', **env)

    def runtime_file(self):
        if not os.access('/dev/shm', os.W_OK):
            self.skipTest('a writable shared-memory test directory is unavailable')
        folder = tempfile.TemporaryDirectory(prefix='seccheck-test-', dir='/dev/shm')
        self.addCleanup(folder.cleanup)
        sample = pathlib.Path(folder.name) / 'data'
        sample.write_text('inert runtime data\n')
        sample.chmod(0o640)
        return sample

    @staticmethod
    def warning(path):
        return ('[22:11:38] Checking /dev for suspicious file types [ Warning ]\n'
                '[22:11:38] Warning: Suspicious file types found in /dev:\n'
                f'[22:11:38]         {path}: data\n'
                '[22:11:38] Checking for hidden files and directories [ OK ]\n')

    def test_native_list_retains_both_indented_paths(self):
        out = self.parse(self.warning('/dev/shm/lsp-catalog-klod.shm').replace(
            '[22:11:38] Checking for hidden',
            '[22:11:38]         /dev/shm/lsp-catalog-klod.lock: data\n'
            '[22:11:38] Checking for hidden'))
        self.assertIn('review|rkh_dev_file|/dev/shm/lsp-catalog-klod.shm|', out)
        self.assertIn('review|rkh_dev_file|/dev/shm/lsp-catalog-klod.lock|', out)

    def test_path_outside_the_native_list_is_not_taken_as_a_dev_finding(self):
        out = self.parse('/dev/shm/unrelated: data\n')
        self.assertNotIn('ROW|', out)

    def test_list_ends_at_the_next_test(self):
        out = self.parse(self.warning('/dev/shm/listed') + '/dev/shm/unrelated: data\n')
        self.assertIn('|/dev/shm/listed|', out)
        self.assertNotIn('|/dev/shm/unrelated|', out)

    def test_unreadable_or_outside_dev_paths_never_authorize_a_lookup(self):
        for path in ('/dev/shm/prefix: misleading', '/dev/shm/name\tother', '/etc/passwd'):
            with self.subTest(path=path):
                out = self.parse(self.warning(path))
                self.assertIn('review|rkh_path_unreadable||', out)
                self.assertIn('UNKNOWN|1', out)

    def test_nul_in_a_native_path_is_rejected_before_bash_can_remove_it(self):
        out = self.parse(self.warning('/dev/shm/name\x00other'))
        self.assertIn('review|rkh_path_unreadable||', out)
        self.assertIn('UNKNOWN|1', out)
        self.assertNotIn('|/dev/shm/nameother|', out)

    def test_shell_metacharacters_and_spaces_are_preserved(self):
        out = self.parse(self.warning('/dev/shm/$(touch EXECUTED) with space'))
        self.assertIn('|/dev/shm/$(touch EXECUTED) with space|', out)
        self.assertFalse((self.folder / 'EXECUTED').exists())

    def test_metadata_and_reported_process_are_visible_without_clearing_warning(self):
        sample = self.runtime_file()
        path = self.command('fuser', '''[[ $1 == -v && $2 == /dev/* && $# == 2 ]] || exit 2
printf '%s\n' "$2" > "$SC_TEST_DIR/fuser-called"
printf ' 12345\n'
printf 'observed access\n' >&2
''')
        self.command('ps', "printf ' 12345 1000 audio-player\\n'\n")
        self.command('readlink', "[[ $1 == -n && $2 == -- ]] || exit 2\nprintf '/usr/bin/audio-player'\n")
        self.command('pacman', "[[ $1 == -Qqo && $2 == -- ]] || exit 2\necho audio-package\n")
        out = self.parse(self.warning(sample), followups=True, PATH=path)
        self.assertIn(f'review|rkh_dev_file|{sample}|rkh_dev_process', out)
        self.assertNotIn('review|rkh_dev|/dev|', out)
        self.assertIn('audio-player', out)
        self.assertIn('audio-package', out)
        self.assertIn('640', out)
        self.assertEqual((self.folder / 'fuser-called').read_text().strip(), str(sample))
        checks = (self.folder / 'checks.tsv').read_text()
        self.assertIn('rkh_dev_process', checks)
        self.assertTrue(any(self.folder.glob('rkh-context.*.fuser')))

    def test_no_process_is_an_observation_not_a_clean_verdict(self):
        sample = self.runtime_file()
        path = self.command('fuser', 'exit 1\n')
        out = self.parse(self.warning(sample), followups=True, PATH=path)
        self.assertIn(f'review|rkh_dev_file|{sample}|rkh_dev_idle', out)
        self.assertNotIn('info|', out)

    def test_empty_regular_runtime_file_is_still_checked(self):
        sample = self.runtime_file()
        sample.write_text('')
        path = self.command('fuser', 'exit 1\n')
        out = self.parse(self.warning(sample), followups=True, PATH=path)
        self.assertIn('|rkh_dev_idle', out)

    def test_process_identity_has_a_bound_and_preserves_full_pid_log(self):
        sample = self.runtime_file()
        path = self.command('fuser', "echo '12345 12346 12347 12348'\n")
        self.command('ps', '''echo "$2" >> "$SC_TEST_DIR/ps-called"
printf ' %s 1000 audio-player\n' "$2"
''')
        self.command('readlink', 'exit 1\n')
        out = self.parse(self.warning(sample), followups=True, PATH=path)
        self.assertIn('|rkh_dev_process', out)
        self.assertIn('altri processi', out)
        self.assertEqual((self.folder / 'ps-called').read_text().splitlines(),
                         ['12345', '12346', '12347'])
        self.assertIn('12348', next(self.folder.glob('rkh-context.*.fuser')).read_text())

    def test_disappearing_process_identity_does_not_claim_a_known_program(self):
        sample = self.runtime_file()
        path = self.command('fuser', "echo '12345'\n")
        self.command('ps', 'exit 1\n')
        out = self.parse(self.warning(sample), followups=True, PATH=path)
        self.assertIn('PID 12345: identita non disponibile',
                      ' '.join(out.replace('à', 'a').split()))
        self.assertNotIn('info|', out)

    def test_dev_details_from_both_streams_become_one_check_per_exact_path(self):
        sample = self.runtime_file()
        self.fixture('rkh-dev.log', self.warning(sample))
        path = self.command('fuser', '''echo "$2" >> "$SC_TEST_DIR/fuser-calls"
exit 1
''')
        out = self.shell('sc_reset rkhunter; SC_RUN_DIR="$SC_TEST_DIR"; sc_ui_init\n'
                         'sc_parse_rkhunter "$SC_TEST_DIR/rkh-dev.log"\n'
                         'sc_parse_rkhunter "$SC_TEST_DIR/rkh-dev.log"\n'
                         'sc_module_set rkhunter completed; sc_run_followups >/dev/null\n'
                         'printf "%s" "${#SC_F_KEY[@]}"\n', PATH=path)
        self.assertEqual(out, '1')
        self.assertEqual((self.folder / 'fuser-calls').read_text().splitlines(), [str(sample)])

    def test_process_output_is_bounded_before_interpretation(self):
        sample = self.runtime_file()
        path = self.command('fuser', "printf '%5000s' 12345\n")
        self.command('ps', 'touch "$SC_TEST_DIR/PS-CALLED"\n')
        out = self.parse(self.warning(sample), followups=True, PATH=path)
        self.assertIn('|rkh_dev_unknown', out)
        self.assertFalse((self.folder / 'PS-CALLED').exists())

    def test_nul_in_pid_output_cannot_select_a_different_process(self):
        sample = self.runtime_file()
        path = self.command('fuser', "printf '123\\00045\\n'\n")
        self.command('ps', 'touch "$SC_TEST_DIR/PS-CALLED"\n')
        out = self.parse(self.warning(sample), followups=True, PATH=path)
        self.assertIn('|rkh_dev_unknown', out)
        self.assertFalse((self.folder / 'PS-CALLED').exists())

    def test_executable_path_ending_in_a_newline_is_not_retargeted(self):
        sample = self.runtime_file()
        path = self.command('fuser', "echo '12345'\n")
        self.command('ps', "echo '12345 1000 audio-player'\n")
        self.command('readlink', "printf '/usr/bin/audio-player\\n'\n")
        self.command('pacman', 'touch "$SC_TEST_DIR/PACMAN-CALLED"\necho wrong-package\n')
        out = self.parse(self.warning(sample), followups=True, PATH=path)
        self.assertIn('|rkh_dev_process', out)
        self.assertNotIn('wrong-package', out)
        self.assertFalse((self.folder / 'PACMAN-CALLED').exists())

    def test_an_identified_flagged_utility_is_not_executed_even_through_an_alias(self):
        sample = self.runtime_file()
        path = self.command('ps', 'touch "$SC_TEST_DIR/FLAGGED-EXECUTED"\n')
        alias = self.folder / 'ps-alias'
        alias.symlink_to(self.folder / 'bin/ps')
        self.command('fuser', "echo '12345'\n")
        out = self.parse(self.warning(sample) +
                         f"Warning: The command '{alias}' has been replaced by a script: shell script\n",
                         followups=True, PATH=path)
        self.assertIn('|rkh_dev_tool_flagged', out)
        self.assertFalse((self.folder / 'FLAGGED-EXECUTED').exists())

    def test_a_flagged_text_filter_is_not_launched_by_the_dev_helper(self):
        sample = self.runtime_file()
        path = self.command('tr', 'touch "$SC_TEST_DIR/FLAGGED-TR"\n')
        out = self.shell('sc_reset rkhunter; SC_RUN_DIR="$SC_TEST_DIR"\n'
                         'SC_F_MODULE=(rkhunter rkhunter)\n'
                         'SC_F_PRIORITY=(review review)\n'
                         'SC_F_OBJECT=("$SC_SAMPLE" "$SC_TEST_DIR/bin/tr")\n'
                         'sc_rkh_check_dev 0\n'
                         'printf "%s" "${SC_F_CHECK_KEY[0]}"\n',
                         PATH=path, SC_SAMPLE=str(sample))
        self.assertEqual(out, 'rkh_dev_tool_flagged')
        self.assertFalse((self.folder / 'FLAGGED-TR').exists())

    def test_real_fuser_and_process_tools_observe_own_temporary_file(self):
        if not shutil.which('fuser'):
            self.skipTest('optional psmisc/fuser is not installed')
        sample = self.runtime_file()
        with sample.open('r+b') as opened, mmap.mmap(opened.fileno(), 0):
            probe = subprocess.run(['fuser', '-v', str(sample)], capture_output=True,
                                   text=True, timeout=10)
            if probe.returncode != 0 or not probe.stdout.strip():
                self.skipTest('this environment cannot observe the own test-file user')
            pids = probe.stdout.split()
            self.assertTrue(all(pid.isdigit() for pid in pids), probe.stdout)
            out = self.parse(self.warning(sample), followups=True)
            self.assertIn('|rkh_dev_process', out)
            self.assertIn('PID ' + pids[0], ' '.join(out.split()))
            self.assertNotIn('info|', out)

    def test_process_lookup_failure_or_malformed_pids_stays_unknown(self):
        sample = self.runtime_file()
        for body in ('echo "permission denied" >&2; exit 1\n', 'echo not-a-pid\n',
                     "printf '12345\\nBAD'\n", "printf '12345\\n'; exit 2\n"):
            with self.subTest(body=body):
                path = self.command('fuser', body)
                self.command('ps', 'touch "$SC_TEST_DIR/PS-CALLED"\n')
                out = self.parse(self.warning(sample), followups=True, PATH=path)
                self.assertIn('|rkh_dev_unknown', out)
                self.assertNotIn('info|', out)
                self.assertFalse((self.folder / 'PS-CALLED').exists())

    def test_nonregular_or_replaced_path_is_not_followed(self):
        sample = self.runtime_file()
        sample.unlink()
        sample.symlink_to(self.folder / 'other')
        path = self.command('fuser', 'touch "$SC_TEST_DIR/FUSER-CALLED"\n')
        out = self.parse(self.warning(sample), followups=True, PATH=path)
        self.assertIn('|rkh_dev_nonregular', out)
        self.assertFalse((self.folder / 'FUSER-CALLED').exists())

    def test_missing_path_is_not_cleared(self):
        out = self.parse(self.warning('/dev/shm/nonexistent-seccheck-fixture'), followups=True)
        self.assertIn('|rkh_dev_missing', out)
        self.assertNotIn('info|', out)

    def test_named_audio_files_are_context_not_an_allowlist(self):
        out = self.parse(self.warning('/dev/shm/lsp-catalog-klod.shm'))
        self.assertIn('LSP', out)
        self.assertIn('non basta', out)
        self.assertIn('review|rkh_dev_file|', out)

    def test_partial_native_list_keeps_the_unreadable_entry(self):
        out = self.parse(self.warning('/dev/shm/valid').replace(
            '[22:11:38] Checking for hidden',
            '[22:11:38]         /dev/shm/ambiguous: path: data\n'
            '[22:11:38] Checking for hidden'), followups=True)
        self.assertIn('review|rkh_path_unreadable||', out)
        self.assertIn('|/dev/shm/valid|', out)

    def test_missing_baseline_is_explained_in_short_result(self):
        out = self.shell('sc_reset rkhunter; SC_LANG=it; sc_ui_init\n'
                         'sc_module_set rkhunter partial rkh_baseline_missing\n'
                         'sc_assess; sc_render_summary\n')
        self.assertIn('rkhunter.dat', out)
        self.assertIn('fotografia', out)
        self.assertIn('propupd', out)
