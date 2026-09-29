"""Native rkhunter warnings, with real local files and inert scanner commands."""
import hashlib

from test_seccheck import SecCheckCase


class RootkitContextTests(SecCheckCase):
    def setUp(self):
        super().setUp()
        self.sample = self.folder / 'sample'
        self.sample.write_text('inert example file\n')
        self.digest = hashlib.sha256(self.sample.read_bytes()).hexdigest()
        self.path = self.command('rkhunter', '''[[ "$1" == --version ]] && { echo 1.4.6; exit; }
while (($#)); do
    if [[ $1 == --logfile ]]; then cp "$SC_TEST_DIR/rkh.log" "$2"; shift; fi
    shift
done
cat "$SC_TEST_DIR/rkh.stdout"
exit 1
''')
        self.command('pacfile', '''[[ $1 == --check && $2 == -- && $3 == "$SC_TEST_DIR/sample" ]] || exit 2
cat "$SC_TEST_DIR/pacfile.data"
cat "$SC_TEST_DIR/pacfile.error" >&2
''')
        self.fixture('pacfile.error', '')
        self.package_record()

    def package_record(self, **changes):
        values = dict(file=str(self.sample)[1:], package='example-package', mode='644',
                      type='file', owner='0/root', group='0/root', size='19 B',
                      sha256=self.digest)
        values.update(changes)
        self.fixture('pacfile.data', '\n'.join([
            'file:   ' + values['file'], 'owner:  ' + values['package'], 'backup: no',
            'mode:   ' + values['mode'], 'type:   ' + values['type'],
            'mtime:  2026-09-28 10:00:00', 'owner:  ' + values['owner'],
            'group:  ' + values['group'], 'size:   ' + values['size'],
            'sha256: ' + values['sha256'], 'md5sum: ' + 'a' * 32, '']))

    def scan(self, lines, stdout=None):
        self.fixture('rkh.log', lines + '\nSystem checks summary\n')
        self.fixture('rkh.stdout', (lines if stdout is None else stdout) + '\nSystem checks summary\n')
        out = self.shell('sc_reset rkhunter; SC_RUN_DIR="$SC_TEST_DIR"\n'
                         'sc_run_rkhunter; sc_assess\n'
                         'for ((i=0;i<${#SC_F_MODULE[@]};i++)); do\n'
                         ' printf "%s|%s|%s|%s\\n" "${SC_F_PRIORITY[i]}" "${SC_F_KEY[i]}" '
                         '"${SC_F_OBJECT[i]}" "${SC_F_CHECK_KEY[i]-}"\ndone\n'
                         'printf "RESULT|%s|%s\\n" "$SC_ASSESSMENT" "${SC_MODULE_STATUS[rkhunter]}"\n'
                         'for ((i=0;i<${#SC_D_MODULE[@]};i++)); do printf "DIAG|%s\\n" "${SC_D_KEY[i]}"; done',
                         PATH=self.path)
        return out

    def script_warning(self):
        return (f"  {self.sample} [ Warning ]\n"
                f"Warning: The command '{self.sample}' has been replaced by a script: POSIX shell script")

    def test_summary_and_both_streams_become_one_file_finding(self):
        out = self.scan(self.script_warning(), f'    {self.sample} [ Warning ]')
        rows = [line for line in out.splitlines() if str(self.sample) in line]
        self.assertEqual(len(rows), 1, out)
        self.assertIn('|rkh_script|' + str(self.sample) + '|', out)

    def test_baseline_notice_and_prerequisites_are_diagnostics(self):
        out = self.scan("Warning: Checking for prerequisites [ Warning ]\n"
                        "Warning: WARNING! It is the users responsibility to ensure that when the '--propupd' option")
        self.assertNotIn('review|', out)
        self.assertIn('DIAG|rkh_prerequisite', out)
        self.assertIn('DIAG|rkh_baseline_notice', out)
        self.assertIn('RESULT|unknown|partial', out)

    def test_matching_package_hash_explains_script_warning(self):
        out = self.scan(self.script_warning())
        self.assertIn('info|rkh_script|', out)
        self.assertIn('|rkh_file_match', out)
        self.assertIn('RESULT|clear|completed', out)
        self.assertFalse((self.folder / 'EXECUTED').exists())

    def test_modified_file_is_not_cleared_by_package_ownership(self):
        self.sample.write_text('changed bytes\n')
        out = self.scan(self.script_warning())
        self.assertIn('review|rkh_script|', out)
        self.assertIn('|rkh_file_changed', out)

    def test_zero_exit_with_empty_or_incomplete_record_never_clears_a_file(self):
        for record in ('', 'file: ' + str(self.sample)[1:] + '\nowner: example-package\n'):
            with self.subTest(record=record):
                self.fixture('pacfile.data', record)
                out = self.scan(self.script_warning())
                self.assertIn('review|rkh_script|', out)
                self.assertIn('|rkh_file_unknown', out)

    def test_record_for_another_file_cannot_clear_the_requested_file(self):
        self.package_record(file='usr/bin/a-different-file')
        out = self.scan(self.script_warning())
        self.assertIn('review|rkh_script|', out)
        self.assertIn('|rkh_file_unknown', out)

    def test_read_warning_even_with_zero_exit_prevents_clearance(self):
        self.fixture('pacfile.error', 'warning: read error (Permission denied)\n')
        out = self.scan(self.script_warning())
        self.assertIn('|rkh_file_unknown', out)
        self.assertNotIn('info|', out)

    def test_matching_hash_does_not_hide_permission_changes(self):
        self.package_record(mode='644 (666 on filesystem)')
        out = self.scan(self.script_warning())
        self.assertIn('|rkh_file_metadata', out)
        self.assertIn('review|rkh_script|', out)

    def test_unowned_hidden_file_remains_unresolved(self):
        self.fixture('pacfile.data', f"no package owns '{self.sample}'\n")
        out = self.scan(f'Warning: Hidden file found: {self.sample}: ASCII text')
        self.assertIn('review|rkh_hidden_file|' + str(self.sample) + '|rkh_file_unowned', out)

    def test_hidden_summary_is_not_an_extra_finding_when_details_exist(self):
        out = self.scan('Checking for hidden files and directories [ Warning ]\n'
                        f'Warning: Hidden file found: {self.sample}: ASCII text')
        self.assertEqual(sum(line.startswith(('review|', 'info|')) for line in out.splitlines()), 1, out)

    def test_colon_in_hidden_path_cannot_verify_an_existing_prefix(self):
        path = str(self.sample) + ':unverified'
        self.command('pacfile', 'printf called > "$SC_TEST_DIR/CALLED"; cat "$SC_TEST_DIR/pacfile.data"\n')
        out = self.scan(f'Warning: Hidden file found: {path}: ASCII text')
        self.assertIn('review|rkh_hidden_file|' + path + '|rkh_file_nonregular', out)
        self.assertNotIn('info|', out)
        self.assertFalse((self.folder / 'CALLED').exists())

    def test_ambiguous_hidden_path_is_left_unresolved(self):
        self.command('pacfile', 'printf called > "$SC_TEST_DIR/CALLED"; cat "$SC_TEST_DIR/pacfile.data"\n')
        out = self.scan(f'Warning: Hidden file found: {self.sample}: different file: ASCII text')
        self.assertIn('review|rkh_path_unreadable||', out)
        self.assertIn('RESULT|review|partial', out)
        self.assertNotIn('info|', out)
        self.assertFalse((self.folder / 'CALLED').exists())

    def test_unambiguous_colon_path_is_checked_without_truncation(self):
        target = self.folder / 'sample:with-colon'
        self.sample.rename(target)
        self.sample = target
        self.package_record()
        self.command('pacfile', '[[ $3 == "$SC_TEST_DIR/sample:with-colon" ]] || exit 2\n'
                     'cat "$SC_TEST_DIR/pacfile.data"\n')
        out = self.scan(f'Warning: Hidden file found: {target}: ASCII text')
        self.assertIn('info|rkh_hidden_file|' + str(target) + '|rkh_file_match', out)

    def test_directory_warning_cannot_verify_a_file_prefix(self):
        self.command('pacfile', 'printf called > "$SC_TEST_DIR/CALLED"; cat "$SC_TEST_DIR/pacfile.data"\n')
        out = self.scan(f'Warning: Hidden directory found: {self.sample}: different directory')
        self.assertIn('review|rkh_hidden_directory|', out)
        self.assertNotIn('info|', out)
        self.assertFalse((self.folder / 'CALLED').exists())

    def test_script_delimiter_inside_path_cannot_verify_a_prefix(self):
        self.command('pacfile', 'printf called > "$SC_TEST_DIR/CALLED"; cat "$SC_TEST_DIR/pacfile.data"\n')
        path = str(self.sample) + "' has been replaced by a script: other"
        out = self.scan(f"Warning: The command '{path}' has been replaced by a script: ASCII text")
        self.assertIn('review|rkh_path_unreadable||', out)
        self.assertNotIn('info|', out)
        self.assertFalse((self.folder / 'CALLED').exists())

    def test_ssh_phrases_in_filenames_do_not_select_another_check(self):
        self.command('sshd', '[[ $1 == -V ]] && echo "OpenSSH_10.0p1"; '
                     '[[ $1 == -T ]] && echo "permitrootlogin no"; exit 0\n')
        for name in ('.ssh protocol v1 payload', '.ssh root access payload',
                     ".ssh configuration option 'Protocol' payload"):
            with self.subTest(name=name):
                path = self.folder / name
                out = self.scan(f'Warning: Hidden file found: {path}: ASCII text')
                self.assertIn('review|rkh_hidden_file|' + str(path) + '|rkh_file_nonregular', out)
                self.assertIn('RESULT|review|partial', out)

    def test_diagnostic_phrases_in_filenames_do_not_hide_a_warning(self):
        for name in ('.checking for prerequisites',
                     ".WARNING! It is the users responsibility to ensure that when the '--propupd' option"):
            with self.subTest(name=name):
                path = self.folder / name
                out = self.scan(f'Warning: Hidden file found: {path}: ASCII text')
                self.assertIn('review|rkh_hidden_file|' + str(path) + '|rkh_file_nonregular', out)
                self.assertNotIn('DIAG|rkh_baseline_notice', out)
                self.assertNotIn('DIAG|rkh_prerequisite', out)

    def test_signature_warning_is_never_downgraded_by_matching_package(self):
        out = self.scan(f'Warning: Possible rootkit detected: {self.sample}')
        self.assertIn('urgent|rkh_signature|', out)
        self.assertIn('RESULT|urgent|completed', out)

    def test_source_file_is_never_executed(self):
        self.sample.write_text('#!/usr/bin/env bash\ntouch "' + str(self.folder / 'EXECUTED') + '"\n')
        self.package_record(sha256=hashlib.sha256(self.sample.read_bytes()).hexdigest())
        out = self.scan(self.script_warning())
        self.assertIn('|rkh_file_match', out)
        self.assertFalse((self.folder / 'EXECUTED').exists())

    def test_shell_characters_in_warning_path_are_not_evaluated(self):
        path = str(self.folder / '$(touch EXECUTED)')
        out = self.scan(f"Warning: The command '{path}' has been replaced by a script: shell script")
        self.assertNotIn('info|', out)
        self.assertFalse((self.folder / 'EXECUTED').exists())

    def test_sanitizing_a_control_character_cannot_retarget_file_verification(self):
        target = self.folder / 'sample?'
        self.sample.rename(target)
        self.sample = target
        self.package_record()
        self.command('pacfile', 'printf called > "$SC_TEST_DIR/CALLED"; cat "$SC_TEST_DIR/pacfile.data"\n')
        raw_path = str(target).replace('?', '\t')
        out = self.scan(f"Warning: The command '{raw_path}' has been replaced by a script: shell script")
        self.assertNotIn('info|', out)
        self.assertFalse((self.folder / 'CALLED').exists())

    def test_ssh_root_uses_effective_setting_and_merges_summary(self):
        self.command('sshd', '[[ "$1" == -T ]] || exit 2; printf "permitrootlogin prohibit-password\\n"\n')
        out = self.scan("Checking if SSH root access is allowed [ Warning ]\n"
                        "Warning: The SSH configuration option 'PermitRootLogin' has not been set.")
        self.assertEqual(out.count('|rkh_ssh_root|'), 1, out)
        self.assertIn('suggestion|rkh_ssh_root|PermitRootLogin|rkh_ssh_keys', out)

    def test_ssh_root_yes_remains_actionable(self):
        self.command('sshd', '[[ "$1" == -T ]] || exit 2; printf "permitrootlogin yes\\n"\n')
        out = self.scan("Warning: The SSH configuration option 'PermitRootLogin' has not been set.")
        self.assertIn('review|rkh_ssh_root|PermitRootLogin|rkh_ssh_allowed', out)

    def test_ssh_config_failure_does_not_claim_root_is_disabled(self):
        self.command('sshd', 'echo "missing host keys" >&2; exit 1\n')
        out = self.scan("Warning: The SSH configuration option 'PermitRootLogin' has not been set.")
        self.assertIn('|rkh_ssh_unknown', out)
        self.assertNotIn('|rkh_ssh_disabled', out)

    def test_legacy_protocol_warning_is_checked_against_server_version(self):
        self.command('sshd', '[[ "$1" == -V ]] || exit 2; echo "OpenSSH_10.0p1, OpenSSL 3.5" >&2\n')
        out = self.scan("Checking if SSH protocol v1 is allowed [ Warning ]\n"
                        "Warning: The SSH configuration option 'Protocol' has not been set.")
        self.assertEqual(out.count('|rkh_ssh_protocol|'), 1, out)
        self.assertIn('info|rkh_ssh_protocol|Protocol|rkh_ssh_modern', out)

    def test_unknown_ssh_server_version_is_not_assumed_modern(self):
        self.command('sshd', 'echo "custom server" >&2\n')
        out = self.scan("Warning: The SSH configuration option 'Protocol' has not been set.")
        self.assertIn('|rkh_ssh_unknown', out)
        self.assertNotIn('info|', out)
