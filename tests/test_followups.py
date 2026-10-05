"""Confirmation and follow-up checks use inert tools and real temporary files."""
import hashlib
import os
import pty
import select
import subprocess
import time
import unittest

from test_seccheck import SecCheckCase, SCRIPT


class FollowupTests(SecCheckCase):
    def file_fixture(self, changed=False, mode='644'):
        target = self.folder / 'sample'
        target.write_text('inert data\n')
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        if changed:
            target.write_text('changed data\n')
        self.fixture('record', f'file: {str(target)[1:]}\nowner: demo\nmode: {mode}\n'
                     f'type: file\nowner: 0/root\ngroup: 0/root\nsha256: {digest}\n')
        return self.command('pacfile', 'printf "called\\n" >> "$SC_TEST_DIR/calls"; cat "$SC_TEST_DIR/record"\n')

    def integrity_followup(self, keys, path):
        return self.shell('sc_reset integrity; sc_ui_init; SC_RUN_DIR="$SC_TEST_DIR"\n'
                          'sc_module_set integrity completed ""\n'
                          'for key in $KEYS; do sc_add_finding integrity integrity review observation '
                          '"$SC_TEST_DIR/sample" "$key" "original difference"; done\n'
                          'sc_run_followups > /dev/null\n'
                          'for i in "${!SC_F_KEY[@]}"; do printf "%s|%s|%s\\n" '
                          '"${SC_F_KEY[i]}" "${SC_F_PRIORITY[i]}" "${SC_F_CHECK_KEY[i]}"; done', KEYS=keys, PATH=path)

    def test_unchanged_hash_does_not_clear_a_timestamp_warning(self):
        out = self.integrity_followup('integrity_time integrity_content', self.file_fixture())
        self.assertIn('integrity_time|review|integrity_hash_only', out)
        self.assertIn('integrity_content|info|integrity_rechecked', out)
        self.assertEqual((self.folder / 'calls').read_text().splitlines(), ['called'])

    def test_modified_content_or_permissions_stays_open(self):
        for changed, mode, result in [(True, '644', 'rkh_file_changed'),
                                      (False, '644 (666 on filesystem)', 'rkh_file_metadata')]:
            with self.subTest(changed=changed, mode=mode):
                out = self.integrity_followup('integrity_content integrity_permissions', self.file_fixture(changed, mode))
                self.assertNotIn('|info|', out)
                self.assertIn('|review|' + result, out)

    def test_sanitized_integrity_path_is_not_retargeted(self):
        path = self.file_fixture()
        self.fixture('integrity.log', 'warning: demo: ' + str(self.folder / 'sample\t') + ' (SHA256 checksum mismatch)\n')
        out = self.shell('sc_reset integrity; SC_RUN_DIR="$SC_TEST_DIR"\n'
                         'sc_parse_integrity "$SC_TEST_DIR/integrity.log"; sc_interpret_integrity\n'
                         'printf "%s|%s" "${SC_F_PRIORITY[0]}" "${SC_F_CHECK_KEY[0]}"', PATH=path)
        self.assertEqual(out, 'review|followup_manual')
        self.assertFalse((self.folder / 'calls').exists())

    @unittest.skipUnless(os.geteuid() == 0, "exercise existing-root interactive flow")
    def test_interactive_yes_updates_the_real_scan_report_and_exit_code(self):
        path = self.file_fixture()
        self.command('pacman', '''[[ $1 == --version ]] && { echo test; exit; }
printf 'warning: demo: %s/sample (SHA256 checksum mismatch)\n' "$SC_TEST_DIR" >&2
echo 'demo: 1 total file, 1 altered file'
exit 1
''')
        self.command('paccheck', 'echo "demo: all files match mtree sha256sums"\n')
        master, slave = pty.openpty()
        script = '''source "$1"
sc_parse_args --lang it --scan integrity --no-color; sc_ui_init
sc_require_scan_host() { return 0; }
sc_prepare_run() { SC_RUN_DIR="$SC_TEST_DIR/run"; mkdir -m 700 "$SC_RUN_DIR"; }
sc_run_requested
'''
        process = subprocess.Popen(['bash', '-c', script, 'test', str(SCRIPT)],
                                   stdin=slave, stdout=slave, stderr=slave,
                                   env=dict(os.environ, PATH=path, SC_TEST_DIR=str(self.folder), NO_COLOR='1'))
        os.close(slave)
        data = b''
        try:
            os.write(master, b's\n0\n')
            until = time.monotonic() + 10
            while time.monotonic() < until:
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        data += os.read(master, 65536)
                    except OSError:
                        break
                elif process.poll() is not None:
                    break
            self.assertEqual(process.wait(timeout=2), 0, data.decode())
            self.assertIn(b'Vuoi che faccia io le verifiche del caso al posto tuo?', data)
            self.assertIn('integrity_rechecked', (self.folder / 'run/checks.tsv').read_text())
            self.assertIn('\tinfo\t', (self.folder / 'run/findings.tsv').read_text())
            self.assertIn('original', (self.folder / 'run/report.txt').read_text().lower())
        finally:
            if process.poll() is None:
                process.kill()
            os.close(master)

    def test_confirmation_is_explicit_and_uses_existing_privileges(self):
        for answer, called in [('s', True), ('S', True), ('y', True), ('n', False), ('', False)]:
            with self.subTest(answer=answer):
                out = self.shell('sc_reset integrity; SC_LANG=it; sc_ui_init\n'
                                 'sc_run_followups() { printf "FOLLOWUPS-RAN\\n"; }\n'
                                 'sc_offer_followups <<< "$ANSWER"\n', ANSWER=answer)
                self.assertIn('Vuoi che faccia io le verifiche del caso al posto tuo?', out)
                self.assertEqual('FOLLOWUPS-RAN' in out, called)

    def test_eof_does_not_start_checks(self):
        out = self.shell('sc_reset; SC_LANG=it; sc_ui_init\n'
                         'sc_run_followups() { printf "FOLLOWUPS-RAN\\n"; }\n'
                         'sc_offer_followups < /dev/null')
        self.assertNotIn('FOLLOWUPS-RAN', out)

    def test_initial_rootkit_scan_defers_file_checks_until_confirmation(self):
        self.fixture('input', "Warning: The command '/usr/bin/example' has been replaced by a script: shell script\nSystem checks summary\n")
        path = self.command('rkhunter', '[[ $1 == --version ]] && { echo 1.4.6; exit; }; cat "$SC_TEST_DIR/input"; exit 1\n')
        self.command('pacfile', 'touch "$SC_TEST_DIR/CALLED"\n')
        out = self.shell('sc_reset rkhunter; SC_RUN_DIR="$SC_TEST_DIR"; sc_run_rkhunter\n'
                         'printf "%s" "${SC_F_PRIORITY[0]}"', PATH=path)
        self.assertEqual(out, 'review')
        self.assertFalse((self.folder / 'CALLED').exists())

    def test_followups_preserve_urgent_and_uncheckable_findings_and_private_report(self):
        out = self.shell('sc_reset "rkhunter integrity lynis aur-health"; SC_LANG=it; sc_ui_init\n'
                         'sc_prepare_run "$SC_TEST_DIR/reports" || exit\n'
                         'sc_module_set rkhunter partial rkh_regex\n'
                         'sc_add_finding rkhunter suspicious urgent unconfirmed signature rkh_signature "Possible rootkit"\n'
                         'sc_add_finding integrity integrity review observation /nonexistent-seccheck-test integrity_missing "missing"\n'
                         'sc_add_finding lynis hardening suggestion observation TEST lynis_suggestion "Lynis evidence"\n'
                         'sc_run_followups\n'
                         'printf "RESULT|%s|%s\\n" "$SC_URGENT" "${SC_MODULE_STATUS[rkhunter]}"\n'
                         'cat "$SC_RUN_DIR/checks.tsv"\n'
                         'stat -c "%a" "$SC_RUN_DIR/report.txt"')
        self.assertIn('RESULT|1|partial', out)
        self.assertIn('followup_manual', out)
        self.assertTrue(out.endswith('600'), out)

    def test_summary_omits_raw_diagnostics_but_report_keeps_them(self):
        out = self.shell('sc_reset rkhunter; SC_LANG=it; sc_ui_init\n'
                         'sc_module_set rkhunter partial rkh_regex\n'
                         'sc_add_diagnostic rkhunter rkh_regex "grep: warning: stray \\ before +"\n'
                         'sc_assess; sc_render_summary\n'
                         'printf "REPORT-START\\n"; sc_render_report')
        summary, report = out.split('REPORT-START')
        self.assertNotIn('stray', summary)
        self.assertIn('stray', report)
        self.assertLess(len(summary.split()), 150)

    def test_changed_files_are_counted_as_still_needing_assessment(self):
        out = self.shell('sc_reset integrity; SC_LANG=en; sc_ui_init\n'
                         'sc_module_set integrity completed ""\n'
                         'sc_add_finding integrity integrity review observation /example integrity_content changed\n'
                         'SC_F_CHECK_KEY[0]=rkh_file_changed; SC_FOLLOWUPS_DONE=1\n'
                         'sc_assess; sc_render_summary')
        self.assertIn('Still to assess: 1', out)

    def test_ssh_executable_with_an_open_finding_is_never_run(self):
        path = self.command('sshd', 'touch "$SC_TEST_DIR/EXECUTED"; echo "OpenSSH_10.5p1"\n')
        (self.folder / 'ssh-alias').symlink_to(self.folder / 'bin/sshd')
        out = self.shell('sc_reset "rkhunter integrity"; SC_RUN_DIR="$SC_TEST_DIR"\n'
                         'sc_add_finding integrity integrity review observation "$SC_TEST_DIR/ssh-alias" integrity_content changed\n'
                         'sc_add_finding rkhunter suspicious review unconfirmed Protocol rkh_ssh_protocol warning\n'
                         'sc_rkh_check_ssh 1\n'
                         'printf "%s|%s" "${SC_F_PRIORITY[1]}" "${SC_F_CHECK_KEY[1]}"', PATH=path)
        self.assertEqual(out, 'review|rkh_ssh_flagged')
        self.assertFalse((self.folder / 'EXECUTED').exists())

    def test_interrupted_followups_record_what_remains_unchecked(self):
        result = subprocess.run(['bash', '-c', '''source "$1"
sc_reset integrity; SC_LANG=en; sc_ui_init
sc_prepare_run "$SC_TEST_DIR/reports" || exit
printf '%s' "$SC_RUN_DIR" > "$SC_TEST_DIR/run-path"
sc_module_set integrity completed ''
sc_add_finding integrity integrity review observation /example integrity_content changed
sc_interpret_integrity() { kill -TERM "$$"; }
sc_run_followups
''', 'test', str(SCRIPT)], capture_output=True, text=True, timeout=5,
                                env=dict(os.environ, SC_TEST_DIR=str(self.folder), NO_COLOR='1'))
        self.assertEqual(result.returncode, 130, result.stderr)
        from pathlib import Path
        run = Path((self.folder / 'run-path').read_text())
        self.assertIn('followup_interrupted', (run / 'checks.tsv').read_text())
        self.assertIn('Additional checks were interrupted', (run / 'report.txt').read_text())
