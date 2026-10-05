"""CLI and private report behavior, without invoking real host scanners."""
import os
import pathlib
import pty
import select
import subprocess
import time
import unittest

from test_seccheck import SecCheckCase, SCRIPT


class InterfaceTests(SecCheckCase):
    def cli(self, *args, **env):
        return subprocess.run(['bash', str(SCRIPT), *args], input='', text=True,
                              capture_output=True, timeout=10,
                              env=dict(os.environ, NO_COLOR='1', **env))

    def test_version_and_help_do_not_require_root_or_scanners(self):
        version = self.cli('--version')
        self.assertEqual(version.stdout.strip(), 'SecCheck 2.0.0')
        help_result = self.cli('--lang', 'it', '--help')
        self.assertEqual(help_result.returncode, 0)
        self.assertIn('integrity|aur-health', help_result.stdout)
        self.assertNotIn('--aur-path', help_result.stdout)
        self.assertIn('Uso:', help_result.stdout)

    def test_invalid_and_incomplete_cli_options_fail(self):
        for args in [('--lang',), ('--lang', 'xx'), ('--scan', 'invalid'),
                     ('--demo', 'invented'), ('--unknown',), ('--aur-path', 'relative')]:
            with self.subTest(args=args):
                result = self.cli(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(result.stderr)

    def test_noninteractive_scan_requires_explicit_language(self):
        result = self.cli('--scan', 'full')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--lang', result.stderr)

    def test_demo_is_bilingual_and_never_reports_safety_percentage(self):
        for language, label in [('it', 'DA VERIFICARE'), ('en', 'REVIEW NEEDED')]:
            result = self.cli('--lang', language, '--demo', 'review', '--ascii')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(label, result.stdout)
            self.assertIn('DEMO', result.stdout)
            self.assertNotIn('%', result.stdout)
            self.assertNotIn('\x1b', result.stdout)

    def test_urgent_demo_preserves_incomplete_coverage(self):
        result = self.cli('--lang', 'it', '--demo', 'urgent')
        self.assertIn('URGENTE', result.stdout)
        self.assertIn('INCOMPLETA', result.stdout)
        self.assertIn('3/4', result.stdout)
        self.assertNotIn('SISTEMA SICURO', result.stdout)

    def test_ascii_output_fits_narrow_and_wide_terminals(self):
        for width in (40, 60, 80, 120):
            result = self.cli('--lang', 'en', '--demo', 'review', '--ascii', COLUMNS=str(width))
            self.assertTrue(result.stdout)
            self.assertLessEqual(max(map(len, result.stdout.splitlines())), width, result.stdout)
            self.assertTrue(result.stdout.isascii())

    def test_startup_language_prompt_and_eof_exit(self):
        master, slave = pty.openpty()
        process = subprocess.Popen(['bash', str(SCRIPT), '--ascii'], stdin=slave, stdout=slave,
                                   stderr=slave, env=dict(os.environ, NO_COLOR='1'))
        os.close(slave)
        data = b''
        try:
            os.write(master, b'2\n0\n')
            until = time.monotonic() + 5
            while time.monotonic() < until and process.poll() is None:
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        data += os.read(master, 65536)
                    except OSError:
                        break
            process.wait(timeout=2)
            self.assertIn(b'1  English', data)
            self.assertIn(b'2  Italiano', data)
            self.assertIn(b'Scansione completa', data)
            self.assertEqual(process.returncode, 0)
        finally:
            if process.poll() is None:
                process.kill()
            os.close(master)
        self.assertNotEqual(self.cli().returncode, 0)

    def test_distro_detection_never_sources_os_release(self):
        self.fixture('os-release', 'ID=derivative\nID_LIKE="arch linux"\ntouch "$SC_TEST_DIR/EXECUTED"\n')
        out = self.shell('sc_is_arch "$SC_TEST_DIR/os-release"; printf "%s" "$?"')
        self.assertEqual(out, '0')
        self.assertFalse((self.folder / 'EXECUTED').exists())
        self.fixture('os-release', 'ID=ubuntu\nID_LIKE=debian\n')
        out = self.shell('sc_is_arch "$SC_TEST_DIR/os-release"; printf "%s" "$?"')
        self.assertEqual(out, '1')

    def test_private_plain_report_and_machine_readable_findings(self):
        out = self.shell('sc_reset rkhunter; SC_LANG=it; SC_ASCII=1; SC_NO_COLOR=1; sc_ui_init\n'
                         'sc_prepare_run "$SC_TEST_DIR/reports" || exit\n'
                         'sc_module_set rkhunter partial unfinished\n'
                         'sc_add_finding rkhunter suspicious urgent unconfirmed $\'/tmp/bad\\e[31m\\tname\' rkh_signature fixture\n'
                         'sc_assess; sc_save_report || exit\nprintf "%s" "$SC_RUN_DIR"')
        folder = pathlib.Path(out)
        self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
        report = folder / 'report.txt'
        self.assertEqual(report.stat().st_mode & 0o777, 0o600)
        self.assertIn('URGENTE', report.read_text())
        self.assertNotIn('\x1b', report.read_text())
        rows = (folder / 'findings.tsv').read_text().splitlines()
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(len(row.split('\t')) == 7 for row in rows))
        self.assertIn('partial', (folder / 'modules.tsv').read_text())

    def test_report_parent_symlink_is_refused(self):
        (self.folder / 'link').symlink_to(self.folder)
        out = self.shell('sc_prepare_run "$SC_TEST_DIR/link"; printf "%s" "$?"')
        self.assertNotEqual(out, '0')

    def test_selected_only_summary_states_its_scope(self):
        out = self.shell('sc_reset lynis; SC_LANG=en; SC_ASCII=1; SC_NO_COLOR=1; sc_ui_init\n'
                         'sc_module_set lynis completed ""; sc_assess; sc_render_summary')
        self.assertIn('1/1', out)
        self.assertIn('Selected modules only', out)
        self.assertNotIn('Not selected', out)

    def test_details_can_reach_findings_after_the_first_page(self):
        out = self.shell('sc_reset rkhunter; SC_LANG=en; SC_ASCII=1; SC_NO_COLOR=1; sc_ui_init\n'
                         'for n in {1..21}; do sc_add_finding rkhunter suspicious review unconfirmed '
                         '"/example/file$n" rkh_warning "warning $n"; done\n'
                         'sc_render_details 20 20')
        self.assertIn('/example/file21', out)
        self.assertNotIn('warning 1\n', out)

    def test_explained_findings_and_their_verification_remain_in_reports(self):
        out = self.shell('sc_reset rkhunter; SC_LANG=it; SC_NO_COLOR=1; sc_ui_init\n'
                         'sc_prepare_run "$SC_TEST_DIR/reports" || exit\n'
                         'sc_module_set rkhunter completed ""\n'
                         'sc_add_finding rkhunter suspicious info observation /example/script rkh_script "original warning"\n'
                         'SC_F_CHECK_KEY[0]=rkh_file_match; SC_F_CHECK_DETAIL[0]="Package: example"\n'
                         'sc_assess; sc_save_report || exit; printf "%s" "$SC_RUN_DIR"')
        folder = pathlib.Path(out)
        report = (folder / 'report.txt').read_text()
        self.assertIn('/example/script', report)
        self.assertIn('Package: example', report)
        self.assertIn('original warning', report)
        self.assertNotIn('causa da chiarire', report)
        self.assertIn('rkh_file_match', (folder / 'checks.tsv').read_text())
        self.assertEqual((folder / 'checks.tsv').stat().st_mode & 0o777, 0o600)

    def test_aur_maintenance_advice_has_matching_summary_guidance(self):
        out = self.shell('sc_reset aur-health; SC_LANG=en; SC_ASCII=1; SC_NO_COLOR=1; sc_ui_init\n'
                         'sc_module_set aur-health completed ""\n'
                         'sc_add_finding aur-health maintenance suggestion observation demo health_inactive "days=400"\n'
                         'sc_assess; sc_render_summary')
        self.assertIn('Read each package or configuration suggestion.', out)
        self.assertNotIn('completed checks found configuration improvements', out)

    def test_signature_update_exit_two_is_success(self):
        path = self.command('rkhunter', 'exit 2\n')
        out = self.shell('SC_LANG=en; SC_RUN_DIR="$SC_TEST_DIR"\n'
                         'sc_update_signatures; printf "|%s" "$?"', PATH=path)
        self.assertIn('updated', out)
        self.assertTrue(out.endswith('|0'))

    def test_signature_update_failure_is_reported(self):
        path = self.command('rkhunter', 'exit 1\n')
        out = self.shell('SC_LANG=en; SC_RUN_DIR="$SC_TEST_DIR"\n'
                         'sc_update_signatures; printf "|%s" "$?"', PATH=path)
        self.assertIn('failed', out)
        self.assertTrue(out.endswith('|1'))

    def test_sudo_retains_language_scan_and_display_network_flags(self):
        path = self.command('sudo', 'printf "%s\\n" "$@"\n')
        out = self.shell('SC_LANG=it; SC_SCAN=aur-health; SC_ASCII=1; SC_NO_COLOR=1; SC_OFFLINE=1\n'
                         'sc_elevate scan', PATH=path)
        self.assertIn('--lang\nit\n--scan\naur-health', out)
        self.assertIn('--offline', out)
        self.assertIn('--ascii', out)
        self.assertIn('--no-color', out)


if __name__ == '__main__':
    unittest.main()
