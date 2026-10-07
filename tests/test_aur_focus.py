"""Four-module scan routing and AUR education, with inert scanner boundaries."""
import os
import subprocess

from test_seccheck import SecCheckCase, SCRIPT


class AurFocusTests(SecCheckCase):
    def test_full_scan_runs_four_modules_and_saves_matching_coverage(self):
        out = self.shell('sc_parse_args --lang en --scan full --ascii; sc_ui_init\n'
                         'sc_prepare_run() { SC_RUN_DIR="$SC_TEST_DIR/run"; mkdir -m 700 "$SC_RUN_DIR"; }\n'
                         'sc_run_rkhunter() { sc_module_set rkhunter completed ""; }\n'
                         'sc_run_lynis() { sc_module_set lynis completed ""; }\n'
                         'sc_run_integrity() { sc_module_set integrity completed ""; }\n'
                         'sc_run_aur_health() { sc_module_set aur-health completed ""; }\n'
                         'sc_run_aur() { touch "$SC_TEST_DIR/REMOVED_SCANNER_RAN"; }\n'
                         'sc_scan_once\n')
        self.assertFalse((self.folder / 'REMOVED_SCANNER_RAN').exists())
        self.assertIn('[4/4]', out)
        self.assertIn('4/4', out)
        report = (self.folder / 'run/report.txt').read_text()
        self.assertIn('All four modules selected', report)
        self.assertNotIn('Atomic', report)
        rows = (self.folder / 'run/modules.tsv').read_text().splitlines()
        self.assertEqual([row.split('\t')[0] for row in rows[1:]],
                         ['rkhunter', 'lynis', 'integrity', 'aur-health'])

    def test_menu_five_runs_aur_maintenance_and_describes_full_scope(self):
        out = self.shell('sc_parse_args --lang it --ascii; sc_ui_init\n'
                         'sc_run_requested() { printf "SELECTED|%s\\n" "$SC_SCAN"; }\n'
                         "sc_menu <<<'5\n0'\n")
        self.assertIn('SELECTED|aur-health', out)
        self.assertIn('voci 2, 3, 4 e 5', out)
        self.assertIn('5 AUR / Manutenzione', out)
        self.assertNotIn('Atomic', out)
        self.assertNotIn('9 AUR', out)

    def test_removed_campaign_arguments_are_rejected_before_any_scan(self):
        for args in [('--scan', 'aur'), ('--aur-path', '/tmp')]:
            with self.subTest(args=args):
                result = subprocess.run(['bash', str(SCRIPT), '--lang', 'en', *args],
                                        capture_output=True, text=True, timeout=5,
                                        env=dict(os.environ, NO_COLOR='1'))
                self.assertEqual(result.returncode, 64)
                self.assertIn('invalid arguments', result.stderr)

    def test_aur_guidance_is_visible_for_selected_offline_module(self):
        out = self.shell('sc_reset aur-health; SC_LANG=it; SC_NO_COLOR=1; sc_ui_init\n'
                         'sc_module_set aur-health skipped offline; sc_assess; sc_render_summary')
        self.assertIn('AUR: USO CONSAPEVOLE', out)
        self.assertIn('PKGBUILD', out)
        self.assertIn('Installa solo cio che ti serve', ' '.join(out.split()))
        self.assertIn('non garantisce', out)
