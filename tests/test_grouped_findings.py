"""Repeated scanner evidence must not become repeated tasks for the user."""
from test_seccheck import SecCheckCase


class GroupedFindingTests(SecCheckCase):
    def setUp(self):
        super().setUp()
        self.fixture('pacman.log',
                     'warning: demo: /usr/lib/demo/cache.dat (Size mismatch)\n'
                     'warning: demo: /usr/lib/demo/cache.dat (SHA256 checksum mismatch)\n'
                     'warning: demo: /usr/lib/demo/cache.dat (Modification time mismatch)\n'
                     'warning: demo: /etc/demo.conf (Permissions mismatch)\n')
        self.fixture('paccheck.log',
                     "demo: '/usr/lib/demo/cache.dat' sha256sum mismatch (expected abcd)\n")
        self.setup = '''sc_reset 'integrity lynis'; SC_LANG=en; sc_ui_init
sc_module_set integrity completed ''; sc_module_set lynis completed ''
sc_parse_integrity "$SC_TEST_DIR/pacman.log" pacman
sc_parse_integrity "$SC_TEST_DIR/paccheck.log" paccheck
for i in "${!SC_F_MODULE[@]}"; do SC_F_CHECK_KEY[i]=rkh_file_changed; done
sc_add_finding lynis hardening suggestion observation TEST lynis_suggestion 'one optional recommendation'
SC_FOLLOWUPS_DONE=1; sc_assess
'''

    def test_pending_counts_paths_and_excludes_recommendations(self):
        out = self.shell(self.setup + 'sc_render_summary')
        self.assertIn('Still to assess: 2', out)
        self.assertIn('Suggestions: 1', out)
        self.assertIn('To review: 2', out)
        self.assertRegex(out, r'Package integrity\s+Completed\s+2')

    def test_one_detail_card_per_path_keeps_all_types_of_difference(self):
        out = self.shell(self.setup + 'sc_render_details')
        self.assertEqual(out.count('Object: /usr/lib/demo/cache.dat'), 1, out)
        self.assertIn('content', out.lower())
        self.assertIn('modification time', out.lower())
        self.assertIn('size', out.lower())
        self.assertEqual(out.count('Object: /etc/demo.conf'), 1, out)

    def test_page_offsets_count_grouped_paths_not_evidence_rows(self):
        out = self.shell(self.setup + 'sc_render_details 1 1')
        self.assertIn('Object: /etc/demo.conf', out)
        self.assertNotIn('Object: /usr/lib/demo/cache.dat', out)
        self.assertNotIn('Object: TEST', out)

    def test_group_keeps_highest_priority_and_unresolved_checks(self):
        out = self.shell(self.setup + '''SC_F_PRIORITY[0]=info; SC_F_CHECK_KEY[0]=integrity_rechecked
SC_F_PRIORITY[1]=urgent; SC_F_CHECK_KEY[1]=rkh_file_changed
sc_assess; sc_render_details 1
printf 'ASSESSMENT|%s|%s\n' "$SC_ASSESSMENT" "$SC_URGENT"
''')
        self.assertEqual(out.count('Object: /usr/lib/demo/cache.dat'), 1, out)
        self.assertIn('Urgent', out)
        self.assertIn('ASSESSMENT|urgent|1', out)
        self.assertIn('differs', out)
        self.assertIn('now matches', out)

    def test_grouping_preserves_every_original_report_row(self):
        out = self.shell(self.setup + '''sc_prepare_run "$SC_TEST_DIR/reports"
sc_render_details >/dev/null; sc_save_report
printf '%s\n' "$SC_RUN_DIR"
''')
        from pathlib import Path
        run = Path(out)
        rows = (run / 'findings.tsv').read_text().splitlines()
        self.assertEqual(len(rows), 7)  # header, five file observations, one suggestion
        self.assertEqual(len((run / 'checks.tsv').read_text().splitlines()), 6)
        report = ' '.join((run / 'report.txt').read_text().split())
        self.assertIn('pacman: warning: demo:', report)
        self.assertIn("paccheck: demo:", report)
        self.assertIn('Size mismatch', report)
        self.assertIn('Modification time mismatch', report)
        self.assertEqual((run / 'report.txt').stat().st_mode & 0o777, 0o600)

    def test_group_keeps_the_action_for_a_missing_verification_tool(self):
        out = self.shell(self.setup + '''for i in "${!SC_F_MODULE[@]}"; do
    [[ ${SC_F_MODULE[i]} != integrity ]] || SC_F_CHECK_KEY[i]=rkh_file_tool_missing
done
sc_render_details 1
''')
        self.assertIn('Install pacutils using option 6', out)

    def test_unknown_paths_and_different_modules_are_not_merged(self):
        out = self.shell('''sc_reset 'integrity lynis'; SC_LANG=en; sc_ui_init
sc_add_finding integrity integrity review unconfirmed '' integrity_path_unreadable first
sc_add_finding integrity integrity review unconfirmed '' integrity_path_unreadable second
sc_add_finding lynis hardening review observation TEST lynis_warning third
SC_FOLLOWUPS_DONE=1; sc_assess; sc_render_summary
''')
        self.assertIn('Still to assess: 3', out)
