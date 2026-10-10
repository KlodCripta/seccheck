"""The simple security workflow keeps evidence without overwhelming the user."""
import subprocess

from test_seccheck import SecCheckCase, SCRIPT


class SecurityFlowTests(SecCheckCase):
    def test_complete_scan_has_only_the_three_security_checks(self):
        self.assertEqual(self.shell('sc_reset; printf "%s\\n" "${SC_SELECTED[@]}"').splitlines(),
                         ['rkhunter', 'lynis', 'integrity'])

    def test_full_scan_runs_three_real_adapters_without_an_online_helper(self):
        path = self.command('rkhunter', '''[[ $1 == --version ]] && { echo 1.4.6; exit; }
echo 'System checks summary'
''')
        self.command('lynis', '''[[ $1 == --version ]] && { echo 3.1.7; exit; }
while (($#)); do
    if [[ $1 == --report-file ]]; then
        printf 'lynis_version=3.1.7\\nreport_datetime_start=start\\nreport_datetime_end=end\\n' > "$2"
        break
    fi
    shift
done
''')
        self.command('pacman', '''[[ $1 == --version ]] && { echo test; exit; }
echo 'demo: 1 total file, 0 altered files'
''')
        self.command('paccheck', "echo 'demo: all files match mtree sha256sums'\n")
        for tool in ('curl', 'python3'):
            self.command(tool, 'touch "$SC_TEST_DIR/ONLINE-HELPER"; exit 1\n')
        out = self.shell('''sc_parse_args --lang it --scan full --no-color; sc_ui_init
sc_prepare_run() { SC_RUN_DIR="$SC_TEST_DIR/run"; mkdir -m 700 "$SC_RUN_DIR"; }
sc_scan_once
printf '\\nSTATUS=%s|%s' "$SC_COMPLETED" "$SC_ASSESSMENT"
''', PATH=path)
        self.assertIn('[3/3]', out)
        self.assertIn('STATUS=3|clear', out)
        self.assertFalse((self.folder / 'ONLINE-HELPER').exists())
        rows = (self.folder / 'run/modules.tsv').read_text().splitlines()
        self.assertEqual(len(rows), 4)

    def test_removed_online_options_are_rejected(self):
        self.assertEqual(self.shell('sc_parse_args --lang it --offline; printf "%s" "$?"'), '64')
        for args in [('--scan', 'aur-health'), ('--offline',)]:
            with self.subTest(args=args):
                result = subprocess.run(['bash', str(SCRIPT), '--lang', 'it', *args],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 64)
        result = subprocess.run(['bash', str(SCRIPT), '--help'],
                                capture_output=True, text=True, timeout=5)
        self.assertNotIn('aur-health', result.stdout)
        self.assertNotIn('--offline', result.stdout)

    def test_large_scan_starts_with_a_brief_result_not_a_file_list(self):
        out = self.shell('''sc_reset; SC_LANG=it; sc_ui_init
for module in "${SC_SELECTED[@]}"; do sc_module_set "$module" completed; done
sc_module_set rkhunter partial rkh_baseline_missing
for n in {1..115}; do
sc_add_finding integrity integrity review observation "/etc/private-$n" integrity_content "RAW-$n"
done
sc_assess; sc_render_summary
''')
        self.assertIn('115', out)
        self.assertIn('2/3', out)
        self.assertIn('rkhunter', out)
        self.assertLessEqual(len(out.splitlines()), 18)
        self.assertNotIn('/etc/private', out)
        self.assertNotIn('RAW-', out)
        self.assertNotIn('--propupd', out)
        self.assertNotIn('AUR', out)

    def test_optional_improvements_do_not_turn_a_complete_clean_check_orange(self):
        out = self.shell('''sc_reset lynis; SC_LANG=it; sc_ui_init
sc_module_set lynis completed
sc_add_finding lynis hardening suggestion observation BOOT-5264 lynis_suggestion "hardening"
SC_FOLLOWUPS_DONE=1; sc_assess
printf 'ASSESSMENT=%s\\n' "$SC_ASSESSMENT"; sc_render_summary
''')
        self.assertIn('ASSESSMENT=clear', out)
        self.assertIn('Miglioramenti facoltativi: 1', out)

    def test_an_incomplete_scan_cannot_be_green_even_with_only_suggestions(self):
        out = self.shell('''sc_reset lynis; sc_ui_init
sc_module_set lynis partial unfinished
sc_add_finding lynis hardening suggestion observation TEST lynis_suggestion "suggestion"
sc_assess; printf '%s' "$SC_ASSESSMENT"
''')
        self.assertEqual(out, 'unknown')

    def test_attention_view_filters_optional_and_explained_items(self):
        out = self.shell('''sc_reset integrity; SC_LANG=it; sc_ui_init
sc_add_finding integrity integrity review observation /open integrity_content changed
sc_add_finding integrity integrity info observation /explained integrity_content original
sc_add_finding integrity integrity suggestion observation /optional integrity_permissions suggestion
sc_render_details 5 0 0 attention
''')
        self.assertIn('/open', out)
        self.assertNotIn('/explained', out)
        self.assertNotIn('/optional', out)

    def test_a_partly_explained_path_stays_whole_in_the_attention_view(self):
        out = self.shell('''sc_reset integrity; SC_LANG=en; sc_ui_init
sc_add_finding integrity integrity review observation /mixed integrity_time "changed time"
sc_add_finding integrity integrity info observation /mixed integrity_content "content now matches"
SC_F_CHECK_KEY[1]=integrity_rechecked
sc_render_details 5 0 0 attention
printf '\\nEXPLAINED-VIEW\\n'; sc_render_details 5 0 0 explained
''')
        attention, explained = out.split('EXPLAINED-VIEW')
        self.assertIn('modification time', attention)
        self.assertIn('now matches', attention)
        self.assertNotIn('/mixed', explained)

    def test_mutable_account_file_gets_an_explanation_without_being_cleared(self):
        out = self.shell('''sc_reset integrity; SC_LANG=it; sc_ui_init
sc_module_set integrity completed
sc_add_finding integrity integrity review observation /etc/passwd integrity_content "changed"
SC_F_CHECK_KEY[0]=rkh_file_changed
SC_FOLLOWUPS_DONE=1; sc_assess; sc_render_details 5 0 0 attention
printf '\\nPRIORITY=%s' "${SC_F_PRIORITY[0]}"
''')
        self.assertIn('account', out)
        self.assertIn('non riconosci', out)
        self.assertIn('PRIORITY=review', out)

    def test_known_lynis_advice_is_explained_in_the_selected_language(self):
        self.fixture('lynis.dat', 'suggestion[]=PKGS-7320|Consider installing arch-audit to determine vulnerable packages|arch-audit||\n')
        out = self.shell('''sc_reset lynis; SC_LANG=it; sc_ui_init
sc_parse_lynis "$SC_TEST_DIR/lynis.dat"; sc_render_details 5 0 0 suggestions
''')
        self.assertIn('vulnerabilit', out)
        self.assertIn('arch-audit', out)
        self.assertNotIn('Consider installing', out)

    def test_a_changed_lynis_message_does_not_receive_unrelated_instructions(self):
        self.fixture('lynis.dat', 'warning[]=PKGS-7320|A different warning||||\n')
        out = self.shell('''sc_reset lynis; SC_LANG=it; sc_ui_init
sc_parse_lynis "$SC_TEST_DIR/lynis.dat"; sc_render_details 5 0 0 attention
''')
        self.assertNotIn('arch-audit', out)
        self.assertIn('rapporto tecnico', out)

    def test_final_result_keeps_urgent_and_incomplete_checks_visible(self):
        out = self.shell('''sc_reset; SC_LANG=it; sc_ui_init
sc_module_set rkhunter partial rkh_baseline_missing
sc_module_set lynis completed; sc_module_set integrity completed
sc_add_finding rkhunter suspicious urgent unconfirmed signature rkh_signature "PRIVATE-SIGNATURE"
SC_FOLLOWUPS_DONE=1; sc_assess; sc_render_summary
''')
        self.assertIn('URGENTE', out)
        self.assertIn('Urgenti: 1', out)
        self.assertIn('2/3', out)
        self.assertNotIn('PRIVATE-SIGNATURE', out)
        self.assertNotIn('%', out)

    def test_primary_menu_has_a_scan_and_two_small_submenus(self):
        out = self.shell("SC_LANG=it; sc_ui_init; sc_menu <<<'0'")
        self.assertIn('1 Scansione completa', out)
        self.assertIn('2 Controlli singoli', out)
        self.assertIn('3 Strumenti', out)
        self.assertNotIn('4 File', out)
        self.assertNotIn('AUR', out)
        self.assertNotIn('8 ', out)
        self.assertLessEqual(len(out.splitlines()), 22)
