"""A beginner report stays bounded without losing unresolved priorities."""
from test_seccheck import SecCheckCase


class SimpleResultsTests(SecCheckCase):
    def test_large_run_has_short_report_and_separate_original_evidence(self):
        out = self.shell('''sc_reset 'integrity lynis'; SC_LANG=it; sc_ui_init
sc_module_set integrity completed; sc_module_set lynis partial unfinished
for n in {1..120}; do
sc_add_finding integrity integrity review unconfirmed "/etc/example$n" integrity_content "PRIVATE-RAW-$n"
done
sc_add_finding lynis hardening urgent unconfirmed TEST lynis_warning 'PRIVATE-URGENT'
sc_assess
sc_render_short_report
printf '\nTECHNICAL-START\n'
sc_render_report
''', timeout=30)
        short, technical = out.split('TECHNICAL-START')
        self.assertNotIn('PRIVATE-', short)
        self.assertLess(len(short.splitlines()), 55)
        self.assertIn('URGENTE', short)
        self.assertIn('Elementi da verificare: 121', short)
        self.assertIn('INCOMPLETA', short)
        self.assertIn('PRIVATE-RAW-120', technical)
        self.assertIn('PRIVATE-URGENT', technical)

    def test_empty_run_does_not_invent_findings(self):
        out = self.shell('''sc_reset integrity; SC_LANG=en; sc_ui_init
sc_module_set integrity completed; sc_assess; sc_render_short_report
''')
        self.assertIn('Items to verify: 0', out)
        self.assertIn('1/1', out)

    def test_compact_brand_fits_ascii_terminal_and_has_separate_color_segments(self):
        out = self.shell('''SC_ASCII=1; COLUMNS=40; sc_ui_init
SC_C_RED='<RED>'; SC_C_WHITE='<WHITE>'; SC_C_RESET='<END>'; sc_brand
''')
        self.assertIn('<RED>S E C', out)
        self.assertIn('<WHITE>C H E C K', out)
        self.assertNotIn('████', out)
        plain = out.replace('<RED>', '').replace('<WHITE>', '').replace('<END>', '')
        self.assertLessEqual(max(map(len, plain.splitlines())), 40)
        self.assertIn('+', plain)

    def test_brand_also_fits_smallest_supported_terminal(self):
        out = self.shell('SC_ASCII=1; COLUMNS=24; sc_ui_init; sc_brand')
        self.assertLessEqual(max(map(len, out.splitlines())), 24)

    def test_wide_brand_is_larger_without_overflow(self):
        out = self.shell('SC_ASCII=1; COLUMNS=80; sc_ui_init; sc_brand')
        rows = out.splitlines()
        self.assertGreaterEqual(len(rows[0]), 50)
        self.assertEqual(sum(row.startswith('  |') for row in rows), 5)
        self.assertLessEqual(max(map(len, rows)), 80)
