"""Distinguish explicit optional exclusions from failed prerequisite checks."""
from test_seccheck import SecCheckCase


class RootkitDiagnosticTests(SecCheckCase):
    def scan(self, log, stdout=None):
        self.fixture('raw', log + '\nSystem checks summary\n')
        self.fixture('standard', (log if stdout is None else stdout) + '\nSystem checks summary\n')
        path = self.command('rkhunter', '''[[ $1 == --version ]] && { echo 1.4.6; exit; }
while (($#)); do
    if [[ $1 == --logfile ]]; then cp "$SC_TEST_DIR/raw" "$2"; shift; fi
    shift
done
cat "$SC_TEST_DIR/standard"
''')
        return self.shell('sc_reset rkhunter; SC_RUN_DIR="$SC_TEST_DIR"; sc_run_rkhunter\n'
                          'printf "STATUS|%s|%s\\n" "${SC_MODULE_STATUS[rkhunter]}" "${SC_MODULE_REASON[rkhunter]}"\n'
                          'printf "%s\\n" "${SC_D_KEY[@]}" "${SC_D_EVIDENCE[@]}"', PATH=path)

    def test_known_optional_test_requires_its_explicit_reason(self):
        pairs = [
            ('Running skdet command', "Info: Unable to find the 'skdet' command"),
            ('Checking for software intrusions', 'Info: Check skipped - tripwire not installed'),
            ('Checking for missing log files', 'Info: No missing log file names configured.'),
            ('Checking for empty log files', 'Info: No empty log file names configured.'),
            ('Checking for enabled inetd services', "Info: Check skipped - file '/etc/inetd.conf' does not exist."),
            ('Checking for enabled xinetd services', "Info: Check skipped - file '/etc/xinetd.conf' does not exist."),
        ]
        for title, reason in pairs:
            with self.subTest(title=title):
                out = self.scan(f'{title} [ Skipped ]\n{reason}', f'{title} [ Skipped ]')
                self.assertIn('STATUS|completed|', out)
                self.assertIn('rkh_optional', out)
                out = self.scan(f'{title} [ Skipped ]\nInfo: unexpected failure')
                self.assertIn('STATUS|partial|', out)

    def test_reason_for_another_test_does_not_make_skip_optional(self):
        out = self.scan("Checking an unknown test [ Skipped ]\nInfo: No empty log file names configured.")
        self.assertIn('STATUS|partial|', out)

    def test_missing_baseline_is_identified_without_running_propupd(self):
        out = self.scan("Checking for prerequisites [ Warning ]\n"
                        "The file of stored file properties (rkhunter.dat) does not exist, and should be created. To do this type in 'rkhunter --propupd'.")
        self.assertIn('STATUS|partial|rkh_baseline_missing', out)
        self.assertIn('rkhunter.dat', out)

    def test_actual_prerequisite_cause_survives_instead_of_only_generic_warning(self):
        for cause in ["Unable to find the 'stat' command - all file attribute checks will be skipped.",
                      "No output from the 'file' command - all script replacement checks will be skipped.",
                      "The 'stat' command has been disabled - all file attribute checks will be skipped.",
                      "Unable to find 'prelink' command."]:
            with self.subTest(cause=cause):
                out = self.scan("Checking for prerequisites [ Warning ]\n" + cause)
                self.assertIn('STATUS|partial|', out)
                self.assertIn(cause, out)
