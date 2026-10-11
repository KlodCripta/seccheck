"""Native integrity message forms and visible reasons for incomplete coverage."""
from test_seccheck import SecCheckCase


class IntegrityFeedbackTests(SecCheckCase):
    def scan(self, pacman_out='demo: 10 total files, 0 altered files\n', pacman_err='',
             paccheck_out='demo: all files match mtree sha256sums\n', paccheck_err='',
             pacman_rc=0, paccheck_rc=0):
        for name, data in [('pm.out', pacman_out), ('pm.err', pacman_err),
                           ('pc.out', paccheck_out), ('pc.err', paccheck_err)]:
            self.fixture(name, data)
        path = self.command('pacman', '[[ $1 == --version ]] && { echo "pacman test"; exit; }\n'
                            'cat "$SC_TEST_DIR/pm.out"; cat "$SC_TEST_DIR/pm.err" >&2\n'
                            f'exit {pacman_rc}\n')
        self.command('paccheck', 'cat "$SC_TEST_DIR/pc.out"; cat "$SC_TEST_DIR/pc.err" >&2\n'
                     f'exit {paccheck_rc}\n')
        return self.shell('sc_reset integrity; SC_RUN_DIR="$SC_TEST_DIR"; SC_LANG=en\n'
                          'sc_run_integrity; sc_assess; SC_NO_COLOR=1; sc_ui_init\n'
                          'sc_render_report\n'
                          'printf "\\nRESULT|%s|%s|%s\\n" "${SC_MODULE_STATUS[integrity]}" '
                          '"$SC_ASSESSMENT" "${#SC_F_MODULE[@]}"\n'
                          'for key in "${SC_D_KEY[@]}"; do printf "DIAG|%s\\n" "$key"; done', PATH=path)

    def test_pacman_sha256_warning_is_a_content_difference(self):
        for prefix in ('warning: ', 'backup file: '):
            with self.subTest(prefix=prefix):
                out = self.scan(pacman_err=prefix + 'demo: /usr/share/demo/cache.dat (SHA256 checksum mismatch)\n',
                                pacman_rc=1)
                self.assertIn('File content differs from the local package record.', out)
                self.assertNotIn('This is not a content hash result.', out)
                self.assertIn('RESULT|completed|review|1', out)

    def test_native_property_differences_have_specific_meanings(self):
        for detail, meaning in [('Permissions mismatch', 'Access permissions'),
                                ('UID mismatch', 'owner or group'),
                                ('GID mismatch', 'owner or group'),
                                ('Modification time mismatch', 'modification time')]:
            with self.subTest(detail=detail):
                out = self.scan(pacman_err=f'warning: demo: /usr/share/demo/data ({detail})\n', pacman_rc=1)
                self.assertIn(meaning, out)
                self.assertIn('RESULT|completed|review|1', out)

    def test_valid_differences_in_both_tools_do_not_reduce_coverage(self):
        out = self.scan(pacman_err='warning: demo: /usr/bin/demo (SHA256 checksum mismatch)\n',
                        pacman_rc=1, paccheck_rc=1,
                        paccheck_out="demo: '/usr/bin/demo' sha256sum mismatch (expected abcd)\n")
        self.assertIn('RESULT|completed|review|2', out)

    def test_unrecognized_output_is_identified_in_the_report(self):
        out = self.scan(paccheck_out='demo: new upstream format\nzlib: all files match mtree sha256sums\n')
        self.assertIn('DIAG|integrity_unparsed', out)
        self.assertIn('paccheck: demo: new upstream format', out)
        self.assertIn('RESULT|partial|unknown|0', out)

    def test_unrecognized_file_reason_is_a_coverage_limit_without_a_detected_change(self):
        for mode in ('pacman', 'paccheck'):
            for reason in ('Input/output error', 'unrecognized upstream reason'):
                with self.subTest(mode=mode, reason=reason):
                    if mode == 'pacman':
                        line = f'warning: demo: /usr/share/demo/data ({reason})\n'
                    else:
                        line = f"warning: demo: '/usr/share/demo/data' {reason}\n"
                    out = self.scan(**{mode + '_err': line, mode + '_rc': 1})
                    self.assertIn('DIAG|integrity_unparsed', out)
                    self.assertIn(mode + ': ' + line.strip(), ' '.join(out.split()))
                    self.assertIn('RESULT|partial|unknown|0', out)

    def test_missing_mtree_explains_unavailable_reference_data(self):
        out = self.scan(paccheck_err='warning: demo: mtree data not available (No such file or directory)\n',
                        paccheck_rc=1)
        self.assertIn('DIAG|integrity_mtree', out)
        self.assertIn('paccheck: warning: demo: mtree data not available', out)
        self.assertIn('RESULT|partial|unknown|0', out)

    def test_read_failure_is_a_coverage_limit_not_a_detected_change(self):
        for mode in ('pacman', 'paccheck'):
            with self.subTest(mode=mode):
                if mode == 'pacman':
                    args = {'pacman_err': 'warning: demo: /usr/share/demo/data (Permission denied)\n'}
                else:
                    args = {'paccheck_err': "warning: demo: '/usr/share/demo/data' read error (Permission denied)\n"}
                out = self.scan(**args)
                self.assertIn('DIAG|integrity_read_error', out)
                self.assertIn(mode + ': warning: demo:', out)
                self.assertIn('RESULT|partial|unknown|0', out)

    def test_error_text_in_a_filename_does_not_become_a_read_failure(self):
        out = self.scan(pacman_err='warning: demo: /usr/share/demo/Permission denied (Permissions mismatch)\n',
                        pacman_rc=1)
        self.assertIn('RESULT|completed|review|1', out)
        self.assertNotIn('DIAG|integrity_read_error', out)

    def test_timeout_and_exit_failure_are_named_even_with_success_lines(self):
        for rc, diagnostic in [(124, 'integrity_timeout'), (2, 'integrity_exit_error')]:
            with self.subTest(rc=rc):
                out = self.scan(paccheck_rc=rc)
                self.assertIn('DIAG|' + diagnostic, out)
                self.assertIn('paccheck: exit=' + str(rc), out)
                self.assertIn('RESULT|partial|unknown|0', out)

    def test_empty_successful_output_does_not_mean_verified(self):
        out = self.scan(paccheck_out='')
        self.assertIn('DIAG|integrity_no_results', out)
        self.assertIn('RESULT|partial|unknown|0', out)

    def test_tool_error_prefix_cannot_be_treated_as_a_completed_file_check(self):
        out = self.scan(pacman_err='error: /usr/share/demo/data (Size mismatch)\n')
        self.assertIn('DIAG|integrity_tool_error', out)
        self.assertIn('RESULT|partial|unknown|0', out)

    def test_exit_one_without_a_difference_is_explained_as_incomplete(self):
        out = self.scan(paccheck_rc=1)
        self.assertIn('DIAG|integrity_exit_unexplained', out)
        self.assertIn('RESULT|partial|unknown|0', out)
