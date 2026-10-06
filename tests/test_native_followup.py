"""Native host-key failure and actionable Lynis reboot feedback."""
from test_seccheck import SecCheckCase


class NativeFollowupTests(SecCheckCase):
    def ssh_check(self, command):
        path = self.command('sshd', command)
        return self.shell('''sc_reset rkhunter; SC_LANG=it; sc_ui_init; SC_RUN_DIR="$SC_TEST_DIR"
sc_add_finding rkhunter suspicious review unconfirmed PermitRootLogin rkh_ssh_root warning
sc_rkh_check_ssh 0; sc_render_details
printf 'RESULT|%s|%s\\n' "${SC_F_PRIORITY[0]}" "${SC_F_CHECK_KEY[0]}"
''', PATH=path)

    def test_missing_host_keys_uses_config_only_without_changing_files(self):
        for value, result, priority in [('no', 'rkh_ssh_disabled', 'suggestion'),
                                         ('yes', 'rkh_ssh_allowed', 'review'),
                                         ('prohibit-password', 'rkh_ssh_keys', 'suggestion')]:
            with self.subTest(value=value):
                out = self.ssh_check('''case $1 in
-T) printf 'sshd: no hostkeys available -- exiting.\\r\\n' >&2; exit 1;;
-G) printf 'permitrootlogin ''' + value + '''\\n';;
*) touch "$SC_TEST_DIR/UNEXPECTED"; exit 9;;
esac
''')
                self.assertIn(f'RESULT|{priority}|{result}', out)
                self.assertIn('chiavi del server', out)
                self.assertIn('no hostkeys', (self.folder / 'rkh-context.0.stderr').read_text())
                self.assertEqual((self.folder / 'rkh-context.0.config.ssh').read_text(),
                                 'permitrootlogin ' + value + '\n')
                self.assertFalse((self.folder / 'UNEXPECTED').exists())

    def test_config_only_failure_or_ambiguous_output_stays_unverified(self):
        for response in ["echo 'unknown option -- G' >&2; exit 255",
                         "echo 'permitrootlogin no'; echo 'configuration warning' >&2",
                         "printf 'permitrootlogin no\\npermitrootlogin yes\\n'",
                         "echo 'unrecognized output'",
                         "echo 'permitrootlogin no'; exit 1"]:
            with self.subTest(response=response):
                out = self.ssh_check('''case $1 in
-T) echo 'sshd: no hostkeys available -- exiting.' >&2; exit 1;;
-G) ''' + response + ''';;
*) exit 9;;
esac
''')
                self.assertIn('RESULT|review|rkh_ssh_unknown', out)
                self.assertNotIn('RESULT|suggestion', out)
                self.assertTrue((self.folder / 'rkh-context.0.config.ssh').exists())

    def test_unrelated_ssh_error_does_not_trigger_fallback(self):
        out = self.ssh_check('''case $1 in
-T) echo 'configuration error: missing option value' >&2; exit 1;;
*) touch "$SC_TEST_DIR/UNEXPECTED"; exit 9;;
esac
''')
        self.assertIn('RESULT|review|rkh_ssh_unknown', out)
        self.assertFalse((self.folder / 'UNEXPECTED').exists())

    def test_host_key_message_with_another_error_does_not_trigger_fallback(self):
        out = self.ssh_check('''case $1 in
-T) printf 'configuration error\nsshd: no hostkeys available -- exiting.\n' >&2; exit 1;;
*) touch "$SC_TEST_DIR/UNEXPECTED"; exit 9;;
esac
''')
        self.assertIn('RESULT|review|rkh_ssh_unknown', out)
        self.assertFalse((self.folder / 'UNEXPECTED').exists())

    def test_host_key_message_with_error_beyond_excerpt_stays_unverified(self):
        out = self.ssh_check('''case $1 in
-T) echo 'sshd: no hostkeys available -- exiting.' >&2
    for ((n=0;n<400;n++)); do printf '\\n' >&2; done
    echo 'configuration error after the excerpt' >&2; exit 1;;
*) touch "$SC_TEST_DIR/UNEXPECTED"; echo 'permitrootlogin no';;
esac
''')
        self.assertIn('RESULT|review|rkh_ssh_unknown', out)
        self.assertFalse((self.folder / 'UNEXPECTED').exists())

    def test_lynis_reboot_warning_has_a_direct_action_and_keeps_evidence(self):
        self.fixture('lynis.dat', 'warning[]=KRNL-5830|Reboot of system is most likely needed|text:reboot||\n')
        out = self.shell('''sc_reset lynis; SC_LANG=it; sc_ui_init
sc_parse_lynis "$SC_TEST_DIR/lynis.dat"
SC_F_CHECK_KEY[0]=followup_manual
sc_render_details
printf 'RESULT|%s\\n' "${SC_F_PRIORITY[0]}"
''')
        self.assertIn('Salva il lavoro', out)
        self.assertIn('riavvia', out)
        self.assertIn('KRNL-5830', out)
        self.assertIn('Reboot of system is most likely needed', out)
        self.assertIn('RESULT|review', out)
        self.assertNotIn('Usalo per chiedere aiuto', out)

    def test_other_lynis_messages_do_not_inherit_reboot_advice(self):
        self.fixture('lynis.dat',
                     'warning[]=KRNL-5830|Unrecognized kernel warning||||\n'
                     'warning[]=OTHER-1234|Reboot of system is most likely needed||||\n')
        out = self.shell('''sc_reset lynis; SC_LANG=it; sc_ui_init
sc_parse_lynis "$SC_TEST_DIR/lynis.dat"; sc_render_details
''')
        self.assertNotIn('Salva il lavoro', out)
        self.assertIn('Unrecognized kernel warning', out)
