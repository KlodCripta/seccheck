"""Guided first baselines use private files and inert scanner boundaries."""
import os
import pty
import select
import subprocess
import time
import unittest
from test_seccheck import SecCheckCase
from test_seccheck import SCRIPT


class BaselineTests(SecCheckCase):
    def setUp(self):
        super().setUp()
        self.db = self.folder / 'db'
        self.db.mkdir(mode=0o700)
        (self.db / 'i18n').mkdir(mode=0o700)
        (self.db / 'i18n/en').write_text('inert language fixture\n')
        self.run = self.folder / 'run'
        self.run.mkdir(mode=0o700)
        self.sample = self.folder / 'sample'
        self.sample.write_text('verified fixture\n')
        self.sample.chmod(0o644)
        self.paths = [self.sample]
        self.path = self.command('pacfile', '''
[[ $1 == --check && $2 == -- ]] || exit 2
f=$3
printf 'file: %s\nowner: fixture\n' "${f#/}"
printf 'owner: %s/user\ngroup: %s/group\n' "$(stat -c %u -- "$f")" "$(stat -c %g -- "$f")"
printf 'mode: %s\n' "$(stat -c %a -- "$f")"
if [[ ${SC_BAD_RECORD:-} == metadata ]]; then printf 'mode: 777\n'; fi
if [[ -L $f ]]; then
  printf 'type: link\ntarget: %s\n' "$(readlink -- "$f")"
else
  printf 'type: file\n'
  h=$(sha256sum -- "$f"); h=${h%% *}
  [[ ${SC_BAD_RECORD:-} != content ]] || h=$(printf '%064d' 0)
  printf 'sha256: %s\n' "$h"
fi
[[ ${SC_BAD_RECORD:-} != nul ]] || printf '\\000'
[[ ${SC_BAD_RECORD:-} != error ]] || { echo 'read error' >&2; exit 1; }
''')
        self.command('rkhunter', '''
[[ $1 != --version ]] || { printf 'Rootkit Hunter 1.4.6\n'; exit; }
action=$1; db=''; log=''; hash=''
while (($#)); do
  case $1 in --dbdir) db=$2; shift;; --logfile) log=$2; shift;; --hash) hash=$2; shift;; esac
  shift
done
[[ $action != --config-check ]] || exit 0
if [[ $action == --propupd ]]; then
  printf 'propupd\n' >> "$SC_TEST_DIR/calls"
  printf 'Version:2026101100\nFormatVersion:1\nHash:%s\nAttributes:Stored\nPkgmgr:\n' "$hash" > "$db/rkhunter.dat"
  while IFS= read -r f; do
    [[ -f $f || -L $f ]] || continue
    h=$(sha256sum -- "$f"); h=${h%% *}; target=''
    [[ ! -L $f ]] || target=$(readlink -f -- "$f")
    attrs=$(stat -c '%i:0%a:%u:%g:%s:%Y' -- "$f")
    [[ ! $attrs =~ ^[0-9]+:0[0-7]{4}: ]] || attrs="${attrs%%:*}:${attrs#*:0}"
    printf 'File:0:%s:%s:%s::0:%s:\n' "$f" "$h" "$attrs" "$target" >> "$db/rkhunter.dat"
  done < "$SC_TEST_DIR/db/rkhunter_prop_list.dat"
  case ${SC_CANDIDATE:-} in
    extra) printf 'File:0:/unchecked/file:%064d:1:0644:0:0:1:1::0::\n' 0 >> "$db/rkhunter.dat";;
    empty) : > "$db/rkhunter.dat";;
    wronghash) sed -i 's/^Hash:.*/Hash:NONE/' "$db/rkhunter.dat";;
    failure) exit 1;;
    concurrent) printf 'existing administrator baseline\n' > "$SC_TEST_DIR/db/rkhunter.dat";;
    legacy) printf 'egrep: warning: egrep is obsolescent; using grep -E\n' >&2;;
    regex) printf 'grep: warning: stray \\ before +\n' >&2;;
    binary) printf '\\000' >&2;;
  esac
  printf 'candidate generated\n' > "$log"
  exit 0
fi
if [[ $action == --check ]]; then
  printf "[00:00:00] Info: Using '%s' as the database directory\n" "$SC_TEST_DIR/db" > "$log"
  printf "Info: No package manager specified: using hash function '%s'\n" "$(command -v sha256sum)" >> "$log"
  if [[ ! -s $SC_TEST_DIR/db/rkhunter.dat ]]; then
    printf "Warning: Checking for prerequisites [ Warning ]\\n         The file of stored file properties (rkhunter.dat) does not exist, and should be created.\\n" >> "$log"
  fi
  case ${SC_REPEAT:-} in
    error) printf 'read error\n' >&2;;
    urgent) printf 'Warning: Possible rootkit detected\n' >> "$log";;
    unfinished) printf 'aborted\n' >> "$log"; exit 1;;
  esac
  printf 'System checks summary\n' >> "$log"
  printf 'System checks summary\n'
  exit 0
fi
exit 2
''')
        self.write_list()
        (self.run / 'rkhunter.log').write_text(
            f"[00:00:00] Info: Using '{self.db}' as the database directory\n"
            "[00:00:00] Info: No package manager specified: using hash function '/usr/bin/sha256sum'\n"
            'Warning: Checking for prerequisites [ Warning ]\n'
            "         The file of stored file properties (rkhunter.dat) does not exist, and should be created.\n"
            'System checks summary\n')

    def write_list(self):
        (self.db / 'rkhunter_prop_list.dat').write_text(
            ''.join(str(p) + '\n' for p in self.paths))

    def setup_shell(self, extra=''):
        return '''sc_reset 'rkhunter lynis integrity'; SC_LANG=it; sc_ui_init
SC_RUN_DIR="$SC_TEST_DIR/run"; SC_STARTED=2026-10-11T00:00:00Z
sc_module_set rkhunter partial rkh_baseline_missing
sc_module_set lynis completed; sc_module_set integrity completed
sc_add_diagnostic rkhunter rkh_baseline_missing 'missing baseline'
SC_FOLLOWUPS_DONE=1
''' + extra

    def execute(self, body, **env):
        return self.shell(self.setup_shell() + body, PATH=self.path, **env)

    def test_preparation_checks_full_native_list_without_propupd(self):
        out = self.execute('sc_baseline_prepare; printf "%s|%s" "$SC_BASELINE_STATE" "$SC_BASELINE_CHECKED"')
        self.assertEqual(out, 'ready|1')
        self.assertFalse((self.folder / 'calls').exists())
        self.assertFalse((self.db / 'rkhunter.dat').exists())

    def test_refusal_and_eof_do_not_create_baseline(self):
        for answer in ('n', ''):
            with self.subTest(answer=answer):
                out = self.execute('sc_offer_baseline < <(printf "%s" "$SC_ANSWER")\n'
                                   'printf "STATE|%s" "$SC_BASELINE_STATE"', SC_ANSWER=answer)
                self.assertIn('STATE|declined', out)
                self.assertIn('non', out.lower())
                self.assertFalse((self.folder / 'calls').exists())
                self.assertFalse((self.db / 'rkhunter.dat').exists())

    def test_success_needs_separate_confirmation_and_retains_first_scan(self):
        before = (self.run / 'rkhunter.log').read_text()
        out = self.execute('''sc_add_finding integrity integrity review observation /etc/example integrity_content ORIGINAL
sc_offer_baseline <<< s
printf 'STATE|%s|%s|%s\n' "$SC_BASELINE_STATE" "${SC_MODULE_STATUS[rkhunter]}" "$SC_REVIEW"
printf 'OBJECTS|%s\n' "${SC_F_OBJECT[*]}"
''')
        self.assertIn('STATE|created|completed|1', out)
        self.assertIn('/etc/example', out)
        self.assertEqual((self.run / 'rkhunter.log').read_text(), before)
        self.assertTrue((self.run / 'rkhunter-repeat.log').exists())
        self.assertTrue((self.db / 'rkhunter.dat').stat().st_size)
        self.assertIn('non', out.lower())
        self.assertIn('riferimento', out)

    def test_existing_nonempty_baseline_is_never_overwritten(self):
        baseline = self.db / 'rkhunter.dat'
        baseline.write_text('existing baseline\n')
        out = self.execute('sc_offer_baseline <<< s; printf "STATE|%s" "$SC_BASELINE_STATE"')
        self.assertIn('STATE|blocked', out)
        self.assertEqual(baseline.read_text(), 'existing baseline\n')
        self.assertFalse((self.folder / 'calls').exists())

    def test_empty_baseline_is_preserved_without_racy_replacement(self):
        (self.db / 'rkhunter.dat').touch()
        out = self.execute('sc_offer_baseline <<< s; printf "STATE|%s" "$SC_BASELINE_STATE"')
        self.assertIn('STATE|blocked', out)
        self.assertEqual((self.db / 'rkhunter.dat').stat().st_size, 0)
        self.assertFalse((self.folder / 'calls').exists())

    def test_unverified_alias_parent_link_blocks_setup(self):
        real = self.folder / 'real'
        real.mkdir()
        (real / 'sample').write_text('fixture\n')
        alias = self.folder / 'alias-dir'
        alias.symlink_to('real', target_is_directory=True)
        self.paths = [alias / 'sample']
        self.write_list()
        # Package data for the alias does not match; resolved leaf data still does.
        original = (self.folder / 'bin/pacfile').read_text()
        self.command('pacfile', '[[ $3 != "$SC_TEST_DIR/alias-dir" ]] || { echo "no package owns \'$3\'"; exit; }\n' + original)
        out = self.execute('sc_offer_baseline <<< s; printf "STATE|%s" "$SC_BASELINE_STATE"')
        self.assertIn('STATE|blocked', out)
        self.assertFalse((self.folder / 'calls').exists())

    def test_nondefault_or_unknown_native_hash_blocks_setup(self):
        log = self.run / 'rkhunter.log'
        original = log.read_text()
        for replacement in ('/usr/bin/sha512sum', '/usr/bin/custom-hash'):
            with self.subTest(replacement=replacement):
                log.write_text(original.replace('/usr/bin/sha256sum', replacement))
                out = self.execute('sc_offer_baseline <<< s; printf "STATE|%s" "$SC_BASELINE_STATE"')
                self.assertIn('STATE|blocked', out)
                self.assertFalse((self.folder / 'calls').exists())

    def test_native_sha256_command_alias_keeps_its_configured_path(self):
        alias = self.folder / 'hash-alias'
        alias.symlink_to('/usr/bin/sha256sum')
        log = self.run / 'rkhunter.log'
        log.write_text(log.read_text().replace('/usr/bin/sha256sum', str(alias)))
        out = self.execute('sc_offer_baseline <<< s; printf "STATE|%s" "$SC_BASELINE_STATE"')
        self.assertIn('STATE|created', out)
        self.assertIn('Hash:' + str(alias), (self.db / 'rkhunter.dat').read_text())

    def test_indirect_flagged_scanner_helper_blocks_setup(self):
        out = self.execute('sc_add_finding integrity integrity review unconfirmed /usr/bin/sed integrity_content FLAGGED\n'
                           'sc_offer_baseline <<< s; printf "STATE|%s" "$SC_BASELINE_STATE"')
        self.assertIn('STATE|blocked', out)
        self.assertFalse((self.folder / 'calls').exists())

    def test_concurrent_target_directory_cannot_count_as_created(self):
        self.command('ln', 'mkdir "$SC_TEST_DIR/db/rkhunter.dat"\nexec /usr/bin/ln "$@"\n')
        out = self.execute('sc_offer_baseline <<< s; printf "STATE|%s" "$SC_BASELINE_STATE"')
        self.assertIn('STATE|failed', out)
        self.assertFalse(list((self.db / 'rkhunter.dat').iterdir()))

    def test_symlink_requires_package_link_and_verified_target(self):
        link = self.folder / 'alias'
        link.symlink_to('sample')
        self.paths.append(link)
        self.write_list()
        out = self.execute('sc_baseline_prepare; printf "%s|%s" "$SC_BASELINE_STATE" "$SC_BASELINE_CHECKED"')
        self.assertEqual(out, 'ready|2')

    def test_native_version_header_and_canonical_link_target_can_be_installed(self):
        link = self.folder / 'alias'
        link.symlink_to('sample')
        self.paths.append(link)
        self.write_list()
        out = self.execute('sc_offer_baseline <<< s; printf "STATE|%s" "$SC_BASELINE_STATE"')
        self.assertIn('STATE|created', out)

    def test_native_four_digit_setuid_mode_is_recorded_correctly(self):
        self.sample.chmod(0o4755)
        out = self.execute('sc_offer_baseline <<< s; printf "STATE|%s" "$SC_BASELINE_STATE"')
        self.assertIn('STATE|created', out)
        self.assertIn(':4755:', (self.db / 'rkhunter.dat').read_text())

    def test_world_writable_properties_or_language_file_blocks_setup(self):
        for path in (self.db / 'rkhunter_prop_list.dat', self.db / 'i18n/en'):
            with self.subTest(path=path.name):
                path.chmod(0o666)
                out = self.execute('sc_offer_baseline <<< s; printf "STATE|%s" "$SC_BASELINE_STATE"')
                self.assertIn('STATE|blocked', out)
                self.assertFalse((self.folder / 'calls').exists())
                path.chmod(0o644)

    def test_file_changed_while_confirmation_was_pending_is_not_registered(self):
        out = self.execute('''sc_baseline_prepare
printf 'different content\n' > "$SC_TEST_DIR/sample"
SC_BASELINE_CONFIRMED=1
sc_baseline_create
printf 'STATE|%s' "$SC_BASELINE_STATE"
''')
        self.assertIn('STATE|failed', out)
        self.assertFalse((self.folder / 'calls').exists())
        self.assertFalse((self.db / 'rkhunter.dat').exists())

    def test_interrupt_saves_report_without_creating_reference(self):
        body = self.setup_shell() + '''sc_baseline_prepare() { kill -TERM "$$"; }
sc_offer_baseline
'''
        result = subprocess.run(['bash', '-c', 'source "$1"\n' + body, 'test', str(SCRIPT)],
                                capture_output=True, text=True, timeout=10,
                                env=dict(os.environ, PATH=self.path, SC_TEST_DIR=str(self.folder), NO_COLOR='1'))
        self.assertEqual(result.returncode, 130, result.stderr + result.stdout)
        self.assertIn('interrupted; consent=0', (self.run / 'report.txt').read_text())
        self.assertIn('rkhunter\tpartial', (self.run / 'modules.tsv').read_text())
        self.assertFalse((self.db / 'rkhunter.dat').exists())

    @unittest.skipUnless(os.geteuid() == 0, 'exercise existing-root terminal flow')
    def test_terminal_followup_consent_does_not_approve_baseline_setup(self):
        for answer, created in ((b's\nn\n0\n', False), (b's\ns\n0\n', True)):
            with self.subTest(answer=answer):
                (self.db / 'rkhunter.dat').unlink(missing_ok=True)
                body = '''source "$1"
sc_parse_args --lang it --scan rkhunter --no-color; sc_ui_init
sc_require_scan_host() { return 0; }
sc_prepare_run() { SC_RUN_DIR="$SC_TEST_DIR/run"; }
sc_run_requested
'''
                master, slave = pty.openpty()
                process = subprocess.Popen(['bash', '-c', body, 'test', str(SCRIPT)],
                                           stdin=slave, stdout=slave, stderr=slave,
                                           env=dict(os.environ, PATH=self.path,
                                                    SC_TEST_DIR=str(self.folder), NO_COLOR='1'))
                os.close(slave)
                data = b''
                try:
                    os.write(master, answer)
                    until = time.monotonic() + 15
                    while time.monotonic() < until:
                        if select.select([master], [], [], 0.1)[0]:
                            try:
                                data += os.read(master, 65536)
                            except OSError:
                                break
                        elif process.poll() is not None:
                            break
                    self.assertEqual(process.wait(timeout=2), 0 if created else 2, data.decode())
                    text = data.decode()
                    self.assertIn('Vuoi che faccia io le verifiche del caso al posto tuo?', text)
                    self.assertIn('Creo il riferimento iniziale e ripeto rkhunter?', text)
                    self.assertEqual((self.db / 'rkhunter.dat').exists(), created)
                    self.assertIn('consent=' + ('1' if created else '0'), (self.run / 'report.txt').read_text())
                finally:
                    if process.poll() is None:
                        process.kill()
                    os.close(master)

    def test_content_metadata_binary_and_error_records_block_setup(self):
        for kind in ('content', 'metadata', 'nul', 'error'):
            with self.subTest(kind=kind):
                out = self.execute('sc_offer_baseline <<< s; printf "STATE|%s" "$SC_BASELINE_STATE"', SC_BAD_RECORD=kind)
                self.assertIn('STATE|blocked', out)
                self.assertFalse((self.folder / 'calls').exists())

    def test_unowned_or_broken_link_blocks_setup(self):
        self.paths = [self.folder / 'broken']
        self.paths[0].symlink_to('missing')
        self.write_list()
        out = self.execute('sc_offer_baseline <<< s; printf "STATE|%s" "$SC_BASELINE_STATE"')
        self.assertIn('STATE|blocked', out)
        self.assertFalse((self.folder / 'calls').exists())

    def test_signature_and_flagged_helper_block_setup(self):
        for obj in ('ROOTKIT', str(self.folder / 'bin/pacfile')):
            out = self.execute('sc_add_finding rkhunter rootkit urgent unconfirmed "$SC_OBJECT" rkh_signature THREAT\n'
                               'sc_offer_baseline <<< s; printf "STATE|%s" "$SC_BASELINE_STATE"', SC_OBJECT=obj)
            self.assertIn('STATE|blocked', out)
            self.assertFalse((self.folder / 'calls').exists())

    def test_review_flagged_helper_is_not_executed(self):
        out = self.execute('sc_add_finding integrity integrity review unconfirmed "$SC_TEST_DIR/bin/pacfile" integrity_content FLAGGED\n'
                           'sc_offer_baseline <<< s; printf "STATE|%s" "$SC_BASELINE_STATE"')
        self.assertIn('STATE|blocked', out)
        self.assertFalse((self.run / 'baseline-file.0.pacfile').exists())

    def test_direct_creation_without_confirmation_cannot_write(self):
        out = self.execute('sc_baseline_prepare; sc_baseline_create; printf "STATUS|%s" "$?"')
        self.assertIn('STATUS|1', out)
        self.assertFalse((self.folder / 'calls').exists())

    def test_unowned_regular_file_blocks_setup(self):
        self.command('pacfile', 'printf "no package owns \'%s\'\\n" "$3"\n')
        out = self.execute('sc_offer_baseline <<< s; printf "STATE|%s" "$SC_BASELINE_STATE"')
        self.assertIn('STATE|blocked', out)
        self.assertFalse((self.folder / 'calls').exists())

    def test_malformed_binary_empty_and_oversized_lists_block_setup(self):
        propfile = self.db / 'rkhunter_prop_list.dat'
        for value in (b'', b'relative/file\n', str(self.sample).encode() + b'\x00\n',
                      b'/tmp/../sample\n', b'x' * 1048577):
            with self.subTest(value=value[:60]):
                propfile.write_bytes(value)
                out = self.execute('sc_offer_baseline <<< s; printf "STATE|%s" "$SC_BASELINE_STATE"')
                self.assertIn('STATE|blocked', out)
                self.assertFalse((self.folder / 'calls').exists())

    def test_missing_and_ambiguous_database_directory_are_not_guessed(self):
        log = self.run / 'rkhunter.log'
        for text in ('System checks summary\n', log.read_text() +
                     "Info: Using '/other/db' as the database directory\n"):
            log.write_text(text)
            out = self.execute('sc_offer_baseline <<< s; printf "STATE|%s" "$SC_BASELINE_STATE"')
            self.assertIn('STATE|blocked', out)
            self.assertFalse((self.folder / 'calls').exists())

    def test_symlink_database_target_is_not_followed(self):
        sentinel = self.folder / 'sentinel'
        sentinel.write_text('original\n')
        (self.db / 'rkhunter.dat').symlink_to(sentinel)
        out = self.execute('sc_offer_baseline <<< s; printf "STATE|%s" "$SC_BASELINE_STATE"')
        self.assertIn('STATE|blocked', out)
        self.assertEqual(sentinel.read_text(), 'original\n')

    def test_bad_candidate_or_concurrent_existing_baseline_is_not_installed(self):
        for kind in ('extra', 'empty', 'wronghash', 'failure', 'concurrent'):
            with self.subTest(kind=kind):
                target = self.db / 'rkhunter.dat'
                target.unlink(missing_ok=True)
                out = self.execute('sc_offer_baseline <<< s; printf "STATE|%s" "$SC_BASELINE_STATE"', SC_CANDIDATE=kind)
                self.assertIn('STATE|failed', out)
                if kind == 'concurrent':
                    self.assertEqual(target.read_text(), 'existing administrator baseline\n')
                else:
                    self.assertFalse(target.exists())

    def test_forwarding_notice_does_not_hide_real_creation_errors(self):
        for kind, state in (('legacy', 'created'), ('regex', 'failed'), ('binary', 'failed')):
            with self.subTest(kind=kind):
                target = self.db / 'rkhunter.dat'
                target.unlink(missing_ok=True)
                out = self.execute('sc_offer_baseline <<< s; printf "STATE|%s" "$SC_BASELINE_STATE"', SC_CANDIDATE=kind)
                self.assertIn('STATE|' + state, out)
                self.assertEqual(target.exists(), state == 'created')

    def test_repeat_error_or_unfinished_output_never_becomes_complete(self):
        for kind in ('error', 'unfinished'):
            with self.subTest(kind=kind):
                (self.db / 'rkhunter.dat').unlink(missing_ok=True)
                out = self.execute('sc_offer_baseline <<< s; printf "STATUS|%s|%s" "${SC_MODULE_STATUS[rkhunter]}" "$SC_ASSESSMENT"', SC_REPEAT=kind)
                self.assertIn('STATUS|partial|unknown', out)

    def test_repeat_retains_prior_unexplained_rootkit_finding(self):
        out = self.execute('sc_add_finding rkhunter rootkit review unconfirmed /dev/shm/unknown rkh_dev_file ORIGINAL\n'
                           'sc_offer_baseline <<< s; printf "RESULT|%s|%s" "$SC_ASSESSMENT" "$SC_REVIEW"')
        self.assertIn('RESULT|review|1', out)

    def test_noninteractive_scan_does_not_offer_or_create_baseline(self):
        body = self.setup_shell() + '''sc_require_scan_host() { :; }
sc_scan_once() { printf 'SCAN\n'; return 2; }
SC_SCAN=rkhunter
sc_run_requested; printf 'EXIT|%s' "$?"
'''
        result = subprocess.run(['/bin/bash', '-c', 'source "$1"\n' + body, 'test', str(SCRIPT)],
                                capture_output=True, text=True, timeout=10,
                                env=dict(os.environ, PATH=self.path, SC_TEST_DIR=str(self.folder), NO_COLOR='1'))
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        if os.geteuid() == 0:
            self.assertEqual(result.stdout, 'SCAN\nEXIT|2')
            self.assertEqual(result.stderr, '')
        else:
            self.assertEqual(result.stdout, 'EXIT|77')
            self.assertIn('sudo', result.stderr)
            self.assertIn('non interattiva', result.stderr)
        self.assertFalse((self.folder / 'calls').exists())
