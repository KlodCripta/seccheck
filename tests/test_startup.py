"""Interactive dependency choices; pacman is always an inert command fixture."""
import os
import pty
import select
import shutil
import subprocess
import time

from test_seccheck import SecCheckCase, SCRIPT


class StartupTests(SecCheckCase):
    def setUp(self):
        super().setUp()
        self.bindir = self.folder / 'bin'
        self.bindir.mkdir()
        for tool in ('bash', 'tr', 'tput', 'readlink', 'cat', 'chmod'):
            (self.bindir / tool).symlink_to(shutil.which(tool))
        for tool in ('rkhunter', 'lynis', 'python3', 'curl', 'paccheck'):
            self.command(tool, 'exit 0\n')
        self.command('sudo', '[[ $1 == -- ]] || exit 2; shift; exec "$@"\n')
        self.command('pacman', '''printf '%s\n' "$@" > "$SC_TEST_DIR/transaction"
printf '#!/usr/bin/env bash\nexit 0\n' > "$SC_TEST_DIR/bin/pacfile"
chmod +x "$SC_TEST_DIR/bin/pacfile"
''')

    def interactive(self, body, answers):
        master, slave = pty.openpty()
        env = dict(os.environ, NO_COLOR='1', TERM='dumb', SC_TEST_DIR=str(self.folder), PATH=str(self.bindir))
        # Distro detection is separately tested against real os-release fixtures.
        # Here only that host boundary is replaced; dependency discovery is real.
        source = 'source "$1"\nsc_is_arch() { return 0; }\n' + body
        process = subprocess.Popen(['/bin/bash', '-c', source, 'test', str(SCRIPT)],
                                   stdin=slave, stdout=slave, stderr=slave, env=env)
        os.close(slave)
        data = b''
        try:
            os.write(master, answers.encode())
            until = time.monotonic() + 8
            while time.monotonic() < until:
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    data += chunk
                elif process.poll() is not None:
                    break
            process.wait(timeout=1)
            self.assertEqual(process.returncode, 0, data.decode(errors='replace'))
            return data.decode(errors='replace')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)

    def test_startup_detects_missing_pacfile_and_decline_reaches_menu(self):
        out = self.interactive('sc_main --lang it --ascii', 'n\n0\n')
        self.assertIn('pacutils', out)
        self.assertIn('mancante', out)
        self.assertLess(out.index('pacutils'), out.index('Scansione completa'))
        self.assertFalse((self.folder / 'transaction').exists())

    def test_accept_installs_only_missing_package_and_rechecks_tools(self):
        out = self.interactive('sc_main --lang it --ascii', 's\n0\n')
        self.assertTrue((self.folder / 'transaction').exists(), out)
        self.assertEqual((self.folder / 'transaction').read_text().splitlines(),
                         ['-S', '--needed', '--', 'pacutils'])
        self.assertIn('Strumenti pronti', out)
        self.assertEqual(out.count('Installare con pacman'), 1, out)

    def test_failed_installation_is_reported_and_menu_remains_available(self):
        self.command('pacman', 'exit 1\n')
        out = self.interactive('sc_main --lang it --ascii', 's\n0\n')
        self.assertIn('Installazione non completata', out)
        self.assertIn('Scansione completa', out)

    def test_complete_dependencies_do_not_prompt_for_installation(self):
        self.command('pacfile', 'exit 0\n')
        out = self.interactive('sc_main --lang it --ascii', '0\n')
        self.assertIn('Strumenti pronti', out)
        self.assertNotIn('Installare con pacman', out)
        self.assertFalse((self.folder / 'transaction').exists())

    def test_demo_does_not_start_dependency_installation(self):
        out = self.interactive('sc_main --lang it --ascii --demo clean', '')
        self.assertIn('DEMO', out)
        self.assertNotIn('Installare con pacman', out)
        self.assertFalse((self.folder / 'transaction').exists())
