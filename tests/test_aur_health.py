"""Official metadata fixtures; curl and pacman are inert command-boundary doubles."""
import json
import os
import time

from test_seccheck import SecCheckCase


class AurHealthTests(SecCheckCase):
    def setUp(self):
        super().setUp()
        self.state = self.folder / 'state'
        self.state.mkdir(mode=0o700)
        self.run = self.folder / 'run'
        self.run.mkdir(mode=0o700)
        self.path = self.command('pacman', 'printf "demo 1.0-1\\nlocal-only 1.0-1\\n"\n')
        self.command('vercmp', '[[ "$1" == "$2" ]] && echo 0 || echo -1\n')
        self.command('curl', '[[ "$*" == *"/packages/"* ]] && cat "$SC_TEST_DIR/page.html" || cat "$SC_TEST_DIR/rpc.json"\n')
        self.package = dict(Name='demo', PackageBase='demo', Version='1.0-1',
                            Maintainer='alice', CoMaintainers=['bob'],
                            LastModified=int(time.time()), OutOfDate=None)
        self.write_response()
        self.fixture('page.html', '<tr class="pkgmaint"><th>Maintainer:</th><td>alice (bob)</td></tr>')

    def write_response(self):
        self.fixture('rpc.json', json.dumps(dict(version=5, type='multiinfo', resultcount=1, results=[self.package])))

    def scan(self, extra=''):
        return self.shell('sc_reset aur-health; SC_LANG=en; SC_OFFLINE=0\n'
                          'SC_RUN_DIR="$SC_TEST_DIR/run"; SC_STATE_DIR="$SC_TEST_DIR/state"\n'
                          + extra + '\nsc_run_aur_health\n'
                          'printf "%s|%s|%s\\n" "${SC_MODULE_STATUS[aur-health]}" "${SC_MODULE_REASON[aur-health]}" "${SC_HEALTH_NOTE-}"\n'
                          'printf "%s\\n" "${SC_F_KEY[@]}"', PATH=self.path)

    def seed_baseline(self, maintainer='alice', co=None):
        data = dict(schema=1, observed_at=1, packages={'demo': dict(
            maintainer=maintainer, co_maintainers=['bob'] if co is None else co, base='demo', seen_at=1)})
        (self.state / 'aur-maintainers.json').write_text(json.dumps(data))
        return (self.state / 'aur-maintainers.json').read_bytes()

    def test_first_observation_is_baseline_not_maintainer_change(self):
        out = self.scan()
        self.assertIn('completed||health_baseline', out)
        self.assertNotIn('health_maintainer', out)
        baseline = json.loads((self.state / 'aur-maintainers.json').read_text())
        self.assertEqual(baseline['packages']['demo']['co_maintainers'], ['bob'])
        self.assertEqual((self.state / 'aur-maintainers.json').stat().st_mode & 0o777, 0o600)

    def test_orphan_flag_age_and_available_update_remain_distinct(self):
        self.package.update(Maintainer=None, CoMaintainers=[], Version='2.0-1',
                            OutOfDate=1700000000, LastModified=int(time.time())-400*86400)
        self.write_response()
        out = self.scan()
        for key in ('health_orphan', 'health_flagged', 'health_inactive', 'health_upgrade'):
            self.assertIn(key, out)
        self.assertNotIn('abandoned', out)

    def test_primary_and_added_removed_co_maintainers_are_reported(self):
        self.seed_baseline(maintainer='old-owner', co=['carol'])
        out = self.scan()
        for key in ('health_maintainer', 'health_co_added', 'health_co_removed'):
            self.assertIn(key, out)

    def test_first_foreign_package_absent_from_aur_is_not_called_removed(self):
        out = self.scan()
        self.assertIn('health_unlisted', out)
        self.assertNotIn('health_removed', out)

    def test_previously_seen_package_absent_from_aur_is_reported(self):
        self.seed_baseline()
        self.fixture('rpc.json', '{"version":5,"type":"multiinfo","resultcount":0,"results":[]}')
        self.assertIn('health_removed', self.scan())

    def test_network_failure_preserves_baseline_and_does_not_report_removal(self):
        before = self.seed_baseline()
        self.command('curl', 'echo "network unavailable" >&2; exit 7\n')
        out = self.scan()
        self.assertIn('partial|', out)
        self.assertNotIn('health_removed', out)
        self.assertEqual(before, (self.state / 'aur-maintainers.json').read_bytes())

    def test_invalid_json_preserves_baseline(self):
        before = self.seed_baseline()
        self.fixture('rpc.json', '<html>upstream challenge</html>')
        self.assertIn('partial|', self.scan())
        self.assertEqual(before, (self.state / 'aur-maintainers.json').read_bytes())

    def test_missing_required_metadata_is_not_inferred_to_be_orphaned(self):
        del self.package['Maintainer']
        self.write_response()
        out = self.scan()
        self.assertIn('partial|', out)
        self.assertNotIn('health_orphan', out)

    def test_missing_comaintainer_field_uses_public_maintainer_row(self):
        self.seed_baseline(co=['carol'])
        del self.package['CoMaintainers']
        self.write_response()
        out = self.scan()
        self.assertIn('completed|', out)
        self.assertIn('health_co_added', out)

    def test_failed_maintainer_page_is_unknown_not_empty(self):
        before = self.seed_baseline()
        del self.package['CoMaintainers']
        self.write_response()
        self.fixture('page.html', '<html>Access denied</html>')
        out = self.scan()
        self.assertIn('partial|', out)
        self.assertNotIn('health_co_removed', out)
        self.assertEqual(before, (self.state / 'aur-maintainers.json').read_bytes())

    def test_truncated_maintainer_row_does_not_remove_co_maintainers(self):
        before = self.seed_baseline()
        del self.package['CoMaintainers']
        self.write_response()
        self.fixture('page.html', '<tr class="pkgmaint"><th>Maintainer:</th><td>alice')
        out = self.scan()
        self.assertIn('partial|', out)
        self.assertNotIn('health_co_removed', out)
        self.assertEqual(before, (self.state / 'aur-maintainers.json').read_bytes())

    def test_python_ignores_modules_from_cwd_and_pythonpath(self):
        self.fixture('json.py', 'from pathlib import Path\nPath("EXECUTED").touch()\nraise RuntimeError("untrusted module executed")\n')
        out = self.scan('cd "$SC_TEST_DIR"\nexport PYTHONPATH="$SC_TEST_DIR"')
        self.assertFalse((self.folder / 'EXECUTED').exists())
        self.assertIn('completed|', out)

    def test_known_primary_change_is_retained_when_co_maintainers_are_unavailable(self):
        self.seed_baseline(maintainer='old-owner')
        del self.package['CoMaintainers']
        self.write_response()
        self.fixture('page.html', '<html>Access denied</html>')
        out = self.scan()
        self.assertIn('partial|', out)
        self.assertIn('health_maintainer', out)

    def test_abandoned_temporary_snapshot_does_not_block_future_runs(self):
        self.seed_baseline()
        (self.state / 'aur-maintainers.next').write_text('interrupted write')
        self.assertIn('completed|', self.scan())

    def test_offline_never_queries_remote_or_updates_baseline(self):
        before = self.seed_baseline()
        self.command('curl', 'touch "$SC_TEST_DIR/QUERIED"; exit 99\n')
        out = self.scan('SC_OFFLINE=1')
        self.assertIn('skipped|offline', out)
        self.assertFalse((self.folder / 'QUERIED').exists())
        self.assertEqual(before, (self.state / 'aur-maintainers.json').read_bytes())

    def test_terminal_controls_in_metadata_are_rejected(self):
        self.package['Maintainer'] = 'bad\x1b[31m'
        self.write_response()
        self.assertIn('partial|', self.scan())

    def test_api_result_for_an_unrequested_package_is_rejected(self):
        self.package['Name'] = 'injected'
        self.write_response()
        self.assertIn('partial|', self.scan())
