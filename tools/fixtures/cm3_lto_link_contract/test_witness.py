"""Pure failure-record controls; no ELF parsing, toolchain or target execution."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

sys.dont_write_bytecode = True
path = Path(__file__).with_name('witness.py')
spec = importlib.util.spec_from_file_location('cm3_link_contract_failure_tests', path)
witness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(witness)


class FailureRecords(unittest.TestCase):
    def fake(self, root):
        instance = witness.Witness.__new__(witness.Witness)
        instance.output = root / 'output'
        instance.report = dict(Status='FAIL', Error=None)
        instance.sha = lambda data: hashlib.sha256(data).hexdigest().upper()
        def save(path, value):
            path.write_text(json.dumps(value, sort_keys=True), encoding='ascii')
        instance.api = SimpleNamespace(save=save,
            files_under=lambda root: {p.relative_to(root).as_posix(): p for p in root.rglob('*') if p.is_file()})
        instance.watch = SimpleNamespace(hashes={})
        instance.identities = {}
        instance.expected = {'results.json', 'artifacts.json'}
        instance.audit = Mock(side_effect=ValueError('deliberate audit refusal'))
        instance.close = Mock()
        return instance

    def test_repeated_seal_failure_refreshes_fail_manifest(self):
        with tempfile.TemporaryDirectory(prefix='cm3-link-failure-') as directory:
            instance = self.fake(Path(directory))
            instance.seal = Mock(side_effect=ValueError('deliberate seal refusal'))
            self.assertFalse(instance.run())
            self.assertEqual(instance.seal.call_count, 1)
            record = json.loads((instance.output / 'results.json').read_bytes())
            manifest = json.loads((instance.output / 'artifacts.json').read_bytes())
            self.assertEqual(record['Status'], 'FAIL')
            self.assertIs(record['OutputSealVerified'], False)
            self.assertEqual(manifest['Artifacts']['results.json'], instance.sha((instance.output / 'results.json').read_bytes()))

    def test_late_success_seal_failure_downgrades_and_refreshes(self):
        with tempfile.TemporaryDirectory(prefix='cm3-link-late-') as directory:
            instance = self.fake(Path(directory))
            instance.audit = Mock()
            instance.seal = Mock(side_effect=ValueError('deliberate late refusal'))
            self.assertFalse(instance.run())
            self.assertEqual(instance.seal.call_count, 2)
            record = json.loads((instance.output / 'results.json').read_bytes())
            manifest = json.loads((instance.output / 'artifacts.json').read_bytes())
            self.assertEqual(record['Status'], 'FAIL')
            self.assertIs(record['InputClosureVerified'], False)
            self.assertIs(record['OutputSealVerified'], False)
            self.assertEqual(manifest['Artifacts']['results.json'], instance.sha((instance.output / 'results.json').read_bytes()))

    def test_closing_physical_identity_change_rejects(self):
        instance = witness.Witness.__new__(witness.Witness)
        instance.watch = SimpleNamespace(close=Mock())
        instance.identities = {Path('input'): dict(Inode=1)}
        instance.identity = Mock(return_value=dict(Inode=2))
        with self.assertRaisesRegex(ValueError, 'physical identity changed'):
            instance.close()
        instance.watch.close.assert_called_once_with()

    def test_copy_refuses_undeclared_escape_or_duplicate(self):
        instance = witness.Witness.__new__(witness.Witness)
        instance.expected = {'results.json'}
        for name in ('results.json', '../escaped.bin', str(Path(__file__).absolute())):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'predetermined output'):
                instance.copy(name, b'not written')


if __name__ == '__main__':
    unittest.main()
