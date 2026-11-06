"""Pure batch orchestration controls with synthetic phases and no processes."""

import argparse
from contextlib import contextmanager, redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import traceback
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SUBJECT = HERE / 'batch_attempt.py'
RECIPES = HERE / 'batch_recipes.py'
RUNNER = HERE / 'runner.py'
METADATA = HERE / 'abi_attempt.py'
GUARD = HERE / 'batch_guard.py'
PINS = {RECIPES: 'C15D57AA9FE3963FF84F22D831F4E1F5F941AC351571AB347ECBC29E9172004B',
        RUNNER: '1B4BFC82D20398FA4F128B368104360C888C27DDBF5104ED74A80819F4371716',
        METADATA: '18237999981DAF689C4D297CC93A9CE574804F1C65578FD4A9E91CD715440279',
        GUARD: '1281084AF70A6AADEA9590E4839311D3F3FA813B17ED06EEE5CD402F4E69BAFD'}
METHODS = 22
BUFFERS, subject, recipes, runner, guard = {}, None, None, None, None
GCC = 'C:/synthetic/bin/arm-none-eabi-gcc.exe'


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def journal(first=0, stop=134):
    return [dict(Label=row['Label'], Argv=[GCC, 'synthetic-only'], State='TERMINAL', TimedOut=False,
        Exit=row['ExpectedExit'], ExpectedExit=row['ExpectedExit'], Seconds=0.25, JournalErrors=[],
        Status='EXPECTED-NONZERO' if row['ExpectedExit'] else 'PASS')
        for row in recipes.batch_plan()['Commands'][first:stop]]


class Watch:
    def __init__(self):
        self.hashes = {}

    def read(self, path, expected=None):
        path = Path(path)
        raw = path.read_bytes()
        value = sha(raw)
        if (expected is not None and value != expected) or (path in self.hashes and self.hashes[path] != value):
            raise ValueError('synthetic input drift')
        self.hashes[path] = value
        return raw

    def close(self):
        for path, expected in self.hashes.items():
            if sha(path.read_bytes()) != expected:
                raise ValueError('synthetic closing input drift')


class FakeSuite:
    """Filesystem fixtures only; no synthetic product is presented as real ELF."""
    def __init__(self, root):
        self.output, self.expected, self.commands, self.phases = root / 'output', {}, [], []
        self._started = False
        self.tools = dict(gcc=Path(GCC))
        self.api = SimpleNamespace(checked_path=lambda path: Path(path))
        self.watch = Watch()
        original = root / 'original.bin'
        original.write_bytes(b'synthetic retained input')
        self.watch.read(original)
        self.report = dict(Status='FAIL', Scope=subject.SCOPE, Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True,
            Cohort=subject.COHORT, SourceInventorySha256=subject.SOURCE, RequiredCellCount=2774,
            RequiredCellsSatisfied=0, Error=None, PrimaryError=None, ClosingErrors=[], FinalReaderRequired=True,
            InputClosureVerified=False, OutputSealVerified=False, **dict.fromkeys((*subject.BUILT, *subject.NONCLAIMS), False))
        self.verify_objects = Mock()
        self.fail_phase = self.promote_phase = self.before_save = self.late_verify = None
        self.calls, self.output_checks = [], 0

    def start(self):
        self.output.mkdir()
        self._started = True
        self.output_identity = self.output.stat().st_dev, self.output.stat().st_ino
        self._save('results.json', self.report)
        self._save('commands.json', [])

    def file(self, name):
        path = self.output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = ('SYNTHETIC NOT ELF: ' + name).encode('ascii')
        path.write_bytes(raw)
        self.expected[name] = sha(raw)
        self.watch.read(path)
        return path

    def binding(self, component, role):
        path = self.file('synthetic/' + component + '/' + role.replace('/', '-') + '.bin')
        return dict(Role=role, Path=str(path), Sha256=sha(path.read_bytes()))

    def build(self, name, first, stop):
        self.calls.append(name)
        if name == self.fail_phase:
            raise ValueError('synthetic phase failure ' + name)
        self.commands.extend(journal(first, stop))
        self.phases.append(dict(Name=name, First=first, Stop=stop, Commands=stop-first))
        self.report.update(Commands=self.commands, Phases=self.phases)
        self.report[dict(ABIControls='ABIControlsBuilt', Isolation='IsolationBuilt',
            CommonAttributes='CommonAttributesBuilt', PortPolicy='PortPolicyBuilt')[name]] = True
        build = dict(Status='BUILT-PENDING-READER', SyntheticOnly=True, Profile='CM3', Mode='Os-lto',
            Linkage='direct', LTO=True, First=first, Stop=stop, Commands=stop-first,
            RequiredCellsSatisfied=0, Qualification=False)
        if name == 'ABIControls':
            self.report['ABIControlsBuild'] = build
            self.report['ABIControlsDeferredReader'] = dict(Status='PENDING', ValidationDeferred=True,
                RequiredCellsSatisfied=0,
                Inputs=[self.binding(name, role) for role in ('OriginalELF', 'ReproducedELF')],
                Map=self.binding(name, 'ReproducedMap'))
            self.report.update(FiveLinkControlsValidated=True, TypedDeclarationProbesValidated=True,
                PositiveAuthority=dict(SyntheticOnly=True, ValidationDeferred=True, LoadImageValidated=False,
                    LoadImageComparison=None), DeclaredProviders=dict(SyntheticOnly=True),
                PreprocessedAttributes=dict(SyntheticOnly=True), ABIProbes={})
            for probe in ('types.c', 'attributes.c', 'slot_read.c', 'slot_write.c', 'slot_address.c'):
                self.report['ABIProbes'][probe] = dict(Object=None, Preprocessed=None, **{field: str(self.file('probes/' + probe + '-' + field))
                    for field in ('Source', 'DiscoveryDependencyFile', 'CompileDependencyFile')})
                row = self.report['ABIProbes'][probe]
                row['SourceSha256'] = sha(Path(row['Source']).read_bytes())
                if probe in ('types.c', 'attributes.c'):
                    row.update({field: str(self.file('probes/' + probe + '-' + field))
                        for field in ('Object', 'Preprocessed')})
                    row['SlimIR'] = dict(SlimIR=True, Object=row['Object'], Sha256=sha(Path(row['Object']).read_bytes()))
                    if probe == 'attributes.c':
                        self.report['PreprocessedAttributes']['PreprocessedSha256'] = sha(Path(row['Preprocessed']).read_bytes())
            deferred = self.report['ABIControlsDeferredReader']
            authority = self.report['PositiveAuthority']
            for item, key in zip(deferred['Inputs'], ('Original', 'Replayed')):
                authority[key], authority[key + 'Sha256'] = item['Path'], item['Sha256']
            authority.update(Map=deferred['Map']['Path'], MapSha256=deferred['Map']['Sha256'], ReaderInputs=deferred['Inputs'])
        elif name == 'Isolation':
            rows = [self.binding(name, role) for role in guard.ISOLATION_ROLES]
            by_role = {row['Role']: row for row in rows}
            providers = [dict(Object=by_role['IsolatedIR' + str(i)]['Path'],
                ObjectSha256=by_role['IsolatedIR' + str(i)]['Sha256']) for i in range(3)]
            linked = []
            for i in range(9):
                item = by_role['IsolatedIR' + str(i)] if i < 3 else by_role['StartupObject'] if i == 8 else self.binding(name, 'linked-' + str(i))
                linked.append(dict(Index=i, Path=item['Path'], Sha256=item['Sha256'], OriginalUnchanged=i >= 3))
            self.report.update(IsolationBuild=build, IsolatedCommon=providers, IsolatedLinkedObjects=linked,
                IsolationDeferredReader=dict(Status='PENDING', ValidationDeferred=True, RequiredCellsSatisfied=0, Inputs=rows))
        elif name == 'CommonAttributes':
            self.report['CommonAttributesDeferredReader'] = dict(build, DeferredReaderRequired=True,
                Lowerings=[dict(Group=group, ValidationDeferred=True, EffectsValidated=False, WorkerOptionsValidated=False,
                    Roles={role: {key: value for key, value in self.binding(name, group + '/' + role).items() if key != 'Role'}
                        for role in guard.COMMON_ROLES}) for group in guard.COMMON_GROUPS])
        else:
            lowers, rows = [], []
            for group in guard.PORT_GROUPS:
                values = [self.binding(name, group + '/' + role) for role in
                    ('Aggregate', 'AggregateDisassembly', 'Machine', 'MachineDisassembly')]
                rows.extend(values)
                lowers.append(dict(Group=group, SupportedPolicy=group != 'stress-raw',
                    Object=values[0]['Path'], ObjectSha256=values[0]['Sha256'],
                    Disassembly={key: value for key, value in values[1].items() if key != 'Role'},
                    ActualWorker=dict(Machine=values[2]['Path'], MachineSha256=values[2]['Sha256']),
                    WorkerDisassembly={key: value for key, value in values[3].items() if key != 'Role'}))
            final_rows = [self.binding(name, 'Final/' + role) for role in
                ('ELF', 'Map', 'Disassembly', 'Machine', 'MachineDisassembly', 'Startup')]
            rows.extend(final_rows)
            objects = [self.binding(name, 'final-object-' + str(i)) for i in range(8)] + [final_rows[-1]]
            final = dict(Path=final_rows[0]['Path'], Sha256=final_rows[0]['Sha256'],
                Map=final_rows[1]['Path'], MapSha256=final_rows[1]['Sha256'],
                Disassembly={key: value for key, value in final_rows[2].items() if key != 'Role'},
                ActualWorker=dict(Machine=final_rows[3]['Path'], MachineSha256=final_rows[3]['Sha256']),
                WorkerDisassembly={key: value for key, value in final_rows[4].items() if key != 'Role'},
                Objects=[row['Path'] for row in objects], UnchangedOtherSixObjects=[
                    dict(Index=i, Path=objects[i]['Path'], Sha256=objects[i]['Sha256']) for i in (0, 1, 2, 6, 7, 8)])
            self.report.update(PortPolicyBuild=build, PortPolicyCompilations=[dict(SyntheticOnly=True)],
                PortPolicyLowerings=lowers, PortPolicyFinalLink=final,
                PortPolicyDeferredReader=dict(Status='PENDING', ValidationDeferred=True,
                    RequiredCellsSatisfied=0, Inputs=rows))
        if name == self.promote_phase:
            self.report['SourceIRProof'] = True
        self._save('commands.json', self.commands)
        return build

    def _save(self, name, value):
        if self.before_save is not None:
            self.before_save(name, value)
        raw = encoded(value)
        (self.output / name).write_bytes(raw)
        self.expected[name] = sha(raw)

    def _verify_outputs(self):
        self.output_checks += 1
        actual = {path.relative_to(self.output).as_posix(): sha(path.read_bytes())
                  for path in self.output.rglob('*') if path.is_file()}
        if actual != self.expected:
            raise ValueError('synthetic output membership/hash drift')
        if self.late_verify is not None:
            self.late_verify(self.output_checks)


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='os-batch-attempt-synthetic-')
        self.addCleanup(self.temporary.cleanup)
        self.suite = FakeSuite(Path(self.temporary.name))
        self.witness = SimpleNamespace(output=self.suite.output, watch=self.suite.watch,
            _physical=lambda path: tuple(getattr(Path(path).stat(), name) for name in ('st_dev', 'st_ino', 'st_nlink', 'st_size')),
            close=self.suite.watch.close, replay_api=SimpleNamespace(files_under=lambda root:
                {path.relative_to(root).as_posix(): path for path in root.rglob('*') if path.is_file()}))
        self.environment = dict(Witness=self.witness)
        self.helpers = dict(recipes=recipes, guard=guard)
        for name, key, first, stop in subject.PHASES:
            self.helpers[key] = SimpleNamespace(build=Mock(side_effect=lambda suite, helpers,
                n=name, a=first, b=stop: suite.build(n, a, b)))

    def run_batch(self):
        with redirect_stdout(io.StringIO()):
            return subject.run(runner, self.environment, self.helpers, self.suite)

    def failure(self):
        row = json.loads((self.suite.output / 'results.json').read_bytes())
        self.assertEqual(row['Status'], 'FAIL')
        self.assertIs(row['InputClosureVerified'], False)
        self.assertIs(row['OutputSealVerified'], False)
        self.assertEqual(row['RequiredCellsSatisfied'], 0)
        self.assertTrue(all(row[name] is False for name in (*subject.BUILT, *subject.NONCLAIMS)))
        return row

    @contextmanager
    def bootstrap(self):
        """Mock only the constructor graph; no authenticated producer executes."""
        payload = b'synthetic pinned module buffer'
        digest = sha(payload)
        def registry(*names):
            return {name: ('tools/synthetic/' + name + '.py', digest) for name in names}
        meta = SimpleNamespace(ARGUMENTS=subject.ARGUMENTS, RUNNER_SHA256=sha(BUFFERS[RUNNER]),
            PINS=registry('session', 'utility', 'lto', 'recipes'), LEAF_PINS=registry('declarations', 'abi_controls'),
            DOCUMENTS={'tools/synthetic/core.py': digest})
        pins = registry(*subject.PINS)
        boot = SimpleNamespace(PINS=registry('admission', 'legacy', 'capture'), DOCUMENTS={}, base_report=lambda witness: {})
        data = {ROOT / path: payload for path, value in [*meta.PINS.values(), *meta.LEAF_PINS.values(),
            *pins.values(), *boot.PINS.values(), *meta.DOCUMENTS.items()]}
        data.update({ROOT / subject.METADATA[0]: BUFFERS[METADATA], RUNNER: BUFFERS[RUNNER], SUBJECT: BUFFERS[SUBJECT]})
        events, enrolled = [], {}
        def read(path):
            events.append(('read', path))
            if path not in data:
                raise AssertionError('unknown bootstrap read')
            return data[path]
        def witness_type(legacy, capture, *, extra_sources):
            events.append(('admit', None))
            enrolled.update(extra_sources)
            return lambda args: SimpleNamespace()
        def construct(environment, helpers, buffers):
            events.append(('suite', None))
            self.assertEqual(enrolled, buffers)
            return SimpleNamespace(report={})
        def loader(name, path, raw):
            if name == '_os_batch_metadata':
                return meta
            if name == '_os_batch_runner':
                return boot
            if name == '_os_batch_admission_admission':
                return SimpleNamespace(witness_type=witness_type)
            if name == '_os_batch_helper_session':
                return SimpleNamespace(suite_type=lambda utility, lto: construct)
            return SimpleNamespace()
        with patch.object(subject, 'PINS', pins), patch.object(Path, 'read_bytes', read), \
                patch.object(subject, 'load', side_effect=loader) as loads:
            yield data, events, enrolled, loads

    def test_all134_commands_build_but_no_reader_or_credit(self):
        report = self.run_batch()
        subject.require_built(report, self.helpers)
        self.assertEqual(report['Status'], 'BUILT-PENDING-READER')
        self.assertEqual(self.suite.calls, [row[0] for row in subject.PHASES])
        self.assertEqual(len(report['Commands']), 134)
        self.assertEqual(sum(row['ExpectedExit'] for row in report['Commands']), 8)
        self.assertTrue(all(report[name] is False for name in subject.NONCLAIMS))

    def test_pending_inputs_are_hash_bound_and_all_components_retained(self):
        report = self.run_batch()
        pending = report['PendingFinalReader']
        self.assertEqual(pending['InputRoleCount'], len(pending['Inputs']))
        self.assertEqual(len(pending['Inputs']), 142)
        for row in pending['Inputs']:
            self.assertEqual(sha(Path(row['Path']).read_bytes()), row['Sha256'])
        self.assertEqual(set(pending['Components']), {row[0] for row in subject.PHASES})
        self.assertIs(pending['FinalReaderExecuted'], False)

    def test_wrong_route_scope_or_mode_is_not_a_built_result(self):
        report = self.run_batch()
        for key, bad in (('Status', 'PASS'), ('Scope', 'whole-cell'), ('Mode', 'O2-lto'), ('Profile', 'CM4'),
                ('Linkage', 'archive'), ('LTO', 1), ('SourceInventorySha256', 'A' * 64), ('Cohort', 'foreign')):
            value = copy.deepcopy(report)
            value[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                subject.require_built(value, self.helpers)

    def test_exact_labels_order_and_expected_exit_plan_are_mandatory(self):
        report = self.run_batch()
        for kind in ('short', 'label', 'order', 'expected'):
            value = copy.deepcopy(report)
            if kind == 'short':
                value['Commands'].pop()
            elif kind == 'label':
                value['Commands'][53]['Label'] = 'foreign'
            elif kind == 'order':
                value['Commands'][53], value['Commands'][54] = value['Commands'][54], value['Commands'][53]
            else:
                row = next(row for row in value['Commands'] if row['ExpectedExit'] == 1)
                row.update(ExpectedExit=0, Exit=0, Status='PASS')
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                subject.require_built(value, self.helpers)

    def test_command_types_timeouts_nonfinite_elapsed_and_journal_faults_reject(self):
        report = self.run_batch()
        for key, bad in (('Exit', False), ('ExpectedExit', 0.0), ('TimedOut', 0), ('State', 'ATTEMPT'),
                ('Status', 'FAIL'), ('Seconds', True), ('Seconds', float('inf')), ('Seconds', -1),
                ('JournalErrors', {}), ('JournalErrors', ['fault']), ('Argv', [])):
            value = copy.deepcopy(report)
            value['Commands'][0][key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                subject.require_built(value, self.helpers)

    def test_phase_coverage_counters_and_clean_error_types_are_literal(self):
        report = self.run_batch()
        for field in ('First', 'Stop', 'Commands'):
            value = copy.deepcopy(report)
            value['Phases'][0][field] = float(value['Phases'][0][field])
            with self.subTest(field=field), self.assertRaises(ValueError):
                subject.require_built(value, self.helpers)
        for key, bad in (('RequiredCellsSatisfied', False), ('RequiredCellCount', 2774.0), ('ToolInvocations', 134.0),
                         ('Error', False), ('PrimaryError', ''), ('ClosingErrors', {})):
            value = copy.deepcopy(report)
            value[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                subject.require_built(value, self.helpers)

    def test_no_reader_semantic_nonclaim_can_be_promoted_or_numeric_aliased(self):
        report = self.run_batch()
        for name in subject.NONCLAIMS:
            for bad in (True, 0, None):
                value = copy.deepcopy(report)
                value[name] = bad
                with self.subTest(name=name, bad=bad), self.assertRaises(ValueError):
                    subject.require_built(value, self.helpers)

    def test_pending_catalog_empty_duplicate_roles_and_fake_reader_reject(self):
        report = self.run_batch()
        for kind in ('empty', 'duplicate', 'reader', 'count', 'hash', 'component', 'coherent-cut'):
            value = copy.deepcopy(report)
            pending = value['PendingFinalReader']
            if kind == 'empty':
                pending['Inputs'] = []
            elif kind == 'duplicate':
                pending['Inputs'][1] = copy.deepcopy(pending['Inputs'][0])
            elif kind == 'reader':
                pending['FinalReaderExecuted'] = True
            elif kind == 'count':
                pending['InputRoleCount'] = float(pending['InputRoleCount'])
            elif kind == 'hash':
                pending['Inputs'][0]['Sha256'] = True
            elif kind == 'coherent-cut':
                pending['Inputs'].pop()
                pending['InputRoleCount'] -= 1
            else:
                pending['Components']['PortPolicy'] = {}
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                subject.require_built(value, self.helpers)

    def test_each_phase_failure_stops_later_phases_without_retry(self):
        for index, (name, key, first, stop) in enumerate(subject.PHASES):
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix='os-batch-phase-fault-') as root:
                self.suite = FakeSuite(Path(root))
                self.witness.output, self.witness.watch, self.witness.close = self.suite.output, self.suite.watch, self.suite.watch.close
                self.suite.fail_phase = name
                with self.assertRaisesRegex(ValueError, 'phase failure'):
                    self.run_batch()
                self.assertEqual(self.suite.calls, [row[0] for row in subject.PHASES[:index+1]])
                receipt = self.failure()
                self.assertEqual(receipt['ToolInvocations'], len(self.suite.commands))
                self.assertEqual(receipt['Commands'], self.suite.commands)

    def test_unclaimed_preexisting_output_never_receives_recovery_writes(self):
        self.suite.output.mkdir()
        marker = self.suite.output / 'results.json'
        marker.write_bytes(b'unrelated preexisting receipt')
        with self.assertRaises(FileExistsError):
            self.run_batch()
        self.assertEqual(marker.read_bytes(), b'unrelated preexisting receipt')
        self.assertFalse((self.suite.output / 'artifacts.json').exists())
        self.assertTrue(self.suite.report['ClosingErrors'])

    def test_replaced_output_is_checked_again_before_each_recovery_write(self):
        self.suite.fail_phase = 'Isolation'
        original_recover, original_write = runner.recover, Path.write_bytes
        def replace_then_recover(environment, report):
            retired = self.suite.output.with_name('retired-owned-output')
            self.suite.output.rename(retired)
            self.suite.output.mkdir()
            original_write(self.suite.output / 'marker.bin', b'unrelated replacement')
            return original_recover(environment, report)
        with patch.object(runner, 'recover', side_effect=replace_then_recover), \
                self.assertRaisesRegex(ValueError, 'phase failure Isolation'):
            self.run_batch()
        self.assertEqual((self.suite.output / 'marker.bin').read_bytes(), b'unrelated replacement')
        self.assertFalse((self.suite.output / 'results.json').exists())
        self.assertFalse((self.suite.output / 'artifacts.json').exists())
        self.assertTrue(any('identity changed' in row for row in self.suite.report['ClosingErrors']))

    def test_phase_semantic_promotion_is_rejected_not_silently_erased(self):
        self.suite.promote_phase = 'CommonAttributes'
        with self.assertRaisesRegex(ValueError, 'semantic promotion'):
            self.run_batch()
        self.assertNotIn('PortPolicy', self.suite.calls)
        self.failure()

    def test_late_input_drift_revokes_build_and_preserves_primary(self):
        self.witness.close = Mock(side_effect=ValueError('late input drift'))
        self.suite.report['PrimaryError'] = 'first primary'
        with self.assertRaisesRegex(ValueError, 'late input drift'):
            self.run_batch()
        self.assertEqual(self.failure()['PrimaryError'], 'first primary')

    def test_post_seal_output_failure_revokes_earlier_built_receipt(self):
        def fail_last(number):
            if number == 2:
                self.assertEqual(json.loads((self.suite.output / 'results.json').read_bytes())['Status'], subject.STATUS)
                raise ValueError('late output drift')
        self.suite.late_verify = fail_last
        with self.assertRaisesRegex(ValueError, 'late output drift'):
            self.run_batch()
        self.failure()

    def test_summary_failure_is_nonzero_and_downgrades_written_build(self):
        with patch('builtins.print', side_effect=BrokenPipeError('summary fault')), \
                self.assertRaisesRegex(BrokenPipeError, 'summary fault'):
            self.run_batch()
        self.assertIn('summary fault', self.failure()['PrimaryError'])

    def test_seal_write_failure_gets_independent_failure_recovery(self):
        def fail_manifest(name, value):
            if name == 'artifacts.json':
                raise OSError('manifest unavailable')
        self.suite.before_save = fail_manifest
        with self.assertRaisesRegex(OSError, 'manifest unavailable'):
            self.run_batch()
        self.assertIn('manifest unavailable', self.failure()['PrimaryError'])

    def test_recovery_error_cannot_replace_first_stage_exception(self):
        self.suite.fail_phase = 'Isolation'
        with patch.object(runner, 'recover', side_effect=OSError('recovery unavailable')), \
                self.assertRaisesRegex(ValueError, 'phase failure Isolation'):
            self.run_batch()
        self.assertEqual(self.suite.report['Status'], 'FAIL')
        self.assertTrue(any('recovery unavailable' in row for row in self.suite.report['ClosingErrors']))

    def test_missing_owner_pin_refuses_before_loading_or_admission(self):
        pins = dict(subject.PINS)
        pins['port_policy'] = (pins['port_policy'][0], None)
        with patch.object(subject, 'PINS', pins), patch.object(subject, 'load') as loader, \
                self.assertRaisesRegex(ValueError, 'unfrozen source pin'):
            subject.prepare(SimpleNamespace())
        loader.assert_not_called()
        self.assertFalse(self.suite.output.exists())

    def test_all_phase_and_helper_bytes_enrolled_before_current_admission(self):
        with self.bootstrap() as (data, events, enrolled, loads):
            unused_runner, environment, helpers, suite = subject.prepare(SimpleNamespace())
            self.assertEqual(enrolled, data)
            cutoff = next(index for index, row in enumerate(events) if row[0] == 'admit')
            self.assertEqual({row[1] for row in events[:cutoff] if row[0] == 'read'}, set(data))
            self.assertFalse(any(row[0] == 'read' for row in events[cutoff:]))
        self.assertFalse(self.suite.output.exists())

    def test_wrong_new_helper_buffer_is_rejected_before_constructor(self):
        with self.bootstrap() as (data, events, enrolled, loads):
            path = ROOT / subject.PINS['attributes_phase'][0]
            data[path] = b'changed source'
            with self.assertRaisesRegex(ValueError, 'fixed source buffer'):
                subject.prepare(SimpleNamespace())
            self.assertEqual(enrolled, {})
            self.assertFalse(any(row[0] == 'admit' for row in events))

    def test_unknown_helper_read_has_no_disk_fallback_after_admission(self):
        with self.bootstrap() as (data, events, enrolled, loads):
            original = loads.side_effect
            def read_unknown(name, path, raw):
                if name == '_os_batch_helper_policy':
                    (ROOT / 'tools/synthetic/unknown.py').read_bytes()
                return original(name, path, raw)
            loads.side_effect = read_unknown
            with self.assertRaisesRegex(ValueError, 'outside opening authenticated buffers'):
                subject.prepare(SimpleNamespace())
            self.assertTrue(enrolled)
        self.assertFalse(self.suite.output.exists())

    def test_final_manifest_binds_actual_closed_bytes_without_self_hash(self):
        report = self.run_batch()
        self.assertEqual(json.loads((self.suite.output / 'results.json').read_bytes()), report)
        manifest = json.loads((self.suite.output / 'artifacts.json').read_bytes())['Artifacts']
        self.assertNotIn('artifacts.json', manifest)
        self.assertEqual(set(manifest), {path.relative_to(self.suite.output).as_posix()
            for path in self.suite.output.rglob('*') if path.is_file() and path.name != 'artifacts.json'})
        for name, digest in manifest.items():
            self.assertEqual(sha((self.suite.output / name).read_bytes()), digest)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if (output.exists() or args.output_dir.is_symlink() or not output.is_relative_to(temporary)
            or output.is_relative_to(ROOT) or ROOT.is_relative_to(output)):
        parser.error('fresh external TEMP output directory required')
    paths = (Path(__file__).resolve(), SUBJECT, RECIPES, RUNNER, METADATA, GUARD)
    report = dict(Status='FAIL', Scope='PURE_SYNTHETIC_OS_134_BUILD_ORCHESTRATION_CONTROLS_ONLY', Tests=0,
        ExpectedTestMethods=METHODS, Errors=0, Failures=0, Skipped=0, SourceHashes={}, SourceDrift=[],
        ClosingFilesVerified=0, SourceClosureVerified=False, SyntheticPhases=True, ConstructorGraphMocked=True,
        ActualCaptureAdmitted=False, ActualCompilerExecuted=False, ActualELFTested=False, FinalReaderExecuted=False,
        Qualification=False, RequiredCellsSatisfied=0, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False)
    try:
        if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode) or sys.flags.optimize:
            raise ValueError('isolated unoptimized -I -S -B Python required')
        BUFFERS.update({path: path.read_bytes() for path in paths})
        report['SourceHashes'] = {str(path): sha(raw) for path, raw in BUFFERS.items()}
        for path, expected in PINS.items():
            if sha(BUFFERS[path]) != expected:
                raise ValueError('fixed helper source identity: ' + str(path))
        global subject, recipes, runner, guard
        with patch('subprocess.Popen', side_effect=AssertionError('pure tests cannot execute tools')), \
                patch('os.system', side_effect=AssertionError('pure tests cannot execute commands')):
            modules = []
            for name, path in (('subject', SUBJECT), ('recipes', RECIPES), ('runner', RUNNER), ('guard', GUARD)):
                module = ModuleType('_os_batch_test_' + name)
                module.__file__ = str(path)
                exec(compile(BUFFERS[path], str(path), 'exec'), module.__dict__)
                modules.append(module)
            subject, recipes, runner, guard = modules
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(BatchTests)
            if suite.countTestCases() != METHODS:
                raise ValueError('exact implemented method count required')
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Errors=len(result.errors), Failures=len(result.failures),
            Skipped=len(result.skipped), Details=[dict(Test=str(case), Error=error)
                for case, error in result.errors + result.failures])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped:
            report['Status'] = 'PASS'
    except BaseException:
        report.update(Status='FAIL', Errors=report['Errors'] + 1, Error=traceback.format_exc())
    finally:
        for path, expected in report['SourceHashes'].items():
            try:
                if sha(Path(path).read_bytes()) == expected:
                    report['ClosingFilesVerified'] += 1
                else:
                    report['SourceDrift'].append(path)
            except OSError:
                report['SourceDrift'].append(path)
        report['SourceClosureVerified'] = len(report['SourceHashes']) == len(paths) and not report['SourceDrift']
        if not report['SourceClosureVerified']:
            report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / 'results.json'
    receipt.write_bytes(encoded(report))
    print('Receipt:', receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
