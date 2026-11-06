"""Pure synthetic constructor/projection controls; no capture or ELF replay."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SUBJECT = HERE / 'witness.py'
CONTRACT = HERE / 'CONTRACT.md'
CAPTURE = HERE.with_name('cm3_current_lto_capture') / 'capture.py'
FILES = (Path(__file__).resolve(), SUBJECT, CONTRACT, CAPTURE)
CAPTURE_SHA = '1191CDCDA9FC9312B09858D6439674DBCA19ABFCE5B0108F3575AEF3C65C0852'
CONTRACT_SHA = 'DAEB282DE77E2A258A66B87651CB5302BE358A7E3B3A1AF194D089D070BA2AFB'
SOURCE_SHA = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
COHORT = 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default'
EXPECTED_METHODS = 15
buffers = {}
subject = capture = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode('ascii')


def same(actual, expected, message):
    if encoded(actual) != encoded(expected):
        raise ValueError('synthetic binding: ' + message)


def stable(path, **unused):
    return Path(os.path.abspath(path))


def digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789ABCDEF' for c in value):
        raise ValueError('synthetic SHA256')
    return value


def load(name, path, raw):
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def setUpModule():
    global buffers, subject, capture
    if not buffers:
        buffers = {path: path.read_bytes() for path in FILES}
    if sha(buffers[CAPTURE]) != CAPTURE_SHA or sha(buffers[CONTRACT]) != CONTRACT_SHA:
        raise ValueError('fixed capture/contract source bytes')
    subject = load('_runtime_binding_admission_subject', SUBJECT, buffers[SUBJECT])
    capture = load('_runtime_binding_admission_capture', CAPTURE, buffers[CAPTURE])


class Watch:
    """In-memory hashes only: this does not exercise filesystem admission."""
    def __init__(self, fixture):
        self.fixture = fixture
        self.hashes, self.buffers, self.trees, self.memberships = {}, {}, {}, {}
        self.denied = set()

    def read(self, path, expected=None):
        path = stable(path)
        raw = self.fixture.memory[path]
        value = sha(raw)
        if expected is not None and value != expected:
            raise ValueError('synthetic expected hash mismatch')
        if path in self.hashes and self.hashes[path] != value:
            raise ValueError('synthetic input drift')
        self.hashes[path] = value
        if path.suffix == '.py':
            self.buffers[path] = raw
        return raw

    def tree(self, root, expected):
        root = stable(root)
        actual = {path.relative_to(root).as_posix(): sha(raw)
                  for path, raw in self.fixture.memory.items() if path.is_relative_to(root)}
        same(actual, expected, 'complete synthetic membership')
        self.trees[root], self.memberships[root] = dict(expected), set(expected)
        for name, value in expected.items():
            self.read(root / name, value)

    def close(self):
        self.fixture.events.append('close')
        if self.fixture.fail_close:
            raise ValueError('synthetic closing refusal')
        for path, value in tuple(self.hashes.items()):
            self.read(path, value)


def descriptor(root, receipt, manifest):
    return dict(Build=str(root), ReceiptSha256=receipt * 64, ArtifactsSha256=manifest * 64)


class Fixture:
    def __init__(self):
        self.root = stable(Path(tempfile.gettempdir()) / ('binding-admission-virtual-' + uuid.uuid4().hex))
        self.events, self.memory, self.fail_close = [], dict(buffers), False
        self.sources = dict(buffers)
        self.current_descriptor = descriptor(self.root / 'inventory', 'A', 'B')
        self.seed_descriptor = descriptor(self.root / 'seed', 'C', 'D')
        self.capture_descriptor = descriptor(self.root / 'capture', 'E', 'F')
        self.current = dict(Bundle=dict(Root=self.root / 'inventory', Descriptor=copy.deepcopy(self.current_descriptor)),
            SourceInventorySha256=SOURCE_SHA, Required=dict(RequiredCellCount=2774))
        self.args = SimpleNamespace(inventory=self.current_descriptor['Build'], inventory_receipt_sha256='A' * 64,
            inventory_artifacts_sha256='B' * 64, capture_build=self.capture_descriptor['Build'],
            capture_receipt_sha256='E' * 64, capture_artifacts_sha256='F' * 64, output_dir=str(self.root / 'output'))
        self.seed_sources, rows = [], []
        for index in range(9):
            source = str(self.root / 'seed/source' / ('unit-%d.' % index + ('S' if index == 8 else 'c')))
            flags = ['-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-O2']
            common = dict(Source=source, SourceSha256=sha(('invented TU %d' % index).encode('ascii')))
            self.seed_sources.append(dict(common, CompileFlags=list(flags)))
            rows.append(dict(common, CompileFlags=list(flags) if index == 8 else flags + ['-flto', '-fno-fat-lto-objects'],
                             Object=str(self.root / 'capture/objects' / ('%02d-unit.o' % index))))
        self.result = dict(Status='PASS', Error=None, PrimaryError=None, ClosingErrors=[], Profile='CM3', Mode='O2-lto',
            Scope='NATIVE_CM3_O2_LTO_CAPTURE_FEASIBILITY_ONLY', Cohort=COHORT, TranslationUnits=9, SlimIRObjects=8,
            CaptureContract='CURRENT_CM3_LTO_SOURCE_CAPTURE_V1', CurrentCaptureRoute='CM3/O2-lto/direct/native',
            SourceInventorySha256=SOURCE_SHA, SourceInventoryReceipt=self.current_descriptor['Build'],
            CurrentInventory=copy.deepcopy(self.current_descriptor), SeedAuthority=copy.deepcopy(self.seed_descriptor),
            SeedBuild=self.seed_descriptor['Build'], SeedReceiptSha256='C' * 64, SeedArtifactsSha256='D' * 64,
            CaptureProducer=dict(Path=str(CAPTURE), Sha256=CAPTURE_SHA), Sources=rows,
            InputClosureVerified=True, OutputSealVerified=True, Linkage='direct', LTO=True,
            RequiredCellSatisfied=False, RequiredCellsSatisfied=0, RequiredCellCount=2774,
            SavedMachineObjects=2, FinalExecutableLinks=2, Links=[dict(Kind='ordinary'), dict(Kind='emit-relocs')],
            TwinLoadImageCompared=True, TwinLoadImageIdentical=True, TwinAllocatedSectionsIdentical=True,
            TwinLoadImages=dict(Identical=True), Commands=[dict(State='TERMINAL', Status='PASS', Exit=0,
                TimedOut=False, Error=None, Argv=['synthetic-command-%d' % index]) for index in range(57)])
        self.result.update(dict.fromkeys(capture.NONCLAIMS, False))
        self.bundle = dict(Root=self.root / 'capture', Result=self.result, Artifacts={'synthetic': '0' * 64},
                           Descriptor=copy.deepcopy(self.capture_descriptor))
        self.outer, self.prepared_watch, self.seed_watch = Watch(self), Watch(self), Watch(self)
        helper = self.root / 'seed/helper.py'
        self.memory[helper] = b'# synthetic Seed helper, never executed\n'
        self.seed_watch.read(helper)
        self.seed = SimpleNamespace(result=dict(Profile='CM3', Mode='O2'), sources=self.seed_sources,
            originals={}, buffers={helper: self.memory[helper]}, closure=self.seed_watch)
        self.prepared = dict(Watch=self.prepared_watch, Seed=self.seed,
            Current=dict(Bundle=dict(Descriptor=copy.deepcopy(self.current_descriptor))),
            Group=dict(Descriptor=copy.deepcopy(self.seed_descriptor)), Producer=copy.deepcopy(self.result['CaptureProducer']),
            Model=dict(Side='native', SeedMode='O2'))
        self.legacy_result = None
        self.reachable_inventory = True
        self.api = SimpleNamespace(checked_path=stable, regular=stable, same=same,
            mode_flags=lambda flags: list(flags) + ['-flto', '-fno-fat-lto-objects'], link_flags=lambda *args: list(args))
        fixture = self

        class Admission:
            def __init__(self, watch):
                if watch is not fixture.outer:
                    raise AssertionError('wrong outer admission watch')

            def snapshot(self, value, *, current=False):
                fixture.events.append('snapshot')
                same(value, fixture.current_descriptor, 'caller inventory descriptor')
                if current is not True:
                    raise AssertionError('current inventory admission required')
                return fixture.current

            def bundle(self, value):
                fixture.events.append('bundle')
                same(value, fixture.capture_descriptor, 'caller capture descriptor')
                return fixture.bundle

            def require_inventory_binding(self, bundle, snapshot, *, required=True):
                fixture.events.append('inventory-binding')
                if bundle is not fixture.bundle or snapshot is not fixture.current or required is not True:
                    raise AssertionError('wrong required reachable inventory binding')
                if not fixture.reachable_inventory:
                    raise ValueError('synthetic foreign reachable inventory')

        class Legacy:
            def __init__(self, args):
                fixture.events.append('legacy')
                self.api, self.watch = fixture.api, Watch(fixture)
                self.root, self.output = fixture.root / 'capture', stable(args.output_dir)
                self.buffers, self.identities = {}, {}
                self.authority = SimpleNamespace(result=fixture.result if fixture.legacy_result is None else fixture.legacy_result)
                self.report = dict(RequiredCellsSatisfied=0, FullABIProof=False, CpuExecution=False,
                                   BoardExecution=False, GlobalFreezeQualified=False)

            def identity(self, path):
                return dict(Device=1, Inode=1, Links=1, Size=len(fixture.memory[stable(path)]))

            def close(self):
                self.watch.close()

        class Recipe:
            @staticmethod
            def _commands(witness, side, group, facade):
                fixture.events.append('recipe')
                same(side, 'Native', 'native command projection')
                same(group['Result']['Commands'], fixture.result['Commands'], 'raw commands unchanged')
                for index, row in enumerate(group['Result']['Sources']):
                    seed_flags = fixture.seed_sources[index]['CompileFlags']
                    same(row['SeedCompileFlags'], seed_flags, 'independent Seed flags')
                    flags = facade.startup_flags(seed_flags) if index == 8 else facade.mode_flags(seed_flags)
                    same(row['CompileFlags'], flags, 'independent recipe-derived captured flags')
                same(facade.link_flags(witness.api, 'synthetic-link'), ['synthetic-link'], 'O2 link facade')
                fixture.command_result = group['Result']
                group['CommandsReconstructed'] = len(group['Result']['Commands'])

        def checked_evidence_path(value, *, directory=False):
            if type(directory) is not bool:
                raise ValueError('synthetic literal directory selector')
            path = stable(value)
            directories = {fixture.root / name for name in ('inventory', 'seed', 'capture')}
            if directory:
                if path not in directories:
                    raise ValueError('synthetic expected evidence directory')
            elif path not in fixture.memory or path in directories:
                raise ValueError('synthetic expected evidence file, not directory')
            return path

        self.replay = replay = SimpleNamespace(Admission=Admission, checked_path=checked_evidence_path,
                                               digest=digest, same=same)
        frontend = SimpleNamespace(SOURCE_SHA=SOURCE_SHA, CombinedClosure=capture.CombinedClosure,
            select=capture.select, require_capture=capture.require_capture,
            load_environment=lambda: (dict(replay=replay), self.outer), prepare=self.prepare)
        self.modules = dict(legacy=SimpleNamespace(Witness=Legacy), capture=frontend, recipe=SimpleNamespace(Witness=Recipe))

    def prepare(self, args):
        self.events.append('prepare')
        same([args.side, args.mode, args.seed_build, args.seed_receipt_sha256, args.seed_artifacts_sha256],
             ['native', 'O2-lto', self.seed_descriptor['Build'], 'C' * 64, 'D' * 64], 'exact native O2 Seed request')
        return self.prepared

    def construct(self):
        return subject.witness_type(self.modules, self.sources)(self.args)


class Controls(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch('subprocess.Popen', side_effect=AssertionError('no processes in admission controls')))
        self.enterContext(patch('os.system', side_effect=AssertionError('no shell in admission controls')))
        self.mkdir = self.enterContext(patch.object(Path, 'mkdir', side_effect=AssertionError('constructor created output')))

    def rejected(self, fixture):
        with self.assertRaises((ValueError, AssertionError)):
            fixture.construct()
        self.mkdir.assert_not_called()
        self.assertFalse(stable(fixture.args.output_dir).exists())

    def test_actual_o2_metadata_admits_without_invented_seed_fields(self):
        fixture = Fixture()
        original = encoded(fixture.result)
        self.assertNotIn('SeedMode', fixture.result)
        self.assertNotIn('SeedSide', fixture.result)
        witness = fixture.construct()
        self.assertEqual(encoded(fixture.result), original)
        self.assertEqual(witness.report['CommandsReconstructed'], 57)
        self.assertEqual(witness.report['RequiredCellsSatisfied'], 0)
        self.assertFalse(witness.report['RuntimeProviderBindingsValidated'])
        self.assertFalse(witness.created_output)
        self.assertLess(fixture.events.index('inventory-binding'), fixture.events.index('legacy'))
        self.assertEqual(fixture.events.count('prepare'), 1)
        self.assertEqual(fixture.events.count('recipe'), 1)
        self.mkdir.assert_not_called()

    def test_slash_spelled_raw_descriptors_admit_without_rewriting_capture(self):
        fixture = Fixture()
        for field in ('CurrentInventory', 'SeedAuthority'):
            fixture.result[field]['Build'] = Path(fixture.result[field]['Build']).as_posix()
        for field in ('SourceInventoryReceipt', 'SeedBuild'):
            fixture.result[field] = Path(fixture.result[field]).as_posix()
        fixture.args.inventory = Path(fixture.args.inventory).as_posix()
        fixture.args.capture_build = Path(fixture.args.capture_build).as_posix()
        original = encoded(fixture.result)
        witness = fixture.construct()
        self.assertEqual(encoded(fixture.result), original)
        self.assertEqual(witness.report['CurrentInventory'], fixture.current_descriptor)
        self.assertEqual(witness.report['SeedAuthority'], fixture.seed_descriptor)
        self.assertEqual(witness.report['CommandsReconstructed'], 57)
        self.assertFalse(witness.created_output)
        self.mkdir.assert_not_called()

    def test_declared_descriptors_reject_foreign_roots_and_nonexact_keys(self):
        for field in ('CurrentInventory', 'SeedAuthority'):
            for change in ('foreign-root', 'extra-key', 'missing-key'):
                with self.subTest(field=field, change=change):
                    fixture = Fixture()
                    value = fixture.result[field]
                    if change == 'foreign-root':
                        value['Build'] = (fixture.root / 'foreign-authority').as_posix()
                    elif change == 'extra-key':
                        value['Command'] = 'unapproved'
                    else:
                        del value['ArtifactsSha256']
                    self.rejected(fixture)
                    self.assertNotIn('legacy', fixture.events)

    def test_inventory_receipt_requires_explicit_directory_admission(self):
        fixture = Fixture()
        inventory = fixture.root / 'inventory'
        with self.assertRaisesRegex(ValueError, 'expected evidence file'):
            fixture.replay.checked_path(inventory)
        self.assertEqual(fixture.replay.checked_path(inventory.as_posix(), directory=True), inventory)
        with self.assertRaisesRegex(ValueError, 'expected evidence directory'):
            fixture.replay.checked_path(SUBJECT, directory=True)
        self.assertEqual(fixture.replay.checked_path(SUBJECT), SUBJECT)
        witness = fixture.construct()
        self.assertEqual(witness.report['SourceInventoryReceipt'], str(inventory))
        self.assertFalse(witness.created_output)
        self.mkdir.assert_not_called()

    def test_caller_hashes_and_current_snapshot_authority_reject(self):
        for field in ('inventory_receipt_sha256', 'inventory_artifacts_sha256',
                      'capture_receipt_sha256', 'capture_artifacts_sha256'):
            with self.subTest(field=field):
                fixture = Fixture()
                setattr(fixture.args, field, '9' * 64)
                self.rejected(fixture)
                self.assertNotIn('legacy', fixture.events)
        for value in (True, 2774.0, 2773):
            with self.subTest(count=value):
                fixture = Fixture()
                fixture.current['Required']['RequiredCellCount'] = value
                self.rejected(fixture)
        fixture = Fixture()
        fixture.current['SourceInventorySha256'] = '9' * 64
        self.rejected(fixture)

    def test_capture_producer_inventory_and_reachable_facts_reject(self):
        for field in ('CaptureProducer', 'CurrentInventory', 'SourceInventoryReceipt'):
            with self.subTest(field=field):
                fixture = Fixture()
                if field == 'CaptureProducer':
                    fixture.result[field]['Sha256'] = '9' * 64
                elif field == 'CurrentInventory':
                    fixture.result[field]['ReceiptSha256'] = '9' * 64
                else:
                    fixture.result[field] = str(fixture.root / 'foreign-inventory')
                self.rejected(fixture)
                self.assertNotIn('legacy', fixture.events)
        fixture = Fixture()
        fixture.reachable_inventory = False
        self.rejected(fixture)

    def test_prepared_seed_and_model_are_independent_authority(self):
        for where, key, value in (('result', 'Profile', 'CM4'), ('result', 'Mode', 'Os'),
                                  ('model', 'Side', 'reference'), ('model', 'SeedMode', 'Os')):
            with self.subTest(where=where, key=key):
                fixture = Fixture()
                target = fixture.seed.result if where == 'result' else fixture.prepared['Model']
                target[key] = value
                self.rejected(fixture)
                self.assertNotIn('legacy', fixture.events)
        for field in ('Current', 'Group', 'Producer'):
            with self.subTest(field=field):
                fixture = Fixture()
                if field == 'Current':
                    fixture.prepared[field]['Bundle']['Descriptor']['ReceiptSha256'] = '9' * 64
                elif field == 'Group':
                    fixture.prepared[field]['Descriptor']['ReceiptSha256'] = '9' * 64
                else:
                    fixture.prepared[field]['Sha256'] = '9' * 64
                self.rejected(fixture)
        fixture = Fixture()
        fixture.result['SeedAuthority']['ReceiptSha256'] = '9' * 64
        self.rejected(fixture)

    def test_raw_compile_flags_are_checked_not_used_as_seed_oracle(self):
        fixture = Fixture()
        fixture.result['Sources'][0]['CompileFlags'][3] = '-Os'
        self.rejected(fixture)
        self.assertIn('recipe', fixture.events)

    def test_legacy_authority_must_equal_modern_capture(self):
        fixture = Fixture()
        fixture.legacy_result = copy.deepcopy(fixture.result)
        fixture.legacy_result['Cohort'] = 'foreign'
        self.rejected(fixture)
        self.assertNotIn('recipe', fixture.events)

    def test_bootstrap_buffer_drift_and_preoutput_closing_reject(self):
        fixture = Fixture()
        fixture.sources[SUBJECT] += b'\n# unadmitted change\n'
        self.rejected(fixture)
        self.assertNotIn('legacy', fixture.events)
        fixture = Fixture()
        fixture.fail_close = True
        self.rejected(fixture)

    def test_output_overlap_rejects_without_directory_creation(self):
        fixture = Fixture()
        fixture.args.output_dir = str(fixture.root)
        self.rejected(fixture)

    def test_projection_adds_only_nine_seed_flag_fields(self):
        fixture = Fixture()
        original = encoded(fixture.result)
        view, projection = subject.command_view(fixture.result, fixture.seed_sources)
        self.assertEqual(encoded(fixture.result), original)
        self.assertEqual(view['Commands'], fixture.result['Commands'])
        self.assertFalse(projection['RawCaptureChanged'])
        self.assertEqual(projection['Authority'], 'INDEPENDENTLY_ADMITTED_ORDINARY_CM3_O2_SEED')
        self.assertEqual(len(projection['AddedFields']), 9)
        for index, row in enumerate(view['Sources']):
            self.assertEqual(set(row) - set(fixture.result['Sources'][index]), {'SeedCompileFlags'})
            self.assertEqual(row.pop('SeedCompileFlags'), fixture.seed_sources[index]['CompileFlags'])
            self.assertEqual(row, fixture.result['Sources'][index])
            self.assertEqual(projection['AddedFields'][index]['SourceIndex'], index)

    def test_projection_does_not_share_mutable_input_or_metadata(self):
        fixture = Fixture()
        original, seed_original = encoded(fixture.result), encoded(fixture.seed_sources)
        view, projection = subject.command_view(fixture.result, fixture.seed_sources)
        view['Commands'][0]['Argv'].append('changed')
        view['Sources'][0]['SeedCompileFlags'].append('changed')
        self.assertNotIn('changed', projection['AddedFields'][0]['Value'])
        projection['AddedFields'][1]['Value'].append('metadata-change')
        self.assertNotIn('metadata-change', view['Sources'][1]['SeedCompileFlags'])
        self.assertEqual(encoded(fixture.result), original)
        self.assertEqual(encoded(fixture.seed_sources), seed_original)

    def test_projection_rejects_wrong_shape_existing_field_and_flags(self):
        for size in (8, 10):
            with self.subTest(size=size):
                fixture = Fixture()
                rows = fixture.result['Sources'][:size] if size == 8 else fixture.result['Sources'] + [{}]
                raw = dict(fixture.result, Sources=rows)
                with self.assertRaises(ValueError):
                    subject.command_view(raw, fixture.seed_sources)
        for value in (None, [], '-O2', ['-O2', True]):
            with self.subTest(flags=value):
                fixture = Fixture()
                fixture.seed_sources[0]['CompileFlags'] = value
                with self.assertRaises(ValueError):
                    subject.command_view(fixture.result, fixture.seed_sources)
        fixture = Fixture()
        fixture.result['Sources'][0]['SeedCompileFlags'] = fixture.seed_sources[0]['CompileFlags']
        with self.assertRaises(ValueError):
            subject.command_view(fixture.result, fixture.seed_sources)

    def test_projection_rejects_provider_order_source_or_hash_change(self):
        for field in ('Source', 'SourceSha256', 'order'):
            with self.subTest(field=field):
                fixture = Fixture()
                if field == 'order':
                    fixture.seed_sources[0], fixture.seed_sources[1] = fixture.seed_sources[1], fixture.seed_sources[0]
                else:
                    fixture.result['Sources'][0][field] = 'foreign'
                original = encoded(fixture.result)
                with self.assertRaises(ValueError):
                    subject.command_view(fixture.result, fixture.seed_sources)
                self.assertEqual(encoded(fixture.result), original)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir')
    args = parser.parse_args(argv)
    opening = {path: path.read_bytes() for path in FILES}
    global buffers
    buffers = dict(opening)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Controls)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    drift = [str(path) for path, raw in opening.items() if path.read_bytes() != raw]
    passed = result.wasSuccessful() and result.testsRun == EXPECTED_METHODS and not result.skipped and not drift
    receipt = dict(Status='PASS' if passed else 'FAIL',
        Scope='PURE_SYNTHETIC_CURRENT_CM3_O2_LTO_RUNTIME_BINDINGS_ADMISSION_CONTROLS_ONLY',
        Tests=result.testsRun, ExpectedTestMethods=EXPECTED_METHODS, Failures=len(result.failures),
        Errors=len(result.errors), Skipped=len(result.skipped),
        FailureDetails=[dict(Test=str(test), Detail=detail) for test, detail in result.failures + result.errors],
        SourceHashes={str(path): sha(raw) for path, raw in opening.items()}, SourceDrift=drift,
        SourceClosureVerified=not drift, ClosingFilesVerified=len(opening), SyntheticInputs=True,
        AdmissionAndSeedPreparationMocked=True, CommandReconstructionMocked=True,
        ActualCaptureAdmitted=False, ActualELFTested=False, ActualParserExecuted=False,
        RuntimeProviderBindingsValidated=False, FinalLinkContractValidated=False,
        CanonicalProtocolValidated=False, FullABIProof=False, FullSemanticABIProof=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0, Qualification=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False, ToolInvocations=0)
    if args.output_dir:
        output = Path(args.output_dir).resolve(strict=False)
        if output.exists() or output.is_relative_to(ROOT) or ROOT.is_relative_to(output):
            raise ValueError('fresh external test receipt directory required')
        output.mkdir(parents=True)
        (output / 'results.json').write_bytes((json.dumps(receipt, sort_keys=True, indent=2) + '\n').encode('ascii'))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
