"""Bounded synthetic composition with genuine frozen worker/effect helpers."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
METHODS = 20
PINS = {
    'workers': ('cm3_os_lto_final_cell/common_workers.py',
        'F12A77717924A11DF5F6FA29800271D335A09C475819171C31EFC0B757474EDB'),
    'effects': ('cm3_os_lto_final_cell/common_effects.py',
        '800942F1CA34DCE0198258C13D85F5BA422DF6BF88726694360C16B39270C81D'),
    'attributes': ('cm3_lto_attributes/attributes.py',
        '93275A5903A67CB2DAEABB76BEF1431B052878BB478455E54343DB20881E83C0'),
    'runner': ('cm3_lto_attributes/runner.py',
        '9C99D38EACC8F3E3B2B63F343CA79555A66264AC76A3CA11957D2BEB0745987A'),
    'transport': ('cm3_lto_transport/probe.py',
        'F2D4CA9F1FC1F7FAE07F275913F7DFC688BFD8570AEE32DE2144EE1EA187F626'),
    'model': ('cm3_os_lto_final_cell/test_common_effects.py',
        '0387FAEA413970B821EC0D8439DFF61C2B2EE7742F9C621BE0B30CF0A085D0BB'),
}
API = MODULES = HELPERS = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(values):
    return ('\n'.join(value.replace('\\', '\\\\') for value in values) + '\n').encode('ascii')


class Fixture:
    def __init__(self, *, pending=False):
        self.root = Path('C:/synthetic-common-lowered')
        self.raw, self.images, self.reads, self.parsed = {}, {}, [], []
        self.on_parse = None
        self.lto1 = self.root / 'toolchain/libexec/lto1.exe'
        self.assembler = self.root / 'toolchain/bin/as.exe'
        self.raw.update({self.lto1: b'synthetic lto1 bytes', self.assembler: b'synthetic assembler bytes'})
        self.native = dict(Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True,
            ResolvedWorkers={name: dict(Path=str(path), Sha256=sha(self.raw[path]))
                             for name, path in [('lto1', self.lto1), ('as', self.assembler)]})
        positive = [self.root / 'attributes/ir/positive' / name for name in
                    ('context_core.o', 'context_runtime_state.o', 'context_panic.o')]
        self.lowerings = []
        model = MODULES['model']
        for index, group in enumerate(API.GROUPS):
            stress, mutation = index >= 4, API.MUTATIONS[index]
            objects = list(positive)
            if 1 <= index <= 3:
                slot = index - 1
                objects[slot] = self.root / 'attributes/ir' / group / positive[slot].name
            elif stress:
                objects = [self.root / 'attributes/ir' / group / 'stress.o']
            for obj in objects:
                self.raw[obj] = ('invented slim IR ' + str(obj)).encode('ascii')
            obj = self.root / 'attributes/lowered' / group / 'aggregate.o'
            roles = dict(Object=obj, Machine=Path(str(obj) + '.ltrans0.ltrans.o'),
                Disassembly=obj.parent / 'aggregate.dis',
                DriverSpecs=self.root / 'attributes/driver/no-auto-gcov.specs',
                Diagnostics=self.root / ('commands/%03d.stderr' % API.STARTS[index]))
            roles.update({name: Path(str(obj) + suffix) for name, suffix in dict(
                WpaArguments='.ltrans_args', LtransArguments='.ltrans0.ltrans_args',
                WpaResponse='.wpa.args.0', LtransResponse='.ltrans0.ltrans.args.0',
                PartitionList='.ltrans.out', Intermediate='.ltrans0.o', Resolution='.res',
                Assembly='.ltrans0.ltrans.s').items()})
            roles['WrapperArgs'] = self.root / (''.join(obj.parts[1:]) + '.lto_wrapper_args')
            for name, path in roles.items():
                self.raw[path] = ('retained binding only ' + name).encode('ascii')
            flags = ['-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-Os', *MODULES['workers'].RAW_FLAGS]
            lower = ['-flto-partition=one', '-nostdlib', '-r', '-flinker-output=nolto-rel']
            specs = '-specs=' + str(roles['DriverSpecs'])
            self.raw[roles['WpaArguments']] = encoded([*flags, *lower, specs, '-fwpa', *map(str, objects)])
            self.raw[roles['LtransArguments']] = encoded([*flags, *lower, specs, '-fltrans',
                '-o', str(roles['Machine']), str(roles['Intermediate'])])
            self.raw[roles['WpaResponse']] = encoded(list(map(str, objects)))
            self.raw[roles['LtransResponse']] = encoded([str(roles['Intermediate'])])
            self.raw[roles['PartitionList']] = ('1\n' + str(roles['Intermediate']) + '\n').encode('ascii')
            invocations = [[str(self.lto1), *flags, '-fwpa', '@' + str(roles['WpaResponse'])],
                [str(self.lto1), *flags, '-fltrans', '-o', str(roles['Assembly']), '@' + str(roles['LtransResponse'])],
                [str(self.assembler), '-o', str(roles['Machine']), str(roles['Assembly'])]]
            self.raw[roles['Diagnostics']] = ''.join(' ' + ' '.join(row) + '\n' for row in invocations).encode('ascii')
            for role in ('Object', 'Machine'):
                image = model.Image(stress=stress, raw_stress=group == 'stress-unprotected')
                if mutation is not None and not stress:
                    image.instrument(mutation)
                if not stress or group == 'stress-unprotected':
                    image.constructor_arrays()
                if pending and not stress:
                    image.instrument(model.SETTER)
                # A bounded header for the real transport check, not a real ELF
                # section table or genuine code-generation fixture.
                raw = bytearray(image.data)
                struct.pack_into('<I', raw, 32, len(raw))
                struct.pack_into('<H', raw, 40, 52)
                struct.pack_into('<HH', raw, 46, 40, 1)
                image.data = bytes(raw) + bytes(40)
                self.images[roles[role]] = image
                self.raw[roles[role]] = image.data
            self.lowerings.append(dict(Group=group, Inputs=[self.binding(path) for path in objects],
                Mutation=mutation, Stress=stress, Roles={name: self.binding(path) for name, path in roles.items()},
                CommandIndices=[API.STARTS[index], API.STARTS[index] + 1], DisassemblyIncludesZeroes=True,
                WorkerOptionsValidated=False, EffectsValidated=False, ValidationDeferred=True))
        self.refresh()
        fixture = self

        class Parsed(model.Image):
            def __init__(self, path, kind):
                if kind != 'ET_REL':
                    raise AssertionError('unexpected final-image parser')
                fixture.parsed.append(Path(path))
                if fixture.on_parse is not None:
                    fixture.on_parse(Path(path))
                self.__dict__.update(copy.deepcopy(fixture.images[Path(path)].__dict__))
                self.data = Path(path).read_bytes()

        self.core = SimpleNamespace(_ELF=Parsed, _width=model.width, _address_form=model.address_form)

    def binding(self, path):
        return dict(Path=str(path), Sha256=sha(self.raw[path]))

    def refresh(self):
        for row in self.lowerings:
            for binding in list(row['Roles'].values()) + row['Inputs']:
                binding['Sha256'] = sha(self.raw[Path(binding['Path'])])

    def read(self, path, expected):
        if not isinstance(path, Path) or path not in self.raw:
            raise ValueError('synthetic read outside explicit authority')
        self.reads.append((path, expected))
        if sha(self.raw[path]) != expected:
            raise ValueError('synthetic authority hash mismatch')
        return self.raw[path]

    def run(self, helpers=None, read=None):
        return API.inspect(self.core, read or self.read, self.lowerings, self.native, helpers or HELPERS)


class LoweredTests(unittest.TestCase):
    def reject(self, fixture, **kwargs):
        with self.assertRaises(ValueError):
            fixture.run(**kwargs)

    def test_full_six_chains_twelve_images_real_helpers(self):
        f = Fixture()
        with patch.object(MODULES['workers'], 'worker_chain', wraps=MODULES['workers'].worker_chain) as workers, \
                patch.object(MODULES['effects'], 'inspect_lowered', wraps=MODULES['effects'].inspect_lowered) as effects:
            p = f.run()
        self.assertEqual(workers.call_count, 6)
        self.assertEqual(effects.call_count, 20)
        self.assertEqual(len(f.parsed), 12)
        self.assertEqual(p['Status'], API.PASS)
        self.assertEqual(len(f.reads), 89)
        self.assertEqual(len({path for path, _ in f.reads}), 89)
        self.assertIs(API.require_result(p, HELPERS), p)
        self.assertFalse(hasattr(HELPERS['attributes'], 'inspect_lowered'))

    def test_input_cohorts_and_retained_only_nonclaims(self):
        f = Fixture(); p = f.run()
        self.assertEqual([len(row['Inputs']) for row in p['Lowerings']], [3, 3, 3, 3, 1, 1])
        self.assertEqual(sum(len(row['Roles']) for row in p['Lowerings']), 84)
        self.assertEqual(len({x['Path'] for row in p['Lowerings'] for x in row['Roles'].values()}), 79)
        for key in ('WrapperSemanticsValidated', 'ResolutionSemanticsValidated', 'AssemblySemanticsValidated',
                    'DisassemblySemanticsValidated', 'JournalBindingsValidated', 'CommonAttributePolicyProven'):
            self.assertIs(p[key], False)

    def test_fixed_order_selectors_and_original_deferred_flags(self):
        for key, value in [('Group', 'foreign'), ('Stress', 0), ('Mutation', 'foreign'),
                ('ValidationDeferred', False), ('WorkerOptionsValidated', True), ('EffectsValidated', True),
                ('DisassemblyIncludesZeroes', 1), ('CommandIndices', [65, 66])]:
            with self.subTest(key=key):
                f = Fixture(); f.lowerings[0][key] = value; self.reject(f); self.assertFalse(f.reads)
        f = Fixture(); f.lowerings.reverse(); self.reject(f)

    def test_missing_extra_rows_fields_and_roles(self):
        for defect in ('missing-row', 'extra-row', 'missing-field', 'extra-field', 'missing-role', 'extra-role', 'role-field'):
            with self.subTest(defect=defect):
                f = Fixture(); row = f.lowerings[0]
                if defect == 'missing-row': f.lowerings.pop()
                elif defect == 'extra-row': f.lowerings.append(copy.deepcopy(row))
                elif defect == 'missing-field': row.pop('Inputs')
                elif defect == 'extra-field': row['ForgedVerdict'] = True
                elif defect == 'missing-role': row['Roles'].pop('Assembly')
                elif defect == 'extra-role': row['Roles']['Foreign'] = dict(row['Roles']['Assembly'])
                else: row['Roles']['Object']['Role'] = 'Object'
                self.reject(f); self.assertFalse(f.reads)

    def test_fixed_role_paths_independent_of_leaf(self):
        for role in API.ROLES:
            with self.subTest(role=role):
                f = Fixture(); f.lowerings[1]['Roles'][role]['Path'] = 'C:/forged/' + role
                self.reject(f); self.assertFalse(f.reads)

    def test_exact_ir_replacements_order_and_shared_hash(self):
        for defect in ('order', 'foreign', 'missing', 'shared-hash', 'stress-extra'):
            with self.subTest(defect=defect):
                f = Fixture()
                if defect == 'order': f.lowerings[0]['Inputs'].reverse()
                elif defect == 'foreign': f.lowerings[1]['Inputs'][0] = dict(f.lowerings[0]['Inputs'][0])
                elif defect == 'missing': f.lowerings[0]['Inputs'].pop()
                elif defect == 'shared-hash': f.lowerings[1]['Inputs'][1]['Sha256'] = 'A' * 64
                else: f.lowerings[-1]['Inputs'].append(dict(f.lowerings[0]['Inputs'][0]))
                self.reject(f); self.assertFalse(f.reads)

    def test_lexical_paths_reject_relative_unc_traversal_controls(self):
        for value in ('relative.o', 'C:relative.o', '//host/share/file.o', 'C:/a/../aggregate.o',
                      'C:/a/./aggregate.o', 'C:/a//aggregate.o', 'C:/a./aggregate.o', 'C:/a\x00/aggregate.o'):
            with self.subTest(path=value):
                f = Fixture(); f.lowerings[0]['Roles']['Object']['Path'] = value; self.reject(f)

    def test_hash_types_reader_bytes_and_hash_mismatch(self):
        for value in (None, 7, 'a' * 64, 'A' * 63):
            f = Fixture(); f.lowerings[0]['Roles']['Object']['Sha256'] = value; self.reject(f)
        f = Fixture(); bad = Path(f.lowerings[0]['Roles']['Object']['Path']); f.raw[bad] += b'changed'; self.reject(f)
        for value in (bytearray(b'x'), 'bytes', None, b''):
            f = Fixture()
            self.reject(f, read=lambda path, expected, value=value: value)

    def test_native_worker_authority_strict_and_hash_bound(self):
        for key, value in [('Profile', 'CM0'), ('Mode', 'O2-lto'), ('Linkage', 'archive'), ('LTO', 1)]:
            f = Fixture(); f.native[key] = value; self.reject(f)
        for defect in ('missing', 'hash', 'alias', 'extra-binding'):
            f = Fixture(); workers = f.native['ResolvedWorkers']
            if defect == 'missing': workers.pop('as')
            elif defect == 'hash': workers['lto1']['Sha256'] = 'A' * 64
            elif defect == 'alias': workers['as'] = dict(workers['lto1'])
            else: workers['as']['Claim'] = True
            self.reject(f)

    def test_saved_worker_flags_and_ordered_responses_recomputed(self):
        for role, old, new in [('WpaArguments', b'-Os', b'-O2'),
                ('LtransArguments', b'-fsanitize=undefined', b'-fno-sanitize=undefined'),
                ('WpaResponse', b'context_core.o', b'foreign_core.o'),
                ('LtransResponse', b'.ltrans0.o', b'.foreign.o'),
                ('PartitionList', b'1\n', b'1\nsecond-partition\n')]:
            with self.subTest(role=role):
                f = Fixture(); path = Path(f.lowerings[0]['Roles'][role]['Path'])
                self.assertIn(old, f.raw[path]); f.raw[path] = f.raw[path].replace(old, new); f.refresh(); self.reject(f)

    def test_actual_diagnostics_and_known_dotted_executable(self):
        f = Fixture(); path = Path(f.lowerings[0]['Roles']['Diagnostics']['Path'])
        canonical = str(f.lto1).encode('ascii')
        f.raw[path] = f.raw[path].replace(canonical, str(f.lto1.parent / 'unused/../lto1.exe').encode('ascii'))
        f.refresh(); self.assertEqual(f.run()['Status'], API.PASS)
        for replacement in (b'C:\\foreign\\lto1.exe', b'relative/lto1.exe'):
            f = Fixture(); path = Path(f.lowerings[0]['Roles']['Diagnostics']['Path'])
            f.raw[path] = f.raw[path].replace(str(f.lto1).encode('ascii'), replacement); f.refresh(); self.reject(f)

    def test_worker_returned_machine_and_nested_records_not_trusted(self):
        original = MODULES['workers'].worker_chain
        for defect in ('machine', 'hash', 'execution', 'stage', 'claim'):
            with self.subTest(defect=defect):
                def corrupt(*args, defect=defect):
                    machine, p = original(*args)
                    if defect == 'machine': machine = Path('C:/foreign.o')
                    elif defect == 'hash': p['MachineSha256'] = 'A' * 64
                    elif defect == 'execution': p['Execution']['TranscriptSha256'] = 'A' * 64
                    elif defect == 'stage': p['ActualInvocationOptions'][0]['SoleOsOptimization'] = 1
                    else: p['Qualification'] = True
                    return machine, p
                with patch.object(MODULES['workers'], 'worker_chain', side_effect=corrupt):
                    self.reject(Fixture())

    def test_no_filesystem_normalization_or_unowned_constructor_reads(self):
        f = Fixture()
        with patch.object(Path, 'open', side_effect=AssertionError('physical open forbidden')), \
                patch.object(Path, 'stat', side_effect=AssertionError('physical stat forbidden')), \
                patch.object(Path, 'lstat', side_effect=AssertionError('physical lstat forbidden')), \
                patch.object(Path, 'exists', side_effect=AssertionError('physical exists forbidden')), \
                patch.object(Path, 'resolve', side_effect=AssertionError('physical resolve forbidden')):
            self.assertEqual(f.run()['Status'], API.PASS)
        for method in ('read_bytes', 'read_text'):
            f = Fixture(); f.on_parse = lambda path, method=method: getattr(Path('C:/not-admitted.txt'), method)()
            self.reject(f)

    def test_parsed_bytes_must_equal_the_admitted_image(self):
        f = Fixture(); base = f.core._ELF
        class Wrong(base):
            def __init__(self, path, kind):
                super().__init__(path, kind); self.data += b'forged parsed bytes'
        f.core._ELF = Wrong
        before = Path.read_bytes; self.reject(f); self.assertIs(Path.read_bytes, before)

    def test_actual_effect_predicate_rejects_unintended_body(self):
        f = Fixture(); path = Path(f.lowerings[0]['Roles']['Machine']['Path'])
        f.images[path].instrument('fiber_internal_runtime_publish_current_context')
        f.raw[path] = f.images[path].data; f.refresh(); self.reject(f)

    def test_pending_projection_preserved_and_never_policy(self):
        f = Fixture(pending=True); p = f.run()
        self.assertEqual(p['Status'], API.PENDING)
        self.assertEqual(len(p['UnresolvedAttribution']), 8)
        self.assertIs(p['CommonAttributionClosed'], False)
        self.assertIs(p['CommonAttributePolicyProven'], False)
        for defect in ('empty', 'truncate', 'promote', 'nested', 'cold-projection'):
            q = copy.deepcopy(p)
            if defect == 'empty': q['UnresolvedAttribution'] = []
            elif defect == 'truncate': q['UnresolvedAttribution'].pop()
            elif defect == 'promote': q.update(Status=API.PASS, CommonAttributionClosed=True)
            elif defect == 'nested': q['CommonMachines'][0]['Machines'][0]['Proof']['ColdInlineAttributionValidated'] = True
            else: q['CommonMachines'][0]['Machines'][0]['Proof']['UnresolvedAttribution'][0]['ColdAddressReferences'] = [{}]
            with self.assertRaises(ValueError): API.require_result(q, HELPERS)

    def test_aggregate_machine_disposition_mismatch_rejected(self):
        f = Fixture(); path = Path(f.lowerings[0]['Roles']['Object']['Path'])
        f.images[path].instrument(MODULES['model'].SETTER); f.raw[path] = f.images[path].data
        f.refresh(); self.reject(f)

    def test_returned_deep_worker_inputs_stages_and_counts(self):
        p = Fixture().run()
        for defect in ('top-extra', 'count-bool', 'read-hash', 'read-size', 'read-order', 'worker-input',
                       'header-count', 'argv', 'response', 'assembler', 'saved-stage'):
            with self.subTest(defect=defect):
                q = copy.deepcopy(p); w = q['WorkerChains'][0]['Proof']
                if defect == 'top-extra': q['ExtraClaim'] = False
                elif defect == 'count-bool': q['CompilerInvocations'] = False
                elif defect == 'read-hash': q['ReadInputs'][0]['Sha256'] = 'A' * 64
                elif defect == 'read-size': q['ReadInputs'][0]['Bytes'] = True
                elif defect == 'read-order': q['ReadInputs'].reverse()
                elif defect == 'worker-input': w['WpaInputs'].reverse()
                elif defect == 'header-count': w['MachineHeader']['SectionCount'] = True
                elif defect == 'argv': w['Execution']['WorkerInvocations'][0]['Argv'].append('-O2')
                elif defect == 'response': w['Execution']['WorkerInvocations'][0]['ResponseSha256'] = 'A' * 64
                elif defect == 'assembler': w['Execution']['Assembler']['Argv'][-1] = 'C:/other.s'
                else: w['Stages'][0]['SavedNoltoRelOptionsValidated'] = 1
                with self.assertRaises(ValueError): API.require_result(q, HELPERS)

    def test_returned_effect_fields_hashes_references_and_nonclaims(self):
        p = Fixture().run()
        for defect in ('leaf-hash', 'leaf-credit', 'reference', 'root-projection', 'mutant-rejection', 'nonclaim',
                       'leaf-extra', 'root-extra', 'reference-extra', 'constructor', 'counter', 'stress-counter'):
            with self.subTest(defect=defect):
                q = copy.deepcopy(p); m = q['CommonMachines'][0]['Machines'][0]; leaf = m['Proof']
                if defect == 'leaf-hash': leaf['ObjectSha256'] = 'A' * 64
                elif defect == 'leaf-credit': leaf['RequiredCellsSatisfied'] = False
                elif defect == 'reference': leaf['References'][0]['AppliedDestinationValidated'] = True
                elif defect == 'root-projection': leaf['RootEvidence'][0]['References'].append(dict(leaf['References'][0]))
                elif defect == 'mutant-rejection': q['CommonMachines'][1]['Machines'][0]['OriginalProtectedPredicateRejected'] = False
                elif defect == 'nonclaim': q['WrapperSemanticsValidated'] = True
                elif defect == 'leaf-extra': leaf['FullABIProof'] = True
                elif defect == 'root-extra': leaf['RootEvidence'][0]['WholeBodySemantics'] = True
                elif defect == 'reference-extra': leaf['References'][0]['AppliedAddress'] = 123
                elif defect == 'constructor': leaf['CompilerConstructors'][0]['References'] = []
                elif defect == 'counter': leaf['CounterDefinitions'][0]['kind'] = 'STT_FUNC'
                else: q['CommonMachines'][-1]['Machines'][0]['Proof']['StressCounterEvidence']['Definition']['ExtraClaim'] = True
                with self.assertRaises(ValueError): API.require_result(q, HELPERS)

    def test_no_caller_mutation_no_global_callback_changes_and_failure_restores(self):
        f = Fixture(); before = copy.deepcopy((f.lowerings, f.native, f.raw))
        callback = MODULES['attributes'].require_hostile_options; read_bytes = Path.read_bytes
        p = f.run()
        self.assertEqual(before, (f.lowerings, f.native, f.raw))
        self.assertIs(MODULES['attributes'].require_hostile_options, callback)
        p['Lowerings'][0]['Roles']['Object']['Sha256'] = 'A' * 64
        self.assertEqual(before, (f.lowerings, f.native, f.raw))
        f = Fixture(); f.on_parse = lambda path: (_ for _ in ()).throw(RuntimeError('synthetic constructor failure'))
        with self.assertRaises(RuntimeError): f.run()
        self.assertIs(Path.read_bytes, read_bytes)
        self.assertIs(MODULES['attributes'].require_hostile_options, callback)


def main(argv=None):
    global API, MODULES, HELPERS
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args(argv)
    output = Path(args.output_dir).resolve()
    if output.exists() or output == ROOT or ROOT in output.parents or output in ROOT.parents:
        parser.error('fresh external output directory required')
    paths = dict(subject=HERE / 'common_lowered.py', tests=Path(__file__).resolve())
    paths.update({name: ROOT / 'tools/fixtures' / row[0] for name, row in PINS.items()})
    buffers = {name: path.read_bytes() for name, path in paths.items()}
    report = dict(Status='FAIL', Scope='PURE_SYNTHETIC_OS_COMMON_LOWERED_COMPOSITION', Tests=0,
        ExpectedTestMethods=METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={str(paths[name]): sha(raw) for name, raw in buffers.items()}, SourceDrift=[],
        SourceClosureVerified=False, SyntheticELFMetadata=True, ActualELFParsed=False,
        ActualCaptureRead=False, ActualOsCodegenValidated=False, ExternalToolsExecuted=0,
        Qualification=False, CpuExecution=False, BoardExecution=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__ or not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode:
            raise ValueError('fresh isolated unoptimized -I -S -B interpreter required')
        for name, row in PINS.items():
            if sha(buffers[name]) != row[1]:
                raise ValueError('frozen synthetic helper/model pin/' + name)
        with patch('subprocess.Popen', side_effect=AssertionError('pure tests cannot spawn processes')), \
                patch('os.system', side_effect=AssertionError('pure tests cannot invoke a shell')):
            MODULES = {}
            for name in ('subject', *PINS):
                module = ModuleType('_os_common_lowered_test_' + name); module.__file__ = str(paths[name])
                exec(compile(buffers[name], str(paths[name]), 'exec'), module.__dict__)
                MODULES[name] = module
            API = MODULES['subject']
            names = ('_header', '_functions', '_symbol_fields', '_walk', '_resolved', 'Rejected',
                'PROTECTED', 'FORWARD', 'THREAD', 'THREAD_SECTION', 'COLD', 'SETTER', 'PANIC', 'STRESS',
                'MUTATIONS', 'HOOKS', 'COLD_IMPORTS', 'STRESS_FAMILIES')
            HELPERS = dict(attributes=SimpleNamespace(**{name: getattr(MODULES['attributes'], name) for name in names}),
                attribute_runner=SimpleNamespace(**{name: getattr(MODULES['runner'], name)
                    for name in ('worker_chain', 'argument_lines', 'worker_diagnostics')}),
                common_workers=MODULES['workers'], common_effects=MODULES['effects'],
                transport=SimpleNamespace(require_elf32le=MODULES['transport'].require_elf32le))
            tests = unittest.defaultTestLoader.loadTestsFromTestCase(LoweredTests)
            if tests.countTestCases() != METHODS:
                raise ValueError('exact implemented method count: ' + str(tests.countTestCases()))
            result = unittest.TextTestRunner(verbosity=2).run(tests)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), Details=[dict(Test=str(test), Detail=detail)
                for test, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped:
            report['Status'] = 'PASS'
    except Exception as error:
        report.update(Status='FAIL', Errors=report['Errors'] + 1, Error=type(error).__name__ + ': ' + str(error))
    for path, expected in report['SourceHashes'].items():
        try:
            if sha(Path(path).read_bytes()) != expected:
                report['SourceDrift'].append(path)
        except OSError:
            report['SourceDrift'].append(path)
    report['SourceClosureVerified'] = len(report['SourceHashes']) == 8 and not report['SourceDrift']
    if not report['SourceClosureVerified']:
        report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / 'results.json'
    receipt.write_bytes((json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n').encode('ascii'))
    print('Receipt:', receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
