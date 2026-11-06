"""Synthetic host controls for four-component replay; never ELF qualification."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SUBJECT = HERE / 'replay.py'
S = None
COUNT = 13


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def raw_json(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('ascii')


class Watch:
    def __init__(self):
        self.data, self.hashes = {}, {}
        self.reads = []

    def put(self, name, raw):
        name = S.path(name)
        self.data[name], self.hashes[name] = raw, sha(raw)

    def read(self, name, expected=None):
        name = S.path(name)
        self.reads.append(name)
        raw = self.data[name]
        if expected is not None and sha(raw) != expected:
            raise ValueError('fake watch hash mismatch')
        return raw


def fixture():
    root = Path(tempfile.gettempdir()) / 'synthetic-four-component-replay'
    watch = Watch()
    admitted = NS(watch=watch)
    capture = root / 'capture'
    objects = tuple(capture / ('%02d.o' % i) for i in range(9))
    links = [dict(Path=str(capture / name / 'image.elf'), Machine=str(capture / name / 'machine.o'),
        Map=str(capture / name / 'image.map')) for name in ('ordinary', 'emit-relocs')]
    suites, bundles = {}, {}
    for role in ('ABIControls', 'Isolation', 'CommonAttributes', 'PortPolicy'):
        output = root / role
        result = dict(Synthetic=True)
        suites[role] = NS(admitted=admitted, watch=watch, output=output, report=result,
            base=capture, objects=objects, result=dict(Links=links),
            sources=[dict(ActualCompileDependencies=[dict(Path=str(capture / 'source/header.h'), Sha256='A' * 64)])] * 9,
            start=Mock(side_effect=AssertionError('no lifecycle')), run=Mock(side_effect=AssertionError('no lifecycle')),
            finish=Mock(side_effect=AssertionError('no lifecycle')), command=Mock(side_effect=AssertionError('no tools')))
        bundles[role] = dict(Root=str(output), Result=result, Artifacts={}, Descriptor=dict(Synthetic=True))
    return suites, bundles, watch


def put(suite, bundle, name, raw):
    selected = S.path(bundle['Root']) / name
    suite.watch.put(selected, raw)
    bundle['Artifacts'][name] = sha(raw)
    return selected


def journal_fixture():
    suites, bundles, watch = fixture()
    suite, bundle = suites['ABIControls'], bundles['ABIControls']
    row = dict(Label='inspect synthetic', Argv=['readelf', '-hSW', 'synthetic.o'],
        Cwd=bundle['Root'], State='TERMINAL', Status='PASS', Exit=0, ExpectedExit=0, TimedOut=False,
        Stdout='commands/000.stdout', Stderr='commands/000.stderr', StdoutSha256=sha(b'bytes'), StderrSha256=sha(b''))
    bundle['Result']['Commands'] = [row]
    for name, raw in (('commands.json', raw_json([row])), ('commands/000.json', raw_json(row)),
            ('commands/000.stdout', b'bytes'), ('commands/000.stderr', b'')):
        put(suite, bundle, name, raw)
    return suite, bundle, watch


class ReplayTests(unittest.TestCase):
    def test_repeated_slim_labels_bind_distinct_exact_object_arguments(self):
        suites, bundles, _ = fixture()
        suite, bundle = suites['CommonAttributes'], bundles['CommonAttributes']
        obj = put(suite, bundle, 'positive/context_core.o', b'synthetic slim bytes')
        other = S.path(bundle['Root']) / 'mutant-engine/context_core.o'
        suite.tools = dict(readelf=Path('readelf.exe'))
        sections = [dict(Index=0, Name='', Size=0, Flags=''),
                    dict(Index=1, Name='.gnu.lto_fake', Size=12, Flags='E')]
        suite.transport = NS(require_elf32le=Mock(return_value=dict(SectionCount=2)),
            section_records=Mock(return_value=sections))
        expected = dict(Object=str(obj), Sha256=sha(b'synthetic slim bytes'), SlimIR=True, Sections=sections)
        record = dict(Object=str(obj), SlimIR=expected)
        rows = [dict(Label='inspect slim context_core', Argv=['readelf.exe', '-hSW', str(value)], Exit=0)
                for value in (other, obj)]
        results = [NS(stdout=b'unrelated', stderr=b'error'), NS(stdout=b'actual sections', stderr=b'')]
        self.assertEqual(S._slim_record(suite, bundle, record, rows, results), expected)
        suite.transport.section_records.assert_called_once_with('actual sections')
        with self.assertRaises(ValueError):
            S._slim_record(suite, bundle, record, rows + [copy.deepcopy(rows[1])], results + [results[1]])
        rows[1]['Exit'] = True
        with self.assertRaises(ValueError):
            S._slim_record(suite, bundle, record, rows, results)

    def test_exact_role_and_shared_admission_boundary(self):
        suites, bundles, watch = fixture()
        S._maps(suites, bundles, {role: object() for role in S.ROLES})
        for change in ('missing', 'foreign', 'different-watch', 'wrong-root', 'report', 'traversal'):
            ss, bb, _ = fixture()
            if change == 'missing':
                ss.pop('PortPolicy')
            elif change == 'foreign':
                bb['Other'] = bb['Isolation']
            elif change == 'different-watch':
                ss['Isolation'].watch = Watch()
            elif change == 'wrong-root':
                ss['Isolation'].output = ss['Isolation'].output.parent
            elif change == 'report':
                ss['Isolation'].report = dict(Synthetic=False)
            else:
                bb['Isolation']['Artifacts']['../foreign.o'] = 'A' * 64
            with self.subTest(change=change), self.assertRaises(ValueError):
                S._maps(ss, bb)
        with self.assertRaises(ValueError):
            S.same(dict(Count=True), dict(Count=1), 'typed equality')

    def test_binary_scope_includes_external_source_assembly_and_startup(self):
        suites, bundles, watch = fixture()
        bundles['Isolation']['Artifacts'].update({'machine.o': 'A' * 64, 'worker.s': 'B' * 64,
            'generated/attributes.i': 'C' * 64, 'source.py': 'D' * 64})
        actual = S.binary_paths(suites, bundles)
        self.assertEqual(actual, sorted(set(actual)))
        root = S.path(bundles['Isolation']['Root'])
        self.assertIn(root / 'machine.o', actual)
        self.assertIn(root / 'worker.s', actual)
        self.assertNotIn(root / 'source.py', actual)
        suite = suites['Isolation']
        self.assertIn(suite.objects[8], actual)
        self.assertIn(suite.base / 'source/fiber/port/ARM_CM3/fiber_port.c', actual)
        self.assertIn(suite.base / 'source/header.h', actual)
        for link in suite.result['Links']:
            self.assertIn(Path(link['Path'] + '.ltrans0.ltrans.s'), actual)
            self.assertIn(Path(link['Map']), actual)
        with self.assertRaises(ValueError):
            S.path(suite.base / 'tools/fixtures/cm33f_secure_transfer_reference/file.o')

    def test_journals_bind_same_raw_json_streams_and_typed_status(self):
        suite, bundle, watch = journal_fixture()
        rows, results = S.journals(suite, bundle, 1)
        self.assertEqual(results[0].stdout, b'bytes')
        self.assertEqual(rows, bundle['Result']['Commands'])
        for field, value in (('Exit', False), ('ExpectedExit', 0.0), ('State', 'ATTEMPT'),
                ('Stdout', '../foreign.stdout'), ('StdoutSha256', 'B' * 64)):
            ss, bb, _ = journal_fixture()
            row = bb['Result']['Commands'][0]
            row[field] = value
            put(ss, bb, 'commands.json', raw_json([row]))
            put(ss, bb, 'commands/000.json', raw_json(row))
            with self.subTest(field=field), self.assertRaises(ValueError):
                S.journals(ss, bb, 1)
        put(suite, bundle, 'commands.json', b'{"same":1,"same":2}')
        with self.assertRaises(ValueError):
            S.journals(suite, bundle, 1)

    def test_dependency_bytes_are_lexical_deduplicated_and_target_bound(self):
        base = S.path(Path(tempfile.gettempdir()) / 'dep-root')
        source, header = base / 'source.c', base / 'header file.h'
        escaped = str(header).replace(' ', '\\ ')
        raw = ('pilot-source-3: ' + str(source) + ' \\\r\n ' + escaped + ' ' + str(source) + '\r\n').encode('utf-8')
        self.assertEqual(S._dependencies(raw, 'pilot-source-3'), sorted({source, header}))
        for bad in (b'other-source-3: source.c\n', b'pilot-source-3:\n', b'pilot-source-True: a.c\n'):
            with self.assertRaises(ValueError):
                S._dependencies(bad, 'pilot-source-3')

    def test_dependency_record_membership_and_source_bytes_recomputed(self):
        suites, bundles, watch = fixture()
        suite, bundle = suites['Isolation'], bundles['Isolation']
        source = put(suite, bundle, 'source.c', b'int source;\n')
        obj = S.path(bundle['Root']) / 'source.o'
        raw = ('pilot-source-0: ' + str(source) + '\n').encode('utf-8')
        discovery = put(suite, bundle, 'source.discovery.d', raw)
        actual = put(suite, bundle, 'source.compile.d', raw)
        row = dict(Object=str(obj), DiscoveryDependencyFile=str(discovery), CompileDependencyFile=str(actual),
            Dependencies=[dict(Path=str(source), Sha256=sha(b'int source;\n'))])
        expected = copy.deepcopy(row)
        self.assertEqual(S.dependencies(suite, bundle, row, source, 0), row['Dependencies'])
        self.assertEqual(row, expected)
        put(suite, bundle, 'source.c', b'int modified;\n')
        with self.assertRaises(ValueError):
            S.dependencies(suite, bundle, row, source, 0)

    def test_exact_argv_disposition_and_unique_label(self):
        rows = [dict(Label='one', Argv=['gcc', '-O2', '-c', 'a.c', '-o', 'a.o'], Exit=0)]
        self.assertEqual(S._command(rows, 'one', rows[0]['Argv']), 0)
        for bad in (rows[0]['Argv'] + ['-O3'], ['gcc', '@unbound'], ['gcc']):
            with self.assertRaises(ValueError):
                S._command(rows, 'one', bad)
        with self.assertRaises(ValueError):
            S._command(rows, 'one', rows[0]['Argv'], failure=True)
        with self.assertRaises(ValueError):
            S._command(rows * 2, 'one', rows[0]['Argv'])

    def test_link_reconstruction_preserves_object_order_and_only_emit_delta(self):
        suites, bundles, watch = fixture()
        suite = suites['Isolation']
        suite.link_argv = ['gcc', '-O2', '-flto', *(str(value) for value in suite.objects),
            '-Wl,-Map=old.map', '-o', suite.result['Links'][0]['Path']]
        changed = list(suite.objects)
        changed[:3] = [suite.output / ('new%d.o' % i) for i in range(3)]
        elf, link_map = suite.output / 'new.elf', suite.output / 'new.map'
        argv = S._link_arguments(suite, changed, elf, link_map)
        self.assertEqual([value for value in argv if value.endswith('.o')], [str(value) for value in changed])
        self.assertIn('-Wl,-Map=' + str(link_map), argv)
        self.assertEqual(S._link_arguments(suite, changed, elf, link_map, emit=True), argv + ['-Wl,--emit-relocs'])
        self.assertEqual(suite.link_argv[-1], suite.result['Links'][0]['Path'])

    def test_private_source_plan_has_one_exact_edit_and_all_unchanged_bytes(self):
        suites, bundles, watch = fixture()
        suite, bundle = suites['ABIControls'], bundles['ABIControls']
        original = suite.base / 'source'
        for name, raw in (('a.c', b'original token\n'), ('header.h', b'unchanged\n')):
            watch.put(original / name, raw)
        suite.bundle = dict(Artifacts={'source/a.c': sha(b'original token\n'), 'source/header.h': sha(b'unchanged\n')})
        suite.source = lambda index: dict(Source=str(original / 'a.c'), CompileFlags=['-I' + str(original)])
        spec = dict(Name='stale', Index=1, Added=None, Mutations=(('a.c', b'original', b'changed'),))
        private = suite.output / 'compilations/stale/source'
        put(suite, bundle, 'compilations/stale/source/a.c', b'changed token\n')
        put(suite, bundle, 'compilations/stale/source/header.h', b'unchanged\n')
        row = dict(Source=str(private / 'a.c'), TemplateIndex=1, SourceDeltas=[dict(Original=str(original / 'a.c'),
            Copy=str(private / 'a.c'), BeforeSha256=sha(b'original token\n'), AfterSha256=sha(b'changed token\n'),
            Before=b'original'.hex(), After=b'changed'.hex(), Count=1)])
        source, flags = S._source_plan(suite, bundle, spec, row)
        self.assertEqual(source, private / 'a.c')
        self.assertEqual(flags, ['-I' + str(private)])
        put(suite, bundle, 'compilations/stale/source/header.h', b'wrong unchanged header\n')
        with self.assertRaises(ValueError):
            S._source_plan(suite, bundle, spec, row)

    def test_record_dispatch_never_uses_lifecycle_or_old_pass_predicate(self):
        suites, bundles, watch = fixture()
        modules = {role: NS(succeeded=Mock(side_effect=AssertionError('old PASS is not authority'))) for role in S.ROLES}
        handlers = ('_abi_records', '_isolation_records', '_attrs_records', '_port_records')
        with patch.object(S, 'journals', return_value=([], [])) as journal, \
                patch.object(S, handlers[0], return_value=dict(New='abi')) as a, \
                patch.object(S, handlers[1], return_value=dict(New='iso')) as b, \
                patch.object(S, handlers[2], return_value=dict(New='attrs')) as c, \
                patch.object(S, handlers[3], return_value=dict(New='port')) as d:
            result = S.verify_records(suites, bundles, modules, watch)
        self.assertEqual([call.args[2] for call in journal.call_args_list], [41, 12, 45, 36])
        self.assertEqual(result['CommandsReclassified'], 134)
        self.assertIs(result['PriorComponentPASSAuthority'], False)
        self.assertEqual(result['RequiredCellsSatisfied'], 0)
        for callback, role in zip((a, b, c, d), S.ROLES):
            callback.assert_called_once_with(suites[role], bundles[role], modules[role], [], [])
            suites[role].command.assert_not_called()
            modules[role].succeeded.assert_not_called()
        with patch.object(S, '_abi_records', side_effect=ValueError('real record failure')), \
                patch.object(S, 'journals', return_value=([], [])), self.assertRaises(ValueError):
            S.verify_records(suites, bundles, modules, watch)

    def test_machine_dispatch_uses_only_supplied_scope_and_complete_slim_set(self):
        suites, bundles, watch = fixture()
        modules = {role: object() for role in S.ROLES}
        core, graph = object(), NS(executed=[dict(Source='synthetic closed module')])
        sizes = dict(zip(S.ROLES, (7, 3, 8, 5)))
        with patch.object(S, '_slim_machines', side_effect=lambda suite, bundle, core: [dict(Synthetic=True)] * sizes[
                next(role for role in S.ROLES if suite is suites[role])]), \
                patch.object(S, '_abi_machines', return_value=dict(New=True)), \
                patch.object(S, '_isolation_machines', return_value=dict(New=True)), \
                patch.object(S, '_attrs_machines', return_value=dict(New=True)), \
                patch.object(S, '_port_machines', return_value=dict(New=True)):
            result = S.inspect_machines(suites, bundles, modules, core, graph)
        self.assertIs(result['SuppliedSingleReaderScope'], True)
        self.assertIs(result['NestedReaderContextOpened'], False)
        self.assertIsNot(result['ExecutedReaderBuffers'], graph.executed)
        self.assertIs(result['FullSemanticABIProof'], False)
        with patch.object(S, '_slim_machines', return_value=[]), self.assertRaises(ValueError):
            S.inspect_machines(suites, bundles, modules, core, graph)

    def test_common_machine_effects_are_recomputed_and_old_booleans_insufficient(self):
        class Rejected(ValueError):
            pass
        names = ('positive', 'mutant-engine', 'mutant-state', 'mutant-panic', 'stress-protected', 'stress-unprotected')
        mutants = dict(zip(names[1:4], ('first', 'second', 'third')))
        def inspect(image, core, *, mutation=None, stress=False):
            if mutation is None and (image.group.startswith('mutant-') or image.group == 'stress-unprotected'):
                raise Rejected('compiled effect')
            return dict(Bytes=image.group + image.owner, Mutation=mutation, Stress=stress)
        core = NS(_ELF=lambda selected, kind: NS(group=selected.parent.name, owner=selected.name))
        attrs = NS(Rejected=Rejected, inspect_lowered=inspect)
        report = dict(Lowerings=[])
        for name in names:
            mutation = 'ctxrt_attribute_stress' if name == 'stress-unprotected' else mutants.get(name)
            stress = name.startswith('stress-')
            left, right = Path('/fake') / name / 'aggregate.o', Path('/fake') / name / 'worker.o'
            report['Lowerings'].append(dict(Group=name, Mutation=mutation, Stress=stress, Object=str(left),
                ActualWorker=dict(Machine=str(right)), Effects=inspect(core._ELF(left, 'ET_REL'), core, mutation=mutation, stress=stress),
                WorkerEffects=inspect(core._ELF(right, 'ET_REL'), core, mutation=mutation, stress=stress),
                OriginalProtectedPredicateRejected=mutation is not None))
        suite, bundle, runner = NS(modules=dict(attributes=attrs)), dict(Result=report), NS(MUTANTS=mutants)
        result = S._attrs_machines(suite, bundle, runner, core)
        self.assertEqual(result['ActualMachineRoles'], 12)
        report['Lowerings'][-1]['WorkerEffects']['Bytes'] = 'forged despite PASS'
        with self.assertRaises(ValueError):
            S._attrs_machines(suite, bundle, runner, core)

    def test_slim_objects_come_from_saved_bytes_not_success_flags(self):
        suites, bundles, watch = fixture()
        suite, bundle = suites['Isolation'], bundles['Isolation']
        selected = suite.output / 'common.o'
        raw = b'synthetic IR bytes, not ELF'
        bundle['Result']['Compilations'] = []
        bundle['Result']['IsolatedCommon'] = [dict(Object=str(selected), ObjectSha256=sha(raw))]
        section = NS(name='.gnu.lto_synthetic', header=NS(sh_size=1, sh_flags=0))
        core = NS(_ELF=Mock(return_value=NS(data=raw, sections=[section])))
        result = S._slim_machines(suite, bundle, core)
        self.assertEqual(result[0]['Sha256'], sha(raw))
        core._ELF.assert_called_once_with(selected, 'ET_REL')
        core._ELF.return_value.sections.append(NS(name='.text', header=NS(sh_size=2, sh_flags=4)))
        with self.assertRaises(ValueError):
            S._slim_machines(suite, bundle, core)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    if output.exists() or output.is_relative_to(ROOT) or ROOT.is_relative_to(output) or not output.is_relative_to(Path(tempfile.gettempdir()).resolve()):
        parser.error('fresh external TEMP output required')
    sources = {selected: selected.read_bytes() for selected in (Path(__file__).resolve(), SUBJECT)}
    report = dict(Status='FAIL', Scope='PURE_SYNTHETIC_FOUR_COMPONENT_REPLAY_CONTROLS_ONLY',
        Tests=0, Errors=0, Failures=0, Skipped=0, ExpectedTestMethods=COUNT,
        SourceHashes={str(selected): sha(raw) for selected, raw in sources.items()}, SourceDrift=[],
        SourceClosureVerified=False, ActualCapturesRead=False, ActualELFTested=False,
        ActualCompilerExecuted=False, TargetExecuted=False, CellContractSatisfied=False,
        FullABIProof=False, GlobalFreezeQualified=False, RequiredCellsSatisfied=0)
    global S
    try:
        if sys.flags.optimize:
            raise ValueError('unoptimized host Python required')
        spec = importlib.util.spec_from_file_location('_component_replay_under_test', SUBJECT)
        S = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = S
        exec(compile(sources[SUBJECT], str(SUBJECT), 'exec'), S.__dict__)
        with patch('subprocess.Popen', side_effect=AssertionError('synthetic tests cannot execute tools')), \
                patch('os.system', side_effect=AssertionError('synthetic tests cannot execute commands')):
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReplayTests)
            if suite.countTestCases() != COUNT:
                raise ValueError('exact implemented test count')
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Errors=len(result.errors), Failures=len(result.failures),
            Skipped=len(result.skipped), Details=[dict(Test=str(test), Error=error) for test, error in result.errors + result.failures])
        if result.wasSuccessful() and result.testsRun == COUNT and not result.skipped:
            report['Status'] = 'PASS'
    except Exception as error:
        report.update(Status='FAIL', Error=type(error).__name__ + ': ' + str(error))
    finally:
        for selected, raw in sources.items():
            try:
                if selected.read_bytes() != raw:
                    report['SourceDrift'].append(str(selected))
            except OSError:
                report['SourceDrift'].append(str(selected))
        report['SourceClosureVerified'] = not report['SourceDrift']
        report['ClosingFilesVerified'] = len(sources) - len(report['SourceDrift'])
        if not report['SourceClosureVerified']:
            report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    target = output / 'results.json'
    target.write_bytes((json.dumps(report, sort_keys=True, indent=2) + '\n').encode('ascii'))
    print('Receipt:', target, sha(target.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
