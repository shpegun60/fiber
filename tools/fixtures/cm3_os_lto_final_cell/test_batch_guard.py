"""Synthetic catalog correspondence and real TEMP directory identity controls."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import stat
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
METHODS = 12
API = None
PROBE_NAMES = ('types.c', 'attributes.c', 'slot_read.c', 'slot_write.c', 'slot_address.c')
ISO_NAMES = ('OriginalOrdinaryELF', 'OriginalEmitELF', 'OriginalMachine', 'OriginalAssembly',
    'OriginalDisassembly', 'OriginalMap', 'IsolatedOrdinaryELF', 'IsolatedOrdinaryMap', 'IsolatedEmitELF',
    'IsolatedMachine', 'IsolatedAssembly', 'IsolatedMap', 'IsolatedDisassembly', 'StartupObject',
    'PortSource', 'IsolatedIR0', 'IsolatedIR1', 'IsolatedIR2')
COMMON_NAMES = ('Object', 'Machine', 'Disassembly', 'WpaArguments', 'LtransArguments', 'WpaResponse',
    'LtransResponse', 'PartitionList', 'Intermediate', 'Resolution', 'Assembly', 'WrapperArgs', 'DriverSpecs', 'Diagnostics')
COMMON_GROUPS = ('positive', 'mutant-engine', 'mutant-state', 'mutant-panic', 'stress-protected', 'stress-unprotected')
COMPONENT_FIELDS = {
    'ABIControls': ('ABIControlsBuild', 'ABIControlsDeferredReader', 'PositiveAuthority', 'DeclaredProviders',
                    'ABIProbes', 'PreprocessedAttributes'),
    'Isolation': ('IsolationBuild', 'IsolationDeferredReader', 'IsolatedCommon', 'IsolatedLinkedObjects'),
    'PortPolicy': ('PortPolicyBuild', 'PortPolicyDeferredReader', 'PortPolicyCompilations',
                   'PortPolicyLowerings', 'PortPolicyFinalLink'),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def projections(report):
    result = {name: {key: copy.deepcopy(report[key]) for key in keys}
              for name, keys in COMPONENT_FIELDS.items()}
    result['CommonAttributes'] = copy.deepcopy(report['CommonAttributesDeferredReader'])
    return result


def make_report():
    """Full invented metadata only. No compiler, capture or ELF authority."""
    root = Path('C:/synthetic-os-batch-guard')
    report = dict(InputHashes={})
    catalog = []

    def binding(name, *, role=None):
        path = str(root / name)
        digest = sha(('SYNTHETIC NOT ELF: ' + name).encode('ascii'))
        report['InputHashes'][path] = digest
        row = dict(Path=path, Sha256=digest)
        if role is not None:
            row['Role'] = role
        return row

    def add(component, role, value):
        catalog.append(dict(Component=component, Role=role, Path=value['Path'], Sha256=value['Sha256']))

    def build(first, stop):
        return dict(Status='BUILT-PENDING-READER', Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True,
            First=first, Stop=stop, Commands=stop-first, RequiredCellsSatisfied=0, Qualification=False)

    report.update(ABIControlsBuild=build(0, 41), IsolationBuild=build(41, 53), PortPolicyBuild=build(98, 134),
                  DeclaredProviders=dict(SyntheticOnly=True, Count=9), ABIProbes={},
                  PreprocessedAttributes=dict(SyntheticOnly=True, ForwardDeclarations=8, ReverseDeclarations=4))
    original = binding('capture/ordinary/image.elf', role='OriginalELF')
    reproduced = binding('output/links/positive/image.elf', role='ReproducedELF')
    link_map = binding('output/links/positive/image.map', role='ReproducedMap')
    inputs = [original, reproduced]
    report['ABIControlsDeferredReader'] = dict(Status='PENDING', ValidationDeferred=True,
        Inputs=copy.deepcopy(inputs), Map=copy.deepcopy(link_map), RequiredCellsSatisfied=0)
    report['PositiveAuthority'] = dict(Original=original['Path'], OriginalSha256=original['Sha256'],
        Replayed=reproduced['Path'], ReplayedSha256=reproduced['Sha256'], Map=link_map['Path'],
        MapSha256=link_map['Sha256'], ReaderInputs=copy.deepcopy(inputs),
        ValidationDeferred=True, LoadImageValidated=False, LoadImageComparison=None)
    for row in (*inputs, link_map):
        add('ABIControls', row['Role'], row)
    for name in PROBE_NAMES:
        source = binding('output/abi/' + name)
        dep1 = binding('output/abi/' + name + '.discovery.d')
        dep2 = binding('output/abi/' + name + '.compile.d')
        row = dict(Source=source['Path'], SourceSha256=source['Sha256'], Object=None, Preprocessed=None,
                   DiscoveryDependencyFile=dep1['Path'], CompileDependencyFile=dep2['Path'])
        values = dict(Source=source, DiscoveryDependencyFile=dep1, CompileDependencyFile=dep2)
        if name in ('types.c', 'attributes.c'):
            obj = binding('output/abi/' + name + '.o')
            cpp = binding('output/abi/' + name + '.i')
            row.update(Object=obj['Path'], Preprocessed=cpp['Path'],
                SlimIR=dict(Object=obj['Path'], Sha256=obj['Sha256'], SlimIR=True))
            values.update(Object=obj, Preprocessed=cpp)
            if name == 'attributes.c':
                report['PreprocessedAttributes']['PreprocessedSha256'] = cpp['Sha256']
        report['ABIProbes'][name] = row
        for field in ('Source', 'Object', 'Preprocessed', 'DiscoveryDependencyFile', 'CompileDependencyFile'):
            if field in values:
                add('ABIControls', name + '/' + field, values[field])
    originals = [binding('capture/objects/%02d-original.o' % index) for index in range(9)]
    isolated = [binding('output/isolated/%02d-common.o' % index) for index in range(3)]
    iso_inputs = []
    for name in ISO_NAMES:
        value = (originals[8] if name == 'StartupObject' else isolated[int(name[-1])] if name.startswith('IsolatedIR')
                 else binding('isolation/' + name))
        iso_inputs.append(dict(Role=name, **value))
        add('Isolation', name, value)
    report['IsolationDeferredReader'] = dict(Status='PENDING', ValidationDeferred=True,
        Inputs=iso_inputs, RequiredCellsSatisfied=0)
    report['IsolatedCommon'] = [dict(Object=row['Path'], ObjectSha256=row['Sha256']) for row in isolated]
    report['IsolatedLinkedObjects'] = [dict(Index=index, OriginalUnchanged=index >= 3, **row)
        for index, row in enumerate(isolated + originals[3:])]
    report['PortPolicyCompilations'] = [dict(SyntheticOnly=True)]
    port_inputs, lowerings = [], []
    for group in ('selected', 'stress-supported', 'stress-raw'):
        obj, dis, machine, worker_dis = [binding('port/' + group + '/' + name)
                                        for name in ('aggregate.o', 'aggregate.dis', 'machine.o', 'machine.dis')]
        lowerings.append(dict(Group=group, Object=obj['Path'], ObjectSha256=obj['Sha256'],
            Disassembly=dis, ActualWorker=dict(Machine=machine['Path'], MachineSha256=machine['Sha256']),
            WorkerDisassembly=worker_dis, SupportedPolicy=group != 'stress-raw'))
        for name, value in (('Aggregate', obj), ('AggregateDisassembly', dis),
                            ('Machine', machine), ('MachineDisassembly', worker_dis)):
            role = group + '/' + name
            port_inputs.append(dict(Role=role, **value))
            add('PortPolicy', role, value)
    final, final_map, final_dis, machine, machine_dis = [binding('port/final/' + name)
        for name in ('image.elf', 'image.map', 'image.dis', 'machine.o', 'machine.dis')]
    final_objects = originals[:]
    final_objects[3:6] = [binding('port/selected/%02d-new.o' % index) for index in (3, 4, 5)]
    report['PortPolicyLowerings'] = lowerings
    report['PortPolicyFinalLink'] = dict(Path=final['Path'], Sha256=final['Sha256'],
        Map=final_map['Path'], MapSha256=final_map['Sha256'], Disassembly=final_dis,
        ActualWorker=dict(Machine=machine['Path'], MachineSha256=machine['Sha256']), WorkerDisassembly=machine_dis,
        Objects=[row['Path'] for row in final_objects],
        UnchangedOtherSixObjects=[dict(Index=index, **final_objects[index]) for index in (0, 1, 2, 6, 7, 8)])
    for name, value in (('ELF', final), ('Map', final_map), ('Disassembly', final_dis),
                        ('Machine', machine), ('MachineDisassembly', machine_dis), ('Startup', originals[8])):
        role = 'Final/' + name
        port_inputs.append(dict(Role=role, **value))
        add('PortPolicy', role, value)
    report['PortPolicyDeferredReader'] = dict(Status='PENDING', ValidationDeferred=True,
        Inputs=port_inputs, RequiredCellsSatisfied=0)
    attrs = build(53, 98)
    attrs.update(DeferredReaderRequired=True, Lowerings=[])
    for group in COMMON_GROUPS:
        values = {name: binding('attributes/' + group + '/' + name) for name in COMMON_NAMES}
        attrs['Lowerings'].append(dict(Group=group, ValidationDeferred=True, EffectsValidated=False,
                                      WorkerOptionsValidated=False, Roles=values))
        for name in COMMON_NAMES:
            add('CommonAttributes', group + '/' + name, values[name])
    report['CommonAttributesDeferredReader'] = attrs
    report['PendingFinalReader'] = dict(Status='PENDING', FinalReaderExecuted=False,
        OneImmutableReaderScopeRequired=True, InputRoleCount=len(catalog), Inputs=catalog,
        Obligations=['ABI provider/declaration and positive-image reproduction',
            'Original/isolated twins, slot protocols and generated common providers',
            'Six hostile aggregate/worker effects and Os saved-worker options',
            'Selected-port aggregate/final census, paired stress and transfer roots'],
        Components=projections(report), Qualification=False, RequiredCellsSatisfied=0, ImmutableInputsConsumed=False)
    return report


class GuardTests(unittest.TestCase):
    def test_complete_catalog_and_sorted_json_roundtrip_without_io(self):
        report = make_report()
        self.assertEqual(len(report['PendingFinalReader']['Inputs']), 142)
        saved = copy.deepcopy(report)
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('pure catalog cannot read')), \
                patch.object(Path, 'stat', side_effect=AssertionError('pure catalog cannot stat')):
            self.assertIs(API.require_pending_catalog(report), report['PendingFinalReader'])
            decoded = json.loads(json.dumps(report, sort_keys=True))
            API.require_pending_catalog(decoded)
        self.assertEqual(report, saved)

    def test_coherent_pending_omissions_reduced_counts_duplicates_and_order(self):
        for defect in ('omit', 'component-omit', 'duplicate', 'order'):
            with self.subTest(defect=defect):
                report = make_report()
                pending = report['PendingFinalReader']
                if defect in ('omit', 'component-omit'):
                    pending['Inputs'] = [row for row in pending['Inputs'] if not
                        (row['Component'] == 'PortPolicy' and row['Role'] == 'Final/MachineDisassembly')]
                    pending['InputRoleCount'] -= 1
                    if defect == 'component-omit':
                        leaf = pending['Components']['PortPolicy']['PortPolicyDeferredReader']
                        leaf['Inputs'] = [row for row in leaf['Inputs'] if row['Role'] != 'Final/MachineDisassembly']
                elif defect == 'duplicate':
                    pending['Inputs'][1] = copy.deepcopy(pending['Inputs'][0])
                else:
                    pending['Inputs'][0], pending['Inputs'][1] = pending['Inputs'][1], pending['Inputs'][0]
                with self.assertRaises(API.Rejected):
                    API.require_pending_catalog(report)

    def test_pending_role_path_hash_and_component_substitutions(self):
        for component in ('ABIControls', 'Isolation', 'PortPolicy', 'CommonAttributes'):
            for field in ('Role', 'Path', 'Sha256', 'Component'):
                with self.subTest(component=component, field=field):
                    report = make_report()
                    row = next(row for row in report['PendingFinalReader']['Inputs'] if row['Component'] == component)
                    row[field] = {'Role': 'foreign', 'Path': str(Path('C:/foreign.bin')),
                                  'Sha256': 'A' * 64, 'Component': 'foreign'}[field]
                    with self.assertRaises(API.Rejected):
                        API.require_pending_catalog(report)

    def test_coherent_original_role_cuts_cannot_shrink_closed_catalog(self):
        for kind in ('isolation', 'port', 'common-role', 'common-group', 'probe'):
            report = make_report()
            if kind == 'isolation':
                report['IsolationDeferredReader']['Inputs'].pop()
            elif kind == 'port':
                report['PortPolicyLowerings'].pop()
                report['PortPolicyDeferredReader']['Inputs'] = report['PortPolicyDeferredReader']['Inputs'][4:]
            elif kind == 'common-role':
                del report['CommonAttributesDeferredReader']['Lowerings'][0]['Roles']['Machine']
            elif kind == 'common-group':
                report['CommonAttributesDeferredReader']['Lowerings'].pop()
            else:
                del report['ABIProbes']['types.c']
            report['PendingFinalReader']['Components'] = projections(report)
            with self.subTest(kind=kind), self.assertRaises(API.Rejected):
                API.require_pending_catalog(report)

    def test_component_projection_exactness_and_bool_integer_aliases(self):
        for field in ('DeclaredProviders', 'PreprocessedAttributes', 'PortPolicyCompilations'):
            report = make_report()
            component = 'PortPolicy' if field.startswith('PortPolicy') else 'ABIControls'
            report['PendingFinalReader']['Components'][component][field] = {}
            with self.subTest(field=field), self.assertRaises(API.Rejected):
                API.require_pending_catalog(report)
        report = make_report()
        report['PendingFinalReader']['Components']['ABIControls']['ABIControlsBuild']['First'] = False
        with self.assertRaises(API.Rejected):
            API.require_pending_catalog(report)

    def test_input_hash_fallback_missing_explicit_conflict_and_aliases(self):
        report = make_report()
        path = report['ABIProbes']['types.c']['DiscoveryDependencyFile']
        self.assertIn(path, report['InputHashes'])
        del report['InputHashes'][path]
        with self.assertRaises(API.Rejected):
            API.require_pending_catalog(report)
        for defect in ('conflict', 'bool-hash', 'duplicate-path', 'relative'):
            report = make_report()
            row = report['ABIProbes']['types.c']
            if defect == 'conflict':
                row['SourceSha256'] = 'B' * 64
            elif defect == 'bool-hash':
                report['InputHashes'][row['Source']] = True
            elif defect == 'duplicate-path':
                report['InputHashes'][row['Source'].upper()] = report['InputHashes'][row['Source']]
            else:
                report['InputHashes']['relative'] = 'A' * 64
            with self.subTest(defect=defect), self.assertRaises(API.Rejected):
                API.require_pending_catalog(report)

    def test_original_counters_and_pending_booleans_strict(self):
        changes = (lambda r: r['ABIControlsBuild'].update(First=False),
            lambda r: r['IsolationBuild'].update(Commands=12.0),
            lambda r: r['PortPolicyBuild'].update(LTO=1),
            lambda r: r['PortPolicyDeferredReader'].update(RequiredCellsSatisfied=False),
            lambda r: r['PendingFinalReader'].update(InputRoleCount=142.0),
            lambda r: r['PendingFinalReader'].update(FinalReaderExecuted=0),
            lambda r: r['PendingFinalReader'].update(RequiredCellsSatisfied=False))
        for index, change in enumerate(changes):
            report = make_report()
            change(report)
            report['PendingFinalReader']['Components'] = projections(report)
            with self.subTest(case=index), self.assertRaises(API.Rejected):
                API.require_pending_catalog(report)

    def test_original_positive_probe_provider_and_startup_crossbindings(self):
        for defect in ('positive', 'probe', 'isolated', 'startup', 'index'):
            report = make_report()
            if defect == 'positive':
                report['PositiveAuthority']['MapSha256'] = 'A' * 64
            elif defect == 'probe':
                report['ABIProbes']['types.c']['SlimIR']['Sha256'] = 'A' * 64
            elif defect == 'isolated':
                report['IsolatedCommon'][0]['Object'] = report['IsolatedCommon'][1]['Object']
                report['IsolatedCommon'][0]['ObjectSha256'] = report['IsolatedCommon'][1]['ObjectSha256']
            elif defect == 'startup':
                report['PortPolicyFinalLink']['UnchangedOtherSixObjects'][-1]['Path'] = report['IsolatedCommon'][0]['Object']
            else:
                report['IsolatedLinkedObjects'][0]['Index'] = False
            report['PendingFinalReader']['Components'] = projections(report)
            with self.subTest(defect=defect), self.assertRaises(API.Rejected):
                API.require_pending_catalog(report)

    def test_owned_output_success_is_read_only(self):
        with tempfile.TemporaryDirectory(prefix='os-owned-output-') as root:
            output = Path(root) / 'output'
            output.mkdir()
            info = output.lstat()
            suite = SimpleNamespace(_started=True, output=output, output_identity=(info.st_dev, info.st_ino))
            before = dict(suite.__dict__)
            with patch.object(Path, 'write_bytes', side_effect=AssertionError('guard cannot write')), \
                    patch.object(Path, 'mkdir', side_effect=AssertionError('guard cannot mkdir')):
                self.assertEqual(API.require_owned_output(suite), output)
            self.assertEqual(suite.__dict__, before)
            self.assertEqual(list(output.iterdir()), [])

    def test_unclaimed_missing_file_and_literal_identity_rejected(self):
        with tempfile.TemporaryDirectory(prefix='os-unclaimed-output-') as root:
            output = Path(root) / 'output'
            output.mkdir()
            info = output.lstat()
            valid = dict(_started=True, output=output, output_identity=(info.st_dev, info.st_ino))
            for change in ({'_started': False}, {'_started': 1}, {'output_identity': None},
                    {'output_identity': (False, info.st_ino)}, {'output_identity': (info.st_dev, float(info.st_ino))},
                    {'output_identity': [info.st_dev, info.st_ino]}, {'output': Path(root) / 'missing'},
                    {'output': str(output)}):
                with self.subTest(change=change), self.assertRaises(API.Rejected):
                    API.require_owned_output(SimpleNamespace(**dict(valid, **change)))
            file = Path(root) / 'file'
            file.write_bytes(b'not a directory')
            entry = file.lstat()
            with self.assertRaises(API.Rejected):
                API.require_owned_output(SimpleNamespace(_started=True, output=file,
                    output_identity=(entry.st_dev, entry.st_ino)))

    def test_replaced_symlink_or_reparse_output_rejected(self):
        with tempfile.TemporaryDirectory(prefix='os-replaced-output-') as root:
            output = Path(root) / 'output'
            output.mkdir()
            info = output.lstat()
            suite = SimpleNamespace(_started=True, output=output, output_identity=(info.st_dev, info.st_ino))
            output.rename(Path(root) / 'old-output')
            output.mkdir()
            with self.assertRaises(API.Rejected):
                API.require_owned_output(suite)
            for mode, attributes in ((stat.S_IFLNK | 0o777, 0), (stat.S_IFDIR | 0o777, 0x400)):
                fake = SimpleNamespace(st_mode=mode, st_file_attributes=attributes,
                    st_dev=info.st_dev, st_ino=info.st_ino)
                with self.subTest(attributes=attributes), patch.object(Path, 'lstat', return_value=fake), \
                        self.assertRaises(API.Rejected):
                    API.require_owned_output(suite)

    def test_refusals_never_modify_unrelated_or_preexisting_files(self):
        with tempfile.TemporaryDirectory(prefix='os-no-recovery-write-') as root:
            output = Path(root) / 'output'
            output.mkdir()
            outside = Path(root) / 'unrelated.bin'
            outside.write_bytes(b'keep unrelated')
            receipt = output / 'results.json'
            receipt.write_bytes(b'keep preexisting receipt')
            before = (outside.read_bytes(), receipt.read_bytes())
            suite = SimpleNamespace(_started=False, output=output, output_identity=None)
            with patch.object(Path, 'write_bytes', side_effect=AssertionError('guard attempted write')), \
                    patch.object(Path, 'mkdir', side_effect=AssertionError('guard attempted mkdir')), \
                    self.assertRaises(API.Rejected):
                API.require_owned_output(suite)
            self.assertEqual(before, (outside.read_bytes(), receipt.read_bytes()))


def main(argv=None):
    global API
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args(argv)
    output = Path(args.output_dir).resolve()
    if output.exists() or output == ROOT or ROOT in output.parents or output in ROOT.parents:
        parser.error('fresh external output directory required')
    paths = dict(subject=HERE / 'batch_guard.py', tests=Path(__file__).resolve())
    buffers = {name: path.read_bytes() for name, path in paths.items()}
    report = dict(Status='FAIL', Scope='PURE_SYNTHETIC_OS_CATALOG_AND_TEMP_OUTPUT_GUARDS', Tests=0,
        ExpectedTestMethods=METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={str(paths[name]): sha(raw) for name, raw in buffers.items()}, SourceDrift=[],
        SourceClosureVerified=False, ActualCaptureRead=False, ActualELFParsed=False,
        ExternalToolsExecuted=0, Qualification=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError('unoptimized Python required')
        with patch('subprocess.Popen', side_effect=AssertionError('pure tests cannot spawn tools')):
            API = ModuleType('_os_batch_guard_test_subject')
            API.__file__ = str(paths['subject'])
            exec(compile(buffers['subject'], str(paths['subject']), 'exec'), API.__dict__)
            tests = unittest.defaultTestLoader.loadTestsFromTestCase(GuardTests)
            if tests.countTestCases() != METHODS:
                raise ValueError('exact twelve methods required')
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
    report['SourceClosureVerified'] = len(report['SourceHashes']) == 2 and not report['SourceDrift']
    if not report['SourceClosureVerified']:
        report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / 'results.json'
    receipt.write_bytes((json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii'))
    print('Receipt:', receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
