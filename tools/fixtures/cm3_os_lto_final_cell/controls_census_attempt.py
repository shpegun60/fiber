"""Recompute the original Os census and all 41 ABI controls in one reader.

This additive zero-tool replay does not qualify a whole cell. Previously sealed
facts are comparison targets, never substitutes for consuming admitted bytes.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BATCH = ('tools/fixtures/cm3_os_lto_final_cell/batch_attempt.py',
         'EC52A23182A5B0B4A09E18429E5BFB94902FBC42592785295D7283ACB572F38A')
NORMAL = ('tools/fixtures/cm3_os_lto_final_cell/normal_attempt.py',
          'ADC2D945F336C4325D3A14151DF5B0E8566DE348871211B9EFB0280A3AC8E084')
COMPOSITION = ('tools/fixtures/cm3_os_lto_final_cell/abi_census_attempt.py',
               '529565FAEF586E10DB09C9A913D6E2541CC4E9BBC6169FCEFB802F0B43DAC111')
PINS = {
    'deps': ('tools/fixtures/cm3_os_lto_final_cell/dependency_bytes.py',
        'CB463BE1E7CD98D254E0F5DB7E67283014EAA67FA10C01E2AEEA8913E4E6B9A6'),
    'controls_replay': ('tools/fixtures/cm3_os_lto_final_cell/abi_controls_replay.py',
        '4F2F543A9559628EC20F6E58BA2C5646E14717FDF9792949E67B7F097D36568D'),
}
DOCUMENTS = {
    'tools/fixtures/cm3_os_lto_final_cell/CONTROLS_CENSUS_ATTEMPT_CONTRACT.md':
        '7223DE1CADCD1ACAE1262DD5F98E9EBD36BF6C93D4403E90FEECD2F94FC95BE8',
}
PASS = 'ORIGINAL-CENSUS-AND-ABI-CONTROLS-REPLAYED-NOT-QUALIFIED'
SCOPE = 'CURRENT_CM3_OS_LTO_ORIGINAL_CENSUS_AND_41_ABI_COMMANDS_ONLY'
ARGUMENTS = ('batch-build', 'batch-receipt-sha256', 'batch-artifacts-sha256',
    'native-build', 'native-receipt-sha256', 'native-artifacts-sha256',
    'reference-build', 'reference-receipt-sha256', 'reference-artifacts-sha256',
    'inventory', 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir',
    'normal-build', 'normal-receipt-sha256', 'normal-artifacts-sha256')
NONCLAIMS = ('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof',
    'IsolationReplayed', 'FinalReferenceParity', 'FinalRootTransferProtocolsValidated',
    'CompleteCellProof', 'RequiredCellSatisfied', 'CellContractSatisfied', 'GlobalFreezeQualified',
    'HostedCIQualified', 'ArchiveQualification', 'CpuExecution', 'BoardExecution',
    'ProducerCompilersReexecuted', 'OsProcessTraceVerified', 'SourceToMachineSemanticProof',
    'OriginalTranslationUnitOwnership', 'PolicyEquivalence', 'PriorReaderVerdictInherited')
FACTS = ('OriginalInspectionBindingsReplayed', 'OriginalCensusReplayed', 'DeferredABIReplayed',
         'ABIControlsReplayed', 'ImmutableInputsConsumed', 'InputClosureVerified', 'OutputSealVerified')


def need(value, detail):
    if not value:
        raise ValueError('cm3-os-lto-controls-census: ' + detail)


def sha(raw):
    need(type(raw) is bytes, 'literal byte buffer')
    return hashlib.sha256(raw).hexdigest().upper()


def load(name, path, raw):
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def prepare(args):
    need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and not sys.flags.optimize,
         'fresh isolated unoptimized -I -S -B interpreter')
    need(not any(name == 'elftools' or name.startswith('elftools.') for name in sys.modules),
         'initially unimported parser')
    buffers = {}

    def enroll(relative, digest):
        need(type(relative) is str and relative.startswith('tools/')
             and all(part not in ('', '.', '..') for part in relative.split('/'))
             and '\\' not in relative and ':' not in relative and type(digest) is str
             and re.fullmatch('[0-9A-F]{64}', digest) is not None, 'fixed authenticated source pin')
        path = ROOT / relative
        raw = buffers[path] if path in buffers else path.read_bytes()
        need(sha(raw) == digest, 'source pin/' + relative)
        buffers[path] = raw
        return path, raw

    path, raw = enroll(*BATCH)
    builder = load('_os_controls_census_builder', path, raw)
    path, raw = enroll(*builder.METADATA)
    metadata = load('_os_controls_census_metadata', path, raw)
    path, raw = enroll('tools/fixtures/cm3_os_lto_final_cell/runner.py', metadata.RUNNER_SHA256)
    runner = load('_os_controls_census_reader_entry', path, raw)
    plans = {}

    def merge(registry):
        builder._pins(registry)
        for name, row in registry.items():
            need(name not in plans or plans[name] == row, 'consistent helper/' + name)
            plans[name] = row
            enroll(*row)

    for registry in (metadata.PINS, metadata.LEAF_PINS, builder.PINS):
        merge(registry)
    for row in runner.PINS.values():
        enroll(*row)
    for documents in (runner.DOCUMENTS, metadata.DOCUMENTS):
        for row in documents.items():
            enroll(*row)
    opening = {str(path): sha(raw) for path, raw in sorted(buffers.items())}
    path, raw = enroll(*NORMAL)
    normal = load('_os_controls_census_normal_metadata', path, raw)
    path, raw = enroll(*COMPOSITION)
    composition = load('_os_controls_census_composition_metadata', path, raw)
    for registry in (normal.PINS, composition.PINS,
                     {'normal_entry': NORMAL, 'composition': COMPOSITION}, PINS):
        merge(registry)
    for documents in (normal.DOCUMENTS, composition.DOCUMENTS, DOCUMENTS):
        for row in documents.items():
            enroll(*row)
    own = Path(__file__).resolve()
    buffers[own] = own.read_bytes()
    modules = {name: load('_os_controls_census_admission_' + name, ROOT / row[0], buffers[ROOT / row[0]])
               for name, row in runner.PINS.items()}
    witness = modules['admission'].witness_type(modules['legacy'], modules['capture'], extra_sources=buffers)(args)
    environment = dict(Witness=witness, Modules=modules, HelperPlans=plans)

    def read(path):
        need(path in buffers, 'bootstrap helper outside authenticated opening buffers')
        return buffers[path]

    with patch.object(Path, 'read_bytes', read):
        helpers = {name: load('_os_controls_census_bootstrap_' + name, ROOT / row[0], buffers[ROOT / row[0]])
                   for name, row in plans.items()}
    return runner, environment, builder, helpers, opening, buffers


def admit_normal(args, runner, environment, batch_root, batch, roles, helpers):
    admitted = helpers['composition'].admit_normal(args, runner, environment, batch_root, batch, roles, helpers)
    admit_control_roles(environment['Witness'], batch, roles, helpers)
    return admitted


def admit_control_roles(witness, batch, roles, helpers):
    native = witness.groups['Native']['Result']
    compiler = Path(native['CapturedCompiler'])
    tool_paths = (compiler, compiler.with_name('arm-none-eabi-nm.exe'),
        compiler.with_name('arm-none-eabi-readelf.exe'), Path(native['ResolvedWorkers']['ld']['Path']),
        Path(native['LTOPlugin']['Path']))
    need(len(set(tool_paths)) == 5, 'five distinct control tools/plugin')
    source_root = Path(native['SeedBuild']) / 'source'
    authority = {Path(name): digest for name, digest in native['InputHashes'].items()}
    batch_authority = {Path(name): digest for name, digest in batch['InputHashes'].items()}
    dependencies = {}
    need(type(native['Sources']) is list and len(native['Sources']) == 9, 'nine control source records')
    for source in native['Sources']:
        rows = source.get('ActualCompileDependencies')
        need(type(rows) is list and rows, 'explicit actual capture dependency records')
        for row in rows:
            need(type(row) is dict and set(row) == {'Path', 'Sha256'}, 'typed actual capture dependency')
            path = Path(row['Path'])
            need(path in authority and type(row['Sha256']) is str
                 and re.fullmatch('[0-9A-F]{64}', row['Sha256']) is not None
                 and authority[path] == row['Sha256'], 'capture dependency hash authority')
            if not path.is_relative_to(source_root):
                need(path not in dependencies or dependencies[path] == row['Sha256'], 'consistent external dependency')
                dependencies[path] = row['Sha256']
    need(len(dependencies) == 9, 'nine external CM3 dependency headers')
    selected = dict(dependencies)
    for path in tool_paths:
        need(path in authority, 'control executable/plugin authority')
        selected[path] = authority[path]
    need(len(selected) == 14, 'fourteen distinct explicit control reader roles')
    for path, digest in selected.items():
        need(type(digest) is str and re.fullmatch('[0-9A-F]{64}', digest) is not None
             and batch_authority.get(path) == digest, 'same batch/capture control input hash')
        need(path not in roles or roles[path] == digest, 'consistent control reader role')
        witness.watch.read(path, digest)
        helpers['machine'].retain_identity(witness, path)
        roles[path] = digest
    witness.close()
    return len(selected)


def replay(runner, environment, batch_root, batch, normal_root, handoff, roles, targets, tool):
    witness, plans = environment['Witness'], environment['HelperPlans']
    wanted = ('machine', 'normal_entry', 'normal', 'census', 'policy', 'workers', 'guard',
              'declarations', 'ordinary', 'abi_replay', 'deps', 'recipes', 'diagnostics',
              'probes', 'plan', 'controls_replay')
    plan = {name: plans[name] for name in wanted}
    plan['transport'] = environment['Modules']['capture'].PINS['api']
    with patch('subprocess.Popen', side_effect=AssertionError('immutable controls/census replay cannot start processes')):
        with runner.reader(environment, {'CensusAndABIControls': {str(i): path for i, path in enumerate(roles)}}) as (core, _, frozen):
            def fresh(name, relative):
                spec = importlib.util.spec_from_file_location(name, ROOT / relative)
                module = importlib.util.module_from_spec(spec)
                sys.modules[name] = module
                spec.loader.exec_module(module)
                return module
            helpers = {name: fresh('_os_controls_census_frozen_' + name, row[0]) for name, row in plan.items()}
            view = helpers['machine'].immutable_view(witness.groups['Native']['Result'], roles, helpers['transport'])
            normal, guard = helpers['normal_entry'], helpers['guard']
            bound_batch = normal.structured(view.watch.read(batch_root / 'results.json'))
            bound_native = normal.structured(view.watch.read(witness.groups['Native']['Root'] / 'results.json'))
            bound_handoff = normal.structured(view.watch.read(normal_root / 'results.json'))
            guard._same(bound_batch, batch, 'same immutable batch receipt')
            guard._same(bound_native, witness.groups['Native']['Result'], 'same immutable native receipt')
            guard._same(bound_handoff, handoff, 'same immutable handoff receipt')
            dumps = normal.validate_inspections(normal_root, tool, targets, bound_handoff['OriginalDisassemblies'],
                                                bound_handoff['Commands'], view.watch.read, guard._same)
            census = helpers['normal'].inspect(bound_batch, bound_native, batch_root, core,
                dict(census=helpers['census'], policy=helpers['policy'], port_runner=helpers['workers'], guard=guard),
                view.watch.read, dumps)
            helpers['normal'].require_result(census)
            guard._same(census, bound_handoff['OriginalCensus'], 'recomputed original census comparison')
            abi = helpers['abi_replay'].inspect(bound_batch, bound_native, batch_root, core,
                {name: helpers[name] for name in ('declarations', 'ordinary', 'guard')}, view.watch.read)
            helpers['abi_replay'].require_result(abi)
            control_helpers = {name: helpers[name] for name in
                ('deps', 'recipes', 'declarations', 'ordinary', 'plan', 'diagnostics', 'probes', 'guard', 'transport')}
            control_helpers['port_runner'] = helpers['workers']
            controls = helpers['controls_replay'].inspect(bound_batch, bound_native, batch_root, core,
                                                         control_helpers, view.watch.read)
            helpers['controls_replay'].require_result(controls)
            guard._same(abi['Inputs']['OriginalELF'], census['OriginalInputs']['OrdinaryFinal'],
                        'shared original ordinary image')
            guard._same(abi['PositiveAuthority']['LoadImageComparison'], census['Twins'],
                        'shared original load-image composition')
            guard._same(controls['Inputs']['OriginalELF'], abi['Inputs']['OriginalELF'],
                        'shared controls original image')
            guard._same(controls['Inputs']['ReproducedELF'], abi['Inputs']['ReproducedELF'],
                        'shared controls positive image')
            guard._same(controls['PositiveAuthority']['LoadImageComparison'], census['Twins'],
                        'shared controls positive load image')
        witness.close()
    return census, abi, controls, frozen


def require_result(report, helpers):
    need(type(report) is dict and report.get('Status') == PASS and report.get('Scope') == SCOPE
         and report.get('Profile') == 'CM3' and report.get('Mode') == 'Os-lto'
         and report.get('Linkage') == 'direct' and report.get('LTO') is True, 'bounded composed disposition')
    for key in FACTS:
        need(report.get(key) is True, 'completed composition fact/' + key)
    for key in NONCLAIMS:
        need(report.get(key) is False, 'nonclaim/' + key)
    for key, value in (('ToolInvocations', 0), ('CompilerInvocations', 0), ('RecordedInspectionInvocations', 2),
                       ('RecordedABICommandsReplayed', 41), ('RequiredCellsSatisfied', 0), ('RequiredCellCount', 2774)):
        need(type(report.get(key)) is int and report[key] == value, 'literal separate counter/' + key)
    need(type(report.get('Commands')) is list and report['Commands'] == []
         and type(report.get('ProjectSourceReaderRoles')) is int and report['ProjectSourceReaderRoles'] > 0,
         'no new commands and explicit project roles')
    helpers['normal'].require_result(report.get('OriginalCensus'))
    helpers['abi_replay'].require_result(report.get('DeferredABI'))
    helpers['controls_replay'].require_result(report.get('ABIControls'))
    census, abi, controls = (report[key] for key in ('OriginalCensus', 'DeferredABI', 'ABIControls'))
    same = helpers['guard']._same
    same(abi['Inputs']['OriginalELF'], census['OriginalInputs']['OrdinaryFinal'], 'result shared original image')
    same(abi['PositiveAuthority']['LoadImageComparison'], census['Twins'], 'result shared ABI load image')
    same(controls['Inputs']['OriginalELF'], abi['Inputs']['OriginalELF'], 'result controls original image')
    same(controls['Inputs']['ReproducedELF'], abi['Inputs']['ReproducedELF'], 'result controls positive image')
    same(controls['PositiveAuthority']['LoadImageComparison'], census['Twins'], 'result controls load image')
    need('Error' in report and report['Error'] is None and 'PrimaryError' in report and report['PrimaryError'] is None
         and type(report.get('ClosingErrors')) is list and report['ClosingErrors'] == [], 'clean explicit errors')


def run(args, runner, environment, builder, helpers, opening, buffers):
    witness = environment['Witness']
    report = dict(runner.base_report(witness), Scope=SCOPE, LTO=True,
        OriginalCensus=None, DeferredABI=None, ABIControls=None,
        **dict.fromkeys(FACTS, False), **dict.fromkeys(NONCLAIMS, False))
    suite = None
    try:
        root, batch, roles = helpers['machine'].admit_batch(args, runner, environment, builder, helpers, opening)
        normal_root, handoff, targets, tool, project_count = admit_normal(
            args, runner, environment, root, batch, roles, helpers)
        suite = helpers['session'].suite_type(helpers['utility'], helpers['lto'])(environment, helpers, buffers)
        suite.report = report
        report.update(Batch=dict(Build=str(root), ReceiptSha256=args.batch_receipt_sha256,
            ArtifactsSha256=args.batch_artifacts_sha256), OriginalCensusHandoff=dict(Build=str(normal_root),
            ReceiptSha256=args.normal_receipt_sha256, ArtifactsSha256=args.normal_artifacts_sha256),
            OriginalTargets=targets, InspectionTool=tool, ProjectSourceReaderRoles=project_count,
            RecordedInspectionInvocations=2, RecordedABICommandsReplayed=0,
            Commands=[], ToolInvocations=0, CompilerInvocations=0)
        suite.start()
        suite._save('commands.json', [])
        report['CommandsSha256'] = suite.expected['commands.json']
        census, abi, controls, frozen = replay(runner, environment, root, batch, normal_root,
                                              handoff, roles, targets, tool)
        report.update(Status=PASS, OriginalInspectionBindingsReplayed=True, OriginalCensusReplayed=True,
            DeferredABIReplayed=True, ABIControlsReplayed=True, RecordedABICommandsReplayed=41, OriginalCensus=census,
            DeferredABI=abi, ABIControls=controls, ImmutableInputsConsumed=True, ImmutableReader=frozen)
        suite.verify_objects()
        witness.close()
        suite._verify_outputs()
        helpers['guard'].require_owned_output(suite)
        runner.seal(environment, report, suite.expected)
        require_result(report, helpers)
        print(json.dumps(dict(Status=PASS, ToolInvocations=0, CompilerInvocations=0,
            RecordedInspectionInvocations=2, RecordedABICommandsReplayed=41,
            RequiredCellsSatisfied=0, Output=str(suite.output),
            ReceiptSha256=sha((suite.output / 'results.json').read_bytes()),
            ArtifactsSha256=sha((suite.output / 'artifacts.json').read_bytes())), sort_keys=True), flush=True)
        return report
    except BaseException as error:
        runner.revoke(report, error)
        report.update(**dict.fromkeys(FACTS, False), **dict.fromkeys(NONCLAIMS, False), RecordedABICommandsReplayed=0)
        if suite is not None and suite._started:
            try:
                builder.recover_owned(runner, environment, suite, helpers['guard'])
            except BaseException as secondary:
                report.setdefault('ClosingErrors', []).append('failure persistence: ' + type(secondary).__name__ + ': ' + str(secondary))
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ARGUMENTS:
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    with patch('os.system', side_effect=AssertionError('controls/census replay cannot execute shell commands')), \
            patch('subprocess.Popen', side_effect=AssertionError('controls/census replay cannot start processes')):
        try:
            run(args, *prepare(args))
            return 0
        except BaseException as error:
            try:
                print(type(error).__name__ + ': ' + str(error), file=sys.stderr, flush=True)
            except BaseException:
                pass
            return 1


if __name__ == '__main__':
    raise SystemExit(main())
