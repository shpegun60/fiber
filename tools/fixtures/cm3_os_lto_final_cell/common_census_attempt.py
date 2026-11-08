"""Replay original Os census, ABI, isolation and common attributes in one reader.

All producer verdicts remain comparison targets. Pending cold-inline attribution
is retained without granting common-policy, whole-cell or execution credit.
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
CONTROLS = ('tools/fixtures/cm3_os_lto_final_cell/controls_census_attempt.py',
            '86FD9DE1DBFF1ED06546AB35FD7EE9B26F917ACF47440461BEAD40708378C234')
ISOLATION = ('tools/fixtures/cm3_os_lto_final_cell/isolation_census_attempt.py',
             '3B1C0F0C29EB3C1DB4E5E3730B2A59B585979300B870DC8B2C5D398939D47C2A')
PINS = {
    'common_workers': ('tools/fixtures/cm3_os_lto_final_cell/common_workers.py',
        'F12A77717924A11DF5F6FA29800271D335A09C475819171C31EFC0B757474EDB'),
    'common_effects': ('tools/fixtures/cm3_os_lto_final_cell/common_effects.py',
        '800942F1CA34DCE0198258C13D85F5BA422DF6BF88726694360C16B39270C81D'),
    'common_lowered': ('tools/fixtures/cm3_os_lto_final_cell/common_lowered.py',
        'C2B67031224EA4E8F76982B7F1BEEF7D7871516543E5CAC0CE9DC30464A58FE9'),
    'common_replay': ('tools/fixtures/cm3_os_lto_final_cell/common_replay.py',
        'D8EEDF06F1C83FB195236AB259A0546A71CB9F63AC627823B7179EE4BA3C8532'),
}
DOCUMENTS = {
    'tools/fixtures/cm3_os_lto_final_cell/COMMON_CENSUS_ATTEMPT_CONTRACT.md':
        '96AFC7DB6D241FAE94A77F6661CACA7164983D3A868C8D3060BB0FD83B255055',
}
PASS = 'ORIGINAL-CENSUS-ABI-ISOLATION-AND-COMMON-REPLAYED-NOT-QUALIFIED'
PENDING = 'ORIGINAL-CENSUS-ABI-ISOLATION-AND-COMMON-REPLAYED-PENDING-ATTRIBUTION'
SCOPE = 'CURRENT_CM3_OS_LTO_CENSUS_41_ABI_12_ISOLATION_45_COMMON_COMMANDS_ONLY'
ARGUMENTS = ('batch-build', 'batch-receipt-sha256', 'batch-artifacts-sha256',
    'native-build', 'native-receipt-sha256', 'native-artifacts-sha256',
    'reference-build', 'reference-receipt-sha256', 'reference-artifacts-sha256',
    'inventory', 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir',
    'normal-build', 'normal-receipt-sha256', 'normal-artifacts-sha256')
NONCLAIMS = ('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof',
    'FullIsolationProof', 'WholeSlotAccessIsolation', 'IRImportClosureValidated', 'FinalReferenceParity',
    'FinalRootTransferProtocolsValidated', 'CurrentSlotIsolationProven', 'CanonicalProtocolValidated',
    'FinalRootRelocationProof', 'CommonAttributePolicyProven', 'SelectedPortAttributePolicyProven',
    'NegativeLinkControlsExecuted', 'CompleteObjectProof', 'SourceIRProof', 'KernelRuntimeProof',
    'FinalLinkContractValidated', 'RuntimeProviderBindingsValidated',
    'CompleteCellProof', 'RequiredCellSatisfied', 'CellContractSatisfied', 'GlobalFreezeQualified',
    'HostedCIQualified', 'ArchiveQualification', 'CpuExecution', 'BoardExecution',
    'ProducerCompilersReexecuted', 'OsProcessTraceVerified', 'SourceToMachineSemanticProof',
    'OriginalTranslationUnitOwnership', 'PolicyEquivalence', 'PriorReaderVerdictInherited',
    'FullAttributeEquivalence', 'TransitiveProtection', 'FullInstructionSemantics', 'AllProtectedBodiesClean')
FACTS = ('OriginalInspectionBindingsReplayed', 'OriginalCensusReplayed', 'DeferredABIReplayed',
    'ABIControlsReplayed', 'IsolationComponentReplayed', 'CommonAttributesReplayed',
    'ImmutableInputsConsumed', 'InputClosureVerified', 'OutputSealVerified')
COUNTERS = (('RecordedABICommandsReplayed', 41), ('RecordedIsolationCommandsReplayed', 12),
            ('RecordedCommonAttributeCommandsReplayed', 45))
COMMON_HELPERS = ('deps', 'recipes', 'probes', 'ownership', 'guard', 'transport',
    'controls_replay', 'attributes_phase', 'attributes', 'attribute_runner',
    'common_workers', 'common_effects', 'common_lowered')
LOWERED_HELPERS = ('attributes', 'attribute_runner', 'common_workers', 'common_effects', 'transport')


def need(value, detail):
    if not value:
        raise ValueError('cm3-os-lto-common-census: ' + detail)


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
        need(digest != '0' * 64, 'final source pin required/' + relative)
        path = ROOT / relative
        raw = buffers[path] if path in buffers else path.read_bytes()
        need(sha(raw) == digest, 'source pin/' + relative)
        buffers[path] = raw
        return path, raw

    path, raw = enroll(*BATCH)
    builder = load('_os_common_census_builder', path, raw)
    path, raw = enroll(*builder.METADATA)
    metadata = load('_os_common_census_metadata', path, raw)
    path, raw = enroll('tools/fixtures/cm3_os_lto_final_cell/runner.py', metadata.RUNNER_SHA256)
    runner = load('_os_common_census_reader_entry', path, raw)
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
    entries = []
    for name, row in (('normal', NORMAL), ('composition', COMPOSITION),
                      ('controls', CONTROLS), ('isolation', ISOLATION)):
        path, raw = enroll(*row)
        entries.append(load('_os_common_census_' + name + '_metadata', path, raw))
    for registry in (*(entry.PINS for entry in entries),
            {'normal_entry': NORMAL, 'composition': COMPOSITION, 'controls_composition': CONTROLS,
             'isolation_composition': ISOLATION}, PINS):
        merge(registry)
    for documents in (*(entry.DOCUMENTS for entry in entries), DOCUMENTS):
        for row in documents.items():
            enroll(*row)
    own = Path(__file__).resolve()
    buffers[own] = own.read_bytes()
    modules = {name: load('_os_common_census_admission_' + name, ROOT / row[0], buffers[ROOT / row[0]])
               for name, row in runner.PINS.items()}
    witness = modules['admission'].witness_type(modules['legacy'], modules['capture'], extra_sources=buffers)(args)
    environment = dict(Witness=witness, Modules=modules, HelperPlans=plans)

    def read(path):
        need(path in buffers, 'bootstrap helper outside authenticated opening buffers')
        return buffers[path]

    with patch.object(Path, 'read_bytes', read):
        helpers = {name: load('_os_common_census_bootstrap_' + name, ROOT / row[0], buffers[ROOT / row[0]])
                   for name, row in plans.items()}
    return runner, environment, builder, helpers, opening, buffers


def admit_normal(args, runner, environment, batch_root, batch, roles, helpers):
    return helpers['isolation_composition'].admit_normal(
        args, runner, environment, batch_root, batch, roles, helpers)


def shared_isolation(census, isolation, same, label):
    for role, original in (('OriginalOrdinaryELF', 'OrdinaryFinal'), ('OriginalEmitELF', 'OriginalFinal'),
                           ('OriginalMachine', 'OriginalLtrans')):
        same(isolation['Inputs'][role], census['OriginalInputs'][original], label + ' isolation ' + role)
    same(isolation['LoadImageComparisons']['OriginalTwins'], census['Twins'], label + ' isolation load image')
    same(isolation['OriginalDumps'], census['DumpInputs'], label + ' isolation original inspections')


def shared_common(common, isolation, authority, same, label):
    for key in ('Root', 'SourceRoot', 'CaptureRoot', 'Cohort', 'SourceInventorySha256'):
        same(common[key], isolation[key], label + ' common ' + key)
    same(common['Root'], authority['BatchRoot'], label + ' common batch root')
    same(common['CaptureRoot'], authority['NativeRoot'], label + ' common native root')
    for key in ('Cohort', 'SourceInventorySha256'):
        same(common[key], authority[key], label + ' common outer ' + key)
    for key in ('Manifest', 'CommandJournal', 'NativeReceipt'):
        same(common['AuthorityInputs'][key], isolation['AuthorityInputs'][key], label + ' common ' + key)
    same(common['AuthorityInputs']['BatchReceipt'], authority['BatchReceipt'], label + ' common batch receipt')
    same(common['AuthorityInputs']['Manifest'], authority['Manifest'], label + ' common batch manifest')
    same(common['AuthorityInputs']['NativeReceipt'], authority['NativeReceipt'], label + ' common native receipt')
    same(common['SourceOwnership'], isolation['SourceOwnership'], label + ' common source ownership')
    same(common['SourceOwnershipInputs'], isolation['SourceOwnershipInputs'], label + ' common source bindings')


def common_result(common, helpers):
    helpers['common_replay'].require_result(common)
    lowered = common['LoweredProofs']
    helpers['common_lowered'].require_result(lowered,
        {name: helpers[name] for name in LOWERED_HELPERS})
    pending = lowered['UnresolvedAttribution']
    need(type(pending) is list, 'explicit common attribution list')
    need(lowered['CommonAttributionClosed'] is (not pending), 'consistent common attribution disposition')
    return pending


def replay(runner, environment, batch_root, batch, normal_root, handoff, roles, targets, tool):
    witness, plans = environment['Witness'], environment['HelperPlans']
    wanted = ('machine', 'normal_entry', 'normal', 'census', 'policy', 'workers', 'guard',
        'declarations', 'ordinary', 'abi_replay', 'deps', 'recipes', 'diagnostics', 'probes', 'plan',
        'controls_replay', 'ownership', 'isolation_replay', 'isolation_slots', 'os_slot', 'neutral_slot',
        'attributes_phase', 'attributes', 'attribute_runner', 'common_workers', 'common_effects', 'common_lowered', 'common_replay')
    plan = {name: plans[name] for name in wanted}
    plan['transport'] = environment['Modules']['capture'].PINS['api']
    with patch('os.system', side_effect=AssertionError('immutable common/census replay cannot execute shell commands')), \
            patch('subprocess.Popen', side_effect=AssertionError('immutable common/census replay cannot start processes')):
        with runner.reader(environment, {'CensusABIIsolationAndCommon': {str(i): path for i, path in enumerate(roles)}}) as (core, _, frozen):
            def fresh(name, relative):
                spec = importlib.util.spec_from_file_location(name, ROOT / relative)
                module = importlib.util.module_from_spec(spec)
                sys.modules[name] = module
                spec.loader.exec_module(module)
                return module
            helpers = {name: fresh('_os_common_census_frozen_' + name, row[0]) for name, row in plan.items()}
            view = helpers['machine'].immutable_view(witness.groups['Native']['Result'], roles, helpers['transport'])
            normal, guard = helpers['normal_entry'], helpers['guard']
            batch_raw = view.watch.read(batch_root / 'results.json')
            native_root = witness.groups['Native']['Root']
            native_raw = view.watch.read(native_root / 'results.json')
            bound_batch, bound_native = normal.structured(batch_raw), normal.structured(native_raw)
            bound_handoff = normal.structured(view.watch.read(normal_root / 'results.json'))
            guard._same(bound_batch, batch, 'same immutable batch receipt')
            guard._same(bound_native, witness.groups['Native']['Result'], 'same immutable native receipt')
            guard._same(bound_handoff, handoff, 'same immutable handoff receipt')
            authority = dict(BatchRoot=str(batch_root), NativeRoot=str(native_root),
                Cohort=bound_native['Cohort'], SourceInventorySha256=bound_native['SourceInventorySha256'],
                BatchReceipt=dict(Path=str(batch_root / 'results.json'), Sha256=sha(batch_raw)),
                Manifest=dict(Path=str(batch_root / 'artifacts.json'), Sha256=sha(view.watch.read(batch_root / 'artifacts.json'))),
                NativeReceipt=dict(Path=str(native_root / 'results.json'), Sha256=sha(native_raw)))
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
            guard._same(abi['Inputs']['OriginalELF'], census['OriginalInputs']['OrdinaryFinal'], 'shared original image')
            guard._same(abi['PositiveAuthority']['LoadImageComparison'], census['Twins'], 'shared ABI load image')
            guard._same(controls['Inputs']['OriginalELF'], abi['Inputs']['OriginalELF'], 'shared controls original image')
            guard._same(controls['Inputs']['ReproducedELF'], abi['Inputs']['ReproducedELF'], 'shared controls positive image')
            guard._same(controls['PositiveAuthority']['LoadImageComparison'], census['Twins'], 'shared controls load image')
            isolation_helpers = {name: helpers[name] for name in
                ('deps', 'recipes', 'probes', 'ownership', 'guard', 'transport', 'controls_replay',
                 'isolation_slots', 'os_slot', 'neutral_slot')}
            isolation = helpers['isolation_replay'].inspect(bound_batch, bound_native, batch_root, core,
                isolation_helpers, view.watch.read, original_dumps=dumps)
            helpers['isolation_replay'].require_result(isolation)
            helpers['isolation_slots'].require_result(isolation['SlotProofs'])
            shared_isolation(census, isolation, guard._same, 'shared')
            common = helpers['common_replay'].inspect(bound_batch, bound_native, batch_root, core,
                {name: helpers[name] for name in COMMON_HELPERS}, view.watch.read)
            common_result(common, helpers)
            shared_common(common, isolation, authority, guard._same, 'shared')
        witness.close()
    return census, abi, controls, isolation, common, frozen


def require_result(report, helpers):
    need(type(report) is dict and report.get('Status') in (PASS, PENDING) and report.get('Scope') == SCOPE
         and report.get('Profile') == 'CM3' and report.get('Mode') == 'Os-lto'
         and report.get('Linkage') == 'direct' and report.get('LTO') is True, 'bounded composed disposition')
    for key in FACTS:
        need(report.get(key) is True, 'completed composition fact/' + key)
    for key in NONCLAIMS:
        need(report.get(key) is False, 'nonclaim/' + key)
    for key, value in (('ToolInvocations', 0), ('CompilerInvocations', 0), ('RecordedInspectionInvocations', 2),
                       *COUNTERS, ('RequiredCellsSatisfied', 0), ('RequiredCellCount', 2774)):
        need(type(report.get(key)) is int and report[key] == value, 'literal separate counter/' + key)
    need(type(report.get('Commands')) is list and report['Commands'] == []
         and type(report.get('ProjectSourceReaderRoles')) is int and report['ProjectSourceReaderRoles'] > 0,
         'no new commands and explicit project roles')
    for name, key in (('normal', 'OriginalCensus'), ('abi_replay', 'DeferredABI'),
                      ('controls_replay', 'ABIControls'), ('isolation_replay', 'IsolationComponent')):
        helpers[name].require_result(report.get(key))
    helpers['isolation_slots'].require_result(report['IsolationComponent']['SlotProofs'])
    common = report['CommonAttributes']
    pending = common_result(common, helpers)
    same = helpers['guard']._same
    same(report['UnresolvedAttribution'], pending, 'outer common attribution projection')
    need(report.get('CommonAttributionClosed') is (not pending)
         and report['Status'] == (PENDING if pending else PASS), 'honest outer attribution disposition')
    census, abi, controls, isolation = (report[key] for key in ('OriginalCensus', 'DeferredABI', 'ABIControls', 'IsolationComponent'))
    same(abi['Inputs']['OriginalELF'], census['OriginalInputs']['OrdinaryFinal'], 'result shared original image')
    same(abi['PositiveAuthority']['LoadImageComparison'], census['Twins'], 'result shared ABI load image')
    same(controls['Inputs']['OriginalELF'], abi['Inputs']['OriginalELF'], 'result shared controls original image')
    same(controls['Inputs']['ReproducedELF'], abi['Inputs']['ReproducedELF'], 'result shared controls positive image')
    same(controls['PositiveAuthority']['LoadImageComparison'], census['Twins'], 'result shared controls load image')
    shared_isolation(census, isolation, same, 'result shared')
    native = [row for row in report['ProducerBindings'] if row['Side'] == 'Native']
    need(len(native) == 1, 'one native producer authority')
    batch = report['Batch']
    authority = dict(BatchRoot=batch['Build'], NativeRoot=native[0]['Build'], Cohort=report['Cohort'],
        SourceInventorySha256=report['SourceInventorySha256'],
        BatchReceipt=dict(Path=str(Path(batch['Build']) / 'results.json'), Sha256=batch['ReceiptSha256']),
        Manifest=dict(Path=str(Path(batch['Build']) / 'artifacts.json'), Sha256=batch['ArtifactsSha256']),
        NativeReceipt=dict(Path=str(Path(native[0]['Build']) / 'results.json'), Sha256=native[0]['ReceiptSha256']))
    shared_common(common, isolation, authority, same, 'result shared')
    need('Error' in report and report['Error'] is None and 'PrimaryError' in report and report['PrimaryError'] is None
         and type(report.get('ClosingErrors')) is list and report['ClosingErrors'] == [], 'clean explicit errors')


def run(args, runner, environment, builder, helpers, opening, buffers):
    witness = environment['Witness']
    report = dict(runner.base_report(witness), Scope=SCOPE, LTO=True, OriginalCensus=None,
        DeferredABI=None, ABIControls=None, IsolationComponent=None, CommonAttributes=None,
        CommonAttributionClosed=False, UnresolvedAttribution=[],
        **dict.fromkeys(FACTS, False), **dict.fromkeys(NONCLAIMS, False),
        **dict.fromkeys((key for key, _ in COUNTERS), 0))
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
            RecordedInspectionInvocations=2, Commands=[], ToolInvocations=0, CompilerInvocations=0)
        suite.start()
        suite._save('commands.json', [])
        report['CommandsSha256'] = suite.expected['commands.json']
        census, abi, controls, isolation, common, frozen = replay(runner, environment, root, batch, normal_root,
            handoff, roles, targets, tool)
        pending = common['LoweredProofs']['UnresolvedAttribution']
        report.update(Status=PENDING if pending else PASS, OriginalInspectionBindingsReplayed=True,
            OriginalCensusReplayed=True, DeferredABIReplayed=True, ABIControlsReplayed=True,
            IsolationComponentReplayed=True, CommonAttributesReplayed=True, ImmutableInputsConsumed=True,
            OriginalCensus=census, DeferredABI=abi, ABIControls=controls, IsolationComponent=isolation,
            CommonAttributes=common, CommonAttributionClosed=not pending, UnresolvedAttribution=pending,
            ImmutableReader=frozen, **dict(COUNTERS))
        suite.verify_objects()
        witness.close()
        suite._verify_outputs()
        helpers['guard'].require_owned_output(suite)
        runner.seal(environment, report, suite.expected)
        require_result(report, helpers)
        print(json.dumps(dict(Status=report['Status'], CommonAttributionClosed=report['CommonAttributionClosed'],
            ToolInvocations=0, CompilerInvocations=0, RecordedInspectionInvocations=2, **dict(COUNTERS),
            RequiredCellsSatisfied=0, Output=str(suite.output),
            ReceiptSha256=sha((suite.output / 'results.json').read_bytes()),
            ArtifactsSha256=sha((suite.output / 'artifacts.json').read_bytes())), sort_keys=True), flush=True)
        return report
    except BaseException as error:
        runner.revoke(report, error)
        report.update(**dict.fromkeys(FACTS, False), **dict.fromkeys(NONCLAIMS, False),
            **dict.fromkeys((key for key, _ in COUNTERS), 0), CommonAttributionClosed=False)
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
    with patch('os.system', side_effect=AssertionError('common/census replay cannot execute shell commands')), \
            patch('subprocess.Popen', side_effect=AssertionError('common/census replay cannot start processes')):
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
