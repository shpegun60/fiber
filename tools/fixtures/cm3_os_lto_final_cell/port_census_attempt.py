"""Replay original Os census, ABI, isolation, common and selected-port evidence.

All six components execute in one fresh immutable reader. Recorded commands
are replayed as evidence only; this entrypoint starts no producer or tool.
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
BASE = ('tools/fixtures/cm3_os_lto_final_cell/common_census_attempt.py',
        '043453302BFEEF871105100C3AA4878AB8B00FB8FFC16126DE08CBD603DDB485')
SEALED = ('tools/fixtures/cm3_os_lto_final_cell/common_sealed_attempt.py',
          '97100FEEB934EBF603D8DB3C9961161272C8DA8F8FAB86D3B3D2D3AE67BF5F81')
PINS = {
    'common_composition': BASE,
    'sealed_composition': SEALED,
    'port_replay': ('tools/fixtures/cm3_os_lto_final_cell/port_replay.py',
        'C88995AC5343B376AC1E73F0570F8AF9F025144820BD88556CF0A57814B8DE94'),
    'port_lowered': ('tools/fixtures/cm3_os_lto_final_cell/port_lowered.py',
        '94718099EB09108ABF678FFA967487A060F38CF9ABF7FCDEB152799BF47D89C7'),
}
DOCUMENTS = {
    'tools/fixtures/cm3_os_lto_final_cell/PORT_CENSUS_ATTEMPT_CONTRACT.md':
        'D69B7D7344CE4CC10FAB420EF59BEAA49659895D19B53B209C762E5A2B9CEEAB',
}
ARGUMENTS = ('batch-build', 'batch-receipt-sha256', 'batch-artifacts-sha256',
    'native-build', 'native-receipt-sha256', 'native-artifacts-sha256',
    'reference-build', 'reference-receipt-sha256', 'reference-artifacts-sha256',
    'inventory', 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir',
    'normal-build', 'normal-receipt-sha256', 'normal-artifacts-sha256')
PASS = 'ORIGINAL-CENSUS-ABI-ISOLATION-COMMON-AND-PORT-REPLAYED-NOT-QUALIFIED'
PENDING = 'ORIGINAL-CENSUS-ABI-ISOLATION-COMMON-AND-PORT-REPLAYED-PENDING-ATTRIBUTION'
SCOPE = 'CURRENT_CM3_OS_LTO_CENSUS_41_ABI_12_ISOLATION_45_COMMON_36_PORT_COMMANDS_ONLY'
FACTS = ('OriginalInspectionBindingsReplayed', 'OriginalCensusReplayed', 'DeferredABIReplayed',
    'ABIControlsReplayed', 'IsolationComponentReplayed', 'CommonAttributesReplayed',
    'PortPolicyComponentReplayed', 'ImmutableInputsConsumed', 'InputClosureVerified', 'OutputSealVerified')
COUNTERS = (('RecordedABICommandsReplayed', 41), ('RecordedIsolationCommandsReplayed', 12),
            ('RecordedCommonAttributeCommandsReplayed', 45), ('RecordedPortPolicyCommandsReplayed', 36))
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
    'FullAttributeEquivalence', 'TransitiveProtection', 'FullInstructionSemantics', 'AllProtectedBodiesClean',
    'GeneralRegistersOnlyEffectProved', 'RawCommonAttributesAloneProved', 'UnchangedOtherSixGeneratedBodies')
COMMON_HELPERS = ('deps', 'recipes', 'probes', 'ownership', 'guard', 'transport',
    'controls_replay', 'attributes_phase', 'attributes', 'attribute_runner',
    'common_workers', 'common_effects', 'common_lowered')
PORT_HELPERS = ('deps', 'recipes', 'guard', 'transport', 'controls_replay', 'ownership',
    'attributes', 'port_phase', 'port_runner', 'policy', 'census', 'effects', 'port_lowered')
LOWERED_HELPERS = ('port_runner', 'port_phase', 'transport', 'census', 'policy', 'effects', 'attributes')
ALIASES = {'port_phase': 'port_policy', 'port_runner': 'workers', 'effects': 'common_effects'}


def need(value, detail):
    if not value:
        raise ValueError('cm3-os-lto-port-census: ' + detail)


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
    builder = load('_os_port_census_builder', path, raw)
    path, raw = enroll(*builder.METADATA)
    metadata = load('_os_port_census_metadata', path, raw)
    path, raw = enroll('tools/fixtures/cm3_os_lto_final_cell/runner.py', metadata.RUNNER_SHA256)
    runner = load('_os_port_census_reader_entry', path, raw)
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
    path, raw = enroll(*BASE)
    base = load('_os_port_census_common_metadata', path, raw)
    path, raw = enroll(*SEALED)
    sealed = load('_os_port_census_sealed_metadata', path, raw)
    need(base.BATCH == sealed.BATCH == BATCH and sealed.BASE == BASE
         and base.ARGUMENTS == sealed.ARGUMENTS == ARGUMENTS, 'fixed common bootstrap/CLI')
    entries = []
    for name, row in (('normal', base.NORMAL), ('composition', base.COMPOSITION),
                      ('controls', base.CONTROLS), ('isolation', base.ISOLATION)):
        path, raw = enroll(*row)
        entries.append(load('_os_port_census_' + name + '_metadata', path, raw))
    for registry in (*(entry.PINS for entry in entries),
            {'normal_entry': base.NORMAL, 'composition': base.COMPOSITION,
             'controls_composition': base.CONTROLS, 'isolation_composition': base.ISOLATION},
            base.PINS, sealed.PINS, PINS):
        merge(registry)
    merge({alias: plans[source] for alias, source in ALIASES.items()})
    for documents in (*(entry.DOCUMENTS for entry in entries), base.DOCUMENTS, sealed.DOCUMENTS, DOCUMENTS):
        for row in documents.items():
            enroll(*row)
    need(set(PORT_HELPERS) | {'port_replay', 'common_composition', 'common_replay', 'common_lowered'} <= set(plans),
         'complete authenticated component helper plan before witness')
    own = Path(__file__).resolve()
    buffers[own] = own.read_bytes()
    modules = {name: load('_os_port_census_admission_' + name, ROOT / row[0], buffers[ROOT / row[0]])
               for name, row in runner.PINS.items()}
    need(plans['transport'] == modules['capture'].PINS['api'], 'same authenticated capture transport')

    def read(path):
        need(path in buffers, 'bootstrap helper outside authenticated opening buffers')
        return buffers[path]

    with patch.object(Path, 'read_bytes', read):
        transport = load('_os_port_census_bootstrap_transport', ROOT / plans['transport'][0],
                         buffers[ROOT / plans['transport'][0]])
    witness = modules['admission'].witness_type(modules['legacy'], modules['capture'], extra_sources=buffers)(args)
    environment = dict(Witness=witness, Modules=modules, HelperPlans=plans)
    with patch.object(Path, 'read_bytes', read):
        helpers = {name: transport if name == 'transport' else
                   load('_os_port_census_bootstrap_' + name, ROOT / row[0], buffers[ROOT / row[0]])
                   for name, row in plans.items()}
    return runner, environment, builder, helpers, opening, buffers


def admit_normal(args, runner, environment, batch_root, batch, roles, helpers):
    return helpers['common_composition'].admit_normal(
        args, runner, environment, batch_root, batch, roles, helpers)


def port_result(port, helpers):
    need(type(helpers) is dict and set(PORT_HELPERS) | {'port_replay'} <= set(helpers),
         'complete authenticated port helper dictionary')
    helpers['port_replay'].require_result(port)
    helpers['port_lowered'].require_result(port['LoweredProofs'],
        {name: helpers[name] for name in LOWERED_HELPERS})


def shared_results(census, abi, controls, isolation, common, port, authority, helpers, label):
    same, prior = helpers['guard']._same, helpers['common_composition']
    same(abi['Inputs']['OriginalELF'], census['OriginalInputs']['OrdinaryFinal'], label + ' ABI original image')
    same(abi['PositiveAuthority']['LoadImageComparison'], census['Twins'], label + ' ABI load image')
    same(controls['Inputs']['OriginalELF'], abi['Inputs']['OriginalELF'], label + ' controls original image')
    same(controls['Inputs']['ReproducedELF'], abi['Inputs']['ReproducedELF'], label + ' controls positive image')
    same(controls['PositiveAuthority']['LoadImageComparison'], census['Twins'], label + ' controls load image')
    prior.shared_isolation(census, isolation, same, label)
    prior.shared_common(common, isolation, authority, same, label)
    for key in ('Root', 'SourceRoot', 'CaptureRoot', 'Cohort', 'SourceInventorySha256',
                'SourceOwnership', 'SourceOwnershipInputs', 'ToolBindings'):
        same(port[key], common[key], label + ' port/common ' + key)
    for key in ('BatchReceipt', 'NativeReceipt', 'Manifest', 'CommandJournal'):
        same(port['AuthorityInputs'][key], common['AuthorityInputs'][key], label + ' port/common ' + key)
    same(port['NativeObjectBindings'], isolation['NativeObjectBindings'], label + ' port native objects')
    startup = port['Inputs']['Final/Startup']
    same({key: startup[key] for key in ('Path', 'Sha256')}, isolation['Inputs']['StartupObject'],
         label + ' port original startup')
    same(port['AuthorityInputs']['LinkScript'], isolation['AuthorityInputs']['LinkScript'], label + ' port link script')


def replay(runner, environment, batch_root, batch, normal_root, handoff, roles, targets, tool):
    witness, plans = environment['Witness'], environment['HelperPlans']
    wanted = ('machine', 'normal_entry', 'normal', 'census', 'policy', 'workers', 'guard',
        'declarations', 'ordinary', 'abi_replay', 'deps', 'recipes', 'diagnostics', 'probes', 'plan',
        'controls_replay', 'ownership', 'isolation_replay', 'isolation_slots', 'os_slot', 'neutral_slot',
        'attributes_phase', 'attributes', 'attribute_runner', 'common_workers', 'common_effects',
        'common_lowered', 'common_replay', 'common_composition', 'port_policy', 'port_phase',
        'port_runner', 'effects', 'port_replay', 'port_lowered', 'transport')
    plan = {name: plans[name] for name in wanted}
    need(plan['transport'] == environment['Modules']['capture'].PINS['api'], 'same reader transport')
    for alias, source in ALIASES.items():
        need(plan[alias] == plan[source], 'same reader alias/' + alias)
    with patch('os.system', side_effect=AssertionError('immutable port/census replay cannot execute shell commands')), \
            patch('subprocess.Popen', side_effect=AssertionError('immutable port/census replay cannot start processes')):
        with runner.reader(environment, {'CensusABIIsolationCommonAndPort': {str(i): path for i, path in enumerate(roles)}}) as (core, _, frozen):
            def fresh(name, relative):
                spec = importlib.util.spec_from_file_location(name, ROOT / relative)
                module = importlib.util.module_from_spec(spec)
                sys.modules[name] = module
                spec.loader.exec_module(module)
                return module
            helpers = {name: fresh('_os_port_census_frozen_' + name, row[0]) for name, row in plan.items()}
            view = helpers['machine'].immutable_view(witness.groups['Native']['Result'], roles, helpers['transport'])
            normal, guard = helpers['normal_entry'], helpers['guard']
            native_root = witness.groups['Native']['Root']
            batch_raw, native_raw = view.watch.read(batch_root / 'results.json'), view.watch.read(native_root / 'results.json')
            bound_batch, bound_native = normal.structured(batch_raw), normal.structured(native_raw)
            bound_handoff = normal.structured(view.watch.read(normal_root / 'results.json'))
            guard._same(bound_batch, batch, 'same immutable batch receipt')
            guard._same(bound_native, witness.groups['Native']['Result'], 'same immutable native receipt')
            guard._same(bound_handoff, handoff, 'same immutable normal handoff')
            authority = dict(BatchRoot=str(batch_root), NativeRoot=str(native_root),
                Cohort=bound_native['Cohort'], SourceInventorySha256=bound_native['SourceInventorySha256'],
                BatchReceipt=dict(Path=str(batch_root / 'results.json'), Sha256=sha(batch_raw)),
                Manifest=dict(Path=str(batch_root / 'artifacts.json'), Sha256=sha(view.watch.read(batch_root / 'artifacts.json'))),
                NativeReceipt=dict(Path=str(native_root / 'results.json'), Sha256=sha(native_raw)))
            dumps = normal.validate_inspections(normal_root, tool, targets, bound_handoff['OriginalDisassemblies'],
                                                bound_handoff['Commands'], view.watch.read, guard._same)
            census = helpers['normal'].inspect(bound_batch, bound_native, batch_root, core,
                dict(census=helpers['census'], policy=helpers['policy'], port_runner=helpers['workers'], guard=guard), view.watch.read, dumps)
            helpers['normal'].require_result(census)
            guard._same(census, bound_handoff['OriginalCensus'], 'recomputed original census comparison')
            abi = helpers['abi_replay'].inspect(bound_batch, bound_native, batch_root, core,
                {name: helpers[name] for name in ('declarations', 'ordinary', 'guard')}, view.watch.read)
            helpers['abi_replay'].require_result(abi)
            control_helpers = {name: helpers[name] for name in
                ('deps', 'recipes', 'declarations', 'ordinary', 'plan', 'diagnostics', 'probes', 'guard', 'transport')}
            control_helpers['port_runner'] = helpers['workers']
            controls = helpers['controls_replay'].inspect(bound_batch, bound_native, batch_root, core, control_helpers, view.watch.read)
            helpers['controls_replay'].require_result(controls)
            isolation_helpers = {name: helpers[name] for name in
                ('deps', 'recipes', 'probes', 'ownership', 'guard', 'transport', 'controls_replay', 'isolation_slots', 'os_slot', 'neutral_slot')}
            isolation = helpers['isolation_replay'].inspect(bound_batch, bound_native, batch_root, core,
                isolation_helpers, view.watch.read, original_dumps=dumps)
            helpers['isolation_replay'].require_result(isolation)
            helpers['isolation_slots'].require_result(isolation['SlotProofs'])
            common = helpers['common_replay'].inspect(bound_batch, bound_native, batch_root, core,
                {name: helpers[name] for name in COMMON_HELPERS}, view.watch.read)
            helpers['common_composition'].common_result(common, helpers)
            port = helpers['port_replay'].inspect(bound_batch, bound_native, batch_root, core,
                {name: helpers[name] for name in PORT_HELPERS}, view.watch.read)
            port_result(port, helpers)
            shared_results(census, abi, controls, isolation, common, port, authority, helpers, 'shared')
        witness.close()
    return census, abi, controls, isolation, common, port, frozen


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
         'no new commands and explicit project reader roles')
    for name, key in (('normal', 'OriginalCensus'), ('abi_replay', 'DeferredABI'),
                      ('controls_replay', 'ABIControls'), ('isolation_replay', 'IsolationComponent')):
        helpers[name].require_result(report.get(key))
    helpers['isolation_slots'].require_result(report['IsolationComponent']['SlotProofs'])
    pending = helpers['common_composition'].common_result(report['CommonAttributes'], helpers)
    port_result(report['PortPolicyComponent'], helpers)
    helpers['guard']._same(report['UnresolvedAttribution'], pending, 'outer common attribution projection')
    need(report.get('CommonAttributionClosed') is (not pending)
         and report['Status'] == (PENDING if pending else PASS), 'honest common attribution disposition')
    native = [row for row in report['ProducerBindings'] if row['Side'] == 'Native']
    need(len(native) == 1, 'one native producer authority')
    batch = report['Batch']
    authority = dict(BatchRoot=batch['Build'], NativeRoot=native[0]['Build'], Cohort=report['Cohort'],
        SourceInventorySha256=report['SourceInventorySha256'],
        BatchReceipt=dict(Path=str(Path(batch['Build']) / 'results.json'), Sha256=batch['ReceiptSha256']),
        Manifest=dict(Path=str(Path(batch['Build']) / 'artifacts.json'), Sha256=batch['ArtifactsSha256']),
        NativeReceipt=dict(Path=str(Path(native[0]['Build']) / 'results.json'), Sha256=native[0]['ReceiptSha256']))
    shared_results(*(report[key] for key in ('OriginalCensus', 'DeferredABI', 'ABIControls', 'IsolationComponent',
        'CommonAttributes', 'PortPolicyComponent')), authority, helpers, 'result shared')
    need('Error' in report and report['Error'] is None and 'PrimaryError' in report and report['PrimaryError'] is None
         and type(report.get('ClosingErrors')) is list and report['ClosingErrors'] == [], 'clean explicit errors')


def run(args, runner, environment, builder, helpers, opening, buffers):
    witness = environment['Witness']
    report = dict(runner.base_report(witness), Scope=SCOPE, LTO=True, OriginalCensus=None,
        DeferredABI=None, ABIControls=None, IsolationComponent=None, CommonAttributes=None, PortPolicyComponent=None,
        CommonAttributionClosed=False, UnresolvedAttribution=[], **dict.fromkeys(FACTS, False),
        **dict.fromkeys(NONCLAIMS, False), **dict.fromkeys((key for key, _ in COUNTERS), 0))
    suite = None
    try:
        root, batch, roles = helpers['machine'].admit_batch(args, runner, environment, builder, helpers, opening)
        normal_root, handoff, targets, tool, project_count = admit_normal(args, runner, environment, root, batch, roles, helpers)
        suite = helpers['session'].suite_type(helpers['utility'], helpers['lto'])(environment, helpers, buffers)
        suite.report = report
        report.update(Batch=dict(Build=str(root), ReceiptSha256=args.batch_receipt_sha256, ArtifactsSha256=args.batch_artifacts_sha256),
            OriginalCensusHandoff=dict(Build=str(normal_root), ReceiptSha256=args.normal_receipt_sha256, ArtifactsSha256=args.normal_artifacts_sha256),
            OriginalTargets=targets, InspectionTool=tool, ProjectSourceReaderRoles=project_count,
            RecordedInspectionInvocations=2, Commands=[], ToolInvocations=0, CompilerInvocations=0)
        suite.start()
        suite._save('commands.json', [])
        report['CommandsSha256'] = suite.expected['commands.json']
        census, abi, controls, isolation, common, port, frozen = replay(runner, environment, root, batch,
            normal_root, handoff, roles, targets, tool)
        pending = common['LoweredProofs']['UnresolvedAttribution']
        report.update(Status=PENDING if pending else PASS, OriginalCensus=census, DeferredABI=abi,
            ABIControls=controls, IsolationComponent=isolation, CommonAttributes=common, PortPolicyComponent=port,
            CommonAttributionClosed=not pending, UnresolvedAttribution=pending, ImmutableReader=frozen,
            **dict.fromkeys((key for key in FACTS if key not in ('InputClosureVerified', 'OutputSealVerified')), True), **dict(COUNTERS))
        suite.verify_objects()
        witness.close()
        suite._verify_outputs()
        helpers['guard'].require_owned_output(suite)
        runner.seal(environment, report, suite.expected)
        require_result(report, helpers)
        print(json.dumps(dict(Status=report['Status'], CommonAttributionClosed=report['CommonAttributionClosed'],
            ToolInvocations=0, CompilerInvocations=0, RecordedInspectionInvocations=2, **dict(COUNTERS), RequiredCellsSatisfied=0,
            Output=str(suite.output), ReceiptSha256=sha((suite.output / 'results.json').read_bytes()),
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
    with patch('os.system', side_effect=AssertionError('port/census replay cannot execute shell commands')), \
            patch('subprocess.Popen', side_effect=AssertionError('port/census replay cannot start processes')):
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
