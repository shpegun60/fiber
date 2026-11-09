"""Replay nine bounded Os-LTO components in one fresh immutable reader.

No producer or inspection command executes. The new 32 transport and two
canonical controls are byte-buffer controls, not qualification or link credit.
"""

import argparse
import copy
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
PARENT = ('tools/fixtures/cm3_os_lto_final_cell/final_replacement_census_attempt.py',
          '4BE4817EFE4C98DC998A8E9EA89A00CD38EC2E5D495C41CB25E84E23795E98B0')
GUARD = ('tools/fixtures/cm3_os_lto_final_cell/batch_guard.py',
         '1281084AF70A6AADEA9590E4839311D3F3FA813B17ED06EEE5CD402F4E69BAFD')
PINS = {
    'final_replacement_composition': PARENT,
    'final_controls_replay': ('tools/fixtures/cm3_os_lto_final_cell/final_controls_replay.py',
        'C507CBCFBB593E78C5E6F5CC6710DF0C7436FEDACF119375429080A40CEEAD11'),
    'native_mutations': ('tools/fixtures/cm3_lto_roots/mutations.py',
        '32BDE6CA67B12EEC9975D24D6628C5576EA29F33121CD60310F1F010CF272353'),
    'reference_mutations': ('tools/fixtures/cm3_reference_lto_roots/mutations.py',
        'E20E55734138E5F9AE76019D3C3EF1260EE708FDF222DC72E5C8B5552E02029C'),
}
DOCUMENTS = {
    'tools/fixtures/cm3_os_lto_final_cell/FINAL_CONTROL_REPLAY_CONTRACT.md':
        '0F58C38B4962B1AB4B2DD6D5797013205DBB86DCE12D99F82CD4A1396D251C00',
    'tools/fixtures/cm3_lto_protocol/witness.py':
        '39E1994A74DB225CD3BB2010AE07C49FD1DB2EE2006BCAD2FC59BD3092E6CF51',
    'tools/fixtures/cm3_reference_lto_protocol/witness.py':
        'B3968C5C51BCB7DFF13425B6656715DB4FA9674C18503AA04FDE7EA0A0F89D5F',
}
ARGUMENTS = ('batch-build', 'batch-receipt-sha256', 'batch-artifacts-sha256',
    'native-build', 'native-receipt-sha256', 'native-artifacts-sha256',
    'reference-build', 'reference-receipt-sha256', 'reference-artifacts-sha256',
    'inventory', 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir',
    'normal-build', 'normal-receipt-sha256', 'normal-artifacts-sha256')
PASS = 'CENSUS-ABI-ISOLATION-COMMON-PORT-ORIGINAL-FINAL-AND-CONTROLS-REPLAYED-NOT-QUALIFIED'
PENDING = 'CENSUS-ABI-ISOLATION-COMMON-PORT-ORIGINAL-FINAL-AND-CONTROLS-REPLAYED-PENDING-ATTRIBUTION'
SCOPE = 'CURRENT_CM3_OS_LTO_NINE_COMPONENTS_WITH_FINAL_BUFFER_CONTROLS_ONLY'
PRIOR_FACTS = ('OriginalInspectionBindingsReplayed', 'OriginalCensusReplayed', 'DeferredABIReplayed',
    'ABIControlsReplayed', 'IsolationComponentReplayed', 'CommonAttributesReplayed',
    'PortPolicyComponentReplayed', 'OriginalComponentReplayed', 'FinalReplacementComponentReplayed',
    'ImmutableInputsConsumed', 'InputClosureVerified', 'OutputSealVerified')
FACTS = (*PRIOR_FACTS, 'FinalControlComponentReplayed')
COUNTERS = (('RecordedABICommandsReplayed', 41), ('RecordedIsolationCommandsReplayed', 12),
    ('RecordedCommonAttributeCommandsReplayed', 45), ('RecordedPortPolicyCommandsReplayed', 36))
CONTROL_COUNTERS = (('TransportControlsExecuted', 32), ('CanonicalControlsExecuted', 2))
NONCLAIMS = ('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof',
    'FullIsolationProof', 'WholeSlotAccessIsolation', 'IRImportClosureValidated', 'FinalReferenceParity',
    'FinalRootTransferProtocolsValidated', 'CurrentSlotIsolationProven', 'CanonicalProtocolValidated',
    'FinalRootRelocationProof', 'CommonAttributePolicyProven', 'SelectedPortAttributePolicyProven',
    'NegativeLinkControlsExecuted', 'CompleteObjectProof', 'SourceIRProof', 'KernelRuntimeProof',
    'FinalLinkContractValidated', 'RuntimeProviderBindingsValidated', 'CompleteCellProof',
    'RequiredCellSatisfied', 'CellContractSatisfied', 'GlobalFreezeQualified', 'HostedCIQualified',
    'ArchiveQualification', 'CpuExecution', 'BoardExecution', 'ProducerCompilersReexecuted',
    'OsProcessTraceVerified', 'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership',
    'PolicyEquivalence', 'PriorReaderVerdictInherited', 'FullAttributeEquivalence', 'TransitiveProtection',
    'FullInstructionSemantics', 'AllProtectedBodiesClean', 'GeneralRegistersOnlyEffectProved',
    'RawCommonAttributesAloneProved', 'UnchangedOtherSixGeneratedBodies')
FINAL_CONTROL_HELPERS = ('abi', 'link_helpers', 'binding_helpers', 'native_roots', 'reference_roots',
    'native_protocol', 'reference_protocol', 'decoder', 'checker', 'os_join', 'join', 'guard',
    'original_replay', 'port_replay', 'final_replacement_replay', 'native_mutations', 'reference_mutations')
READER_HELPERS = ('machine', 'normal_entry', 'normal', 'census', 'policy', 'workers', 'guard',
    'declarations', 'ordinary', 'abi_replay', 'deps', 'recipes', 'diagnostics', 'probes', 'plan',
    'controls_replay', 'ownership', 'isolation_replay', 'isolation_slots', 'os_slot', 'neutral_slot',
    'attributes_phase', 'attributes', 'attribute_runner', 'common_workers', 'common_effects',
    'common_lowered', 'common_replay', 'common_composition', 'port_policy', 'port_phase', 'port_runner',
    'effects', 'port_replay', 'port_lowered', 'transport', 'port_composition', 'original_replay',
    'original_composition', 'final_replacement_replay', 'final_replacement_composition',
    'final_controls_replay', 'native_mutations', 'reference_mutations')
FIELDS = frozenset((*FACTS, *NONCLAIMS, *(name for name, _ in COUNTERS),
    *(name for name, _ in CONTROL_COUNTERS), 'Status', 'Scope', 'Profile', 'Mode', 'Linkage', 'LTO',
    'Cohort', 'ReferenceCommit', 'SourceInventorySha256', 'CurrentInventory', 'CurrentCaptureProducer',
    'ProducerBindings', 'BootstrapSources', 'Error', 'PrimaryError', 'ClosingErrors', 'Links',
    'RequiredCellCount', 'RequiredCellsSatisfied', 'ToolInvocations', 'CompilerInvocations',
    'OriginalCensus', 'DeferredABI', 'ABIControls', 'IsolationComponent', 'CommonAttributes',
    'PortPolicyComponent', 'OriginalComponent', 'FinalReplacementComponent', 'FinalControlComponent',
    'CommonAttributionClosed', 'UnresolvedAttribution', 'Batch', 'OriginalCensusHandoff', 'OriginalTargets',
    'InspectionTool', 'ProjectSourceReaderRoles', 'RecordedInspectionInvocations', 'Commands',
    'CapturedSources', 'CommandsSha256', 'ImmutableReader', 'InputHashes', 'InputPhysicalIdentities',
    'ClosingFilesVerified'))


def need(value, detail):
    if not value:
        raise ValueError('cm3-os-lto-final-controls-census: ' + detail)


def sha(raw):
    need(type(raw) is bytes, 'literal byte buffer')
    return hashlib.sha256(raw).hexdigest().upper()


def load(name, path, raw):
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def _parent(helpers):
    need(type(helpers) is dict and 'final_replacement_composition' in helpers,
         'explicit authenticated eight-component composition')
    parent = helpers['final_replacement_composition']
    calls = ('require_result', 'original_helpers', 'final_helpers', 'final_batch_descriptor',
             'port_result', 'shared_results', 'original_inputs', 'original_call_inputs',
             'admit_normal', 'descriptor', 'final_result')
    need(all(callable(getattr(parent, name, None)) for name in calls), 'published eight-component API')
    need(getattr(parent, 'ARGUMENTS', None) == ARGUMENTS and getattr(parent, 'BATCH', None) == BATCH
         and getattr(parent, 'FACTS', None) == PRIOR_FACTS and getattr(parent, 'COUNTERS', None) == COUNTERS
         and getattr(parent, 'NONCLAIMS', None) == NONCLAIMS,
         'unchanged published CLI/facts/credits/nonclaims')
    return parent


def final_control_helpers(helpers):
    parent = _parent(helpers)
    need(set(FINAL_CONTROL_HELPERS[12:]) | set(parent.ORIGINAL_ALIASES.values()) <= set(helpers),
         'complete final-control helper dictionary')
    result = dict(parent.final_helpers(helpers),
        final_replacement_replay=helpers['final_replacement_replay'],
        native_mutations=helpers['native_mutations'], reference_mutations=helpers['reference_mutations'])
    need(set(result) == set(FINAL_CONTROL_HELPERS), 'exact seventeen final-control helpers')
    return result


def prepare(args):
    need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and not sys.flags.optimize,
         'fresh isolated unoptimized -I -S -B interpreter')
    need(not any(name == 'elftools' or name.startswith('elftools.') for name in sys.modules),
         'initially unimported parser')
    need(type(DOCUMENTS) is dict and set(DOCUMENTS) == {
        'tools/fixtures/cm3_os_lto_final_cell/FINAL_CONTROL_REPLAY_CONTRACT.md',
        'tools/fixtures/cm3_lto_protocol/witness.py',
        'tools/fixtures/cm3_reference_lto_protocol/witness.py'},
        'exact contract and two protocol-witness document pins')
    buffers = {}

    def enroll(relative, digest):
        need(type(relative) is str and relative.startswith('tools/')
             and all(part not in ('', '.', '..') for part in relative.split('/'))
             and '\\' not in relative and ':' not in relative and type(digest) is str
             and re.fullmatch('[0-9A-F]{64}', digest) is not None and digest != '0' * 64,
             'fixed nonzero source pin')
        path = ROOT / relative
        raw = buffers[path] if path in buffers else path.read_bytes()
        need(sha(raw) == digest, 'source pin/' + relative)
        buffers.setdefault(path, raw)
        return path, raw

    path, raw = enroll(*BATCH)
    builder = load('_os_final_controls_builder', path, raw)
    path, raw = enroll(*builder.METADATA)
    metadata = load('_os_final_controls_metadata', path, raw)
    path, raw = enroll('tools/fixtures/cm3_os_lto_final_cell/runner.py', metadata.RUNNER_SHA256)
    runner = load('_os_final_controls_reader_entry', path, raw)
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
    # This comparison cohort belongs to the old builder, not the enlarged witness.
    opening = {str(path): sha(raw) for path, raw in sorted(buffers.items())}
    path, raw = enroll(*PARENT)
    parent = load('_os_final_controls_parent_metadata', path, raw)
    _parent({'final_replacement_composition': parent})
    previous = {}
    for name, row in (('base', parent.BASE), ('sealed', parent.SEALED),
                      ('port', parent.PORT), ('original', parent.ORIGINAL)):
        path, raw = enroll(*row)
        previous[name] = load('_os_final_controls_' + name + '_metadata', path, raw)
    base, sealed, port, original = (previous[name] for name in ('base', 'sealed', 'port', 'original'))
    need(base.BATCH == sealed.BATCH == BATCH and sealed.BASE == parent.BASE
         and port.BASE == parent.BASE and port.SEALED == parent.SEALED
         and original.PORT == parent.PORT and original.BASE == parent.BASE and original.SEALED == parent.SEALED
         and base.ARGUMENTS == sealed.ARGUMENTS == port.ARGUMENTS == original.ARGUMENTS == ARGUMENTS,
         'unchanged published bootstrap chain')
    entries = []
    for name, row in (('normal', base.NORMAL), ('composition', base.COMPOSITION),
                      ('controls', base.CONTROLS), ('isolation', base.ISOLATION)):
        path, raw = enroll(*row)
        entries.append(load('_os_final_controls_' + name + '_metadata', path, raw))
    for registry in (*(entry.PINS for entry in entries),
            {'normal_entry': base.NORMAL, 'composition': base.COMPOSITION,
             'controls_composition': base.CONTROLS, 'isolation_composition': base.ISOLATION},
            base.PINS, sealed.PINS, port.PINS, original.PINS, parent.PINS, PINS):
        merge(registry)
    merge({alias: plans[source] for alias, source in parent.ALIASES.items()})
    for documents in (*(entry.DOCUMENTS for entry in entries), base.DOCUMENTS, sealed.DOCUMENTS,
                      port.DOCUMENTS, original.DOCUMENTS, parent.DOCUMENTS, DOCUMENTS):
        for row in documents.items():
            enroll(*row)
    wanted = set(READER_HELPERS) | set(parent.ORIGINAL_ALIASES.values())
    need(wanted <= set(plans) and plans['guard'] == GUARD, 'all reader helpers planned before witness')
    own = Path(__file__).resolve()
    if own not in buffers:
        buffers[own] = own.read_bytes()
    modules = {name: load('_os_final_controls_admission_' + name, ROOT / row[0], buffers[ROOT / row[0]])
               for name, row in runner.PINS.items()}
    for key in ('abi', 'link_helpers', 'binding_helpers'):
        need(plans[parent.ORIGINAL_ALIASES[key]] == runner.PINS[key], 'same original binding helper/' + key)
    for key in parent.ORIGINAL_HELPERS:
        if key not in ('abi', 'link_helpers', 'binding_helpers', 'guard'):
            relative, digest = plans[parent.ORIGINAL_ALIASES[key]]
            need(modules['legacy'].FIXED.get(relative) == digest, 'same original root helper/' + key)
    for relative, digest in (*[PINS[name] for name in ('native_mutations', 'reference_mutations')],
                              *[(name, digest) for name, digest in DOCUMENTS.items() if name.endswith('/witness.py')]):
        need(modules['legacy'].FIXED.get(relative) == digest, 'same frozen recipe authority/' + relative)
    need((modules['legacy'].POLICY, modules['legacy'].POLICY_SHA) == parent.POLICY,
         'same fixed original policy authority')
    need(plans['transport'] == modules['capture'].PINS['api'], 'same authenticated capture transport')

    def read(path):
        need(path in buffers, 'bootstrap read outside first-seen enrolled buffers')
        return buffers[path]

    with patch.object(Path, 'read_bytes', read):
        transport = load('_os_final_controls_bootstrap_transport', ROOT / plans['transport'][0],
                         buffers[ROOT / plans['transport'][0]])
    witness = modules['admission'].witness_type(modules['legacy'], modules['capture'], extra_sources=buffers)(args)
    environment = dict(Witness=witness, Modules=modules, HelperPlans=plans)
    with patch.object(Path, 'read_bytes', read):
        helpers = {name: transport if name == 'transport' else
                   load('_os_final_controls_bootstrap_' + name, ROOT / row[0], buffers[ROOT / row[0]])
                   for name, row in plans.items()}
    final_control_helpers(helpers)
    return runner, environment, builder, helpers, opening, buffers


def replay(runner, environment, batch_root, batch, normal_root, handoff, roles, targets, tool):
    witness, plans = environment['Witness'], environment['HelperPlans']
    parent_aliases = ('original_abi', 'original_link_helpers', 'original_binding_helpers', 'original_native_roots',
        'original_reference_roots', 'original_native_protocol', 'original_reference_protocol', 'original_decoder',
        'original_checker', 'original_os_join', 'original_join')
    plan = {name: plans[name] for name in (*READER_HELPERS, *parent_aliases)}
    need(plan['transport'] == environment['Modules']['capture'].PINS['api'], 'same reader transport')
    with patch('os.system', side_effect=AssertionError('nine-component replay cannot execute shell commands')), \
            patch('subprocess.Popen', side_effect=AssertionError('nine-component replay cannot start processes')):
        with runner.reader(environment, {'CensusABIIsolationCommonPortOriginalFinalAndControls':
                {str(i): path for i, path in enumerate(roles)}}) as (core, _, frozen):
            def fresh(name, relative):
                spec = importlib.util.spec_from_file_location(name, ROOT / relative)
                module = importlib.util.module_from_spec(spec)
                sys.modules[name] = module
                spec.loader.exec_module(module)
                return module
            helpers = {name: fresh('_os_final_controls_frozen_' + name, row[0]) for name, row in plan.items()}
            parent = _parent(helpers)
            for alias, source in parent.ALIASES.items():
                need(plan[alias] == plan[source], 'same reader alias/' + alias)
            view = helpers['machine'].immutable_view(witness.groups['Native']['Result'], roles, helpers['transport'])
            normal, guard = helpers['normal_entry'], helpers['guard']
            native_root = witness.groups['Native']['Root']
            batch_raw, native_raw = view.watch.read(batch_root / 'results.json'), view.watch.read(native_root / 'results.json')
            bound_batch, bound_native = normal.structured(batch_raw), normal.structured(native_raw)
            bound_handoff = normal.structured(view.watch.read(normal_root / 'results.json'))
            guard._same(bound_batch, batch, 'same immutable batch receipt')
            guard._same(bound_native, witness.groups['Native']['Result'], 'same immutable native receipt')
            guard._same(bound_handoff, handoff, 'same immutable normal handoff')
            authority = dict(BatchRoot=str(batch_root), NativeRoot=str(native_root), Cohort=bound_native['Cohort'],
                SourceInventorySha256=bound_native['SourceInventorySha256'],
                BatchReceipt=dict(Path=str(batch_root / 'results.json'), Sha256=sha(batch_raw)),
                Manifest=dict(Path=str(batch_root / 'artifacts.json'), Sha256=sha(view.watch.read(batch_root / 'artifacts.json'))),
                NativeReceipt=dict(Path=str(native_root / 'results.json'), Sha256=sha(native_raw)))
            descriptors = {}
            for side in ('Native', 'Reference'):
                expected = parent.descriptor(witness.groups[side])
                source = Path(expected['Root'])
                receipt_raw, manifest_raw = view.watch.read(source / 'results.json'), view.watch.read(source / 'artifacts.json')
                captured_manifest = normal.structured(manifest_raw)
                need(type(captured_manifest) is dict and set(captured_manifest) == {'Artifacts'}, 'original immutable manifest')
                actual = dict(Root=str(source), Result=normal.structured(receipt_raw), Artifacts=captured_manifest['Artifacts'],
                    ReceiptSha256=sha(receipt_raw), ManifestSha256=sha(manifest_raw))
                guard._same(actual, expected, 'same immutable original descriptor/' + side)
                descriptors[side] = actual
                authority[side] = dict(Root=str(source),
                    Receipt=dict(Path=str(source / 'results.json'), Sha256=actual['ReceiptSha256']),
                    Manifest=dict(Path=str(source / 'artifacts.json'), Sha256=actual['ManifestSha256']))
            original_roles, ledgers, original_hashes = parent.original_inputs(descriptors['Native'], descriptors['Reference'])
            need(all(roles.get(path) == digest for path, digest in original_hashes.items()), 'all original roles admitted before reader')
            dumps = normal.validate_inspections(normal_root, tool, targets, bound_handoff['OriginalDisassemblies'],
                bound_handoff['Commands'], view.watch.read, guard._same)
            census = helpers['normal'].inspect(bound_batch, bound_native, batch_root, core,
                dict(census=helpers['census'], policy=helpers['policy'], port_runner=helpers['workers'], guard=guard), view.watch.read, dumps)
            helpers['normal'].require_result(census)
            guard._same(census, bound_handoff['OriginalCensus'], 'recomputed original census comparison')
            abi = helpers['abi_replay'].inspect(bound_batch, bound_native, batch_root, core,
                {name: helpers[name] for name in ('declarations', 'ordinary', 'guard')}, view.watch.read)
            helpers['abi_replay'].require_result(abi)
            abi_helpers = {name: helpers[name] for name in
                ('deps', 'recipes', 'declarations', 'ordinary', 'plan', 'diagnostics', 'probes', 'guard', 'transport')}
            abi_helpers['port_runner'] = helpers['workers']
            controls = helpers['controls_replay'].inspect(bound_batch, bound_native, batch_root, core, abi_helpers, view.watch.read)
            helpers['controls_replay'].require_result(controls)
            isolation_helpers = {name: helpers[name] for name in ('deps', 'recipes', 'probes', 'ownership', 'guard',
                'transport', 'controls_replay', 'isolation_slots', 'os_slot', 'neutral_slot')}
            isolation = helpers['isolation_replay'].inspect(bound_batch, bound_native, batch_root, core,
                isolation_helpers, view.watch.read, original_dumps=dumps)
            helpers['isolation_replay'].require_result(isolation)
            helpers['isolation_slots'].require_result(isolation['SlotProofs'])
            common = helpers['common_replay'].inspect(bound_batch, bound_native, batch_root, core,
                {name: helpers[name] for name in parent.COMMON_HELPERS}, view.watch.read)
            helpers['common_composition'].common_result(common, helpers)
            port = helpers['port_replay'].inspect(bound_batch, bound_native, batch_root, core,
                {name: helpers[name] for name in parent.PORT_HELPERS}, view.watch.read)
            parent.port_result(port, helpers)
            original_roles, ledgers = parent.original_call_inputs(original_roles, ledgers, original_hashes)
            original = helpers['original_replay'].inspect(core, view.watch.read, descriptors['Native'], descriptors['Reference'],
                parent.original_helpers(helpers), roles=original_roles, ledgers=ledgers)
            helpers['original_replay'].require_result(original, parent.original_helpers(helpers))
            final_batch = parent.final_batch_descriptor(batch_root, batch_raw, view.watch.read(batch_root / 'artifacts.json'), helpers)
            guard._same(final_batch['Result'], bound_batch, 'same genuine final batch descriptor')
            final = helpers['final_replacement_replay'].inspect(core, view.watch.read, final_batch, port, original, parent.final_helpers(helpers))
            parent.final_result(final, final_batch, port, original, helpers)
            parent.shared_results(census, abi, controls, isolation, common, port, original, final, authority, helpers, 'shared')
            final_controls = helpers['final_controls_replay'].inspect(core, view.watch.read, final_batch,
                port, original, final, final_control_helpers(helpers))
            helpers['final_controls_replay'].require_result(final_controls, final_batch, port, original, final, final_control_helpers(helpers))
        witness.close()
    return census, abi, controls, isolation, common, port, original, final, final_controls, frozen


def _retained_sources(report, helpers):
    """Join recorded source retention; physical closing stays outside the reader."""
    parent, module = _parent(helpers), helpers['original_replay']
    hashes, identities = report['InputHashes'], report['InputPhysicalIdentities']
    need(type(hashes) is dict and hashes and type(identities) is dict and set(identities) == set(hashes),
         'complete recorded input hash/identity catalogs')
    module._same(report['ClosingFilesVerified'], len(hashes), 'complete recorded input count')
    for name, digest in hashes.items():
        module._same(name, str(module._path(name)), 'canonical recorded input path')
        need(type(digest) is str and re.fullmatch('[A-F0-9]{64}', digest) is not None, 'recorded input hash')
        row = identities[name]
        need(type(row) is list and len(row) == 3 and all(type(value) is int and value >= 0 for value in row),
             'recorded physical identity triple')
    bootstrap, captured = {}, {}
    need(type(report['BootstrapSources']) is list and report['BootstrapSources']
         and type(report['CapturedSources']) is list and report['CapturedSources'], 'retained source catalogs')
    for row in report['BootstrapSources']:
        module._keys(row, ('Path', 'Sha256'), 'bootstrap source')
        name = row['Path']; module._same(name, str(module._path(name)), 'canonical bootstrap source')
        need(name not in bootstrap, 'unique bootstrap source')
        module._same(hashes.get(name), row['Sha256'], 'bootstrap source/input hash')
        bootstrap[name] = row['Sha256']
    copies = set()
    for row in report['CapturedSources']:
        module._keys(row, ('Original', 'Captured', 'Sha256'), 'retained source pair')
        name = row['Original']; module._same(name, str(module._path(name)), 'canonical retained original')
        copied = module._path(row['Captured'])
        module._same(row['Captured'], str(copied), 'canonical retained copy')
        need(name not in captured and copied not in copies and copied.parent.name == 'source-buffers',
             'unique retained source pair')
        module._same(hashes.get(name), row['Sha256'], 'retained original/input hash')
        captured[name] = row['Sha256']; copies.add(copied)
    module._same(list(bootstrap), sorted(bootstrap, key=module._path), 'ordered bootstrap source catalog')
    module._same(list(captured), sorted(captured, key=module._path), 'ordered retained source catalog')
    need(set(bootstrap) <= set(captured), 'all bootstrap sources retained')
    for name, digest in bootstrap.items():
        module._same(captured[name], digest, 'bootstrap/retained source bytes')
    required = dict(DOCUMENTS)
    for relative, digest in PINS.values():
        required[relative] = digest
    for name in parent.ORIGINAL_HELPERS:
        relative, digest = GUARD if name == 'guard' else parent.PINS[parent.ORIGINAL_ALIASES[name]]
        required[relative] = digest
    for name in ('original_replay', 'port_replay', 'final_replacement_replay'):
        registry = helpers['port_composition'].PINS if name == 'port_replay' else parent.PINS
        relative, digest = registry[name]; required[relative] = digest
    for relative, digest in required.items():
        name = str(ROOT / relative)
        module._same(bootstrap.get(name), digest, 'required pre-witness source/' + relative)
        module._same(captured.get(name), digest, 'required retained source/' + relative)
    own = str(Path(__file__))
    need(own in bootstrap and own in captured, 'own first-seen frontend bytes retained')
    frozen = report['ImmutableReader']
    module._keys(frozen, ('OneImmutableReaderScope', 'PhysicalClosingOutsideScope', 'SourceBuffers',
        'InputPaths', 'Reads', 'ExecutedSourceBuffers'), 'one immutable reader record')
    module._same(frozen['OneImmutableReaderScope'], True, 'one reader for all nine components')
    module._same(frozen['PhysicalClosingOutsideScope'], True, 'physical closing outside reader')
    module._same(frozen['SourceBuffers'], len(captured), 'all reader source buffers retained')
    need(type(frozen['InputPaths']) is int and frozen['InputPaths'] >= len(captured)
         and type(frozen['Reads']) is dict and type(frozen['ExecutedSourceBuffers']) is list,
         'literal reader accounting')
    for name, digest in frozen['Reads'].items():
        module._same(hashes.get(name), digest, 'observed reader/input hash')
    executed = set()
    for row in frozen['ExecutedSourceBuffers']:
        module._keys(row, ('Name', 'Path', 'Sha256'), 'executed source binding')
        need(type(row['Name']) is str and row['Name'], 'literal executed module name')
        module._same(captured.get(row['Path']), row['Sha256'], 'executed/retained source hash')
        executed.add(row['Path'])
    called = final_control_helpers(helpers)
    for name, helper in dict(called, final_controls_replay=helpers['final_controls_replay']).items():
        path = str(module._path(getattr(helper, '__file__', None)))
        need(path in executed and path in bootstrap, 'actual reader-executed control helper/' + name)


def require_result(report, helpers):
    parent = _parent(helpers)
    module = helpers['original_replay']
    module._keys(report, FIELDS, 'nine-component result')
    need(report['Status'] in (PASS, PENDING), 'bounded composed disposition')
    module._same(report['Scope'], SCOPE, 'nine-component scope')
    for key in FACTS:
        module._same(report[key], True, 'completed composition fact/' + key)
    for key, value in CONTROL_COUNTERS:
        module._same(report[key], value, 'separate bounded control count/' + key)
    # Validate the unchanged eight-component projection, not an inherited verdict.
    prior = {key: value for key, value in report.items() if key not in
             ('FinalControlComponent', 'FinalControlComponentReplayed', 'TransportControlsExecuted', 'CanonicalControlsExecuted')}
    prior['Scope'] = parent.SCOPE
    prior['Status'] = parent.PASS if report['Status'] == PASS else parent.PENDING
    parent.require_result(prior, helpers)
    final, port, original = report['FinalReplacementComponent'], report['PortPolicyComponent'], report['OriginalComponent']
    final_batch = parent.final_batch_descriptor(Path(report['Batch']['Build']),
        bytes.fromhex(final['ControlBytes']['BatchReceipt']), bytes.fromhex(final['ControlBytes']['BatchManifest']), helpers)
    control = report['FinalControlComponent']
    helpers['final_controls_replay'].require_result(control, final_batch, port, original, final, final_control_helpers(helpers))
    for key, value in CONTROL_COUNTERS:
        module._same(report[key], control[key], 'outer/leaf bounded control count/' + key)
    module._same(report['CommandsSha256'], sha(b'[]\n'), 'empty recorded output command journal')
    _retained_sources(report, helpers)


def _revoke(runner, report, error):
    try:
        runner.revoke(report, error)
    finally:
        report.update(Status='FAIL', **dict.fromkeys(FACTS, False), **dict.fromkeys(NONCLAIMS, False),
            **dict.fromkeys((key for key, _ in (*COUNTERS, *CONTROL_COUNTERS)), 0),
            RecordedInspectionInvocations=0, ToolInvocations=0, CompilerInvocations=0,
            RequiredCellsSatisfied=0, CommonAttributionClosed=False)


def run(args, runner, environment, builder, helpers, opening, buffers):
    witness, parent = environment['Witness'], _parent(helpers)
    report = dict(runner.base_report(witness), Scope=SCOPE, LTO=True, OriginalCensus=None, DeferredABI=None,
        ABIControls=None, IsolationComponent=None, CommonAttributes=None, PortPolicyComponent=None,
        OriginalComponent=None, FinalReplacementComponent=None, FinalControlComponent=None,
        CommonAttributionClosed=False, UnresolvedAttribution=[], **dict.fromkeys(FACTS, False),
        **dict.fromkeys(NONCLAIMS, False), **dict.fromkeys((key for key, _ in (*COUNTERS, *CONTROL_COUNTERS)), 0))
    suite = None
    try:
        root, batch, roles = helpers['machine'].admit_batch(args, runner, environment, builder, helpers, opening)
        normal_root, handoff, targets, tool, project_count = parent.admit_normal(
            args, runner, environment, root, batch, roles, helpers)
        suite = helpers['session'].suite_type(helpers['utility'], helpers['lto'])(environment, helpers, buffers)
        suite.report = report
        report.update(Batch=dict(Build=str(root), ReceiptSha256=args.batch_receipt_sha256, ArtifactsSha256=args.batch_artifacts_sha256),
            OriginalCensusHandoff=dict(Build=str(normal_root), ReceiptSha256=args.normal_receipt_sha256, ArtifactsSha256=args.normal_artifacts_sha256),
            OriginalTargets=targets, InspectionTool=tool, ProjectSourceReaderRoles=project_count,
            RecordedInspectionInvocations=2, Commands=[], ToolInvocations=0, CompilerInvocations=0)
        suite.start()
        suite._save('commands.json', [])
        report['CommandsSha256'] = suite.expected['commands.json']
        census, abi, controls, isolation, common, port, original, final, final_controls, frozen = replay(
            runner, environment, root, batch, normal_root, handoff, roles, targets, tool)
        pending = common['LoweredProofs']['UnresolvedAttribution']
        report.update(Status=PENDING if pending else PASS, OriginalCensus=census, DeferredABI=abi, ABIControls=controls,
            IsolationComponent=isolation, CommonAttributes=common, PortPolicyComponent=port, OriginalComponent=original,
            FinalReplacementComponent=final, FinalControlComponent=final_controls, CommonAttributionClosed=not pending,
            UnresolvedAttribution=pending, ImmutableReader=frozen,
            **dict.fromkeys((key for key in FACTS if key not in ('InputClosureVerified', 'OutputSealVerified')), True),
            **dict(COUNTERS), **dict(CONTROL_COUNTERS))
        suite.verify_objects()
        witness.close()
        suite._verify_outputs()
        helpers['guard'].require_owned_output(suite)
        runner.seal(environment, report, suite.expected)
        require_result(report, helpers)
        witness.close()
        print(json.dumps(dict(Status=report['Status'], CommonAttributionClosed=report['CommonAttributionClosed'],
            ToolInvocations=0, CompilerInvocations=0, RecordedInspectionInvocations=2, **dict(COUNTERS),
            **dict(CONTROL_COUNTERS), RequiredCellsSatisfied=0, RequiredCellCount=2774, Output=str(suite.output),
            ReceiptSha256=sha((suite.output / 'results.json').read_bytes()),
            ArtifactsSha256=sha((suite.output / 'artifacts.json').read_bytes())), sort_keys=True), flush=True)
        return report
    except BaseException as error:
        _revoke(runner, report, error)
        if suite is not None and suite._started:
            try:
                builder.recover_owned(runner, environment, suite, helpers['guard'])
            except BaseException as secondary:
                report.setdefault('ClosingErrors', []).append('failure persistence: ' + type(secondary).__name__ + ': ' + str(secondary))
            finally:
                _revoke(runner, report, error)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ARGUMENTS:
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    with patch('os.system', side_effect=AssertionError('nine-component replay cannot execute shell commands')), \
            patch('subprocess.Popen', side_effect=AssertionError('nine-component replay cannot start processes')):
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
