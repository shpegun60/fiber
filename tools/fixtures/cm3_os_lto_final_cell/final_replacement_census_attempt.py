"""Replay selected-replacement final roots with all seven earlier components.

All eight components execute in one fresh immutable reader. Recorded commands
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
PORT = ('tools/fixtures/cm3_os_lto_final_cell/port_census_attempt.py',
        '20822705ECE09DA3F1F4C6F5055F022377FFE014A8F888DD452A7C65E956936B')
ORIGINAL = ('tools/fixtures/cm3_os_lto_final_cell/original_census_attempt.py',
        '1AD81179EF4617156CE73CA13412709668E2E7FE15AFF61FDB67E4BEAC0FAD74')
PINS = {
    'original_composition': ORIGINAL,
    'final_replacement_replay': ('tools/fixtures/cm3_os_lto_final_cell/final_replacement_replay.py',
        'A3333BF83305179DECB4AB77AED2FA36840100EF69E886E243A6F6D7734A8F3D'),
    'port_composition': PORT,
    'original_replay': ('tools/fixtures/cm3_os_lto_final_cell/original_replay.py',
        'BF15568AE1EF2D5A67FC63573965D36AA0A9D31308A57C1B2FC860310E0DA645'),
    'original_abi': ('tools/fixtures/cm3_os_lto_final_cell/abi.py',
        'D0471869CA413901AB51016BDA662683FAED60231FB87CD9F9BA14BFD121A73E'),
    'original_link_helpers': ('tools/fixtures/cm3_lto_link_contract/audit.py',
        '9D6B4E1694A8C0A2D7F2E1C7B6D108B58B103131DD7C19D45CD08238E4CED759'),
    'original_binding_helpers': ('tools/fixtures/cm3_lto_runtime_bindings/bindings.py',
        'A8C994427DDE61619AB789D62E198B24DEC0B05EF8D1EE8E1C28BE86536E4C3B'),
    'original_native_roots': ('tools/fixtures/cm3_lto_roots/native.py',
        'D4BA0378FA50E11A570D40180149794B16EB0807E36DC902C19840E32D1AF05D'),
    'original_reference_roots': ('tools/fixtures/cm3_reference_lto_roots/reference.py',
        '3E53C4C0C5030B973A599FBDD0CB0B7FDECC625DEFD8C204A8C9691C5F6A616D'),
    'original_native_protocol': ('tools/fixtures/cm3_lto_protocol/protocol.py',
        'BA3B630BB1FEA67C81D2EE18C84F6D2A47DE9802E8763F52EE55DB34CD65F419'),
    'original_reference_protocol': ('tools/fixtures/cm3_reference_lto_protocol/protocol.py',
        '200B277D03DF4236FE887907F732BC2A26898D8C15C1544D917B3DC3CF6BF798'),
    'original_decoder': ('tools/fixtures/cm55_tfm_parity/elf.py',
        '394BA0549C2325BC5BB988EB1A6EBA89263CAF3E351189582931C59A64D5752D'),
    'original_checker': ('tools/fixtures/cm3_freeze_parity/check.py',
        'F0D9CD4F48912FB6E5455AA365BF73FFCF356BAFAD922B3A73ACA992A616A11A'),
    'original_os_join': ('tools/fixtures/cm3_os_lto_join/compose.py',
        '359BB0E7463F4514F5964529702DDC07CCED773927970AC3C246A1B7E845367E'),
    'original_join': ('tools/fixtures/cm3_lto_join/join.py',
        'F4EF2402495FF90C6D781762EC2B85A458F7DA702F14B2C6A1581D9E09343CE3'),
}
DOCUMENTS = {
    'tools/fixtures/cm3_os_lto_final_cell/FINAL_REPLACEMENT_REPLAY_CONTRACT.md':
        '89404FDD9D2B9461B4D91123C73277CBFFA8E1CAD9E10A6837C4D60EF2744001',
}
ARGUMENTS = ('batch-build', 'batch-receipt-sha256', 'batch-artifacts-sha256',
    'native-build', 'native-receipt-sha256', 'native-artifacts-sha256',
    'reference-build', 'reference-receipt-sha256', 'reference-artifacts-sha256',
    'inventory', 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir',
    'normal-build', 'normal-receipt-sha256', 'normal-artifacts-sha256')
PASS = 'CENSUS-ABI-ISOLATION-COMMON-PORT-ORIGINAL-AND-FINAL-REPLAYED-NOT-QUALIFIED'
PENDING = 'CENSUS-ABI-ISOLATION-COMMON-PORT-ORIGINAL-AND-FINAL-REPLAYED-PENDING-ATTRIBUTION'
SCOPE = 'CURRENT_CM3_OS_LTO_EIGHT_COMPONENTS_WITH_FINAL_REPLACEMENT_ROOTS_ONLY'
FACTS = ('OriginalInspectionBindingsReplayed', 'OriginalCensusReplayed', 'DeferredABIReplayed',
    'ABIControlsReplayed', 'IsolationComponentReplayed', 'CommonAttributesReplayed',
    'PortPolicyComponentReplayed', 'OriginalComponentReplayed',
    'FinalReplacementComponentReplayed',
    'ImmutableInputsConsumed', 'InputClosureVerified', 'OutputSealVerified')
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
ORIGINAL_HELPERS = ('abi', 'link_helpers', 'binding_helpers', 'native_roots', 'reference_roots',
    'native_protocol', 'reference_protocol', 'decoder', 'checker', 'os_join', 'join', 'guard')
ORIGINAL_ALIASES = {name: 'original_' + name for name in ORIGINAL_HELPERS if name != 'guard'}
ORIGINAL_ALIASES['guard'] = 'guard'
NATIVE_ROLES = ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup', 'Attributes', 'MachineAttributes')
REFERENCE_ROLES = ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup', 'Plain', 'MachineDisassembly')
POLICY = ('tools/fixtures/cm3_final_join/POLICY_DIFFERENCES.md',
          '778B098F80EAE5EE641B323B4F8D60441C2F725921B506AEDA90B487D3EB5019')


def need(value, detail):
    if not value:
        raise ValueError('cm3-os-lto-final-replacement-census: ' + detail)


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
    builder = load('_os_final_replacement_census_builder', path, raw)
    path, raw = enroll(*builder.METADATA)
    metadata = load('_os_final_replacement_census_metadata', path, raw)
    path, raw = enroll('tools/fixtures/cm3_os_lto_final_cell/runner.py', metadata.RUNNER_SHA256)
    runner = load('_os_final_replacement_census_reader_entry', path, raw)
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
    base = load('_os_final_replacement_census_common_metadata', path, raw)
    path, raw = enroll(*SEALED)
    sealed = load('_os_final_replacement_census_sealed_metadata', path, raw)
    path, raw = enroll(*PORT)
    port = load('_os_final_replacement_census_port_metadata', path, raw)
    path, raw = enroll(*ORIGINAL)
    original = load('_os_final_replacement_census_original_metadata', path, raw)
    need(base.BATCH == sealed.BATCH == BATCH and sealed.BASE == BASE
         and port.BASE == BASE and port.SEALED == SEALED
         and original.PORT == PORT and original.BASE == BASE and original.SEALED == SEALED
         and base.ARGUMENTS == sealed.ARGUMENTS == port.ARGUMENTS == original.ARGUMENTS == ARGUMENTS,
         'fixed published bootstrap/CLI')
    entries = []
    for name, row in (('normal', base.NORMAL), ('composition', base.COMPOSITION),
                      ('controls', base.CONTROLS), ('isolation', base.ISOLATION)):
        path, raw = enroll(*row)
        entries.append(load('_os_final_replacement_census_' + name + '_metadata', path, raw))
    for registry in (*(entry.PINS for entry in entries),
            {'normal_entry': base.NORMAL, 'composition': base.COMPOSITION,
             'controls_composition': base.CONTROLS, 'isolation_composition': base.ISOLATION},
            base.PINS, sealed.PINS, port.PINS, original.PINS, PINS):
        merge(registry)
    merge({alias: plans[source] for alias, source in ALIASES.items()})
    for documents in (*(entry.DOCUMENTS for entry in entries), base.DOCUMENTS, sealed.DOCUMENTS,
                      port.DOCUMENTS, original.DOCUMENTS, DOCUMENTS):
        for row in documents.items():
            enroll(*row)
    need(set(PORT_HELPERS) | set(ORIGINAL_ALIASES.values()) | {'original_replay', 'port_composition',
         'port_replay', 'common_composition', 'common_replay', 'common_lowered',
         'original_composition', 'final_replacement_replay'} <= set(plans),
         'complete authenticated component helper plan before witness')
    own = Path(__file__).resolve()
    buffers[own] = own.read_bytes()
    modules = {name: load('_os_final_replacement_census_admission_' + name, ROOT / row[0], buffers[ROOT / row[0]])
               for name, row in runner.PINS.items()}
    for key in ('abi', 'link_helpers', 'binding_helpers'):
        need(plans[ORIGINAL_ALIASES[key]] == runner.PINS[key], 'same original binding helper/' + key)
    for key in ORIGINAL_HELPERS:
        if key not in ('abi', 'link_helpers', 'binding_helpers', 'guard'):
            relative, digest = plans[ORIGINAL_ALIASES[key]]
            need(modules['legacy'].FIXED.get(relative) == digest, 'same original root helper/' + key)
    need((modules['legacy'].POLICY, modules['legacy'].POLICY_SHA) == POLICY, 'same fixed original policy authority')
    need(plans['transport'] == modules['capture'].PINS['api'], 'same authenticated capture transport')

    def read(path):
        need(path in buffers, 'bootstrap helper outside authenticated opening buffers')
        return buffers[path]

    with patch.object(Path, 'read_bytes', read):
        transport = load('_os_final_replacement_census_bootstrap_transport', ROOT / plans['transport'][0],
                         buffers[ROOT / plans['transport'][0]])
    witness = modules['admission'].witness_type(modules['legacy'], modules['capture'], extra_sources=buffers)(args)
    environment = dict(Witness=witness, Modules=modules, HelperPlans=plans)
    with patch.object(Path, 'read_bytes', read):
        helpers = {name: transport if name == 'transport' else
                   load('_os_final_replacement_census_bootstrap_' + name, ROOT / row[0], buffers[ROOT / row[0]])
                   for name, row in plans.items()}
    return runner, environment, builder, helpers, opening, buffers


def admit_normal(args, runner, environment, batch_root, batch, roles, helpers):
    return helpers['original_composition'].admit_normal(
        args, runner, environment, batch_root, batch, roles, helpers)


def absolute(value):
    need(type(value) is str and '\0' not in value and Path(value).is_absolute()
         and str(Path(value)) == value and '..' not in Path(value).parts, 'canonical absolute original path')
    return Path(value)


def descriptor(group):
    return dict(Root=str(group['Root']), Result=group['Result'], Artifacts=group['Artifacts'],
        ReceiptSha256=group['ReceiptSha256'], ManifestSha256=group['ManifestSha256'])


def original_inputs(native, reference):
    """Reconstruct paths without physical APIs; the leaf independently repeats this."""
    result, hashes = {}, {}

    def captured(side, path):
        root = absolute(side['Root'])
        need(path.is_relative_to(root), 'original role in its own capture')
        digest = side['Artifacts'].get(path.relative_to(root).as_posix())
        need(type(digest) is str and re.fullmatch('[0-9A-F]{64}', digest) is not None,
             'original role exact manifest membership')
        need(path not in hashes or hashes[path] == digest, 'consistent original role hash')
        hashes[path] = digest
        return path

    for name, side, count in (('Native', native, 9), ('Reference', reference, 4)):
        need(type(side) is dict and set(side) == {'Root', 'Result', 'Artifacts', 'ReceiptSha256', 'ManifestSha256'},
             'closed original capture descriptor')
        record = side['Result']
        need(type(record['Sources']) is list and len(record['Sources']) == count
             and type(record['Links']) is list and len(record['Links']) == 2
             and [row['Kind'] for row in record['Links']] == ['ordinary', 'emit-relocs'],
             'original source count and ordered twins/' + name)
        startup = absolute(record['Sources'][-1]['Object'])
        links = record['Links']
        for link in links if name == 'Native' else links[1:]:
            final, machine = absolute(link['Path']), absolute(link['Machine'])
            row = dict(Machine=machine, Final=final, Disassembly=Path(str(final) + '.dis'),
                LinkMap=absolute(link['Map']), Startup=startup)
            if name == 'Native':
                row.update(Attributes=Path(str(final) + '.readelf'), MachineAttributes=Path(str(machine) + '.readelf'))
            else:
                row['Plain'] = absolute(links[0]['Path'])
            if link['Kind'] == 'emit-relocs':
                row['MachineDisassembly'] = Path(str(machine) + '.dis')
            key = ('NativeOrdinary' if link['Kind'] == 'ordinary' else 'NativeEmitted') if name == 'Native' else 'Reference'
            result[key] = {role: captured(side, path) for role, path in row.items()}
            for field, path_field in (('Sha256', 'Final'), ('MachineSha256', 'Machine'), ('MapSha256', 'LinkMap')):
                need(link[field] == hashes[row[path_field]], 'original link record hash/' + field)
            need(record['Sources'][-1]['ObjectSha256'] == hashes[startup], 'original startup source/object hash')
        twin = absolute(record['TwinLoadImagesPath'])
        need(twin == absolute(side['Root']) / 'load-image.json', 'fixed original load-image record')
        result.setdefault('LoadImages', {})[name] = captured(side, twin)
        need(record['TwinLoadImagesSha256'] == hashes[twin], 'original load-image hash authority')
        for filename, field in (('results.json', 'ReceiptSha256'), ('artifacts.json', 'ManifestSha256')):
            digest = side[field]
            need(type(digest) is str and re.fullmatch('[0-9A-F]{64}', digest) is not None, 'original authority digest')
            hashes[absolute(side['Root']) / filename] = digest
    n, r = native['Result'], reference['Result']
    need(n['SourceInventoryReceipt'] == r['SourceInventoryReceipt'], 'same captured inventory ledger authority')
    master = absolute(n['SourceInventoryReceipt']) / 'inputs' / 'FREERTOS_ASM_PARITY.md'
    policy = ROOT / POLICY[0]
    ledgers = dict(Master=master, Policy=policy)
    for name, path in ledgers.items():
        digest = n['InputHashes'].get(str(path)) if name == 'Master' else POLICY[1]
        need(type(digest) is str and re.fullmatch('[0-9A-F]{64}', digest) is not None
             and (name == 'Policy' or r['InputHashes'].get(str(path)) == digest),
             'captured master or fixed policy ledger hash/' + name)
        hashes[path] = digest
    logical = [path for row in result.values() for path in row.values()] + list(ledgers.values())
    authorities = [absolute(side['Root']) / filename for side in (native, reference)
                   for filename in ('results.json', 'artifacts.json')]
    startup = result['NativeOrdinary']['Startup']
    need(len(logical) == 26 and len(set(logical)) == 25
         and result['NativeEmitted']['Startup'] == startup and logical.count(startup) == 2
         and len(set(logical + authorities)) == len(hashes) == 29,
         'thirty logical original inputs with only shared native startup')
    return result, ledgers, hashes


def original_helpers(helpers):
    need(type(helpers) is dict and set(ORIGINAL_ALIASES.values()) | {'original_replay'} <= set(helpers),
         'complete authenticated original helper dictionary')
    return {name: helpers[alias] for name, alias in ORIGINAL_ALIASES.items()}


def final_helpers(helpers):
    return dict(original_helpers(helpers), original_replay=helpers['original_replay'],
                port_replay=helpers['port_replay'])


def final_batch_descriptor(root, receipt_raw, manifest_raw, helpers):
    parser = helpers['original_replay']
    manifest = parser._json(manifest_raw)
    parser._keys(manifest, ('Artifacts',), 'final batch manifest')
    return dict(Root=str(root), Result=parser._json(receipt_raw), Artifacts=manifest['Artifacts'],
        ReceiptSha256=sha(receipt_raw), ManifestSha256=sha(manifest_raw))


def final_result(proof, batch, port, original, helpers):
    helpers['final_replacement_replay'].require_result(proof, batch, port, original, final_helpers(helpers))


def original_call_inputs(roles, ledgers, hashes):
    def binding(path):
        need(path in hashes, 'bound original call input')
        return dict(Path=str(path), Sha256=hashes[path])
    return ({group: {name: binding(path) for name, path in row.items()} for group, row in roles.items()},
            {name: binding(path) for name, path in ledgers.items()})


def port_result(port, helpers):
    need(type(helpers) is dict and set(PORT_HELPERS) | {'port_replay'} <= set(helpers),
         'complete authenticated port helper dictionary')
    helpers['port_replay'].require_result(port)
    helpers['port_lowered'].require_result(port['LoweredProofs'],
        {name: helpers[name] for name in LOWERED_HELPERS})


def shared_results(census, abi, controls, isolation, common, port, original, final, authority, helpers, label):
    helpers['original_composition'].shared_results(census, abi, controls, isolation, common, port,
        original, authority, helpers, label)
    helpers['guard']._same(final['BatchRoot'], authority['BatchRoot'], label + ' final batch root')
    helpers['guard']._same(final['BatchAuthority'],
        dict(Receipt=authority['BatchReceipt'], Manifest=authority['Manifest']), label + ' final batch authority')


def replay(runner, environment, batch_root, batch, normal_root, handoff, roles, targets, tool):
    witness, plans = environment['Witness'], environment['HelperPlans']
    wanted = ('machine', 'normal_entry', 'normal', 'census', 'policy', 'workers', 'guard',
        'declarations', 'ordinary', 'abi_replay', 'deps', 'recipes', 'diagnostics', 'probes', 'plan',
        'controls_replay', 'ownership', 'isolation_replay', 'isolation_slots', 'os_slot', 'neutral_slot',
        'attributes_phase', 'attributes', 'attribute_runner', 'common_workers', 'common_effects',
        'common_lowered', 'common_replay', 'common_composition', 'port_policy', 'port_phase',
        'port_runner', 'effects', 'port_replay', 'port_lowered', 'transport', 'port_composition',
        'original_replay', 'original_composition', 'final_replacement_replay', *ORIGINAL_ALIASES.values())
    plan = {name: plans[name] for name in wanted}
    need(plan['transport'] == environment['Modules']['capture'].PINS['api'], 'same reader transport')
    for alias, source in ALIASES.items():
        need(plan[alias] == plan[source], 'same reader alias/' + alias)
    with patch('os.system', side_effect=AssertionError('immutable port/census replay cannot execute shell commands')), \
            patch('subprocess.Popen', side_effect=AssertionError('immutable port/census replay cannot start processes')):
        with runner.reader(environment, {'CensusABIIsolationCommonPortOriginalAndFinal': {str(i): path for i, path in enumerate(roles)}}) as (core, _, frozen):
            def fresh(name, relative):
                spec = importlib.util.spec_from_file_location(name, ROOT / relative)
                module = importlib.util.module_from_spec(spec)
                sys.modules[name] = module
                spec.loader.exec_module(module)
                return module
            helpers = {name: fresh('_os_final_replacement_census_frozen_' + name, row[0]) for name, row in plan.items()}
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
            descriptors = {}
            for side in ('Native', 'Reference'):
                expected = descriptor(witness.groups[side])
                source = Path(expected['Root'])
                receipt_raw = view.watch.read(source / 'results.json')
                manifest_raw = view.watch.read(source / 'artifacts.json')
                captured_manifest = normal.structured(manifest_raw)
                need(type(captured_manifest) is dict and set(captured_manifest) == {'Artifacts'},
                     'original immutable manifest schema/' + side)
                actual = dict(Root=str(source), Result=normal.structured(receipt_raw),
                    Artifacts=captured_manifest['Artifacts'], ReceiptSha256=sha(receipt_raw),
                    ManifestSha256=sha(manifest_raw))
                guard._same(actual, expected, 'same immutable original descriptor/' + side)
                descriptors[side] = actual
                authority[side] = dict(Root=str(source),
                    Receipt=dict(Path=str(source / 'results.json'), Sha256=actual['ReceiptSha256']),
                    Manifest=dict(Path=str(source / 'artifacts.json'), Sha256=actual['ManifestSha256']))
            original_roles, ledgers, original_hashes = original_inputs(descriptors['Native'], descriptors['Reference'])
            need(all(roles.get(path) == digest for path, digest in original_hashes.items()),
                 'all original paths explicitly admitted before reader')
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
            original_roles, ledgers = original_call_inputs(original_roles, ledgers, original_hashes)
            original = helpers['original_replay'].inspect(core, view.watch.read,
                descriptors['Native'], descriptors['Reference'], original_helpers(helpers),
                roles=original_roles, ledgers=ledgers)
            helpers['original_replay'].require_result(original, original_helpers(helpers))
            final_batch = final_batch_descriptor(batch_root, batch_raw,
                view.watch.read(batch_root / 'artifacts.json'), helpers)
            guard._same(final_batch['Result'], bound_batch, 'same final batch descriptor')
            final = helpers['final_replacement_replay'].inspect(core, view.watch.read, final_batch,
                port, original, final_helpers(helpers))
            final_result(final, final_batch, port, original, helpers)
            shared_results(census, abi, controls, isolation, common, port, original, final, authority, helpers, 'shared')
        witness.close()
    return census, abi, controls, isolation, common, port, original, final, frozen


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
    helpers['original_replay'].require_result(report['OriginalComponent'], original_helpers(helpers))
    final = report['FinalReplacementComponent']
    final_batch = final_batch_descriptor(Path(report['Batch']['Build']),
        bytes.fromhex(final['ControlBytes']['BatchReceipt']), bytes.fromhex(final['ControlBytes']['BatchManifest']), helpers)
    helpers['guard']._same(final_batch['ReceiptSha256'], report['Batch']['ReceiptSha256'], 'final batch receipt hash')
    helpers['guard']._same(final_batch['ManifestSha256'], report['Batch']['ArtifactsSha256'], 'final batch manifest hash')
    final_result(final, final_batch, report['PortPolicyComponent'], report['OriginalComponent'], helpers)
    helpers['guard']._same(report['UnresolvedAttribution'], pending, 'outer common attribution projection')
    need(report.get('CommonAttributionClosed') is (not pending)
         and report['Status'] == (PENDING if pending else PASS), 'honest common attribution disposition')
    producers = {}
    for side in ('Native', 'Reference'):
        rows = [row for row in report['ProducerBindings'] if row['Side'] == side]
        need(len(rows) == 1, 'one original producer authority/' + side)
        producers[side] = rows[0]
    native = [producers['Native']]
    batch = report['Batch']
    authority = dict(BatchRoot=batch['Build'], NativeRoot=native[0]['Build'], Cohort=report['Cohort'],
        SourceInventorySha256=report['SourceInventorySha256'],
        BatchReceipt=dict(Path=str(Path(batch['Build']) / 'results.json'), Sha256=batch['ReceiptSha256']),
        Manifest=dict(Path=str(Path(batch['Build']) / 'artifacts.json'), Sha256=batch['ArtifactsSha256']),
        NativeReceipt=dict(Path=str(Path(native[0]['Build']) / 'results.json'), Sha256=native[0]['ReceiptSha256']))
    for side, producer in producers.items():
        source = Path(producer['Build'])
        authority[side] = dict(Root=str(source),
            Receipt=dict(Path=str(source / 'results.json'), Sha256=producer['ReceiptSha256']),
            Manifest=dict(Path=str(source / 'artifacts.json'), Sha256=producer['ArtifactsSha256']))
    shared_results(*(report[key] for key in ('OriginalCensus', 'DeferredABI', 'ABIControls', 'IsolationComponent',
        'CommonAttributes', 'PortPolicyComponent', 'OriginalComponent', 'FinalReplacementComponent')),
        authority, helpers, 'result shared')
    need('Error' in report and report['Error'] is None and 'PrimaryError' in report and report['PrimaryError'] is None
         and type(report.get('ClosingErrors')) is list and report['ClosingErrors'] == [], 'clean explicit errors')


def run(args, runner, environment, builder, helpers, opening, buffers):
    witness = environment['Witness']
    report = dict(runner.base_report(witness), Scope=SCOPE, LTO=True, OriginalCensus=None,
        DeferredABI=None, ABIControls=None, IsolationComponent=None, CommonAttributes=None, PortPolicyComponent=None,
        OriginalComponent=None, FinalReplacementComponent=None,
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
        census, abi, controls, isolation, common, port, original, final, frozen = replay(runner, environment, root, batch,
            normal_root, handoff, roles, targets, tool)
        pending = common['LoweredProofs']['UnresolvedAttribution']
        report.update(Status=PENDING if pending else PASS, OriginalCensus=census, DeferredABI=abi,
            ABIControls=controls, IsolationComponent=isolation, CommonAttributes=common, PortPolicyComponent=port,
            OriginalComponent=original, FinalReplacementComponent=final,
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
