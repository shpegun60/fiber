"""Qualify one bounded current CM3 Os-LTO static cell without running tools.

All binary predicates run once through the frozen nine-component replay.
Coverage is revocable accounting, not an inherited component verdict.
"""
import argparse
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
NINE = ('tools/fixtures/cm3_os_lto_final_cell/final_controls_census_attempt.py',
        '6C56480F99198EB4A52B777C13CAEABA8B262F73B0350A0171F780EFC8902394')
BATCH = ('tools/fixtures/cm3_os_lto_final_cell/batch_attempt.py',
         'EC52A23182A5B0B4A09E18429E5BFB94902FBC42592785295D7283ACB572F38A')
PARENT = ('tools/fixtures/cm3_os_lto_final_cell/final_replacement_census_attempt.py',
          '4BE4817EFE4C98DC998A8E9EA89A00CD38EC2E5D495C41CB25E84E23795E98B0')
GUARD = ('tools/fixtures/cm3_os_lto_final_cell/batch_guard.py',
         '1281084AF70A6AADEA9590E4839311D3F3FA813B17ED06EEE5CD402F4E69BAFD')
PINS = {
    'nine_composition': NINE,
    'cell_model': ('tools/fixtures/cm3_os_lto_final_cell/cell_model.py',
        'E9CA01CA5DF0E459E2F8FCDF0FA3C4C2CFF725E0330EA03571F336664D5EEA53'),
    'cell_coverage': ('tools/fixtures/ordinary_final_cell/coverage.py',
        'D513BEA4622DB4C0CD4FC7DED6D341BF940233E4FA3B219F9723EA84E6B31DC9'),
}
DOCUMENTS = {
    'tools/fixtures/cm3_os_lto_final_cell/CELL_QUALIFIER_CONTRACT.md':
        '2DC6DA23F50A9E7ADB2D71CB1B94B8B492069A5EB8F9C8A0C820FBD76726B04A',
}
ARGUMENTS = ('batch-build', 'batch-receipt-sha256', 'batch-artifacts-sha256',
    'native-build', 'native-receipt-sha256', 'native-artifacts-sha256',
    'reference-build', 'reference-receipt-sha256', 'reference-artifacts-sha256',
    'inventory', 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir',
    'normal-build', 'normal-receipt-sha256', 'normal-artifacts-sha256')
SCOPE = 'ONE_CURRENT_CM3_OS_LTO_DIRECT_BOUNDED_STATIC_CELL'
PASS = 'BOUNDED_STATIC_CELL_VERIFIED'
PROMOTED = frozenset(('RequiredCellSatisfied', 'CellContractSatisfied'))
EXTRA_FIELDS = frozenset(('Route', 'Key', 'CohortSha256', 'ModelContract', 'QualifierSource', 'Output',
    'CurrentInventoryInputs', 'CurrentInventoryBytes', 'CommonPrerequisites', 'RuntimeObligations',
    'Coverage', 'MissingWork', 'AccountingArtifacts'))
INVENTORY_ROLES = ('Receipt', 'Manifest', 'RequiredCells', 'CohortManifest')
ACCOUNTING_FILES = {'Coverage': 'coverage.json', 'MissingWork': 'missing-work.json'}


def need(value, detail):
    if not value:
        raise ValueError('cm3-os-lto-cell-qualifier: ' + detail)


def sha(raw):
    need(type(raw) is bytes, 'literal byte buffer')
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def same(actual, expected, detail):
    need(type(actual) is type(expected), detail + '/type')
    if type(expected) is dict:
        need(set(actual) == set(expected), detail + '/keys')
        for key in expected:
            same(actual[key], expected[key], detail + '/' + key)
    elif type(expected) in (list, tuple):
        need(len(actual) == len(expected), detail + '/length')
        for index, (left, right) in enumerate(zip(actual, expected)):
            same(left, right, detail + '/' + str(index))
    else:
        need(actual == expected, detail)


def keys(value, names, detail):
    need(type(value) is dict and set(value) == set(names), detail)


def digest(value):
    need(type(value) is str and re.fullmatch('[A-F0-9]{64}', value) is not None, 'literal SHA256')
    return value


def lexical(value):
    need(isinstance(value, (str, Path)) and '\0' not in os.fspath(value)
         and Path(value).is_absolute() and '..' not in Path(value).parts, 'absolute lexical path')
    return Path(os.path.abspath(value))


def load(name, path, raw):
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def _nine(helpers):
    need(type(helpers) is dict and set(PINS) <= set(helpers), 'explicit qualifier helper bindings')
    nine = helpers['nine_composition']
    need(all(callable(getattr(nine, name, None)) for name in
             ('replay', 'require_result', '_revoke', '_parent', 'final_control_helpers'))
         and type(getattr(nine, 'FIELDS', None)) is frozenset, 'fixed nine API')
    return nine


def prepare(args):
    need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and not sys.flags.optimize,
         'fresh isolated unoptimized -I -S -B interpreter')
    need(not any(name == 'elftools' or name.startswith('elftools.') for name in sys.modules),
         'initially unimported parser')
    need(set(PINS) == {'nine_composition', 'cell_model', 'cell_coverage'}
         and set(DOCUMENTS) == {'tools/fixtures/cm3_os_lto_final_cell/CELL_QUALIFIER_CONTRACT.md'},
         'exact qualifier source and document registries')
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
    builder = load('_os_cell_qualifier_builder', path, raw)
    path, raw = enroll(*builder.METADATA)
    metadata = load('_os_cell_qualifier_metadata', path, raw)
    path, raw = enroll('tools/fixtures/cm3_os_lto_final_cell/runner.py', metadata.RUNNER_SHA256)
    runner = load('_os_cell_qualifier_reader_entry', path, raw)
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
    path, raw = enroll(*NINE)
    nine = load('_os_cell_qualifier_nine_metadata', path, raw)
    need(nine.BATCH == BATCH and nine.PARENT == PARENT and nine.GUARD == GUARD
         and nine.ARGUMENTS == ARGUMENTS, 'unchanged frozen nine bootstrap')
    need(PINS['nine_composition'] == NINE and type(nine.DOCUMENTS) is dict
         and set(nine.DOCUMENTS) == {'tools/fixtures/cm3_os_lto_final_cell/FINAL_CONTROL_REPLAY_CONTRACT.md',
             'tools/fixtures/cm3_lto_protocol/witness.py',
             'tools/fixtures/cm3_reference_lto_protocol/witness.py'}, 'inherited document authorities')
    path, raw = enroll(*PARENT)
    parent = load('_os_cell_qualifier_parent_metadata', path, raw)
    nine._parent({'final_replacement_composition': parent})
    previous = {}
    for name, row in (('base', parent.BASE), ('sealed', parent.SEALED),
                      ('port', parent.PORT), ('original', parent.ORIGINAL)):
        path, raw = enroll(*row)
        previous[name] = load('_os_cell_qualifier_' + name + '_metadata', path, raw)
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
        entries.append(load('_os_cell_qualifier_' + name + '_metadata', path, raw))
    for registry in (*(entry.PINS for entry in entries),
            {'normal_entry': base.NORMAL, 'composition': base.COMPOSITION,
             'controls_composition': base.CONTROLS, 'isolation_composition': base.ISOLATION},
            base.PINS, sealed.PINS, port.PINS, original.PINS, parent.PINS, nine.PINS, PINS):
        merge(registry)
    merge({alias: plans[source] for alias, source in parent.ALIASES.items()})
    for documents in (*(entry.DOCUMENTS for entry in entries), base.DOCUMENTS, sealed.DOCUMENTS,
                      port.DOCUMENTS, original.DOCUMENTS, parent.DOCUMENTS, nine.DOCUMENTS, DOCUMENTS):
        for row in documents.items():
            enroll(*row)
    wanted = set(nine.READER_HELPERS) | set(parent.ORIGINAL_ALIASES.values())
    need(wanted <= set(plans) and plans['guard'] == GUARD, 'all reader helpers planned before witness')
    own = Path(__file__).resolve()
    if own not in buffers:
        buffers[own] = own.read_bytes()
    modules = {name: load('_os_cell_qualifier_admission_' + name, ROOT / row[0], buffers[ROOT / row[0]])
               for name, row in runner.PINS.items()}
    for key in ('abi', 'link_helpers', 'binding_helpers'):
        need(plans[parent.ORIGINAL_ALIASES[key]] == runner.PINS[key], 'same original binding helper/' + key)
    for key in parent.ORIGINAL_HELPERS:
        if key not in ('abi', 'link_helpers', 'binding_helpers', 'guard'):
            relative, digest = plans[parent.ORIGINAL_ALIASES[key]]
            need(modules['legacy'].FIXED.get(relative) == digest, 'same original root helper/' + key)
    for relative, digest in (*[nine.PINS[name] for name in ('native_mutations', 'reference_mutations')],
                              *[(name, digest) for name, digest in nine.DOCUMENTS.items() if name.endswith('/witness.py')]):
        need(modules['legacy'].FIXED.get(relative) == digest, 'same frozen recipe authority/' + relative)
    need((modules['legacy'].POLICY, modules['legacy'].POLICY_SHA) == parent.POLICY,
         'same fixed original policy authority')
    need(plans['transport'] == modules['capture'].PINS['api'], 'same authenticated capture transport')

    def read(path):
        need(path in buffers, 'bootstrap read outside first-seen enrolled buffers')
        return buffers[path]

    with patch.object(Path, 'read_bytes', read):
        transport = load('_os_cell_qualifier_bootstrap_transport', ROOT / plans['transport'][0],
                         buffers[ROOT / plans['transport'][0]])
    witness = modules['admission'].witness_type(modules['legacy'], modules['capture'], extra_sources=buffers)(args)
    environment = dict(Witness=witness, Modules=modules, HelperPlans=plans)
    with patch.object(Path, 'read_bytes', read):
        helpers = {name: transport if name == 'transport' else
                   load('_os_cell_qualifier_bootstrap_' + name, ROOT / row[0], buffers[ROOT / row[0]])
                   for name, row in plans.items()}
    _nine(helpers).final_control_helpers(helpers)
    need(callable(getattr(helpers['cell_model'], 'contract', None))
         and callable(getattr(helpers['cell_model'], 'coverage', None))
         and callable(getattr(helpers['cell_coverage'], '_plan', None)), 'fixed metadata helper APIs')
    return runner, environment, builder, helpers, opening, buffers


def project_nine(report, helpers):
    nine = _nine(helpers)
    need(type(report) is dict and set(nine.FIELDS) <= set(report), 'complete shared nine fields')
    result = {key: deepcopy(report[key]) for key in nine.FIELDS}
    result.update(Scope=nine.SCOPE,
        Status=nine.PASS if report['CommonAttributionClosed'] is True else nine.PENDING,
        RequiredCellsSatisfied=0, RequiredCellSatisfied=False, CellContractSatisfied=False)
    return result


def _raw_record(row, text):
    keys(row, ('Path', 'Sha256', 'Bytes'), 'exact raw authority binding')
    need(type(text) is str, 'literal authority hex')
    try:
        raw = bytes.fromhex(text)
    except ValueError as error:
        raise ValueError('cm3-os-lto-cell-qualifier: invalid authority hex') from error
    need(raw.hex() == text and type(row['Bytes']) is int and row['Bytes'] == len(raw)
         and row['Sha256'] == sha(raw), 'authority byte/hash/size join')
    digest(row['Sha256'])
    same(row['Path'], str(lexical(row['Path'])), 'canonical authority path')
    return raw


def inventory_plan(report, helpers, *, closed=True):
    need(type(closed) is bool, 'literal closure-validation mode')
    model, normal = helpers['cell_model'], helpers['normal_entry']
    bindings, texts = report['CurrentInventoryInputs'], report['CurrentInventoryBytes']
    keys(bindings, INVENTORY_ROLES, 'four inventory authority roles')
    keys(texts, INVENTORY_ROLES, 'four retained inventory buffers')
    raw = {name: _raw_record(bindings[name], texts[name]) for name in INVENTORY_ROLES}
    descriptor = report['CurrentInventory']
    keys(descriptor, ('Build', 'ReceiptSha256', 'ArtifactsSha256'), 'current inventory descriptor')
    root = lexical(descriptor['Build'])
    paths = dict(Receipt=root / 'results.json', Manifest=root / 'artifacts.json',
                 RequiredCells=root / 'required-cells.json', CohortManifest=root / 'inputs/tools/freeze_cohorts.json')
    for name, path in paths.items():
        same(bindings[name]['Path'], str(path), 'fixed inventory role/' + name)
        if closed:
            same(report['InputHashes'].get(str(path)), bindings[name]['Sha256'], 'closed inventory input/' + name)
    same(bindings['Receipt']['Sha256'], digest(descriptor['ReceiptSha256']), 'inventory receipt authority')
    same(bindings['Manifest']['Sha256'], digest(descriptor['ArtifactsSha256']), 'inventory manifest authority')
    receipt, manifest = normal.structured(raw['Receipt']), normal.structured(raw['Manifest'])
    keys(manifest, ('Artifacts',), 'inventory manifest wrapper')
    artifacts = manifest['Artifacts']
    need(type(artifacts) is dict and 'artifacts.json' not in artifacts, 'non-self inventory manifest')
    for name in ('Receipt', 'RequiredCells', 'CohortManifest'):
        same(artifacts.get(paths[name].relative_to(root).as_posix()), bindings[name]['Sha256'],
             'inventory artifact membership/' + name)
    same(receipt['Verdict'], 'INVENTORY-PLAN-PASS', 'inventory disposition')
    same(receipt['Error'], None, 'inventory error')
    same(receipt['SourceInventorySha256'], model.SOURCE_INVENTORY_SHA256, 'inventory source cut')
    same(report['SourceInventorySha256'], model.SOURCE_INVENTORY_SHA256, 'qualifier source cut')
    same(receipt['RequiredCellCount'], model.REQUIRED_CELL_COUNT, 'inventory plan size')
    same(receipt['RequiredCellsSha256'], bindings['RequiredCells']['Sha256'], 'receipt required-plan bytes')
    same(receipt['ManifestSha256'], bindings['CohortManifest']['Sha256'], 'receipt captured cohort bytes')
    required = normal.structured(raw['RequiredCells'])
    cohort = normal.structured(raw['CohortManifest'])
    need(type(cohort) is dict and 'scope_backlog' in cohort, 'captured backlog authority')
    backlog = cohort['scope_backlog']
    model.coverage(required, backlog, [], coverage_module=helpers['cell_coverage'])
    return required, backlog


def admit_inventory(environment, report, helpers):
    witness = environment['Witness']
    descriptor = report['CurrentInventory']
    root = witness.replay_api.checked_path(descriptor['Build'], directory=True)
    raw = dict(Receipt=witness.watch.read(root / 'results.json', descriptor['ReceiptSha256']),
               Manifest=witness.watch.read(root / 'artifacts.json', descriptor['ArtifactsSha256']))
    manifest = helpers['normal_entry'].structured(raw['Manifest'])['Artifacts']
    paths = dict(Receipt=root / 'results.json', Manifest=root / 'artifacts.json',
                 RequiredCells=root / 'required-cells.json', CohortManifest=root / 'inputs/tools/freeze_cohorts.json')
    for name in ('RequiredCells', 'CohortManifest'):
        path = paths[name]
        raw[name] = witness.watch.read(path, digest(manifest[path.relative_to(root).as_posix()]))
    for path in paths.values():
        helpers['machine'].retain_identity(witness, path)
    report['CurrentInventoryInputs'] = {name: dict(Path=str(paths[name]), Sha256=sha(value), Bytes=len(value))
                                        for name, value in raw.items()}
    report['CurrentInventoryBytes'] = {name: value.hex() for name, value in raw.items()}
    return inventory_plan(report, helpers, closed=False)


EVIDENCE_PATHS = {
    'cpu-neutral-engine': (
        'IsolationComponent/SourceOwnership', 'IsolationComponent/IsolatedCommon',
        'IsolationComponent/DependencyBindings', 'IsolationComponent/IsolatedLinkedObjects',
        'CommonAttributes/Compilations', 'CommonAttributes/LoweredProofs/Lowerings'),
    'reverse-v1-ownership': (
        'ABIControls/DeclaredProviders/SourceInspection', 'IsolationComponent/SourceOwnershipInputs',
        'OriginalComponent/NativeBindings/Ordinary', 'OriginalComponent/NativeBindings/Emitted'),
    'source-provider-identity': (
        'DeferredABI/DeclaredProviders', 'ABIControls/NativeObjectBindings', 'ABIControls/DependencyBindings',
        'CommonAttributes/SourceInputs', 'CommonAttributes/DependencyBindings',
        'CommonAttributes/LoweredProofs/WorkerChains', 'PortPolicyComponent/SourceCohort',
        'PortPolicyComponent/DependencyBindings', 'PortPolicyComponent/LoweredProofs/WorkerChains'),
    'forward-eight': (
        'OriginalComponent/NativeBindings/Ordinary', 'OriginalComponent/NativeBindings/Emitted',
        'DeferredABI/PreprocessedAttributes', 'ABIControls/ABIProbes/types.c',
        'ABIControls/ABIProbes/attributes.c', 'ABIControls/AcceptedSaves'),
    'reverse-v1': (
        'OriginalComponent/NativeBindings/Ordinary', 'OriginalComponent/NativeBindings/Emitted',
        'ABIControls/AnchorConsumer', 'DeferredABI/DeclaredProviders/SourceInspection'),
    'current-slot-isolation': (
        'IsolationComponent/SlotProofs', 'IsolationComponent/LoadImageComparisons',
        'ABIControls/ABIProbes/slot_address.c', 'ABIControls/ABIProbes/slot_read.c',
        'ABIControls/ABIProbes/slot_write.c'),
    'strong-handlers': (
        'OriginalComponent/NativeBindings/Ordinary', 'OriginalComponent/NativeBindings/Emitted',
        'FinalReplacementComponent/TransportRoots', 'FinalReplacementComponent/CanonicalJoin/ProtocolProof'),
    'exact-profile-context-cohort': (
        'DeferredABI/DeclaredProviders/TargetContract', 'DeferredABI/PreprocessedAttributes/TargetContract',
        'CommonAttributes/CommandBindings', 'CommonAttributes/LoweredProofs/WorkerChains',
        'PortPolicyComponent/CommandBindings', 'PortPolicyComponent/LoweredProofs/WorkerChains'),
    'generated-assembly-reference-parity': (
        'OriginalComponent/TransportRoots', 'OriginalComponent/CanonicalJoin',
        'OriginalComponent/PolicyDifferenceRationales', 'FinalReplacementComponent/TransportRoots',
        'FinalReplacementComponent/CanonicalJoin', 'FinalReplacementComponent/PolicyDifferenceRationales',
        'FinalControlComponent/Baseline'),
    'final-elf-vectors': (
        'OriginalCensus/OriginalFinal', 'OriginalCensus/OriginalLtrans', 'OriginalCensus/Twins',
        'OriginalComponent/NativeBindings', 'OriginalComponent/LoadImageComparisons',
        'FinalReplacementComponent/Inputs', 'FinalReplacementComponent/ByteComparisons',
        'FinalReplacementComponent/LoadImageComparison'),
    'negative-link-controls': (
        'ABIControls/Controls', 'ABIControls/ABIProbes', 'ABIControls/AbsentOutputs',
        'ABIControls/CommandBindings', 'FinalControlComponent/Controls', 'FinalControlComponent/DerivedBuffers'),
}


def obligation_rows(report, helpers):
    model = helpers['cell_model']
    need(set(EVIDENCE_PATHS) == set((*model.COMMON, *model.RUNTIME)), 'exact eleven obligation names')
    same(report['CommonAttributionClosed'], True, 'required common attribution closed')
    same(report['UnresolvedAttribution'], [], 'no unresolved required attribution')
    same(report['CommonAttributes']['LoweredProofs']['CommonAttributionClosed'], True, 'lowered attribution closed')
    same(report['CommonAttributes']['LoweredProofs']['UnresolvedAttribution'], [], 'lowered attribution list')
    component_hashes, rows = {}, {}
    for name, paths in EVIDENCE_PATHS.items():
        references = []
        for text in paths:
            component, *parts = text.split('/')
            proof = report[component]
            need(type(proof) is dict and type(proof.get('Status')) is str and proof['Status'] != 'FAIL',
                 'completed detailed component/' + component)
            if component not in component_hashes:
                component_hashes[component] = sha(canonical(proof))
            value = proof
            for part in parts:
                need(type(value) is dict and part in value, 'named detailed evidence/' + text)
                value = value[part]
            need(type(value) in (dict, list) and value, 'substantive evidence, not a flag/' + text)
            references.append(dict(Component=component, Path=parts, Sha256=sha(canonical(value)),
                                   ComponentSha256=component_hashes[component]))
        rows[name] = dict(Satisfied=True, Evidence=references)
    return ({name: rows[name] for name in model.COMMON}, {name: rows[name] for name in model.RUNTIME})


def _accounting(report, helpers, verified_keys):
    required, backlog = inventory_plan(report, helpers, closed=False)
    coverage, missing = helpers['cell_model'].coverage(required, backlog, verified_keys,
                                                      coverage_module=helpers['cell_coverage'])
    report.update(Coverage=coverage, MissingWork=missing)
    root = lexical(report['Output'])
    report['AccountingArtifacts'] = {name: dict(Path=str(root / filename), Sha256=sha(encoded(report[name])),
                                               Bytes=len(encoded(report[name])))
                                     for name, filename in ACCOUNTING_FILES.items()}


def require_result(report, helpers):
    nine, model = _nine(helpers), helpers['cell_model']
    keys(report, nine.FIELDS | EXTRA_FIELDS, 'closed whole-qualifier result')
    same(report['Status'], PASS, 'bounded qualifier disposition')
    same(report['Scope'], SCOPE, 'qualifier scope')
    same(report['Route'], model.ROUTE, 'exact Os route')
    same(report['Key'], list(model.KEY), 'exact Os five-field key')
    same(report['CohortSha256'], model.COHORT_SHA256, 'cohort fingerprint')
    same(report['ModelContract'], model.contract(), 'unchanged metadata contract')
    same(report['RequiredCellSatisfied'], True, 'one satisfied cell')
    same(report['CellContractSatisfied'], True, 'whole contract satisfied')
    same(report['RequiredCellsSatisfied'], 1, 'one-cell accounting')
    same(report['RequiredCellCount'], model.REQUIRED_CELL_COUNT, 'complete required count')
    for name in set(nine.NONCLAIMS) - PROMOTED:
        same(report[name], False, 'preserved bounded nonclaim/' + name)
    nine.require_result(project_nine(report, helpers), helpers)
    common, runtime = obligation_rows(report, helpers)
    same(report['CommonPrerequisites'], common, 'detailed COMMON3 mapping')
    same(report['RuntimeObligations'], runtime, 'detailed RUNTIME8 mapping')
    required, backlog = inventory_plan(report, helpers)
    coverage, missing = model.coverage(required, backlog, [model.KEY], coverage_module=helpers['cell_coverage'])
    same(report['Coverage'], coverage, 'full eligible coverage')
    same(report['MissingWork'], missing, 'full remaining work')
    root = lexical(report['Output'])
    same(report['Output'], str(root), 'canonical output root')
    keys(report['AccountingArtifacts'], ACCOUNTING_FILES, 'two accounting artifacts')
    for name, filename in ACCOUNTING_FILES.items():
        raw = encoded(report[name])
        same(report['AccountingArtifacts'][name], dict(Path=str(root / filename), Sha256=sha(raw), Bytes=len(raw)),
             'accounting intended-byte binding/' + name)
    bootstrap = {row['Path']: row['Sha256'] for row in report['BootstrapSources']}
    captured = {row['Original']: row['Sha256'] for row in report['CapturedSources']}
    for relative, value in (*PINS.values(), *DOCUMENTS.items()):
        path = str(ROOT / relative)
        same(bootstrap.get(path), value, 'qualifier pre-witness pin/' + relative)
        same(captured.get(path), value, 'qualifier captured pin/' + relative)
    keys(report['QualifierSource'], ('Path', 'Sha256'), 'own first-seen source binding')
    own = str(lexical(__file__))
    same(report['QualifierSource']['Path'], own, 'fixed qualifier entry source')
    value = digest(report['QualifierSource']['Sha256'])
    same(bootstrap.get(own), value, 'own bootstrap bytes')
    same(captured.get(own), value, 'own captured bytes')
    for row in report['CapturedSources']:
        need(lexical(row['Captured']).parent == root / 'source-buffers', 'source copy in owned qualifier output')


def revoke(runner, report, helpers, error):
    nine, model = _nine(helpers), helpers['cell_model']
    primary = report.get('PrimaryError') or report.get('Error') or type(error).__name__ + ': ' + str(error)
    try:
        nine._revoke(runner, report, error)
    except BaseException as secondary:
        report.setdefault('ClosingErrors', []).append('aggregate revocation: ' + type(secondary).__name__ + ': ' + str(secondary))
    finally:
        report.update(Status='FAIL', Error=report.get('Error') or primary, PrimaryError=primary,
            **dict.fromkeys((*nine.FACTS, *nine.NONCLAIMS), False),
            **dict.fromkeys((name for name, _ in (*nine.COUNTERS, *nine.CONTROL_COUNTERS)), 0),
            RecordedInspectionInvocations=0, ToolInvocations=0, CompilerInvocations=0,
            RequiredCellsSatisfied=0, CommonAttributionClosed=False)
        for field, names in (('CommonPrerequisites', model.COMMON), ('RuntimeObligations', model.RUNTIME)):
            old = report.get(field)
            report[field] = {name: dict(Satisfied=False,
                Evidence=deepcopy(old[name].get('Evidence', [])) if type(old) is dict
                    and type(old.get(name)) is dict else []) for name in names}
    try:
        _accounting(report, helpers, [])
    except BaseException as secondary:
        report.update(Coverage=None, MissingWork=None, AccountingArtifacts={})
        report.setdefault('ClosingErrors', []).append('zero-credit accounting: ' + type(secondary).__name__ + ': ' + str(secondary))


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_nlink, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, getattr(info, 'st_file_attributes', 0))


def _regular_output(suite, guard, name):
    root = guard.require_owned_output(suite)
    need(name in ('results.json', 'artifacts.json', *ACCOUNTING_FILES.values()), 'bounded mutable metadata destination')
    path = root / name
    expected = getattr(suite, 'qualifier_manifest_sha', None) if name == 'artifacts.json' else suite.expected.get(name)
    try:
        info = path.lstat()
    except FileNotFoundError:
        need(name not in suite.identities and expected is None, 'owned metadata destination disappeared')
        guard.require_owned_output(suite)
        return path, None
    need(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_nlink == 1
         and not getattr(info, 'st_file_attributes', 0) & 0x400, 'regular unaliased metadata destination')
    need(name in suite.identities and expected is not None, 'preexisting unrecorded metadata destination')
    need((info.st_dev, info.st_ino) == suite.identities[name][:2], 'metadata destination physically replaced')
    raw = path.read_bytes()
    same(_stamp(path.lstat()), _stamp(info), 'metadata destination changed during prior-byte read')
    guard.require_owned_output(suite)
    need(sha(raw) == expected, 'prior intended metadata bytes changed')
    return path, info


def _prewrite(suite, guard, path, before):
    need(guard.require_owned_output(suite) == path.parent, 'same immediate prewrite root')
    try:
        current = path.lstat()
    except FileNotFoundError:
        need(before is None, 'metadata destination disappeared before write')
    else:
        need(before is not None, 'metadata destination appeared before write')
        same(_stamp(current), _stamp(before), 'metadata destination replaced before write')
    guard.require_owned_output(suite)


def _written(suite, guard, path, before, raw, count):
    guard.require_owned_output(suite)
    info = path.lstat()
    need(count == len(raw) and stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)
         and info.st_nlink == 1 and not getattr(info, 'st_file_attributes', 0) & 0x400,
         'complete owned metadata destination')
    if before is not None:
        need((info.st_dev, info.st_ino) == (before.st_dev, before.st_ino), 'metadata write replaced destination')
    same(path.read_bytes(), raw, 'complete intended metadata bytes')
    same(_stamp(path.lstat()), _stamp(info), 'metadata changed during write verification')
    guard.require_owned_output(suite)
    return info


@contextmanager
def metadata_writes(suite, guard):
    original = Path.write_bytes

    def write(path, raw):
        root = guard.require_owned_output(suite)
        need(path in (root / 'results.json', root / 'artifacts.json') and type(raw) is bytes,
             'bounded receipt/manifest writer')
        target, before = _regular_output(suite, guard, path.name)
        _prewrite(suite, guard, target, before)
        count = original(target, raw)
        info = _written(suite, guard, target, before, raw, count)
        suite.identities[path.name] = (info.st_dev, info.st_ino, info.st_nlink, info.st_size)
        if path.name == 'artifacts.json':
            suite.qualifier_manifest_sha = sha(raw)
        else:
            suite.expected[path.name] = sha(raw)
        return count

    with patch.object(Path, 'write_bytes', write):
        yield


def _write_failed_accounting(suite, guard, name, raw):
    need(name in ACCOUNTING_FILES.values() and type(raw) is bytes, 'narrow failed-accounting write')
    path, before = _regular_output(suite, guard, name)
    need(path not in suite.watch.hashes or suite.watch.hashes[path] == sha(raw), 'never rewrite a consumed input')
    _prewrite(suite, guard, path, before)
    count = path.write_bytes(raw)
    info = _written(suite, guard, path, before, raw, count)
    suite.expected[name] = sha(raw)
    suite.identities[name] = (info.st_dev, info.st_ino, info.st_nlink, info.st_size)


def verify_seal(environment, suite, report, helpers):
    witness, guard = environment['Witness'], helpers['guard']
    root = guard.require_owned_output(suite)
    api = witness.replay_api
    actual = api.files_under(root)
    expected = dict(suite.expected)
    need('artifacts.json' not in expected, 'manifest self-entry excluded from intended ledger')
    receipt_raw = encoded(report)
    expected['results.json'] = sha(receipt_raw)
    manifest_raw = encoded(dict(Artifacts=expected))
    same(getattr(suite, 'qualifier_manifest_sha', None), sha(manifest_raw), 'owned intended manifest bytes')
    for field, filename in ACCOUNTING_FILES.items():
        same(expected.get(filename), sha(encoded(report[field])), 'intended accounting contents/' + field)
    sealed = dict(expected, **{'artifacts.json': sha(manifest_raw)})
    same(sorted(actual), sorted(sealed), 'post-seal exact owned file membership')
    physical = set()
    for name, path in actual.items():
        guard.require_owned_output(suite)
        before = path.lstat()
        need(stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode) and before.st_nlink == 1
             and not getattr(before, 'st_file_attributes', 0) & 0x400, 'post-seal regular output/' + name)
        identity = (before.st_dev, before.st_ino, before.st_nlink, before.st_size)
        need(identity[:2] not in physical, 'post-seal physical output alias')
        physical.add(identity[:2])
        need(name in suite.identities, 'recorded post-seal output identity/' + name)
        same(identity, suite.identities[name], 'post-seal output identity/size/' + name)
        raw = path.read_bytes()
        after = path.lstat()
        same((after.st_dev, after.st_ino, after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
             (before.st_dev, before.st_ino, before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns),
             'stable post-seal output read/' + name)
        same(sha(raw), sealed[name], 'post-seal intended bytes/' + name)
        if name == 'results.json':
            same(raw, receipt_raw, 'persisted exact report')
        elif name == 'artifacts.json':
            same(raw, manifest_raw, 'persisted exact manifest')
    guard.require_owned_output(suite)
    same(sorted(api.files_under(root)), sorted(sealed), 'closing post-seal exact file membership')
    return dict(ReceiptSha256=sha(receipt_raw), ArtifactsSha256=sha(manifest_raw))


def recover_owned(runner, environment, builder, suite, helpers):
    report, guard = suite.report, helpers['guard']
    root = guard.require_owned_output(suite)
    try:
        _accounting(report, helpers, [])
    except BaseException as error:
        report.update(Coverage=None, MissingWork=None)
        report['AccountingArtifacts'] = {field: dict(Path=str(root / filename),
            Sha256=sha(encoded(None)), Bytes=len(encoded(None))) for field, filename in ACCOUNTING_FILES.items()}
        report.setdefault('ClosingErrors', []).append('FAIL accounting unavailable: ' + type(error).__name__ + ': ' + str(error))
    for field, filename in ACCOUNTING_FILES.items():
        try:
            _write_failed_accounting(suite, guard, filename, encoded(report[field]))
        except BaseException as error:
            report.setdefault('ClosingErrors', []).append('FAIL ' + filename + ': ' + type(error).__name__ + ': ' + str(error))
    # Frozen recovery permits only these two destinations; keep its root guard.
    with metadata_writes(suite, guard):
        builder.recover_owned(runner, environment, suite, guard)
    # The frozen helper swallows write failures. Its return is not seal evidence.
    same(report['Status'], 'FAIL', 'recovery cannot restore PASS')
    same(report['RequiredCellsSatisfied'], 0, 'recovered credit remains zero')
    environment['Witness'].close()
    verify_seal(environment, suite, report, helpers)


def run(args, runner, environment, builder, helpers, opening, buffers):
    nine, model = _nine(helpers), helpers['cell_model']
    witness = environment['Witness']
    report = dict(runner.base_report(witness), Scope=SCOPE, LTO=True, Route=model.ROUTE, Key=list(model.KEY),
        CohortSha256=model.COHORT_SHA256, ModelContract=model.contract(), Output=str(witness.output),
        QualifierSource=dict(Path=str(lexical(__file__)), Sha256=sha(buffers[lexical(__file__)])),
        OriginalCensus=None, DeferredABI=None, ABIControls=None, IsolationComponent=None,
        CommonAttributes=None, PortPolicyComponent=None, OriginalComponent=None,
        FinalReplacementComponent=None, FinalControlComponent=None,
        CurrentInventoryInputs={}, CurrentInventoryBytes={}, CommonPrerequisites={}, RuntimeObligations={},
        Coverage=None, MissingWork=None, AccountingArtifacts={}, CommonAttributionClosed=False, UnresolvedAttribution=[],
        **dict.fromkeys(nine.FACTS, False), **dict.fromkeys(nine.NONCLAIMS, False),
        **dict.fromkeys((name for name, _ in (*nine.COUNTERS, *nine.CONTROL_COUNTERS)), 0))
    suite = None
    try:
        root, batch, roles = helpers['machine'].admit_batch(args, runner, environment, builder, helpers, opening)
        normal_root, handoff, targets, tool, project_count = nine._parent(helpers).admit_normal(
            args, runner, environment, root, batch, roles, helpers)
        admit_inventory(environment, report, helpers)
        report.update(Batch=dict(Build=str(root), ReceiptSha256=args.batch_receipt_sha256,
                                ArtifactsSha256=args.batch_artifacts_sha256),
            OriginalCensusHandoff=dict(Build=str(normal_root), ReceiptSha256=args.normal_receipt_sha256,
                                      ArtifactsSha256=args.normal_artifacts_sha256),
            OriginalTargets=targets, InspectionTool=tool, ProjectSourceReaderRoles=project_count,
            RecordedInspectionInvocations=2, Commands=[], ToolInvocations=0, CompilerInvocations=0)
        _accounting(report, helpers, [])
        suite = helpers['session'].suite_type(helpers['utility'], helpers['lto'])(environment, helpers, buffers)
        suite.report = report
        suite.start()
        suite._save('commands.json', [])
        report['CommandsSha256'] = suite.expected['commands.json']
        values = nine.replay(runner, environment, root, batch, normal_root, handoff, roles, targets, tool)
        names = ('OriginalCensus', 'DeferredABI', 'ABIControls', 'IsolationComponent', 'CommonAttributes',
                 'PortPolicyComponent', 'OriginalComponent', 'FinalReplacementComponent', 'FinalControlComponent',
                 'ImmutableReader')
        need(type(values) is tuple and len(values) == len(names), 'one complete frozen nine replay')
        report.update(zip(names, values))
        pending = report['CommonAttributes']['LoweredProofs']['UnresolvedAttribution']
        report.update(CommonAttributionClosed=not pending, UnresolvedAttribution=deepcopy(pending),
            **dict.fromkeys((name for name in nine.FACTS if name not in ('InputClosureVerified', 'OutputSealVerified')), True),
            **dict(nine.COUNTERS), **dict(nine.CONTROL_COUNTERS))
        common, runtime = obligation_rows(report, helpers)
        report.update(CommonPrerequisites=common, RuntimeObligations=runtime)
        _accounting(report, helpers, [model.KEY])
        for field, filename in ACCOUNTING_FILES.items():
            suite._save(filename, report[field])
            same(suite.expected[filename], report['AccountingArtifacts'][field]['Sha256'], 'intended accounting encoder')
        report.update(Status=PASS, CellContractSatisfied=True, RequiredCellSatisfied=True, RequiredCellsSatisfied=1)
        suite.verify_objects()
        witness.close()
        suite._verify_outputs()
        helpers['guard'].require_owned_output(suite)
        with metadata_writes(suite, helpers['guard']):
            runner.seal(environment, report, suite.expected)
        require_result(report, helpers)
        witness.close()
        sealed = verify_seal(environment, suite, report, helpers)
        print(json.dumps(dict(Status=report['Status'], RequiredCellsSatisfied=1, RequiredCellCount=2774,
            ToolInvocations=0, CompilerInvocations=0, Output=str(suite.output), **sealed), sort_keys=True), flush=True)
        return report
    except BaseException as error:
        revoke(runner, report, helpers, error)
        if suite is not None and suite._started:
            try:
                recover_owned(runner, environment, builder, suite, helpers)
            except BaseException as secondary:
                report.setdefault('ClosingErrors', []).append('failure persistence: ' + type(secondary).__name__ + ': ' + str(secondary))
            finally:
                revoke(runner, report, helpers, error)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ARGUMENTS:
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    with patch('os.system', side_effect=AssertionError('qualifier cannot execute shell commands')), \
            patch('subprocess.Popen', side_effect=AssertionError('qualifier cannot start processes')):
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
