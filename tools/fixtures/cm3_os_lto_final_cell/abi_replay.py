"""Pure deferred declaration/CPP/positive-image replay, not ABI controls.

The caller admits the batch, manifest, native capture, helpers and core reader.
No command, dependency discovery, module loading or physical I/O happens here.
The core comparator must use that same immutable scope, not reopen the paths.
"""

import copy
import hashlib
import json
import math
from pathlib import Path
import re


STATUS = 'CM3-OS-LTO-ABI-DEFERRED-FACTS-REPLAYED-NOT-QUALIFIED'
SCOPE = 'CM3_OS_LTO_DECLARATIONS_CPP_AND_POSITIVE_LOAD_IMAGE_ONLY'
COHORT = 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default'
SOURCE = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
ADAPTER = 'NATIVE_CURRENT_CM3_OS_LTO_DIRECT_DECLARATION_PROVIDER_ADMISSION_ONLY'
POSITIVE_SCOPE = 'SAME_OS_SLIM_INPUTS_RECIPE_LOAD_IMAGE_REPRODUCTION_ONLY'
ORDER = ('context/context_core.c', 'context/context_runtime_state.c', 'context/context_panic.c',
    'fiber/port/ARM_CM3/fiber_port.c', 'fiber/port/ARM_CM3/fiber_port_boot.c',
    'fiber/port/ARM_CM3/fiber_port_exception.c', 'fiber/port/fiber_port_context_cohort_expectation.c',
    'tools/fixtures/classic_final_image/application.c', 'tools/fixtures/classic_final_image/startup.S')
DECL_NONCLAIMS = ('CompilerExecuted', 'DeclarationTypesProven', 'DeclarationAttributesProven',
    'PublishedAttributeBundleProven', 'ProviderObjectIdentityProven', 'ActualDependencyClosureProven',
    'SourceBodyIsolationProven', 'GeneratedSlotIsolationProven', 'ColdAnchorReadProven',
    'FullABIProof', 'FullSemanticABIProof', 'WholeProviderEquivalence', 'InstructionEquivalence',
    'PolicyEquivalence', 'SourceIRProof', 'SourceToMachineSemanticProof', 'KernelRuntimeProof',
    'HandlerRoutingProven', 'CpuExecution', 'BoardExecution', 'HostedCIQualified',
    'ArchiveQualification', 'GlobalFreezeQualified', 'CellContractSatisfied', 'RequiredCellSatisfied')
NONCLAIMS = DECL_NONCLAIMS + ('Qualification', 'CompleteCellProof', 'ABIControlsReplayed',
    'TypedDeclarationProbesReplayed', 'NegativeLinkControlsReplayed', 'AcceptedCompileReplayed',
    'CompilationProvenanceReplayed', 'ExternalDependencyBytesReplayed', 'SeedDiscoveryDependencySetCompared',
    'PositiveLinkRecipeReplayed', 'PositiveMapSemanticsReplayed', 'IsolationReplayed',
    'FinalRootTransferProtocolsValidated', 'FinalReferenceParity', 'OriginalTranslationUnitOwnership',
    'SourceToIRSemanticProof', 'ProducerCommandProvenanceReplayed', 'AcceptedCompileProvenanceReplayed')
FACTS = ('DeclaredProviderDependenciesReplayed', 'PreprocessedAttributesReplayed', 'PositiveLinkRevalidated',
    'CallerOwnsAdmissionAndImmutableScope', 'CallerOwnsCoreImmutableBinding')
COUNTS = dict(DeferredFactsReplayed=3, ProviderRecords=9, RawSourceIdentities=18,
              CPPDeclarations=12, ForwardDeclarations=8, ReverseDeclarations=4,
              ComparedImages=2, RequiredCellsSatisfied=0)
FIELDS = frozenset(NONCLAIMS + FACTS) | frozenset(COUNTS) | frozenset(('Status', 'Scope', 'Profile',
    'Mode', 'Linkage', 'LTO', 'Cohort', 'SourceInventorySha256', 'Root', 'SourceRoot', 'CaptureRoot',
    'ProjectSourceFiles', 'ProjectSources', 'ReadFiles', 'ReadInputs', 'Inputs', 'DeclaredProviders',
    'PreprocessedAttributes', 'PositiveAuthority', 'ABIControlsDeferredReader'))


class Rejected(ValueError):
    pass


def need(value, detail):
    if not value:
        raise Rejected('REJECT:CM3-OS-LTO-ABI-REPLAY:' + detail)


def sha(raw):
    need(type(raw) is bytes, 'immutable bytes')
    return hashlib.sha256(raw).hexdigest().upper()


def _hash(value):
    need(type(value) is str and re.fullmatch('[0-9A-F]{64}', value) is not None, 'literal SHA256')
    return value


def _path(value):
    need(type(value) is str or isinstance(value, Path), 'literal path')
    need(str(value) and not any(char in str(value) for char in '\0\r\n'), 'path grammar')
    path = Path(value)
    need(path.is_absolute() and '..' not in path.parts, 'absolute lexical path')
    return path


def _relative(value):
    need(type(value) is str and value and '\\' not in value and ':' not in value
         and not any(char in value for char in '\0\r\n')
         and all(part not in ('', '.', '..') for part in value.split('/')), 'relative path')
    return value


def _equal(left, right):
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def _json(raw):
    sha(raw)

    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result

    def constant(value):
        raise Rejected('REJECT:CM3-OS-LTO-ABI-REPLAY:nonfinite JSON/' + value)

    def floating(value):
        result = float(value)
        need(math.isfinite(result), 'nonfinite JSON number')
        return result

    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant,
                          parse_float=floating)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Rejected('REJECT:CM3-OS-LTO-ABI-REPLAY:JSON grammar') from error


def _identity(record):
    need(type(record) is dict, 'Os metadata object')
    for key, value in (('Profile', 'CM3'), ('Mode', 'Os-lto'), ('Linkage', 'direct'),
                       ('Cohort', COHORT), ('SourceInventorySha256', SOURCE)):
        need(type(record.get(key)) is str and record[key] == value, 'Os identity/' + key)
    need(record.get('LTO') is True, 'literal LTO')


def _pending(inputs, identical):
    original, replayed, link_map = (inputs[key] for key in ('OriginalELF', 'ReproducedELF', 'ReproducedMap'))
    readers = [dict(Role=role, **inputs[role]) for role in ('OriginalELF', 'ReproducedELF')]
    positive = dict(Original=original['Path'], OriginalSha256=original['Sha256'],
        Replayed=replayed['Path'], ReplayedSha256=replayed['Sha256'], Map=link_map['Path'],
        MapSha256=link_map['Sha256'], RawElfByteIdentical=identical,
        Scope='SAME_OS_SLIM_INPUTS_RECIPE_LOAD_IMAGE_REPRODUCTION_PENDING',
        LoadImageComparison=None, LoadImageValidated=False, ValidationDeferred=True,
        LinkCommandIndex=0, ReaderInputs=readers)
    deferred = dict(Kind='OS_POSITIVE_LOAD_IMAGE_REPRODUCTION', Status='PENDING',
        ValidationDeferred=True, Inputs=copy.deepcopy(readers), Map=dict(Role='ReproducedMap', **link_map),
        PositiveLinkRevalidated=False, RequiredCellsSatisfied=0)
    return positive, deferred


def inspect(batch, native, root, core, helpers, read):
    """Replay three facts in a pre-admitted scope; never promote the batch.

    read(Path, expected_sha) must return immutable bytes. Only the already
    caller-admitted batch artifacts.json may use None when not in InputHashes.
    All sources under SourceSeed/source are read, including non-oracle files.
    """
    root = _path(root)
    need(type(helpers) is dict and set(helpers) == {'declarations', 'ordinary', 'guard'}, 'explicit helpers')
    need(callable(read) and callable(getattr(core, 'compare_load_images', None)), 'explicit immutable reader/core')
    need(all(callable(getattr(helpers['declarations'], name, None)) for name in
         ('inspect_provider_dependencies', 'inspect_preprocessed_attributes')), 'declaration functions')
    need(callable(getattr(helpers['ordinary'], 'profile_contract', None))
         and callable(getattr(helpers['guard'], '_same', None)), 'ordinary/guard functions')

    def same(left, right, label):
        try:
            helpers['guard']._same(left, right, label)
        except ValueError as error:
            raise Rejected('REJECT:CM3-OS-LTO-ABI-REPLAY:' + label) from error

    _identity(batch); _identity(native)
    same(batch.get('Status'), 'BUILT-PENDING-READER', 'pending batch')
    same(native.get('Status'), 'PASS', 'native capture status')
    need(type(batch.get('SourceSeed')) is str, 'literal source seed')
    source_root = _path(batch.get('SourceSeed')) / 'source'
    same(native.get('SeedBuild'), batch['SourceSeed'], 'native source seed')
    capture_root = _path(batch.get('NativeCapture', {}).get('Build'))
    for left, right in ((root, source_root), (root, capture_root), (source_root, capture_root)):
        need(not left.is_relative_to(right) and not right.is_relative_to(left), 'disjoint roots')
    need(type(batch.get('InputHashes')) is dict and batch['InputHashes'], 'input hash authority')
    authority = {}
    for name, digest in batch['InputHashes'].items():
        path = _path(name)
        need(path not in authority, 'ambiguous input identity')
        authority[path] = _hash(digest)
    consumed = {}

    def checked(path, digest):
        value = read(path, digest)
        need(sha(value) == digest and (path not in consumed or consumed[path] == value), 'immutable read hash')
        consumed[path] = value
        return value

    manifest_path = root / 'artifacts.json'
    manifest_raw = read(manifest_path, authority.get(manifest_path))
    if manifest_path in authority:
        need(sha(manifest_raw) == authority[manifest_path], 'manifest input hash')
    consumed[manifest_path] = manifest_raw
    manifest = _json(manifest_raw)
    need(type(manifest) is dict and set(manifest) == {'Artifacts'}
         and type(manifest['Artifacts']) is dict and manifest['Artifacts'], 'admitted batch manifest')
    artifacts = {}
    for relative, digest in manifest['Artifacts'].items():
        _relative(relative)
        path = root.joinpath(*relative.split('/'))
        need(path != manifest_path and path not in artifacts, 'distinct artifact identity')
        artifacts[path] = _hash(digest)
        if path in authority:
            same(artifacts[path], authority[path], 'manifest/input correspondence')

    def raw(path, digest):
        path, digest = _path(path), _hash(digest)
        registry = artifacts if path.is_relative_to(root) else authority
        same(registry.get(path), digest, 'admitted role/' + str(path))
        return checked(path, digest)

    native_path = capture_root / 'results.json'
    native_hash = _hash(batch['NativeCapture'].get('ReceiptSha256'))
    native_raw = raw(native_path, native_hash)
    same(_json(native_raw), native, 'reparsed native capture')
    sources, source_records = {}, []
    for path, digest in sorted(authority.items()):
        if not path.is_relative_to(source_root):
            continue
        relative = path.relative_to(source_root).as_posix()
        _relative(relative)
        sources[relative] = raw(path, digest)
        source_records.append(dict(Relative=relative, Path=str(path), Sha256=digest))
    need(sources, 'project source cohort')
    try:
        providers = helpers['declarations'].inspect_provider_dependencies(sources, native_raw,
            source_root=str(source_root), capture_root=str(capture_root), ordinary=helpers['ordinary'])
    except (ValueError, UnicodeError) as error:
        raise Rejected('REJECT:CM3-OS-LTO-ABI-REPLAY:provider dependencies') from error
    same(providers, batch.get('DeclaredProviders'), 'stored provider comparison')
    probe = batch.get('ABIProbes', {}).get('attributes.c')
    need(type(probe) is dict, 'accepted CPP probe')
    cpp_path = root / 'abi/attributes.i'
    same(probe.get('Preprocessed'), str(cpp_path), 'fixed accepted CPP path')
    same(probe.get('Classification'), dict(AcceptedCompile=True), 'recorded accepted CPP probe')
    cpp_raw = raw(cpp_path, artifacts.get(cpp_path))
    try:
        attributes = helpers['declarations'].inspect_preprocessed_attributes(cpp_raw, ordinary=helpers['ordinary'])
    except (ValueError, UnicodeError) as error:
        raise Rejected('REJECT:CM3-OS-LTO-ABI-REPLAY:preprocessed attributes') from error
    same(attributes, batch.get('PreprocessedAttributes'), 'stored CPP comparison')
    for direction, name in (('forward', 'context_port_abi.h'), ('reverse', 'context_runtime_port_abi.h')):
        need(_path(attributes.get('CanonicalHeaders', {}).get(direction)) == source_root / 'context' / name,
             'canonical CPP source header')
    links = native.get('Links')
    need(type(links) is list and len(links) == 2 and all(type(row) is dict for row in links), 'native twin records')
    same([row.get('Kind') for row in links], ['ordinary', 'emit-relocs'], 'native twin order')
    original = capture_root / 'ordinary/image.elf'
    same(links[0].get('Path'), str(original), 'native ordinary path')
    inputs = dict(Manifest=dict(Path=str(manifest_path), Sha256=sha(manifest_raw)),
        NativeReceipt=dict(Path=str(native_path), Sha256=native_hash),
        Attributes=dict(Path=str(cpp_path), Sha256=sha(cpp_raw)))
    for role, path, digest in (('OriginalELF', original, links[0].get('Sha256')),
            ('ReproducedELF', root / 'links/positive/image.elf', artifacts.get(root / 'links/positive/image.elf')),
            ('ReproducedMap', root / 'links/positive/image.map', artifacts.get(root / 'links/positive/image.map'))):
        raw(path, digest)
        inputs[role] = dict(Path=str(path), Sha256=digest)
    identical = inputs['OriginalELF']['Sha256'] == inputs['ReproducedELF']['Sha256']
    positive, deferred = _pending(inputs, identical)
    same(batch.get('PositiveAuthority'), positive, 'stored positive authority comparison')
    same(batch.get('ABIControlsDeferredReader'), deferred, 'stored deferred obligation comparison')
    comparison = core.compare_load_images(original, root / 'links/positive/image.elf')
    positive.update(LoadImageComparison=copy.deepcopy(comparison), LoadImageValidated=True,
                    ValidationDeferred=False, Scope=POSITIVE_SCOPE)
    deferred.update(Status='REPLAYED', ValidationDeferred=False, PositiveLinkRevalidated=True,
                    LoadImageComparison=copy.deepcopy(comparison))
    result = dict(Status=STATUS, Scope=SCOPE, Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True,
        Cohort=COHORT, SourceInventorySha256=SOURCE, Root=str(root), SourceRoot=str(source_root),
        CaptureRoot=str(capture_root), ProjectSourceFiles=len(source_records), ProjectSources=source_records,
        Inputs=inputs, DeclaredProviders=copy.deepcopy(providers), PreprocessedAttributes=copy.deepcopy(attributes),
        PositiveAuthority=positive, ABIControlsDeferredReader=deferred, ReadFiles=len(consumed),
        ReadInputs=[dict(Path=str(path), Sha256=sha(value)) for path, value in sorted(consumed.items())],
        **COUNTS, **dict.fromkeys(FACTS, True), **dict.fromkeys(NONCLAIMS, False))
    return require_result(result)


def require_result(proof):
    """Validate the closed bounded proof, not replace recomputation/admission."""
    need(type(proof) is dict and set(proof) == FIELDS, 'closed result schema')
    _identity(proof)
    need(proof['Status'] == STATUS and proof['Scope'] == SCOPE, 'bounded disposition')
    for key, value in COUNTS.items():
        need(type(proof[key]) is int and proof[key] == value, 'literal count/' + key)
    for key in FACTS:
        need(proof[key] is True, 'replayed fact/' + key)
    for key in NONCLAIMS:
        need(proof[key] is False, 'nonclaim/' + key)
    root, source_root, capture_root = (_path(proof[key]) for key in ('Root', 'SourceRoot', 'CaptureRoot'))
    need(source_root.name == 'source', 'source root suffix')
    for left, right in ((root, source_root), (root, capture_root), (source_root, capture_root)):
        need(not left.is_relative_to(right) and not right.is_relative_to(left), 'result disjoint roots')
    records = proof['ProjectSources']
    need(type(records) is list and type(proof['ProjectSourceFiles']) is int
         and len(records) == proof['ProjectSourceFiles'] >= 18, 'complete project source count')
    sources = {}
    for row in records:
        need(type(row) is dict and set(row) == {'Relative', 'Path', 'Sha256'}, 'typed source binding')
        relative = _relative(row['Relative']); path = _path(row['Path'])
        need(path == source_root.joinpath(*relative.split('/')) and path not in sources, 'distinct canonical source')
        sources[path] = _hash(row['Sha256'])
    inputs = proof['Inputs']
    fixed = dict(Manifest=root / 'artifacts.json', NativeReceipt=capture_root / 'results.json',
        Attributes=root / 'abi/attributes.i', OriginalELF=capture_root / 'ordinary/image.elf',
        ReproducedELF=root / 'links/positive/image.elf', ReproducedMap=root / 'links/positive/image.map')
    need(type(inputs) is dict and set(inputs) == set(fixed), 'six fixed input roles')
    for key, path in fixed.items():
        row = inputs[key]
        need(type(row) is dict and set(row) == {'Path', 'Sha256'} and row['Path'] == str(path), 'fixed input/' + key)
        _hash(row['Sha256'])
    reads = proof['ReadInputs']
    need(type(reads) is list and type(proof['ReadFiles']) is int
         and len(reads) == proof['ReadFiles'] == len(sources) + 6, 'closed read counter')
    read_map = {}
    for row in reads:
        need(type(row) is dict and set(row) == {'Path', 'Sha256'}, 'typed read binding')
        path = _path(row['Path']);need(path not in read_map, 'unique read role')
        read_map[path] = _hash(row['Sha256'])
    expected = dict(sources)
    expected.update({_path(row['Path']): row['Sha256'] for row in inputs.values()})
    need(read_map == expected and len(expected) == len(sources) + 6, 'source/input read closure')
    providers, attributes = proof['DeclaredProviders'], proof['PreprocessedAttributes']
    inspection = providers.get('SourceInspection') if type(providers) is dict else None
    metadata = {'Profile', 'Mode', 'Linkage', 'LTO', 'Cohort', 'AdapterScope', 'AllowedModes', 'Scope', 'TargetContract'}
    schemas = (metadata | {'ReceiptSha256', 'SourceInspection', 'DeclaredProviderDependenciesBound',
        'DeclaredDependencyAuthority', 'SeedFlagsTransformVerified', 'SeedDiscoveryDependencySetCompared',
        'SourceRoot', 'CaptureRoot', 'Providers', 'UnverifiedExternalDependencies'},
        metadata | {'RawSourceIdentitiesChecked', 'Sources', 'ExpectedOwners'},
        metadata | {'AcceptedCompileRequired', 'AuthenticatedHeaderBindingRequired', 'CanonicalHeaders',
        'Declarations', 'ForwardDeclarations', 'ReverseDeclarations', 'LineMarkerProvenanceOnly',
        'PreprocessedNoSanitizeDeclarationsChecked', 'PreprocessedSha256', 'SameAttemptReflectionRequired'})
    for record, schema in zip((providers, inspection, attributes), schemas):
        need(type(record) is dict and set(record) == schema, 'closed declaration result schema')
        need(type(record) is dict and record.get('Profile') == 'CM3' and record.get('Mode') == 'Os-lto'
             and record.get('Linkage') == 'direct' and record.get('LTO') is True
             and record.get('Cohort') == COHORT and record.get('AdapterScope') == ADAPTER
             and _equal(record.get('AllowedModes'), ['Os-lto']), 'bounded declaration metadata')
        scope = record.get('Scope')
        need(type(scope) is dict and set(scope) == set(DECL_NONCLAIMS) | {'RequiredCellsSatisfied'}, 'declaration scope')
        need(all(scope[key] is False for key in DECL_NONCLAIMS) and type(scope['RequiredCellsSatisfied']) is int
             and scope['RequiredCellsSatisfied'] == 0, 'declaration nonclaims')
        contract = record.get('TargetContract')
        expected_contract = dict(Profile='CM3', Cohort=COHORT, SourceGroup='CM3', Architecture='ARMV7M',
            FloatABI='soft', FpuUnit='', FPStacking='none', VTOR=True, NVICPriorityBits=4, SchedulerBASEPRI=16,
            Linkage='direct', AllowedModes=['Os-lto'], SourceInventorySha256=SOURCE,
            InventoryManifestSha256='BC6B8EADABCAA6637FDD121D03B5CA341EEE31848D7E007D1D027AEE63EC8CBE',
            Mode='Os-lto', LTO=True)
        need(_equal(contract, expected_contract), 'Os target contract')
    need(providers.get('ReceiptSha256') == inputs['NativeReceipt']['Sha256']
         and _path(providers.get('SourceRoot')) == source_root and _path(providers.get('CaptureRoot')) == capture_root
         and providers.get('DeclaredProviderDependenciesBound') is True
         and providers.get('DeclaredDependencyAuthority') == 'CAPTURE_INPUT_HASHES'
         and providers.get('SeedFlagsTransformVerified') is True
         and providers.get('SeedDiscoveryDependencySetCompared') is False, 'bounded provider result')
    need(inspection.get('RawSourceIdentitiesChecked') is True and type(inspection.get('Sources')) is list
         and len(inspection['Sources']) == 18, 'eighteen raw source identities')
    inspected = set()
    for row in inspection['Sources']:
        need(type(row) is dict and set(row) == {'Path', 'Sha256'}, 'source inspection record')
        relative = _relative(row['Path']);need(relative not in inspected, 'distinct raw identities')
        inspected.add(relative)
        need(sources.get(source_root.joinpath(*relative.split('/'))) == _hash(row['Sha256']), 'raw identity/read binding')
    rows = providers.get('Providers')
    need(type(rows) is list and len(rows) == 9, 'nine ordered providers')
    for index, (row, relative) in enumerate(zip(rows, ORDER)):
        need(type(row) is dict and set(row) == {'ObjectIndex', 'Source', 'Object', 'DependencyFile',
             'DeclaredObjectSha256', 'DeclaredSlimIR', 'SeedCompileFlags', 'CompileFlags', 'Dependencies'},
             'closed provider row')
        need(type(row) is dict and type(row.get('ObjectIndex')) is int and row['ObjectIndex'] == index
             and row.get('Source') == relative and row.get('DeclaredSlimIR') is (index != 8), 'provider selectors')
        obj = capture_root / 'objects' / ('%02d-' % index + Path(relative).stem + '.o')
        need(_path(row.get('Object')) == obj and _path(row.get('DependencyFile')) == obj.with_suffix('.d'), 'provider object paths')
        _hash(row.get('DeclaredObjectSha256'))
        dependencies = row.get('Dependencies')
        need(type(dependencies) is list and dependencies == sorted(set(dependencies)) and relative in dependencies,
             'ordered canonical dependency set')
        for name in dependencies:
            _relative(name);need(source_root.joinpath(*name.split('/')) in sources, 'provider project dependency')
        for key in ('SeedCompileFlags', 'CompileFlags'):
            need(type(row.get(key)) is list and row[key] and all(type(flag) is str for flag in row[key]), 'recorded flags')
    external = providers.get('UnverifiedExternalDependencies')
    need(type(external) is list, 'external dependency metadata')
    external_paths = set()
    for row in external:
        need(type(row) is dict and set(row) == {'Path', 'Sha256'}, 'external declaration')
        path = _path(row['Path']);_hash(row['Sha256'])
        need(path not in external_paths and not path.is_relative_to(source_root), 'distinct external roles')
        external_paths.add(path)
    need(attributes.get('PreprocessedSha256') == inputs['Attributes']['Sha256']
         and attributes.get('PreprocessedNoSanitizeDeclarationsChecked') is True, 'CPP byte binding')
    for key in ('AcceptedCompileRequired', 'AuthenticatedHeaderBindingRequired', 'LineMarkerProvenanceOnly',
                'SameAttemptReflectionRequired'):
        need(attributes.get(key) is True, 'remaining CPP obligation/' + key)
    for key, value in (('ForwardDeclarations', 8), ('ReverseDeclarations', 4)):
        need(type(attributes.get(key)) is int and attributes[key] == value, 'CPP declaration count')
    headers = attributes.get('CanonicalHeaders')
    need(type(headers) is dict and set(headers) == {'forward', 'reverse'}, 'two canonical CPP headers')
    for direction, name in (('forward', 'context_port_abi.h'), ('reverse', 'context_runtime_port_abi.h')):
        path = source_root / 'context' / name
        need(_path(headers[direction]) == path and path in sources, 'CPP header/source binding')
    declarations = attributes.get('Declarations')
    need(type(declarations) is list and len(declarations) == 12
         and len({row.get('Name') for row in declarations if type(row) is dict}) == 12, 'twelve distinct CPP declarations')
    for row, direction in zip(declarations, ['forward'] * 8 + ['reverse'] * 4):
        need(type(row) is dict and set(row) == {'Direction', 'Header', 'Line', 'Name', 'NoSanitizeArguments'},
             'closed CPP declaration')
        need(type(row) is dict and row.get('Direction') == direction and type(row.get('Name')) is str
             and row['Name'] and row.get('Header') == headers[direction]
             and type(row.get('Line')) is int and row['Line'] > 0
             and _equal(row.get('NoSanitizeArguments'), ['address', 'undefined', 'thread']), 'typed CPP declaration')
    owners = []
    for row, index in zip(declarations, (4, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 0)):
        owners.append(dict(Name=row['Name'], Direction=row['Direction'], ObjectIndex=index, Source=ORDER[index],
            NoReturn=row['Name'] in ('fiber_port_panic_wait', 'fiber_port_runtime_start_first', 'fiber_internal_task_return')))
    need(_equal(inspection.get('ExpectedOwners'), owners), 'twelve declared owner selectors')
    positive, deferred = _pending(inputs, inputs['OriginalELF']['Sha256'] == inputs['ReproducedELF']['Sha256'])
    comparison = proof['PositiveAuthority'].get('LoadImageComparison') if type(proof['PositiveAuthority']) is dict else None
    need(type(comparison) is dict and set(comparison) == {'Entry', 'Identical', 'Segments', 'VectorAddress', 'VectorBytes'}
         and comparison.get('Identical') is True and type(comparison.get('Entry')) is int and comparison['Entry'] > 0
         and type(comparison.get('VectorAddress')) is int and comparison['VectorAddress'] >= 0
         and type(comparison.get('VectorBytes')) is str and re.fullmatch('[0-9a-f]{2048}', comparison['VectorBytes']) is not None,
         'positive load comparison')
    segments = comparison['Segments']
    need(type(segments) is list and segments, 'positive load segments')
    for segment in segments:
        need(type(segment) is dict and set(segment) == {'Vaddr', 'Paddr', 'FileSize', 'MemorySize', 'Flags', 'Align', 'BytesSha256'}
             and all(type(segment[key]) is int and segment[key] >= 0 for key in
                 ('Vaddr', 'Paddr', 'FileSize', 'MemorySize', 'Flags', 'Align'))
             and segment['MemorySize'] >= segment['FileSize'], 'typed positive load segment')
        _hash(segment['BytesSha256'])
    positive.update(LoadImageComparison=comparison, LoadImageValidated=True, ValidationDeferred=False, Scope=POSITIVE_SCOPE)
    deferred.update(Status='REPLAYED', ValidationDeferred=False, PositiveLinkRevalidated=True, LoadImageComparison=comparison)
    need(_equal(positive, proof['PositiveAuthority']) and _equal(deferred, proof['ABIControlsDeferredReader']), 'replayed positive/deferred correspondence')
    return proof
