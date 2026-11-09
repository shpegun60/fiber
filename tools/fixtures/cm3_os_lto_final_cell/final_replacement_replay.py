"""Pure selected-replacement final/root replay over caller-admitted bytes.

The caller authenticates the fourteen helpers and validates the detailed port
adapter. No capture is invented and no original attribute dump is borrowed.
Detached validation checks report/control joins, not renewed binary admission.
"""

import copy
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
from unittest.mock import patch


STATUS = 'CM3-OS-LTO-FINAL-REPLACEMENT-REPLAYED-NOT-QUALIFIED'
SCOPE = 'CM3_OS_LTO_SELECTED_REPLACEMENT_FINAL_AND_SIX_ROOTS_ONLY'
COHORT = 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default'
ORIGINAL_REPLAY_SHA256 = 'BF15568AE1EF2D5A67FC63573965D36AA0A9D31308A57C1B2FC860310E0DA645'
PORT_REPLAY_SHA256 = 'C88995AC5343B376AC1E73F0570F8AF9F025144820BD88556CF0A57814B8DE94'
ORIGINAL_HELPERS = ('abi', 'link_helpers', 'binding_helpers', 'native_roots', 'reference_roots',
    'native_protocol', 'reference_protocol', 'decoder', 'checker', 'os_join', 'join', 'guard')
HELPERS = frozenset((*ORIGINAL_HELPERS, 'original_replay', 'port_replay'))
FINAL_ROLES = ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup', 'MachineDisassembly')
ROLE_NAMES = dict(Final=FINAL_ROLES, Reference=FINAL_ROLES, OriginalNative=('Machine', 'Emitted', 'Ordinary'),
    Ledgers=('Master', 'Policy'), Authorities=('BatchReceipt', 'BatchManifest', 'NativeReceipt',
        'NativeManifest', 'ReferenceReceipt', 'ReferenceManifest'))
CONTROL_NAMES = (*ROLE_NAMES['Authorities'], 'MasterLedger', 'PolicyLedger')
NONCLAIMS = ('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof',
    'FullInstructionSemantics', 'SourceIRProof', 'SourceToIRSemanticProof', 'SourceToMachineSemanticProof',
    'OriginalTranslationUnitOwnership', 'OrdinaryRootPreservationProven', 'HandlerRoutingProven',
    'FinalReferenceParity', 'InstructionEquivalence', 'PolicyEquivalence', 'ArbitraryCallbackSafetyProven',
    'MutantsReexecuted', 'ProducerCompilersReexecuted', 'UnchangedOtherSixGeneratedBodies', 'CompleteCellProof',
    'WholeCellProof', 'RequiredCellSatisfied', 'CellContractSatisfied', 'ArchiveQualification', 'HostedCIQualified',
    'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified')
FIELDS = frozenset(('Status', 'Scope', 'Profile', 'Mode', 'Linkage', 'LTO', 'Cohort', 'SourceInventorySha256',
    'BatchRoot', 'BatchAuthority', 'OriginalProofSha256', 'PortProofSha256', 'Inputs', 'ControlBytes',
    'ByteComparisons', 'LoadImageComparison', 'TransportRoots', 'CanonicalJoin', 'PolicyDifferenceRationales',
    'ReadInputs', 'ReadFiles', 'LogicalRoles', 'FreshFinalCanonicalRootsRecomputed', 'OwnFinalInputsBound',
    'ToolInvocations', 'CompilerInvocations', 'RequiredCellsSatisfied', 'Nonclaims'))


class Rejected(ValueError):
    pass


def need(condition, label):
    if not condition:
        raise Rejected('REJECT:CM3-OS-LTO-FINAL-REPLACEMENT:' + label)


def sha(raw):
    need(type(raw) is bytes, 'literal immutable bytes')
    return hashlib.sha256(raw).hexdigest().upper()


def _hash(value):
    need(type(value) is str and re.fullmatch('[A-F0-9]{64}', value) is not None, 'uppercase SHA256')
    return value


def _identity(value):
    return PureWindowsPath(str(value)).as_posix().casefold()


def _binding(path, digest, original):
    return dict(Path=str(original._path(path)), Sha256=_hash(digest))


def _check_binding(row, original):
    original._keys(row, ('Path', 'Sha256'), 'final replacement binding')
    need(type(row['Path']) is str, 'literal returned path string')
    original._same(row, _binding(row['Path'], row['Sha256'], original), 'canonical returned binding')
    return row


def _hex(value):
    need(type(value) is str and re.fullmatch('(?:[0-9a-f]{2})+', value) is not None, 'nonempty lowercase control hex')
    return bytes.fromhex(value)


def _proof_sha(proof):
    try:
        raw = json.dumps(proof, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError, OverflowError, RecursionError) as error:
        raise Rejected('REJECT:CM3-OS-LTO-FINAL-REPLACEMENT:finite JSON component proof') from error
    return sha(raw)


def _helpers(helpers):
    need(type(helpers) is dict and set(helpers) == HELPERS, 'exact fourteen helpers')
    original = helpers['original_replay']
    calls = ('require_result', '_keys', '_same', '_path', '_json', '_manifest', '_require_transport',
        '_require_join', '_parsed_image', '_require_load', '_json_value')
    need(all(callable(getattr(original, name, None)) for name in calls)
         and callable(getattr(helpers['port_replay'], 'require_result', None)), 'published pure helper API')
    base = {key: helpers[key] for key in ORIGINAL_HELPERS}
    expected = tuple('SelectedReplacementBodiesIdentical' if key == 'UnchangedOtherSixGeneratedBodies' else key for key in NONCLAIMS)
    original._same(tuple(original.NONCLAIMS), expected, 'published original nonclaim catalog')
    original._same(original.COHORT, COHORT, 'published original cohort')
    return original, base


def _components(port, original, helpers):
    module, base = _helpers(helpers)
    module.require_result(original, base)
    helpers['port_replay'].require_result(port)
    for key in ('Cohort', 'SourceInventorySha256'):
        module._same(port[key], original[key], 'port/original ' + key)
    module._same(port['CaptureRoot'], original['Authorities']['Native']['Root'], 'port original native capture')
    module._same(port['AuthorityInputs']['NativeReceipt'], original['Authorities']['Native']['Receipt'], 'port native receipt')
    return module, base


def _batch_authority(batch, original):
    original._keys(batch, ('Root', 'Result', 'Artifacts', 'ReceiptSha256', 'ManifestSha256'), 'genuine batch descriptor')
    root = original._path(batch['Root'])
    return root, dict(Receipt=_binding(root / 'results.json', batch['ReceiptSha256'], original),
                      Manifest=_binding(root / 'artifacts.json', batch['ManifestSha256'], original))


def _control_bindings(authorities, ledgers):
    return dict(authorities, MasterLedger=ledgers['Master'], PolicyLedger=ledgers['Policy'])


def _layout(batch, port, original, controls, module):
    """Derive the exact role map; only the genuine batch descriptor is accepted."""
    root, authority = _batch_authority(batch, module)
    module._keys(controls, CONTROL_NAMES, 'eight final replacement controls')
    for kind in ('Receipt', 'Manifest'):
        module._same(sha(controls['Batch' + kind]), authority[kind]['Sha256'], 'batch control hash/' + kind)
    result = module._json(controls['BatchReceipt'])
    manifest = module._keys(module._json(controls['BatchManifest']), ('Artifacts',), 'batch artifact manifest')
    module._same(result, batch['Result'], 'independently read batch receipt')
    module._same(manifest['Artifacts'], batch['Artifacts'], 'independently read batch manifest')
    module._manifest(manifest['Artifacts'])
    for key, expected in (('Profile', 'CM3'), ('Mode', 'Os-lto'), ('Linkage', 'direct'), ('LTO', True), ('Cohort', COHORT)):
        module._same(result.get(key), expected, 'batch identity/' + key)
    need(result.get('Status') == 'BUILT-PENDING-READER' and result.get('PortPolicyBuilt') is True, 'sealed pending port batch')
    module._same(result.get('SourceInventorySha256'), original['SourceInventorySha256'], 'batch source inventory')
    module._same(str(root), port['Root'], 'own batch root')
    module._same(authority['Receipt'], port['AuthorityInputs']['BatchReceipt'], 'port batch receipt')
    module._same(authority['Manifest'], port['AuthorityInputs']['Manifest'], 'port batch manifest')
    authorities = dict(BatchReceipt=authority['Receipt'], BatchManifest=authority['Manifest'])
    captures = {}
    for side in ('Native', 'Reference'):
        for kind in ('Receipt', 'Manifest'):
            name = side + kind
            row = original['Authorities'][side][kind]
            _check_binding(row, module)
            authorities[name] = copy.deepcopy(row)
            module._same(sha(controls[name]), row['Sha256'], 'fresh capture authority hash/' + name)
            module._same(controls[name], _hex(original['ControlBytes'][name]), 'same original capture control bytes/' + name)
        captures[side] = module._json(controls[side + 'Receipt'])
        cap_manifest = module._keys(module._json(controls[side + 'Manifest']), ('Artifacts',), 'capture manifest/' + side)
        module._manifest(cap_manifest['Artifacts'])
    native_capture = result.get('NativeCapture')
    module._keys(native_capture, ('Build', 'ReceiptSha256', 'ArtifactsSha256'), 'batch native authority')
    module._same(str(module._path(native_capture['Build'])), original['Authorities']['Native']['Root'], 'batch native root')
    module._same(native_capture['ReceiptSha256'], authorities['NativeReceipt']['Sha256'], 'batch native receipt authority')
    module._same(native_capture['ArtifactsSha256'], authorities['NativeManifest']['Sha256'], 'batch native manifest authority')
    module._same(result.get('PortPolicyFinalLink'), port['FinalLink'], 'bound complete final link record')
    native_objects = port['NativeObjectBindings']
    need(type(native_objects) is list and len(native_objects) == 9, 'nine native object providers')
    provider = native_objects[8]
    module._keys(provider, ('Index', 'Path', 'Sha256'), 'native startup provider eight')
    module._same(provider['Index'], 8, 'typed startup provider index')
    startup = _check_binding({key: provider[key] for key in ('Path', 'Sha256')}, module)
    for kind in ('NativeOrdinary', 'NativeEmitted'):
        module._same(startup, original['Inputs'][kind]['Startup'], 'original native startup/' + kind)
    source = captures['Native']['Sources'][8]
    module._same(startup, _binding(source['Object'], source['ObjectSha256'], module), 'captured native provider eight')
    final_record = result['PortPolicyFinalLink']
    module._same(str(module._path(final_record['Objects'][8])), startup['Path'], 'final recipe startup provider')
    output = root / 'port-policy/final-supported/image.elf'
    paths = dict(Machine=Path(str(output) + '.ltrans0.ltrans.o'), Final=output,
        Disassembly=Path(str(output) + '.dis'), LinkMap=output.with_suffix('.map'), Startup=Path(startup['Path']),
        MachineDisassembly=Path(str(output) + '.ltrans0.ltrans.o.dis'))
    port_names = dict(Machine='Final/Machine', Final='Final/ELF', Disassembly='Final/Disassembly', LinkMap='Final/Map',
        Startup='Final/Startup', MachineDisassembly='Final/MachineDisassembly')
    final = {}
    deferred = result.get('PortPolicyDeferredReader')
    need(type(deferred) is dict and type(deferred.get('Inputs')) is list, 'batch deferred role rows')
    for name in FINAL_ROLES:
        role_name, path = port_names[name], paths[name]
        row = module._keys(port['Inputs'][role_name], ('Role', 'Path', 'Sha256'), 'detailed port final role/' + name)
        module._same(row['Role'], role_name, 'exact port role label')
        binding = _binding(path, startup['Sha256'] if name == 'Startup' else
            manifest['Artifacts'].get(path.relative_to(root).as_posix()), module)
        module._same({key: row[key] for key in ('Path', 'Sha256')}, binding, 'fixed own final path/hash/' + name)
        matched = [candidate for candidate in deferred['Inputs'] if type(candidate) is dict and candidate.get('Role') == role_name]
        module._same(matched, [dict(Role=role_name, **binding)], 'batch deferred role/' + name)
        final[name] = binding
    module._same(final_record['Path'], final['Final']['Path'], 'final record own ELF path')
    module._same(final_record['Sha256'], final['Final']['Sha256'], 'final record own ELF hash')
    module._same(final_record['Map'], final['LinkMap']['Path'], 'final record own map path')
    module._same(final_record['MapSha256'], final['LinkMap']['Sha256'], 'final record own map hash')
    module._same(final_record['Disassembly'], final['Disassembly'], 'final record own dump')
    module._same(final_record['WorkerDisassembly'], final['MachineDisassembly'], 'final record own machine dump')
    module._same(final_record['ActualWorker']['Machine'], final['Machine']['Path'], 'final record own generated machine path')
    module._same(final_record['ActualWorker']['MachineSha256'], final['Machine']['Sha256'], 'final record own generated machine hash')
    reference = {name: copy.deepcopy(original['Inputs']['Reference'][name]) for name in FINAL_ROLES}
    originals = dict(Machine=copy.deepcopy(original['Inputs']['NativeEmitted']['Machine']),
        Emitted=copy.deepcopy(original['Inputs']['NativeEmitted']['Final']), Ordinary=copy.deepcopy(original['Inputs']['NativeOrdinary']['Final']))
    inputs = dict(Final=final, Reference=reference, OriginalNative=originals,
        Ledgers=copy.deepcopy(original['Inputs']['Ledgers']), Authorities=authorities)
    for name in ('Master', 'Policy'):
        control_name = name + 'Ledger'
        module._same(sha(controls[control_name]), inputs['Ledgers'][name]['Sha256'], 'fresh ledger hash/' + name)
        module._same(controls[control_name], _hex(original['ControlBytes'][control_name]), 'same original ledger bytes/' + name)
    return inputs, authority


def _unique(inputs, module):
    module._keys(inputs, ROLE_NAMES, 'five final replacement input groups')
    paths, identities = {}, set()
    for group, names in ROLE_NAMES.items():
        module._keys(inputs[group], names, 'input roles/' + group)
        for name in names:
            row = _check_binding(inputs[group][name], module)
            identity = _identity(row['Path'])
            need(identity not in identities, '23 distinct roles, no aliases/' + group + '/' + name)
            identities.add(identity)
            paths[module._path(row['Path'])] = row['Sha256']
    need(len(paths) == len(identities) == 23, 'exact 23 unique input paths')
    return paths


def _join_inputs(inputs):
    return dict(NativeEmitted=inputs['Final'], Reference=inputs['Reference'], Ledgers=inputs['Ledgers'])


def inspect(core, read, batch, port, original, helpers):
    """Read exactly 23 admitted paths and freshly recompute final/root predicates."""
    module, base = _components(port, original, helpers)
    need(callable(read) and callable(getattr(core, 'compare_load_images', None)), 'explicit immutable reader/core')
    _, authority = _batch_authority(batch, module)
    buffers, hashes = {}, {}

    def consume(row):
        _check_binding(row, module)
        path, digest = module._path(row['Path']), row['Sha256']
        if path not in buffers:
            raw = read(path, digest)
            need(type(raw) is bytes and sha(raw) == digest, 'immutable admitted byte/hash binding/' + str(path))
            buffers[path], hashes[path] = raw, digest
        else:
            module._same(hashes[path], digest, 'same input path/hash')
        return buffers[path]

    auth_rows = dict(BatchReceipt=authority['Receipt'], BatchManifest=authority['Manifest'])
    for side in ('Native', 'Reference'):
        for kind in ('Receipt', 'Manifest'):
            auth_rows[side + kind] = original['Authorities'][side][kind]
    controls = {name: consume(row) for name, row in _control_bindings(auth_rows, original['Inputs']['Ledgers']).items()}
    inputs, authority = _layout(batch, port, original, controls, module)
    paths = _unique(inputs, module)
    for path, digest in paths.items():
        consume(_binding(path, digest, module))
    module._same(set(buffers), set(paths), 'exact 23 consumed roles')
    comparisons = {}
    for name, left, right in (('Final', inputs['Final']['Final'], inputs['OriginalNative']['Emitted']),
                               ('Machine', inputs['Final']['Machine'], inputs['OriginalNative']['Machine'])):
        left_raw, right_raw = buffers[module._path(left['Path'])], buffers[module._path(right['Path'])]
        need(left_raw == right_raw and bool(left_raw), 'actual whole-file equality/' + name)
        comparisons[name] = dict(Left=copy.deepcopy(left), Right=copy.deepcopy(right), Bytes=len(left_raw),
            Sha256=sha(left_raw), Identical=True)

    def buffered(path):
        path = module._path(path)
        need(path in buffers, 'constructor read outside final replacement roles/' + str(path))
        return buffers[path]

    def text(path, encoding=None, errors=None, newline=None):
        need(encoding in (None, 'ascii', 'utf-8') and errors in (None, 'strict') and newline is None, 'strict buffered text')
        return buffered(path).decode(encoding or 'utf-8')

    with patch.object(Path, 'read_bytes', buffered), patch.object(Path, 'read_text', text):
        views = {}
        for side, group, adapter, protocol in (
            ('Native', 'Final', helpers['native_roots'].NativeCM3LTOImage, helpers['native_protocol'].NativeProtocolView),
            ('Reference', 'Reference', helpers['reference_roots'].ReferenceCM3LTOImage, helpers['reference_protocol'].ReferenceProtocolView)):
            row = inputs[group]
            machine, final, startup, dump, link_map, machine_dump = (module._path(row[name]['Path']) for name in
                ('Machine', 'Final', 'Startup', 'Disassembly', 'LinkMap', 'MachineDisassembly'))
            transport = adapter(core, machine, final, dump, provider_objects={str(machine): machine, str(startup): startup}, link_map=link_map)
            module._parsed_image(transport.image, row, buffers)
            decoded = helpers['decoder'].Object(machine, machine_dump)
            need(type(decoded.data) is bytes and decoded.data == buffers[machine], 'decoder consumes own actual machine/' + side)
            views[side] = protocol(decoded, transport)
        joined = helpers['os_join'].check_join(views['Native'], views['Reference'], helpers['checker'], controls['MasterLedger'].decode('ascii'), base['join'])
        load_image = core.compare_load_images(module._path(inputs['OriginalNative']['Ordinary']['Path']), module._path(inputs['Final']['Final']['Path']))
        module._require_load(load_image)
        module._same(load_image, original['LoadImageComparisons']['Native'], 'actual selected-final/native-ordinary load comparison')
    joined = module._json_value(joined)
    proof = dict(Status=STATUS, Scope=SCOPE, Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True,
        Cohort=COHORT, SourceInventorySha256=original['SourceInventorySha256'], BatchRoot=str(module._path(batch['Root'])),
        BatchAuthority=authority, OriginalProofSha256=_proof_sha(original), PortProofSha256=_proof_sha(port),
        Inputs=inputs, ControlBytes={name: controls[name].hex() for name in CONTROL_NAMES}, ByteComparisons=comparisons,
        LoadImageComparison=copy.deepcopy(load_image), TransportRoots=copy.deepcopy(joined['RawTransportRoots']), CanonicalJoin=joined,
        PolicyDifferenceRationales=helpers['join'].require_ledger(controls['PolicyLedger'].decode('ascii'), joined['ProtocolProof']),
        ReadInputs=[dict(Path=str(path), Sha256=hashes[path], Bytes=len(raw)) for path, raw in sorted(buffers.items())],
        ReadFiles=23, LogicalRoles=23, FreshFinalCanonicalRootsRecomputed=True, OwnFinalInputsBound=True,
        ToolInvocations=0, CompilerInvocations=0, RequiredCellsSatisfied=0, Nonclaims=dict.fromkeys(NONCLAIMS, False))
    return require_result(proof, batch, port, original, helpers)


def require_result(proof, batch, port, original, helpers):
    """Validate closed detached evidence; no ELF constructors, reader or I/O."""
    module, base = _components(port, original, helpers)
    module._keys(proof, FIELDS, 'final replacement result')
    for key, expected in (('Status', STATUS), ('Scope', SCOPE), ('Profile', 'CM3'), ('Mode', 'Os-lto'),
        ('Linkage', 'direct'), ('LTO', True), ('Cohort', COHORT), ('ReadFiles', 23), ('LogicalRoles', 23),
        ('FreshFinalCanonicalRootsRecomputed', True), ('OwnFinalInputsBound', True), ('ToolInvocations', 0),
        ('CompilerInvocations', 0), ('RequiredCellsSatisfied', 0)):
        module._same(proof[key], expected, 'final replacement result/' + key)
    module._same(proof['Nonclaims'], dict.fromkeys(NONCLAIMS, False), 'closed all-false final replacement nonclaims')
    module._same(proof['OriginalProofSha256'], _proof_sha(original), 'full original component proof hash')
    module._same(proof['PortProofSha256'], _proof_sha(port), 'full port component proof hash')
    module._same(proof['SourceInventorySha256'], original['SourceInventorySha256'], 'same source inventory')
    module._same(proof['BatchRoot'], str(module._path(batch['Root'])), 'same genuine batch root')
    module._keys(proof['ControlBytes'], CONTROL_NAMES, 'eight final replacement control buffers')
    controls = {name: _hex(proof['ControlBytes'][name]) for name in CONTROL_NAMES}
    inputs, authority = _layout(batch, port, original, controls, module)
    module._same(proof['Inputs'], inputs, 'independently derived final replacement role map')
    module._same(proof['BatchAuthority'], authority, 'same batch authority pair')
    paths = _unique(inputs, module)
    reads = proof['ReadInputs']
    need(type(reads) is list and len(reads) == 23, '23 read inventory rows')
    sizes, digests = {}, {}
    for row in reads:
        module._keys(row, ('Path', 'Sha256', 'Bytes'), 'final replacement read row')
        need(type(row['Path']) is str and type(row['Bytes']) is int and row['Bytes'] > 0, 'literal path and positive byte count')
        path = module._path(row['Path'])
        module._same(row['Path'], str(path), 'canonical read inventory path')
        need(path not in digests, 'unique input inventory row')
        sizes[path], digests[path] = row['Bytes'], _hash(row['Sha256'])
    module._same({str(path): digest for path, digest in digests.items()},
                 {str(path): digest for path, digest in paths.items()}, 'exact read-role hashes/membership')
    module._same([row['Path'] for row in reads], [str(path) for path in sorted(paths)], 'sorted read inventory')
    joined_sizes = set()
    for name, row in _control_bindings(inputs['Authorities'], inputs['Ledgers']).items():
        module._same(sha(controls[name]), row['Sha256'], 'control hash/' + name)
        module._same(len(controls[name]), sizes[module._path(row['Path'])], 'control size/' + name)
        joined_sizes.add(module._path(row['Path']))
    for label, prior_reads in (('original', original['ReadInputs']), ('port', port['LoweredProofs']['ReadInputs'])):
        need(type(prior_reads) is list, 'prior read inventory/' + label)
        for row in prior_reads:
            module._keys(row, ('Path', 'Sha256', 'Bytes'), 'prior sized read/' + label)
            path = module._path(row['Path'])
            if path in paths:
                module._same(row, dict(Path=str(path), Sha256=paths[path], Bytes=sizes[path]),
                             'authoritative read size/' + label + '/' + str(path))
                joined_sizes.add(path)
    module._same(joined_sizes, set(paths), 'all 23 sizes join independent authorities')
    module._keys(proof['ByteComparisons'], ('Final', 'Machine'), 'two whole-file byte comparisons')
    for name, left, right in (('Final', inputs['Final']['Final'], inputs['OriginalNative']['Emitted']),
                               ('Machine', inputs['Final']['Machine'], inputs['OriginalNative']['Machine'])):
        row = proof['ByteComparisons'][name]
        module._keys(row, ('Left', 'Right', 'Bytes', 'Sha256', 'Identical'), 'whole-file comparison/' + name)
        module._same(row['Left'], left, 'comparison own final binding/' + name)
        module._same(row['Right'], right, 'comparison original binding/' + name)
        module._same(row['Identical'], True, 'whole-file comparison completed')
        need(type(row['Bytes']) is int and row['Bytes'] > 0, 'positive comparison size')
        for binding in (left, right):
            module._same(row['Sha256'], binding['Sha256'], 'comparison file digest')
            module._same(row['Bytes'], sizes[module._path(binding['Path'])], 'comparison file size')
    module._require_load(proof['LoadImageComparison'])
    module._same(proof['LoadImageComparison'], original['LoadImageComparisons']['Native'], 'same original native load image')
    module._keys(proof['TransportRoots'], ('Native', 'Reference'), 'final replacement transport sides')
    for side, group, names in (('Native', 'Final', module.NATIVE_ROOTS), ('Reference', 'Reference', module.REFERENCE_ROOTS)):
        rows = proof['TransportRoots'][side]
        need(type(rows) is list and len(rows) == 3, 'three complete transport roots/' + side)
        for row, name in zip(rows, names):
            module._require_transport(row, side, name, inputs[group], base)
    rationales = module._require_join(proof['CanonicalJoin'], proof['TransportRoots'], _join_inputs(inputs), controls, base)
    module._same(proof['PolicyDifferenceRationales'], rationales, 'fixed policy ledger rationales')
    module._same(proof['TransportRoots']['Reference'], original['TransportRoots']['Reference'], 'same own reference transport bytes/roles')
    module._same(proof['CanonicalJoin']['Roots']['Reference'], original['CanonicalJoin']['Roots']['Reference'], 'same own reference canonical evidence')
    return proof
