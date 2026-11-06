"""Pure pending-catalog correspondence and read-only output ownership guards.

These guards grant no reader, machine, cell or qualification credit. Catalog
validation reads no filesystem; it derives authority from original top-level
phase records and InputHashes, never from PendingFinalReader.Components.
Output ownership uses a no-follow directory stat and performs no writes.
"""

import math
import ntpath
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat


PROBES = ('types.c', 'attributes.c', 'slot_read.c', 'slot_write.c', 'slot_address.c')
PROBE_FIELDS = ('Source', 'Object', 'Preprocessed', 'DiscoveryDependencyFile', 'CompileDependencyFile')
COMPONENT_KEYS = {
    'ABIControls': ('ABIControlsBuild', 'ABIControlsDeferredReader', 'PositiveAuthority',
                    'DeclaredProviders', 'ABIProbes', 'PreprocessedAttributes'),
    'Isolation': ('IsolationBuild', 'IsolationDeferredReader', 'IsolatedCommon', 'IsolatedLinkedObjects'),
    'PortPolicy': ('PortPolicyBuild', 'PortPolicyDeferredReader', 'PortPolicyCompilations',
                   'PortPolicyLowerings', 'PortPolicyFinalLink'),
}
ISOLATION_ROLES = ('OriginalOrdinaryELF', 'OriginalEmitELF', 'OriginalMachine', 'OriginalAssembly',
    'OriginalDisassembly', 'OriginalMap', 'IsolatedOrdinaryELF', 'IsolatedOrdinaryMap', 'IsolatedEmitELF',
    'IsolatedMachine', 'IsolatedAssembly', 'IsolatedMap', 'IsolatedDisassembly', 'StartupObject',
    'PortSource', 'IsolatedIR0', 'IsolatedIR1', 'IsolatedIR2')
COMMON_GROUPS = ('positive', 'mutant-engine', 'mutant-state', 'mutant-panic', 'stress-protected', 'stress-unprotected')
COMMON_ROLES = ('Object', 'Machine', 'Disassembly', 'WpaArguments', 'LtransArguments', 'WpaResponse',
    'LtransResponse', 'PartitionList', 'Intermediate', 'Resolution', 'Assembly', 'WrapperArgs', 'DriverSpecs', 'Diagnostics')
PORT_GROUPS = ('selected', 'stress-supported', 'stress-raw')
OBLIGATIONS = ('ABI provider/declaration and positive-image reproduction',
    'Original/isolated twins, slot protocols and generated common providers',
    'Six hostile aggregate/worker effects and Os saved-worker options',
    'Selected-port aggregate/final census, paired stress and transfer roots')


class Rejected(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected('REJECT:CM3-OS-LTO-BATCH-GUARD:' + message)


def _hash(value):
    need(type(value) is str and re.fullmatch('[0-9A-F]{64}', value) is not None, 'literal SHA256')
    return value


def _path(value):
    need(type(value) is str and value and '\0' not in value, 'literal absolute path')
    windows, posix = PureWindowsPath(value), PurePosixPath(value)
    if windows.is_absolute():
        need('..' not in windows.parts, 'no parent traversal in path')
        return 'win:' + ntpath.normcase(ntpath.normpath(value))
    need(posix.is_absolute() and '\\' not in value and '..' not in posix.parts, 'absolute path domain')
    return 'posix:' + str(posix)


def _same(actual, expected, label):
    """JSON equality with exact types, unlike Python's False == 0 aliases."""
    need(type(actual) is type(expected), 'type correspondence/' + label)
    if type(expected) is dict:
        need(set(actual) == set(expected), 'object keys/' + label)
        for key in expected:
            need(type(key) is str, 'JSON object key/' + label)
            _same(actual[key], expected[key], label + '/' + key)
    elif type(expected) is list:
        need(len(actual) == len(expected), 'ordered list size/' + label)
        for index, (left, right) in enumerate(zip(actual, expected)):
            _same(left, right, label + '/' + str(index))
    else:
        need(type(expected) in (str, int, float, bool, type(None)), 'JSON scalar/' + label)
        if type(expected) is float:
            need(math.isfinite(actual) and math.isfinite(expected), 'finite JSON number/' + label)
        need(actual == expected, 'value correspondence/' + label)


def _build(row, first, stop):
    need(type(row) is dict and row.get('Status') == 'BUILT-PENDING-READER'
         and row.get('Profile') == 'CM3' and row.get('Mode') == 'Os-lto'
         and row.get('Linkage') == 'direct' and row.get('LTO') is True, 'fixed original build record')
    for key, expected in (('First', first), ('Stop', stop), ('Commands', stop-first), ('RequiredCellsSatisfied', 0)):
        need(type(row.get(key)) is int and row[key] == expected, 'typed build counter/' + key)
    need(row.get('Qualification') is False, 'build is not qualification')


def _pending(row):
    need(type(row) is dict and row.get('Status') == 'PENDING' and row.get('ValidationDeferred') is True
         and type(row.get('RequiredCellsSatisfied')) is int and row['RequiredCellsSatisfied'] == 0,
         'original phase reader remains pending')


def _require_pending_catalog(report):
    """Return the unchanged pending record only after exact reconstruction.

    The role order intentionally matches batch_attempt.pending_reader: ABI,
    Isolation, PortPolicy, CommonAttributes. Object-key order is immaterial,
    including after a sort_keys JSON round trip; role-list order is exact.
    """
    need(type(report) is dict, 'report object')
    hashes = report.get('InputHashes')
    need(type(hashes) is dict and hashes, 'complete admitted input hash map')
    authority = {}
    for path, digest in hashes.items():
        key = _path(path)
        need(key not in authority, 'ambiguous normalized input hash path')
        authority[key] = _hash(digest)
    roles = []

    def binding(path, digest=None):
        key = _path(path)
        need(key in authority, 'catalog path absent from InputHashes: ' + path)
        value = authority[key] if digest is None else _hash(digest)
        need(value == authority[key], 'original record disagrees with InputHashes: ' + path)
        return dict(Path=path, Sha256=value)

    def add(component, role, path, digest=None):
        need(type(role) is str and role, 'fixed role name')
        roles.append(dict(Component=component, Role=role, **binding(path, digest)))

    def record_binding(row, *, role=None):
        need(type(row) is dict and 'Path' in row and 'Sha256' in row, 'original path/hash record')
        if role is not None:
            need(row.get('Role') == role, 'original fixed role/' + role)
        return binding(row['Path'], row['Sha256'])

    for key, first, stop in (('ABIControlsBuild', 0, 41), ('IsolationBuild', 41, 53), ('PortPolicyBuild', 98, 134)):
        _build(report.get(key), first, stop)
    abi, positive = report.get('ABIControlsDeferredReader'), report.get('PositiveAuthority')
    _pending(abi)
    need(type(positive) is dict and positive.get('ValidationDeferred') is True
         and positive.get('LoadImageValidated') is False and positive.get('LoadImageComparison') is None,
         'original positive image proof remains deferred')
    inputs = abi.get('Inputs')
    need(type(inputs) is list and len(inputs) == 2, 'two original positive-image roles')
    for role, path_key, hash_key, row in (('OriginalELF', 'Original', 'OriginalSha256', inputs[0]),
            ('ReproducedELF', 'Replayed', 'ReplayedSha256', inputs[1])):
        original = record_binding(row, role=role)
        _same(original, binding(positive[path_key], positive[hash_key]), 'positive/' + role)
        add('ABIControls', role, original['Path'], original['Sha256'])
    _same(positive.get('ReaderInputs'), inputs, 'original positive reader inputs')
    original = record_binding(abi.get('Map'), role='ReproducedMap')
    _same(original, binding(positive['Map'], positive['MapSha256']), 'positive map')
    add('ABIControls', 'ReproducedMap', original['Path'], original['Sha256'])
    probes = report.get('ABIProbes')
    need(type(probes) is dict and set(probes) == set(PROBES), 'exact five original ABI probes')
    for name in PROBES:
        row = probes[name]
        accepted = name in PROBES[:2]
        need(type(row) is dict and all(field in row for field in PROBE_FIELDS), 'complete original probe fields')
        if not accepted:
            need(row['Object'] is row['Preprocessed'] is None, 'rejected probe has no accepted artifacts')
        for field in PROBE_FIELDS:
            path = row[field]
            if path is None:
                need(not accepted and field in ('Object', 'Preprocessed'), 'missing mandatory probe artifact')
                continue
            explicit = row.get('SourceSha256') if field == 'Source' else None
            if field == 'Source':
                need(explicit is not None, 'original emitted probe source hash')
            if field == 'Object':
                slim = row.get('SlimIR')
                need(type(slim) is dict and slim.get('SlimIR') is True and slim.get('Object') == path,
                     'original accepted slim probe identity')
                explicit = slim.get('Sha256')
                need(explicit is not None, 'original accepted slim object hash')
            if field == 'Preprocessed' and name == 'attributes.c':
                attrs = report.get('PreprocessedAttributes')
                need(type(attrs) is dict, 'original declaration metadata')
                explicit = attrs.get('PreprocessedSha256')
                need(explicit is not None, 'original accepted CPP hash')
            add('ABIControls', name + '/' + field, path, explicit)

    isolation = report.get('IsolationDeferredReader')
    _pending(isolation)
    rows = isolation.get('Inputs')
    need(type(rows) is list and len(rows) == len(ISOLATION_ROLES), 'complete original Isolation catalog')
    for role, row in zip(ISOLATION_ROLES, rows):
        value = record_binding(row, role=role)
        add('Isolation', role, value['Path'], value['Sha256'])
    common = report.get('IsolatedCommon')
    linked = report.get('IsolatedLinkedObjects')
    need(type(common) is list and len(common) == 3 and type(linked) is list and len(linked) == 9,
         'three isolated providers and nine linked objects')
    by_role = {row['Role']: row for row in rows}
    for index, row in enumerate(linked):
        need(type(row) is dict and type(row.get('Index')) is int and row['Index'] == index
             and row.get('OriginalUnchanged') is (index >= 3), 'literal original isolated link order')
        record_binding(row)
        if index < 3:
            provider = common[index]
            need(type(provider) is dict, 'original isolated provider record')
            _same(binding(provider['Object'], provider['ObjectSha256']), record_binding(by_role['IsolatedIR' + str(index)]),
                  'isolated provider/' + str(index))
            _same(record_binding(row), binding(provider['Object'], provider['ObjectSha256']), 'isolated link/' + str(index))
    _same(record_binding(by_role['StartupObject']), record_binding(linked[8]), 'original isolated startup')

    lowerings = report.get('PortPolicyLowerings')
    need(type(lowerings) is list and len(lowerings) == 3, 'three original port lowerings')
    port_roles = []
    for group, row in zip(PORT_GROUPS, lowerings):
        need(type(row) is dict and row.get('Group') == group and row.get('SupportedPolicy') is (group != 'stress-raw'),
             'original fixed port lower group')
        worker, dis, worker_dis = row['ActualWorker'], row['Disassembly'], row['WorkerDisassembly']
        for role, path, digest in ((group + '/Aggregate', row['Object'], row['ObjectSha256']),
                (group + '/AggregateDisassembly', dis['Path'], dis['Sha256']),
                (group + '/Machine', worker['Machine'], worker['MachineSha256']),
                (group + '/MachineDisassembly', worker_dis['Path'], worker_dis['Sha256'])):
            port_roles.append(dict(Role=role, **binding(path, digest)))
    final = report.get('PortPolicyFinalLink')
    need(type(final) is dict and type(final.get('Objects')) is list and len(final['Objects']) == 9,
         'original final port link')
    unchanged = final.get('UnchangedOtherSixObjects')
    need(type(unchanged) is list and len(unchanged) == 6, 'six original unchanged final objects')
    for index, row in zip((0, 1, 2, 6, 7, 8), unchanged):
        need(type(row) is dict and type(row.get('Index')) is int and row['Index'] == index
             and row.get('Path') == final['Objects'][index], 'literal unchanged final object role')
        record_binding(row)
    startup = unchanged[-1]
    for role, path, digest in (('Final/ELF', final['Path'], final['Sha256']),
            ('Final/Map', final['Map'], final['MapSha256']),
            ('Final/Disassembly', final['Disassembly']['Path'], final['Disassembly']['Sha256']),
            ('Final/Machine', final['ActualWorker']['Machine'], final['ActualWorker']['MachineSha256']),
            ('Final/MachineDisassembly', final['WorkerDisassembly']['Path'], final['WorkerDisassembly']['Sha256']),
            ('Final/Startup', startup['Path'], startup['Sha256'])):
        port_roles.append(dict(Role=role, **binding(path, digest)))
    port = report.get('PortPolicyDeferredReader')
    _pending(port)
    _same(port.get('Inputs'), port_roles, 'original port deferred roles versus actual lower/final records')
    for row in port_roles:
        add('PortPolicy', row['Role'], row['Path'], row['Sha256'])

    attributes = report.get('CommonAttributesDeferredReader')
    _build(attributes, 53, 98)
    need(attributes.get('DeferredReaderRequired') is True, 'common attribute reader remains deferred')
    lowers = attributes.get('Lowerings')
    need(type(lowers) is list and len(lowers) == 6, 'six original hostile lowerings')
    for group, lower in zip(COMMON_GROUPS, lowers):
        need(type(lower) is dict and lower.get('Group') == group and lower.get('ValidationDeferred') is True
             and lower.get('EffectsValidated') is False and lower.get('WorkerOptionsValidated') is False,
             'original deferred hostile lower group')
        values = lower.get('Roles')
        need(type(values) is dict and set(values) == set(COMMON_ROLES), 'complete original common role catalog')
        for role in COMMON_ROLES:
            value = record_binding(values[role])
            add('CommonAttributes', group + '/' + role, value['Path'], value['Sha256'])
    need(len(roles) == 142 and len({(row['Component'], row['Role']) for row in roles}) == 142,
         'closed 142-role handoff')
    components = {component: {key: report[key] for key in keys} for component, keys in COMPONENT_KEYS.items()}
    components['CommonAttributes'] = attributes
    pending = report.get('PendingFinalReader')
    need(type(pending) is dict and pending.get('Status') == 'PENDING'
         and pending.get('FinalReaderExecuted') is False and pending.get('OneImmutableReaderScopeRequired') is True
         and pending.get('Qualification') is False and pending.get('ImmutableInputsConsumed') is False
         and type(pending.get('RequiredCellsSatisfied')) is int and pending['RequiredCellsSatisfied'] == 0
         and type(pending.get('InputRoleCount')) is int and pending['InputRoleCount'] == 142,
         'literal pending-only handoff disposition')
    _same(pending.get('Inputs'), roles, 'complete ordered pending role projection')
    _same(pending.get('Components'), components, 'complete original component projections')
    _same(pending.get('Obligations'), list(OBLIGATIONS), 'fixed pending obligations')
    return pending


def require_pending_catalog(report):
    """Fail closed on malformed original records as well as mismatched copies."""
    try:
        return _require_pending_catalog(report)
    except (KeyError, TypeError, AttributeError) as error:
        raise Rejected('REJECT:CM3-OS-LTO-BATCH-GUARD:malformed original catalog: ' + str(error)) from error


def require_owned_output(suite):
    """Read-only root guard; call immediately before each recovery write.

    This is not an atomic open/write primitive. The caller must additionally
    restrict filenames and guard existing destination files before writing.
    """
    need(getattr(suite, '_started', None) is True, 'output session never successfully started')
    claimed = getattr(suite, 'output_identity', None)
    need(type(claimed) is tuple and len(claimed) == 2 and all(type(value) is int and value >= 0 for value in claimed),
         'claimed literal output identity required')
    output = getattr(suite, 'output', None)
    need(isinstance(output, Path) and output.is_absolute(), 'claimed absolute output path')
    try:
        info = output.lstat()
    except OSError as error:
        raise Rejected('REJECT:CM3-OS-LTO-BATCH-GUARD:owned output unavailable: ' + str(error)) from error
    need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
         and not getattr(info, 'st_file_attributes', 0) & 0x400,
         'owned output must be a non-symlink non-reparse directory')
    need((info.st_dev, info.st_ino) == claimed, 'output directory identity changed')
    return output
