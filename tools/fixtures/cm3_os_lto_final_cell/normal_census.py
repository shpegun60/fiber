"""Pure original-native Os census and selected definition-journal composition.

The caller admits metadata, manifests, helpers and parser buffers, and binds the
two zero-inclusive dump collection journals. Only caller-supplied reads and core
parsers are used here. No compilation, source-to-IR proof or cell credit follows.
"""

import copy
import hashlib
import json
import math
from pathlib import Path
import re


STATUS = 'CM3-OS-LTO-NORMAL-ORIGINAL-CENSUS-REPLAYED-NOT-QUALIFIED'
SCOPE = 'CM3_OS_LTO_ORIGINAL_NATIVE_CENSUS_AND_SELECTED_DEFINITION_JOURNALS_ONLY'
COHORT = 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default'
SOURCE = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
ROLES = ('runtime', 'boot', 'exception')
STEMS = ('fiber_port', 'fiber_port_boot', 'fiber_port_exception')
NONCLAIMS = ('Qualification', 'CellContractSatisfied', 'RequiredCellSatisfied', 'CompleteCellProof',
    'FullABIProof', 'FullSemanticABIProof', 'SourceToIRSemanticProof', 'SourceToMachineSemanticProof',
    'OriginalTranslationUnitOwnership', 'ReplacementGeneratedBodyIdentity', 'CompilationProvenanceReplayed',
    'DumpCollectionProvenanceValidated', 'FinalRootTransferProtocolsValidated', 'FinalReferenceParity',
    'ABIControlsReplayed', 'IsolationReplayed', 'CpuExecution', 'BoardExecution',
    'HostedCIQualified', 'GlobalFreezeQualified', 'CompilerExecuted')
CENSUS_NONCLAIMS = ('FullInstructionSemantics', 'SourceIRSemantics', 'OriginalTranslationUnitOwnership',
    'AttributeOnlyProtection', 'GeneralRegistersOnlyEffectProved', 'WorkerProvenanceValidated',
    'CanonicalRootProtocolsValidated', 'CPUExecution', 'BoardExecution', 'GlobalQualification')
RESULT_FIELDS = frozenset(NONCLAIMS) | frozenset(('Status', 'Scope', 'Profile', 'Mode', 'Linkage', 'LTO',
    'Cohort', 'SourceInventorySha256', 'SourceCohort', 'DefinitionSurface', 'OriginalInputs', 'DumpInputs',
    'OriginalLtrans', 'OriginalFinal', 'Twins', 'DefinitionCommands', 'SelectedSources', 'OriginalMachineRoles',
    'TwinImages', 'SelectedIRDefinitionProvenanceValidated', 'CallerOwnsDumpJournalBinding',
    'CallerOwnsAdmissionAndImmutableScope', 'RequiredCellsSatisfied', 'ReadInputs'))


class Rejected(ValueError):
    pass


def need(value, detail):
    if not value:
        raise Rejected('REJECT:CM3-OS-LTO-NORMAL-CENSUS:' + detail)


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


def _equal(left, right):
    return json.dumps(left, sort_keys=True, allow_nan=False, separators=(',', ':')) == json.dumps(
        right, sort_keys=True, allow_nan=False, separators=(',', ':'))


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result

    def constant(value):
        raise Rejected('REJECT:CM3-OS-LTO-NORMAL-CENSUS:nonfinite JSON/' + value)

    def floating(value):
        result = float(value)
        need(math.isfinite(result), 'nonfinite JSON number')
        return result

    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant,
                          parse_float=floating)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Rejected('REJECT:CM3-OS-LTO-NORMAL-CENSUS:JSON grammar') from error


def inspect(batch, native, root, core, helpers, read, dumps):
    """Recompute narrow evidence in the caller's existing immutable scope.

    read(Path, expected_sha) accepts None only for the already-admitted batch
    artifacts.json. dumps has exactly Machine/Final -> (dump Path, bytes); their
    collection journals are caller-owned and the dump files are not read here.
    """
    root = _path(root)
    need(type(helpers) is dict and set(helpers) == {'census', 'policy', 'port_runner', 'guard'}, 'explicit helpers')
    for name, functions in (('census', ('inspect_lowered', 'inspect_final')),
            ('policy', ('inspect_ir_definitions',)), ('port_runner', ('parse_ir_definitions',)), ('guard', ('_same',))):
        need(all(callable(getattr(helpers[name], method, None)) for method in functions), 'helper/' + name)
    need(callable(read) and callable(getattr(core, '_ELF', None))
         and callable(getattr(core, 'compare_load_images', None)), 'explicit immutable reader/core')

    def same(left, right, label):
        try:
            helpers['guard']._same(left, right, label)
        except ValueError as error:
            raise Rejected('REJECT:CM3-OS-LTO-NORMAL-CENSUS:' + label) from error

    for record, status in ((batch, 'BUILT-PENDING-READER'), (native, 'PASS')):
        need(type(record) is dict, 'metadata object')
        for key, expected in (('Status', status), ('Profile', 'CM3'), ('Mode', 'Os-lto'),
                              ('Linkage', 'direct'), ('LTO', True), ('Cohort', COHORT), ('SourceInventorySha256', SOURCE)):
            same(record.get(key), expected, 'actual Os metadata/' + key)
    authority = {}
    need(type(batch.get('InputHashes')) is dict and batch['InputHashes'], 'input hash authority')
    for name, digest in batch['InputHashes'].items():
        path = _path(name)
        need(path not in authority, 'ambiguous input identity')
        authority[path] = _hash(digest)
    manifest_raw = read(root / 'artifacts.json', None)
    sha(manifest_raw)
    manifest = _json(manifest_raw)
    need(type(manifest) is dict and set(manifest) == {'Artifacts'}
         and type(manifest['Artifacts']) is dict and manifest['Artifacts'], 'admitted batch manifest')
    artifacts = {}
    for name, digest in manifest['Artifacts'].items():
        need(type(name) is str and name and '\\' not in name and ':' not in name
             and not any(char in name for char in '\0\r\n') and name != 'artifacts.json'
             and all(part not in ('', '.', '..') for part in name.split('/')), 'relative artifact key')
        path = root.joinpath(*name.split('/'))
        need(path.is_relative_to(root) and path not in artifacts, 'distinct manifest path')
        artifacts[path] = _hash(digest)
        if path in authority:
            same(authority[path], artifacts[path], 'manifest/input correspondence')
    consumed = {root / 'artifacts.json': manifest_raw}

    def raw(path, expected):
        path, expected = _path(path), _hash(expected)
        registry = artifacts if path.is_relative_to(root) else authority
        same(registry.get(path), expected, 'admitted read hash/' + str(path))
        value = read(path, expected)
        need(sha(value) == expected and (path not in consumed or consumed[path] == value), 'immutable read bytes')
        consumed[path] = value
        return value

    commands = batch.get('Commands')
    need(type(commands) is list and len(commands) == 134, '134-command batch')
    same(_json(raw(root / 'commands.json', batch.get('CommandsSha256'))), commands, 'whole command journal')
    rows, sources = batch.get('PortPolicyCompilations'), native.get('Sources')
    need(type(rows) is list and len(rows) == 5 and type(sources) is list and len(sources) == 9, 'fixed compilation cohorts')
    native_root = _path(batch.get('NativeCapture', {}).get('Build'))
    need(not native_root.is_relative_to(root) and not root.is_relative_to(native_root), 'distinct native/batch roots')
    gcc = native_root / 'toolchain/bin/arm-none-eabi-gcc.exe'
    same(native.get('CapturedCompiler'), str(gcc), 'native captured compiler')
    nm = gcc.with_name('arm-none-eabi-nm.exe')
    plugin = native.get('LTOPlugin')
    need(type(plugin) is dict, 'native plugin identity')
    plugin_path = _path(plugin.get('Path'))
    same(authority.get(plugin_path), _hash(plugin.get('Sha256')), 'admitted plugin hash')
    need(nm in authority, 'admitted plugin-NM executable')
    grouped, cohort = {}, []
    for position, (role, stem, index, first, command_index) in enumerate(zip(
            ROLES, STEMS, (3, 4, 5), (99, 104, 109), (103, 108, 113))):
        row, source_row = rows[position], sources[index]
        need(type(row) is dict and type(source_row) is dict, 'typed selected provider records')
        same(row.get('Group'), 'selected', 'selected compilation group')
        same(row.get('TemplateIndex'), index, 'selected template')
        same(row.get('SupportedPolicy'), True, 'selected policy')
        same(row.get('CommandIndices'), list(range(first, command_index + 1)), 'selected compilation range')
        obj = root / 'port-policy/ir/selected' / (stem + '.o')
        same(row.get('Object'), str(obj), 'selected object path')
        object_hash = _hash(row.get('ObjectSha256'))
        raw(obj, object_hash)
        source = _path(source_row.get('Source'))
        same(row.get('Source'), str(source), 'unchanged selected source path')
        same(row.get('SourceSha256'), _hash(source_row.get('SourceSha256')), 'unchanged selected source hash')
        raw(source, row['SourceSha256'])
        original_obj = _path(source_row.get('Object'))
        need(original_obj.is_relative_to(native_root) and not source.is_relative_to(root), 'native source/object roles')
        original_hash = _hash(source_row.get('ObjectSha256'))
        raw(original_obj, original_hash)
        journal = commands[command_index]
        need(type(journal) is dict, 'definition journal record')
        same(journal.get('Label'), 'definitions selected ' + stem, 'definition label')
        same(journal.get('Argv'), [str(nm), '--plugin', str(plugin_path), '-P', '-S', '--defined-only', str(obj)],
             'definition argv')
        same(journal.get('Cwd'), str(root), 'definition working directory')
        for key, value in (('State', 'TERMINAL'), ('Status', 'PASS'), ('Exit', 0), ('ExpectedExit', 0), ('TimedOut', False)):
            same(journal.get(key), value, 'definition terminal/' + key)
        need(journal.get('Error') is None and type(journal.get('JournalErrors', [])) is list
             and journal.get('JournalErrors', []) == [] and type(journal.get('Seconds')) in (int, float)
             and math.isfinite(journal['Seconds']) and journal['Seconds'] >= 0, 'clean definition journal')
        prefix = 'commands/%03d' % command_index
        json_path = root / (prefix + '.json')
        same(_json(raw(json_path, artifacts.get(json_path))), journal, 'per-command definition journal')
        streams = []
        for field, suffix in (('Stdout', '.stdout'), ('Stderr', '.stderr')):
            same(journal.get(field), prefix + suffix, 'fixed definition stream/' + field)
            streams.append(raw(root / (prefix + suffix), journal.get(field + 'Sha256')))
        need(streams[0] and streams[1] == b'', 'complete clean plugin-NM stdout')
        try:
            definitions = helpers['port_runner'].parse_ir_definitions(streams[0])
        except (ValueError, UnicodeError) as error:
            raise Rejected('REJECT:CM3-OS-LTO-NORMAL-CENSUS:plugin-NM grammar') from error
        same(row.get('IRDefinitions'), definitions, 'stored IR definitions comparison')
        grouped[role] = definitions
        cohort.append(dict(Role=role, TemplateIndex=index, Source=str(source), SourceSha256=row['SourceSha256'],
            NativeObject=str(original_obj), NativeObjectSha256=original_hash, SelectedObject=str(obj),
            SelectedObjectSha256=object_hash, DefinitionCommandIndex=command_index,
            DefinitionStdoutSha256=sha(streams[0]), Definitions=copy.deepcopy(definitions)))
    try:
        surface = helpers['policy'].inspect_ir_definitions(grouped)
    except ValueError as error:
        raise Rejected('REJECT:CM3-OS-LTO-NORMAL-CENSUS:definition surface') from error
    same(batch.get('PortPolicyIRDefinitionSurface'), surface, 'stored definition surface comparison')

    links = native.get('Links')
    need(type(links) is list and len(links) == 2 and all(type(row) is dict for row in links), 'two native original links')
    same([row.get('Kind') for row in links], ['ordinary', 'emit-relocs'], 'native original twin order')
    inputs = {}
    for row in links:
        final = native_root / row['Kind'] / 'image.elf'
        machine = Path(str(final) + '.ltrans0.ltrans.o')
        same(row.get('Path'), str(final), 'original native final path')
        same(row.get('Machine'), str(machine), 'original native worker path')
        raw(final, row.get('Sha256'))
        if row['Kind'] == 'emit-relocs':
            raw(machine, row.get('MachineSha256'))
            inputs['OriginalLtrans'] = dict(Path=str(machine), Sha256=row['MachineSha256'])
            inputs['OriginalFinal'] = dict(Path=str(final), Sha256=row['Sha256'])
        else:
            inputs['OrdinaryFinal'] = dict(Path=str(final), Sha256=row['Sha256'])
    need(type(dumps) is dict and set(dumps) == {'Machine', 'Final'}, 'two caller-bound dump pairs')
    dump_inputs, dump_bytes = {}, {}
    for role in ('Machine', 'Final'):
        pair = dumps[role]
        need(type(pair) in (tuple, list) and len(pair) == 2 and isinstance(pair[0], Path)
             and type(pair[1]) is bytes and pair[1], 'literal dump pair/' + role)
        path = _path(pair[0])
        need(path not in consumed and all(str(path) != row['Path'] for row in inputs.values()), 'distinct dump file role')
        dump_inputs[role] = dict(Path=str(path), Sha256=sha(pair[1]))
        dump_bytes[role] = pair[1]
    need(dump_inputs['Machine']['Path'] != dump_inputs['Final']['Path'], 'distinct dump files')
    proofs = {}
    for role, dump_role, final in (('OriginalLtrans', 'Machine', False), ('OriginalFinal', 'Final', True)):
        path = Path(inputs[role]['Path'])
        image = core._ELF(path, 'ET_EXEC' if final else 'ET_REL')
        need(image.data == consumed[path] and image.final is final, 'parser consumes exact original bytes/' + role)
        try:
            proofs[role] = (helpers['census'].inspect_final(image, core, dump_bytes[dump_role], surface, helpers['policy'])
                if final else helpers['census'].inspect_lowered(image, core, dump_bytes[dump_role], surface,
                                                              helpers['policy'], whole_image=True))
        except ValueError as error:
            raise Rejected('REJECT:CM3-OS-LTO-NORMAL-CENSUS:original census/' + role) from error
    twins = core.compare_load_images(Path(inputs['OrdinaryFinal']['Path']), Path(inputs['OriginalFinal']['Path']))
    same(twins, native.get('TwinLoadImages'), 'stored native twins comparison')
    result = dict(Status=STATUS, Scope=SCOPE, Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True,
        Cohort=COHORT, SourceInventorySha256=SOURCE, SourceCohort=cohort, DefinitionSurface=copy.deepcopy(surface),
        OriginalInputs=inputs, DumpInputs=dump_inputs, OriginalLtrans=copy.deepcopy(proofs['OriginalLtrans']),
        OriginalFinal=copy.deepcopy(proofs['OriginalFinal']), Twins=copy.deepcopy(twins),
        DefinitionCommands=3, SelectedSources=3, OriginalMachineRoles=2, TwinImages=2,
        SelectedIRDefinitionProvenanceValidated=True, CallerOwnsDumpJournalBinding=True,
        CallerOwnsAdmissionAndImmutableScope=True, RequiredCellsSatisfied=0,
        ReadInputs=[dict(Path=str(path), Sha256=sha(value)) for path, value in sorted(consumed.items())],
        **dict.fromkeys(NONCLAIMS, False))
    return require_result(result)


def require_result(proof):
    """Strict bounded result checks, not an alternative to actual recomputation."""
    need(type(proof) is dict, 'result object')
    need(set(proof) == RESULT_FIELDS, 'closed bounded result schema')
    for key, value in (('Status', STATUS), ('Scope', SCOPE), ('Profile', 'CM3'), ('Mode', 'Os-lto'),
                       ('Linkage', 'direct'), ('Cohort', COHORT), ('SourceInventorySha256', SOURCE)):
        need(type(proof.get(key)) is str and proof[key] == value, 'result identity/' + key)
    for key, value in (('DefinitionCommands', 3), ('SelectedSources', 3), ('OriginalMachineRoles', 2),
                       ('TwinImages', 2), ('RequiredCellsSatisfied', 0)):
        need(type(proof.get(key)) is int and proof[key] == value, 'result literal count/' + key)
    for key in ('LTO', 'SelectedIRDefinitionProvenanceValidated', 'CallerOwnsDumpJournalBinding', 'CallerOwnsAdmissionAndImmutableScope'):
        need(proof.get(key) is True, 'result fact/' + key)
    for key in NONCLAIMS:
        need(proof.get(key) is False, 'result nonclaim/' + key)
    cohort, surface = proof.get('SourceCohort'), proof.get('DefinitionSurface')
    need(type(cohort) is list and len(cohort) == 3 and type(surface) is dict, 'result source/surface records')
    need(surface.get('IRDefinitionsValidated') is True and surface.get('OriginalTranslationUnitMachineOwnership') is False,
         'bounded definition surface')
    need(type(surface.get('PublicFunctions')) is int and surface['PublicFunctions'] == 29
         and type(surface.get('CohortObjects')) is int and surface['CohortObjects'] == 2, 'definition surface counts')
    definitions = []
    for row, role, index, command_index, count in zip(cohort, ROLES, (3, 4, 5), (103, 108, 113), (15, 14, 2)):
        need(type(row) is dict and row.get('Role') == role and type(row.get('TemplateIndex')) is int
             and row['TemplateIndex'] == index and type(row.get('DefinitionCommandIndex')) is int
             and row['DefinitionCommandIndex'] == command_index, 'typed source cohort selectors')
        for field in ('Source', 'NativeObject', 'SelectedObject'):
            _path(row.get(field)); _hash(row.get(field + 'Sha256'))
        _hash(row.get('DefinitionStdoutSha256'))
        rows = row.get('Definitions')
        need(type(rows) is list and len(rows) == count, 'definition cohort size')
        for item in rows:
            need(type(item) is dict and set(item) == {'Name', 'Kind', 'Value', 'Size'}
                 and type(item['Name']) is str and item['Name'] and item['Kind'] in ('T', 'D', 'W')
                 and type(item['Value']) is int and item['Value'] == 0 and item['Size'] is None, 'typed raw definition')
            definitions.append(dict(Role=role, **item))
    need(len({row['Name'] for row in definitions}) == 31 and _equal(surface.get('Definitions'), definitions),
         'complete definition surface correspondence')
    source_paths = [row[field] for row in cohort for field in ('Source', 'NativeObject', 'SelectedObject')]
    need(len(set(map(_path, source_paths))) == 9, 'distinct selected/native/source cohort paths')
    inputs, dumps = proof.get('OriginalInputs'), proof.get('DumpInputs')
    need(type(inputs) is dict and set(inputs) == {'OriginalLtrans', 'OriginalFinal', 'OrdinaryFinal'}
         and type(dumps) is dict and set(dumps) == {'Machine', 'Final'}, 'result input roles')
    for row in (*inputs.values(), *dumps.values()):
        need(type(row) is dict and set(row) == {'Path', 'Sha256'}, 'typed input binding')
        _path(row['Path']); _hash(row['Sha256'])
    need(len({row['Path'] for row in (*inputs.values(), *dumps.values())}) == 5, 'distinct result input paths')
    final_path = Path(inputs['OriginalFinal']['Path'])
    need(final_path.name == 'image.elf' and final_path.parent.name == 'emit-relocs'
         and inputs['OriginalLtrans']['Path'] == str(final_path) + '.ltrans0.ltrans.o'
         and inputs['OrdinaryFinal']['Path'] == str(final_path.parent.parent / 'ordinary/image.elf'), 'own original twin paths')
    for role, dump_role, final in (('OriginalLtrans', 'Machine', False), ('OriginalFinal', 'Final', True)):
        census = proof.get(role)
        need(type(census) is dict and census.get('Status') == 'CM3-OS-LTO-PORT-CENSUS-PASS'
             and census.get('Scope') == 'CM3_OS_LTO_PORT_MACHINE_CENSUS_ONLY'
             and census.get('Profile') == 'CM3' and census.get('Mode') == 'Os-lto'
             and census.get('FinalELF') is final, 'result original census identity/' + role)
        need(census.get('ObjectSha256') == inputs[role]['Sha256'] and census.get('DisassemblySha256') == dumps[dump_role]['Sha256']
             and _equal(census.get('DefinitionSurface'), surface), 'result census byte/surface binding')
        for key in ('CompleteExecutableCensus', 'ForbiddenDependenciesAbsent', 'RecognizedForbiddenFormsAbsent'):
            need(census.get(key) is True, 'census required fact/' + key)
        for key in CENSUS_NONCLAIMS:
            need(census.get(key) is False, 'census nonclaim/' + key)
        need(type(census.get('RequiredCellsSatisfied')) is int and census['RequiredCellsSatisfied'] == 0, 'census zero credit')
        functions = census.get('FunctionEvidence')
        need(type(census.get('FunctionsAudited')) is int and census['FunctionsAudited'] > 0
             and type(functions) is list and len(functions) == census['FunctionsAudited'], 'complete census function count')
        names = []
        for function in functions:
            need(type(function) is dict and type(function.get('Name')) is str and function['Name']
                 and type(function.get('Instructions')) is int and function['Instructions'] > 0
                 and type(function.get('DataBytes')) is int and function['DataBytes'] >= 0, 'typed census function evidence')
            _hash(function.get('BodySha256'))
            names.append(function['Name'])
        need(len(names) == len(set(names)) and type(census.get('DefinitionsFromIR')) is list
             and len(census['DefinitionsFromIR']) == 31, 'complete distinct census providers')
        need(type(census.get('ExecutableInstructionBytes')) is int and census['ExecutableInstructionBytes'] > 0
             and type(census.get('ExecutableMappedDataBytes')) is int and census['ExecutableMappedDataBytes'] >= 0, 'typed census byte counts')
        expected = [] if final else sorted(('__pilot_ram_begin', '__pilot_ram_end', '__pilot_text_begin', '__pilot_text_end'))
        need(_equal(census.get('Undefined'), expected), 'original census undefined surface')
    twins = proof.get('Twins')
    need(type(twins) is dict and twins.get('Identical') is True and type(twins.get('Segments')) is list and twins['Segments'], 'original load twins')
    need(type(twins.get('Entry')) is int and twins['Entry'] > 0 and type(twins.get('VectorAddress')) is int
         and twins['VectorAddress'] >= 0 and type(twins.get('VectorBytes')) is str
         and re.fullmatch('[0-9a-f]{2048}', twins['VectorBytes']) is not None, 'typed original twin vector')
    for segment in twins['Segments']:
        need(type(segment) is dict and all(type(segment.get(key)) is int and segment[key] >= 0
             for key in ('Vaddr', 'FileSize', 'MemorySize', 'Flags')), 'typed twin load segment')
        _hash(segment.get('BytesSha256'))
    vector = proof['OriginalFinal'].get('FinalRootVectorBindings')
    need(type(vector) is dict and type(vector.get('Words')) is int and vector['Words'] == 256
         and vector.get('AllocatedFileBackedLoadValidated') is True and vector.get('CanonicalRootProtocolsValidated') is False
         and type(vector.get('Entry')) is int and vector['Entry'] == twins['Entry']
         and all(type(vector.get(key)) is int and vector[key] > 0 for key in ('SVC', 'PendSV'))
         and vector.get('VectorSha256') == sha(bytes.fromhex(twins['VectorBytes'])), 'bounded final vector/twin correspondence')
    reads = proof.get('ReadInputs')
    need(type(reads) is list and len(reads) == 23, 'twenty-three immutable read records')
    paths = []
    for row in reads:
        need(type(row) is dict and set(row) == {'Path', 'Sha256'}, 'typed immutable read record')
        paths.append(_path(row['Path'])); _hash(row['Sha256'])
    need(len(paths) == len(set(paths)), 'unique immutable read paths')
    read_map = {Path(row['Path']): row['Sha256'] for row in reads}
    batch_root = Path(cohort[0]['SelectedObject']).parents[3]
    expected_paths = {batch_root / 'artifacts.json', batch_root / 'commands.json'}
    for row, stem in zip(cohort, STEMS):
        need(row['SelectedObject'] == str(batch_root / 'port-policy/ir/selected' / (stem + '.o')), 'fixed selected result object')
        for field in ('Source', 'NativeObject', 'SelectedObject'):
            path = Path(row[field]); expected_paths.add(path)
            need(read_map.get(path) == row[field + 'Sha256'], 'cohort/read hash correspondence')
        for suffix in ('.json', '.stdout', '.stderr'):
            expected_paths.add(batch_root / ('commands/%03d%s' % (row['DefinitionCommandIndex'], suffix)))
        need(read_map.get(batch_root / ('commands/%03d.stdout' % row['DefinitionCommandIndex'])) == row['DefinitionStdoutSha256'],
             'definition stdout/read correspondence')
    for row in inputs.values():
        path = Path(row['Path']); expected_paths.add(path)
        need(read_map.get(path) == row['Sha256'], 'original/read hash correspondence')
    need(set(paths) == expected_paths and not any(Path(row['Path']) in read_map for row in dumps.values()), 'closed read cohort')
    return proof
