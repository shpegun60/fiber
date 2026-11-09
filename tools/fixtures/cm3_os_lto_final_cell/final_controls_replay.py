"""Pure final/reference buffer controls; no capture, filesystem or qualification."""

from contextlib import contextmanager
import copy
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import struct
from unittest.mock import patch


STATUS = 'CM3-OS-LTO-FINAL-CONTROLS-REPLAYED-NOT-QUALIFIED'
SCOPE = 'CM3_OS_LTO_SELECTED_FINAL_AND_REFERENCE_34_BUFFER_CONTROLS_ONLY'
COHORT = 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default'
BASE_HELPERS = ('abi', 'link_helpers', 'binding_helpers', 'native_roots', 'reference_roots',
    'native_protocol', 'reference_protocol', 'decoder', 'checker', 'os_join', 'join', 'guard',
    'original_replay', 'port_replay')
HELPERS = frozenset((*BASE_HELPERS, 'final_replacement_replay', 'native_mutations', 'reference_mutations'))
ROLES = ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup', 'MachineDisassembly')
SIDES = ('Native', 'Reference')
ROOTS = dict(Native=('fiber_port_start_first_context', 'SVC_Handler', 'PendSV_Handler'),
             Reference=('prvPortStartFirstTask', 'vPortSVCHandler', 'xPortPendSVHandler'))
NATIVE_CASES = (
    ('machine-nonrelocation-byte', 'LTO-PRESERVATION'), ('machine-bl-addend', 'LTO-RELOC'),
    ('machine-slot-addend', 'LTO-SLOT'), ('applied-slot-word', 'LTO-SLOT'),
    ('coherent-slot-in-bss', 'LTO-(ORIGIN|SYMBOL)'), ('globalized-slot', 'LTO-SYMBOL'),
    ('wrong-slot-section-target', 'LTO-SLOT'), ('function-alias', 'LTO-SYMBOL'),
    ('slot-object-alias', 'LTO-SYMBOL'), ('code-without-execute', 'LTO-SYMBOL'),
    ('callee-data-mapping', 'LTO-SYMBOL'), ('coherent-callee-entry', 'LTO-ORIGIN'),
    ('wrong-machine-section-size', '(LTO-)?ORIGIN'), ('foreign-map-provider', '(LTO-)?ORIGIN'),
    ('missing-root-reference', 'LTO-RELOC'), ('extra-root-reference', 'LTO-RELOC'))
REFERENCE_CASES = (
    ('machine-nonrelocation-byte', 'REF-LTO-PRESERVATION'), ('machine-bl-addend', 'REF-LTO-RELOC'),
    ('machine-slot-addend', 'REF-LTO-SLOT'), ('applied-slot-word', 'REF-LTO-SLOT'),
    ('coherent-slot-in-bss', 'REF-LTO-ORIGIN'), ('localized-slot', 'REF-LTO-SYMBOL'),
    ('wrong-slot-named-target', 'REF-LTO-RELOC'), ('function-alias', 'REF-LTO-SYMBOL'),
    ('slot-object-alias', 'REF-LTO-SYMBOL'), ('code-without-execute', 'REF-LTO-SYMBOL'),
    ('callee-data-mapping', 'REF-LTO-SYMBOL'), ('coherent-callee-entry', 'REF-LTO-ORIGIN'),
    ('wrong-machine-section-size', 'REF-LTO-ORIGIN'), ('foreign-map-provider', 'REF-LTO-ORIGIN'),
    ('missing-root-reference', 'REF-LTO-RELOC'), ('extra-root-reference', 'REF-LTO-RELOC'))
CASES = dict(Native=NATIVE_CASES, Reference=REFERENCE_CASES)
NONCLAIMS = ('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof',
    'FullInstructionSemantics', 'SourceIRProof', 'SourceToIRSemanticProof', 'SourceToMachineSemanticProof',
    'OriginalTranslationUnitOwnership', 'OrdinaryRootPreservationProven', 'HandlerRoutingProven',
    'FinalReferenceParity', 'InstructionEquivalence', 'PolicyEquivalence', 'ArbitraryCallbackSafetyProven',
    'AllProducerMutantsReexecuted', 'ProducerCompilersReexecuted', 'UnchangedOtherSixGeneratedBodies',
    'CompleteCellProof', 'WholeCellProof', 'RequiredCellSatisfied', 'CellContractSatisfied',
    'ArchiveQualification', 'HostedCIQualified', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified')
FIELDS = frozenset(('Status', 'Scope', 'Profile', 'Mode', 'Linkage', 'LTO', 'Cohort', 'SourceInventorySha256',
    'BatchRoot', 'BatchAuthority', 'PortProofSha256', 'OriginalProofSha256', 'FinalProofSha256', 'Inputs',
    'LedgerBytes', 'Baseline', 'Controls', 'DerivedBuffers', 'ReadInputs', 'LogicalRoles', 'ReadFiles',
    'DerivedRoleInstances', 'TransportControlsExecuted', 'CanonicalControlsExecuted', 'FreshControlsExecuted',
    'ImmutableInputsConsumed', 'ToolInvocations', 'CompilerInvocations', 'RequiredCellsSatisfied', 'Nonclaims'))


class Rejected(ValueError):
    pass


def need(condition, label):
    if not condition:
        raise Rejected('REJECT:CM3-OS-LTO-FINAL-CONTROLS:' + label)


def sha(raw):
    need(type(raw) is bytes, 'literal immutable bytes')
    return hashlib.sha256(raw).hexdigest().upper()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def _hex(value, empty=False):
    need(type(value) is str and re.fullmatch('(?:[0-9a-f]{2})' + ('*' if empty else '+'), value) is not None,
         'lowercase byte hex')
    return bytes.fromhex(value)


def _helpers(helpers):
    need(type(helpers) is dict and set(helpers) == HELPERS, 'exact seventeen helpers')
    base = {name: helpers[name] for name in BASE_HELPERS}
    original, final = helpers['original_replay'], helpers['final_replacement_replay']
    need(all(callable(getattr(final, name, None)) for name in ('require_result', '_helpers'))
         and callable(getattr(original, '_helpers', None)), 'published pure helper API')
    admitted_original, original_helpers = final._helpers(base)
    need(admitted_original is original, 'same original helper instance')
    original._helpers(original_helpers)
    original._same(getattr(final, 'NONCLAIMS', None), tuple('MutantsReexecuted' if name == 'AllProducerMutantsReexecuted'
        else name for name in NONCLAIMS), 'independent final nonclaim catalog')
    for side, alias in (('Native', 'native_mutations'), ('Reference', 'reference_mutations')):
        helper = helpers[alias]
        original._same(getattr(helper, 'CASES', None), CASES[side], 'frozen control catalog/' + side)
        names = ('_symbol', '_address_offset', '_relocation_offset', 'encode_bl') + (
            ('_symbol_file_offset',) if side == 'Native' else ('_symbol_offset', '_dis_line', '_dis_record'))
        need(all(callable(getattr(helper, name, None)) for name in names), 'pure recipe helper APIs/' + side)
    return original, final, base


def _components(batch, port, original, final, helpers):
    module, published, base = _helpers(helpers)
    published.require_result(final, batch, port, original, base)
    module._same(final['Cohort'], COHORT, 'fixed current cohort')
    return module, published, base


def _inputs(final, module):
    inputs = {name: copy.deepcopy(final['Inputs'][name]) for name in ('Final', 'Reference', 'Ledgers')}
    paths, identities = {}, set()
    for group, names in (('Final', ROLES), ('Reference', ROLES), ('Ledgers', ('Master', 'Policy'))):
        module._keys(inputs[group], names, 'control input group/' + group)
        for name in names:
            row = inputs[group][name]
            module._keys(row, ('Path', 'Sha256'), 'control input binding')
            path = module._path(row['Path'])
            module._same(row['Path'], str(path), 'canonical input path')
            need(type(row['Sha256']) is str and re.fullmatch('[A-F0-9]{64}', row['Sha256']), 'uppercase input hash')
            identity = PureWindowsPath(str(path)).as_posix().casefold()
            need(identity not in identities, 'fourteen nonaliased input paths')
            identities.add(identity); paths[path] = row['Sha256']
    need(len(paths) == 14, 'fourteen positive paths')
    sizes = {module._path(row['Path']): row['Bytes'] for row in final['ReadInputs']}
    return inputs, paths, {path: sizes[path] for path in paths}


@contextmanager
def _facade(buffers, module):
    frozen = dict(buffers)
    need(all(type(raw) is bytes for raw in frozen.values()), 'frozen facade bytes')

    def read(path):
        path = module._path(path)
        need(path in frozen, 'read outside current control buffers/' + str(path))
        return frozen[path]

    def text(path, encoding=None, errors=None, newline=None):
        need(encoding in (None, 'ascii', 'utf-8') and errors in (None, 'strict') and newline is None,
             'strict buffered text')
        return read(path).decode(encoding or 'utf-8')

    with patch.object(Path, 'read_bytes', read), patch.object(Path, 'read_text', text):
        yield
    need(buffers == frozen, 'buffer membership and bytes close')


def _transport(core, side, paths, helpers):
    adapter = helpers['native_roots' if side == 'Native' else 'reference_roots']
    factory = adapter.NativeCM3LTOImage if side == 'Native' else adapter.ReferenceCM3LTOImage
    return factory(core, paths['Machine'], paths['Final'], paths['Disassembly'],
        provider_objects={str(paths['Machine']): paths['Machine'], str(paths['Startup']): paths['Startup']},
        link_map=paths['LinkMap'])


def _view(core, side, paths, transport, helpers):
    decoded = helpers['decoder'].Object(paths['Machine'], paths['MachineDisassembly'])
    module = helpers['native_protocol' if side == 'Native' else 'reference_protocol']
    return (module.NativeProtocolView if side == 'Native' else module.ReferenceProtocolView)(decoded, transport)


def _baseline(core, inputs, buffers, final, helpers, module):
    images, views = {}, {}
    with _facade(buffers, module):
        for side, group in (('Native', 'Final'), ('Reference', 'Reference')):
            paths = {name: module._path(row['Path']) for name, row in inputs[group].items()}
            images[side] = _transport(core, side, paths, helpers)
            views[side] = _view(core, side, paths, images[side], helpers)
        joined = helpers['os_join'].check_join(views['Native'], views['Reference'], helpers['checker'],
            buffers[module._path(inputs['Ledgers']['Master']['Path'])].decode('ascii'), helpers['join'])
        joined = module._json_value(joined)
        rationales = helpers['join'].require_ledger(
            buffers[module._path(inputs['Ledgers']['Policy']['Path'])].decode('ascii'), joined['ProtocolProof'])
    baseline = dict(TransportRoots=joined['RawTransportRoots'], CanonicalJoin=joined, PolicyDifferenceRationales=rationales)
    module._same(baseline, {key: final[key] for key in baseline}, 'fresh complete control baseline')
    return baseline, images


def _edit_buffer(buffers, edits, role, offset, after, length=None):
    need(role in buffers and type(offset) is int and offset >= 0 and type(after) is bytes, 'bounded recipe edit arguments')
    before = buffers[role]; length = len(after) if length is None else length
    need(type(length) is int and length >= 0 and offset + length <= len(before), 'bounded recipe edit extent')
    old = before[offset:offset + length]
    need(old != after, 'nonempty actual recipe edit')
    buffers[role] = before[:offset] + after + before[offset + length:]
    edits[role].append(dict(FileOffset=offset, Before=old.hex(), After=after.hex()))


def _field(raw, offset, form):
    size = struct.calcsize(form)
    need(type(offset) is int and 0 <= offset <= len(raw) - size, 'bounded ELF32 field')
    return struct.unpack_from(form, raw, offset)


def _elf_fields(raw):
    """Read bounded ELF32 fields, not a transport/decoder or semantic audit."""
    header = _field(raw, 0, '<16sHHIIIIIHHHHHH')
    need(header[0][:7] == b'\x7fELF\x01\x01\x01' and header[1] in (1, 2) and header[2] == 40
         and header[3] == 1 and header[8] == 52 and header[11] == 40 and header[12] > 0,
         'bounded little-endian ARM ELF32 header')
    start, count = header[6], header[12]
    need(start <= len(raw) and count <= (len(raw) - start) // 40, 'bounded ELF32 section table')
    sections = [_field(raw, start + i * 40, '<IIIIIIIIII') for i in range(count)]
    tables = [row for row in sections if row[1] == 2]
    need(len(tables) == 1, 'one bounded ELF32 symbol table')
    table = tables[0]
    need(table[9] == 16 and table[5] % 16 == 0 and table[4] <= len(raw) - table[5]
         and table[6] < count and sections[table[6]][1] == 3, 'bounded ELF32 symbols/string table')
    strings = sections[table[6]]
    need(strings[4] <= len(raw) - strings[5], 'bounded ELF32 string bytes')
    names = raw[strings[4]:strings[4] + strings[5]]
    symbols = []
    for index in range(table[5] // 16):
        offset = table[4] + index * 16
        name, value, size, info, other, section = _field(raw, offset, '<IIIBBH')
        need(name < len(names), 'bounded symbol name')
        end = names.find(b'\0', name)
        need(end >= name, 'terminated symbol name')
        symbols.append(dict(Name=names[name:end].decode('ascii'), Index=index, Value=value, Size=size, Info=info,
            Other=other, Section=section, FileOffset=offset))
    return header[1], sections, symbols


def _symbol_fields(raw, name):
    kind, sections, symbols = _elf_fields(raw)
    rows = [row for row in symbols if row['Name'] == name and row['Section'] != 0]
    need(len(rows) == 1 and 0 < rows[0]['Section'] < len(sections), 'unique bounded symbol/' + name)
    symbol = rows[0]
    return kind, sections, symbols, symbol


def _body(raw, name):
    kind, sections, _, symbol = _symbol_fields(raw, name)
    section = sections[symbol['Section']]
    start = (symbol['Value'] & ~1) - (section[3] if kind == 2 else 0)
    need(symbol['Info'] & 15 == 2 and symbol['Value'] & 1 and symbol['Size'] > 0
         and section[1] != 8 and 0 <= start <= section[5] - symbol['Size'], 'bounded Thumb body/' + name)
    offset = section[4] + start
    need(offset <= len(raw) - symbol['Size'], 'file-backed bounded body/' + name)
    return raw[offset:offset + symbol['Size']], offset, symbol


def _definition(baseline, side, root, name):
    row = next(row for row in baseline['TransportRoots'][side] if row['Name'] == root)
    definitions = [definition for definition in row['DefinitionOrigins'] if definition['Name'] == name]
    need(len(definitions) == 1, 'one baseline definition/' + name)
    return definitions[0]


def _relocation_fields(raw, section):
    _, sections, _ = _elf_fields(raw)
    rows = []
    for table in sections:
        if table[1] == 9 and table[7] == section:
            need(table[9] == 8 and table[5] % 8 == 0 and table[4] <= len(raw) - table[5], 'bounded ELF32 REL entries')
            for index in range(table[5] // 8):
                offset = table[4] + index * 8
                address, info = _field(raw, offset, '<II')
                rows.append((offset, address, info))
    return rows


def _relocation_field(raw, section, address):
    rows = [row for row in _relocation_fields(raw, section) if row[1] == address]
    need(len(rows) == 1, 'one actual bounded REL field')
    return rows[0][0]


def _section_offset(sections, index, address, final=False, length=4):
    need(type(index) is int and 0 < index < len(sections), 'bounded actual section index')
    section = sections[index]; relative = address - (section[3] if final else 0)
    need(section[1] != 8 and 0 <= relative <= section[5] - length, 'bounded file-backed section coordinate')
    return section[4] + relative


def _transport_expected(side, name, paths, before, after, baseline, helpers, module):
    if name in ('coherent-slot-in-bss', 'coherent-callee-entry'):
        return _coherence_expected(side, name, before, after, baseline, helpers, module)
    reference = side == 'Reference'
    slot_name = 'pxCurrentTCB' if reference else 'fiber_internal_runtime_current_context_slot'
    _, machine_sections, machine_symbols, svc = _symbol_fields(before['Machine'], ROOTS[side][1])
    _, final_sections, final_symbols, final_svc = _symbol_fields(before['Final'], ROOTS[side][1])
    _, _, _, slot = _symbol_fields(before['Final'], slot_name)
    expected, edits = dict(before), {role: [] for role in before}

    def edit(role, offset, data, length=None):
        _edit_buffer(expected, edits, role, offset, data, length)

    if name == 'machine-nonrelocation-byte':
        offset = _section_offset(machine_sections, svc['Section'], 0x54 if reference else 0, length=1)
        edit('Machine', offset, bytes([before['Machine'][offset] ^ 1]))
    elif name == 'machine-bl-addend':
        if reference:
            _, _, _, pend = _symbol_fields(before['Machine'], ROOTS[side][2])
            edit('Machine', _section_offset(machine_sections, pend['Section'], 0xB4),
                helpers['reference_mutations'].encode_bl(0xB4, 0xB8))
        else:
            edit('Machine', _section_offset(machine_sections, svc['Section'], 0x72), bytes.fromhex('fff7ffff'))
    elif name == 'machine-slot-addend':
        edit('Machine', _section_offset(machine_sections, svc['Section'], 0x74 if reference else 0xB4), struct.pack('<I', 4))
    elif name == 'applied-slot-word':
        _, offset, _ = _body(before['Final'], ROOTS[side][1])
        need(slot['Value'] >= 4, 'nonwrapping applied slot target')
        edit('Final', offset + (32 if reference else 0xB4), struct.pack('<I', slot['Value'] - 4))
    elif name in ('globalized-slot', 'localized-slot'):
        edit('Final', slot['FileOffset'] + 12, b'\x01' if reference else b'\x11')
    elif name in ('wrong-slot-section-target', 'wrong-slot-named-target'):
        if reference:
            _, _, _, wrong = _symbol_fields(before['Final'], 'reference_failure_code')
        else:
            wrongs = [row for row in final_symbols if row['Info'] & 15 == 3 and row['Section'] == final_svc['Section']]
            need(bool(wrongs), 'actual root section-symbol target'); wrong = wrongs[0]
        place = (final_svc['Value'] & ~1) + (32 if reference else 0xB4)
        edit('Final', _relocation_field(before['Final'], final_svc['Section'], place) + 4,
             struct.pack('<I', wrong['Index'] << 8 | 2))
    elif name in ('function-alias', 'slot-object-alias'):
        slot_case = name == 'slot-object-alias'
        _, _, _, target = _symbol_fields(before['Machine'], slot_name) if slot_case else (None, None, None, svc)
        if reference:
            _, _, _, alias = _symbol_fields(before['Machine'], 'reference_failure_code' if slot_case else 'reference_reset_forbidden')
            need(alias['Info'] & 15 == target['Info'] & 15, 'matching actual alias kind')
        else:
            adapter = helpers['native_roots']
            names = {*adapter.ROOTS, *adapter.CALLEES, adapter.SLOT}
            aliases = [row for row in machine_symbols if row['Name'] not in names
                and row['Info'] & 15 == target['Info'] & 15 and 0 < row['Section'] < len(machine_sections) and row['Size'] > 0]
            need(bool(aliases), 'actual non-root alias source'); alias = aliases[0]
        if reference or (alias['Value'], alias['Size']) != (target['Value'], 4):
            edit('Machine', alias['FileOffset'] + 4, struct.pack('<II', target['Value'], 4))
        if alias['Section'] != target['Section']:
            edit('Machine', alias['FileOffset'] + 14, struct.pack('<H', target['Section']))
    elif name == 'code-without-execute':
        header = _field(before['Final'], 0, '<16sHHIIIIIHHHHHH')
        need(header[9] == 32 and header[5] <= len(before['Final']) and
             header[10] <= (len(before['Final']) - header[5]) // 32, 'bounded ELF32 program headers')
        address, loads = final_svc['Value'] & ~1, []
        for index in range(header[10]):
            offset = header[5] + index * 32; segment = _field(before['Final'], offset, '<IIIIIIII')
            if segment[0] == 1 and segment[2] <= address < segment[2] + segment[5]: loads.append((offset, segment))
        need(len(loads) == 1 and loads[0][1][6] & 1, 'one actual executable load')
        edit('Final', loads[0][0] + 24, struct.pack('<I', loads[0][1][6] & ~1))
    elif name == 'callee-data-mapping':
        _, _, _, callee = _symbol_fields(before['Machine'], 'vTaskSwitchContext' if reference else 'fiber_panic')
        mappings = [row for row in machine_symbols if row['Name'].split('.')[0] == '$t'
            and row['Section'] == callee['Section'] and
            (row['Value'] == callee['Value'] & ~1 if reference else row['Value'] <= callee['Value'] & ~1)]
        need(len(mappings) == 1 if reference else bool(mappings), 'actual callee code mapping')
        mapping = mappings[0] if reference else max(mappings, key=lambda row: row['Value'])
        table = next(row for row in machine_sections if row[1] == 2)
        strings = machine_sections[table[6]]
        position = before['Machine'][strings[4]:strings[4] + strings[5]].find(b'\0$d\0')
        need(position >= 0, 'existing data-mapping string')
        edit('Machine', mapping['FileOffset'], struct.pack('<I', position + 1))
    elif name in ('wrong-machine-section-size', 'foreign-map-provider'):
        raw = before['LinkMap']; text = raw.decode('utf-8')
        if not reference and name == 'foreign-map-provider':
            changed = raw.replace(str(paths['Machine']).encode('utf-8'), b'C:/unbound-lto-machine.o')
        else:
            pattern = r'(?m)^\s+\.text\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(' + re.escape(str(paths['Machine'])) + r')\s*$'
            rows = list(re.finditer(pattern, text)); need(len(rows) == 1, 'one complete machine map placement')
            row = rows[0]; group = 2 if name == 'wrong-machine-section-size' else 3
            replacement = hex(int(row[2], 16) - 2) if group == 2 else 'C:/unbound-reference-lto-machine.o'
            changed = (text[:row.start(group)] + replacement + text[row.end(group):]).encode('utf-8')
        edit('LinkMap', 0, changed, len(raw))
    elif name in ('missing-root-reference', 'extra-root-reference'):
        if reference:
            address, target = (0xB4, 0xDC) if name == 'missing-root-reference' else (0x20, 0x7C)
        elif name == 'missing-root-reference':
            address, target = 0x72, 0xB8
        else:
            addresses = [row[1] for row in _relocation_fields(before['Machine'], svc['Section']) if 0x184 <= row[1] < 0x41C]
            need(bool(addresses), 'actual extra-root relocation source'); address, target = min(addresses), 2
        edit('Machine', _relocation_field(before['Machine'], svc['Section'], address), struct.pack('<I', target))
    else:
        raise Rejected('unknown fixed transport recipe/' + side + '/' + name)
    module._same(after, expected, 'complete exact transport recipe bytes/' + side + '/' + name)
    return None


def _changed_roles(side, name):
    if name == 'coherent-svc-immediate':
        return {'Machine', 'Final', 'Disassembly', 'MachineDisassembly'}
    if name in ('coherent-slot-in-bss', 'coherent-callee-entry'):
        return {'Final', 'Disassembly'} if side == 'Reference' else {'Final'}
    if name in ('wrong-machine-section-size', 'foreign-map-provider'):
        return {'LinkMap'}
    if name in ('applied-slot-word', 'globalized-slot', 'localized-slot', 'wrong-slot-section-target',
                'wrong-slot-named-target', 'code-without-execute'):
        return {'Final'}
    return {'Machine'}


def _dump_edit(helper, raw, section, address, data, slot, callee=None, target=None):
    offset, length, line = helper._dis_line(raw, section, address)
    end = '\r\n' if line.endswith('\r\n') else '\n' if line.endswith('\n') else ''
    if target is None:
        word = struct.unpack('<I', data)[0]
        text = ' %x:\t%08x \t.word\t0x%08x\t%x: R_ARM_ABS32\t%s' % (address, word, word, address, slot)
    else:
        a, b = struct.unpack('<HH', data)
        text = ' %x:\t%04x %04x \tbl\t%x <%s>\t%x: R_ARM_THM_CALL\t%s' % (address, a, b, target, callee, address, callee)
    return offset, length, (text + end).encode('utf-8')


def _coherence_expected(side, name, before, after, baseline, helpers, module):
    if name not in ('coherent-slot-in-bss', 'coherent-callee-entry'):
        return None
    reference = side == 'Reference'
    root = ROOTS[side][1] if name == 'coherent-slot-in-bss' or not reference else ROOTS[side][2]
    slot = 'pxCurrentTCB' if reference else 'fiber_internal_runtime_current_context_slot'
    callee = 'vTaskSwitchContext' if reference else 'fiber_port_context_validate_restore'
    target_name = slot if name == 'coherent-slot-in-bss' else callee
    definition = _definition(baseline, side, root, target_name)
    _, sections, _, symbol = _symbol_fields(before['Final'], target_name)
    module._same(symbol['Value'] & ~1 if name == 'coherent-callee-entry' else symbol['Value'],
                 definition['Entry'], 'baseline coherent definition entry')
    module._same(symbol['Size'], definition['Size'], 'baseline coherent definition size')
    expected, edits = dict(before), {role: [] for role in before}

    def edit(role, offset, data, length=None):
        _edit_buffer(expected, edits, role, offset, data, length)

    if name == 'coherent-slot-in-bss':
        address = symbol['Value']; target = address - 4
        section = sections[symbol['Section']]
        need(symbol['Info'] & 15 == 1 and symbol['Size'] == 4 and target >= 0 and address % 4 == 0
             and section[1] == 8 and section[3] <= target and address + 4 <= section[3] + section[5],
             'bounded coherent BSS slot')
        loads = []
        for selected, relative in zip(ROOTS[side][1:], (32, 64) if reference else (0xB4, 0xC8)):
            body, offset, root_symbol = _body(before['Final'], selected)
            need(relative + 4 <= len(body) and struct.unpack_from('<I', body, relative)[0] == address,
                 'baseline actual slot word')
            data = struct.pack('<I', target)
            edit('Final', offset + relative, data)
            if reference:
                row = next(row for row in baseline['TransportRoots'][side] if row['Name'] == selected)
                point = (root_symbol['Value'] & ~1) + relative
                start, length, text = _dump_edit(helpers['reference_mutations'], expected['Disassembly'],
                    row['RootOrigin']['OutputSection'], point, data, slot)
                edit('Disassembly', start, text, length)
            loads.append(dict(Root=selected, RootRelativeOffset=relative, Bytes=data.hex(), DisassemblyUpdated=reference))
        neighbor = None
        if reference:
            _, _, _, peer = _symbol_fields(before['Final'], 'ulMaxPRIGROUPValue')
            need(peer['Info'] == 1 and peer['Size'] == 4 and peer['Section'] == symbol['Section']
                 and peer['Value'] == target, 'fixed occupied neighboring BSS object')
            edit('Final', peer['FileOffset'] + 4, struct.pack('<I', address))
            neighbor = dict(Name=peer['Name'], BeforeAddress=target, AfterAddress=address)
        edit('Final', symbol['FileOffset'] + 4, struct.pack('<I', target))
        _, changed_sections, changed_symbols, changed = _symbol_fields(expected['Final'], slot)
        need(changed['Value'] == target, 'changed slot metadata is actual')
        if reference:
            intervals = sorted((row['Value'], row['Value'] + row['Size']) for row in changed_symbols
                if row['Info'] & 15 == 1 and row['Section'] == changed['Section'] and row['Size'] > 0)
            section = changed_sections[changed['Section']]
            need(all(section[3] <= a < b <= section[3] + section[5] for a, b in intervals)
                 and all(a[1] <= b[0] for a, b in zip(intervals, intervals[1:])), 'nonoverlapping actual changed BSS')
        result = dict(Kind='SLOT-IN-BSS', OriginalAddress=address, MutatedAddress=target, Loads=loads,
            NeighborSwap=neighbor, ImmutableOriginControlCoherenceChecked=True, ProviderSemanticsClaimed=False)
    else:
        address = symbol['Value'] & ~1; target = address + 2
        need(symbol['Info'] & 15 == 2 and symbol['Value'] & 1 and symbol['Size'] > 4,
             'bounded coherent Thumb callee')
        if reference: module._same(symbol['Size'], 12, 'fixed reference callee extent')
        relative = 28 if reference else 0x72
        body, offset, root_symbol = _body(before['Final'], root)
        need(relative + 4 <= len(body), 'bounded coherent branch site')
        place = (root_symbol['Value'] & ~1) + relative
        helper = helpers['reference_mutations' if reference else 'native_mutations']
        module._same(body[relative:relative + 4], helper.encode_bl(place, address), 'baseline exact BL target bits')
        branch = helper.encode_bl(place, target)
        edit('Final', symbol['FileOffset'] + 4, struct.pack('<II', symbol['Value'] + 2, symbol['Size'] - 2))
        edit('Final', offset + relative, branch)
        if reference:
            row = next(row for row in baseline['TransportRoots'][side] if row['Name'] == root)
            start, length, text = _dump_edit(helper, expected['Disassembly'], row['RootOrigin']['OutputSection'],
                place, branch, slot, callee, target)
            edit('Disassembly', start, text, length)
        result = dict(Kind='CALLEE-ENTRY', Name=callee, OriginalAddress=address, MutatedAddress=target,
            OriginalSize=symbol['Size'], MutatedSize=symbol['Size'] - 2, Root=root, RootRelativeOffset=relative,
            BranchBytes=branch.hex(), DisassemblyUpdated=reference,
            ImmutableOriginControlCoherenceChecked=True, ProviderSemanticsClaimed=False)
    module._same(after, expected, 'coherent case complete exact recipe bytes/' + side + '/' + name)
    return result


def _canonical_bytes(side, paths, before, edit, baseline, helpers, module):
    relative, old, new = (82, b'\x46\xdf', b'\x47\xdf') if side == 'Native' else (22, b'\x00\xdf', b'\x01\xdf')
    addresses = {}
    root = ROOTS[side][0]
    records = baseline['TransportRoots'][side]
    record = next(row for row in records if row['Name'] == root)
    for role in ('Machine', 'Final'):
        body, offset, symbol = _body(before[role], root)
        need(body[relative:relative + 2] == old, 'exact canonical original opcode/' + side + '/' + role)
        module._same(sha(body), record['MachineBodySha256' if role == 'Machine' else 'BodySha256'],
                     'baseline complete canonical body')
        edit(role, offset + relative, new)
        addresses[role] = (symbol['Value'] & ~1) + relative
    helper = helpers['reference_mutations']
    for role, binary in (('MachineDisassembly', 'Machine'), ('Disassembly', 'Final')):
        section = record['RootOrigin']['InputSection' if binary == 'Machine' else 'OutputSection']
        offset, length, line = helper._dis_line(before[role], section, addresses[binary])
        prefix = r'^(\s*' + format(addresses[binary], 'x') + r':\s+)'
        if side == 'Native':
            pattern = prefix + r'df46(\s+svc\s+)70(\s*@\s*)0x46'
            changed, count = re.subn(pattern, r'\g<1>df47\g<2>71\g<3>0x47', line)
        else:
            changed, count = re.subn(prefix + r'df00(\s+svc\s+)0(?=\s*$)', r'\g<1>df01\g<2>1', line)
        need(count == 1, 'one exact canonical dump opcode/' + role)
        edit(role, offset, changed.encode('ascii'), length)
    return relative, old.hex(), new.hex()


def _canonical_expected(side, paths, before, after, baseline, helpers, module):
    expected, edits = dict(before), {role: [] for role in before}
    relative, old, new = _canonical_bytes(side, paths, before,
        lambda role, offset, data, length=None: _edit_buffer(expected, edits, role, offset, data, length),
        baseline, helpers, module)
    module._same(after, expected, 'canonical case complete exact recipe bytes/' + side)
    tokens = copy.deepcopy(baseline['CanonicalJoin']['Roots'][side][0]['RawCanonicalTokens'])
    old_token, new_token = (['svc', '70'], ['svc', '71']) if side == 'Native' else (['svc', '0'], ['svc', '1'])
    need(tokens.count(old_token) == 1, 'single exact baseline SVC token')
    tokens[tokens.index(old_token)] = new_token
    records = copy.deepcopy(baseline['TransportRoots'][side])
    machine_hash = sha(after['Machine'])
    for row in records:
        row['RootOrigin']['ProviderSha256'] = machine_hash
        for definition in row['DefinitionOrigins']: definition['ProviderSha256'] = machine_hash
        row['MachineBodySha256'] = sha(_body(after['Machine'], row['Name'])[0])
        row['BodySha256'] = sha(_body(after['Final'], row['Name'])[0])
        if row['Name'] == ROOTS[side][0]:
            instructions = [instruction for instruction in row['Instructions'] if instruction['Offset'] == relative]
            need(len(instructions) == 1 and instructions[0]['Bytes'] == old and instructions[0]['Mnemonic'] == 'svc',
                 'one actual baseline SVC instruction record')
            instructions[0]['Bytes'], instructions[0]['Operands'] = new, new_token[1]
    return dict(Kind='SVC-IMMEDIATE', Root=ROOTS[side][0], RootRelativeOffset=relative, BeforeOpcode=old, AfterOpcode=new,
        TransportPreservationAccepted=True, TransportRoots=records, CanonicalTokens=tokens,
        CanonicalTokenSha256=sha(json.dumps(tokens, separators=(',', ':'), ensure_ascii=True).encode('ascii')),
        CanonicalRejected=True, TwinComparisonExecuted=False, SourceAuthorityPreserved=False)


def _net_edits(before, after):
    if before == after:
        return []
    start = 0
    while start < min(len(before), len(after)) and before[start] == after[start]: start += 1
    suffix = 0
    while suffix < min(len(before), len(after)) - start and before[-suffix - 1] == after[-suffix - 1]: suffix += 1
    end_before, end_after = len(before) - suffix, len(after) - suffix
    return [dict(FileOffset=start, Before=before[start:end_before].hex(), After=after[start:end_after].hex())]


def _rows(side, stage, name, group, inputs, before, after, edits, derived):
    indices = []
    for role in ROLES[:5] if stage == 'Transport' else ROLES:
        indices.append(len(derived))
        derived.append(dict(Side=side, Stage=stage, Case=name, Role=role,
            Input=dict(copy.deepcopy(inputs[group][role]), Bytes=len(before[role])),
            Output=dict(Sha256=sha(after[role]), Bytes=len(after[role]), Data=after[role].hex()),
            Edits=_net_edits(before[role], after[role])))
    return indices


def _token_rejection(side, tokens, helpers):
    class Tokens:
        def function(self, name, *, literal_islands=False):
            need(name == ROOTS[side][0] and literal_islands is True, 'one complete negative token root')
            return [tuple(row) for row in tokens]
    checker = helpers['checker']
    try:
        checker._match(Tokens(), side, ROOTS[side][0], (checker._NATIVE if side == 'Native' else checker._REFERENCE)[ROOTS[side][0]])
    except checker.Rejected as error:
        message = str(error)
        need(message.startswith('REJECT:CM3-CLOSED-ROOTS:' + side + '/' + ROOTS[side][0] + '/'),
             'precise canonical token rejection')
        return message
    raise Rejected('canonical negative tokens were accepted/' + side)


def inspect(core, read, batch, port, original, final, helpers):
    module, _, _ = _components(batch, port, original, final, helpers)
    need(callable(read) and callable(getattr(core, '_ELF', None))
         and callable(getattr(core, '_address_form', None)), 'explicit core and immutable reader')
    inputs, paths, sizes = _inputs(final, module)
    buffers = {}
    for path, digest in paths.items():
        raw = read(path, digest)
        need(type(raw) is bytes and sha(raw) == digest and len(raw) == sizes[path], 'actual positive input binding/' + str(path))
        buffers[path] = raw
    baseline, originals = _baseline(core, inputs, buffers, final, helpers, module)
    controls, derived = {}, []
    for side, group in (('Native', 'Final'), ('Reference', 'Reference')):
        paths = {name: module._path(row['Path']) for name, row in inputs[group].items()}
        positive = {role: buffers[path] for role, path in paths.items()}
        records = dict(Transport=[], Canonical=[])
        helper = helpers['native_mutations' if side == 'Native' else 'reference_mutations']
        adapter = helpers['native_roots' if side == 'Native' else 'reference_roots']
        recipe = _native_recipe if side == 'Native' else _reference_recipe
        coherence_check = _native_coherence if side == 'Native' else _reference_coherence
        for name, expected in CASES[side]:
            role_paths = {role: paths[role] for role in ROLES[:5]}
            before = {role: positive[role] for role in ROLES[:5]}
            after, edits = dict(before), {role: [] for role in before}
            recipe(name, core, helper, adapter, originals[side], role_paths, after,
                lambda role, offset, data, length=None: _edit_buffer(after, edits, role, offset, data, length))
            frozen = dict(after)
            need({role for role in edits if edits[role]} == _changed_roles(side, name), 'exact recipe changed roles/' + name)
            expected_coherence = _transport_expected(side, name, role_paths, before, frozen, baseline, helpers, module)
            with _facade({paths[role]: raw for role, raw in frozen.items()}, module):
                if expected_coherence is not None:
                    changed_final = core._ELF(paths['Final'], 'ET_EXEC')
                    actual_coherence = coherence_check(name, core, helper, adapter, originals[side], changed_final,
                        frozen['Disassembly'])
                    module._same(actual_coherence, expected_coherence, 'fresh structured control coherence')
                try:
                    candidate = _transport(core, side, role_paths, helpers)
                    for root in ROOTS[side]: candidate.function(root)
                except core.Rejected as error:
                    message = str(error)
                    need(re.match('^REJECT:' + expected + ':', message) is not None,
                         'intended transport rejection/' + side + '/' + name + '/' + message)
                else:
                    raise Rejected('transport negative was accepted/' + side + '/' + name)
            need(after == frozen, 'case buffers close after rejection')
            indices = _rows(side, 'Transport', name, group, inputs, before, frozen, edits, derived)
            records['Transport'].append(dict(Name=name, Expected=expected, Status='PASS', BufferIndices=indices,
                Rejection=dict(Type='CORE', Message=message), Coherence=expected_coherence))
        name = 'coherent-svc-immediate'
        before, after = dict(positive), dict(positive)
        edits = {role: [] for role in before}
        _canonical_bytes(side, paths, before,
            lambda role, offset, data, length=None: _edit_buffer(after, edits, role, offset, data, length),
            baseline, helpers, module)
        frozen = dict(after)
        coherence = _canonical_expected(side, paths, before, frozen, baseline, helpers, module)
        with _facade({paths[role]: raw for role, raw in frozen.items()}, module):
            candidate = _transport(core, side, paths, helpers)
            preserved = [candidate.function(root) for root in ROOTS[side]]
            module._same(json.loads(_json(preserved)), coherence['TransportRoots'], 'fresh complete changed transport roots')
            view = _view(core, side, paths, candidate, helpers)
            checker = helpers['checker']
            try:
                checker._match(view, side, ROOTS[side][0], (checker._NATIVE if side == 'Native' else checker._REFERENCE)[ROOTS[side][0]])
            except checker.Rejected as error:
                message = str(error)
                module._same(message, _token_rejection(side, coherence['CanonicalTokens'], helpers), 'actual canonical rejection')
                module._same(json.loads(_json(view.evidence[ROOTS[side][0]]['RawCanonicalTokens'])),
                             coherence['CanonicalTokens'], 'actual changed decoder tokens')
            else:
                raise Rejected('coherent canonical negative was accepted/' + side)
        need(after == frozen, 'canonical buffers close')
        indices = _rows(side, 'Canonical', name, group, inputs, before, frozen, edits, derived)
        records['Canonical'].append(dict(Name=name, Expected='CM3-CLOSED-ROOTS', Status='PASS', BufferIndices=indices,
            Rejection=dict(Type='CHECKER', Message=message), Coherence=coherence))
        controls[side] = records
    proof = dict(Status=STATUS, Scope=SCOPE, Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True, Cohort=COHORT,
        SourceInventorySha256=final['SourceInventorySha256'], BatchRoot=final['BatchRoot'], BatchAuthority=copy.deepcopy(final['BatchAuthority']),
        PortProofSha256=sha(_json(port)), OriginalProofSha256=sha(_json(original)), FinalProofSha256=sha(_json(final)),
        Inputs=inputs, LedgerBytes={name: buffers[module._path(row['Path'])].hex() for name, row in inputs['Ledgers'].items()},
        Baseline=baseline, Controls=controls, DerivedBuffers=derived,
        ReadInputs=[dict(Path=str(path), Sha256=sha(raw), Bytes=len(raw)) for path, raw in sorted(buffers.items())],
        LogicalRoles=14, ReadFiles=14, DerivedRoleInstances=172, TransportControlsExecuted=32, CanonicalControlsExecuted=2,
        FreshControlsExecuted=True, ImmutableInputsConsumed=True, ToolInvocations=0, CompilerInvocations=0,
        RequiredCellsSatisfied=0, Nonclaims=dict.fromkeys(NONCLAIMS, False))
    return require_result(proof, batch, port, original, final, helpers)


def _reconstruct(row, input_binding, input_size, module):
    module._keys(row['Input'], ('Path', 'Sha256', 'Bytes'), 'derived input binding')
    module._same(row['Input'], dict(input_binding, Bytes=input_size), 'derived input authority')
    output = row['Output']; module._keys(output, ('Sha256', 'Bytes', 'Data'), 'derived output bytes')
    raw = _hex(output['Data'])
    module._same(output['Bytes'], len(raw), 'derived literal output size')
    module._same(output['Sha256'], sha(raw), 'derived literal output hash')
    edits = row['Edits']; need(type(edits) is list, 'literal edit list')
    parsed = []
    for edit in edits:
        module._keys(edit, ('FileOffset', 'Before', 'After'), 'closed sequential edit')
        offset, before, after = edit['FileOffset'], _hex(edit['Before'], True), _hex(edit['After'], True)
        need(type(offset) is int and offset >= 0 and before != after, 'bounded real edit')
        parsed.append((offset, before, after))
    positive = raw
    for offset, before, after in reversed(parsed):
        need(offset <= len(positive) - len(after) and positive[offset:offset + len(after)] == after,
             'reverse edit extent and bytes')
        positive = positive[:offset] + before + positive[offset + len(after):]
    module._same(len(positive), input_size, 'reconstructed positive size')
    module._same(sha(positive), input_binding['Sha256'], 'reconstructed positive hash')
    forward = positive
    for offset, before, after in parsed:
        need(offset <= len(forward) - len(before) and forward[offset:offset + len(before)] == before,
             'forward edit extent and bytes')
        forward = forward[:offset] + after + forward[offset + len(before):]
    module._same(forward, raw, 'exact bidirectional edit reconstruction')
    module._same(edits, _net_edits(positive, raw), 'unique net edit, no invented intermediate steps')
    return positive, raw


def require_result(proof, batch, port, original, final, helpers):
    module, _, _ = _components(batch, port, original, final, helpers)
    module._keys(proof, FIELDS, 'final control result')
    for name, value in (('Status', STATUS), ('Scope', SCOPE), ('Profile', 'CM3'), ('Mode', 'Os-lto'), ('Linkage', 'direct'),
            ('LTO', True), ('Cohort', COHORT), ('LogicalRoles', 14), ('ReadFiles', 14), ('DerivedRoleInstances', 172),
            ('TransportControlsExecuted', 32), ('CanonicalControlsExecuted', 2), ('FreshControlsExecuted', True),
            ('ImmutableInputsConsumed', True), ('ToolInvocations', 0), ('CompilerInvocations', 0), ('RequiredCellsSatisfied', 0)):
        module._same(proof[name], value, 'literal result field/' + name)
    module._same(proof['Nonclaims'], dict.fromkeys(NONCLAIMS, False), 'closed false nonclaims')
    for name, component in (('Port', port), ('Original', original), ('Final', final)):
        module._same(proof[name + 'ProofSha256'], sha(_json(component)), 'full component proof hash/' + name)
    for name in ('SourceInventorySha256', 'BatchRoot', 'BatchAuthority'):
        module._same(proof[name], final[name], 'final authority/' + name)
    inputs, paths, sizes = _inputs(final, module)
    module._same(proof['Inputs'], inputs, 'exact final control input roles')
    module._keys(proof['LedgerBytes'], ('Master', 'Policy'), 'two ledger buffers')
    positives = {}
    for name, row in inputs['Ledgers'].items():
        path = module._path(row['Path']); raw = _hex(proof['LedgerBytes'][name])
        module._same(sha(raw), row['Sha256'], 'ledger hash/' + name)
        module._same(len(raw), sizes[path], 'ledger size/' + name)
        module._same(raw.hex(), final['ControlBytes'][name + 'Ledger'], 'same final ledger bytes/' + name)
        positives[path] = raw
    expected_baseline = {name: copy.deepcopy(final[name]) for name in ('TransportRoots', 'CanonicalJoin', 'PolicyDifferenceRationales')}
    module._same(proof['Baseline'], expected_baseline, 'complete baseline proof')
    module._keys(proof['Controls'], SIDES, 'two control sides')
    derived = proof['DerivedBuffers']; need(type(derived) is list and len(derived) == 172, '172 derived role-buffer instances')
    offset, pending = 0, []
    for side, group in (('Native', 'Final'), ('Reference', 'Reference')):
        records = proof['Controls'][side]; module._keys(records, ('Transport', 'Canonical'), 'two control phases')
        for stage, catalog in (('Transport', CASES[side]), ('Canonical', (('coherent-svc-immediate', 'CM3-CLOSED-ROOTS'),))):
            rows = records[stage]; need(type(rows) is list and len(rows) == len(catalog), 'complete ordered cases')
            roles = ROLES[:5] if stage == 'Transport' else ROLES
            for record, (name, expected) in zip(rows, catalog):
                module._keys(record, ('Name', 'Expected', 'Status', 'BufferIndices', 'Rejection', 'Coherence'), 'closed control case')
                for key, value in (('Name', name), ('Expected', expected), ('Status', 'PASS'),
                                   ('BufferIndices', list(range(offset, offset + len(roles))))):
                    module._same(record[key], value, 'ordered control/' + key)
                before, after = {}, {}
                changed = set()
                for row, role in zip(derived[offset:offset + len(roles)], roles):
                    module._keys(row, ('Side', 'Stage', 'Case', 'Role', 'Input', 'Output', 'Edits'), 'closed derived role')
                    for key, value in (('Side', side), ('Stage', stage), ('Case', name), ('Role', role)):
                        module._same(row[key], value, 'derived owner/' + key)
                    path = module._path(inputs[group][role]['Path'])
                    positive, output = _reconstruct(row, inputs[group][role], sizes[path], module)
                    if path in positives: module._same(positive, positives[path], 'shared positive bytes agree')
                    positives[path] = positive
                    before[role], after[role] = positive, output
                    if row['Edits']: changed.add(role)
                module._same(changed, _changed_roles(side, name), 'exact changed recipe roles')
                module._keys(record['Rejection'], ('Type', 'Message'), 'closed intended rejection')
                message = record['Rejection']['Message']
                need(type(message) is str and bool(message), 'literal rejection message')
                module._same(record['Rejection']['Type'], 'CORE' if stage == 'Transport' else 'CHECKER', 'rejection type')
                if stage == 'Transport':
                    need(re.match('^REJECT:' + expected + ':', message) is not None, 'case-specific transport diagnostic')
                pending.append((side, stage, name, before, after, record))
                offset += len(roles)
    module._same(offset, 172, 'all derived rows consumed once')
    module._same(set(positives), set(paths), 'fourteen positive buffers reconstructed')
    reads = [dict(Path=str(path), Sha256=sha(raw), Bytes=len(raw)) for path, raw in sorted(positives.items())]
    module._same(proof['ReadInputs'], reads, 'exact independently sized read inventory')
    for side, stage, name, before, after, record in pending:
        group = 'Final' if side == 'Native' else 'Reference'
        role_paths = {role: module._path(row['Path']) for role, row in inputs[group].items()}
        if stage == 'Canonical':
            expected = _canonical_expected(side, role_paths, before, after, expected_baseline, helpers, module)
            module._same(record['Coherence'], expected, 'canonical tokens/transport/byte coherence')
            module._same(record['Rejection']['Message'], _token_rejection(side, expected['CanonicalTokens'], helpers),
                         'pure canonical negative diagnostic')
        else:
            expected = _transport_expected(side, name, role_paths, before, after, expected_baseline, helpers, module)
            module._same(record['Coherence'], expected, 'actual slot/callee coherence')
    return proof


# Buffer adaptations of the frozen native/reference recipes; no physical APIs.
def _native_recipe(name, core, helper, adapter, original, paths, buffers, edit):
    catalog = (
        ('machine-nonrelocation-byte', 'LTO-PRESERVATION'),
        ('machine-bl-addend', 'LTO-RELOC'),
        ('machine-slot-addend', 'LTO-SLOT'),
        ('applied-slot-word', 'LTO-SLOT'),
        ('coherent-slot-in-bss', 'LTO-(ORIGIN|SYMBOL)'),
        ('globalized-slot', 'LTO-SYMBOL'),
        ('wrong-slot-section-target', 'LTO-SLOT'),
        ('function-alias', 'LTO-SYMBOL'),
        ('slot-object-alias', 'LTO-SYMBOL'),
        ('code-without-execute', 'LTO-SYMBOL'),
        ('callee-data-mapping', 'LTO-SYMBOL'),
        ('coherent-callee-entry', 'LTO-ORIGIN'),
        ('wrong-machine-section-size', '(LTO-)?ORIGIN'),
        ('foreign-map-provider', '(LTO-)?ORIGIN'),
        ('missing-root-reference', 'LTO-RELOC'),
        ('extra-root-reference', 'LTO-RELOC'),
    )
    roles = ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup')
    need(type(helper.CASES) is tuple and helper.CASES == catalog,
         'native recipe catalog differs from frozen authority')
    need(type(name) is str and name in tuple(row[0] for row in catalog),
         'unknown native recipe')
    need(type(paths) is dict and set(paths) == set(roles)
         and all(str(paths[role]) for role in roles), 'native five role paths')
    need(type(buffers) is dict and set(buffers) == set(roles)
         and all(type(buffers[role]) is bytes and buffers[role] for role in roles),
         'native five immutable input buffers')
    need(callable(edit), 'native edit callback')
    initial = dict(buffers)
    machine, final = original.machine, original.final
    need(machine.final is False and final.final is True
         and type(machine.data) is bytes and type(final.data) is bytes
         and buffers['Machine'] == machine.data and buffers['Final'] == final.data,
         'native positive parser/buffer binding')
    need(core.sha256(buffers['Disassembly']) == original.image.hashes['DisassemblySha256']
         and core.sha256(buffers['LinkMap']) == original.image.link_map_hash,
         'native positive dump/map binding')
    need(adapter.SLOT == 'fiber_internal_runtime_current_context_slot'
         and adapter.ROOTS == {'SVC_Handler': (184, 64, 5),
                              'PendSV_Handler': (204, 72, 6),
                              'fiber_port_start_first_context': (104, 34, 2)}
         and adapter.CALLEES == frozenset((
             'fiber_panic', 'fiber_port_context_validate_restore',
             'fiber_port_context_validate_save_current',
             'fiber_port_scheduler_pick_next_from_pendsv')),
         'native fixed fixture catalog')

    def section(elf, index):
        need(type(index) is int and 0 < index < len(elf.sections),
             'native bounded section index')
        return elf.sections[index]

    def definition(elf, symbol_name, *, slot=False):
        row = helper._symbol(elf, symbol_name)
        h = section(elf, row['section']).header
        need(row['kind'] == ('STT_OBJECT' if slot else 'STT_FUNC')
             and row['binding'] == ('STB_LOCAL' if slot else 'STB_GLOBAL')
             and row['visibility'] == 'STV_DEFAULT'
             and type(row['value']) is int and type(row['size']) is int
             and 0 <= row['value'] < 1 << 32 and 0 < row['size'] < 1 << 32,
             'native original definition metadata ' + symbol_name)
        base = row['value'] if slot else row['value'] & ~1
        origin = h.sh_addr if elf.final else 0
        need(h.sh_flags & 7 == (3 if slot else 6)
             and h.sh_type == ('SHT_NOBITS' if slot else 'SHT_PROGBITS')
             and origin <= base and base + row['size'] <= origin + h.sh_size,
             'native original definition extent ' + symbol_name)
        need((row['size'] == 4 and base % 4 == 0) if slot
             else (row['value'] & 1 and row['size'] % 2 == 0),
             'native original slot/Thumb definition ' + symbol_name)
        return row

    def field_offset(elf, row):
        need(len(elf.tables) == 1, 'native unique symbol table')
        table = elf.sections[next(iter(elf.tables))]
        need(table.header.sh_type == 'SHT_SYMTAB' and table.header.sh_entsize == 16
             and type(row['index']) is int and row['index'] >= 0
             and (row['index'] + 1) * 16 <= table.header.sh_size,
             'native bounded ELF32 symbol field')
        offset = helper._symbol_file_offset(elf, row)
        need(0 <= offset and offset + 16 <= len(elf.data),
             'native file-backed symbol entry')
        value, size = struct.unpack_from('<II', elf.data, offset + 4)
        need((value, size) == (row['value'], row['size']),
             'native raw symbol value/size correspondence')
        return offset

    def address_offset(elf, index, address, length):
        h = section(elf, index).header
        origin = h.sh_addr if elf.final else 0
        need(type(address) is int and type(length) is int and length > 0
             and origin <= address and address + length <= origin + h.sh_size,
             'native complete address patch extent')
        offset = helper._address_offset(elf, index, address)
        need(0 <= offset and offset + length <= len(elf.data),
             'native complete file-backed patch extent')
        return offset

    def relocation_offset(elf, index, address):
        h = section(elf, index).header
        key = (index, address - (h.sh_addr if elf.final else 0))
        need(key in elf.relocations, 'native existing REL patch site')
        offset = helper._relocation_offset(elf, index, address)
        need(0 <= offset and offset + 8 <= len(elf.data), 'native bounded ELF32 REL entry')
        raw_address, info = struct.unpack_from('<II', elf.data, offset)
        kind, target = elf.relocations[key]
        need(raw_address == address and info == (target['index'] << 8 | kind),
             'native raw REL correspondence')
        owners = [row for row in elf.sections
                  if row.header.sh_type == 'SHT_REL' and row.header.sh_info == index
                  and row.header.sh_entsize == 8
                  and row.header.sh_offset <= offset
                  and offset + 8 <= row.header.sh_offset + row.header.sh_size
                  and (offset - row.header.sh_offset) % 8 == 0]
        need(len(owners) == 1, 'native unique complete ELF32 REL owner')
        return offset

    changes = 0

    def change(role, offset, after, length=None):
        nonlocal changes
        need(role in roles and type(offset) is int and type(after) is bytes and after,
             'native typed edit')
        width = len(after) if length is None else length
        need(type(width) is int and width > 0 and 0 <= offset
             and offset + width <= len(buffers[role]), 'native bounded edit')
        before = dict(buffers)
        need(before[role][offset:offset + width] != after, 'native nonempty actual edit')
        expected = before[role][:offset] + after + before[role][offset + width:]
        edit(role, offset, after, length=width)
        need(type(buffers) is dict and set(buffers) == set(roles)
             and all(type(buffers[item]) is bytes for item in roles)
             and buffers[role] == expected
             and all(buffers[item] == before[item] for item in roles if item != role),
             'native edit callback exact buffer effect')
        changes += 1

    svc = definition(machine, 'SVC_Handler')
    slot = definition(final, adapter.SLOT, slot=True)
    final_svc = definition(final, 'SVC_Handler')
    need(svc['value'] == 1 and svc['size'] == final_svc['size'] == 184
         and section(machine, svc['section']).name == '.text'
         and machine.sections[svc['section']].header.sh_size >= 0x41C,
         'native fixed merged-text SVC fixture')
    need(section(final, slot['section']).name == '.bss', 'native fixed final BSS slot')

    if name == 'machine-nonrelocation-byte':
        offset = address_offset(machine, svc['section'], 0, 1)
        need(not any(index == svc['section'] and address <= 0 < address + 4
                     for index, address in machine.relocations),
             'native nonrelocation byte site')
        change('Machine', offset, bytes((buffers['Machine'][offset] ^ 1,)))
    elif name == 'machine-bl-addend':
        need(machine.relocations.get((svc['section'], 0x72), (None,))[0] == 10,
             'native fixed machine BL REL site')
        offset = address_offset(machine, svc['section'], 0x72, 4)
        form = core._address_form(buffers['Machine'][offset:offset + 4], 0x72)
        need(form is not None and form[0] == 'bl' and form[3] == -4,
             'native original machine BL addend')
        change('Machine', offset, bytes.fromhex('fff7ffff'))
    elif name == 'machine-slot-addend':
        need(machine.relocations.get((svc['section'], 0xB4), (None,))[0] == 2,
             'native fixed machine slot REL site')
        offset = address_offset(machine, svc['section'], 0xB4, 4)
        need(buffers['Machine'][offset:offset + 4] == b'\0' * 4,
             'native original zero slot addend')
        change('Machine', offset, struct.pack('<I', 4))
    elif name in ('applied-slot-word', 'coherent-slot-in-bss'):
        target = slot['value'] - 4
        need(0 <= target < 1 << 32 and target % 4 == 0, 'native aligned slot target')
        if name == 'coherent-slot-in-bss':
            h = final.sections[slot['section']].header
            need(h.sh_addr <= target and target + 4 <= h.sh_addr + h.sh_size,
                 'native coherent target retains BSS extent')
        roots = ('SVC_Handler', 'PendSV_Handler') if name == 'coherent-slot-in-bss' else ('SVC_Handler',)
        for root in roots:
            symbol = definition(final, root)
            relative = 0xB4 if root == 'SVC_Handler' else 0xC8
            need(symbol['size'] == adapter.ROOTS[root][0] and relative + 4 <= symbol['size'],
                 'native slot word root extent')
            offset = address_offset(final, symbol['section'], (symbol['value'] & ~1) + relative, 4)
            need(struct.unpack_from('<I', buffers['Final'], offset)[0] == slot['value'],
                 'native original applied slot word')
            change('Final', offset, struct.pack('<I', target))
        if name == 'coherent-slot-in-bss':
            change('Final', field_offset(final, slot) + 4, struct.pack('<I', target))
    elif name == 'globalized-slot':
        offset = field_offset(final, slot) + 12
        need(buffers['Final'][offset:offset + 1] == b'\x01', 'native original local object info')
        change('Final', offset, b'\x11')
    elif name == 'wrong-slot-section-target':
        symbols = [row for row in final.symbols
                   if row['kind'] == 'STT_SECTION' and row['section'] == final_svc['section']]
        need(len(symbols) == 1, 'native unique wrong text section target')
        target = symbols[0]
        need(target['binding'] == 'STB_LOCAL' and target['visibility'] == 'STV_DEFAULT'
             and target['name'] == '' and target['size'] == 0,
             'native original text section symbol')
        address = (final_svc['value'] & ~1) + 0xB4
        key = (final_svc['section'], address - final.sections[final_svc['section']].header.sh_addr)
        need(final.relocations[key][0] == 2, 'native original final slot REL kind')
        offset = relocation_offset(final, final_svc['section'], address)
        change('Final', offset + 4, struct.pack('<I', target['index'] << 8 | 2))
    elif name in ('function-alias', 'slot-object-alias'):
        slot_case = name == 'slot-object-alias'
        target = definition(machine, adapter.SLOT, slot=True) if slot_case else svc
        candidates = [row for row in machine.symbols
                      if row['name'] not in (*adapter.ROOTS, *adapter.CALLEES, adapter.SLOT)
                      and row['kind'] == target['kind'] and type(row['section']) is int
                      and row['section'] > 0 and row['size'] > 0]
        need(candidates, 'native frozen-order alias candidate')
        alias = candidates[0]
        need(helper._symbol(machine, alias['name']) == alias,
             'native unique selected alias definition')
        section(machine, alias['section'])
        offset = field_offset(machine, alias)
        if (alias['value'], alias['size']) != (target['value'], 4):
            change('Machine', offset + 4, struct.pack('<II', target['value'], 4))
        if alias['section'] != target['section']:
            change('Machine', offset + 14, struct.pack('<H', target['section']))
    elif name == 'code-without-execute':
        address = final_svc['value'] & ~1
        loads = [(index, segment) for index, segment in enumerate(final.elf.iter_segments())
                 if segment.header.p_type == 'PT_LOAD'
                 and segment.header.p_vaddr <= address
                 < segment.header.p_vaddr + segment.header.p_memsz]
        need(len(loads) == 1, 'native unique executable program-header owner')
        index, segment = loads[0]
        header = final.elf.header
        need(header.e_phentsize == 32 and 0 <= index < header.e_phnum
             and segment.header.p_flags & 1, 'native executable ELF32 program-header fixture')
        offset = header.e_phoff + index * header.e_phentsize + 24
        need(0 <= offset and offset + 4 <= len(buffers['Final'])
             and struct.unpack_from('<I', buffers['Final'], offset)[0] == segment.header.p_flags,
             'native raw program-header flags correspondence')
        change('Final', offset, struct.pack('<I', segment.header.p_flags & ~1))
    elif name == 'callee-data-mapping':
        callee = definition(machine, 'fiber_panic')
        mappings = [row for row in machine.symbols if row['name'].split('.')[0] == '$t'
                    and row['section'] == callee['section'] and row['value'] <= (callee['value'] & ~1)]
        need(mappings, 'native existing callee Thumb mapping')
        latest = max(row['value'] for row in mappings)
        selected = [row for row in mappings if row['value'] == latest]
        need(len(selected) == 1, 'native unique active callee Thumb mapping')
        mapping = selected[0]
        need(mapping['kind'] == 'STT_NOTYPE' and mapping['binding'] == 'STB_LOCAL'
             and mapping['size'] == 0, 'native original Thumb mapping metadata')
        need(len(machine.tables) == 1, 'native mapping symbol table')
        table = machine.sections[next(iter(machine.tables))]
        strings = section(machine, table.header.sh_link)
        h = strings.header
        need(h.sh_type == 'SHT_STRTAB' and 0 <= h.sh_offset
             and h.sh_offset + h.sh_size <= len(buffers['Machine']),
             'native bounded raw symbol string table')
        raw = buffers['Machine'][h.sh_offset:h.sh_offset + h.sh_size]
        position = raw.find(b'\0$d\0')
        need(position >= 0, 'native existing raw data-mapping name')
        change('Machine', field_offset(machine, mapping), struct.pack('<I', position + 1))
    elif name == 'coherent-callee-entry':
        callee = definition(final, 'fiber_port_context_validate_restore')
        need(callee['size'] > 4 and callee['value'] + 2 < 1 << 32,
             'native coherent callee mutation extent')
        change('Final', field_offset(final, callee) + 4,
               struct.pack('<II', callee['value'] + 2, callee['size'] - 2))
        place = (final_svc['value'] & ~1) + 0x72
        offset = address_offset(final, final_svc['section'], place, 4)
        form = core._address_form(buffers['Final'][offset:offset + 4], place)
        need(form is not None and form[0] == 'bl' and form[1] == callee['value'] & ~1,
             'native original final callee BL')
        change('Final', offset, helper.encode_bl(place, (callee['value'] & ~1) + 2))
    elif name == 'wrong-machine-section-size':
        raw = buffers['LinkMap']
        text = raw.decode('utf-8', errors='strict')
        matches = list(re.finditer(
            r'(?m)^\s+\.text\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+'
            + re.escape(str(paths['Machine'])) + r'\s*$', text))
        need(len(matches) == 1, 'native unique full machine text placement')
        match = matches[0]
        size = int(match[2], 16)
        need(size == machine.sections[svc['section']].header.sh_size and size > 2
             and int(match[1], 16) == final_svc['value'] & ~1,
             'native original full machine text placement correspondence')
        offset = len(text[:match.start(2)].encode('utf-8'))
        change('LinkMap', offset, hex(size - 2).encode('ascii'),
               length=len(match[2].encode('ascii')))
    elif name == 'foreign-map-provider':
        before = buffers['LinkMap']
        provider = str(paths['Machine']).encode('utf-8')
        replacement = b'C:/unbound-lto-machine.o'
        need(provider and provider != replacement and provider in before,
             'native actual map provider replacement')
        cursor = 0
        while True:
            offset = buffers['LinkMap'].find(provider, cursor)
            if offset < 0:
                break
            change('LinkMap', offset, replacement, length=len(provider))
            cursor = offset + len(replacement)
        need(buffers['LinkMap'] == before.replace(provider, replacement),
             'native complete frozen map provider substitution')
    else:
        if name == 'missing-root-reference':
            address, destination = 0x72, 0xB8
        else:
            candidates = [offset for index, offset in machine.relocations
                          if index == svc['section'] and 0x184 <= offset < 0x41C]
            need(candidates, 'native existing extra-reference source')
            address, destination = min(candidates), 2
        need((svc['section'], destination) not in machine.relocations
             and destination + 4 <= machine.sections[svc['section']].header.sh_size,
             'native distinct bounded replacement REL site')
        offset = relocation_offset(machine, svc['section'], address)
        change('Machine', offset, struct.pack('<I', destination))

    expected_role = ('LinkMap' if name in ('wrong-machine-section-size', 'foreign-map-provider')
                     else 'Machine' if name in (
                         'machine-nonrelocation-byte', 'machine-bl-addend', 'machine-slot-addend',
                         'function-alias', 'slot-object-alias', 'callee-data-mapping',
                         'missing-root-reference', 'extra-root-reference') else 'Final')
    need(changes > 0 and [role for role in roles if buffers[role] != initial[role]] == [expected_role],
         'native exact nonempty recipe changed-role set')
    need(machine.data == initial['Machine'] and final.data == initial['Final'],
         'native positive parser bytes preserved')
    return None


def _native_coherence(name, core, helper, adapter, original, changed_final, disassembly_bytes):
    if name not in ('coherent-slot-in-bss', 'coherent-callee-entry'):
        return None
    final = original.final
    changed = changed_final
    need(type(final.data) is bytes and type(changed.data) is bytes
         and final.final is True and changed.final is True
         and len(changed.data) == len(final.data), 'native coherent fresh final bytes')
    need(type(disassembly_bytes) is bytes and disassembly_bytes
         and core.sha256(disassembly_bytes) == original.image.hashes['DisassemblySha256'],
         'native coherent unchanged positive disassembly binding')
    expected = bytearray(final.data)

    def patch(offset, after):
        need(type(offset) is int and type(after) is bytes and after and 0 <= offset
             and offset + len(after) <= len(expected), 'native coherent expected patch bounds')
        need(bytes(expected[offset:offset + len(after)]) != after,
             'native coherent expected patch is not a no-op')
        expected[offset:offset + len(after)] = after

    def same_metadata(before, after, fields):
        need(type(before) is dict and type(after) is dict and set(before) == set(after)
             and all(type(before[key]) is type(after[key]) and before[key] == after[key]
                     for key in before if key not in fields),
             'native coherent unchanged definition metadata')

    def owner(elf, row, *, slot=False):
        need(type(row['section']) is int and 0 < row['section'] < len(elf.sections)
             and row['kind'] == ('STT_OBJECT' if slot else 'STT_FUNC')
             and row['binding'] == ('STB_LOCAL' if slot else 'STB_GLOBAL')
             and row['visibility'] == 'STV_DEFAULT'
             and type(row['value']) is int and type(row['size']) is int
             and 0 <= row['value'] < 1 << 32 and 0 < row['size'] < 1 << 32,
             'native coherent actual definition role')
        h = elf.sections[row['section']].header
        base = row['value'] if slot else row['value'] & ~1
        need(h.sh_type == ('SHT_NOBITS' if slot else 'SHT_PROGBITS')
             and h.sh_flags & 7 == (3 if slot else 6)
             and h.sh_addr <= base and base + row['size'] <= h.sh_addr + h.sh_size,
             'native coherent actual section flags/type/extent')
        need((row['size'] == 4 and base % 4 == 0) if slot
             else (row['value'] & 1 and row['size'] % 2 == 0),
             'native coherent actual aligned slot/Thumb entry')
        loads = [load for load in elf.loads if load['Vaddr'] <= base
                 and base + row['size'] <= load['Vaddr'] + load['MemorySize']]
        need(len(loads) == 1 and (loads[0]['Flags'] & 3 == 2 if slot else loads[0]['Flags'] & 1 != 0),
             'native coherent actual load flags/extent')
        return h

    def field(elf, row):
        need(len(elf.tables) == 1, 'native coherent unique symbol table')
        h = elf.sections[next(iter(elf.tables))].header
        need(h.sh_type == 'SHT_SYMTAB' and h.sh_entsize == 16
             and type(row['index']) is int and row['index'] >= 0
             and (row['index'] + 1) * 16 <= h.sh_size,
             'native coherent complete symbol entry')
        offset = helper._symbol_file_offset(elf, row)
        need(0 <= offset and offset + 16 <= len(elf.data)
             and struct.unpack_from('<II', elf.data, offset + 4) == (row['value'], row['size']),
             'native coherent raw symbol metadata')
        return offset

    def word(elf, root, relative):
        row = helper._symbol(elf, root)
        h = owner(elf, row)
        need(root in adapter.ROOTS and row['size'] == adapter.ROOTS[root][0]
             and relative + 4 <= row['size'], 'native coherent exact handler extent')
        address = (row['value'] & ~1) + relative
        need(h.sh_addr <= address and address + 4 <= h.sh_addr + h.sh_size,
             'native coherent complete handler field')
        offset = helper._address_offset(elf, row['section'], address)
        need(0 <= offset and offset + 4 <= len(elf.data), 'native coherent file-backed handler field')
        return row, address, offset, elf.data[offset:offset + 4]

    if name == 'coherent-slot-in-bss':
        before = helper._symbol(final, adapter.SLOT)
        after = helper._symbol(changed, adapter.SLOT)
        before_h, after_h = owner(final, before, slot=True), owner(changed, after, slot=True)
        same_metadata(before, after, {'value'})
        need(final.sections[before['section']].name == changed.sections[after['section']].name == '.bss'
             and before_h == after_h and after['value'] == before['value'] - 4,
             'native coherent actual shifted BSS slot')
        loads = []
        for root, relative in (('SVC_Handler', 0xB4), ('PendSV_Handler', 0xC8)):
            old_root, old_address, old_offset, old_raw = word(final, root, relative)
            new_root, new_address, new_offset, new_raw = word(changed, root, relative)
            same_metadata(old_root, new_root, set())
            need(old_address == new_address and old_offset == new_offset
                 and struct.unpack('<I', old_raw)[0] == before['value']
                 and struct.unpack('<I', new_raw)[0] == after['value'],
                 'native coherent both actual applied slot words')
            patch(old_offset, struct.pack('<I', after['value']))
            loads.append(dict(Root=root, RootRelativeOffset=relative, Bytes=new_raw.hex(),
                              DisassemblyUpdated=False))
        old_field, new_field = field(final, before), field(changed, after)
        need(old_field == new_field, 'native coherent stable slot symbol field')
        patch(old_field + 4, struct.pack('<I', after['value']))
        need(changed.data == bytes(expected), 'native coherent exact slot recipe bytes only')
        return dict(Kind='SLOT-IN-BSS', OriginalAddress=before['value'], MutatedAddress=after['value'],
                    Loads=loads, NeighborSwap=None, ImmutableOriginControlCoherenceChecked=True,
                    ProviderSemanticsClaimed=False)

    callee_name = 'fiber_port_context_validate_restore'
    before = helper._symbol(final, callee_name)
    after = helper._symbol(changed, callee_name)
    before_h, after_h = owner(final, before), owner(changed, after)
    same_metadata(before, after, {'value', 'size'})
    need(before_h == after_h and before['size'] > 4
         and after['value'] == before['value'] + 2 and after['size'] == before['size'] - 2,
         'native coherent actual callee entry/size shift')
    old_field, new_field = field(final, before), field(changed, after)
    need(old_field == new_field, 'native coherent stable callee symbol field')
    patch(old_field + 4, struct.pack('<II', after['value'], after['size']))
    old_root, old_place, old_offset, old_raw = word(final, 'SVC_Handler', 0x72)
    new_root, new_place, new_offset, new_raw = word(changed, 'SVC_Handler', 0x72)
    same_metadata(old_root, new_root, set())
    old_form = core._address_form(old_raw, old_place)
    form = core._address_form(new_raw, new_place)
    need(old_place == new_place and old_offset == new_offset
         and old_form is not None and old_form[0] == 'bl' and old_form[1] == before['value'] & ~1
         and form is not None and form[0] == 'bl' and form[1] == after['value'] & ~1,
         'native coherent actual BL bits resolve to actual changed callee')
    encoded = helper.encode_bl(new_place, after['value'] & ~1)
    need(new_raw == encoded, 'native coherent canonical BL encoding')
    patch(old_offset, encoded)
    need(changed.data == bytes(expected), 'native coherent exact callee recipe bytes only')
    return dict(Kind='CALLEE-ENTRY', Name=callee_name,
                OriginalAddress=before['value'] & ~1, MutatedAddress=after['value'] & ~1,
                OriginalSize=before['size'], MutatedSize=after['size'], Root='SVC_Handler',
                RootRelativeOffset=0x72, BranchBytes=new_raw.hex(), DisassemblyUpdated=False,
                ImmutableOriginControlCoherenceChecked=True, ProviderSemanticsClaimed=False)


def _reference_recipe(name, core, helper, adapter, original, paths, buffers, edit):
    roles = ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup')
    roots = ('prvPortStartFirstTask', 'vPortSVCHandler', 'xPortPendSVHandler')
    slot_name, callee_name = 'pxCurrentTCB', 'vTaskSwitchContext'
    cases = (
        ('machine-nonrelocation-byte', 'REF-LTO-PRESERVATION'),
        ('machine-bl-addend', 'REF-LTO-RELOC'),
        ('machine-slot-addend', 'REF-LTO-SLOT'),
        ('applied-slot-word', 'REF-LTO-SLOT'),
        ('coherent-slot-in-bss', 'REF-LTO-ORIGIN'),
        ('localized-slot', 'REF-LTO-SYMBOL'),
        ('wrong-slot-named-target', 'REF-LTO-RELOC'),
        ('function-alias', 'REF-LTO-SYMBOL'),
        ('slot-object-alias', 'REF-LTO-SYMBOL'),
        ('code-without-execute', 'REF-LTO-SYMBOL'),
        ('callee-data-mapping', 'REF-LTO-SYMBOL'),
        ('coherent-callee-entry', 'REF-LTO-ORIGIN'),
        ('wrong-machine-section-size', 'REF-LTO-ORIGIN'),
        ('foreign-map-provider', 'REF-LTO-ORIGIN'),
        ('missing-root-reference', 'REF-LTO-RELOC'),
        ('extra-root-reference', 'REF-LTO-RELOC'),
    )
    need(type(paths) is dict and set(paths) == set(roles), 'reference recipe five role paths')
    need(len({str(paths[role]) for role in roles}) == 5, 'reference recipe distinct role paths')
    need(type(buffers) is dict and set(buffers) == set(roles)
         and all(type(buffers[role]) is bytes and buffers[role] for role in roles),
         'reference recipe five immutable role buffers')
    need(tuple(helper.ROLES) == roles and tuple(helper.ROOTS) == roots
         and tuple(helper.CASES) == cases and helper.SLOT == slot_name and helper.CALLEE == callee_name,
         'reference recipe frozen helper catalog')
    need(tuple(adapter.ROOTS) == roots and adapter.SLOT == slot_name and adapter.CALLEE == callee_name,
         'reference recipe fixed adapter')
    need(type(name) is str and name in {row[0] for row in cases} and callable(edit),
         'reference recipe fixed case and edit callback')
    machine, final = original.machine, original.final
    need(type(machine.data) is bytes and type(final.data) is bytes
         and buffers['Machine'] == machine.data and buffers['Final'] == final.data,
         'reference recipe original parser bytes bound to initial buffers')
    for root, offset, size, binding in ((roots[0], 0x78, 32, 'STB_LOCAL'),
                                       (roots[1], 0x54, 36, 'STB_GLOBAL'),
                                       (roots[2], 0x98, 68, 'STB_GLOBAL')):
        symbol = helper._symbol(machine, root)
        need(symbol['value'] == (offset | 1) and symbol['size'] == size
             and symbol['binding'] == binding and symbol['kind'] == 'STT_FUNC'
             and type(symbol['section']) is int and 0 < symbol['section'] < len(machine.sections),
             'reference recipe fixed actual machine layout')

    def patch(role, offset, after, length=None):
        need(role in buffers and type(offset) is int and type(after) is bytes and after,
             'reference recipe literal bounded edit')
        length = len(after) if length is None else length
        before = buffers[role]
        need(type(length) is int and length > 0 and 0 <= offset <= len(before)
             and offset + length <= len(before) and before[offset:offset + length] != after,
             'reference recipe nonempty in-bounds edit')
        snapshot = dict(buffers)
        expected = before[:offset] + after + before[offset + length:]
        edit(role, offset, after, length)
        need(set(buffers) == set(roles) and type(buffers[role]) is bytes and buffers[role] == expected
             and all(type(buffers[other]) is bytes and buffers[other] == snapshot[other]
                     for other in roles if other != role), 'reference recipe exact callback update')

    def address_offset(elf, section, address, size=4):
        need(type(section) is int and 0 < section < len(elf.sections)
             and type(address) is int and type(size) is int and size > 0,
             'reference recipe bounded address metadata')
        offset = helper._address_offset(elf, section, address, size)
        need(type(offset) is int and 0 <= offset and offset + size <= len(elf.data),
             'reference recipe bounded file-backed field')
        return offset

    def symbol_offset(elf, symbol, relative, size):
        need(type(relative) is int and type(size) is int and 0 <= relative
             and size > 0 and relative + size <= 16, 'reference recipe ELF32 symbol subfield')
        offset = helper._symbol_offset(elf, symbol) + relative
        need(0 <= offset and offset + size <= len(elf.data), 'reference recipe bounded symbol bytes')
        return offset

    def relocation_offset(elf, section, address):
        offset = helper._relocation_offset(elf, section, address)
        need(type(offset) is int and 0 <= offset and offset + 8 <= len(elf.data),
             'reference recipe bounded ELF32 REL field')
        return offset

    svc, pend = helper._symbol(machine, roots[1]), helper._symbol(machine, roots[2])
    slot = helper._symbol(final, slot_name)
    final_svc, final_pend = helper._symbol(final, roots[1]), helper._symbol(final, roots[2])

    def disassembly(symbol, address, raw, target=None):
        need(type(raw) is bytes and len(raw) == 4, 'reference recipe complete displayed word or BL')
        offset, length, old = helper._dis_line(
            buffers['Disassembly'], final.sections[symbol['section']].name, address)
        end = '\r\n' if old.endswith('\r\n') else '\n' if old.endswith('\n') else ''
        if target is None:
            word = struct.unpack('<I', raw)[0]
            text = ' %x:\t%08x \t.word\t0x%08x\t%x: R_ARM_ABS32\t%s' % (
                address, word, word, address, slot_name)
        else:
            a, b = struct.unpack('<HH', raw)
            text = ' %x:\t%04x %04x \tbl\t%x <%s>\t%x: R_ARM_THM_CALL\t%s' % (
                address, a, b, target, callee_name, address, callee_name)
        patch('Disassembly', offset, (text + end).encode('utf-8'), length)

    if name == 'machine-nonrelocation-byte':
        offset = address_offset(machine, svc['section'], 0x54, 1)
        patch('Machine', offset, bytes([machine.data[offset] ^ 1]))
    elif name == 'machine-bl-addend':
        patch('Machine', address_offset(machine, pend['section'], 0xB4), helper.encode_bl(0xB4, 0xB8))
    elif name == 'machine-slot-addend':
        patch('Machine', address_offset(machine, svc['section'], 0x74), struct.pack('<I', 4))
    elif name in ('applied-slot-word', 'coherent-slot-in-bss'):
        target = slot['value'] - 4
        need(type(target) is int and 0 <= target < 1 << 32 and target % 4 == 0,
             'reference recipe preceding aligned slot address')
        selected = ((final_svc, 32), (final_pend, 64)) if name == 'coherent-slot-in-bss' else ((final_svc, 32),)
        for symbol, relative in selected:
            place = (symbol['value'] & ~1) + relative
            raw = struct.pack('<I', target)
            patch('Final', address_offset(final, symbol['section'], place), raw)
            if name == 'coherent-slot-in-bss':
                disassembly(symbol, place, raw)
        if name == 'coherent-slot-in-bss':
            peer = helper._symbol(final, 'ulMaxPRIGROUPValue')
            need(peer['kind'] == 'STT_OBJECT' and peer['binding'] == 'STB_LOCAL' and peer['size'] == 4
                 and peer['section'] == slot['section'] and peer['value'] == target,
                 'reference recipe fixed occupied neighboring BSS object')
            patch('Final', symbol_offset(final, peer, 4, 4), struct.pack('<I', slot['value']))
            patch('Final', symbol_offset(final, slot, 4, 4), struct.pack('<I', target))
    elif name == 'localized-slot':
        patch('Final', symbol_offset(final, slot, 12, 1), b'\x01')
    elif name == 'wrong-slot-named-target':
        wrong = helper._symbol(final, 'reference_failure_code')
        need(type(wrong['index']) is int and 0 <= wrong['index'] < 1 << 24,
             'reference recipe bounded named relocation target')
        offset = relocation_offset(final, final_svc['section'], (final_svc['value'] & ~1) + 32)
        patch('Final', offset + 4, struct.pack('<I', wrong['index'] << 8 | 2))
    elif name in ('function-alias', 'slot-object-alias'):
        target = helper._symbol(machine, slot_name) if name == 'slot-object-alias' else svc
        alias = helper._symbol(machine, 'reference_failure_code' if name == 'slot-object-alias'
                               else 'reference_reset_forbidden')
        need(alias['name'] != target['name'] and alias['kind'] == target['kind']
             and type(alias['section']) is int and 0 < alias['section'] < len(machine.sections)
             and type(target['section']) is int and 0 < target['section'] < len(machine.sections),
             'reference recipe unique defined alias role')
        patch('Machine', symbol_offset(machine, alias, 4, 8), struct.pack('<II', target['value'], 4))
        if alias['section'] != target['section']:
            patch('Machine', symbol_offset(machine, alias, 14, 2), struct.pack('<H', target['section']))
    elif name == 'code-without-execute':
        address = final_svc['value'] & ~1
        loads = [(index, row) for index, row in enumerate(final.elf.iter_segments())
                 if row.header.p_type == 'PT_LOAD'
                 and row.header.p_vaddr <= address < row.header.p_vaddr + row.header.p_memsz]
        need(len(loads) == 1 and loads[0][1].header.p_flags & 1, 'reference recipe actual executable load owner')
        index, row = loads[0]
        need(final.elf.header.e_phentsize == 32, 'reference recipe ELF32 program-header extent')
        offset = final.elf.header.e_phoff + index * final.elf.header.e_phentsize + 24
        patch('Final', offset, struct.pack('<I', row.header.p_flags & ~1))
    elif name == 'callee-data-mapping':
        callee = helper._symbol(machine, callee_name)
        rows = [row for row in machine.symbols if row['name'].split('.')[0] == '$t'
                and row['section'] == callee['section'] and row['value'] == (callee['value'] & ~1)]
        need(len(rows) == 1 and len(machine.tables) == 1, 'reference recipe exact callee code mapping')
        table = machine.sections[next(iter(machine.tables))]
        position = machine.sections[table.header.sh_link].data().find(b'\x00$d\x00')
        need(position >= 0, 'reference recipe existing raw data-mapping name')
        patch('Machine', symbol_offset(machine, rows[0], 0, 4), struct.pack('<I', position + 1))
    elif name == 'coherent-callee-entry':
        callee = helper._symbol(final, callee_name)
        need(callee['size'] == 12 and callee['value'] & 1, 'reference recipe fixed actual Thumb callee extent')
        target, place = (callee['value'] & ~1) + 2, (final_pend['value'] & ~1) + 28
        patch('Final', symbol_offset(final, callee, 4, 8), struct.pack('<II', callee['value'] + 2, callee['size'] - 2))
        raw = helper.encode_bl(place, target)
        patch('Final', address_offset(final, final_pend['section'], place), raw)
        disassembly(final_pend, place, raw, target)
    elif name in ('wrong-machine-section-size', 'foreign-map-provider'):
        text = buffers['LinkMap'].decode('utf-8')
        pattern = (r'(?m)^\s+\.text\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+('
                   + re.escape(str(paths['Machine'])) + r')\s*$')
        matches = list(re.finditer(pattern, text))
        need(len(matches) == 1, 'reference recipe unique full actual machine text placement')
        match = matches[0]
        group = 2 if name == 'wrong-machine-section-size' else 3
        need(int(match[2], 16) > 2, 'reference recipe positive machine placement extent')
        replacement = hex(int(match[2], 16) - 2) if group == 2 else 'C:/unbound-reference-lto-machine.o'
        offset = len(text[:match.start(group)].encode('utf-8'))
        patch('LinkMap', offset, replacement.encode('utf-8'), len(match[group].encode('utf-8')))
    elif name in ('missing-root-reference', 'extra-root-reference'):
        address, target = (0xB4, 0xDC) if name == 'missing-root-reference' else (0x20, 0x7C)
        patch('Machine', relocation_offset(machine, svc['section'], address), struct.pack('<I', target))
    return None


def _reference_coherence(name, core, helper, adapter, original, changed_final, disassembly_bytes):
    if name not in ('coherent-slot-in-bss', 'coherent-callee-entry'):
        return None
    roots = ('prvPortStartFirstTask', 'vPortSVCHandler', 'xPortPendSVHandler')
    slot_name, callee_name = 'pxCurrentTCB', 'vTaskSwitchContext'
    need(tuple(helper.ROOTS) == tuple(adapter.ROOTS) == roots
         and helper.SLOT == adapter.SLOT == slot_name and helper.CALLEE == adapter.CALLEE == callee_name,
         'reference coherence fixed helper and adapter')
    changed = changed_final
    need(type(changed.data) is bytes and type(disassembly_bytes) is bytes,
         'reference coherence actual parsed and dump buffers')
    need(changed.final is True and original.final.final is True, 'reference coherence actual final ELF objects')

    def field(elf, symbol, relative, size=4):
        need(type(symbol['section']) is int and 0 < symbol['section'] < len(elf.sections),
             'reference coherence bounded root section')
        place = (symbol['value'] & ~1) + relative
        offset = helper._address_offset(elf, symbol['section'], place, size)
        need(type(offset) is int and 0 <= offset and offset + size <= len(elf.data),
             'reference coherence complete file-backed field')
        return place, elf.data[offset:offset + size]

    if name == 'coherent-slot-in-bss':
        slot, old = helper._symbol(changed, slot_name), helper._symbol(original.final, slot_name)
        peer = helper._symbol(changed, 'ulMaxPRIGROUPValue')
        old_peer = helper._symbol(original.final, 'ulMaxPRIGROUPValue')
        need(type(slot['section']) is int and 0 < slot['section'] < len(changed.sections),
             'reference coherence bounded BSS section')
        h = changed.sections[slot['section']].header
        need(slot['kind'] == 'STT_OBJECT' and slot['binding'] == 'STB_GLOBAL' and slot['size'] == 4
             and slot['value'] == old['value'] - 4 and slot['value'] % 4 == 0
             and slot['section'] == old['section'] and h.sh_type == 'SHT_NOBITS'
             and peer['binding'] == 'STB_LOCAL' and peer['kind'] == 'STT_OBJECT' and peer['size'] == 4
             and peer['section'] == slot['section'] and peer['value'] == old['value']
             and old_peer['value'] == slot['value']
             and all(slot[key] == old[key] and peer[key] == old_peer[key]
                     for key in ('name', 'kind', 'binding', 'visibility', 'section', 'size', 'index')),
             'reference coherence exact BSS metadata swap')
        intervals = sorted((row['value'], row['value'] + row['size']) for row in changed.symbols
                           if row['kind'] == 'STT_OBJECT' and row['section'] == slot['section'] and row['size'] > 0)
        need(all(h.sh_addr <= a < b <= h.sh_addr + h.sh_size for a, b in intervals)
             and all(a[1] <= b[0] for a, b in zip(intervals, intervals[1:])),
             'reference coherence nonoverlapping BSS extents')
        loads = []
        for root, relative in ((roots[1], 32), (roots[2], 64)):
            symbol = helper._symbol(changed, root)
            need(symbol == helper._symbol(original.final, root), 'reference coherence unchanged slot-load root metadata')
            place, raw = field(changed, symbol, relative)
            shown, operation, operands = helper._dis_record(
                disassembly_bytes, changed.sections[symbol['section']].name, place)
            need(struct.unpack('<I', raw)[0] == slot['value'] and shown == raw
                 and operation == '.word' and int(operands, 16) == slot['value'],
                 'reference coherence both-slot-word and actual dump agreement')
            loads.append(dict(Root=root, RootRelativeOffset=relative, Bytes=raw.hex(), DisassemblyUpdated=True))
        return dict(Kind='SLOT-IN-BSS', OriginalAddress=old['value'], MutatedAddress=slot['value'],
                    Loads=loads, NeighborSwap=dict(Name='ulMaxPRIGROUPValue',
                        BeforeAddress=old_peer['value'], AfterAddress=peer['value']),
                    ImmutableOriginControlCoherenceChecked=True, ProviderSemanticsClaimed=False)

    callee, old = helper._symbol(changed, callee_name), helper._symbol(original.final, callee_name)
    pend = helper._symbol(changed, roots[2])
    need(pend == helper._symbol(original.final, roots[2]), 'reference coherence unchanged BL root metadata')
    need(type(callee['section']) is int and 0 < callee['section'] < len(changed.sections),
         'reference coherence bounded callee section')
    h = changed.sections[callee['section']].header
    target = callee['value'] & ~1
    place, raw = field(changed, pend, 28)
    form = core._address_form(raw, place)
    shown, operation, operands = helper._dis_record(
        disassembly_bytes, changed.sections[pend['section']].name, place)
    need(old['size'] == 12 and callee['value'] == old['value'] + 2 and callee['value'] & 1
         and callee['size'] == old['size'] - 2 and callee['size'] > 0
         and callee['kind'] == 'STT_FUNC' and callee['binding'] == 'STB_GLOBAL'
         and all(callee[key] == old[key] for key in ('name', 'kind', 'binding', 'visibility', 'section', 'index'))
         and h.sh_type == 'SHT_PROGBITS' and h.sh_addr <= target
         and target + callee['size'] <= h.sh_addr + h.sh_size
         and changed.mapping(callee['section'], target)[0] == 't'
         and form is not None and form[0] == 'bl' and form[1] == target
         and shown == raw and operation == 'bl' and operands.split()
         and int(operands.split()[0], 16) == target,
         'reference coherence actual callee BL bits and dump agreement')
    return dict(Kind='CALLEE-ENTRY', Name=callee_name, OriginalAddress=old['value'] & ~1,
                MutatedAddress=target, OriginalSize=old['size'], MutatedSize=callee['size'],
                Root=roots[2], RootRelativeOffset=28, BranchBytes=raw.hex(), DisassemblyUpdated=True,
                ImmutableOriginControlCoherenceChecked=True, ProviderSemanticsClaimed=False)
