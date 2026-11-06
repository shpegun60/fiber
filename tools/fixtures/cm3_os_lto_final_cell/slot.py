"""Pure fixed CM3 Os-LTO current-slot protocols; no helper loading or I/O.

The caller supplies the authenticated frozen cm3_lto_isolation.slot module.
Its origin, relocation and handler-address machinery is reused, not its O2
program table or inspect result. Six source-derived Os bodies retain every
guard, branch, call, store, alignment instruction and pool. Handler completeness
and source-to-machine equivalence remain separate obligations.
"""

import hashlib
import re
import struct


HELPER_SHA256 = '669F294A622B076984E36F6FA9C73235BD0D3F778AA4A36F496051D49DE822B3'
SLOT = 'fiber_internal_runtime_current_context_slot'
SECTION = '.bss.fiber_runtime_current_context_slot'
SCHEDULER = 'fiber_internal_runtime_scheduler_pick_next'
BARRIER = 'fiber_port_runtime_memory_barrier'
PUBLISHER = 'fiber_internal_runtime_publish_current_context'
HANDLERS = {'SVC_Handler': 0, 'PendSV_Handler': 1}
SCOPE = 'NATIVE_CM3_OS_LTO_MERGED_MACHINE_SECTION_MEDIATED_SLOT_ACCESSES_ONLY'
STATUS = 'CM3-OS-LTO-SLOT-ISOLATION-PASS-NOT-QUALIFIED'

# These are complete protocols of the fixed source operations under Os, not
# subsequences extracted from an output. Pool words retain their section roles.
PROGRAMS = {
    'fiber_internal_runtime_load_current_context': '''
push {r3,lr}
bl fiber_port_runtime_memory_barrier
ldr r3,pool
ldr r0,[r3]
pop {r3,pc}
align
pool:
word slot
''',
    'fiber_internal_runtime_context_configuration_is_open': '''
push {r3,lr}
bl fiber_port_runtime_memory_barrier
ldr r3,pool
ldr r2,[r3,#4]
cbnz r2,closed
ldr r2,pool+4
ldr r2,[r2]
cbnz r2,closed
ldr r3,[r3,#8]
cbnz r3,closed
bl fiber_port_runtime_memory_barrier
movs r0,#1
done:
pop {r3,pc}
closed:
bl fiber_port_runtime_memory_barrier
movs r0,#0
b done
align
pool:
word scheduler
word slot
''',
    'fiber_internal_runtime_select_scheduler_candidate': '''
push {r4,r5,r6,lr}
mov r5,r0
ldr r4,pool
cbnz r0,selected
ldr r3,pool+4
ldr r3,[r3]
cbz r3,checkfirst
already:
movs r0,#107
panic:
bl fiber_panic
checkfirst:
ldr r3,[r4,#8]
cmp r3,#0
bne already
ldr r3,[r4]
cbnz r3,begin
badpick:
movs r0,#75
b panic
begin:
bl fiber_port_runtime_memory_barrier
movs r3,#1
str r3,[r4,#8]
bl fiber_port_runtime_memory_barrier
selected:
ldr r6,[r4]
bl fiber_port_runtime_memory_barrier
ldr r1,[r4,#16]
cmp r6,#0
beq badpick
mov r0,r5
blx r6
cbnz r0,done
movs r0,#78
b panic
done:
pop {r4,r5,r6,pc}
align
pool:
word scheduler
word slot
''',
    PUBLISHER: '''
push {r4,lr}
mov r4,r0
cbnz r0,valid
movs r0,#78
bl fiber_panic
valid:
bl fiber_port_runtime_memory_barrier
ldr r3,pool
str r4,[r3]
pop {r4,lr}
b fiber_port_runtime_memory_barrier
align
pool:
word slot
''',
    'fiber_internal_runtime_require_current_context': '''
push {r3,lr}
bl fiber_port_runtime_memory_barrier
ldr r3,pool
ldr r3,[r3]
cbnz r3,present
movs r0,#71
bl fiber_panic
present:
pop {r3,lr}
b fiber_port_runtime_memory_barrier
align
pool:
word slot
''',
    'ctxrt_v1_set_dispatcher': '''
push {r4,r5,r6,lr}
mov r4,r0
mov r6,r1
bl fiber_port_require_scheduler_configuration_environment
ldr r3,pool
ldr r3,[r3]
cbz r3,checkfirst
already:
movs r0,#107
panic:
bl fiber_panic
checkfirst:
ldr r5,pool+4
ldr r3,[r5,#8]
cmp r3,#0
bne already
cbnz r4,valid
movs r0,#75
b panic
valid:
bl fiber_port_runtime_memory_barrier
str r6,[r5,#16]
bl fiber_port_runtime_memory_barrier
str r4,[r5]
pop {r4,r5,r6,lr}
b fiber_port_runtime_memory_barrier
align
pool:
word slot
word scheduler
''',
}
SIZES = dict(zip(PROGRAMS, (16, 48, 80, 32, 32, 64)))
REFERENCE_COUNTS = dict(zip(PROGRAMS, (2, 5, 6, 4, 4, 7)))
FALSE_FIELDS = (
    'CommonSourceOwnershipValidated', 'CompleteHandlerBodiesValidated',
    'ArbitraryPointerAliasProof', 'WholeProgramMemorySafetyProof',
    'FullSemanticABIProof', 'FullABIProof', 'SourceToMachineSemanticProof',
    'OriginalTranslationUnitOwnership', 'Qualification', 'CellContractSatisfied',
    'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified', 'RequiredCellSatisfied',
)


class Rejected(ValueError):
    pass


def need(value, message):
    if not value:
        raise Rejected('REJECT:CM3-OS-LTO-SLOT:' + message)


def sha(raw):
    need(type(raw) is bytes, 'immutable bytes')
    return hashlib.sha256(raw).hexdigest().upper()


def _program(text, h, aliases=None):
    """Small complete protocol grammar; BEQ is preserved, never normalized away."""
    rows, labels, position = [], {}, 0
    for line in text.splitlines():
        line = line.split('@', 1)[0].strip()
        if not line or line in ('.syntax unified', '.thumb'):
            continue
        if line.endswith(':'):
            label = line[:-1].lower()
            need(re.fullmatch(r'[.A-Za-z_][.A-Za-z0-9_]*', label) and label not in labels,
                 'unique complete protocol label')
            labels[label] = position
            continue
        if re.fullmatch(r'(?:align|\.align\s+2)', line):
            rows.append((position, 'align', ''))
            position = (position + 3) & ~3
            continue
        parts = line.split(None, 1)
        need(len(parts) == 2, 'complete generated statement')
        op, args = parts[0], h.normalized(parts[1])
        if op == '.word':
            need(aliases is not None and args in aliases, 'exact section-alias pool operand')
            op, args = 'word', aliases[args]
        if op == 'word':
            need(args in ('slot', 'scheduler'), 'fixed pool role')
            width = 4
        elif op == 'ldr' and '[' not in args:
            op, width = 'literal', 2
        elif op == 'bl' or op == 'b' and args.startswith('fiber_'):
            width = 4
        elif op in ('b', 'beq', 'bne', 'cbz', 'cbnz'):
            width = 2
        else:
            width = len(h._fixed(op, args))
        rows.append((position, op, args))
        position += width
    resolved = []
    for offset, op, args in rows:
        if op == 'literal':
            register, expression = args.split(',', 1)
            match = re.fullmatch(r'([.A-Za-z_][.A-Za-z0-9_]*)(?:\+([0-9]+))?', expression)
            need(match and match[1] in labels, 'complete local literal label')
            args = register, labels[match[1]] + int(match[2] or 0)
        elif op in ('cbz', 'cbnz') or op in ('b', 'beq', 'bne') and args in labels:
            register, label = args.split(',', 1) if op in ('cbz', 'cbnz') else ('', args)
            need(label in labels, 'complete local branch label')
            args = register, labels[label]
        else:
            need(op not in ('beq', 'bne'), 'conditional target must be local')
        resolved.append((offset, op, args))
    return resolved, position


def _local_branch(h, op, args, offset):
    if op != 'beq':
        return h._local_branch(op, args, offset)
    register, target = args
    delta = target - offset - 4
    need(register == '' and delta % 2 == 0 and -256 <= delta <= 254,
         'bounded exact T16 BEQ')
    return struct.pack('<H', 0xD000 | (delta >> 1 & 255))


def _assembly(raw, h):
    text = raw.decode('ascii')
    definition = re.compile(r'(?m)^\s*\.section\s+' + re.escape(SECTION)
        + r',"aw",%nobits\s*\n\s*\.align\s+2\s*\n\s*\.set\s+(?P<alias>\.LANCHOR[0-9]+),\.\s*\+\s*0\s*\n'
        + r'\s*\.type\s+' + SLOT + r',\s*%object\s*\n\s*\.size\s+' + SLOT + r',\s*4\s*\n'
        + SLOT + r':\s*\n\s*\.space\s+4\s*(?=\n\s*\.section)')
    definitions = list(definition.finditer(text))
    need(len(definitions) == 1, 'one dedicated generated four-byte slot')
    alias = definitions[0]['alias']
    scheduler = re.findall(r'(?m)^\s*\.bss\s*\n\s*\.align\s+[0-9]+\s*\n\s*\.set\s+'
        r'(\.LANCHOR[0-9]+),\.\s*\+\s*0\s*\n\s*\.type\s+' + SCHEDULER + r',\s*%object', text)
    need(len(scheduler) == 1 and scheduler[0] != alias, 'distinct scheduler section alias')
    aliases = {alias.lower(): 'slot', scheduler[0].lower(): 'scheduler'}
    programs, generated, spans = {}, [], [definitions[0].span()]
    for name in (*PROGRAMS, *HANDLERS):
        starts = list(re.finditer(r'(?m)^' + name + r':\s*$', text))
        ends = list(re.finditer(r'(?m)^\s*\.size\s+' + name + r',\s*\.-' + name + r'\s*$', text))
        need(len(starts) == len(ends) == 1 and starts[0].end() < ends[0].start(),
             'one complete generated body: ' + name)
        body = text[starts[0].end():ends[0].start()]
        if name in PROGRAMS:
            expected = _program(PROGRAMS[name], h)
            need(_program(body, h, aliases) == expected,
                 'complete Os generated common protocol: ' + name)
            programs[name] = expected
            for match in re.finditer(r'(?m)^\s*\.word\s+' + re.escape(alias) + r'\s*$', body):
                spans.append((starts[0].end() + match.start(), starts[0].end() + match.end()))
        else:
            register = 'r' + str(HANDLERS[name])
            pairs = list(re.finditer(r'(?m)^[ \t]*ldr[ \t]+' + register + r',[ \t]*=' + SLOT
                + r'[ \t]*\r?\n[ \t]*ldr[ \t]+' + register + r',[ \t]*\[' + register + r'\][ \t]*\r?$', body))
            need(len(pairs) == 1, 'one immediate generated handler slot pair: ' + name)
            begin, end = starts[0].end() + pairs[0].start(), starts[0].end() + pairs[0].end()
            spans.append((begin, end))
            generated.append(dict(Owner=name, Register=register,
                                  GeneratedLine=text.count('\n', 0, begin) + 1))
    for token in (SLOT, alias):
        mentions = re.finditer(r'(?<![A-Za-z0-9_.])' + re.escape(token) + r'(?![A-Za-z0-9_])', text)
        need(all(any(start <= row.start() < row.end() <= end for start, end in spans) for row in mentions),
             'unclassified generated slot address, alias or escape')
    need(len(re.findall(r'(?m)^\s*\.set\s+' + re.escape(alias) + r',', text)) == 1,
         'unique generated slot alias')
    return programs, generated, alias


def _common(audit, name, program, h):
    """Complete BEQ-containing body, using the same explicit frozen primitives."""
    origin = audit.origin(name)
    rows, size = program
    need(origin['Size'] == size and origin['SymbolOffset'] % 4 == origin['Entry'] % 4 == 0,
         'complete aligned Os common body')
    used, addresses, references = set(), set(), []
    for offset, op, args in rows:
        addresses.add(origin['Entry'] + offset)
        if op == 'word':
            definition = audit.slot if args == 'slot' else audit.scheduler
            ref = audit.reference(origin, offset, 2, definition, section_target=True)
            references.append(ref)
            used.add(origin['SymbolOffset'] + offset)
            audit.record(origin, offset, bytes.fromhex(ref['FinalBytes']), data=True)
            continue
        if op in ('bl', 'b') and type(args) is str:
            references.append(audit.reference(origin, offset, 10 if op == 'bl' else 30, audit.origin(args)))
            used.add(origin['SymbolOffset'] + offset)
            continue
        if op == 'align':
            count = (-offset) % 4
            if count:
                need(count == 2, 'exact alignment size')
                before, after = audit.bytes(origin, offset, count, 't')
                need(before == after == b'\x00\xbf', 'retained alignment NOP')
                audit.record(origin, offset, after, 'nop', '')
            continue
        if op == 'literal':
            register, target = args
            delta = target - ((offset + 4) & ~3)
            need(re.fullmatch(r'r[0-7]', register) and delta % 4 == 0 and 0 <= delta <= 1020,
                 'exact narrow literal load')
            expected = struct.pack('<H', 0x4800 | int(register[1:]) << 8 | delta // 4)
        elif type(args) is tuple:
            expected = _local_branch(h, op, args, offset)
        else:
            expected = h._fixed(op, args)
        before, after = audit.bytes(origin, offset, len(expected), 't')
        need(before == after == expected and audit.core._width(struct.unpack_from('<H', before)[0]) == len(expected),
             'exact Os source-derived instruction encoding')
        display_op, display_args = op, args
        if op == 'pop' and args.endswith('lr}'):
            display_op, display_args = 'ldmia', 'sp!,' + args
        if op == 'literal':
            display_op, display_args = 'ldr', None
        elif type(args) is tuple:
            display_args = None
        audit.record(origin, offset, after, display_op, display_args)
        if op == 'literal':
            form = audit.core._address_form(after, origin['Entry'] + offset)
            need(form is not None and form[:3] == ('ldr', origin['Entry'] + args[1], int(args[0][1:])),
                 'literal bits bind complete local pool')
    for elf, section, start in ((audit.machine, origin['InputSectionIndex'], origin['SymbolOffset']),
                               (audit.final, origin['OutputSectionIndex'], origin['OutputSectionOffset'])):
        actual = {offset for sec, offset in elf.relocations if sec == section and start <= offset < start + size}
        expected = {at - origin['SymbolOffset'] + start for at in used} if not elf.final or audit.emitted else set()
        need(actual == expected, 'complete Os body relocation membership')
    need(not any(sec == origin['OutputSectionIndex'] and origin['Entry'] <= at < origin['Entry'] + size
                 and at not in addresses for sec, at in audit.image.instructions),
         'unclassified Os body disassembly record')
    before = h._bytes(audit.machine, origin['InputSectionIndex'], origin['SymbolOffset'], size)
    after = h._bytes(audit.final, origin['OutputSectionIndex'], origin['OutputSectionOffset'], size)
    return dict(Name=name, Origin=origin, MachineBodySha256=sha(before), FinalBodySha256=sha(after),
                CompleteBodyValidated=True, Size=size, References=references, TailNops=0)


def _audit_type(h, pool_count):
    class OsAudit(h.Audit):
        def common(self, name, program):
            if any(op == 'beq' for _, op, _ in program[0]):
                return _common(self, name, program, h)
            return super().common(name, program)

        def slot_word_positions(self):
            machine_words, final_words = set(), set()
            for (section, offset), (kind, target) in self.machine.relocations.items():
                h._raw_target(self.machine, target)
                if target['section'] != self.slot['InputSectionIndex'] and target['name'] != SLOT:
                    continue
                need(type(kind) is int and kind == 2, 'only ABS32 slot-bearing words')
                h.integer(section, 'slot word section', 1)
                h.integer(offset, 'slot word offset')
                need(section < len(self.machine.sections), 'slot word section bounds')
                source = self.machine.sections[section]
                header = source.header
                placement = self.image.placements.get((self.slot['Provider'], source.name))
                need(type(placement) is tuple and len(placement) == 2 and all(type(v) is int for v in placement)
                     and header.sh_addr == 0 and placement[1] == header.sh_size
                     and placement[0] % max(1, header.sh_addralign) == 0
                     and offset % 4 == 0 and offset + 4 <= header.sh_size
                     and sum(row.name == source.name for row in self.machine.sections) == 1,
                     'whole input-section authority for every Os slot word')
                address = placement[0] + offset
                outputs = [(index, row) for index, row in enumerate(self.final.sections)
                           if row.header.sh_flags & 2 and row.header.sh_addr <= placement[0]
                           and placement[0] + placement[1] <= row.header.sh_addr + row.header.sh_size]
                need(len(outputs) == 1, 'unique complete output slot-word placement')
                output, last = outputs[0]
                need(header.sh_type == last.header.sh_type == 'SHT_PROGBITS'
                     and header.sh_flags & 7 == last.header.sh_flags & 7,
                     'slot word storage agreement')
                h._mapped(self.machine, section, offset, 4, 'd')
                h._mapped(self.final, output, address, 4, 'd')
                need(h._bytes(self.machine, section, offset, 4) == bytes(4)
                     and h._bytes(self.final, output, address - last.header.sh_addr, 4)
                     == struct.pack('<I', self.slot['Entry']), 'original zero addend and exact applied slot value')
                machine_words.add((section, offset))
                need(address not in final_words, 'slot word placements cannot alias')
                final_words.add(address)
            need(len(machine_words) == len(final_words) == pool_count,
                 'complete Os protocol-derived slot-word domain')
            return machine_words, final_words

        def all_slot_references(self):
            found = set()
            for owner, elf in self.image.providers.items():
                for key, (kind, target) in elf.relocations.items():
                    h._raw_target(elf, target)
                    section = target['section']
                    touches = target['name'] == SLOT or type(section) is int and 0 < section < len(elf.sections) \
                        and elf.sections[section].name == SECTION
                    if touches:
                        need(owner == self.slot['Provider'] and type(kind) is int and kind == 2,
                             'no foreign or non-ABS32 slot reference')
                        found.add(key)
            need(found == self.expected_slot and len(found) == pool_count,
                 'all Os original slot references, no unclassified escapes')
            actual = set()
            for key, (kind, target) in self.final.relocations.items():
                h._raw_target(self.final, target)
                if target['section'] == self.slot['OutputSectionIndex'] or target['name'] == SLOT:
                    need(type(kind) is int and kind == 2, 'only supported applied BSS reference kinds')
                    value = struct.unpack('<I', h._bytes(self.final, key[0], key[1], 4))[0]
                    if self.slot['Entry'] <= value < self.slot['Entry'] + 4:
                        actual.add(key)
            expected = set()
            for name in (*PROGRAMS, *HANDLERS):
                origin = self.origin(name)
                for section, offset in found:
                    if section == origin['InputSectionIndex'] and origin['SymbolOffset'] <= offset \
                            < origin['SymbolOffset'] + origin['Size']:
                        expected.add((origin['OutputSectionIndex'], origin['OutputSectionOffset']
                                      + offset - origin['SymbolOffset']))
            need(len(expected) == pool_count and actual == (expected if self.emitted else set()),
                 'complete applied Os slot-reference membership')
    return OsAudit


def inspect(image, core, slot_helpers, *, port_source, assembly, emit_relocs=True):
    """Use caller-authenticated images, source buffers and the frozen helper.

    No parser, module, source file or physical identity is loaded here. Helper
    bytes must be authenticated by the enclosing immutable reader environment.
    """
    need(type(port_source) is bytes and type(assembly) is bytes and type(emit_relocs) is bool,
         'literal buffers and emitted selector')
    h = slot_helpers
    need(h.SLOT == SLOT and h.SECTION == SECTION and h.SCHEDULER == SCHEDULER
         and h.HANDLERS == HANDLERS, 'fixed helper symbol contract')
    try:
        source_pairs = h._port_source(port_source)
        programs, generated, alias = _assembly(assembly, h)
        need({name: value[1] for name, value in programs.items()} == SIZES, 'fixed Os body extents')
        pool_count = sum(op == 'word' and args == 'slot' for rows, _ in programs.values()
                         for _, op, args in rows) + len(HANDLERS)
        need(all(sum(op == 'word' and args == 'slot' for _, op, args in rows) == 1
                 for rows, _ in programs.values()), 'one slot word per complete Os common body')
        audit = _audit_type(h, pool_count)(image, core, emit_relocs)
        bodies = [audit.common(name, programs[name]) for name in PROGRAMS]
        handlers = audit.handlers()
        audit.all_slot_references()
    except h.Rejected as error:
        raise Rejected('REJECT:CM3-OS-LTO-SLOT:frozen primitive: ' + str(error)) from error
    except UnicodeError as error:
        raise Rejected('REJECT:CM3-OS-LTO-SLOT:ASCII source and assembly') from error
    proof = dict(Status=STATUS, Scope=SCOPE, Profile='CM3', Mode='Os-lto', Linkage='direct',
        EmitRelocs=emit_relocs, SlotIsolationValidated=True, SlotOrigin=audit.slot, SlotAlias=alias,
        SourceSha256=sha(port_source), AssemblySha256=sha(assembly),
        MachineSha256=sha(image.prelink.data), FinalSha256=sha(image.final.data), LinkMapSha256=image.link_map_hash,
        HandlerLoadPairs=2, HandlerLoads=handlers, SourcePairs=source_pairs, GeneratedPairs=generated,
        ClosedCommonBodies=6, CommonBodies=bodies, CommonBytes=sum(SIZES.values()),
        CommonLoads=5, CommonStores=1, Publisher=PUBLISHER,
        SlotReferences=pool_count, AppliedSlotReferences=pool_count if emit_relocs else 0,
        RawSectionSymbolsPreserved=True, AllSectionMediatedSlotReferencesValidated=True,
        RequiredCellsSatisfied=0)
    proof.update({name: False for name in FALSE_FIELDS})
    return require_result(proof, emit_relocs=emit_relocs)


def require_result(proof, *, emit_relocs=True):
    """Validate this leaf's returned shape; not a substitute for recomputation."""
    need(type(proof) is dict and type(emit_relocs) is bool, 'literal result and selector')
    for key, value in (('Status', STATUS), ('Scope', SCOPE), ('Profile', 'CM3'),
                       ('Mode', 'Os-lto'), ('Linkage', 'direct'), ('Publisher', PUBLISHER)):
        need(type(proof.get(key)) is str and proof[key] == value, 'fixed result/' + key)
    for key, value in (('ClosedCommonBodies', 6), ('CommonBytes', 272), ('HandlerLoadPairs', 2),
                       ('CommonLoads', 5), ('CommonStores', 1), ('SlotReferences', 8),
                       ('AppliedSlotReferences', 8 if emit_relocs else 0), ('RequiredCellsSatisfied', 0)):
        need(type(proof.get(key)) is int and proof[key] == value, 'literal result count/' + key)
    need(proof.get('EmitRelocs') is emit_relocs, 'literal emitted result')
    for key in ('SlotIsolationValidated', 'RawSectionSymbolsPreserved', 'AllSectionMediatedSlotReferencesValidated'):
        need(proof.get(key) is True, 'required result fact/' + key)
    for key in FALSE_FIELDS:
        need(proof.get(key) is False, 'bounded nonclaim/' + key)
    for key in ('SourceSha256', 'AssemblySha256', 'MachineSha256', 'FinalSha256', 'LinkMapSha256'):
        need(type(proof.get(key)) is str and re.fullmatch('[0-9A-F]{64}', proof[key]), 'raw hash/' + key)
    need(type(proof.get('SlotAlias')) is str and re.fullmatch(r'\.LANCHOR[0-9]+', proof['SlotAlias']),
         'generated slot alias')
    slot = proof.get('SlotOrigin')
    need(type(slot) is dict and slot.get('Name') == SLOT, 'nonempty own slot origin')
    for key, value in (('Size', 4), ('SectionSize', 4), ('SymbolOffset', 0)):
        need(type(slot.get(key)) is int and slot[key] == value, 'slot extent/' + key)
    bodies = proof.get('CommonBodies')
    need(type(bodies) is list and len(bodies) == 6 and [row.get('Name') for row in bodies
         if type(row) is dict] == list(PROGRAMS), 'exact six ordered common bodies')
    for row in bodies:
        name = row['Name']
        need(row.get('CompleteBodyValidated') is True and type(row.get('TailNops')) is int
             and row['TailNops'] == 0 and type(row.get('Size')) is int and row['Size'] == SIZES[name],
             'complete fixed common body/' + name)
        need(type(row.get('Origin')) is dict and row['Origin'].get('Name') == name,
             'own complete common origin/' + name)
        for key in ('MachineBodySha256', 'FinalBodySha256'):
            need(type(row.get(key)) is str and re.fullmatch('[0-9A-F]{64}', row[key]), 'body hash/' + name)
        refs = row.get('References')
        need(type(refs) is list and len(refs) == REFERENCE_COUNTS[name], 'complete common references/' + name)
        for ref in refs:
            _require_reference(ref, name, emit_relocs)
        need(sum(ref['Target'] == SLOT and ref['Kind'] == 2 for ref in refs) == 1,
             'one declared common slot reference/' + name)
    handlers = proof.get('HandlerLoads')
    need(type(handlers) is list and len(handlers) == 2 and [row.get('Owner') for row in handlers
         if type(row) is dict] == list(HANDLERS), 'exact two handler load records')
    for row in handlers:
        name = row['Owner']
        _require_reference(row, name, emit_relocs)
        need(row['Kind'] == 2 and row['Target'] == SLOT and row.get('Register') == 'r' + str(HANDLERS[name]),
             'exact handler slot load role')
        for key, value in (('MachineLiteralLoads', 1), ('FinalLiteralLoads', 1), ('SlotBearingWordsCensused', 8)):
            need(type(row.get(key)) is int and row[key] == value, 'both-stream handler count/' + key)
        need(type(row.get('LoadOffset')) is int and row['LoadOffset'] >= 0
             and type(row.get('DereferenceOffset')) is int and row['DereferenceOffset'] == row['LoadOffset'] + 2,
             'immediate load-only handler pair')
        for key in ('BothInstructionStreamsCensused', 'UnsupportedPCAddressFormsRejected', 'CrossOwnerSlotLiteralUsesRejected'):
            need(row.get(key) is True, 'complete handler census/' + key)
    source, generated = proof.get('SourcePairs'), proof.get('GeneratedPairs')
    need(type(source) is list and len(source) == 2 and all(type(row) is dict for row in source)
         and {row.get('Register') for row in source} == {'r0', 'r1'}, 'two source inline pairs')
    need(type(generated) is list and len(generated) == 2 and all(type(row) is dict for row in generated)
         and [row.get('Owner') for row in generated] == list(HANDLERS), 'two generated inline pairs')
    return proof


def _require_reference(ref, owner, emitted):
    need(type(ref) is dict and ref.get('Owner') == owner, 'own reference record')
    need(type(ref.get('Kind')) is int and ref['Kind'] in (2, 10, 30), 'supported reference kind')
    for key in ('FunctionOffset', 'InputSectionIndex', 'InputOffset', 'Address'):
        need(type(ref.get(key)) is int and 0 <= ref[key] <= 0xFFFFFFFF, 'reference integer/' + key)
    need(type(ref.get('Target')) is str and bool(ref['Target']), 'named reference role')
    for key in ('OriginalBytes', 'FinalBytes'):
        need(type(ref.get(key)) is str and re.fullmatch('[0-9a-f]{8}', ref[key]), 'complete reference raw bytes')
    need(type(ref.get('OriginalRelocationSymbol')) is dict and bool(ref['OriginalRelocationSymbol']),
         'original raw relocation symbol')
    need((type(ref.get('FinalRelocationSymbol')) is dict and bool(ref['FinalRelocationSymbol']))
         if emitted else ref.get('FinalRelocationSymbol') is None, 'applied raw relocation symbol selector')
