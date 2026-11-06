"""Synthetic Os slot protocol controls. No ELF parsing, tools or target code."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import tempfile
import traceback
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
SUBJECT = HERE / 'slot.py'
HELPER = HERE.parent / 'cm3_lto_isolation' / 'slot.py'
HELPER_SHA = '669F294A622B076984E36F6FA9C73235BD0D3F778AA4A36F496051D49DE822B3'
SLOT = 'fiber_internal_runtime_current_context_slot'
SECTION = '.bss.fiber_runtime_current_context_slot'
SCHEDULER = 'fiber_internal_runtime_scheduler_pick_next'
BARRIER = 'fiber_port_runtime_memory_barrier'
PUBLISHER = 'fiber_internal_runtime_publish_current_context'
HANDLERS = {'SVC_Handler': 0, 'PendSV_Handler': 1}
METHODS = 16
subject = helper = None

# An independently transcribed synthetic fixture, not the reader's program
# table. Labels deliberately differ. No compiled output supplies expected bytes.
EXPECTED = {
    'fiber_internal_runtime_load_current_context': '''
push {r3,lr}; bl fiber_port_runtime_memory_barrier
ldr r3,words; ldr r0,[r3]; pop {r3,pc}; align
words:; word slot
''',
    'fiber_internal_runtime_context_configuration_is_open': '''
push {r3,lr}; bl fiber_port_runtime_memory_barrier
ldr r3,words; ldr r2,[r3,#4]; cbnz r2,no
ldr r2,words+4; ldr r2,[r2]; cbnz r2,no
ldr r3,[r3,#8]; cbnz r3,no
bl fiber_port_runtime_memory_barrier; movs r0,#1
out:; pop {r3,pc}
no:; bl fiber_port_runtime_memory_barrier; movs r0,#0; b out; align
words:; word scheduler; word slot
''',
    'fiber_internal_runtime_select_scheduler_candidate': '''
push {r4,r5,r6,lr}; mov r5,r0; ldr r4,words; cbnz r0,pick
ldr r3,words+4; ldr r3,[r3]; cbz r3,first
closed:; movs r0,#107
die:; bl fiber_panic
first:; ldr r3,[r4,#8]; cmp r3,#0; bne closed
ldr r3,[r4]; cbnz r3,start
bad:; movs r0,#75; b die
start:; bl fiber_port_runtime_memory_barrier
movs r3,#1; str r3,[r4,#8]; bl fiber_port_runtime_memory_barrier
pick:; ldr r6,[r4]; bl fiber_port_runtime_memory_barrier
ldr r1,[r4,#16]; cmp r6,#0; beq bad
mov r0,r5; blx r6; cbnz r0,out; movs r0,#78; b die
out:; pop {r4,r5,r6,pc}; align
words:; word scheduler; word slot
''',
    PUBLISHER: '''
push {r4,lr}; mov r4,r0; cbnz r0,ok; movs r0,#78; bl fiber_panic
ok:; bl fiber_port_runtime_memory_barrier; ldr r3,words; str r4,[r3]
pop {r4,lr}; b fiber_port_runtime_memory_barrier; align
words:; word slot
''',
    'fiber_internal_runtime_require_current_context': '''
push {r3,lr}; bl fiber_port_runtime_memory_barrier; ldr r3,words
ldr r3,[r3]; cbnz r3,ok; movs r0,#71; bl fiber_panic
ok:; pop {r3,lr}; b fiber_port_runtime_memory_barrier; align
words:; word slot
''',
    'ctxrt_v1_set_dispatcher': '''
push {r4,r5,r6,lr}; mov r4,r0; mov r6,r1
bl fiber_port_require_scheduler_configuration_environment
ldr r3,words; ldr r3,[r3]; cbz r3,first
closed:; movs r0,#107
die:; bl fiber_panic
first:; ldr r5,words+4; ldr r3,[r5,#8]; cmp r3,#0; bne closed
cbnz r4,ok; movs r0,#75; b die
ok:; bl fiber_port_runtime_memory_barrier; str r6,[r5,#16]
bl fiber_port_runtime_memory_barrier; str r4,[r5]; pop {r4,r5,r6,lr}
b fiber_port_runtime_memory_barrier; align
words:; word slot; word scheduler
''',
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def parse_fixture(text):
    labels, rows, offset = {}, [], 0
    for statement in text.replace(';', '\n').splitlines():
        statement = statement.strip()
        if not statement:
            continue
        if statement.endswith(':'):
            labels[statement[:-1]] = offset
            continue
        if statement == 'align':
            rows.append((offset, 'align', ''))
            offset = (offset + 3) // 4 * 4
            continue
        op, args = statement.split(None, 1)
        args = re.sub(r'\s+', '', args).replace('[r3]', '[r3,#0]').replace('[r4]', '[r4,#0]')
        args = args.replace('[r2]', '[r2,#0]').replace('[r5]', '[r5,#0]')
        if op == 'word' or op == 'bl' or op == 'b' and args.startswith('fiber_'):
            size = 4
        elif op == 'pop' and args.endswith('lr}'):
            size = 4
        else:
            size = 2
        rows.append((offset, op, args))
        offset += size
    resolved = []
    for at, op, args in rows:
        if op == 'ldr' and '[' not in args:
            reg, expression = args.split(',')
            label, _, plus = expression.partition('+')
            op, args = 'literal', (reg, labels[label] + int(plus or 0))
        elif op in ('cbz', 'cbnz'):
            reg, label = args.split(',')
            args = reg, labels[label]
        elif op in ('b', 'beq', 'bne') and args in labels:
            args = '', labels[args]
        resolved.append((at, op, args))
    return resolved, offset


def local_encoding(op, args, at):
    reg, target = args
    delta = target - at - 4
    if op in ('cbz', 'cbnz'):
        word = 0xB100 + (0x800 if op == 'cbnz' else 0) + ((delta & 64) << 3) \
            + ((delta & 62) << 2) + int(reg[1:])
    elif op in ('beq', 'bne'):
        word = (0xD000 if op == 'beq' else 0xD100) | (delta // 2 & 255)
    else:
        word = 0xE000 | (delta // 2 & 2047)
    return struct.pack('<H', word)


class Elf:
    def __init__(self, final=False):
        self.final, self.data = final, bytes(0x4000)
        self.symbols, self.relocations, self.mappings = [], {}, {}
        def section(name, addr, size, flags=6, kind='SHT_PROGBITS', offset=0x100):
            return SimpleNamespace(name=name, header=SimpleNamespace(sh_addr=addr, sh_size=size,
                sh_flags=flags, sh_type=kind, sh_offset=offset, sh_addralign=4))
        self.sections = [section('', 0, 0, 0),
            section('.text', 0x1000 if final else 0, 0x1010 if final else 0x1000),
            section('.bss', 0x20000000 if final else 0, 24 if final else 20, 3, 'SHT_NOBITS')]
        if not final:
            self.sections.extend((section(SECTION, 0, 4, 3, 'SHT_NOBITS'),
                                  section('.text.ctxrt_api_thread', 0, 16, offset=0x1200)))
        self.loads = [dict(Vaddr=0x1000, MemorySize=0x1010, FileSize=0x1010, Flags=5),
                      dict(Vaddr=0x20000000, MemorySize=24, FileSize=0, Flags=6)] if final else []
        for index, item in enumerate(self.sections[1:], 1):
            self.add('', index, item.header.sh_addr if final else 0, 0, 'STT_SECTION', 'STB_LOCAL')

    def add(self, name, section, value, size, kind='STT_FUNC', binding='STB_GLOBAL'):
        row = dict(name=name, section=section, value=value, size=size, kind=kind,
                   binding=binding, visibility='STV_DEFAULT', index=len(self.symbols))
        self.symbols.append(row)
        return row

    def symbol(self, name):
        return next(row for row in self.symbols if row['name'] == name)

    def section_symbol(self, section):
        return next(row for row in self.symbols if row['section'] == section and row['kind'] == 'STT_SECTION')

    def write(self, section, offset, raw):
        start = self.sections[section].header.sh_offset + offset
        self.data = self.data[:start] + raw + self.data[start + len(raw):]

    def mapping(self, section, address):
        before = [at for sec, at in self.mappings if sec == section and at <= address]
        after = [at for sec, at in self.mappings if sec == section and at > address]
        end = min(after) if after else self.sections[section].header.sh_addr + self.sections[section].header.sh_size
        if not before:
            raise AssertionError('synthetic missing mapping')
        return self.mappings[section, max(before)], end


class Fixture:
    def __init__(self, emitted=True):
        self.emitted, self.machine, self.final = emitted, Elf(), Elf(True)
        self.programs = {name: parse_fixture(text) for name, text in EXPECTED.items()}
        self.locations, cursor = {}, 0
        for index, (name, (_, size)) in enumerate(self.programs.items()):
            section, offset, entry = (4, 0, 0x2000) if index == 0 else (1, cursor, 0x1000 + cursor)
            self.locations[name] = section, offset, entry
            self.machine.add(name, section, offset | 1, size)
            self.final.add(name, 1, entry | 1, size)
            if index:
                cursor = (cursor + size + 3) & ~3
        for name in (*HANDLERS, BARRIER, 'fiber_panic', 'fiber_port_require_scheduler_configuration_environment'):
            size = 16 if name in HANDLERS else 2
            self.locations[name] = 1, cursor, 0x1000 + cursor
            self.machine.add(name, 1, cursor | 1, size)
            self.final.add(name, 1, (0x1000 + cursor) | 1, size)
            cursor = (cursor + size + 3) & ~3
        self.machine.add(SLOT, 3, 0, 4, 'STT_OBJECT', 'STB_LOCAL')
        self.final.add(SLOT, 2, 0x20000014, 4, 'STT_OBJECT', 'STB_LOCAL')
        self.machine.add(SCHEDULER, 2, 0, 4, 'STT_OBJECT', 'STB_LOCAL')
        self.final.add(SCHEDULER, 2, 0x20000000, 4, 'STT_OBJECT', 'STB_LOCAL')
        self.image = SimpleNamespace(prelink=self.machine, final=self.final,
            providers={'machine.o': self.machine}, placements={('machine.o', '.text'): (0x1000, 0x1000),
            ('machine.o', '.text.ctxrt_api_thread'): (0x2000, 16),
            ('machine.o', '.bss'): (0x20000000, 20), ('machine.o', SECTION): (0x20000014, 4)},
            instructions={}, link_map_hash='A' * 64)
        self.core = SimpleNamespace(_width=lambda word: 4 if word >> 11 in (29, 30, 31) else 2,
                                    _address_form=self.address_form)
        self.source = ('"ldr r0, =' + SLOT + ' \\n" "ldr r0, [r0] \\n"\n'
                       '"ldr r1, =' + SLOT + ' \\n" /* pair */ "ldr r1, [r1] \\n"').encode('ascii')
        parts = []
        for name, text in EXPECTED.items():
            body = text.replace(';', '\n').replace('word slot', '.word .LANCHOR0')
            body = body.replace('word scheduler', '.word .LANCHOR1').replace('align\n', '.align 2\n')
            parts.append(name + ':\n' + body + '.size ' + name + ', .-' + name + '\n')
            for offset, op, args in self.programs[name][0]:
                self.statement(name, offset, op, args)
        for name, reg in HANDLERS.items():
            parts.append(name + ':\nldr r%d, =' % reg + SLOT
                         + '\nldr r%d, [r%d]\n.size ' % (reg, reg) + name + ', .-' + name + '\n')
            self.put(name, 0, struct.pack('<H', 0x4802 | reg << 8), 'ldr', 'r%d,[pc,#8]' % reg)
            self.put(name, 2, struct.pack('<H', 0x6800 | reg << 3 | reg), 'ldr', 'r%d,[r%d,#0]' % (reg, reg))
            for at in (4, 6, 8, 10):
                self.put(name, at, b'\x00\xbf', 'nop', '')
            self.statement(name, 12, 'word', 'slot')
        parts.append('.bss\n.align 2\n.set .LANCHOR1,. + 0\n.type ' + SCHEDULER + ',%object\n')
        parts.append('.section ' + SECTION + ',"aw",%nobits\n.align 2\n.set .LANCHOR0,. + 0\n.type '
                     + SLOT + ',%object\n.size ' + SLOT + ',4\n' + SLOT + ':\n.space 4\n.section .other,"a"\n')
        self.assembly = ''.join(parts).encode('ascii')

    @staticmethod
    def address_form(raw, place):
        word = struct.unpack('<H', raw)[0]
        if word & 0xF800 == 0x4800:
            delta = (word & 255) * 4
            return 'ldr', ((place + 4) & ~3) + delta, (word >> 8) & 7, delta
        return None

    def put(self, owner, offset, before, op, args, after=None, data=False):
        section, start, entry = self.locations[owner]
        after = before if after is None else after
        self.machine.write(section, start + offset, before)
        self.final.write(1, entry - 0x1000 + offset, after)
        self.machine.mappings[section, start + offset] = 'd' if data else 't'
        self.final.mappings[1, entry + offset] = 'd' if data else 't'
        self.image.instructions[1, entry + offset] = op, args, after

    def statement(self, name, offset, op, args):
        section, begin, entry = self.locations[name]
        if op == 'align':
            if offset % 4:
                self.put(name, offset, b'\x00\xbf', 'nop', '')
        elif op == 'word':
            self.machine.relocations[section, begin + offset] = 2, self.machine.section_symbol(3 if args == 'slot' else 2)
            if self.emitted:
                self.final.relocations[1, entry - 0x1000 + offset] = 2, self.final.section_symbol(2)
            value = 0x20000014 if args == 'slot' else 0x20000000
            self.put(name, offset, bytes(4), '.word', hex(value), struct.pack('<I', value), data=True)
        elif op in ('bl', 'b') and type(args) is str:
            kind = 10 if op == 'bl' else 30
            self.machine.relocations[section, begin + offset] = kind, self.machine.symbol(args)
            if self.emitted:
                self.final.relocations[1, entry - 0x1000 + offset] = kind, self.final.symbol(args)
            target = self.locations[args][2]
            self.put(name, offset, helper._long_branch(0, 0, op == 'bl'), op, '%x <%s>' % (target, args),
                     helper._long_branch(entry + offset, target, op == 'bl'))
        elif op == 'literal':
            reg, target = args
            delta = target - ((offset + 4) & ~3)
            self.put(name, offset, struct.pack('<H', 0x4800 | int(reg[1:]) << 8 | delta // 4),
                     'ldr', '%s,[pc,#%d]' % (reg, delta))
        elif type(args) is tuple:
            operands = (args[0] + ',' if args[0] else '') + '%x' % (entry + args[1])
            self.put(name, offset, local_encoding(op, args, offset), op, operands)
        else:
            display_op, display_args = ('ldmia', 'sp!,' + args) if op == 'pop' and args.endswith('lr}') else (op, args)
            self.put(name, offset, helper._fixed(op, args), display_op, display_args)

    def check(self):
        return subject.inspect(self.image, self.core, helper, port_source=self.source,
                               assembly=self.assembly, emit_relocs=self.emitted)

    def site(self, name, op):
        return next(at for at, kind, _ in self.programs[name][0] if kind == op)


class SlotTests(unittest.TestCase):
    def reject(self, fixture):
        with self.assertRaises(subject.Rejected):
            fixture.check()

    def test_complete_os_bodies_two_sections_and_both_twins(self):
        for emitted in (False, True):
            f = Fixture(emitted)
            proof = f.check()
            self.assertEqual([row['Size'] for row in proof['CommonBodies']], [16, 48, 80, 32, 32, 64])
            self.assertEqual([len(row['References']) for row in proof['CommonBodies']], [2, 5, 6, 4, 4, 7])
            self.assertEqual((proof['CommonBytes'], proof['SlotReferences'], proof['AppliedSlotReferences']),
                             (272, 8, 8 if emitted else 0))
            self.assertEqual(proof['CommonBodies'][0]['Origin']['InputSectionIndex'], 4)
            self.assertIs(subject.require_result(proof, emit_relocs=emitted), proof)

    def test_independent_beq_encoding_and_protocol_conditions(self):
        self.assertEqual(subject._local_branch(helper, 'beq', ('', 8), 0), bytes.fromhex('02d0'))
        self.assertEqual(subject._local_branch(helper, 'beq', ('', 0), 8), bytes.fromhex('fad0'))
        self.assertEqual(helper._fixed('str', 'r4,[r3,#0]'), bytes.fromhex('1c60'))
        for args, at in ((('', 3), 0), (('', 260), 0), (('r0', 8), 0)):
            with self.assertRaises(subject.Rejected):
                subject._local_branch(helper, 'beq', args, at)
        f = Fixture(); f.assembly = f.assembly.replace(b'beq bad', b'bne bad'); self.reject(f)
        f = Fixture(); name = 'fiber_internal_runtime_select_scheduler_candidate'
        at = f.site(name, 'beq'); raw = local_encoding('bne', next(args for pos, op, args in f.programs[name][0] if op == 'beq'), at)
        f.put(name, at, raw, 'bne', '0'); self.reject(f)

    def test_guards_registers_stores_and_complete_generated_protocols(self):
        for before, after in ((b'cbnz r0,ok', b'cbz r0,ok'), (b'blx r6', b'blx r5'),
                              (b'#107', b'#106'), (b'str r4,[r3]', b'ldr r4,[r3]'),
                              (b'str r6,[r5,#16]', b'str r6,[r5,#12]'),
                              (b'word .LANCHOR0', b'word .LANCHOR0\nmov r0,r3')):
            with self.subTest(before=before):
                f = Fixture(); self.assertIn(before, f.assembly)
                f.assembly = f.assembly.replace(before, after, 1); self.reject(f)

    def test_coherent_raw_instruction_and_final_disassembly_mutants(self):
        for name, op, raw, mnemonic, args in (
                ('fiber_internal_runtime_load_current_context', 'ldr', '1860', 'str', 'r0,[r3,#0]'),
                (PUBLISHER, 'str', '1c68', 'ldr', 'r4,[r3,#0]')):
            f = Fixture(); f.put(name, f.site(name, op), bytes.fromhex(raw), mnemonic, args); self.reject(f)
        f = Fixture(); name = 'ctxrt_v1_set_dispatcher'
        at = f.site(name, 'bl'); _, _, entry = f.locations[name]
        f.image.instructions[1, entry + at] = 'bl', '1000', b'\x00\xbf\x00\xbf'
        self.reject(f)

    def test_exact_source_trivia_and_no_extra_slot_mentions(self):
        for extra in (b' int *' + SLOT.encode() + b';', b' (void)&' + SLOT.encode() + b';'):
            f = Fixture(); f.source += extra; self.reject(f)
        for gap in (b' /* one */ + /* two */ ', b' /* line \\\n */ '):
            f = Fixture(); f.source = f.source.replace(b' /* pair */ ', gap); self.reject(f)

    def test_generated_alias_definition_and_escape_reject(self):
        for before, after in ((b'.set .LANCHOR0,. + 0', b'.set .LANCHOR0,. + 4'),
                              (b'.word .LANCHOR0', b'.word .LANCHOR1'),
                              (b'.space 4', b'.space 8'),
                              (b'ldr r0, [r0]', b'mov r2,r0\nldr r0, [r0]')):
            f = Fixture(); f.assembly = f.assembly.replace(before, after, 1); self.reject(f)
        f = Fixture(); f.assembly += b'.word .LANCHOR0\n'; self.reject(f)

    def test_common_original_applied_refs_addends_targets_and_membership(self):
        for changed in ('kind', 'original', 'applied', 'missing', 'extra'):
            f = Fixture(); name = PUBLISHER; at = f.site(name, 'word')
            section, start, entry = f.locations[name]
            if changed == 'kind':
                f.machine.relocations[section, start + at] = True, f.machine.section_symbol(3)
            elif changed == 'original':
                f.machine.write(section, start + at, b'\x04\x00\x00\x00')
            elif changed == 'applied':
                f.final.write(1, entry - 0x1000 + at, struct.pack('<I', 0x20000018))
            elif changed == 'missing':
                del f.final.relocations[1, entry - 0x1000 + at]
            else:
                f.machine.relocations[section, start + 2] = 2, f.machine.section_symbol(2)
            with self.subTest(changed=changed):
                self.reject(f)

    def test_branch_call_addend_target_and_mapping_are_not_filtered(self):
        for changed in ('original', 'destination', 'rawtarget', 'mapping'):
            f = Fixture(); name = PUBLISHER; at = f.site(name, 'bl')
            section, start, entry = f.locations[name]
            if changed == 'original':
                f.machine.write(section, start + at, helper._long_branch(0, 2, True))
            elif changed == 'destination':
                target = f.locations['fiber_panic'][2] + 2
                f.final.write(1, entry - 0x1000 + at, helper._long_branch(entry + at, target, True))
                f.image.instructions[1, entry + at] = 'bl', '%x' % target, helper._long_branch(entry + at, target, True)
            elif changed == 'rawtarget':
                kind, target = f.machine.relocations[section, start + at]
                f.machine.relocations[section, start + at] = kind, dict(target, size=True)
            else:
                f.final.mappings[1, entry + at] = 'd'
            with self.subTest(changed=changed):
                self.reject(f)

    def test_immediate_handler_dereference_is_load_only(self):
        for name, reg in HANDLERS.items():
            f = Fixture()
            f.put(name, 2, struct.pack('<H', 0x6000 | reg << 3 | reg), 'str', 'r%d,[r%d,#0]' % (reg, reg))
            self.reject(f)

    def test_same_pool_additional_load_in_either_stream_rejects(self):
        for side in ('machine', 'final', 'both'):
            f = Fixture(); section, start, entry = f.locations['SVC_Handler']
            raw = bytes.fromhex('014b')
            if side != 'final':
                f.machine.write(section, start + 4, raw)
            if side != 'machine':
                f.final.write(1, entry - 0x1000 + 4, raw)
                f.image.instructions[1, entry + 4] = 'ldr', 'r3,[pc,#4]', raw
            with self.subTest(side=side):
                self.reject(f)

    def test_cross_owner_pool_reuse_both_twins_and_streams(self):
        for emitted in (False, True):
            for both in (False, True):
                f = Fixture(emitted)
                section, start, entry = f.locations['SVC_Handler']
                target = f.locations['PendSV_Handler'][2] + 12
                delta = target - ((entry + 4 + 4) & ~3)
                raw = struct.pack('<H', 0x4B00 | delta // 4)
                refs = copy.deepcopy((f.machine.relocations, f.final.relocations))
                if both:
                    f.machine.write(section, start + 4, raw)
                f.final.write(1, entry - 0x1000 + 4, raw)
                f.image.instructions[1, entry + 4] = 'ldr', 'r3,[pc,#%d]' % delta, raw
                self.assertEqual((f.machine.relocations, f.final.relocations), refs)
                with self.subTest(emitted=emitted, both=both):
                    self.reject(f)

    def test_unsupported_pc_forms_cannot_bypass_handler_census(self):
        for first in (0xF8DF, 0xF85F, 0xF89F, 0xF99F, 0xE9DF, 0xED9F, 0xF20F, 0xF2AF):
            f = Fixture(); section, start, entry = f.locations['SVC_Handler']
            raw = struct.pack('<HH', first, 0x3004)
            f.put('SVC_Handler', 4, raw, 'ldr', 'r3,[pc,#4]')
            del f.machine.mappings[section, start + 6]
            del f.final.mappings[1, entry + 6]
            del f.image.instructions[1, entry + 6]
            with self.subTest(first=first):
                self.reject(f)

    def test_domain_covers_all_sections_foreign_providers_and_no_extra_pools(self):
        f = Fixture(); foreign = Elf()
        foreign.relocations[1, 0] = 2, foreign.section_symbol(3)
        f.image.providers['startup.o'] = foreign; self.reject(f)
        f = Fixture(); f.machine.relocations[1, 0x900] = 2, f.machine.section_symbol(3)
        f.machine.mappings[1, 0x900] = 'd'
        f.final.mappings[1, 0x1900] = 'd'
        f.final.write(1, 0x900, struct.pack('<I', 0x20000014)); self.reject(f)
        f = Fixture(); f.image.placements['machine.o', '.text.ctxrt_api_thread'] = (0x2004, 16)
        self.reject(f)

    def test_slot_symbol_storage_alias_and_typed_numbers(self):
        for field, value in (('size', True), ('value', False), ('section', True), ('binding', 'STB_GLOBAL')):
            f = Fixture(); f.machine.symbol(SLOT)[field] = value
            with self.subTest(field=field):
                self.reject(f)
        f = Fixture(); f.final.loads[1]['Flags'] = 4; self.reject(f)
        f = Fixture(); f.machine.add('alias', 3, 0, 4, 'STT_OBJECT', 'STB_LOCAL'); self.reject(f)
        for selector in (0, 1, None, 'True'):
            f = Fixture()
            with self.assertRaises(subject.Rejected):
                subject.inspect(f.image, f.core, helper, port_source=f.source, assembly=f.assembly, emit_relocs=selector)

    def test_returned_leaf_strictness_nonclaims_and_no_o2_relabel(self):
        proof = Fixture().check()
        mutations = [('Mode', 'O2-lto'), ('Scope', 'O2'), ('RequiredCellsSatisfied', False),
                     ('ClosedCommonBodies', 6.0), ('CommonBytes', True), ('Qualification', True),
                     ('CompleteHandlerBodiesValidated', True), ('MachineSha256', '')]
        for key, value in mutations:
            broken = copy.deepcopy(proof); broken[key] = value
            with self.subTest(key=key), self.assertRaises(subject.Rejected):
                subject.require_result(broken)
        for target in ('CommonBodies', 'HandlerLoads', 'SourcePairs', 'GeneratedPairs'):
            broken = copy.deepcopy(proof); broken[target] = []
            with self.subTest(target=target), self.assertRaises(subject.Rejected):
                subject.require_result(broken)
        for key in ('TailNops', 'Size'):
            broken = copy.deepcopy(proof); broken['CommonBodies'][0][key] = False
            with self.assertRaises(subject.Rejected):
                subject.require_result(broken)
        for row in proof['CommonBodies']:
            self.assertIs(row['CompleteBodyValidated'], True)
        for key in subject.FALSE_FIELDS:
            self.assertIs(proof[key], False)
        self.assertIs(type(proof['RequiredCellsSatisfied']), int)

    def test_no_io_model_or_frozen_helper_global_mutation(self):
        f = Fixture()
        before = copy.deepcopy((vars(f.machine), vars(f.final), f.image.instructions, f.image.placements))
        globals_before = dict(helper.__dict__)
        with patch('builtins.open', side_effect=AssertionError('no open')), \
                patch.object(Path, 'read_bytes', side_effect=AssertionError('no read')), \
                patch('subprocess.Popen', side_effect=AssertionError('no process')):
            f.check()
        self.assertEqual(before, (vars(f.machine), vars(f.final), f.image.instructions, f.image.placements))
        self.assertEqual(globals_before, helper.__dict__)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    if output.exists() or not output.is_relative_to(Path(tempfile.gettempdir()).resolve()) \
            or output.is_relative_to(HERE.parents[2]):
        parser.error('fresh external TEMP output required')
    paths = (Path(__file__).resolve(), SUBJECT, HELPER)
    buffers = {path: path.read_bytes() for path in paths}
    report = dict(Status='FAIL', Scope='PURE_SYNTHETIC_CM3_OS_LTO_SLOT_CONTROLS_ONLY',
        Tests=0, ExpectedTestMethods=METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={str(path): sha(raw) for path, raw in buffers.items()}, SourceDrift=[],
        SourceClosureVerified=False, SyntheticModels=True, ActualELFParsed=False,
        PredicateExecutionOnActualArtifacts=False, NativeCommandsExecuted=0,
        Qualification=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0,
        FullABIProof=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError('unoptimized Python required')
        if sha(buffers[HELPER]) != HELPER_SHA:
            raise ValueError('frozen helper source pin')
        global subject, helper
        helper = ModuleType('_cm3_os_slot_frozen_helper')
        subject = ModuleType('_cm3_os_slot_subject')
        helper.__file__, subject.__file__ = str(HELPER), str(SUBJECT)
        with patch('subprocess.Popen', side_effect=AssertionError('pure test process spawn')):
            exec(compile(buffers[HELPER], str(HELPER), 'exec'), helper.__dict__)
            exec(compile(buffers[SUBJECT], str(SUBJECT), 'exec'), subject.__dict__)
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(SlotTests)
            if suite.countTestCases() != METHODS:
                raise ValueError('exact sixteen synthetic methods required')
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), Details=[dict(Test=str(test), Detail=detail)
                for test, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped:
            report['Status'] = 'PASS'
    except Exception:
        report.update(Status='FAIL', Error=traceback.format_exc(), Errors=report['Errors'] + 1)
    for path, expected in report['SourceHashes'].items():
        try:
            if sha(Path(path).read_bytes()) != expected:
                report['SourceDrift'].append(path)
        except OSError:
            report['SourceDrift'].append(path)
    report['SourceClosureVerified'] = len(report['SourceHashes']) == 3 and not report['SourceDrift']
    if not report['SourceClosureVerified']:
        report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / 'results.json'
    receipt.write_bytes((json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii'))
    print('Receipt:', receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
