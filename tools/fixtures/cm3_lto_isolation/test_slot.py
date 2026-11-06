"""Synthetic malformed-record and byte controls; no ELF parser or tools."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import traceback
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
SUBJECT = HERE / 'slot.py'
SUBJECT_SHA = '669F294A622B076984E36F6FA9C73235BD0D3F778AA4A36F496051D49DE822B3'
EXPECTED_METHODS = 22
subject = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


class Elf:
    def __init__(self, final=False):
        self.final, self.data = final, bytes(0x3000)
        self.symbols, self.relocations, self.mappings = [], {}, {}
        def section(name, address, size, flags=6, kind='SHT_PROGBITS', offset=0x100):
            return SimpleNamespace(name=name, header=SimpleNamespace(sh_addr=address, sh_size=size,
                sh_flags=flags, sh_type=kind, sh_offset=offset, sh_addralign=4))
        self.sections = [section('', 0, 0, 0), section('.text', 0x1000 if final else 0, 0x1000),
                         section('.bss', 0x20000000 if final else 0, 20 if final else 16, 3, 'SHT_NOBITS')]
        if not final:
            self.sections.append(section(subject.SECTION, 0, 4, 3, 'SHT_NOBITS'))
        self.loads = [dict(Vaddr=0x1000, MemorySize=0x1000, FileSize=0x1000, Flags=5),
                      dict(Vaddr=0x20000000, MemorySize=20, FileSize=0, Flags=6)] if final else []
        for index in range(1, len(self.sections)):
            self.add('', index, self.sections[index].header.sh_addr if final else 0,
                     0, 'STT_SECTION', 'STB_LOCAL')

    def add(self, name, section, value, size, kind='STT_FUNC', binding='STB_GLOBAL'):
        row = dict(name=name, section=section, value=value, size=size, kind=kind,
                   binding=binding, visibility='STV_DEFAULT', index=len(self.symbols))
        self.symbols.append(row)
        return row

    def symbol(self, name):
        return next(row for row in self.symbols if row['name'] == name)

    def section_symbol(self, index):
        return next(row for row in self.symbols if row['kind'] == 'STT_SECTION' and row['section'] == index)

    def write(self, section, offset, raw):
        at = self.sections[section].header.sh_offset + offset
        self.data = self.data[:at] + raw + self.data[at + len(raw):]

    def mapping(self, section, address):
        previous = [at for sec, at in self.mappings if sec == section and at <= address]
        following = [at for sec, at in self.mappings if sec == section and at > address]
        if not previous:
            raise ValueError('synthetic missing mapping')
        boundary = min(following) if following else self.sections[section].header.sh_addr + self.sections[section].header.sh_size
        return self.mappings[section, max(previous)], boundary


class Fixture:
    """A schema model, not a learned ELF oracle or independent compiler proof.

    The subject's explicit protocol grammar constructs valid model bytes. Tests
    independently check selected ISA constants and then coherently corrupt the
    model, assembly, raw REL records and final disassembly. Real retained twins
    are a separate host replay, never described here as synthetic ELF parsing.
    """
    def __init__(self, emitted=True):
        self.emitted = emitted
        self.machine, self.final = Elf(), Elf(True)
        self.programs = {name: subject._program(text) for name, text in subject.PROGRAMS.items()}
        self.entries, cursor = {}, 0
        for name, (_, size) in self.programs.items():
            self.entries[name] = cursor
            self.machine.add(name, 1, cursor | 1, size)
            self.final.add(name, 1, (0x1000 + cursor) | 1, size)
            cursor = (cursor + size + 3) & ~3
        for name in (*subject.HANDLERS, subject.BARRIER, 'fiber_panic',
                     'fiber_port_require_scheduler_configuration_environment'):
            size = 16 if name in subject.HANDLERS else 2
            self.entries[name] = cursor
            self.machine.add(name, 1, cursor | 1, size)
            self.final.add(name, 1, (0x1000 + cursor) | 1, size)
            cursor = (cursor + size + 3) & ~3
        self.machine.add(subject.SLOT, 3, 0, 4, 'STT_OBJECT', 'STB_LOCAL')
        self.final.add(subject.SLOT, 2, 0x20000010, 4, 'STT_OBJECT', 'STB_LOCAL')
        self.machine.add(subject.SCHEDULER, 2, 0, 4, 'STT_OBJECT', 'STB_LOCAL')
        self.final.add(subject.SCHEDULER, 2, 0x20000000, 4, 'STT_OBJECT', 'STB_LOCAL')
        self.image = SimpleNamespace(prelink=self.machine, final=self.final,
            providers={'machine.o': self.machine}, placements={('machine.o', '.text'): (0x1000, 0x1000),
            ('machine.o', '.bss'): (0x20000000, 16), ('machine.o', subject.SECTION): (0x20000010, 4)},
            instructions={}, link_map_hash='A' * 64)
        self.core = SimpleNamespace(_width=lambda word: 4 if word >> 11 in (29, 30, 31) else 2,
                                    _address_form=self.address_form)
        self.source = ('"ldr r0, =' + subject.SLOT + ' \\n" "ldr r0, [r0] \\n"\n'
                       '"ldr r1, =' + subject.SLOT + ' \\n" /* pair */ "ldr r1, [r1] \\n"').encode('ascii')
        parts = []
        for name, text in subject.PROGRAMS.items():
            body = text.replace('word slot', '.word .LANCHOR0').replace('word scheduler', '.word .LANCHOR1')
            body = body.replace('align\n', '.align 2\n')
            parts.append(name + ':\n' + body + '.size ' + name + ', .-' + name + '\n')
            for offset, op, args in self.programs[name][0]:
                self.statement(name, offset, op, args)
        for name, register in subject.HANDLERS.items():
            parts.append(name + ':\nldr r%d, =' % register + subject.SLOT
                + '\nldr r%d, [r%d]\n.size ' % (register, register) + name + ', .-' + name + '\n')
            self.put(name, 0, struct.pack('<H', 0x4802 | register << 8), 'ldr', 'r%d,[pc,#8]' % register)
            self.put(name, 2, struct.pack('<H', 0x6800 | register << 3 | register), 'ldr', 'r%d,[r%d,#0]' % (register, register))
            for offset in (4, 6, 8, 10):
                self.put(name, offset, b'\x00\xbf', 'nop', '')
            self.statement(name, 12, 'word', 'slot')
        parts.append('.bss\n.align 2\n.set .LANCHOR1,. + 0\n.type ' + subject.SCHEDULER + ',%object\n')
        parts.append('.section ' + subject.SECTION + ',"aw",%nobits\n.align 2\n.set .LANCHOR0,. + 0\n.type '
            + subject.SLOT + ',%object\n.size ' + subject.SLOT + ',4\n' + subject.SLOT + ':\n.space 4\n.section .other,"a"\n')
        self.assembly = ''.join(parts).encode('ascii')

    @staticmethod
    def address_form(raw, place):
        word = struct.unpack('<H', raw)[0]
        if word & 0xF800 == 0x4800:
            delta = (word & 255) * 4
            return 'ldr', ((place + 4) & ~3) + delta, (word >> 8) & 7, delta
        return None

    def put(self, owner, offset, before, op, args, after=None, data=False):
        start = self.entries[owner] + offset
        after = before if after is None else after
        self.machine.write(1, start, before)
        self.final.write(1, start, after)
        self.machine.mappings[1, start] = 'd' if data else 't'
        self.final.mappings[1, 0x1000 + start] = 'd' if data else 't'
        self.image.instructions[1, 0x1000 + start] = op, args, after

    def statement(self, owner, offset, op, args):
        start = self.entries[owner] + offset
        if op == 'align':
            if offset % 4:
                self.put(owner, offset, b'\x00\xbf', 'nop', '')
            return
        if op == 'word':
            section = 3 if args == 'slot' else 2
            target = self.machine.section_symbol(section)
            final_target = self.final.section_symbol(2)
            self.machine.relocations[1, start] = 2, target
            if self.emitted:
                self.final.relocations[1, start] = 2, final_target
            value = 0x20000010 if args == 'slot' else 0x20000000
            self.put(owner, offset, bytes(4), '.word', hex(value), struct.pack('<I', value), data=True)
        elif op in ('bl', 'b') and type(args) is str:
            kind = 10 if op == 'bl' else 30
            self.machine.relocations[1, start] = kind, self.machine.symbol(args)
            if self.emitted:
                self.final.relocations[1, start] = kind, self.final.symbol(args)
            self.put(owner, offset, subject._long_branch(start, start, op == 'bl'), op,
                '%x <%s>' % (0x1000 + self.entries[args], args),
                subject._long_branch(start + 0x1000, self.entries[args] + 0x1000, op == 'bl'))
        elif op == 'literal':
            reg, target = args
            delta = target - ((offset + 4) & ~3)
            raw = struct.pack('<H', 0x4800 | int(reg[1:]) << 8 | delta // 4)
            self.put(owner, offset, raw, 'ldr', '%s,[pc,#%d]' % (reg, delta))
        elif type(args) is tuple:
            target = 0x1000 + self.entries[owner] + args[1]
            operands = ('%s,' % args[0] if args[0] else '') + '%x' % target
            self.put(owner, offset, subject._local_branch(op, args, offset), op, operands)
        else:
            display_op, display_args = op, args
            if op == 'pop' and args.endswith('lr}'):
                display_op, display_args = 'ldmia', 'sp!,' + args
            self.put(owner, offset, subject._fixed(op, args), display_op, display_args)

    def check(self):
        return subject.inspect(self.source, self.assembly, self.image, self.core, emit_relocs=self.emitted)

    def site(self, owner, op):
        return next(offset for offset, operation, args in self.programs[owner][0] if operation == op)


class SlotTests(unittest.TestCase):
    def reject(self, fixture):
        with self.assertRaises(subject.Rejected):
            fixture.check()

    def test_positive_emitted_and_ordinary_models(self):
        for emitted in (False, True):
            proof = Fixture(emitted).check()
            self.assertEqual((proof['ClosedCommonBodies'], proof['HandlerLoadPairs'], proof['CommonLoads'],
                              proof['CommonStores'], proof['SlotReferences']), (6, 2, 5, 1, 8))
            self.assertEqual(proof['AppliedSlotReferences'], 8 if emitted else 0)
            self.assertEqual(proof['Publisher'], 'fiber_internal_runtime_publish_current_context')

    def test_independent_instruction_encoding_constants(self):
        for op, args, encoded in (('ldr', 'r0,[r3,#0]', '1868'), ('str', 'r4,[r3,#0]', '1c60'),
                ('push', '{r4,lr}', '10b5'), ('pop', '{r4,lr}', 'bde81040'), ('mov', 'r4,r0', '0446'),
                ('movs', 'r0,#78', '4e20'), ('blx', 'r6', 'b047')):
            self.assertEqual(subject._fixed(op, args), bytes.fromhex(encoded))
        self.assertEqual(subject._long_branch(0, 0, True), bytes.fromhex('fff7feff'))
        self.assertEqual(subject._long_branch(0, 0, False), bytes.fromhex('fff7febf'))
        self.assertEqual(subject._local_branch('cbz', ('r0', 0x16), 2), bytes.fromhex('40b1'))

    def test_source_trivia_only_and_no_c_access_or_phase_two_escape(self):
        for gap in (' /* first */ + /* last */ ', ' /* first */ macro_token /* last */ ',
                    ' /* continuation \\\n */ '):
            f = Fixture()
            f.source = f.source.replace(b' /* pair */ ', gap.encode('ascii'))
            self.reject(f)
        for extra in (b'\nint *' + subject.SLOT.encode() + b';', b'\n(void)&' + subject.SLOT.encode() + b';'):
            f = Fixture(); f.source += extra; self.reject(f)

    def test_generated_handler_immediate_pair_register_and_extra_mentions(self):
        for before, after in ((b'ldr r0, [r0]', b'str r0, [r0]'),
                              (b'ldr r1, [r1]', b'mov r2,r1\nldr r1, [r1]'),
                              (b'ldr r1, [r1]', b'ldr r2, [r1]')):
            f = Fixture(); f.assembly = f.assembly.replace(before, after); self.reject(f)
        f = Fixture(); f.assembly += b'.word ' + subject.SLOT.encode() + b'\n'; self.reject(f)

    def test_common_full_protocol_extra_store_escape_guard_and_branch(self):
        for before, after in ((b'ldr r0,[r3]', b'str r0,[r3]'),
                              (b'str r4,[r3]', b'str r4,[r3]\nmov r0,r3'),
                              (b'cbz r0,badnext', b'cbnz r0,badnext'),
                              (b'blx r6', b'blx r5')):
            f = Fixture(); f.assembly = f.assembly.replace(before, after, 1); self.reject(f)

    def test_slot_alias_definition_rebinding_and_other_alias_references(self):
        for before, after in ((b'.set .LANCHOR0,. + 0', b'.set .LANCHOR0,. + 4'),
                              (b'.word .LANCHOR0', b'.word .LANCHOR1'),
                              (b'.size ' + subject.SLOT.encode() + b',4', b'.size ' + subject.SLOT.encode() + b',8')):
            f = Fixture(); f.assembly = f.assembly.replace(before, after, 1); self.reject(f)
        f = Fixture(); f.assembly += b'.word .LANCHOR0\n'; self.reject(f)

    def test_coherent_machine_and_disassembly_store_mutation_rejects(self):
        f = Fixture()
        name = 'fiber_internal_runtime_load_current_context'
        offset = next(at for at, op, args in f.programs[name][0] if op == 'ldr')
        f.put(name, offset, bytes.fromhex('1860'), 'str', 'r0,[r3,#0]')
        self.reject(f)

    def test_handler_actual_raw_load_pair_rejects_store_and_escape(self):
        for name in subject.HANDLERS:
            f = Fixture(); reg = subject.HANDLERS[name]
            f.put(name, 2, struct.pack('<H', 0x6000 | reg << 3 | reg), 'str', 'r%d,[r%d,#0]' % (reg, reg))
            self.reject(f)
        f = Fixture(); f.put('SVC_Handler', 0, bytes.fromhex('0148'), 'ldr', 'r0,[pc,#4]'); self.reject(f)

    def test_handler_narrow_pool_reuse_is_censused_in_both_streams(self):
        for side in ('machine', 'final', 'both'):
            for name in subject.HANDLERS:
                f = Fixture(); offset = f.entries[name] + 4
                # PC=Align(P+4,4)=entry+8; imm4 reuses the existing entry+12 pool.
                raw = struct.pack('<H', 0x4B01)
                if side in ('machine', 'both'):
                    f.machine.write(1, offset, raw)
                if side in ('final', 'both'):
                    f.final.write(1, offset, raw)
                    f.image.instructions[1, 0x1000 + offset] = 'ldr', 'r3,[pc,#4]', raw
                with self.subTest(side=side, name=name):
                    with self.assertRaisesRegex(subject.Rejected, 'both handler streams'):
                        f.check()

    def test_handler_t32_pool_reuse_and_other_pc_forms_fail_closed(self):
        # Positive word literal form really addresses the existing pool, without
        # any new REL. Other unsupported PC forms reject even if not slot-bound.
        forms = [(struct.pack('<HH', word, 0x3004), 'ldr', 'r3,[pc,#4]') for word in
                 (0xF8DF, 0xF85F, 0xF89F, 0xF81F, 0xF8BF, 0xF99F,
                  0xE9DF, 0xED9F, 0xF20F, 0xF2AF)]
        forms += [(bytes.fromhex('01a3'), 'adr', 'r3,pc'),
                  (struct.pack('<H', 0x467B), 'mov', 'r3,pc')]
        for side in ('machine', 'final', 'both'):
            for raw, op, operands in forms:
                f = Fixture(); offset = f.entries['SVC_Handler'] + 4
                if side in ('machine', 'both'):
                    f.machine.write(1, offset, raw)
                    if len(raw) == 4:
                        del f.machine.mappings[1, offset + 2]
                if side in ('final', 'both'):
                    f.final.write(1, offset, raw)
                    f.image.instructions[1, offset + 0x1000] = op, operands, raw
                    if len(raw) == 4:
                        del f.final.mappings[1, offset + 0x1002]
                        del f.image.instructions[1, offset + 0x1002]
                with self.subTest(side=side, raw=raw.hex()):
                    with self.assertRaisesRegex(subject.Rejected, 'unsupported .*PC'):
                        f.check()

    def cross_pool_fixture(self, emitted, *, both):
        f = Fixture(emitted)
        owner, target_owner = 'SVC_Handler', 'PendSV_Handler'
        at = f.entries[owner] + 4
        target = f.entries[target_owner] + 12
        delta = target - ((at + 4) & ~3)
        self.assertGreater(delta, 0)
        self.assertEqual(delta % 4, 0)
        raw = struct.pack('<H', 0x4B00 | delta // 4)
        # Reuse the other handler's existing ABS32 word; introduce no REL.
        before_relocations = copy.deepcopy((f.machine.relocations, f.final.relocations))
        if both:
            f.machine.write(1, at, raw)
        f.final.write(1, at, raw)
        f.image.instructions[1, at + 0x1000] = 'ldr', 'r3,[pc,#%d]' % delta, raw
        self.assertEqual((f.machine.relocations, f.final.relocations), before_relocations)
        return f

    def test_handler_cross_owner_pool_coherent_in_both_streams_rejects(self):
        for emitted in (False, True):
            with self.subTest(emitted=emitted):
                with self.assertRaisesRegex(subject.Rejected, 'cross-owner slot literal'):
                    self.cross_pool_fixture(emitted, both=True).check()

    def test_handler_final_only_cross_pool_rejects_without_emitted_rel_dependency(self):
        for emitted in (False, True):
            with self.subTest(emitted=emitted):
                with self.assertRaisesRegex(subject.Rejected, 'cross-owner slot literal'):
                    self.cross_pool_fixture(emitted, both=False).check()

    def test_original_rel_extra_missing_kind_addend_and_raw_symbol_alias(self):
        for change in ('extra', 'missing', 'kind', 'addend', 'named', 'raw-index'):
            f = Fixture(); key = next(key for key, value in f.machine.relocations.items() if value[1]['section'] == 3)
            kind, target = f.machine.relocations[key]
            if change == 'extra':
                f.machine.relocations[1, 0xF00] = kind, target
            elif change == 'missing':
                del f.machine.relocations[key]
            elif change == 'kind':
                f.machine.relocations[key] = 43, target
            elif change == 'addend':
                f.machine.write(key[0], key[1], struct.pack('<I', 4))
            elif change == 'named':
                f.machine.relocations[key] = kind, f.machine.symbol(subject.SLOT)
            else:
                f.machine.relocations[key] = kind, dict(target, index=True)
            with self.subTest(change=change):
                self.reject(f)

    def test_final_pointer_retarget_applied_metadata_extra_and_missing(self):
        for change in ('value', 'missing', 'kind', 'extra', 'named'):
            f = Fixture(); key = next(key for key, value in f.machine.relocations.items() if value[1]['section'] == 3)
            if change == 'value':
                f.final.write(key[0], key[1], struct.pack('<I', 0x20000000))
            elif change == 'missing':
                del f.final.relocations[key]
            elif change == 'kind':
                f.final.relocations[key] = 10, f.final.relocations[key][1]
            elif change == 'extra':
                f.final.relocations[1, 0xF00] = 2, f.final.section_symbol(2)
                f.final.write(1, 0xF00, struct.pack('<I', 0x20000010))
            else:
                f.final.relocations[key] = 2, f.final.symbol(subject.SLOT)
            with self.subTest(change=change):
                self.reject(f)

    def test_branch_raw_source_addend_and_final_target_not_text_oracles(self):
        for change in ('source', 'applied', 'text'):
            f = Fixture(); owner = subject.PUBLISHER; offset = f.site(owner, 'bl')
            at = f.entries[owner] + offset
            if change == 'source':
                f.machine.write(1, at, subject._long_branch(at, at + 2, True))
            elif change == 'applied':
                f.final.write(1, at, subject._long_branch(at + 0x1000, f.entries['fiber_panic'] + 0x1000, True))
            else:
                op, args, raw = f.image.instructions[1, at + 0x1000]
                f.image.instructions[1, at + 0x1000] = op, 'abcd <foreign>', raw
            self.reject(f)

    def test_mapping_padding_data_and_additional_disassembly_not_discarded(self):
        for change in ('mapping', 'padding', 'interior', 'none'):
            f = Fixture(); name = 'fiber_internal_runtime_require_current_context'
            offset = f.site(name, 'align'); start = f.entries[name]
            if change == 'mapping':
                f.machine.mappings[1, start] = 'd'
            elif change == 'padding':
                f.put(name, offset, bytes.fromhex('c046'), 'mov', 'r8,r8')
            elif change == 'interior':
                f.image.instructions[1, 0x1000 + start + 1] = 'nop', '', b'\x00\xbf'
            else:
                f.image.instructions[1, 0x1000 + start] = None
            with self.subTest(change=change):
                self.reject(f)

    def test_slot_local_size_extent_whole_map_and_object_aliases(self):
        for change in ('binding', 'size', 'placement', 'offset', 'alias'):
            f = Fixture()
            if change == 'binding':
                f.machine.symbol(subject.SLOT)['binding'] = 'STB_GLOBAL'
            elif change == 'size':
                f.machine.symbol(subject.SLOT)['size'] = 8
            elif change == 'placement':
                f.image.placements['machine.o', subject.SECTION] = 0x2000000C, 4
            elif change == 'offset':
                f.machine.symbol(subject.SLOT)['value'] = 1
            else:
                f.machine.add('foreign_alias', 3, 0, 4, 'STT_OBJECT', 'STB_LOCAL')
            with self.subTest(change=change):
                self.reject(f)

    def test_slot_zero_fill_and_nonexecuting_writable_load_required(self):
        for field, value in (('Flags', 7), ('Flags', 4), ('FileSize', 20), ('MemorySize', 16)):
            f = Fixture(); f.final.loads[1][field] = value
            with self.subTest(field=field, value=value):
                self.reject(f)

    def test_foreign_provider_slot_reference_cannot_hide_in_startup(self):
        f = Fixture(); foreign = Elf()
        foreign.relocations[1, 0] = 2, foreign.section_symbol(3)
        f.image.providers['startup.o'] = foreign
        self.reject(f)

    def test_literal_typed_selectors_and_symbol_numbers(self):
        for field in ('value', 'section', 'size', 'index'):
            f = Fixture(); f.machine.symbol(subject.SLOT)[field] = False
            with self.subTest(field=field):
                self.reject(f)
        f = Fixture()
        for selected in (1, 0, None, 'true'):
            with self.assertRaises(subject.Rejected):
                subject.inspect(f.source, f.assembly, f.image, f.core, emit_relocs=selected)

    def test_no_file_process_or_model_mutation(self):
        f = Fixture()
        before = copy.deepcopy((vars(f.machine), vars(f.final), f.image.placements, f.image.instructions))
        with patch('builtins.open', side_effect=AssertionError('slot file I/O')), \
                patch.object(Path, 'read_bytes', side_effect=AssertionError('slot path read')), \
                patch('subprocess.Popen', side_effect=AssertionError('slot subprocess')):
            proof = f.check()
        self.assertEqual((vars(f.machine), vars(f.final), f.image.placements, f.image.instructions), before)
        self.assertTrue(proof['AllSectionMediatedSlotReferencesValidated'])

    def test_nonclaims_are_explicit_and_credit_exact_zero(self):
        proof = Fixture().check()
        for key in ('CommonSourceOwnershipValidated', 'CompleteHandlerBodiesValidated', 'ArbitraryPointerAliasProof',
                    'WholeProgramMemorySafetyProof', 'FullSemanticABIProof', 'SourceToMachineSemanticProof',
                    'OriginalTranslationUnitOwnership', 'Qualification', 'CellContractSatisfied', 'CpuExecution',
                    'BoardExecution', 'GlobalFreezeQualified', 'RequiredCellSatisfied'):
            self.assertIs(proof[key], False)
        self.assertIs(type(proof['RequiredCellsSatisfied']), int)
        self.assertEqual(proof['RequiredCellsSatisfied'], 0)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    temporary = Path(tempfile.gettempdir()).resolve()
    if output.exists() or not output.is_relative_to(temporary) or output.is_relative_to(HERE.parents[2]):
        parser.error('fresh external TEMP directory required')
    paths = (Path(__file__).resolve(), SUBJECT)
    report = dict(Status='FAIL', Tests=0, Failures=0, Errors=0, Skipped=0, ExpectedTestMethods=EXPECTED_METHODS,
        Scope='PURE_SYNTHETIC_CM3_LTO_SLOT_CONTROLS_ONLY', SourceHashes={}, SourceDrift=[],
        SourceClosureVerified=False, SyntheticModels=True, ActualELFParsed=False, NativeCommandsExecuted=0,
        Qualification=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError('unoptimized Python required')
        buffers = {path: path.read_bytes() for path in paths}
        report['SourceHashes'] = {str(path): sha(raw) for path, raw in buffers.items()}
        if sha(buffers[SUBJECT]) != SUBJECT_SHA:
            raise ValueError('frozen slot source pin')
        global subject
        subject = ModuleType('_cm3_lto_slot_test_subject')
        subject.__file__ = str(SUBJECT)
        with patch('subprocess.Popen', side_effect=AssertionError('pure controls cannot spawn processes')):
            exec(compile(buffers[SUBJECT], str(SUBJECT), 'exec'), subject.__dict__)
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(SlotTests)
            if suite.countTestCases() != EXPECTED_METHODS:
                raise ValueError('exact twenty-two synthetic methods required')
            outcome = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=outcome.testsRun, Failures=len(outcome.failures), Errors=len(outcome.errors),
            Skipped=len(outcome.skipped), Details=[dict(Test=str(case), Detail=detail)
                for case, detail in outcome.failures + outcome.errors])
        if outcome.wasSuccessful() and outcome.testsRun == EXPECTED_METHODS and not outcome.skipped:
            report['Status'] = 'PASS'
    except Exception:
        report.update(Status='FAIL', Error=traceback.format_exc(), Errors=report['Errors'] + 1)
    finally:
        for path, expected in report['SourceHashes'].items():
            try:
                if sha(Path(path).read_bytes()) != expected:
                    report['SourceDrift'].append(path)
            except OSError:
                report['SourceDrift'].append(path)
        report['SourceClosureVerified'] = len(report['SourceHashes']) == len(paths) and not report['SourceDrift']
        if not report['SourceClosureVerified']:
            report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / 'results.json'
    receipt.write_bytes((json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii'))
    print('Receipt:', receipt, sha(receipt.read_bytes()))
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
