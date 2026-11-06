"""Pure synthetic Os orchestration controls, not actual Os ELF qualification."""

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
from unittest.mock import Mock, patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SUBJECT = HERE / 'abi.py'
LINK = HERE.with_name('cm3_lto_link_contract') / 'audit.py'
BINDING = HERE.with_name('cm3_lto_runtime_bindings') / 'bindings.py'
FIXTURE = BINDING.with_name('test_bindings.py')
BASE_FIXTURE = LINK.with_name('test_audit.py')
CORE = HERE.with_name('classic_final_image') / 'elf.py'
PINS = {
    LINK: '9D6B4E1694A8C0A2D7F2E1C7B6D108B58B103131DD7C19D45CD08238E4CED759',
    BINDING: 'A8C994427DDE61619AB789D62E198B24DEC0B05EF8D1EE8E1C28BE86536E4C3B',
    FIXTURE: 'E879782FE6CD0149E4827757F17FFF6E8CCB9BB1EF683C8E1E30B8B50D1C75D1',
    BASE_FIXTURE: '3E215D413CC4ADBA6DE85901B394EE1550804EA0A714604AF0269C64D6B68B9D',
    CORE: '3A8F4E42B42189CDDAE44DE6AFA4468F24781B6EDFD13F02491C96C1E0729809',
}
EXPECTED_METHODS = 25
subject = link = binding = fixtures = base = core = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def load(name, path, raw):
    module = ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def check(fixture, **options):
    arguments = dict(emit_relocs=fixture.emit, machine_attributes_text=base.ATTRS)
    arguments.update(options)
    return subject.inspect(fixture.image, core, link, binding, base.ATTRS, **arguments)


def wide_fixture(emitted=True):
    """Small source-transcribed r8 carrier; no observed body/hash oracle.

    Keep one distinct cohort-byte read and a later anchor-byte read, with a
    named BL between them. Both actual synthetic byte streams and RELs are
    supplied to the unchanged mapping/placement/binding predicates.
    """
    f = fixtures.Fixture(emitted)
    anchor = f.machine.symbol(subject.ANCHOR)
    anchor['value'] = 1
    f.final.symbol(subject.ANCHOR)['value'] = 0xE01
    f.machine.write(0xA01, b'\x01')
    f.final.write(0x1201, b'\x01')
    for _, first, last in f.cold_sites:
        f.machine.write(0x100 + first, struct.pack('<I', anchor['value']))
        f.final.write(0x800 + last, struct.pack('<I', 0xE01))
    name, old_pool, old_final_pool = f.cold_sites[1]
    old_start = f.machine.symbol(name)['value'] & ~1
    old_last = f.final.symbol(name)['value'] & ~1
    before_ref = f.machine.relocations.pop((1, old_pool))
    after_ref = f.final.relocations.pop((2, old_final_pool), None)
    f.literal_ranges[id(f.machine)].remove((old_pool, old_pool + 4))
    f.literal_ranges[id(f.final)].remove((old_last + 8, old_last + 12))
    for key in list(f.image.instructions):
        if key[0] == 2 and old_last <= key[1] < old_last + 12:
            del f.image.instructions[key]
    start, last = 0x800, 0xC40
    f.machine.symbol(name)['value'] = start | 1
    f.final.symbol(name)['value'] = last | 1
    prefix = bytes.fromhex('2de9f043dff818801f4604460d46164698f80030')
    target = fixtures.FRAME
    original = prefix + fixtures.bl(start + 20, start + 20) + bytes.fromhex('98f80130704700bf') + bytes(4)
    f.write_function(name, original)
    final_call = fixtures.bl(last + 20, f.final.symbol(target)['value'] & ~1)
    f.final.write(0x800 + last - 0x400 + 20, final_call)
    pool, final_pool = start + 32, last - 0x400 + 32
    f.machine.relocations[1, pool] = before_ref
    if emitted:
        f.final.relocations[2, final_pool] = after_ref
    f.machine.write(0x100 + pool, bytes(4))
    f.final.write(0x800 + final_pool, struct.pack('<I', 0xE00))
    f.literal_ranges[id(f.machine)].append((pool, pool + 4))
    f.literal_ranges[id(f.final)].append((last + 32, last + 36))
    f.machine.relocations[1, start + 20] = (10, f.machine.symbol(target))
    if emitted:
        f.final.relocations[2, last - 0x400 + 20] = (10, f.final.symbol(target))
    rows = ((0, 4, 'stmdb', 'sp!, {r4, r5, r6, r7, r8, r9, lr}'),
            (4, 4, 'ldr', 'r8, [pc, #24]'), (8, 2, 'mov', 'r7, r3'),
            (10, 2, 'mov', 'r4, r0'), (12, 2, 'mov', 'r5, r1'), (14, 2, 'mov', 'r6, r2'),
            (16, 4, 'ldrb', 'r3, [r8]'),
            (20, 4, 'bl', '%x <%s>' % (f.final.symbol(target)['value'] & ~1, target)),
            (24, 4, 'ldrb', 'r3, [r8, #1]'), (28, 2, 'bx', 'lr'), (30, 2, 'nop', ''))
    for offset, size, mnemonic, operand in rows:
        raw = f.final.data[0x800 + last - 0x400 + offset:0x800 + last - 0x400 + offset + size]
        f.image.instructions[2, last + offset] = (mnemonic, operand, raw)
    f.wide = SimpleNamespace(name=name, start=start, last=last, call=start + 20,
                             final_call=last - 0x400 + 20, pool=pool, final_pool=final_pool)
    return f


class AbiTests(unittest.TestCase):
    def rejects(self, fixture, **options):
        with self.assertRaises((subject.Rejected, link.Rejected, binding.Rejected, core.Rejected)):
            check(fixture, **options)

    def test_synthetic_ordinary_and_emitted_complete_os_results(self):
        for emitted in (False, True):
            with self.subTest(emitted=emitted):
                f = fixtures.Fixture(emitted)
                result = check(f)
                self.assertIsNone(subject.require_result(result, emit_relocs=emitted))
                self.assertEqual((result['Status'], result['Scope']), (subject.STATUS, subject.SCOPE))
                self.assertEqual((result['Profile'], result['Mode'], result['Linkage']), ('CM3', 'Os-lto', 'direct'))
                self.assertEqual(len(result['LinkContract']['Symbols']), 26)
                self.assertEqual(len(result['MandatoryDefinitions']), 30)
                self.assertEqual(len(result['AdditionalConsumerOrigins']), 3)
                for key, expected in (('ForwardProviderCount', 8), ('ReverseProviderCount', 4),
                        ('ReverseReferenceCount', 5), ('ColdAnchorReadCount', 2),
                        ('StartupVectorReferenceCount', 3), ('OriginalBindingRelocations', 10),
                        ('AppliedBindingRelocations', 10 if emitted else 0)):
                    self.assertIs(type(result[key]), int)
                    self.assertEqual(result[key], expected)
                self.assertEqual(result['MachineSha256'], sha(f.machine.data))
                self.assertEqual(result['FinalSha256'], sha(f.final.data))

    def test_o2_entrypoints_are_never_called_or_relabelled(self):
        f = fixtures.Fixture()
        link_proxy = SimpleNamespace(**vars(link))
        binding_proxy = SimpleNamespace(**vars(binding))
        link_proxy.audit = Mock(side_effect=AssertionError('O2 audit entry point called'))
        binding_proxy.inspect = Mock(side_effect=AssertionError('O2 inspect entry point called'))
        result = subject.inspect(f.image, core, link_proxy, binding_proxy, base.ATTRS,
                                 machine_attributes_text=base.ATTRS)
        link_proxy.audit.assert_not_called()
        binding_proxy.inspect.assert_not_called()
        self.assertEqual(result['LinkContract']['Mode'], 'Os-lto')
        self.assertNotIn('O2', json.dumps(result))

    def test_literal_selector_and_complete_machine_attributes_required(self):
        for selector in (0, 1, 0.0, 1.0, None, 'true'):
            with self.subTest(selector=repr(selector)):
                self.rejects(fixtures.Fixture(), emit_relocs=selector)
        for attributes in (None, '', base.ATTRS + '\n Tag_ABI_HardFP_use: SP only\n'):
            with self.subTest(attributes=attributes):
                self.rejects(fixtures.Fixture(), machine_attributes_text=attributes)

    def test_headers_soft_flags_and_provider_membership_reject(self):
        for change in ('hard-reader', 'machine-flags', 'final-kind', 'third-provider', 'provider-bytes', 'map-hash'):
            f = fixtures.Fixture()
            if change == 'hard-reader':
                f.image.float_abi = 'hard'
            elif change == 'machine-flags':
                f.machine.write(36, struct.pack('<I', 0x05000400))
            elif change == 'final-kind':
                f.final.write(16, struct.pack('<H', 1))
            elif change == 'third-provider':
                f.image.providers['foreign.o'] = copy.deepcopy(f.machine)
            elif change == 'provider-bytes':
                f.image.providers['machine.o'] = copy.deepcopy(f.machine)
                f.image.providers['machine.o'].write(0x100, b'\x01')
            else:
                f.image.link_map_hash = 'not-a-hash'
            with self.subTest(change=change):
                self.rejects(f)

    def test_public_forward_definitions_and_fixed_local_roles(self):
        for name, field, value in ((subject.PUBLIC[0], 'kind', 'STT_OBJECT'),
                (subject.FORWARD[0], 'binding', 'STB_LOCAL'),
                (subject.ANCHOR, 'binding', 'STB_GLOBAL'),
                (subject.SLOT, 'binding', 'STB_GLOBAL'), ('fiber_panic', 'binding', 'STB_WEAK')):
            for side in ('machine', 'final'):
                f = fixtures.Fixture()
                getattr(f, side).symbol(name)[field] = value
                with self.subTest(name=name, side=side):
                    self.rejects(f)

    def test_reverse_providers_missing_alias_and_wrong_numeric_metadata(self):
        for name in subject.REVERSE:
            for change in ('missing', 'alias', 'boolean-size', 'float-value'):
                f = fixtures.Fixture()
                row = f.machine.symbol(name)
                if change == 'missing':
                    f.machine.symbols.remove(row)
                elif change == 'alias':
                    f.machine.symbols.append(dict(row, name='foreign_alias'))
                elif change == 'boolean-size':
                    row['size'] = True
                else:
                    row['value'] = float(row['value'])
                with self.subTest(name=name, change=change):
                    self.rejects(f)

    def test_whole_section_origin_and_final_entry_are_mandatory(self):
        for change in ('address', 'extent', 'entry', 'provider'):
            f = fixtures.Fixture()
            if change in ('address', 'extent'):
                f.image.placements['machine.o', '.text'] = ((0x444, 0x900) if change == 'address' else (0x440, 0x8FC))
            elif change == 'entry':
                f.final.symbol(subject.REVERSE[0])['value'] += 2
            else:
                f.startup.symbols.append(dict(f.machine.symbol(subject.REVERSE[0])))
            with self.subTest(change=change):
                self.rejects(f)

    def test_pointer_tables_original_addend_kind_and_final_value_reject(self):
        for section in (4, 5):
            for change in ('source-addend', 'kind', 'final-value', 'missing-applied'):
                f = fixtures.Fixture()
                if change == 'source-addend':
                    f.machine.write(f.machine.sections[section].header.sh_offset, struct.pack('<I', 4))
                elif change == 'kind':
                    f.machine.relocations[section, 0] = (10, f.machine.relocations[section, 0][1])
                elif change == 'final-value':
                    f.final.write(f.final.sections[section].header.sh_offset, struct.pack('<I', 0))
                else:
                    del f.final.relocations[section, 0]
                with self.subTest(section=section, change=change):
                    self.rejects(f)

    def test_slot_zero_fill_load_and_vector_template_reject(self):
        for change in ('file-backed-slot', 'executable-slot', 'slot-size', 'vector-word', 'vector-align'):
            f = fixtures.Fixture()
            if change == 'file-backed-slot':
                f.final.loads[1]['FileSize'] = 4
            elif change == 'executable-slot':
                f.final.loads[1]['Flags'] |= 1
            elif change == 'slot-size':
                f.machine.sections[3].header.sh_size = 8
            elif change == 'vector-word':
                f.final.write(0x400 + 15 * 4, struct.pack('<I', 0))
            else:
                f.final.sections[1].header.sh_addralign = 512
            with self.subTest(change=change):
                self.rejects(f)

    def test_reverse_sites_original_kind_addend_and_target_reject(self):
        for change in ('missing', 'kind', 'target', 'addend', 'symbol-index-bool'):
            f = fixtures.Fixture()
            _, _, offset, _ = f.call_sites[0]
            kind, target = f.machine.relocations[1, offset]
            if change == 'missing':
                del f.machine.relocations[1, offset]
            elif change == 'kind':
                f.machine.relocations[1, offset] = (2, target)
            elif change == 'target':
                f.machine.relocations[1, offset] = (kind, f.machine.symbol(subject.REVERSE[0]))
            elif change == 'addend':
                f.machine.write(0x100 + offset, fixtures.bl(offset, offset + 4))
            else:
                f.machine.relocations[1, offset] = (kind, dict(target, index=True))
            with self.subTest(change=change):
                self.rejects(f)

    def test_reverse_applied_bytes_metadata_and_disassembly_reject(self):
        for change in ('retarget', 'missing', 'wrong-kind', 'text', 'interior'):
            f = fixtures.Fixture()
            _, _, _, offset = f.call_sites[0]
            key = (2, 0x400 + offset)
            if change == 'retarget':
                f.final.write(0x800 + offset, fixtures.bl(key[1], f.final.symbol(subject.REVERSE[0])['value'] & ~1))
            elif change == 'missing':
                del f.final.relocations[2, offset]
            elif change == 'wrong-kind':
                f.final.relocations[2, offset] = (2, f.final.relocations[2, offset][1])
            elif change == 'text':
                mnemonic, _, raw = f.image.instructions[key]
                f.image.instructions[key] = (mnemonic, '0 <foreign>', raw)
            else:
                f.image.instructions[2, key[1] + 2] = ('nop', '', b'\x00\xbf')
            with self.subTest(change=change):
                self.rejects(f)

    def test_task_return_original_zero_and_applied_thumb_pointer(self):
        for change in ('source-addend', 'applied-interior', 'named-target'):
            f = fixtures.Fixture()
            first, last = f.return_site
            if change == 'source-addend':
                f.machine.write(0x100 + first, struct.pack('<I', 4))
            elif change == 'applied-interior':
                f.final.write(0x800 + last, struct.pack('<I', f.final.symbol(subject.REVERSE[3])['value'] + 2))
            else:
                f.machine.relocations[1, first] = (2, f.machine.symbol(subject.REVERSE[2]))
            with self.subTest(change=change):
                self.rejects(f)

    def test_cold_narrow_byte_read_and_anchor_pointer_fail_closed(self):
        for change in ('read', 'pointer', 'mapping', 'final-only'):
            f = fixtures.Fixture()
            name, first, last = f.cold_sites[0]
            start = f.machine.symbol(name)['value'] & ~1
            if change == 'read':
                f.machine.write(0x100 + start + 2, b'\x1b\x68')
            elif change == 'pointer':
                f.final.write(0x800 + last, struct.pack('<I', f.final.symbol(subject.ANCHOR)['value'] + 1))
            elif change == 'mapping':
                f.literal_ranges[id(f.machine)] = []
            else:
                at = (f.final.symbol(name)['value'] & ~1) - 0x400
                f.final.write(0x800 + at + 2, b'\x00\xbf')
            with self.subTest(change=change):
                self.rejects(f)

    def test_os_high_register_t32_cold_form_is_explicitly_unsupported(self):
        f = fixtures.Fixture()
        name, old_pool, old_final_pool = f.cold_sites[1]
        start = f.machine.symbol(name)['value'] & ~1
        last = f.final.symbol(name)['value'] & ~1
        raw = bytes.fromhex('dff8088098f80030704700bf') + bytes(4)
        f.write_function(name, raw)
        before_ref = f.machine.relocations.pop((1, old_pool))
        after_ref = f.final.relocations.pop((2, old_final_pool))
        pool, final_pool = start + 12, last - 0x400 + 12
        f.machine.relocations[1, pool] = before_ref
        f.final.relocations[2, final_pool] = after_ref
        f.machine.write(0x100 + pool, struct.pack('<I', f.machine.symbol(subject.ANCHOR)['value']))
        f.final.write(0x800 + final_pool, struct.pack('<I', f.final.symbol(subject.ANCHOR)['value']))
        f.literal_ranges[id(f.machine)].remove((old_pool, old_pool + 4))
        f.literal_ranges[id(f.machine)].append((pool, pool + 4))
        f.literal_ranges[id(f.final)].remove((last + 8, last + 12))
        f.literal_ranges[id(f.final)].append((last + 12, last + 16))
        for key in list(f.image.instructions):
            if key[0] == 2 and last <= key[1] < last + 12:
                del f.image.instructions[key]
        f.image.instructions[2, last] = ('ldr', 'r8, [pc, #8]', raw[:4])
        f.image.instructions[2, last + 4] = ('ldrb', 'r3, [r8]', raw[4:8])
        with self.assertRaisesRegex(subject.Rejected, 'unsupported or invalid cold read in ' + name):
            check(f)

    def test_wide_r8_positive_binds_later_anchor_and_explicit_call_assumption(self):
        for emitted in (False, True):
            f = wide_fixture(emitted)
            result = check(f)
            row = result['ColdAnchorReads'][1]
            with self.subTest(emitted=emitted):
                self.assertEqual((row['BaseRegister'], row['LoadOffset'], row['ReadOffset'],
                                  row['ByteDisplacement']), (8, 4, 24, 1))
                self.assertEqual(row['AnchorReference']['ResolvedByteAddress'], 0xE01)
                self.assertIs(row['InitialCohortReadIsNotABIAnchorRead'], True)
                self.assertEqual(row['InterveningCallOffsets'], [20])
                self.assertIs(row['AAPCSCalleeSavedRegisterAssumption'], True)
                self.assertIs(row['CalleeRegisterPreservationProven'], False)
                self.assertIs(row['ControlFlowOrDominanceProven'], False)
                self.assertEqual(row['InterveningCalls'][0]['Name'], fixtures.FRAME)
                self.assertEqual(result['AppliedBindingRelocations'], 10 if emitted else 0)

    def test_wide_records_use_core_normalized_mnemonics_not_width_suffixes(self):
        for offset, normalized in ((4, 'ldr'), (24, 'ldrb')):
            f = wide_fixture()
            key = (2, f.wide.last + offset)
            mnemonic, operand, raw = f.image.instructions[key]
            self.assertEqual(mnemonic, normalized)
            self.assertEqual(len(raw), 4)
            check(f)
            f.image.instructions[key] = (normalized + '.w', operand, raw)
            with self.subTest(offset=offset):
                self.rejects(f)

    def test_wide_r8_clobber_or_unsupported_instruction_rejects(self):
        for raw in (bytes.fromhex('8046'), bytes.fromhex('8044'), bytes.fromhex('00be'),
                    bytes.fromhex('00bf')):
            f = wide_fixture()
            for elf, offset in ((f.machine, 0x100 + f.wide.start + 10),
                                (f.final, 0x800 + f.wide.last - 0x400 + 10)):
                elf.write(offset, raw)
            with self.subTest(raw=raw.hex()):
                self.rejects(f)

    def test_wide_r8_effect_subset_rejects_actual_r8_and_pc_destinations(self):
        for raw in (bytes.fromhex('8046'), bytes.fromhex('8044'), bytes.fromhex('00f10108'),
                    bytes.fromhex('00f1010f'), bytes.fromhex('00f80f80')):
            with self.subTest(raw=raw.hex()):
                self.assertIsNone(subject._preserves_r8(raw))
        for raw in (bytes.fromhex('1f46'), bytes.fromhex('10f14d0f'), bytes.fromhex('00f14c09'),
                    bytes.fromhex('27f00100'), bytes.fromhex('10b9'), bytes.fromhex('01d0')):
            with self.subTest(raw=raw.hex()):
                self.assertIs(subject._preserves_r8(raw), False)

    def test_wide_call_original_and_applied_authority_reject_mutations(self):
        for change in ('missing', 'kind', 'addend', 'retarget', 'applied', 'text'):
            f = wide_fixture()
            if change == 'missing':
                del f.machine.relocations[1, f.wide.call]
            elif change == 'kind':
                f.machine.relocations[1, f.wide.call] = (2, f.machine.symbol(fixtures.FRAME))
            elif change == 'addend':
                f.machine.write(0x100 + f.wide.call, fixtures.bl(f.wide.call, f.wide.call + 4))
            elif change == 'retarget':
                place = f.wide.last + 20
                f.final.write(0x800 + f.wide.final_call, fixtures.bl(place, f.final.symbol(subject.REVERSE[0])['value'] & ~1))
            elif change == 'applied':
                del f.final.relocations[2, f.wide.final_call]
            else:
                key = (2, f.wide.last + 20)
                mnemonic, _, raw = f.image.instructions[key]
                f.image.instructions[key] = (mnemonic, '0 <foreign>', raw)
            with self.subTest(change=change):
                self.rejects(f)

    def test_wide_cohort_only_wrong_anchor_and_literal_text_reject(self):
        for change in ('cohort-only', 'wrong-pointer', 'wrong-displacement', 'literal-text', 'extra-rel'):
            f = wide_fixture()
            if change in ('cohort-only', 'wrong-displacement'):
                raw = bytes.fromhex('98f80030' if change == 'cohort-only' else '98f80230')
                f.machine.write(0x100 + f.wide.start + 24, raw)
                f.final.write(0x800 + f.wide.last - 0x400 + 24, raw)
            elif change == 'wrong-pointer':
                f.final.write(0x800 + f.wide.final_pool, struct.pack('<I', 0xE01))
            elif change == 'literal-text':
                key = (2, f.wide.last + 4)
                mnemonic, _, raw = f.image.instructions[key]
                f.image.instructions[key] = (mnemonic, 'r8, [pc, #20]', raw)
            else:
                f.machine.relocations[1, f.wide.start + 8] = (2, f.machine.symbol(subject.ANCHOR))
            with self.subTest(change=change):
                self.rejects(f)

    def test_wide_final_only_instruction_and_mapping_drift_reject(self):
        for change in ('raw', 'interior', 'missing-dis', 'mapping'):
            f = wide_fixture()
            key = (2, f.wide.last + 12)
            if change == 'raw':
                f.final.write(0x800 + f.wide.last - 0x400 + 12, bytes.fromhex('8046'))
            elif change == 'interior':
                f.image.instructions[2, f.wide.last + 6] = ('nop', '', b'\x00\xbf')
            elif change == 'missing-dis':
                del f.image.instructions[key]
            else:
                f.literal_ranges[id(f.final)].append((f.wide.last + 12, f.wide.last + 14))
            with self.subTest(change=change):
                self.rejects(f)

    def test_original_startup_rel_kind_addend_and_applied_membership(self):
        for offset, name in subject.VECTORS:
            for change in ('missing', 'kind', 'addend', 'applied'):
                f = fixtures.Fixture()
                if change == 'missing':
                    del f.startup.relocations[1, offset]
                elif change == 'kind':
                    f.startup.relocations[1, offset] = (10, f.startup.relocations[1, offset][1])
                elif change == 'addend':
                    f.startup.write(0x400 + offset, struct.pack('<I', 4))
                else:
                    del f.final.relocations[1, offset]
                with self.subTest(name=name, change=change):
                    self.rejects(f)

    def test_result_guard_rejects_partial_renamed_or_promoted_records(self):
        good = check(fixtures.Fixture())
        mutations = [('Mode', 'O2-lto'), ('Scope', 'anything'), ('MandatoryDefinitions', {}),
                     ('ReverseReferences', []), ('ColdAnchorReads', []), ('StartupVectors', []),
                     ('MachineSha256', '0'), ('RuntimeProviderBindingsValidated', 1)]
        mutations += [(name, True) for name in subject.NONCLAIMS]
        mutations += [(name, float(good[name])) for name in ('RequiredCellsSatisfied',
                       'ColdAnchorReadCount', 'AppliedBindingRelocations')]
        mutations += [('RequiredCellsSatisfied', False), ('ColdAnchorReadCount', True)]
        for key, value in mutations:
            broken = copy.deepcopy(good)
            broken[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(subject.Rejected):
                subject.require_result(broken, emit_relocs=True)
        for field in ('Mode', 'AppliedPointerRelocations', 'Qualification'):
            broken = copy.deepcopy(good)
            broken['LinkContract'][field] = {'Mode': 'O2-lto', 'AppliedPointerRelocations': 7.0,
                                              'Qualification': True}[field]
            with self.subTest(link=field), self.assertRaises(subject.Rejected):
                subject.require_result(broken, emit_relocs=True)

    def test_inputs_helpers_unchanged_and_no_io_or_process(self):
        f = fixtures.Fixture()
        before = [(elf.data, copy.deepcopy(elf.symbols), copy.deepcopy(elf.relocations))
                  for elf in (f.machine, f.startup, f.final)]
        placements = copy.deepcopy(f.image.placements)
        helper_names = (link.PUBLIC, binding.REVERSE, link.audit, binding.inspect, binding.Bindings)
        with patch('builtins.open', side_effect=AssertionError('unexpected file I/O')), \
                patch.object(Path, 'read_bytes', side_effect=AssertionError('unexpected path read')), \
                patch.object(Path, 'read_text', side_effect=AssertionError('unexpected text read')), \
                patch.object(Path, 'write_bytes', side_effect=AssertionError('unexpected path write')):
            result = check(f)
        self.assertEqual(before, [(elf.data, elf.symbols, elf.relocations) for elf in (f.machine, f.startup, f.final)])
        self.assertEqual(placements, f.image.placements)
        self.assertEqual(helper_names, (link.PUBLIC, binding.REVERSE, link.audit, binding.inspect, binding.Bindings))
        self.assertFalse(hasattr(f.image, '_contract_machine_owner'))
        for field in subject.NONCLAIMS:
            self.assertIs(result[field], False)
        result['MandatoryDefinitions'][subject.ANCHOR]['Original']['name'] = 'changed-proof-only'
        self.assertEqual(f.machine.symbol(subject.ANCHOR)['name'], subject.ANCHOR)

    def test_helper_contract_drift_rejects_before_validation(self):
        for which, field in (('link', 'PRIVATE'), ('binding', 'REVERSE'), ('binding', 'COLD')):
            left, right = SimpleNamespace(**vars(link)), SimpleNamespace(**vars(binding))
            setattr(left if which == 'link' else right, field, ('foreign',))
            with self.subTest(which=which, field=field), self.assertRaises(subject.Rejected):
                subject.inspect(fixtures.Fixture().image, core, left, right, base.ATTRS,
                                machine_attributes_text=base.ATTRS)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if (output.exists() or args.output_dir.is_symlink() or not output.is_relative_to(temporary)
            or output.is_relative_to(REPO) or REPO.is_relative_to(output)):
        parser.error('fresh external TEMP output directory required')
    paths = (Path(__file__).resolve(), SUBJECT, LINK, BINDING, FIXTURE, BASE_FIXTURE, CORE)
    report = dict(Status='FAIL', Scope='PURE_SYNTHETIC_CM3_OS_LTO_ABI_ORCHESTRATION_CONTROLS_ONLY',
        Tests=0, ExpectedTestMethods=EXPECTED_METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={}, SourceDrift=[], SourceClosureVerified=False, ClosingFilesVerified=0,
        SyntheticInputs=True, ActualELFTested=False, ActualOsShapesQualified=False,
        QualifiedParserExecuted=False, NativeCommandsExecuted=0, ToolInvocations=0,
        Qualification=False, FullABIProof=False, CanonicalProtocolValidated=False,
        FinalReferenceParity=False, CpuExecution=False, BoardExecution=False,
        GlobalFreezeQualified=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError('unoptimized Python required')
        buffers = {path: path.read_bytes() for path in paths}
        report['SourceHashes'] = {str(path): sha(raw) for path, raw in buffers.items()}
        for path, expected in PINS.items():
            if sha(buffers[path]) != expected:
                raise ValueError('frozen helper/fixture pin mismatch: ' + str(path))
        global subject, link, binding, fixtures, base, core
        with patch('subprocess.Popen', side_effect=AssertionError('pure tests cannot spawn')), \
                patch('os.system', side_effect=AssertionError('pure tests cannot execute commands')):
            link = load('_os_abi_frozen_link', LINK, buffers[LINK])
            binding = load('_os_abi_frozen_bindings', BINDING, buffers[BINDING])
            base = load('_os_abi_base_synthetic_fixture', BASE_FIXTURE, buffers[BASE_FIXTURE])
            fixtures = load('_os_abi_synthetic_fixture', FIXTURE, buffers[FIXTURE])
            core = fixtures.core_primitives(buffers[CORE])
            fixtures.old, fixtures.audit, fixtures.core = base, link, core
            subject = load('_os_abi_subject', SUBJECT, buffers[SUBJECT])
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(AbiTests)
            if suite.countTestCases() != EXPECTED_METHODS:
                raise ValueError('exact twenty-five implemented methods required')
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), FailureDetails=[dict(Test=str(case), Detail=detail)
                for case, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == EXPECTED_METHODS and not result.skipped:
            report['Status'] = 'PASS'
    except Exception:
        report.update(Status='FAIL', Error=traceback.format_exc(), Errors=report['Errors'] + 1)
    finally:
        for path, expected in report['SourceHashes'].items():
            try:
                if sha(Path(path).read_bytes()) == expected:
                    report['ClosingFilesVerified'] += 1
                else:
                    report['SourceDrift'].append(path)
            except OSError:
                report['SourceDrift'].append(path)
        report['SourceClosureVerified'] = len(report['SourceHashes']) == len(paths) and not report['SourceDrift']
        if not report['SourceClosureVerified']:
            report['Status'] = 'FAIL'
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / 'results.json'
    receipt.write_bytes((json.dumps(report, indent=2, sort_keys=True) + '\n').encode('ascii'))
    print('Receipt:', receipt, sha(receipt.read_bytes()), flush=True)
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
