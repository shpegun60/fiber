"""Synthetic Os effect/REL controls using authenticated neutral primitives only."""

import argparse
import copy
import hashlib
from pathlib import Path
import json
import struct
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
HELPER = ROOT / 'tools/fixtures/cm3_lto_attributes/attributes.py'
HELPER_SHA = '93275A5903A67CB2DAEABB76BEF1431B052878BB478455E54343DB20881E83C0'
METHODS = 20
API = H = None
ROOTS = ('fiber_internal_task_return', 'ctxrt_v1_init', 'ctxrt_v1_current',
    'ctxrt_v1_start', 'ctxrt_v1_set_dispatcher', 'ctxrt_v1_yield',
    'fiber_internal_runtime_load_current_context', 'fiber_internal_runtime_select_scheduler_candidate',
    'fiber_internal_runtime_publish_current_context', 'fiber_internal_runtime_require_current_context',
    'fiber_internal_scheduler_is_configured', 'fiber_internal_runtime_close_context_configuration',
    'fiber_internal_runtime_context_configuration_is_open', 'fiber_panic')
FWD = ('fiber_port_context_init', 'fiber_port_runtime_memory_barrier', 'fiber_port_panic_wait',
    'fiber_port_require_scheduler_configuration_environment', 'fiber_port_runtime_prepare_start',
    'fiber_port_runtime_select_first', 'fiber_port_runtime_start_first', 'fiber_port_runtime_schedule')
THREAD = ('ctxrt_v1_current', 'ctxrt_v1_yield', 'fiber_internal_runtime_load_current_context')
THREAD_SECTION = '.text.fiber_runtime_thread_functions'
COLD = 'fiber_internal_scheduler_store_pick_next'
SETTER = 'ctxrt_v1_set_dispatcher'
PANIC = 'fiber_panic'
STRESS = 'ctxrt_attribute_stress'
CTOR_I, CTOR_D = '_sub_I_00100_0', '_sub_D_00100_1'
CALL = bytes.fromhex('fff7feff')
TAIL = bytes.fromhex('fff7febf')


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def symbol(name, section='SHN_UNDEF', *, value=0, size=0, kind='STT_NOTYPE', binding='STB_GLOBAL'):
    return dict(name=name, section=section, value=value, size=size, kind=kind,
                binding=binding, visibility='STV_DEFAULT', index=0)


class Image:
    """Invented metadata and bytes, not genuine ELF or measured Os codegen."""
    def __init__(self, *, stress=False, raw_stress=False):
        self.final = False
        self.names = ['', '.text', THREAD_SECTION, '.bss', '.rodata']
        functions = [STRESS] if stress else list(ROOTS) + [COLD]
        if not stress or raw_stress:
            functions += [CTOR_I, CTOR_D]
        self.symbols, self.relocations = [], {}
        contents = {1: bytearray(), 2: bytearray(), 3: bytearray(16), 4: bytearray(128)}
        self.maps = {1: [(0, 't')], 2: [(0, 't')]}
        for name in functions:
            section = 2 if name in THREAD else 1
            start = len(contents[section])
            contents[section] += bytes.fromhex('00bf') * 16
            self.maps[section].append((start, 't'))
            self.symbols.append(symbol(name, section, value=start | 1, size=32, kind='STT_FUNC',
                binding='STB_LOCAL' if name in (CTOR_I, CTOR_D) else 'STB_WEAK' if name == PANIC else 'STB_GLOBAL'))
        header = bytearray(52)
        header[:7] = b'\x7fELF\x01\x01\x01'
        struct.pack_into('<HHI', header, 16, 1, 40, 1)
        self.data = bytes(header)
        self.sections = [SimpleNamespace(header=SimpleNamespace(sh_type='SHT_NULL', sh_size=0, sh_flags=0, sh_offset=0))]
        for section in range(1, 5):
            raw = bytes(contents[section])
            self.sections.append(SimpleNamespace(header=SimpleNamespace(sh_offset=len(self.data), sh_size=len(raw),
                sh_flags=6 if section < 3 else 3 if section == 3 else 2,
                sh_type='SHT_NOBITS' if section == 3 else 'SHT_PROGBITS')))
            self.data += raw
        if not stress:
            for index, name in enumerate(FWD):
                self.reference(4, index * 4, 2, name)
            self.instrument_cold()
        if raw_stress:
            item = self.function(STRESS)
            for index, name in enumerate(('__cyg_profile_func_enter', '__cyg_profile_func_exit', '__stack_chk_fail',
                    '__ubsan_handle_add_overflow', '__ubsan_handle_out_of_bounds', '__sanitizer_cov_trace_pc')):
                self.transfer(STRESS, index * 4, name)
            self.pool(STRESS, 24, '__stack_chk_guard')
            counter = symbol('__gcov0.' + STRESS, 3, size=8, kind='STT_OBJECT', binding='STB_LOCAL')
            self.symbols.append(counter)
            self.pool(STRESS, 28, counter)
            self.reference(4, 64, 2, '__gcov_merge_add')
            self.transfer(CTOR_I, 0, '__gcov_init')
            self.transfer(CTOR_D, 0, '__gcov_exit')
        self.reindex()

    def reindex(self):
        for index, row in enumerate(self.symbols):
            row['index'] = index

    def function(self, name):
        return next(row for row in self.symbols if row['name'] == name)

    def reference(self, section, offset, kind, target):
        if type(target) is str:
            matches = [row for row in self.symbols if row['name'] == target]
            if matches:
                target = matches[0]
            else:
                target = symbol(target)
                self.symbols.append(target)
        self.relocations[section, offset] = kind, target
        self.reindex()

    def put(self, section, offset, raw):
        h = self.sections[section].header
        if offset < 0 or offset + len(raw) > h.sh_size:
            raise ValueError('synthetic write bounds')
        start = h.sh_offset + offset
        self.data = self.data[:start] + raw + self.data[start + len(raw):]

    def transfer(self, name, relative, target, *, kind=10, raw=CALL):
        item = self.function(name)
        offset = (item['value'] & ~1) + relative
        self.put(item['section'], offset, raw)
        self.reference(item['section'], offset, kind, target)

    def pool(self, name, relative, target):
        item = self.function(name)
        offset = (item['value'] & ~1) + relative
        self.put(item['section'], offset, bytes(4))
        self.maps[item['section']].append((offset, 'd'))
        self.reference(item['section'], offset, 2, target)

    def instrument_cold(self):
        for offset, target in ((0, '__cyg_profile_func_enter'), (4, '__cyg_profile_func_exit'),
                (8, '__stack_chk_fail'), (12, '__sanitizer_cov_trace_pc')):
            self.transfer(COLD, offset, target)
        counter = symbol('__gcov0.' + COLD, 3, size=8, kind='STT_OBJECT', binding='STB_LOCAL')
        self.symbols.append(counter)
        self.pool(COLD, 24, counter)
        self.pool(COLD, 28, '__stack_chk_guard')
        self.reference(4, 64, 2, '__gcov_merge_add')
        self.transfer(CTOR_I, 0, '__gcov_init')
        self.transfer(CTOR_D, 0, '__gcov_exit')

    def instrument(self, name):
        self.transfer(name, 0, '__cyg_profile_func_enter')
        self.transfer(name, 4, '__cyg_profile_func_exit')

    def constructor_arrays(self, *, init=CTOR_I, fini=CTOR_D):
        sections = {}
        for side, name, kind, target in (('I', '.init_array.00100', 'SHT_INIT_ARRAY', init),
                                       ('D', '.fini_array.00100', 'SHT_FINI_ARRAY', fini)):
            section = len(self.sections)
            self.names.append(name)
            self.sections.append(SimpleNamespace(header=SimpleNamespace(sh_offset=len(self.data),
                sh_size=4, sh_flags=3, sh_type=kind, sh_addralign=4, sh_entsize=4)))
            self.data += bytes(4)
            self.maps[section] = [(0, 'd')]
            self.reference(section, 0, 38, self.function(target))
            sections[side] = section
        return sections

    def section_read(self, section, offset, size):
        header = self.sections[section].header
        if not (0 <= offset and 0 < size and offset + size <= header.sh_size):
            raise ValueError('synthetic section read bounds')
        start = header.sh_offset + offset
        return self.data[start:start + size]

    def mapping(self, section, position):
        rows = sorted(self.maps[section])
        index = max(index for index, (offset, _) in enumerate(rows) if offset <= position)
        return rows[index][1], rows[index + 1][0] if index + 1 < len(rows) else self.sections[section].header.sh_size


def width(first):
    return 4 if first >> 11 in (29, 30, 31) else 2


def address_form(raw, place):
    if raw == CALL:
        return 'bl', place, None, -4
    if raw == bytes.fromhex('fff7fdff'):
        return 'bl', place - 2, None, -6
    return None


CORE = SimpleNamespace(_ELF=Image, _width=width, _address_form=address_form)


class EffectsTests(unittest.TestCase):
    def inspect(self, image=None, **kwargs):
        return API.inspect_lowered(image or Image(), CORE, H, **kwargs)

    def test_positive_complete_os_owned_roots(self):
        proof = self.inspect()
        self.assertEqual(proof['Mode'], 'Os-lto')
        self.assertEqual(proof['Scope'], 'NATIVE_CM3_OS_LTO_COMMON_ATTRIBUTE_EFFECT_COMPONENT_ONLY')
        self.assertEqual(proof['ProtectedFunctions'], 14)
        self.assertEqual([row['Name'] for row in proof['RootEvidence']], list(ROOTS))
        self.assertIs(proof['AllProtectedBodiesClean'], True)
        self.assertIs(proof['OriginalRELFieldsCensused'], True)
        self.assertIs(proof['OsCompilerOptionsValidated'], False)
        self.assertFalse(hasattr(H, 'inspect_lowered'))
        self.assertIs(API.require_result(proof), proof)

    def test_all_three_actual_carrier_mutant_models(self):
        for name in ('ctxrt_v1_current', 'fiber_internal_runtime_load_current_context', PANIC):
            with self.subTest(name=name):
                image = Image()
                image.instrument(name)
                proof = self.inspect(image, mutation=name)
                self.assertEqual(proof['Status'], API.MUTANT)
                self.assertIs(proof['CompiledAnnotationMutantDetected'], True)
                self.assertIs(proof['AllProtectedBodiesClean'], False)
                with self.assertRaises(API.Rejected):
                    self.inspect(image)
                with self.assertRaises(API.Rejected):
                    self.inspect(Image(), mutation=name)
        image = Image()
        image.instrument('fiber_internal_runtime_publish_current_context')
        with self.assertRaises(API.Rejected):
            self.inspect(image, mutation='ctxrt_v1_current')

    def test_protected_and_raw_stress_families(self):
        clean = self.inspect(Image(stress=True), stress=True)
        self.assertEqual(clean['ProtectedFunctions'], 1)
        self.assertEqual(clean['Undefined'], [])
        raw = Image(stress=True, raw_stress=True)
        proof = self.inspect(raw, stress=True, mutation=STRESS)
        self.assertIs(proof['StressFamiliesActivated'], True)
        self.assertTrue(proof['StressCounterEvidence']['References'])
        with self.assertRaises(API.Rejected):
            self.inspect(raw, stress=True)
        with self.assertRaises(API.Rejected):
            self.inspect(Image(stress=True), stress=True, mutation=STRESS)

    def test_setter_inline_effects_remain_pending(self):
        image = Image()
        image.instrument(SETTER)
        proof = self.inspect(image)
        self.assertEqual(proof['Status'], API.PENDING)
        self.assertIs(proof['AllProtectedBodiesClean'], False)
        self.assertIs(proof['ColdInlineAttributionValidated'], False)
        self.assertEqual(len(proof['UnresolvedAttribution']), 1)
        self.assertIs(proof['UnresolvedAttribution'][0]['AttributionValidated'], False)
        forged = copy.deepcopy(proof)
        forged.update(Status=API.PASS, AllProtectedBodiesClean=True)
        with self.assertRaises(API.Rejected):
            API.require_result(forged)

    def test_catalog_bindings_aliases_and_thread_sections(self):
        for defect in ('missing', 'foreign', 'alias', 'thread', 'local'):
            with self.subTest(defect=defect):
                image = Image()
                item = image.function('ctxrt_v1_current')
                if defect == 'missing':
                    image.symbols.remove(item)
                elif defect in ('foreign', 'alias'):
                    extra = dict(item, name='foreign_function')
                    if defect == 'foreign':
                        extra['value'] += 2
                    image.symbols.append(extra)
                elif defect == 'thread':
                    image.names[2] = '.text.wrong'
                else:
                    item['binding'] = 'STB_LOCAL'
                with self.assertRaises(API.Rejected):
                    self.inspect(image)

    def test_header_and_ir_substitute_rejection(self):
        for offset, raw in ((4, b'\x02'), (5, b'\x02'), (16, b'\x02\0'), (18, b'\x3e\0'), (36, b'\0\x04\0\x05')):
            with self.subTest(offset=offset):
                image = Image()
                image.data = image.data[:offset] + raw + image.data[offset + len(raw):]
                with self.assertRaises(API.Rejected):
                    self.inspect(image)
        image = Image()
        image.names[4] = '.gnu.lto_fake'
        with self.assertRaises(API.Rejected):
            self.inspect(image)

    def test_literal_selector_symbol_and_rel_integer_types(self):
        for kwargs in ({'stress': 1}, {'stress': 0.0}, {'mutation': False}, {'mutation': 'foreign'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(API.Rejected):
                self.inspect(**kwargs)
        for field in ('section', 'index', 'value', 'size'):
            with self.subTest(field=field):
                image = Image()
                image.function('ctxrt_v1_init')[field] = False
                with self.assertRaises(API.Rejected):
                    self.inspect(image)
        for kind in (True, 2.0, 255):
            image = Image()
            _, target = image.relocations[4, 0]
            image.relocations[4, 0] = kind, target
            with self.subTest(kind=kind), self.assertRaises(API.Rejected):
                self.inspect(image)

    def test_rel_bounds_alignment_overlap_and_foreign_target(self):
        for defect in ('straddle', 'unaligned', 'overlap', 'foreign-target', 'nobits'):
            with self.subTest(defect=defect):
                image = Image()
                if defect == 'straddle':
                    image.relocations[4, 126] = image.relocations[4, 0]
                elif defect == 'unaligned':
                    image.relocations[4, 34] = image.relocations.pop((4, 0))
                elif defect == 'overlap':
                    item = image.function(COLD)
                    start = item['value'] & ~1
                    image.relocations[item['section'], start + 2] = image.relocations[item['section'], start]
                elif defect == 'foreign-target':
                    image.relocations[4, 0] = 2, symbol('foreign')
                else:
                    image.sections[4].header.sh_type = 'SHT_NOBITS'
                with self.assertRaises(API.Rejected):
                    self.inspect(image)

    def test_call_tail_and_external_literal_addends(self):
        image = Image()
        image.transfer(COLD, 0, '__cyg_profile_func_enter', kind=30, raw=TAIL)
        proof = self.inspect(image)
        self.assertTrue(any(row['Kind'] == 30 and row['OriginalAddend'] == -4 for row in proof['References']))
        for defect in ('call-addend', 'tail-bytes', 'literal-addend', 'call-nop'):
            with self.subTest(defect=defect):
                image = Image()
                item = image.function(COLD)
                start = item['value'] & ~1
                if defect == 'call-addend':
                    image.put(item['section'], start, bytes.fromhex('fff7fdff'))
                elif defect == 'tail-bytes':
                    image.relocations[item['section'], start] = 30, image.relocations[item['section'], start][1]
                elif defect == 'literal-addend':
                    image.put(4, 0, struct.pack('<I', 4))
                else:
                    image.put(item['section'], start, bytes.fromhex('00bf00bf'))
                with self.assertRaises(API.Rejected):
                    self.inspect(image)

    def test_owner_mapping_extent_and_undefined_use(self):
        for defect in ('instruction-data', 'short-body', 'unowned-hook', 'unused-import'):
            with self.subTest(defect=defect):
                image = Image()
                cold = image.function(COLD)
                start = cold['value'] & ~1
                if defect == 'instruction-data':
                    image.maps[cold['section']].append((start + 24, 't'))
                elif defect == 'short-body':
                    cold['size'] = 26
                elif defect == 'unowned-hook':
                    image.reference(4, 68, 2, '__cyg_profile_func_enter')
                else:
                    image.symbols.append(symbol('__ubsan_handle_sub_overflow'))
                with self.assertRaises(API.Rejected):
                    self.inspect(image)

    def test_raw_counter_definition_reference_and_families_required(self):
        for defect in ('wrong-counter', 'bounds', 'no-reference', 'missing-family'):
            with self.subTest(defect=defect):
                image = Image(stress=True, raw_stress=True)
                counter = image.function('__gcov0.' + STRESS)
                if defect == 'wrong-counter':
                    counter['name'] = '__gcov0.foreign'
                elif defect == 'bounds':
                    counter['size'] = 100
                elif defect == 'no-reference':
                    del image.relocations[1, 28]
                else:
                    del image.relocations[1, 12]
                with self.assertRaises(API.Rejected):
                    self.inspect(image, stress=True, mutation=STRESS)

    def test_constructor_names_bodies_and_counter_ownership(self):
        for suffix in ('', '.lto_priv.0', '.1'):
            with self.subTest(suffix=suffix):
                image = Image()
                image.function(CTOR_I)['name'] += suffix
                self.assertIs(self.inspect(image)['AllProtectedBodiesClean'], True)
        for defect in ('bad-name', 'bad-hook', 'foreign-counter'):
            with self.subTest(defect=defect):
                image = Image()
                if defect == 'bad-name':
                    image.function(CTOR_I)['name'] += '.lto_priv.x'
                elif defect == 'bad-hook':
                    image.transfer(CTOR_I, 4, '__cyg_profile_func_enter')
                else:
                    image.function('__gcov0.' + COLD)['name'] = '__gcov0.foreign'
                with self.assertRaises(API.Rejected):
                    self.inspect(image)

    def test_target1_constructor_array_pairs_and_allowed_suffixes(self):
        for suffix in ('', '.lto_priv.0', '.17'):
            for raw_stress in (False, True):
                with self.subTest(suffix=suffix, raw_stress=raw_stress):
                    image = Image(stress=raw_stress, raw_stress=raw_stress)
                    image.function(CTOR_I)['name'] += suffix
                    image.function(CTOR_D)['name'] += suffix
                    sections = image.constructor_arrays(init=CTOR_I + suffix, fini=CTOR_D + suffix)
                    kwargs = dict(stress=True, mutation=STRESS) if raw_stress else {}
                    saved = copy.deepcopy((image.data, image.names, image.symbols, image.relocations))
                    with patch.object(H, '_resolved', wraps=H._resolved) as resolved:
                        proof = self.inspect(image, **kwargs)
                    self.assertFalse(any(value.args[1] == 38 for value in resolved.call_args_list))
                    rows = [row for row in proof['References'] if row['Kind'] == 38]
                    self.assertEqual(len(rows), 2)
                    for row, side, array, name in zip(rows, ('I', 'D'),
                            ('.init_array.00100', '.fini_array.00100'), (CTOR_I + suffix, CTOR_D + suffix)):
                        self.assertEqual((row['Section'], row['Offset']), (sections[side], 0))
                        self.assertEqual(row['ConstructorArray'], array)
                        self.assertEqual(row['Target'], image.function(name))
                        self.assertEqual(row['Target']['binding'], 'STB_LOCAL')
                        self.assertEqual(row['Target']['kind'], 'STT_FUNC')
                        self.assertEqual(row['Target']['value'] & 1, 1)
                        self.assertEqual(row['SemanticTarget'], name)
                        self.assertEqual(row['FieldBytes'], 4)
                        self.assertEqual(row['SiteBytes'], '00000000')
                        self.assertIs(type(row['OriginalAddend']), int)
                        self.assertEqual(row['OriginalAddend'], 0)
                        self.assertIsNone(row['Owner'])
                        self.assertIsNone(row['ResolvedABS32'])
                        for field in ('AppliedDestinationValidated', 'CompilerHook', 'CompilerCounter',
                                      'OriginalHookTransferValidated'):
                            self.assertIs(row[field], False)
                        self.assertIn(row, proof['MetadataReferences'])
                    for row in proof['References']:
                        if row['Kind'] != 38:
                            self.assertIn('ConstructorArray', row)
                            self.assertIsNone(row['ConstructorArray'])
                    self.assertIs(API.require_result(proof, **kwargs), proof)
                    self.assertEqual(saved, (image.data, image.names, image.symbols, image.relocations))
                    self.assertIs(proof['Qualification'], False)
                    self.assertEqual(proof['RequiredCellsSatisfied'], 0)

    def test_target1_constructor_array_section_geometry_and_uniqueness(self):
        defects = (('sh_type', 'SHT_PROGBITS'), ('sh_type', 'SHT_NOBITS'), ('sh_flags', 0),
            ('sh_flags', 2), ('sh_flags', 7), ('sh_addralign', 0), ('sh_addralign', 2), ('sh_addralign', 8),
            ('sh_entsize', 0), ('sh_entsize', 1), ('sh_entsize', 8), ('sh_size', 0), ('sh_size', 3), ('sh_size', 8))
        for side in ('I', 'D'):
            for field, bad in defects:
                image = Image()
                section = image.constructor_arrays()[side]
                setattr(image.sections[section].header, field, bad)
                with self.subTest(side=side, field=field, bad=bad), self.assertRaises(API.Rejected):
                    self.inspect(image)
            for defect in ('base-name', 'wrong-priority', 'wrong-array-type', 'duplicate'):
                image = Image()
                section = image.constructor_arrays()[side]
                if defect == 'base-name':
                    image.names[section] = '.init_array' if side == 'I' else '.fini_array'
                elif defect == 'wrong-priority':
                    image.names[section] = image.names[section].replace('00100', '00101')
                elif defect == 'wrong-array-type':
                    image.sections[section].header.sh_type = 'SHT_FINI_ARRAY' if side == 'I' else 'SHT_INIT_ARRAY'
                else:
                    image.names.append(image.names[section])
                    image.sections.append(copy.deepcopy(image.sections[section]))
                with self.subTest(side=side, defect=defect), self.assertRaises(API.Rejected):
                    self.inspect(image)

    def test_target1_constructor_array_sites_zero_addends_and_file_bounds(self):
        for side in ('I', 'D'):
            for offset in (-1, 1, 4, False, 0.0):
                image = Image()
                section = image.constructor_arrays()[side]
                image.relocations[section, offset] = image.relocations.pop((section, 0))
                with self.subTest(side=side, offset=offset), self.assertRaises(API.Rejected):
                    self.inspect(image)
            for addend in (1, 4, 0xFFFFFFFF):
                image = Image()
                section = image.constructor_arrays()[side]
                image.put(section, 0, struct.pack('<I', addend))
                with self.subTest(side=side, addend=addend), self.assertRaises(API.Rejected):
                    self.inspect(image)
            for bound in ('negative', 'bool', 'straddle', 'outside'):
                image = Image()
                section = image.constructor_arrays()[side]
                image.sections[section].header.sh_offset = {'negative': -1, 'bool': False,
                    'straddle': len(image.data) - 3, 'outside': len(image.data)}[bound]
                with self.subTest(side=side, bound=bound), self.assertRaises(API.Rejected):
                    self.inspect(image)

    def test_target1_constructor_array_target_side_catalog_binding_kind_and_thumb(self):
        for side, name, opposite in (('I', CTOR_I, CTOR_D), ('D', CTOR_D, CTOR_I)):
            for defect in ('wrong-side', 'nonconstructor', 'priority', 'bad-suffix', 'global', 'weak',
                           'foreign-binding', 'object', 'notype', 'no-thumb', 'foreign-symbol'):
                image = Image()
                section = image.constructor_arrays()[side]
                target = image.function(name)
                if defect == 'wrong-side':
                    image.relocations[section, 0] = 38, image.function(opposite)
                elif defect == 'nonconstructor':
                    image.relocations[section, 0] = 38, image.function(COLD)
                elif defect in ('priority', 'bad-suffix'):
                    target['name'] = name.replace('00100', '00200') if defect == 'priority' else name + '.lto_priv.x'
                elif defect in ('global', 'weak', 'foreign-binding'):
                    target['binding'] = {'global': 'STB_GLOBAL', 'weak': 'STB_WEAK', 'foreign-binding': 'STB_GNU_UNIQUE'}[defect]
                elif defect in ('object', 'notype'):
                    image.relocations[section, 0] = 38, dict(target, kind='STT_OBJECT' if defect == 'object' else 'STT_NOTYPE')
                    image.symbols.append(image.relocations[section, 0][1])
                elif defect == 'no-thumb':
                    target['value'] &= ~1
                else:
                    image.relocations[section, 0] = 38, dict(target, index=99999)
                with self.subTest(side=side, defect=defect), self.assertRaises(API.Rejected):
                    self.inspect(image)
            for defect in ('missing-function', 'different-function-record'):
                image = Image()
                section = image.constructor_arrays()[side]
                functions = H._functions(image)
                walks = {key: H._walk(image, CORE, item) for key, item in functions.items()}
                if defect == 'missing-function':
                    del functions[name]
                else:
                    functions[name] = dict(functions[name], index=99999)
                with self.subTest(side=side, defect=defect), self.assertRaisesRegex(API.Rejected, 'exact constructor-array target'):
                    API._reference(image, CORE, H, functions, walks, (section, 0), image.relocations[section, 0], set())

    def test_target1_is_confined_to_exact_constructor_array_relocation_sites(self):
        for kind in (2, 10, 30, 255, True, 38.0):
            image = Image()
            section = image.constructor_arrays()['I']
            image.relocations[section, 0] = kind, image.function(CTOR_I)
            with self.subTest(kind=kind), self.assertRaises(API.Rejected):
                self.inspect(image)
        for site in ('metadata', 'function'):
            image = Image()
            image.constructor_arrays()
            if site == 'metadata':
                image.reference(4, 68, 38, image.function(CTOR_I))
            else:
                item = image.function(COLD)
                image.relocations[item['section'], item['value'] & ~1] = 38, image.function(CTOR_I)
            with self.subTest(site=site), self.assertRaises(API.Rejected):
                self.inspect(image)

    def test_returned_target1_rows_preserve_narrow_constructor_and_nonclaims(self):
        image = Image()
        image.constructor_arrays()
        image.transfer(COLD, 0, '__cyg_profile_func_enter', kind=30, raw=TAIL)
        original = self.inspect(image)
        index = next(index for index, row in enumerate(original['References']) if row['Kind'] == 38)
        changes = [('ConstructorArray', value) for value in (None, [], '.init_array', '.fini_array.00100')]
        changes += [('ResolvedABS32', dict(Symbol=CTOR_I)), ('ResolvedABS32', False),
            ('AppliedDestinationValidated', True), ('AppliedDestinationValidated', 0), ('Owner', COLD),
            ('Kind', 38.0), ('FieldBytes', 4.0), ('Offset', False), ('Offset', 2), ('OriginalAddend', False),
            ('OriginalAddend', 0.0), ('OriginalAddend', 1), ('SiteBytes', '01000000'),
            ('SemanticTarget', COLD), ('CompilerHook', True), ('CompilerCounter', True),
            ('OriginalHookTransferValidated', True), ('CompilerHook', 0)]
        target_changes = [('name', value) for value in (None, [], COLD, CTOR_D, '_sub_I_00200_0', CTOR_I + '.lto_priv.x')]
        target_changes += [('kind', 'STT_OBJECT'), ('binding', 'STB_GLOBAL'), ('binding', 'STB_WEAK'),
                           ('value', False), ('value', 2)]
        for nested, mutations in ((False, changes), (True, target_changes)):
            for key, bad in mutations:
                proof = copy.deepcopy(original)
                row = proof['References'][index]
                (row['Target'] if nested else row)[key] = bad
                proof['MetadataReferences'] = copy.deepcopy([value for value in proof['References'] if value['Owner'] is None])
                proof['OrdinaryEvidence'] = copy.deepcopy([value for value in proof['References'] if value['Owner'] == COLD])
                with self.subTest(nested=nested, key=key, bad=bad):
                    with self.assertRaises(API.Rejected):
                        API._returned_reference(row)
                    with self.assertRaises(API.Rejected):
                        API.require_result(proof)
        for kind in (2, 10, 30):
            row = copy.deepcopy(next(row for row in original['References'] if row['Kind'] == kind))
            row['ConstructorArray'] = '.init_array.00100'
            with self.subTest(kind=kind), self.assertRaises(API.Rejected):
                API._returned_reference(row)

    def test_inputs_helpers_and_returned_records_not_mutated(self):
        image = Image()
        original = copy.deepcopy((image.data, image.symbols, image.relocations, image.maps))
        helpers = dict(H.__dict__)
        proof = self.inspect(image)
        self.assertEqual(original, (image.data, image.symbols, image.relocations, image.maps))
        self.assertEqual(helpers, H.__dict__)
        proof['RootEvidence'][0]['Symbol']['name'] = 'changed-result-only'
        self.assertEqual(original, (image.data, image.symbols, image.relocations, image.maps))

    def test_returned_leaf_counts_scope_booleans_and_nonclaims(self):
        original = self.inspect()
        mutations = (lambda p: p.update(Mode='O2-lto'), lambda p: p.update(ProtectedFunctions=True),
            lambda p: p.update(RequiredCellsSatisfied=False), lambda p: p.update(RelocationFields=0),
            lambda p: p.update(FullIRSemantics=True), lambda p: p.update(ObjectSha256='junk'),
            lambda p: p['RootEvidence'].pop(), lambda p: p['RootEvidence'][0].update(InstructionCount=True),
            lambda p: p['References'][0].update(OriginalAddend=False),
            lambda p: p['RootEvidence'][0].update(References=[p['References'][0]]))
        for index, change in enumerate(mutations):
            with self.subTest(case=index):
                proof = copy.deepcopy(original)
                change(proof)
                with self.assertRaises(API.Rejected):
                    API.require_result(proof)


def main(argv=None):
    global API, H
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args(argv)
    output = Path(args.output_dir).resolve()
    if output.exists() or output == ROOT or ROOT in output.parents or output in ROOT.parents:
        parser.error('fresh external output directory required')
    paths = dict(subject=HERE / 'common_effects.py', tests=Path(__file__).resolve(), helpers=HELPER)
    buffers = {name: path.read_bytes() for name, path in paths.items()}
    report = dict(Status='FAIL', Scope='PURE_SYNTHETIC_OS_COMMON_EFFECT_CONTROLS', Tests=0,
        ExpectedTestMethods=METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={str(paths[name]): sha(raw) for name, raw in buffers.items()}, SourceDrift=[],
        SourceClosureVerified=False, SyntheticELFMetadata=True, ActualELFParsed=False,
        ActualOsCodegenValidated=False, ExternalToolsExecuted=0, CpuExecution=False, BoardExecution=False,
        Qualification=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError('unoptimized Python required')
        if sha(buffers['helpers']) != HELPER_SHA:
            raise ValueError('neutral helper pin before execution')
        with patch('subprocess.Popen', side_effect=AssertionError('pure tests cannot spawn tools')):
            loaded = {}
            for name in ('subject', 'helpers'):
                module = ModuleType('_os_common_effects_test_' + name)
                module.__file__ = str(paths[name])
                exec(compile(buffers[name], str(paths[name]), 'exec'), module.__dict__)
                loaded[name] = module
            API = loaded['subject']
            if API.HELPER_SHA256 != HELPER_SHA:
                raise ValueError('subject helper identity')
            helper = loaded['helpers']
            names = ('_header', '_functions', '_symbol_fields', '_walk', '_resolved', 'Rejected',
                'PROTECTED', 'FORWARD', 'THREAD', 'THREAD_SECTION', 'COLD', 'SETTER', 'PANIC', 'STRESS',
                'MUTATIONS', 'HOOKS', 'COLD_IMPORTS', 'STRESS_FAMILIES')
            H = SimpleNamespace(**{name: getattr(helper, name) for name in names})
            tests = unittest.defaultTestLoader.loadTestsFromTestCase(EffectsTests)
            if tests.countTestCases() != METHODS:
                raise ValueError('exact implemented method count required: ' + str(tests.countTestCases()))
            result = unittest.TextTestRunner(verbosity=2).run(tests)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors),
            Skipped=len(result.skipped), Details=[dict(Test=str(test), Detail=detail)
                for test, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped:
            report['Status'] = 'PASS'
    except Exception as error:
        report.update(Status='FAIL', Errors=report['Errors'] + 1, Error=type(error).__name__ + ': ' + str(error))
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
