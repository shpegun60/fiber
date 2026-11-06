"""Read-only retained-ELF replay and in-memory predicate controls; no tools."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = Path('C:/fz-replay-refresh-cm0-o2-20261105-e2/Native')
RECEIPT = 'D5FF0D8A8368EC38C816ABC627D506278EB47978676A69ACC11FD19603D96FBB'
MANIFEST = 'ACB4BD4EE450EADD25E3EB727BB27B3C0AF780C6D00195669D3C656E6266E11B'


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def load_buffer(name, path, raw):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


class BindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        opened = {}

        def read(path, expected=None):
            path = Path(path)
            raw = path.read_bytes()
            if expected is not None and sha(raw) != expected:
                raise AssertionError('fixture hash: ' + str(path))
            opened[path] = sha(raw)
            return raw

        result = read(ROOT / 'results.json', RECEIPT)
        manifest = json.loads(read(ROOT / 'artifacts.json', MANIFEST))['Artifacts']
        parser_paths = {p.relative_to(ROOT).as_posix() for p in (ROOT / 'python').rglob('*') if p.is_file()}
        expected_parser = {p for p in manifest if p.startswith('python/')}
        if parser_paths != expected_parser:
            raise AssertionError('captured parser membership')
        for name in sorted(parser_paths):
            read(ROOT / name, manifest[name])
        for name in ('ordinary.elf', 'ordinary.dis', 'ordinary.map',
                     'emit-relocs.elf', 'emit-relocs.dis', 'emit-relocs.map'):
            read(ROOT / name, manifest[name])
        cls.result = json.loads(result)
        for row in cls.result['Sources']:
            read(row['Source'], row['SourceSha256'])
            read(row['Object'], row['ObjectSha256'])
        subject_path, test_path = HERE / 'bindings.py', Path(__file__).resolve()
        subject_raw = read(subject_path)
        read(test_path)
        reader = ROOT / 'source/tools/fixtures/classic_final_image/elf.py'
        reader_raw = read(reader, manifest[reader.relative_to(ROOT).as_posix()])
        old_path, old_bytecode = list(sys.path), sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(ROOT / 'python'))

        def close():
            try:
                for module_name, module in tuple(sys.modules.items()):
                    if module_name == 'elftools' or module_name.startswith('elftools.'):
                        path = Path(module.__file__).resolve(strict=True)
                        if not path.is_relative_to((ROOT / 'python/elftools').resolve()):
                            raise AssertionError('ambient parser import: ' + module_name)
                        if path not in opened or sha(path.read_bytes()) != opened[path]:
                            raise AssertionError('unbound imported parser: ' + module_name)
                if {p.relative_to(ROOT).as_posix() for p in (ROOT / 'python').rglob('*') if p.is_file()} != parser_paths:
                    raise AssertionError('closing parser membership')
                if any(sha(p.read_bytes()) != value for p, value in opened.items()):
                    raise AssertionError('binding fixture/source drift')
            finally:
                sys.path[:] = old_path
                sys.dont_write_bytecode = old_bytecode

        cls.addClassCleanup(close)
        for name, module in tuple(sys.modules.items()):
            if name == 'elftools' or name.startswith('elftools.'):
                if not Path(module.__file__).resolve().is_relative_to((ROOT / 'python/elftools').resolve()):
                    raise AssertionError('ambient parser already loaded')
        cls.subject = load_buffer('cm0_binding_subject', subject_path, subject_raw)
        cls.core = load_buffer('cm0_binding_captured_reader', reader, reader_raw)
        cls.real_elf, cls.real_image = cls.core._ELF, cls.core.FinalImage
        cls.actual = cls.subject.inspect(cls.result, ROOT, cls.core)

    def rejects(self, mutate, message):
        hits = []

        def parsed(path, kind):
            value = self.real_elf(path, kind)
            if mutate('elf', Path(path), value):
                hits.append(str(path))
            return value

        def image(*args, **kwargs):
            value = self.real_image(*args, **kwargs)
            if mutate('image', Path(args[1]), value):
                hits.append(str(args[1]))
            return value

        with patch.object(self.core, '_ELF', side_effect=parsed), \
                patch.object(self.core, 'FinalImage', side_effect=image):
            with self.assertRaisesRegex((self.subject.Rejected, self.core.Rejected), message):
                self.subject.inspect(self.result, ROOT, self.core)
        self.assertTrue(hits, 'control did not actually mutate an input model')

    def test_actual_retained_bindings_and_literal_nonclaims(self):
        result = self.actual
        self.assertEqual(result['Status'], 'PASS')
        self.assertEqual(len(result['Sources']), 9)
        for name in ('Ordinary', 'EmitRelocs'):
            image = result[name]
            self.assertEqual([(r['Name'], r['ObjectIndex']) for r in image['ForwardProviders']], [
                ('fiber_port_context_init', 4), ('fiber_port_runtime_memory_barrier', 3),
                ('fiber_port_panic_wait', 3), ('fiber_port_require_scheduler_configuration_environment', 3),
                ('fiber_port_runtime_prepare_start', 3), ('fiber_port_runtime_select_first', 3),
                ('fiber_port_runtime_start_first', 3), ('fiber_port_runtime_schedule', 3)])
            self.assertEqual([r['ObjectIndex'] for r in image['ReverseProviders']], [1, 1, 1, 0])
            for field, count in (('ReverseReferences', 5), ('ColdAnchorReads', 2),
                                 ('CohortReferences', 4), ('SlotReferences', 2), ('StartupVectors', 3)):
                self.assertEqual(len(image[field]), count, field)
            for r in image['ReverseReferences']:
                self.assertEqual(r['Addend'], -4 if r['Kind'] == 10 else 0)
                self.assertIs(r['AppliedRelocationMetadataChecked'], name == 'EmitRelocs')
            self.assertTrue(all(r['RetainedByteRead'] is True for r in image['ColdAnchorReads']))
            self.assertEqual(image['SlotOrigin']['ObjectIndex'], 1)
            self.assertEqual(image['SlotOrigin']['Size'], 4)
        for field in ('InputAuthenticationProof', 'ClosingProof', 'TwinLoadImageCompared',
                      'CanonicalProtocolValidated', 'GeneratedSlotIsolationProven',
                      'CalleeBodySemanticsProven', 'TypedABIProof', 'SourceIRProof',
                      'SourceToMachineSemanticProof', 'KernelRuntimeProof', 'FullABIProof', 'FullSemanticABIProof',
                      'CellContractSatisfied', 'RequiredCellSatisfied', 'CompilerExecution',
                      'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified'):
            self.assertIs(result[field], False, field)
        self.assertIs(type(result['RequiredCellsSatisfied']), int)
        self.assertEqual(result['RequiredCellsSatisfied'], 0)

    def test_selection_order_and_declared_hash_controls(self):
        for key, value in (('Profile', 'CM0PLUS'), ('Mode', 'Os'), ('Cohort', 'foreign'),
                           ('SourceInventorySha256', 'A' * 64)):
            wrong = copy.deepcopy(self.result)
            wrong[key] = value
            with self.subTest(key=key), self.assertRaises(self.subject.Rejected):
                self.subject.inspect(wrong, ROOT, self.core)
        for change in ('order', 'source-hash', 'object-hash'):
            wrong = copy.deepcopy(self.result)
            if change == 'order':
                wrong['Sources'][0], wrong['Sources'][1] = wrong['Sources'][1], wrong['Sources'][0]
            else:
                wrong['Sources'][0]['SourceSha256' if change == 'source-hash' else 'ObjectSha256'] = '0' * 64
            with self.subTest(change=change), self.assertRaises(self.subject.Rejected):
                self.subject.inspect(wrong, ROOT, self.core)

    def test_reverse_provider_binding_and_duplicate_controls(self):
        for variant in ('binding', 'duplicate'):
            def mutate(stage, path, elf):
                if stage != 'elf' or path.name != '01-context_runtime_state.o':
                    return False
                symbol = next(s for s in elf.symbols if s['name'] == self.subject.SELECT)
                if variant == 'binding':
                    symbol['binding'] = 'STB_LOCAL'
                else:
                    elf.symbols.append(dict(symbol))
                return True
            with self.subTest(variant=variant):
                self.rejects(mutate, 'original definition|unique provider')

    def test_forward_eight_owner_kind_and_final_origin(self):
        for variant in ('duplicate-owner', 'kind', 'origin'):
            def mutate(stage, path, elf):
                if stage != 'elf':
                    return False
                if variant == 'duplicate-owner' and path.name == '03-fiber_port.o':
                    symbol = next(s for s in elf.symbols if s['name'] == 'fiber_port_runtime_schedule')
                    elf.symbols.append(dict(symbol, name='fiber_port_context_init'))
                    return True
                if variant == 'kind' and path.name == '04-fiber_port_boot.o':
                    next(s for s in elf.symbols if s['name'] == 'fiber_port_context_init')['kind'] = 'STT_OBJECT'
                    return True
                if variant == 'origin' and path.name == 'ordinary.elf':
                    next(s for s in elf.symbols if s['name'] == 'fiber_port_runtime_memory_barrier')['value'] += 2
                    return True
                return False
            with self.subTest(variant=variant):
                self.rejects(mutate, 'unique provider|original definition|definition placement')

    def test_selected_reference_missing_extra_and_wrong_kind(self):
        for variant in ('missing', 'extra', 'kind'):
            def mutate(stage, path, elf):
                if stage != 'elf' or path.name != '03-fiber_port.o':
                    return False
                key = next(k for k, v in elf.relocations.items() if v[1]['name'] == self.subject.CURRENT)
                row = elf.relocations[key]
                if variant == 'missing':
                    del elf.relocations[key]
                elif variant == 'extra':
                    elf.relocations[(key[0], key[1] + 4)] = row
                else:
                    elf.relocations[key] = (2, row[1])
                return True
            with self.subTest(variant=variant):
                self.rejects(mutate, 'relocation membership')

    def test_original_call_addend(self):
        def mutate(stage, path, elf):
            if stage != 'elf' or path.name != '03-fiber_port.o':
                return False
            index = elf.names.index('.text.fiber_port_runtime_schedule')
            old = elf.section_read
            elf.section_read = lambda sec, off, size: bytes.fromhex('00f000f8') if (sec, off, size) == (index, 10, 4) else old(sec, off, size)
            return True
        self.rejects(mutate, 'BL addend')

    def test_applied_call_and_residual_relocation(self):
        for variant in ('destination', 'residual'):
            def mutate(stage, path, elf):
                if stage != 'elf' or path.name != 'emit-relocs.elf':
                    return False
                ref = self.actual['EmitRelocs']['ReverseReferences'][0]
                if variant == 'destination':
                    old = elf.read
                    elf.read = lambda addr, size: bytes.fromhex('fff7feff') if (addr, size) == (ref['Place'], 4) else old(addr, size)
                else:
                    key = next(k for k, v in elf.relocations.items() if v[1]['name'] == self.subject.CURRENT)
                    elf.relocations[key] = (2, elf.relocations[key][1])
                return True
            with self.subTest(variant=variant):
                self.rejects(mutate, 'BL addend|final relocation')

    def test_cold_read_is_byte_load_not_store(self):
        for owner, name, pool, load, read in self.subject.COLD:
            def mutate(stage, path, elf):
                if stage != 'elf' or path.name != ('%02d-%s.o' % (owner, 'fiber_port' if owner == 3 else 'fiber_port_boot')):
                    return False
                index = elf.names.index('.text.' + name)
                old = elf.section_read
                elf.section_read = lambda sec, off, size: old(sec, off, size)[:2] + bytes.fromhex('1b60') if (sec, off, size) == (index, load, 4) else old(sec, off, size)
                return True
            with self.subTest(owner=owner):
                self.rejects(mutate, 'retained LDRB')

    def test_coherent_cold_load_retarget(self):
        def mutate(stage, path, elf):
            if stage != 'elf':
                return False
            if path.name == '03-fiber_port.o':
                index = elf.names.index('.text.fiber_port_runtime_prepare_start')
                old = elf.section_read
                elf.section_read = lambda sec, off, size: bytes.fromhex('064b1b78') if (sec, off, size) == (index, 2, 4) else old(sec, off, size)
                return True
            if path.name == 'ordinary.elf':
                addr = self.actual['Ordinary']['ColdAnchorReads'][0]['LoadAddress']
                old = elf.read
                elf.read = lambda at, size: bytes.fromhex('064b1b78') if (at, size) == (addr, 4) else old(at, size)
                return True
            return False
        self.rejects(mutate, 'cold literal load')

    def test_readonly_anchor_origin_and_contents(self):
        for variant in ('map', 'byte'):
            def mutate(stage, path, image):
                if stage != 'image' or path.name != 'ordinary.elf':
                    return False
                if variant == 'map':
                    key = next(k for k in image.placements if k[1] == '.rodata.' + self.subject.ANCHOR)
                    address, size = image.placements[key]
                    image.placements[key] = (address + 1, size)
                else:
                    addr = self.actual['Ordinary']['ColdAnchorReads'][0]['AnchorReference']['ResolvedValue']
                    old = image.read
                    image.read = lambda at, size: b'\0' if (at, size) == (addr, 1) else old(at, size)
                return True
            with self.subTest(variant=variant):
                self.rejects(mutate, 'definition placement|read-only byte')

    def test_cohort_foreign_identity_and_original_addend(self):
        for variant in ('name', 'addend'):
            def mutate(stage, path, elf):
                if stage != 'elf' or path.name != '04-fiber_port_boot.o':
                    return False
                if variant == 'name':
                    next(s for s in elf.symbols if s['name'] == self.subject.PRIVATE)['name'] += '_foreign'
                else:
                    index = elf.names.index('.text.fiber_port_context_init')
                    old = elf.section_read
                    elf.section_read = lambda sec, off, size: b'\1\0\0\0' if (sec, off, size) == (index, 0x134, 4) else old(sec, off, size)
                return True
            with self.subTest(variant=variant):
                self.rejects(mutate, 'foreign private|original zero addend')

    def test_cohort_applied_pointer_and_full_map_size(self):
        for variant in ('pointer', 'size'):
            def mutate(stage, path, image):
                if stage != 'image' or path.name != 'ordinary.elf':
                    return False
                if variant == 'pointer':
                    addr = self.actual['Ordinary']['CohortReferences'][2]['Place']
                    old = image.read
                    image.read = lambda at, size: b'\0' * 4 if (at, size) == (addr, 4) else old(at, size)
                else:
                    key = next(k for k in image.placements if k[1] == '.text.fiber_port_context_init')
                    address, size = image.placements[key]
                    image.placements[key] = (address, size - 4)
                return True
            with self.subTest(variant=variant):
                self.rejects(mutate, 'applied destination' if variant == 'pointer' else 'full input-section placement')

    def test_slot_zero_fill_size_and_load_permissions(self):
        for variant in ('size', 'file-backed', 'executable'):
            def mutate(stage, path, elf):
                if stage != 'elf':
                    return False
                if variant != 'executable' and path.name == '01-context_runtime_state.o':
                    index = elf.names.index('.bss.fiber_runtime_current_context_slot')
                    elf.sections[index].header['sh_size' if variant == 'size' else 'sh_type'] = 8 if variant == 'size' else 'SHT_PROGBITS'
                    return True
                if variant == 'executable' and path.name == 'ordinary.elf':
                    addr = self.actual['Ordinary']['SlotOrigin']['Value']
                    for load in elf.loads:
                        if load['Vaddr'] <= addr < load['Vaddr'] + load['MemorySize']:
                            load['Flags'] |= 1
                    return True
                return False
            with self.subTest(variant=variant):
                self.rejects(mutate, 'input-section|input/final storage|slot')

    def test_vector_original_rel_and_applied_pointer(self):
        for variant in ('original', 'pointer'):
            def mutate(stage, path, elf):
                if stage != 'elf':
                    return False
                if variant == 'original' and path.name == '08-startup.o':
                    del elf.relocations[(elf.names.index('.isr_vector'), 44)]
                    return True
                if variant == 'pointer' and path.name == 'ordinary.elf':
                    old = elf.read
                    elf.read = lambda at, size: b'\0' * 4 if (at, size) == (44, 4) else old(at, size)
                    return True
                return False
            with self.subTest(variant=variant):
                self.rejects(mutate, 'original relocation|applied destination')

    def test_reverse_and_slot_final_symbol_retarget(self):
        for target in (self.subject.SELECT, self.subject.SLOT):
            def mutate(stage, path, elf):
                if stage != 'elf' or path.name != 'ordinary.elf':
                    return False
                next(s for s in elf.symbols if s['name'] == target)['value'] += 4
                return True
            with self.subTest(target=target):
                self.rejects(mutate, 'definition placement')


if __name__ == '__main__':
    unittest.main(verbosity=2)
