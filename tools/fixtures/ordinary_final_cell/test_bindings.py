"""Pure reference-class controls and separately identified retained ELF tests."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CATALOG = Path('C:/fz-freeze-capture-inputs-20261105-e1/ordinary30-current.json')
CATALOG_SHA = 'EB7864CBDEC4257BBBE13830BE8757E508512BB47E4185BBD5FE473473857C4B'


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def load(name, path, raw=None):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes() if raw is None else raw, str(path), 'exec'), module.__dict__)
    return module


b = load('_ordinary_binding_subject', HERE / 'bindings.py')


def fixture():
    private, storage = 'private_independent_symbol', 'storage_independent_symbol'
    rows = [*b.REVERSE, *((i, '.text.' + function, 2, b.ANCHOR) for i, function in b.COLD),
            (4, '.text.fiber_port_context_init', 2, private),
            (5, '.text.fiber_exception_runtime_check', 2, private),
            (6, b.EXPECTATION, 2, private), (7, b.EXPECTATION, 2, storage), *b.SLOTS]
    objects = [SimpleNamespace(sections=[], relocations={}) for _ in range(9)]
    for owner, name, kind, target in rows:
        obj = objects[owner]
        index = next((i for i, section in enumerate(obj.sections) if section.name == name), None)
        if index is None:
            index = len(obj.sections)
            obj.sections.append(SimpleNamespace(name=name))
        offset = 4 * (len(obj.relocations) + 1)
        obj.relocations[(index, offset)] = (kind, dict(name=target))
    return objects, private, storage


class MembershipTests(unittest.TestCase):
    def test_all_exact_reference_classes_and_measured_offsets(self):
        objects, private, storage = fixture()
        expected = b.reference_membership(objects, private, storage)
        self.assertEqual({key: len(value) for key, value in expected.items()},
                         dict(Reverse=5, Cold=2, Cohort=4, Slot=2))
        before = copy.deepcopy(objects)
        for obj in objects:
            obj.relocations = {(index, offset + 100): value for (index, offset), value in obj.relocations.items()}
        changed = b.reference_membership(objects, private, storage)
        for key in expected:
            self.assertEqual([r[:2] + r[3:] for r in expected[key]], [r[:2] + r[3:] for r in changed[key]])
            self.assertEqual([r[2] + 100 for r in expected[key]], [r[2] for r in changed[key]])
        self.assertNotEqual(objects[3].relocations, before[3].relocations)

    def test_missing_duplicate_wrong_owner_kind_section_or_target_reject(self):
        for change in ('missing', 'duplicate', 'owner', 'kind', 'section', 'target'):
            objects, private, storage = fixture()
            obj = objects[3]
            index, offset = next(iter(obj.relocations))
            kind, symbol = obj.relocations[(index, offset)]
            if change == 'missing':
                del obj.relocations[(index, offset)]
            elif change == 'duplicate':
                obj.relocations[(index, offset + 100)] = kind, symbol
            elif change == 'owner':
                del obj.relocations[(index, offset)]
                objects[4].sections.append(SimpleNamespace(name=obj.sections[index].name))
                objects[4].relocations[(len(objects[4].sections) - 1, offset)] = kind, symbol
            elif change == 'kind':
                obj.relocations[(index, offset)] = 2, symbol
            elif change == 'section':
                obj.sections[index].name = '.text.foreign'
            else:
                obj.relocations[(index, offset)] = kind, dict(name='foreign_target')
            with self.subTest(change=change), self.assertRaises(b.Rejected):
                b.reference_membership(objects, private, storage)

    def test_foreign_tracked_use_in_unexpected_consumer_is_not_ignored(self):
        objects, private, storage = fixture()
        objects[8].sections.append(SimpleNamespace(name='.isr_vector'))
        objects[8].relocations[(0, 64)] = 2, dict(name=b.SLOT)
        with self.assertRaises(b.Rejected):
            b.reference_membership(objects, private, storage)


class RetainedBindingTests(unittest.TestCase):
    """Fixed local seed tests, not portable CI or input-closure qualification."""
    @classmethod
    def setUpClass(cls):
        cls.opened = {}

        def read(path, expected=None):
            path = Path(path).resolve(strict=True)
            raw = path.read_bytes()
            if expected is not None and sha(raw) != expected:
                raise AssertionError('retained fixture hash: ' + str(path))
            cls.opened[path] = sha(raw)
            return raw

        cls.read = staticmethod(read)
        selections = json.loads(read(CATALOG, CATALOG_SHA))['Selections']
        if len(selections) != 30 or len({row['Route'] for row in selections}) != 30:
            raise AssertionError('exact thirty-route fixture catalog')
        first = next(row for row in selections if row['Route'] == 'CM0/O2/direct')
        base = Path(first['Native']['Build'])
        manifest = json.loads(read(base / 'artifacts.json', first['Native']['ArtifactsSha256']))['Artifacts']
        parser = {name: value for name, value in manifest.items() if name.startswith('python/elftools/')}
        actual = {p.relative_to(base).as_posix() for p in (base / 'python').rglob('*') if p.is_file()}
        if set(parser) != actual:
            raise AssertionError('complete captured parser package')
        for name, digest in parser.items():
            read(base / name, digest)
        old_path, old_bytecode = list(sys.path), sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(base / 'python'))

        def close():
            try:
                for name, module in tuple(sys.modules.items()):
                    if name == 'elftools' or name.startswith('elftools.'):
                        path = Path(module.__file__).resolve(strict=True)
                        if path not in cls.opened or not path.is_relative_to(base / 'python/elftools'):
                            raise AssertionError('ambient/unbound parser module: ' + name)
                if any(sha(path.read_bytes()) != digest for path, digest in cls.opened.items()):
                    raise AssertionError('fixture/source closing drift')
                if {p.relative_to(base).as_posix() for p in (base / 'python').rglob('*') if p.is_file()} != actual:
                    raise AssertionError('closing parser membership')
            finally:
                sys.path[:] = old_path
                sys.dont_write_bytecode = old_bytecode

        cls.addClassCleanup(close)
        reader = base / 'source/tools/fixtures/classic_final_image/elf.py'
        reader_raw = read(reader, manifest[reader.relative_to(base).as_posix()])
        cls.core = load('_ordinary_binding_reader', reader, reader_raw)
        cls.profiles = load('_ordinary_binding_profiles', HERE / 'profiles.py', read(HERE / 'profiles.py'))
        read(HERE / 'bindings.py')
        read(Path(__file__))
        cls.fixtures = []
        for row in selections:
            profile, mode, _ = row['Route'].split('/')
            native = Path(row['Native']['Build'])
            result = json.loads(read(native / 'results.json', row['Native']['ReceiptSha256']))
            artifacts = json.loads(read(native / 'artifacts.json', row['Native']['ArtifactsSha256']))['Artifacts']
            if {name: digest for name, digest in artifacts.items() if name.startswith('python/elftools/')} != parser:
                raise AssertionError('identical admitted parser bytes across profiles')
            for source in result['Sources']:
                read(source['Source'], source['SourceSha256'])
                read(source['Object'], source['ObjectSha256'])
            for name in ('ordinary.elf', 'ordinary.dis', 'ordinary.map',
                         'emit-relocs.elf', 'emit-relocs.dis', 'emit-relocs.map'):
                read(native / name, artifacts[name])
            cls.fixtures.append((profile, mode, native, result))

    def contract(self, profile, mode):
        return self.profiles.profile(profile, mode)

    def test_all_thirty_profile_mode_bindings_and_nonclaims(self):
        for profile, mode, native, result in self.fixtures:
            with self.subTest(profile=profile, mode=mode):
                actual = b.inspect(self.contract(profile, mode), result, native, self.core)
                self.assertEqual(actual['Status'], 'PASS')
                for twin in ('Ordinary', 'EmitRelocs'):
                    image = actual[twin]
                    for name, count in (('ForwardProviders', 8), ('ReverseProviders', 4), ('ReverseReferences', 5),
                                        ('ColdAnchorReads', 2), ('CohortReferences', 4), ('SlotReferences', 2),
                                        ('StartupVectors', 3)):
                        self.assertEqual(len(image[name]), count, name)
                    self.assertTrue(all(row['RetainedByteRead'] is True for row in image['ColdAnchorReads']))
                self.assertIs(actual['FullSemanticABIProof'], False)
                self.assertIs(actual['RequiredCellSatisfied'], False)
                self.assertEqual(actual['RequiredCellsSatisfied'], 0)

    def test_receipt_profile_mode_cohort_and_source_order_mismatch_reject(self):
        profile, mode, native, result = self.fixtures[0]
        contract = self.contract(profile, mode)
        for key, value in (('Profile', 'CM7'), ('Mode', 'foreign'), ('Cohort', 'foreign'),
                           ('SourceInventorySha256', '0' * 64), ('LTO', True)):
            wrong = copy.deepcopy(result)
            wrong[key] = value
            with self.subTest(key=key), self.assertRaises(b.Rejected):
                b.inspect(contract, wrong, native, self.core)
        wrong = copy.deepcopy(result)
        wrong['Sources'][0], wrong['Sources'][1] = wrong['Sources'][1], wrong['Sources'][0]
        with self.assertRaises(b.Rejected):
            b.inspect(contract, wrong, native, self.core)

    def test_mutated_original_reference_class_and_cold_read_reject(self):
        profile, mode, native, result = self.fixtures[0]
        contract = self.contract(profile, mode)
        real_elf = self.core._ELF
        for change in ('owner', 'addend', 'cold-read'):
            hits = []

            def mutate(path, kind):
                elf = real_elf(path, kind)
                if Path(path) == native / 'objects/03-fiber_port.o':
                    if change == 'owner':
                        key = next(k for k, (_, s) in elf.relocations.items() if s['name'] == b.CURRENT)
                        elf.sections[key[0]].name = '.text.foreign'
                    else:
                        target = b.CURRENT if change == 'addend' else b.ANCHOR
                        key = next(k for k, (_, s) in elf.relocations.items() if s['name'] == target)
                        read = elf.section_read

                        def altered(index, start, size):
                            raw = read(index, start, size)
                            if index == key[0] and (change == 'cold-read' or start == key[1]):
                                return bytes(size)
                            return raw

                        elf.section_read = altered
                    hits.append(True)
                return elf

            with self.subTest(change=change), patch.object(self.core, '_ELF', side_effect=mutate):
                with self.assertRaises((b.Rejected, self.core.Rejected)):
                    b.inspect(contract, result, native, self.core)
            self.assertTrue(hits)

    def test_foreign_independent_private_and_storage_identity_reject(self):
        profile, mode, native, result = self.fixtures[0]
        for field in ('PrivateSymbol', 'StorageSymbol'):
            contract = self.contract(profile, mode)
            contract[field] += '_foreign'
            with self.subTest(field=field), self.assertRaises(b.Rejected):
                b.inspect(contract, result, native, self.core)

    def test_nonzero_original_abs32_addend_rejects_on_each_profile(self):
        real_elf = self.core._ELF
        for profile in ('CM0', 'CM0PLUS', 'CM0PLUSVTOR', 'CM3', 'CM4', 'CM7'):
            _, mode, native, result = next(row for row in self.fixtures if row[0] == profile and row[1] == 'O2')
            hits = []

            def mutate(path, kind):
                elf = real_elf(path, kind)
                if Path(path) == native / 'objects/03-fiber_port.o':
                    key = next(k for k, (_, s) in elf.relocations.items() if s['name'] == b.RETURN)
                    read = elf.section_read

                    def altered(index, start, size):
                        if (index, start, size) == (key[0], key[1], 4):
                            hits.append(True)
                            return bytes.fromhex('04000000')
                        return read(index, start, size)

                    elf.section_read = altered
                return elf

            with self.subTest(profile=profile), patch.object(self.core, '_ELF', side_effect=mutate):
                with self.assertRaisesRegex(b.Rejected, 'zero addend'):
                    b.inspect(self.contract(profile, mode), result, native, self.core)
            self.assertTrue(hits)

    def test_missing_emit_relocation_or_unexpected_ordinary_metadata_reject(self):
        profile, mode, native, result = self.fixtures[0]
        real_image = self.core.FinalImage
        for change in ('missing-emitted', 'ordinary-extra'):
            hits = []

            def mutate(*args, **kwargs):
                image = real_image(*args, **kwargs)
                emitted = Path(args[1]).name == 'emit-relocs.elf'
                if emitted != (change == 'missing-emitted'):
                    return image
                obj = image.prelink
                (index, offset), (kind, symbol) = next((key, value) for key, value in obj.relocations.items()
                    if value[1]['name'] == b.CURRENT)
                owner = self.core._object_identity(native / 'objects/03-fiber_port.o')
                address = image.placements[(owner, obj.sections[index].name)][0] + offset
                final_index = next(i for i, section in enumerate(image.final.sections)
                    if section.header.sh_flags & 2 and section.header.sh_addr <= address
                    and address + 4 <= section.header.sh_addr + section.header.sh_size)
                key = final_index, address - image.final.sections[final_index].header.sh_addr
                if emitted:
                    del image.final.relocations[key]
                else:
                    definition = image.final.symbol(b.CURRENT, 'STT_FUNC', root=True)
                    image.final.relocations[key] = kind, definition
                hits.append(True)
                return image

            with self.subTest(change=change), patch.object(self.core, 'FinalImage', side_effect=mutate):
                with self.assertRaisesRegex(b.Rejected, 'metadata disposition'):
                    b.inspect(self.contract(profile, mode), result, native, self.core)
            self.assertTrue(hits)


if __name__ == '__main__':
    unittest.main(verbosity=2)
