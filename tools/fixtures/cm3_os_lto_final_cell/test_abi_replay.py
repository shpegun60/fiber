"""Synthetic deferred ABI replay controls; no real capture or ELF execution."""

import argparse
import copy
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
METHODS = 22
HEADERS = ('context/context_port_abi.h', 'context/context_runtime_port_abi.h',
    'context/context_api_attributes.h', 'context/context_api_types.h', 'context/context_panic.h',
    'context/context_runtime_state.h', 'fiber/fiber_api_attributes.h', 'fiber/fiber_runtime_port_abi.h',
    'fiber/port/fiber_port_runtime_abi.h')
ORDER = ('context/context_core.c', 'context/context_runtime_state.c', 'context/context_panic.c',
    'fiber/port/ARM_CM3/fiber_port.c', 'fiber/port/ARM_CM3/fiber_port_boot.c',
    'fiber/port/ARM_CM3/fiber_port_exception.c', 'fiber/port/fiber_port_context_cohort_expectation.c',
    'tools/fixtures/classic_final_image/application.c', 'tools/fixtures/classic_final_image/startup.S')
PROTOTYPES = (
    'void fiber_port_context_init(CtxrtContextV1 *context, void *stack_begin, void *stack_end, CtxrtEntryFnV1 entry, void *arg);',
    'void fiber_port_runtime_memory_barrier(void);', 'void fiber_port_panic_wait(void);',
    'void fiber_port_require_scheduler_configuration_environment(void);', 'void fiber_port_runtime_prepare_start(void);',
    'CtxrtContextV1 *fiber_port_runtime_select_first(void);', 'void fiber_port_runtime_start_first(CtxrtContextV1 *first);',
    'void fiber_port_runtime_schedule(void);',
    'CtxrtContextV1 *fiber_internal_runtime_select_scheduler_candidate(CtxrtContextV1 *current);',
    'void fiber_internal_runtime_publish_current_context(CtxrtContextV1 *next);',
    'void fiber_internal_runtime_require_current_context(void);', 'void fiber_internal_task_return(void);')
BUFFERS, LOADED, m = {}, {}, None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


class Model:
    """Real frozen declaration helpers, invented metadata/core and dictionary I/O."""
    def __init__(self):
        self.root = Path('C:/synthetic-abi-replay/batch')
        self.seed = self.root.parent / 'seed'
        self.source_root = self.seed / 'source'
        self.capture = self.root.parent / 'native-Os-lto'
        self.files, self.reads, self.calls = {}, [], []
        self.sources = {name: BUFFERS[ROOT / name] for name in HEADERS + ORDER}
        self.sources['tools/fixtures/classic_final_image/main.h'] = b'synthetic generated forced include'
        self.sources['unused/unselected.c'] = b'synthetic extra project source, still must be read'
        for name, raw in self.sources.items():
            self.files[self.source_root / name] = raw
        metadata = dict(Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True,
                        Cohort=m.COHORT, SourceInventorySha256=m.SOURCE)
        self.native = dict(metadata, Status='PASS', SeedMode='O2', SeedBuild=str(self.seed),
                           TranslationUnits=9, SlimIRObjects=8, Sources=[], InputHashes={})
        for index, name in enumerate(ORDER):
            required = {name, 'tools/fixtures/classic_final_image/main.h'}
            if index <= 4:
                required.update(('context/context_port_abi.h', 'context/context_api_attributes.h',
                                 'context/context_api_types.h', 'fiber/fiber_api_attributes.h'))
            if index in (0, 1, 3, 4):
                required.add('context/context_runtime_port_abi.h')
            dependencies = [dict(Path=str(self.source_root / relative), Sha256=sha(self.sources[relative]))
                            for relative in sorted(required)]
            dependencies.append(dict(Path=str(self.capture / 'toolchain/include/stdint.h'), Sha256='B' * 64))
            self.native['InputHashes'].update({row['Path']: row['Sha256'] for row in dependencies})
            obj = self.capture / 'objects' / ('%02d-' % index + Path(name).stem + '.o')
            seed_flags = self.seed_flags(index)
            flags = ['-Os' if flag == '-O2' else flag for flag in seed_flags]
            if index != 8:
                flags += ['-flto', '-fno-fat-lto-objects']
            self.native['Sources'].append(dict(Source=str(self.source_root / name), SourceSha256=sha(self.sources[name]),
                Object=str(obj), DependencyFile=str(obj.with_suffix('.d')), ObjectSha256='A' * 64,
                SeedCompileFlags=seed_flags, CompileFlags=flags, SlimIR=index != 8,
                CompileDependenciesVerified=True, ActualCompileDependencies=dependencies))
        self.original, self.replayed = b'synthetic ordinary ELF metadata A', b'synthetic replayed ELF metadata B'
        self.files[self.capture / 'ordinary/image.elf'] = self.original
        self.files[self.root / 'links/positive/image.elf'] = self.replayed
        self.files[self.root / 'links/positive/image.map'] = b'synthetic uninterpreted map'
        self.native['Links'] = [dict(Kind='ordinary', Path=str(self.capture / 'ordinary/image.elf'), Sha256=sha(self.original)),
                               dict(Kind='emit-relocs', Path=str(self.capture / 'emit-relocs/image.elf'), Sha256='C' * 64)]
        attribute = '__attribute__((no_sanitize("address", "undefined", "thread"))) '
        self.cpp = ('# 1 "' + self.source_root.as_posix() + '/context/context_port_abi.h" 1\n'
            + '\n'.join(attribute + row for row in PROTOTYPES[:8])
            + '\n# 1 "' + self.source_root.as_posix() + '/context/context_runtime_port_abi.h" 1\n'
            + '\n'.join(attribute + row for row in PROTOTYPES[8:]) + '\n').encode('ascii')
        self.files[self.root / 'abi/attributes.i'] = self.cpp
        self.batch = dict(metadata, Status='BUILT-PENDING-READER', SourceSeed=str(self.seed),
            NativeCapture=dict(Build=str(self.capture)), ABIProbes={'attributes.c': dict(
                Preprocessed=str(self.root / 'abi/attributes.i'), Classification=dict(AcceptedCompile=True),
                CommandIndices=[32, 33])})
        self.helpers = {key: LOADED[key] for key in ('declarations', 'ordinary', 'guard')}
        self.core = types.SimpleNamespace(compare_load_images=self.compare)
        vector = struct.pack('<256I', *([0x20001000, 0x101] + [0] * 254))
        self.comparison = dict(Identical=True, Entry=0x101, VectorAddress=0, VectorBytes=vector.hex(),
            Segments=[dict(Vaddr=0, Paddr=0, FileSize=1024, MemorySize=1152, Flags=5, Align=4096,
                           BytesSha256=sha(vector))])
        self.sync_native()
        self.sync_cpp()
        self.sync_positive()
        self.catalog()

    def seed_flags(self, index):
        if index == 8:
            return ['-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-O2', '-g0', '-DPILOT_HAS_VTOR=1']
        root = self.source_root.as_posix()
        return (['-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-O2', '-std=gnu11', '-g0', '-ffreestanding',
            '-ffunction-sections', '-fdata-sections', '-Wall', '-Wextra', '-Werror=implicit-function-declaration',
            '-Werror=attributes', '-Werror=ignored-attributes', '-DFIBER_PORT_ARMV7M=1',
            '-DFIBER_PORT_BUILD_SELECTED=1', '-DFIBER_SCHEDULER_BASEPRI=16']
            + ['-I' + root + ('/' + name if name else '') for name in
               ('tools/fixtures/classic_final_image', 'fiber/port/ARM_CM3', 'fiber/port', 'fiber', 'context', '')]
            + ['-I' + self.seed.as_posix() + '/cmsis', '-include', root + '/tools/fixtures/classic_final_image/main.h',
               '-I' + root + '/' + ORDER[index].rsplit('/', 1)[0]])

    def sync_native(self, providers=True):
        raw = encoded(self.native)
        self.files[self.capture / 'results.json'] = raw
        self.batch['NativeCapture']['ReceiptSha256'] = sha(raw)
        if providers:
            self.batch['DeclaredProviders'] = self.helpers['declarations'].inspect_provider_dependencies(
                self.sources, raw, source_root=str(self.source_root), capture_root=str(self.capture), ordinary=self.helpers['ordinary'])

    def sync_cpp(self):
        self.batch['PreprocessedAttributes'] = self.helpers['declarations'].inspect_preprocessed_attributes(
            self.files[self.root / 'abi/attributes.i'], ordinary=self.helpers['ordinary'])

    def sync_positive(self):
        original, replayed, link_map = (self.capture / 'ordinary/image.elf', self.root / 'links/positive/image.elf',
                                        self.root / 'links/positive/image.map')
        readers = [dict(Role=role, Path=str(path), Sha256=sha(self.files[path])) for role, path in
                   (('OriginalELF', original), ('ReproducedELF', replayed))]
        map_record = dict(Role='ReproducedMap', Path=str(link_map), Sha256=sha(self.files[link_map]))
        self.batch['PositiveAuthority'] = dict(Original=str(original), OriginalSha256=sha(self.files[original]),
            Replayed=str(replayed), ReplayedSha256=sha(self.files[replayed]), Map=str(link_map), MapSha256=map_record['Sha256'],
            RawElfByteIdentical=self.files[original] == self.files[replayed], ReaderInputs=readers,
            Scope='SAME_OS_SLIM_INPUTS_RECIPE_LOAD_IMAGE_REPRODUCTION_PENDING', LoadImageComparison=None,
            LoadImageValidated=False, ValidationDeferred=True, LinkCommandIndex=0)
        self.batch['ABIControlsDeferredReader'] = dict(Kind='OS_POSITIVE_LOAD_IMAGE_REPRODUCTION', Status='PENDING',
            ValidationDeferred=True, Inputs=copy.deepcopy(readers), Map=map_record,
            PositiveLinkRevalidated=False, RequiredCellsSatisfied=0)

    def catalog(self, *, enroll_manifest=False):
        path = self.root / 'artifacts.json'
        self.files[path] = encoded(dict(Artifacts={name.relative_to(self.root).as_posix(): sha(raw)
            for name, raw in self.files.items() if name.is_relative_to(self.root) and name != path}))
        self.batch['InputHashes'] = {str(name): sha(raw) for name, raw in self.files.items() if name != path}
        self.batch['InputHashes'][str(self.capture / 'toolchain/include/stdint.h')] = 'B' * 64
        if enroll_manifest:
            self.batch['InputHashes'][str(path)] = sha(self.files[path])

    def read(self, path, expected):
        if not isinstance(path, Path) or path not in self.files:
            raise ValueError('synthetic missing read role/' + str(path))
        if expected is None and path != self.root / 'artifacts.json':
            raise AssertionError('only admitted manifest permits None')
        value = self.files[path]
        if expected is not None and sha(value) != expected:
            raise ValueError('synthetic hash mismatch')
        self.reads.append((path, expected))
        return value

    def compare(self, original, replayed):
        self.calls.append((original, replayed))
        if (original, replayed) != (self.capture / 'ordinary/image.elf', self.root / 'links/positive/image.elf'):
            raise ValueError('synthetic foreign comparison role')
        if self.files[original] != self.original or self.files[replayed] != self.replayed:
            raise ValueError('synthetic unequal actual load image')
        return copy.deepcopy(self.comparison)

    def run(self, **kwargs):
        args = dict(batch=self.batch, native=self.native, root=self.root, core=self.core, helpers=self.helpers, read=self.read)
        args.update(kwargs)
        return m.inspect(**args)


class ReplayTests(unittest.TestCase):
    def test_three_facts_and_exact_detached_bounded_result(self):
        model = Model(); proof = model.run()
        self.assertIs(m.require_result(proof), proof)
        self.assertEqual(proof['DeferredFactsReplayed'], 3)
        self.assertEqual((proof['ProviderRecords'], proof['CPPDeclarations'], proof['ComparedImages']), (9, 12, 2))
        self.assertEqual(proof['ReadFiles'], proof['ProjectSourceFiles'] + 6)
        self.assertEqual((proof['ProjectSourceFiles'], proof['RawSourceIdentities']), (20, 18))
        for key in m.NONCLAIMS:
            self.assertIs(proof[key], False)
        self.assertEqual(model.calls, [(model.capture / 'ordinary/image.elf', model.root / 'links/positive/image.elf')])
        self.assertFalse(proof['PositiveAuthority']['RawElfByteIdentical'])
        self.assertTrue(proof['PositiveAuthority']['LoadImageComparison']['Identical'])
        self.assertIsNone(model.batch['PositiveAuthority']['LoadImageComparison'])

    def test_no_filesystem_process_module_loading_or_o2_verdict_and_no_mutation(self):
        model = Model();before = copy.deepcopy((model.batch, model.native, model.files))
        old_modes = LOADED['ordinary'].MODES
        with ExitStack() as stack:
            for key in ('read_bytes', 'read_text', 'open', 'resolve', 'absolute', 'stat', 'lstat', 'exists',
                        'is_file', 'is_dir', 'samefile', 'iterdir', 'glob', 'rglob'):
                stack.enter_context(patch.object(Path, key, side_effect=AssertionError('filesystem/' + key)))
            for key in ('stat', 'lstat', 'scandir', 'listdir', 'system', 'getcwd'):
                stack.enter_context(patch.object(os, key, side_effect=AssertionError('physical/' + key)))
            stack.enter_context(patch('builtins.open', side_effect=AssertionError('file open')))
            stack.enter_context(patch.object(subprocess, 'Popen', side_effect=AssertionError('subprocess')))
            stack.enter_context(patch.object(importlib.util, 'spec_from_file_location', side_effect=AssertionError('loading')))
            stack.enter_context(patch.object(LOADED['ordinary'], 'inspect_provider_dependencies', side_effect=AssertionError('ordinary admission')))
            model.run()
        self.assertEqual(before, (model.batch, model.native, model.files))
        self.assertIs(LOADED['ordinary'].MODES, old_modes)

    def test_all_project_bytes_read_not_just_pinned_eighteen_or_external_tools(self):
        model = Model();proof = model.run();reads = dict(model.reads)
        self.assertIn(model.source_root / 'unused/unselected.c', reads)
        self.assertNotIn(model.capture / 'toolchain/include/stdint.h', reads)
        self.assertEqual(set(reads), {Path(row['Path']) for row in proof['ReadInputs']})
        for row in proof['ProjectSources']:
            self.assertEqual(reads[Path(row['Path'])], row['Sha256'])

    def test_missing_canonical_source_and_wrong_source_bytes(self):
        for defect in ('missing', 'changed', 'case-alias'):
            model = Model();path = model.source_root / HEADERS[0]
            if defect == 'missing': del model.files[path]
            elif defect == 'changed': model.files[path] += b' '
            else: model.files[model.source_root / HEADERS[0].upper()] = model.files.pop(path)
            model.catalog()
            with self.subTest(defect=defect), self.assertRaises(ValueError):model.run()

    def test_missing_project_dependency_in_actual_native_record(self):
        model = Model();row = model.native['Sources'][0]
        row['ActualCompileDependencies'] = [value for value in row['ActualCompileDependencies']
            if not value['Path'].endswith('context_runtime_port_abi.h')]
        model.sync_native(providers=False);model.catalog()
        with self.assertRaisesRegex(m.Rejected, 'provider dependencies'):model.run()

    def test_passed_native_must_equal_reparsed_actual_receipt(self):
        model = Model();model.native['UnusedForgedField'] = True
        with self.assertRaisesRegex(m.Rejected, 'reparsed native capture'):model.run()
        model = Model();model.native['LTO'] = 1
        with self.assertRaises(m.Rejected):model.run()

    def test_native_receipt_explicit_hash_and_admission_required(self):
        for defect in ('declared', 'authority', 'missing'):
            model = Model();path = model.capture / 'results.json'
            if defect == 'declared':model.batch['NativeCapture']['ReceiptSha256'] = 'F' * 64
            elif defect == 'authority':model.batch['InputHashes'][str(path)] = 'F' * 64
            else:del model.batch['InputHashes'][str(path)]
            with self.subTest(defect=defect), self.assertRaises(m.Rejected):model.run()

    def test_wrong_seed_overlapping_roots_and_foreign_metadata(self):
        for defect in ('seed', 'seed-alias', 'root', 'mode', 'profile', 'helper', 'core'):
            model = Model();kwargs = {}
            if defect == 'seed':model.batch['SourceSeed'] = 'C:/foreign/seed'
            elif defect == 'seed-alias':model.batch['SourceSeed'] = model.seed.as_posix()
            elif defect == 'root':kwargs['root'] = model.source_root
            elif defect == 'mode':model.batch['Mode'] = 'O2-lto'
            elif defect == 'profile':model.native['Profile'] = 'CM4'
            elif defect == 'helper':kwargs['helpers'] = dict(model.helpers, implicit=object())
            else:kwargs['core'] = object()
            with self.subTest(defect=defect), self.assertRaises(m.Rejected):model.run(**kwargs)

    def test_provider_recipe_and_dependency_declarations_recomputed(self):
        for defect in ('flags', 'input-hash', 'dependency-hash', 'slim'):
            model = Model();row = model.native['Sources'][0]
            if defect == 'flags':row['CompileFlags'][3] = '-O2'
            elif defect == 'input-hash':model.native['InputHashes'][row['Source']] = 'F' * 64
            elif defect == 'dependency-hash':row['ActualCompileDependencies'][0]['Sha256'] = 'F' * 64
            else:row['SlimIR'] = 1
            model.sync_native(providers=False);model.catalog()
            with self.subTest(defect=defect), self.assertRaisesRegex(m.Rejected, 'provider dependencies'):model.run()

    def test_stored_provider_proof_is_only_comparison_target(self):
        for defect in ('receipt', 'counter', 'scope', 'extra'):
            model = Model();proof = model.batch['DeclaredProviders']
            if defect == 'receipt':proof['ReceiptSha256'] = 'F' * 64
            elif defect == 'counter':proof['Providers'][0]['ObjectIndex'] = False
            elif defect == 'scope':proof['Scope']['FullABIProof'] = True
            else:proof['ExtraForgedFact'] = True
            with self.subTest(defect=defect), self.assertRaisesRegex(m.Rejected, 'stored provider comparison'):model.run()

    def test_wrong_cpp_path_or_foreign_canonical_origin(self):
        model = Model();model.batch['ABIProbes']['attributes.c']['Preprocessed'] = 'C:/foreign/attributes.i'
        with self.assertRaisesRegex(m.Rejected, 'fixed accepted CPP'):model.run()
        model = Model();path = model.root / 'abi/attributes.i'
        model.files[path] = model.cpp.replace(model.source_root.as_posix().encode(), b'C:/foreign/source')
        model.sync_cpp();model.catalog()
        with self.assertRaisesRegex(m.Rejected, 'canonical CPP source header'):model.run()

    def test_wrong_cpp_bytes_and_missing_saved_cpp(self):
        for defect in ('attribute', 'declaration', 'missing'):
            model = Model();path = model.root / 'abi/attributes.i'
            if defect == 'attribute':model.files[path] = model.cpp.replace(b'"thread"', b'"memory"', 1)
            elif defect == 'declaration':model.files[path] = model.cpp.replace(PROTOTYPES[0].encode(), b'', 1)
            else:del model.files[path]
            model.catalog()
            with self.subTest(defect=defect), self.assertRaises(m.Rejected):model.run()

    def test_forged_stored_cpp_hash_counts_or_scope_rejected(self):
        for defect in ('hash', 'count', 'scope'):
            model = Model();record = model.batch['PreprocessedAttributes']
            if defect == 'hash':record['PreprocessedSha256'] = 'F' * 64
            elif defect == 'count':record['ForwardDeclarations'] = 7
            else:record['Scope']['DeclarationAttributesProven'] = True
            with self.subTest(defect=defect), self.assertRaisesRegex(m.Rejected, 'stored CPP comparison'):model.run()

    def test_recorded_acceptance_is_not_compile_replay(self):
        for value in (False, 1, None):
            model = Model();model.batch['ABIProbes']['attributes.c']['Classification'] = dict(AcceptedCompile=value)
            with self.subTest(value=value), self.assertRaises(m.Rejected):model.run()
        proof = Model().run()
        for key in ('AcceptedCompileReplayed', 'CompilationProvenanceReplayed',
                    'ProducerCommandProvenanceReplayed', 'AcceptedCompileProvenanceReplayed'):
            self.assertIs(proof[key], False)

    def test_wrong_positive_role_even_with_both_stored_copies_changed(self):
        for field in ('Original', 'Replayed', 'Map'):
            model = Model();model.batch['PositiveAuthority'][field] = 'C:/foreign/image.elf'
            readers = model.batch['ABIControlsDeferredReader']
            if field == 'Original':readers['Inputs'][0]['Path'] = 'C:/foreign/image.elf'
            elif field == 'Replayed':readers['Inputs'][1]['Path'] = 'C:/foreign/image.elf'
            else:readers['Map']['Path'] = 'C:/foreign/image.elf'
            with self.subTest(field=field), self.assertRaises(m.Rejected):model.run()
        model = Model();model.native['Links'][0]['Path'] = str(model.capture / 'emit-relocs/image.elf')
        model.sync_native();model.catalog()
        with self.assertRaisesRegex(m.Rejected, 'native ordinary path'):model.run()

    def test_wrong_positive_bytes_not_hidden_by_resigned_claims(self):
        model = Model();model.files[model.root / 'links/positive/image.elf'] = b'wrong actual image'
        model.sync_positive();model.catalog()
        with self.assertRaisesRegex(ValueError, 'unequal actual load image'):model.run()

    def test_stored_pending_or_promoted_deferred_facts_are_not_authority(self):
        for target, key, value in (('PositiveAuthority', 'LoadImageComparison', {}),
                ('PositiveAuthority', 'LinkCommandIndex', False), ('PositiveAuthority', 'RawElfByteIdentical', True),
                ('ABIControlsDeferredReader', 'Status', 'REPLAYED'), ('ABIControlsDeferredReader', 'ValidationDeferred', False),
                ('ABIControlsDeferredReader', 'RequiredCellsSatisfied', False)):
            model = Model();model.batch[target][key] = value
            with self.subTest(target=target, key=key), self.assertRaises(m.Rejected):model.run()

    def test_result_schema_counters_and_nonclaims_strict(self):
        baseline = Model().run()
        for key in m.COUNTS:
            for value in (True, -1, '0'):
                proof = copy.deepcopy(baseline);proof[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(m.Rejected):m.require_result(proof)
        for key in m.NONCLAIMS:
            proof = copy.deepcopy(baseline);proof[key] = 0
            with self.subTest(key=key), self.assertRaises(m.Rejected):m.require_result(proof)
        proof = copy.deepcopy(baseline);proof['FullCellQualified'] = True
        with self.assertRaises(m.Rejected):m.require_result(proof)

    def test_result_nested_metadata_sources_and_read_closure_strict(self):
        for defect in ('scope', 'provider-index', 'cpp-count', 'cpp-name', 'source', 'read', 'read-hash', 'extra-source',
                       'extra-fact', 'owner-count', 'target-bool', 'provider-extra', 'cpp-extra'):
            proof = Model().run()
            if defect == 'scope':proof['DeclaredProviders']['Scope']['CompilerExecuted'] = True
            elif defect == 'provider-index':proof['DeclaredProviders']['Providers'][0]['ObjectIndex'] = False
            elif defect == 'cpp-count':proof['PreprocessedAttributes']['ForwardDeclarations'] = True
            elif defect == 'cpp-name':proof['PreprocessedAttributes']['Declarations'][0]['Name'] = proof['PreprocessedAttributes']['Declarations'][1]['Name']
            elif defect == 'source':proof['ProjectSources'][0]['Path'] = 'C:/foreign/source.c'
            elif defect == 'read':proof['ReadInputs'].pop();proof['ReadFiles'] -= 1
            elif defect == 'read-hash':proof['ReadInputs'][0]['Sha256'] = 'F' * 64
            elif defect == 'extra-source':proof['ProjectSources'].append(copy.deepcopy(proof['ProjectSources'][0]));proof['ProjectSourceFiles'] += 1
            elif defect == 'extra-fact':proof['DeclaredProviders']['FullCellQualified'] = True
            elif defect == 'owner-count':proof['DeclaredProviders']['SourceInspection']['ExpectedOwners'].pop()
            elif defect == 'target-bool':proof['PreprocessedAttributes']['TargetContract']['NVICPriorityBits'] = True
            elif defect == 'provider-extra':proof['DeclaredProviders']['Providers'][0]['CompileProvenanceValidated'] = True
            else:proof['PreprocessedAttributes']['Declarations'][0]['AttributeEffectProven'] = True
            with self.subTest(defect=defect), self.assertRaises(m.Rejected):m.require_result(proof)

    def test_reader_bytes_missing_roles_and_manifest_authority(self):
        for defect in ('mutable', 'wrong', 'missing'):
            for role in ('source', 'native', 'cpp', 'original', 'replayed', 'map'):
                model = Model();path = dict(source=model.source_root / 'unused/unselected.c', native=model.capture / 'results.json',
                    cpp=model.root / 'abi/attributes.i', original=model.capture / 'ordinary/image.elf',
                    replayed=model.root / 'links/positive/image.elf', map=model.root / 'links/positive/image.map')[role]
                def read(name, expected):
                    raw = model.read(name, expected)
                    if name == path:
                        if defect == 'mutable':return bytearray(raw)
                        if defect == 'wrong':return raw + b'changed'
                        raise ValueError('missing read role')
                    return raw
                with self.subTest(defect=defect, role=role), self.assertRaises(ValueError):model.run(read=read)
        model = Model();model.catalog(enroll_manifest=True);model.run()
        self.assertIsNotNone(dict(model.reads)[model.root / 'artifacts.json'])
        model = Model();model.batch['InputHashes'][str(model.root / 'abi/attributes.i')] = 'F' * 64
        with self.assertRaisesRegex(m.Rejected, 'manifest/input correspondence'):model.run()

    def test_duplicate_nonfinite_overflow_and_malformed_json_fail_closed(self):
        for raw in (b'{"a":0,"a":1}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-Infinity}',
                    b'{"a":1e999}', b'[0,-1e999]', b'\xff', b'{'):
            with self.subTest(raw=raw), self.assertRaises(m.Rejected):m._json(raw)
        self.assertEqual(m._json(b'{"a":1e308,"b":1.25,"c":"1e999"}'),dict(a=1e308,b=1.25,c='1e999'))
        for location in ('manifest', 'native'):
            model = Model()
            if location == 'manifest':model.files[model.root / 'artifacts.json'] = b'{"Artifacts":{},"Unused":1e999}'
            else:
                path = model.capture / 'results.json';model.files[path] = b'{"Unused":1e999}'
                model.batch['NativeCapture']['ReceiptSha256'] = sha(model.files[path]);model.catalog()
            with self.subTest(location=location), self.assertRaisesRegex(m.Rejected, 'nonfinite JSON number'):model.run()

    def test_malformed_comparator_results_fail_without_promoting_claims(self):
        for key, value in (('Identical', False), ('Identical', 1), ('Entry', True), ('Segments', []), ('VectorBytes', '00')):
            model = Model();model.comparison[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(m.Rejected):model.run()
        model = Model();proof = model.run();proof['DeclaredProviders']['Providers'][0]['CompileFlags'].clear()
        self.assertTrue(model.batch['DeclaredProviders']['Providers'][0]['CompileFlags'])
        self.assertIsNone(model.batch['PositiveAuthority']['LoadImageComparison'])


def main():
    global BUFFERS, LOADED, m
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.absolute();temporary = Path(tempfile.gettempdir()).absolute()
    if output.exists() or output.is_relative_to(ROOT) or not output.is_relative_to(temporary):
        parser.error('fresh external TEMP output directory required')
    paths = dict(leaf=HERE / 'abi_replay.py', declarations=HERE / 'declarations.py', ordinary=HERE.parent / 'ordinary_final_cell/abi.py',
                 guard=HERE / 'batch_guard.py', oracle=HERE.parent / 'cm0_final_cell/abi.py')
    sources = (Path(__file__).resolve(), *paths.values(), *(ROOT / name for name in HEADERS + ORDER))
    BUFFERS = {path: path.read_bytes() for path in sources}
    opening = {str(path): sha(raw) for path, raw in BUFFERS.items()}
    for key, path in paths.items():
        if key == 'oracle':continue
        module = types.ModuleType('_abi_replay_test_' + key);module.__file__ = str(path)
        def buffered_read(name):
            if name not in BUFFERS:raise AssertionError('unenrolled helper read/' + str(name))
            return BUFFERS[name]
        with patch.object(Path, 'read_bytes', buffered_read):
            exec(compile(BUFFERS[path], str(path), 'exec'), module.__dict__)
        LOADED[key] = module
    m = LOADED['leaf']
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ReplayTests))
    closing = {str(path): sha(path.read_bytes()) for path in sources}
    report = dict(Status='PASS' if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped
                  and opening == closing else 'FAIL', Tests=result.testsRun, ExpectedTests=METHODS, Errors=len(result.errors),
        Failures=len(result.failures), Skipped=len(result.skipped), SourceHashes=opening, SourceDrift=opening != closing,
        ClosingFilesVerified=sum(opening[key] == value for key, value in closing.items()), SyntheticControlsOnly=True,
        ActualMachineBytesValidated=False, CompilerExecuted=False, AcceptedCompileReplayed=False,
        FullABIProof=False, Qualification=False, RequiredCellsSatisfied=0)
    output.mkdir(parents=True)
    (output / 'results.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n', encoding='ascii')
    print(json.dumps(report, sort_keys=True))
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
