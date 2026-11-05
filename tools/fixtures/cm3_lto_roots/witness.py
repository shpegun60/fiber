"""Retained native CM3 machine-root witness; no tools, targets or parity claim."""
import argparse
import ctypes
import hashlib
import importlib.abc
import importlib.util
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PROBE = ROOT / 'tools/fixtures/cm3_lto_transport/probe.py'
PROBE_SHA = 'F2D4CA9F1FC1F7FAE07F275913F7DFC688BFD8570AEE32DE2144EE1EA187F626'
LOADER = ROOT / 'tools/fixtures/cm3_final_roots/reference_witness.py'
LOADER_SHA = 'AED0DBAC11EB8644EED71F9FAF36C67B2854DE19262A78CC7EA601FA7A3DD99C'
CORE_SHA = '3A8F4E42B42189CDDAE44DE6AFA4468F24781B6EDFD13F02491C96C1E0729809'


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def need(condition, message):
    if not condition:
        raise ValueError('cm3-lto-root-witness: ' + message)


def stable_path(path):
    return Path(os.path.abspath(os.fspath(path)))


def load(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def interpreter_path():
    if os.name != 'nt':
        return Path(sys.executable).resolve(strict=True)
    buffer = ctypes.create_unicode_buffer(32768)
    api = ctypes.WinDLL('kernel32', use_last_error=True).GetModuleFileNameW
    api.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32)
    api.restype = ctypes.c_uint32
    length = api(None, buffer, len(buffer))
    need(0 < length < len(buffer), 'actual interpreter module path')
    return Path(buffer.value).resolve(strict=True)


class Witness:
    def __init__(self, args):
        probe_bytes = PROBE.read_bytes()
        need(sha(probe_bytes) == PROBE_SHA, 'fixed capture-admission utilities required')
        self.api = load('cm3_lto_root_capture_utilities', PROBE, probe_bytes)
        self.watch = self.api.Closure()
        self.root = self.api.checked_path(args.capture_build)
        self.result = self.watch.structured(self.root / 'results.json', self.api.digest_text(args.capture_receipt_sha256))
        self.artifacts = self.watch.structured(self.root / 'artifacts.json', self.api.digest_text(args.capture_artifacts_sha256))['Artifacts']
        need(type(self.artifacts) is dict and self.artifacts.get('results.json') == args.capture_receipt_sha256,
             'caller-bound capture seal')
        self.watch.tree(self.root, dict(self.artifacts, **{'artifacts.json': args.capture_artifacts_sha256}))
        r = self.result
        self.api.same([r['Status'], r['Scope'], r['Profile'], r['Mode'], r['Cohort'], r['Linkage'],
                       r['TranslationUnits'], r['SlimIRObjects'], r['FinalExecutableLinks'], r['SavedMachineObjects']],
                      ['PASS', 'NATIVE_CM3_O2_LTO_CAPTURE_FEASIBILITY_ONLY', 'CM3', 'O2-lto', self.api.COHORT,
                       'direct', 9, 8, 2, 2], 'exact native O2-lto capture scope')
        for key in ('InputClosureVerified', 'OutputSealVerified', 'TwinLoadImageCompared', 'TwinLoadImageIdentical',
                    'TwinAllocatedSectionsIdentical'):
            need(r.get(key) is True, 'complete capture closure and twins required')
        for key in ('FinalRootRelocationProof', 'FinalReferenceParity', 'SourceToMachineSemanticProof',
                    'OrdinaryOwnerContractSatisfied', 'PolicyEquivalence', 'CpuExecution', 'BoardExecution',
                    'GlobalFreezeQualified', 'ReferenceBuilt', 'ArchiveExtraction', 'RequiredCellSatisfied'):
            need(r.get(key) is False, 'literal false producer scope: ' + key)
        need(type(r.get('RequiredCellsSatisfied')) is int and r['RequiredCellsSatisfied'] == 0, 'no producer global credit')
        inputs = self.watch.structured(self.root / 'inputs.json')
        self.buffers = {}
        self.api.same([row['Kind'] for row in r['Links']], ['ordinary', 'emit-relocs'], 'fixed ordered links')
        need(len(r['Sources']) == 9 and r['Commands'] and all(c['Status'] == 'PASS' and type(c['Exit']) is int
             and c['Exit'] == 0 and c['TimedOut'] is False for c in r['Commands']), 'complete producer source/command records')
        for row in inputs['Watched']:
            self.watch.read(row['Path'], row['Sha256'])
        self.originals = set()
        for row in inputs['Files']:
            original, captured = self.api.regular(row['Original']), self.api.regular(row['Captured'])
            need(original not in self.originals and captured.is_relative_to(self.root), 'unique captured-input provider')
            self.originals.add(original)
            need(self.artifacts[captured.relative_to(self.root).as_posix()] == row['Sha256'], 'input/artifact binding')
            data = self.watch.read(captured, row['Sha256'])
            self.watch.read(original, row['Sha256'])
            if original.suffix == '.py':
                self.buffers[original] = data
        need(self.buffers.get(PROBE) == probe_bytes and sha(self.buffers[LOADER]) == LOADER_SHA,
             'executed capture and immutable-loader source authority')
        self.core_path = Path(r['SeedBuild']) / 'source/tools/fixtures/classic_final_image/elf.py'
        need(sha(self.buffers[self.core_path]) == CORE_SHA, 'unchanged ordinary core reader')
        interpreter = self.api.regular(interpreter_path())
        self.watch.read(interpreter)
        self.output = self.api.checked_path(args.output_dir, must_exist=False)
        denied = {ROOT, self.root, *(path.parent for path in self.watch.hashes)}
        need(not self.output.exists() and all(not self.output.is_relative_to(path) and not path.is_relative_to(self.output)
                                             for path in denied), 'fresh output outside all authenticated input roots')
        self.watch.read(PROBE, PROBE_SHA)
        for path in (Path(__file__).resolve(), HERE / 'native.py', HERE / 'mutations.py'):
            self.buffers[path] = self.watch.read(path)
        twin_path = self.root / 'load-image.json'
        need(r['TwinLoadImagesPath'] == str(twin_path), 'fixed producer twin path')
        self.api.same(self.watch.structured(twin_path, r['TwinLoadImagesSha256']), r['TwinLoadImages'], 'producer twin value')
        self.watch.close()
        self.args = args
        self.expected_outputs = {'results.json', 'artifacts.json'}
        self.report = dict(Status='FAIL', Scope='NATIVE_CM3_O2_LTO_MACHINE_TO_FINAL_ROOT_WITNESS_ONLY', Error=None,
            CaptureBuild=str(self.root), CaptureReceiptSha256=args.capture_receipt_sha256,
            CaptureArtifactsSha256=args.capture_artifacts_sha256, NativeCommandsExecuted=0,
            RequiredCellsSatisfied=0, Qualification=False, SourceToMachineSemanticProof=False,
            CanonicalProtocolValidated=False, FinalReferenceParity=False, PolicyEquivalence=False,
            CompleteObjectProof=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False)
        self.report['Interpreter'] = dict(ReportedExecutable=sys.executable, ModulePath=str(interpreter),
                                          Sha256=self.watch.hashes[interpreter], Version=sys.version)

    def run(self):
        self.output.mkdir(parents=True)
        try:
            self._read_roots()
            self.watch.close()
            self.report.update(Status='MACHINE-ROOT-WITNESS-PASS-NOT-QUALIFIED',
                               InputClosureVerified=True, ClosingFilesVerified=len(self.watch.hashes))
        except BaseException as error:
            self.report.update(Status='FAIL', Error=type(error).__name__ + ': ' + str(error), InputClosureVerified=False)
        self.report['InputHashes'] = {str(path): value for path, value in sorted(self.watch.hashes.items())}
        try:
            self._seal()
            self.watch.close()
            actual = {name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items() if name != 'artifacts.json'}
            self.api.same(actual, self.sealed, 'late witness artifact membership/hash closure')
            need(sha((self.output / 'artifacts.json').read_bytes()) == self.manifest_sha, 'late witness manifest drift')
        except BaseException as error:
            self.report.update(Status='FAIL', Error=(self.report.get('Error') or '') + '; closing: ' + str(error),
                               InputClosureVerified=False)
            try:
                self._seal()
            except BaseException as failure:
                self.report.update(OutputSealVerified=False, SealError=str(failure))
                self.api.save(self.output / 'results.json', self.report)
        return self.report['Status'] == 'MACHINE-ROOT-WITNESS-PASS-NOT-QUALIFIED'

    def _read_roots(self):
        loader = load('cm3_lto_root_immutable_loader', LOADER, self.buffers[LOADER])
        graph = loader.FrozenSources(self.buffers)
        package = Path(self.result['SeedBuild']) / 'python/elftools'
        modules = {}
        for path in self.buffers:
            if path.is_relative_to(package):
                parts = list(path.relative_to(package.parent).with_suffix('').parts)
                is_package = parts[-1] == '__init__'
                if is_package:
                    parts.pop()
                name = '.'.join(parts)
                need(name not in modules, 'parser module alias')
                modules[name] = (path, is_package)
        need('elftools' in modules and not any(n == 'elftools' or n.startswith('elftools.') for n in sys.modules),
             'closed unimported parser package')
        class Finder(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname != 'elftools' and not fullname.startswith('elftools.'):
                    return None
                need(fullname in modules and target is None, 'unknown parser source')
                source, is_package = modules[fullname]
                spec = graph.spec(fullname, source)
                if is_package:
                    spec.submodule_search_locations = [str(source.parent)]
                return spec
        copies = []
        for index, (path, data) in enumerate(sorted(self.buffers.items())):
            target = self.output / 'source-buffers' / ('%04d-' % index + path.name)
            self.declare_output(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            self.watch.read(target, sha(data))
            copies.append(dict(Original=str(path), Captured=str(target), Sha256=sha(data)))
        link = self.result['Links'][1]
        machine, startup = self.api.regular(link['Machine']), self.api.regular(self.result['Sources'][-1]['Object'])
        need(machine == self.root / 'emit-relocs/image.elf.ltrans0.ltrans.o', 'exact saved-machine role')
        inputs = dict(Machine=machine, Final=self.api.regular(link['Path']),
                      Disassembly=self.api.regular(link['Path'] + '.dis'), LinkMap=self.api.regular(link['Map']), Startup=startup)
        roles = dict(inputs, Plain=self.api.regular(self.result['Links'][0]['Path']))
        need(len(set(roles.values())) == 6 and all(not path.samefile(other) for index, path in enumerate(roles.values())
             for other in list(roles.values())[:index]), 'six distinct physical positive input roles')
        binary_buffers, binary_copies = {}, []
        for role, path in roles.items():
            need(path.is_relative_to(self.root), 'positive input escaped authenticated capture')
            expected = self.artifacts[path.relative_to(self.root).as_posix()]
            data = self.watch.read(path, expected)
            target = self.output / 'witness-inputs' / (role + path.suffix)
            self.declare_output(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            self.watch.read(target, expected)
            binary_buffers[path] = data
            binary_copies.append(dict(Role=role, Original=str(path), Captured=str(target), Sha256=expected))
        old_meta, raw_read = list(sys.meta_path), Path.read_bytes
        immutable = {stable_path(path): data for path, data in self.buffers.items()}
        immutable.update({stable_path(path): data for path, data in binary_buffers.items()})
        mutable_paths = set()
        def source_read(path):
            selected = stable_path(path)
            if selected in immutable:
                return immutable[selected]
            need(selected in mutable_paths, 'unknown reader input outside immutable buffers or declared private files')
            return raw_read(path)
        try:
            sys.meta_path.insert(0, Finder())
            with graph.active(), patch.object(Path, 'read_bytes', source_read):
                core = graph.load('cm3_lto_root_frozen_core', self.core_path)
                adapter = graph.load('cm3_lto_root_native_adapter', HERE / 'native.py')
                image = adapter.NativeCM3LTOImage(core, machine, link['Path'], link['Path'] + '.dis',
                    provider_objects={str(machine): machine, str(startup): startup}, link_map=link['Map'])
                self.report['Roots'] = [image.function(name) for name in adapter.ROOTS]
                self.report['Twins'] = core.compare_load_images(self.result['Links'][0]['Path'], link['Path'])
                mutations = graph.load('cm3_lto_root_actual_mutations', HERE / 'mutations.py')
                for name, _ in mutations.CASES:
                    need(type(name) is str and name and all(character.isascii() and (character.isalnum() or character == '-')
                                                         for character in name), 'fixed private case name')
                    for role, path in inputs.items():
                        target = self.output / 'mutants' / name / (role + path.suffix)
                        self.declare_output(target)
                        mutable_paths.add(stable_path(target))
                self.report['Mutants'] = mutations.run_cases(core, adapter, image, inputs, self.output)
                for case in self.report['Mutants']:
                    for row in case['Files']:
                        self.watch.read(row['Path'], row['Sha256'])
                need(len(self.report['Mutants']) == 16 and all(row['Status'] == 'PASS' for row in self.report['Mutants']),
                     'all fixed actual ELF negative controls must reject at their declared guard')
            self.report.update(ExecutedSourceBuffers=graph.executed, CapturedSourceBuffers=copies,
                               BinaryInputs=binary_copies, ImmutablePositiveInputsConsumed=True)
        finally:
            sys.meta_path[:] = old_meta

    def declare_output(self, path):
        path = Path(path)
        need(path.is_relative_to(self.output), 'declared output escaped witness')
        name = path.relative_to(self.output).as_posix()
        need(name not in self.expected_outputs, 'duplicate declared output member')
        self.expected_outputs.add(name)

    def _seal(self):
        success = self.report['Status'] == 'MACHINE-ROOT-WITNESS-PASS-NOT-QUALIFIED'
        expected = self.expected_outputs - {'artifacts.json'}
        if success:
            members = set(self.api.files_under(self.output)) - {'results.json', 'artifacts.json'}
            planned = expected - {'results.json'}
            self.report['UnexpectedOutputMembers'] = sorted(members - planned)
            self.report['MissingDeclaredOutputMembers'] = sorted(planned - members)
            need(members == planned, 'predetermined witness artifact membership required before receipt')
        self.report['OutputSealVerified'] = True
        self.api.save(self.output / 'results.json', self.report)
        self.sealed = {name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items() if name != 'artifacts.json'}
        if success:
            need(set(self.sealed) == expected, 'predetermined witness artifact membership required')
        manifest = dict(Artifacts=self.sealed)
        self.api.save(self.output / 'artifacts.json', manifest)
        manifest_bytes = (self.output / 'artifacts.json').read_bytes()
        self.api.same(json.loads(manifest_bytes, object_pairs_hook=self.api.unique_object), manifest,
                      'written witness manifest value differs')
        self.manifest_sha = sha(manifest_bytes)
        actual = {name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items() if name != 'artifacts.json'}
        self.api.same(actual, self.sealed, 'exact witness output seal')


def main(argv=None):
    need(not sys.flags.optimize, 'unoptimized interpreter required')
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('capture-build', 'capture-receipt-sha256', 'capture-artifacts-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    witness = Witness(parser.parse_args(argv))
    passed = witness.run()
    print(witness.report['Status'], witness.report.get('Error') or '', str(witness.output))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
