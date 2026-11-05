"""Actual reference CM3 LTO roots and private ELF mutation controls."""
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
UTILITY = ROOT / 'tools/fixtures/cm3_lto_transport/probe.py'
UTILITY_SHA = 'F2D4CA9F1FC1F7FAE07F275913F7DFC688BFD8570AEE32DE2144EE1EA187F626'
PRODUCER = ROOT / 'tools/fixtures/cm3_reference_lto_transport/probe.py'
PRODUCER_SHA = '1D1FDC0D644123FEF1E182107A8062A0BA9BCCB385DA0C2D13BDFD741290F2C3'
ADMISSION = ROOT / 'tools/fixtures/cm3_reference_lto_transport/admission.py'
ADMISSION_SHA = '27C192C12E30BD4F1A872D6A8586B85C303AF6D6873A85A26238BE7DD4962ECC'
LOADER = ROOT / 'tools/fixtures/cm3_final_roots/reference_witness.py'
LOADER_SHA = 'AED0DBAC11EB8644EED71F9FAF36C67B2854DE19262A78CC7EA601FA7A3DD99C'
CORE_SHA = '3A8F4E42B42189CDDAE44DE6AFA4468F24781B6EDFD13F02491C96C1E0729809'
PIN = 'a50edad08b29052631aa469d4df6e6ec7ff68878'
PASS = 'REFERENCE-MACHINE-ROOT-PASS-NOT-QUALIFIED'


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def need(value, message):
    if not value:
        raise ValueError('cm3-reference-lto-witness: ' + message)


def stable(path):
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
    b = ctypes.create_unicode_buffer(32768)
    api = ctypes.WinDLL('kernel32', use_last_error=True).GetModuleFileNameW
    api.argtypes, api.restype = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32), ctypes.c_uint32
    count = api(None, b, len(b))
    need(0 < count < len(b), 'actual interpreter module path')
    return Path(b.value).resolve(strict=True)


class Witness:
    def __init__(self, args):
        utility_bytes = UTILITY.read_bytes()
        need(sha(utility_bytes) == UTILITY_SHA, 'fixed self-trusted capture utilities')
        self.api = load('cm3_reference_lto_root_utilities', UTILITY, utility_bytes)
        self.watch = self.api.Closure()
        self.root = self.api.checked_path(args.capture_build)
        self.result = self.watch.structured(self.root / 'results.json', self.api.digest_text(args.capture_receipt_sha256))
        self.artifacts = self.watch.structured(self.root / 'artifacts.json', self.api.digest_text(args.capture_artifacts_sha256))['Artifacts']
        need(type(self.artifacts) is dict and self.artifacts.get('results.json') == args.capture_receipt_sha256,
             'caller-bound capture manifest/receipt')
        self.watch.tree(self.root, dict(self.artifacts, **{'artifacts.json': args.capture_artifacts_sha256}))
        r = self.result
        self.api.same([r['Status'], r['Scope'], r['Profile'], r['Mode'], r['Cohort'], r['Linkage'],
                       r['ReferenceCommit'], r['TranslationUnits'], r['SlimIRObjects'], r['FinalExecutableLinks'], r['SavedMachineObjects']],
                      ['PASS', 'PINNED_REFERENCE_CM3_O2_LTO_CAPTURE_FEASIBILITY_ONLY', 'CM3', 'O2-lto', self.api.COHORT,
                       'direct', PIN, 4, 3, 2, 2], 'exact pinned reference capture scope')
        for key in ('ReferenceBuilt', 'InputClosureVerified', 'OutputSealVerified', 'TwinLoadImageCompared',
                    'TwinLoadImageIdentical', 'TwinAllocatedSectionsIdentical'):
            need(r.get(key) is True, 'literal complete capture marker: ' + key)
        for key in ('NativeBuilt', 'FinalRootRelocationProof', 'FinalReferenceParity', 'SourceToMachineSemanticProof',
                    'OrdinaryOwnerContractSatisfied', 'PolicyEquivalence', 'ReferenceKernelAvailable',
                    'SchedulerSemanticsProven', 'CSourceSemanticProof', 'CanonicalProtocolValidated',
                    'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified', 'RequiredCellSatisfied'):
            need(r.get(key) is False, 'literal nonclaim: ' + key)
        need(type(r.get('RequiredCellsSatisfied')) is int and r['RequiredCellsSatisfied'] == 0, 'no producer global credit')
        self.api.same([row['Kind'] for row in r['Links']], ['ordinary', 'emit-relocs'], 'fixed ordered twins')
        need(len(r['Sources']) == 4 and r['Commands'] and all(row['Status'] == 'PASS' and type(row['Exit']) is int
             and row['Exit'] == 0 and row['TimedOut'] is False for row in r['Commands']), 'complete producer records')
        records = self.watch.structured(self.root / 'inputs.json')
        self.buffers, originals = {}, set()
        for row in records['Watched']:
            self.watch.read(row['Path'], row['Sha256'])
        for row in records['Files']:
            original, captured = self.api.regular(row['Original']), self.api.regular(row['Captured'])
            need(original not in originals and captured.is_relative_to(self.root), 'unique contained captured-input role')
            originals.add(original)
            need(self.artifacts[captured.relative_to(self.root).as_posix()] == row['Sha256'], 'input/manifest binding')
            data = self.watch.read(captured, row['Sha256'])
            self.watch.read(original, row['Sha256'])
            if original.suffix == '.py':
                self.buffers[original] = data
        for path, expected in ((UTILITY, UTILITY_SHA), (PRODUCER, PRODUCER_SHA), (ADMISSION, ADMISSION_SHA), (LOADER, LOADER_SHA)):
            need(sha(self.buffers[path]) == expected, 'fixed executed producer/loader source identity')
        need(self.buffers[UTILITY] == utility_bytes, 'executed utility bytes differ from capture authority')
        self.core_path = Path(r['SeedBuild']) / 'source/tools/fixtures/classic_final_image/elf.py'
        need(sha(self.buffers[self.core_path]) == CORE_SHA, 'unchanged ordinary generic reader')
        interpreter = self.api.regular(interpreter_path())
        self.watch.read(interpreter)
        self.output = self.api.checked_path(args.output_dir, must_exist=False)
        denied = {ROOT, self.root, *(path.parent for path in self.watch.hashes)}
        need(not self.output.exists() and all(not self.output.is_relative_to(path) and not path.is_relative_to(self.output)
             for path in denied), 'fresh output outside all authenticated input roots')
        for path in (Path(__file__).resolve(), HERE / 'reference.py', HERE / 'mutations.py'):
            self.buffers[path] = self.watch.read(path)
        twin_path = self.root / 'load-image.json'
        need(r['TwinLoadImagesPath'] == str(twin_path), 'fixed producer twin path')
        self.api.same(self.watch.structured(twin_path, r['TwinLoadImagesSha256']), r['TwinLoadImages'], 'producer twin value')
        self.watch.close()
        self.expected = {'results.json', 'artifacts.json'}
        self.report = dict(Status='FAIL', Error=None, Scope='REFERENCE_CM3_O2_LTO_MACHINE_TO_FINAL_ROOTS_ONLY',
            CaptureBuild=str(self.root), CaptureReceiptSha256=args.capture_receipt_sha256,
            CaptureArtifactsSha256=args.capture_artifacts_sha256, ReferenceCommit=PIN,
            Qualification=False, ActualELFMutationControlsExecuted=False, Mutants=[], NativeCommandsExecuted=0,
            CanonicalProtocolValidated=False, FinalReferenceParity=False, FullABIProof=False,
            SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False, CompleteObjectProof=False,
            PolicyEquivalence=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False, RequiredCellsSatisfied=0,
            Interpreter=dict(ReportedExecutable=sys.executable, ModulePath=str(interpreter), Version=sys.version,
                             Sha256=self.watch.hashes[interpreter]))

    def declare(self, path):
        need(path.is_relative_to(self.output), 'declared output escaped witness')
        name = path.relative_to(self.output).as_posix()
        need(name not in self.expected, 'duplicate declared output')
        self.expected.add(name)

    def _read(self):
        loader = load('cm3_reference_lto_root_immutable_loader', LOADER, self.buffers[LOADER])
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
                need(name not in modules, 'ambiguous parser source')
                modules[name] = (path, is_package)
        need('elftools' in modules and not any(n == 'elftools' or n.startswith('elftools.') for n in sys.modules),
             'closed fresh parser package')
        class Finder(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname != 'elftools' and not fullname.startswith('elftools.'):
                    return None
                need(fullname in modules and target is None, 'unknown parser import')
                source, is_package = modules[fullname]
                spec = graph.spec(fullname, source)
                if is_package:
                    spec.submodule_search_locations = [str(source.parent)]
                return spec
        copies = []
        for index, (path, data) in enumerate(sorted(self.buffers.items())):
            target = self.output / 'source-buffers' / ('%04d-' % index + path.name)
            self.declare(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            self.watch.read(target, sha(data))
            copies.append(dict(Original=str(path), Captured=str(target), Sha256=sha(data)))
        link = self.result['Links'][1]
        roles = dict(Machine=self.api.regular(link['Machine']), Final=self.api.regular(link['Path']),
                     Disassembly=self.api.regular(link['Path'] + '.dis'), LinkMap=self.api.regular(link['Map']),
                     Startup=self.api.regular(self.result['Sources'][3]['Object']), Plain=self.api.regular(self.result['Links'][0]['Path']))
        need(roles['Machine'] == self.root / 'emit-relocs/image.elf.ltrans0.ltrans.o', 'fixed actual machine role')
        need(len(set(roles.values())) == 6 and all(not path.samefile(other) for index, path in enumerate(roles.values())
             for other in list(roles.values())[:index]), 'six distinct physical positive roles')
        snapshots = {stable(path): data for path, data in self.buffers.items()}
        binaries = []
        for role, path in roles.items():
            need(path.is_relative_to(self.root), 'positive role escaped capture')
            expected = self.artifacts[path.relative_to(self.root).as_posix()]
            data = self.watch.read(path, expected)
            target = self.output / 'witness-inputs' / (role + path.suffix)
            self.declare(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            self.watch.read(target, expected)
            snapshots[stable(path)] = data
            binaries.append(dict(Role=role, Original=str(path), Captured=str(target), Sha256=expected))
        raw_read, mutable_paths = Path.read_bytes, set()
        def fixed_read(path):
            selected = stable(path)
            if selected in snapshots:
                return snapshots[selected]
            need(selected in mutable_paths, 'unknown reader input outside immutable buffers or declared private files')
            return raw_read(path)
        old_meta = list(sys.meta_path)
        try:
            sys.meta_path.insert(0, Finder())
            with graph.active(), patch.object(Path, 'read_bytes', fixed_read):
                core = graph.load('cm3_reference_lto_root_core', self.core_path)
                adapter = graph.load('cm3_reference_lto_root_adapter', HERE / 'reference.py')
                image = adapter.ReferenceCM3LTOImage(core, roles['Machine'], roles['Final'], roles['Disassembly'],
                    provider_objects={str(roles['Machine']): roles['Machine'], str(roles['Startup']): roles['Startup']},
                    link_map=roles['LinkMap'])
                self.report['Roots'] = [image.function(name) for name in adapter.ROOTS]
                self.report['Twins'] = core.compare_load_images(roles['Plain'], roles['Final'])
                mutations = graph.load('cm3_reference_lto_root_mutations', HERE / 'mutations.py')
                inputs = {role: path for role, path in roles.items() if role != 'Plain'}
                need(len(mutations.CASES) == 16 and len({name for name, _ in mutations.CASES}) == 16,
                     'exact fixed mutation catalog')
                for name, _ in mutations.CASES:
                    need(type(name) is str and name and all(character.isascii() and (character.isalnum() or character == '-')
                                                         for character in name), 'fixed private case name')
                    for role, path in inputs.items():
                        target = self.output / 'mutants' / name / (role + path.suffix)
                        self.declare(target)
                        mutable_paths.add(stable(target))
                self.report['Mutants'] = mutations.run_cases(core, adapter, image, inputs, self.output)
                for case in self.report['Mutants']:
                    for row in case['Files']:
                        self.watch.read(row['Path'], row['Sha256'])
                need(len(self.report['Mutants']) == 16 and all(row['Status'] == 'PASS' for row in self.report['Mutants']),
                     'all actual ELF controls must reject at their declared guard')
            self.report.update(ExecutedSourceBuffers=graph.executed, CapturedSourceBuffers=copies,
                               BinaryInputs=binaries, ImmutablePositiveInputsConsumed=True,
                               ActualELFMutationControlsExecuted=True)
        finally:
            sys.meta_path[:] = old_meta

    def _seal(self):
        success = self.report['Status'] == PASS
        if success:
            members = set(self.api.files_under(self.output)) - {'results.json', 'artifacts.json'}
            planned = self.expected - {'results.json', 'artifacts.json'}
            self.report.update(UnexpectedOutputMembers=sorted(members - planned), MissingDeclaredOutputMembers=sorted(planned - members))
            need(members == planned, 'predetermined output membership')
        self.report['OutputSealVerified'] = True
        self.api.save(self.output / 'results.json', self.report)
        self.sealed = {name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items() if name != 'artifacts.json'}
        if success:
            need(set(self.sealed) == self.expected - {'artifacts.json'}, 'exact planned seal membership')
        manifest = dict(Artifacts=self.sealed)
        self.api.save(self.output / 'artifacts.json', manifest)
        manifest_bytes = (self.output / 'artifacts.json').read_bytes()
        self.api.same(json.loads(manifest_bytes, object_pairs_hook=self.api.unique_object), manifest, 'written manifest value')
        self.manifest_sha = sha(manifest_bytes)
        actual = {name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items() if name != 'artifacts.json'}
        self.api.same(actual, self.sealed, 'post-manifest output closure')

    def run(self):
        self.output.mkdir(parents=True)
        try:
            self._read()
            self.watch.close()
            self.report.update(Status=PASS, InputClosureVerified=True, ClosingFilesVerified=len(self.watch.hashes))
        except BaseException as error:
            self.report.update(Status='FAIL', Error=type(error).__name__ + ': ' + str(error), InputClosureVerified=False)
        self.report['InputHashes'] = {str(path): value for path, value in sorted(self.watch.hashes.items())}
        try:
            self._seal()
            self.watch.close()
            self.api.same({name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items()
                           if name != 'artifacts.json'}, self.sealed, 'late output closure')
            need(sha((self.output / 'artifacts.json').read_bytes()) == self.manifest_sha, 'late manifest drift')
        except BaseException as error:
            self.report.update(Status='FAIL', Error=(self.report.get('Error') or '') + '; closing: ' + str(error), InputClosureVerified=False)
            try:
                self._seal()
            except BaseException as failure:
                self.report.update(OutputSealVerified=False, SealError=str(failure))
                self.api.save(self.output / 'results.json', self.report)
        return self.report['Status'] == PASS


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
