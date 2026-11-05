"""Pinned reference CM3 O2-lto capture feasibility, not native/reference parity."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
from types import SimpleNamespace
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMMON = HERE.with_name('cm3_lto_transport') / 'probe.py'
COMMON_SHA = 'F2D4CA9F1FC1F7FAE07F275913F7DFC688BFD8570AEE32DE2144EE1EA187F626'
PIN = 'a50edad08b29052631aa469d4df6e6ec7ff68878'
NAMES = ('prvPortStartFirstTask', 'vPortSVCHandler', 'xPortPendSVHandler', 'pxCurrentTCB',
         'vTaskSwitchContext', 'xTaskIncrementTick', 'reference_fail_stop')


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def need(condition, message):
    if not condition:
        raise ValueError('cm3-reference-lto-probe: ' + message)


def load(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def scope_report(api):
    result = api.scope_report()
    result.update(Scope='PINNED_REFERENCE_CM3_O2_LTO_CAPTURE_FEASIBILITY_ONLY', ReferenceCommit=PIN,
        NativeBuilt=False, ReferenceBuilt=False, ReferenceKernelAvailable=False, SchedulerSemanticsProven=False,
        CSourceSemanticProof=False, HandlerRoutingProven=False, CanonicalProtocolValidated=False)
    return result


def symbol_records(text, sections):
    found = {name: [] for name in NAMES}
    names = {row['Index']: row['Name'] for row in sections}
    pattern = r'\s*[0-9]+:\s+([0-9a-fA-F]+)\s+([0-9]+|0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*'
    for line in text.splitlines():
        match = re.fullmatch(pattern, line)
        if match and match[7] in found:
            section = int(match[6]) if match[6].isdigit() else match[6]
            found[match[7]].append(dict(Name=match[7], Value=int(match[1], 16),
                Size=int(match[2], 16 if match[2].startswith('0x') else 10), Type=match[3], Binding=match[4],
                Visibility=match[5], Section=section, SectionName=names.get(section), SymbolOriginBound=False))
    need(all(len(rows) == 1 for rows in found.values()), 'exactly one actual symbol fact per fixed reference name')
    return [found[name][0] for name in NAMES]


def probe_type(api):
    class Probe(api.Probe):
        def __init__(self, seed, args):
            # Reuse only the shared tool/capture plumbing's receipt field names.
            internal = SimpleNamespace(**vars(args), native_receipt_sha256=args.reference_receipt_sha256,
                                       native_artifacts_sha256=args.reference_artifacts_sha256)
            super().__init__(seed, internal)
            self.report = scope_report(api)

        def prepare(self):
            super().prepare()
            self.report.update(SeedSide='Reference', ReferenceCommit=PIN,
                SourceToMachineOwnership='LTO-MERGED; NO ORIGINAL FOUR-TU MACHINE OWNERSHIP CLAIM',
                ReferenceFileBindings=self.seed.result['ReferenceFileBindings'],
                FixtureHandlerInstallationCheck=1, ReferenceKernelAvailable=False)

        def verify_objects(self, stage):
            need(len(self.object_hashes) == len(self.objects) == 4, 'four frozen reference inputs required')
            for path in self.objects:
                need(sha(api.regular(path).read_bytes()) == self.object_hashes[path], 'slim/startup input drift: ' + stage)
            self.report.setdefault('ObjectChecks', []).append(dict(Stage=stage, Status='PASS'))

        def compile(self):
            directory = self.output / 'objects'
            directory.mkdir()
            for index, row in enumerate(self.seed.sources):
                source = api.regular(row['Source'])
                self.seed.closure.read(source, row['SourceSha256'])
                flags = row['CompileFlags'] if index == 3 else api.mode_flags(row['CompileFlags'])
                obj = directory / ('%02d-' % index + source.stem + '.o')
                dependency_file = obj.with_suffix('.d')
                result = dict(Source=str(source), SourceSha256=row['SourceSha256'], CompileFlags=flags,
                              Object=str(obj), DependencyFile=str(dependency_file), SlimIR=index != 3)
                self.report['Sources'].append(result)
                self.command([self.tools['gcc'], *flags, '-MD', '-MF', dependency_file, '-MT', 'pilot-source-' + str(index),
                              '-c', source, '-o', obj], 'compile ' + source.name)
                header = api.require_elf32le(api.regular(obj).read_bytes())
                self.seed.closure.read(source, row['SourceSha256'])
                expected = {api.regular(dependency['Path']) for dependency in row['Dependencies']}
                expected = {self.tool_root / path.relative_to(self.seed.tool_root)
                            if path.is_relative_to(self.seed.tool_root) else path for path in expected}
                actual = set(self.seed.native.read_dependencies(dependency_file))
                need(actual == expected, 'actual reference compile dependency set differs from ordinary seed')
                result['ActualCompileDependencies'] = [dict(Path=str(path), Sha256=sha(path.read_bytes())) for path in sorted(actual)]
                for path in actual:
                    if path.is_relative_to(self.tool_root):
                        need(sha(path.read_bytes()) == self.tool_hashes[path], 'relocated system header drift')
                    else:
                        self.seed.closure.read(path, self.seed.closure.hashes[path])
                text = self.inspect(obj)
                sections = api.section_records(text)
                api.same([section['Index'] for section in sections], list(range(header['SectionCount'])),
                         'all actual input sections must be accounted')
                if index != 3:
                    need(any(section['Name'].startswith('.gnu.lto_') for section in sections) and
                         not any('X' in section['Flags'] and section['Size'] for section in sections),
                         'genuine slim reference IR; machine fat fallback forbidden')
                    self.report['SlimIRObjects'] += 1
                else:
                    need(not any(section['Name'].startswith('.gnu.lto_') for section in sections), 'startup must remain native')
                result.update(ObjectSha256=sha(obj.read_bytes()), ELFHeader=header, Sections=sections, CompileDependenciesVerified=True)
                self.objects.append(obj)
                self.object_hashes[obj] = result['ObjectSha256']
                self.report['TranslationUnits'] += 1
            self.verify_objects('after-compile')

        def build(self):
            self.prepare()
            self.compile()
            for kind, emit in (('ordinary', False), ('emit-relocs', True)):
                directory = self.output / kind
                directory.mkdir()
                image, link_map = directory / 'image.elf', directory / 'image.map'
                self.seed.closure.close()
                self.verify_objects('before-link-' + kind)
                try:
                    command = self.command([self.tools['gcc'], *api.link_flags(self.seed.artifact, self.objects,
                        self.seed.script, image, link_map, emit)], 'link ' + kind, cwd=directory)
                finally:
                    self.verify_objects('after-link-' + kind)
                machine = api.require_saved_machine_name(directory / 'image.elf.ltrans0.ltrans.o', image)
                need({path for path in directory.iterdir() if re.fullmatch(r'image[.]elf[.]ltrans[0-9]+[.]ltrans[.]o', path.name)}
                     == {machine}, 'exactly one actual machine partition per link')
                machine_bytes = api.regular(machine).read_bytes()
                header = api.require_elf32le(machine_bytes)
                text = self.inspect(machine)
                sections = api.section_records(text)
                api.same([row['Index'] for row in sections], list(range(header['SectionCount'])), 'all saved-machine sections required')
                need(not any(row['Name'].startswith('.gnu.lto_') for row in sections)
                     and any('X' in row['Flags'] and row['Size'] for row in sections), 'real post-LTO machine bytes required')
                symbols = [dict(row, Artifact=str(machine), ArtifactSha256=sha(machine_bytes))
                           for row in symbol_records(text, sections)]
                self.inspect(image)
                final_header = api.require_elf32le(api.regular(image).read_bytes(), 'EXEC')
                need(api.regular(link_map).stat().st_size > 0, 'retained actual reference map required')
                for suffix in ('.res', '.ltrans.out', '.ltrans0.o', '.ltrans0.ltrans.s'):
                    need(api.regular(Path(str(image) + suffix)).stat().st_size > 0, 'actual LTO transport record: ' + suffix)
                observed = self.trace_identities(command.stderr)
                captured = {name: sha(path.read_bytes()) for name, path in api.files_under(directory).items()}
                self.seed.closure.tree(directory, captured)
                self.report['Links'].append(dict(Kind=kind, Path=str(image), Sha256=sha(image.read_bytes()),
                    Map=str(link_map), MapSha256=sha(link_map.read_bytes()), Machine=str(machine), MachineSha256=sha(machine_bytes),
                    MachineHeader=header, FinalHeader=final_header, MachineSections=sections, MachineSymbols=symbols,
                    VerboseObservedTools=observed, EntireDirectoryArtifacts=captured,
                    MachineOwner='ACTUAL-LTRANS-OBJECT; NOT ORIGINAL PORT-TU', OrdinarySymbolPredicatesApplied=False))
                self.report['FinalExecutableLinks'] += 1
                self.report['SavedMachineObjects'] += 1
            self.verify_objects('closing')
            self.compare_twins()
            self.report['ReferenceBuilt'] = True
            self.complete = True

        def finish(self, error=None):
            self.report.update(Error=None if error is None else type(error).__name__ + ': ' + str(error),
                               InputClosureVerified=False, OutputSealVerified=False)
            try:
                self.close_inputs()
                self.report['InputClosureVerified'] = True
                need(error is None and self.complete is True and len(self.report['Sources']) == 4
                     and self.report['TranslationUnits'] == 4
                     and len(self.report['Links']) == 2 and self.report['SlimIRObjects'] == 3
                     and self.report['SavedMachineObjects'] == 2 and self.report['FinalExecutableLinks'] == 2
                     and self.report['ReferenceBuilt'] is True and self.twins_verified is True
                     and self.report.get('TwinLoadImageCompared') is True
                     and self.report.get('TwinLoadImages', {}).get('Identical') is True
                     and type(self.report['Commands']) is list and self.report['Commands']
                     and all(row['Status'] == 'PASS' for row in self.report['Commands']), 'complete reference capture build required')
                self.report['Status'] = 'PASS'
            except BaseException as failure:
                self.report['Status'] = 'FAIL'
                if self.report['Error'] is None:
                    self.report['Error'] = type(failure).__name__ + ': ' + str(failure)
            self.report['ClosingFilesVerified'] = len(self.seed.closure.hashes)
            try:
                api.save(self.output / 'inputs.json', dict(Files=self.inputs,
                    Watched=[dict(Path=str(path), Sha256=value) for path, value in sorted(self.seed.closure.hashes.items())]))
                expected = self.write_seal()
                self.close_inputs()
                actual = {name: sha(path.read_bytes()) for name, path in api.files_under(self.output).items() if name != 'artifacts.json'}
                api.same(actual, expected, 'late reference artifact membership/hash drift')
                need(sha((self.output / 'artifacts.json').read_bytes()) == self.manifest_hash, 'late reference manifest drift')
                return self.report['Status'] == 'PASS'
            except BaseException as failure:
                self.report.update(Status='FAIL', InputClosureVerified=False, OutputSealVerified=False,
                    Error=(self.report.get('Error') or '') + '; sealing: ' + type(failure).__name__ + ': ' + str(failure))
                try:
                    self.write_seal()
                except BaseException as final_error:
                    self.report.update(OutputSealVerified=False, SealError=str(final_error))
                    try:
                        api.save(self.output / 'results.json', self.report)
                    except BaseException:
                        pass
                return False

    return Probe


def main(argv=None):
    need(not sys.flags.optimize, 'unoptimized interpreter required')
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('reference-build', 'reference-receipt-sha256', 'reference-artifacts-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    common_bytes = COMMON.read_bytes()
    need(sha(common_bytes) == COMMON_SHA, 'fixed capture-plumbing source cohort required')
    api = load('cm3_reference_lto_shared_capture', COMMON, common_bytes)
    source = api.regular(HERE / 'admission.py')
    admission_bytes = source.read_bytes()
    admission = load('cm3_reference_lto_admission', source, admission_bytes)
    seed = admission.Seed(api, args)
    seed.closure.read(COMMON, COMMON_SHA)
    seed.closure.read(Path(__file__).resolve())
    seed.closure.read(source, sha(admission_bytes))
    seed.closure.close()
    seed.output.mkdir(parents=True)
    probe, error = probe_type(api)(seed, args), None
    try:
        probe.build()
    except BaseException as failure:
        error = failure
    passed = probe.finish(error)
    print(probe.report['Status'], probe.report.get('Error') or '', str(seed.output))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
