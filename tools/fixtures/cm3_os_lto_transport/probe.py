"""Fresh native/reference CM3 Os-lto transport capture, never qualification."""

import argparse
import hashlib
import importlib.util
from pathlib import Path
import re
import sys
from types import SimpleNamespace


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
COMMON = HERE.with_name('cm3_lto_transport') / 'probe.py'
COMMON_SHA = 'F2D4CA9F1FC1F7FAE07F275913F7DFC688BFD8570AEE32DE2144EE1EA187F626'
REFERENCE = HERE.with_name('cm3_reference_lto_transport') / 'probe.py'
REFERENCE_SHA = '1D1FDC0D644123FEF1E182107A8062A0BA9BCCB385DA0C2D13BDFD741290F2C3'
ADMISSION = REFERENCE.with_name('admission.py')
ADMISSION_SHA = '27C192C12E30BD4F1A872D6A8586B85C303AF6D6873A85A26238BE7DD4962ECC'


def need(condition, message):
    if not condition:
        raise ValueError('cm3-os-lto-probe: ' + message)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def _os_flags(base):
    need(type(base) is list and all(type(flag) is str for flag in base), 'literal ordered flags')
    need([flag for flag in base if flag.startswith('-O')] == ['-O2'], 'sole original -O2 required')
    return ['-Os' if flag == '-O2' else flag for flag in base]


def startup_flags(base):
    need(type(base) is list and all(type(flag) is str for flag in base), 'literal original startup flags')
    need(not any(flag.startswith(('-flto', '-fno-lto', '-ffat-lto', '-fno-fat-lto')) for flag in base),
         'original inputs must not override LTO')
    return _os_flags(base)


def mode_flags(base):
    return [*startup_flags(base), '-flto', '-fno-fat-lto-objects']


def link_flags(api, artifact, objects, script, output, map, emit):
    """Transform only the optimization flag of the frozen exact link recipe."""
    return _os_flags(api.link_flags(artifact, objects, script, output, map, emit))


def load(name, path, expected):
    data = path.read_bytes()
    need(sha(data) == expected, 'fixed helper source: ' + str(path))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def seed_args(args):
    need(type(args.side) is str and args.side in ('native', 'reference'), 'exact capture side')
    return SimpleNamespace(**{args.side + '_build': args.seed_build,
        args.side + '_receipt_sha256': args.seed_receipt_sha256,
        args.side + '_artifacts_sha256': args.seed_artifacts_sha256, 'output_dir': args.output_dir})


def probe_type(api, side, reference_api=None):
    need(type(side) is str and side in ('native', 'reference'), 'exact capture side')
    need(side == 'native' or reference_api is not None, 'fixed reference capture plumbing required')
    base = api.Probe if side == 'native' else reference_api.probe_type(api)
    count, startup = (9, 8) if side == 'native' else (4, 3)

    class Probe(base):
        def __init__(self, seed, args):
            super().__init__(seed, args)
            self.report.update(Mode='Os-lto', SeedMode='O2', SeedSide=side.capitalize(),
                Scope=('NATIVE_CM3_OS_LTO_CAPTURE_FEASIBILITY_ONLY' if side == 'native'
                       else 'PINNED_REFERENCE_CM3_OS_LTO_CAPTURE_FEASIBILITY_ONLY'),
                OptimizationTransform=dict(Original='-O2', Captured='-Os', OtherSeedFlagsUnchanged=True),
                Qualification=False, FullABIProof=False, SourceIRProof=False,
                SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False,
                CanonicalProtocolValidated=False, FinalRootRelocationProof=False, FinalReferenceParity=False,
                PolicyEquivalence=False, CompleteObjectProof=False, CpuExecution=False,
                BoardExecution=False, GlobalFreezeQualified=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0)

        def compile(self):
            need(len(self.seed.sources) == count, 'exact admitted native/reference source count')
            directory = self.output / 'objects'
            directory.mkdir()
            for index, row in enumerate(self.seed.sources):
                source = api.regular(row['Source'])
                self.seed.closure.read(source, row['SourceSha256'])
                flags = startup_flags(row['CompileFlags']) if index == startup else mode_flags(row['CompileFlags'])
                obj = directory / ('%02d-' % index + source.stem + '.o')
                dependency = obj.with_suffix('.d')
                result = dict(Source=str(source), SourceSha256=row['SourceSha256'], CompileFlags=flags,
                    SeedCompileFlags=list(row['CompileFlags']), Object=str(obj), DependencyFile=str(dependency),
                    SlimIR=index != startup)
                self.report['Sources'].append(result)
                self.command([self.tools['gcc'], *flags, '-MD', '-MF', dependency,
                    '-MT', 'pilot-source-' + str(index), '-c', source, '-o', obj], 'compile ' + source.name)
                header = api.require_elf32le(api.regular(obj).read_bytes())
                self.seed.closure.read(source, row['SourceSha256'])
                expected = {api.regular(item['Path']) for item in row['Dependencies']}
                expected = {self.tool_root / path.relative_to(self.seed.tool_root)
                            if path.is_relative_to(self.seed.tool_root) else path for path in expected}
                actual = set(self.seed.native.read_dependencies(dependency))
                need(actual == expected, 'actual compile dependencies differ from admitted O2 seed')
                result['ActualCompileDependencies'] = [dict(Path=str(path), Sha256=sha(path.read_bytes()))
                                                       for path in sorted(actual)]
                for path in actual:
                    if path.is_relative_to(self.tool_root):
                        need(sha(path.read_bytes()) == self.tool_hashes[path], 'relocated system-header drift')
                    else:
                        self.seed.closure.read(path, self.seed.closure.hashes[path])
                text = self.inspect(obj)
                need(re.search(r'^\s*Type:\s+REL\b', text, re.MULTILINE)
                     and re.search(r'^\s*Machine:\s+ARM\s*$', text, re.MULTILINE), 'actual ARM ET_REL input')
                sections = api.section_records(text)
                api.same([section['Index'] for section in sections], list(range(header['SectionCount'])),
                         'all actual input sections must be accounted')
                if index != startup:
                    need(any(section['Name'].startswith('.gnu.lto_') for section in sections)
                         and not any('X' in section['Flags'] and section['Size'] for section in sections),
                         'genuine slim IR without executable fat fallback')
                    self.report['SlimIRObjects'] += 1
                else:
                    need(not any(section['Name'].startswith('.gnu.lto_') for section in sections),
                         'startup must remain native, not LTO')
                result.update(ObjectSha256=sha(obj.read_bytes()), ELFHeader=header, Sections=sections,
                              CompileDependenciesVerified=True)
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
                    command = self.command([self.tools['gcc'], *link_flags(api, self.seed.artifact,
                        self.objects, self.seed.script, image, link_map, emit)], 'link ' + kind, cwd=directory)
                finally:
                    self.verify_objects('after-link-' + kind)
                machine = api.require_saved_machine_name(directory / 'image.elf.ltrans0.ltrans.o', image)
                need({path for path in directory.iterdir()
                      if re.fullmatch(r'image[.]elf[.]ltrans[0-9]+[.]ltrans[.]o', path.name)} == {machine},
                     'exactly one actual saved machine partition per link')
                machine_bytes = api.regular(machine).read_bytes()
                header = api.require_elf32le(machine_bytes)
                text = self.inspect(machine)
                need(re.search(r'^\s*Type:\s+REL\b', text, re.MULTILINE)
                     and re.search(r'^\s*Machine:\s+ARM\s*$', text, re.MULTILINE), 'actual ARM saved machine ET_REL')
                sections = api.section_records(text)
                api.same([row['Index'] for row in sections], list(range(header['SectionCount'])),
                         'all saved-machine sections must be accounted')
                need(not any(row['Name'].startswith('.gnu.lto_') for row in sections)
                     and any('X' in row['Flags'] and row['Size'] for row in sections),
                     'saved machine must contain real code, not GIMPLE')
                symbols = api.symbol_records(text, sections) if side == 'native' else reference_api.symbol_records(text, sections)
                symbols = [dict(row, Artifact=str(machine), ArtifactSha256=sha(machine_bytes)) for row in symbols]
                self.inspect(image)
                final_header = api.require_elf32le(api.regular(image).read_bytes(), 'EXEC')
                need(api.regular(link_map).stat().st_size > 0, 'actual retained link map')
                for suffix in ('.res', '.ltrans.out', '.ltrans0.o', '.ltrans0.ltrans.s'):
                    need(api.regular(Path(str(image) + suffix)).stat().st_size > 0, 'actual LTO transport record: ' + suffix)
                observed = self.trace_identities(command.stderr)
                captured = {name: sha(path.read_bytes()) for name, path in api.files_under(directory).items()}
                self.seed.closure.tree(directory, captured)
                self.report['Links'].append(dict(Kind=kind, Path=str(image), Sha256=sha(image.read_bytes()),
                    Map=str(link_map), MapSha256=sha(link_map.read_bytes()), Machine=str(machine),
                    MachineSha256=sha(machine_bytes), MachineHeader=header, FinalHeader=final_header,
                    MachineSections=sections, MachineSymbols=symbols, VerboseObservedTools=observed,
                    EntireDirectoryArtifacts=captured, MachineOwner='ACTUAL-LTRANS-OBJECT; NOT ORIGINAL PORT-TU',
                    OrdinarySymbolPredicatesApplied=False))
                self.report['FinalExecutableLinks'] += 1
                self.report['SavedMachineObjects'] += 1
            self.verify_objects('closing')
            self.compare_twins()
            if side == 'reference':
                self.report['ReferenceBuilt'] = True
            self.complete = True

    return Probe


def main(argv=None):
    need(not sys.flags.optimize and __debug__, 'unoptimized interpreter required')
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--side', choices=('native', 'reference'), required=True)
    for name in ('seed-build', 'seed-receipt-sha256', 'seed-artifacts-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    translated = seed_args(args)
    api = load('cm3_os_lto_common', COMMON, COMMON_SHA)
    reference = None
    dependencies = [(COMMON, COMMON_SHA)]
    if args.side == 'native':
        seed = api.Seed(translated)
    else:
        reference = load('cm3_os_lto_reference', REFERENCE, REFERENCE_SHA)
        admission = load('cm3_os_lto_reference_admission', ADMISSION, ADMISSION_SHA)
        seed = admission.Seed(api, translated)
        dependencies.extend(((REFERENCE, REFERENCE_SHA), (ADMISSION, ADMISSION_SHA)))
    for path, digest in dependencies:
        seed.closure.read(path, digest)
    script = Path(__file__).resolve()
    seed.closure.read(script)
    seed.closure.close()
    seed.output.mkdir(parents=True)
    probe = probe_type(api, args.side, reference)(seed, translated)
    probe.report['CaptureProducer'] = dict(Path=str(script), Sha256=seed.closure.hashes[script])
    probe.report['FrozenCaptureHelpers'] = [dict(Path=str(path), Sha256=digest) for path, digest in dependencies]
    error = None
    try:
        probe.build()
    except BaseException as failure:
        error = failure
    passed = probe.finish(error)
    print(probe.report['Status'], probe.report.get('Error') or '', str(seed.output))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
