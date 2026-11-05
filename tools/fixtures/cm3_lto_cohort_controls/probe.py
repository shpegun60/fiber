"""Capture CM3 O2-lto policy-cohort links; no final or ABI qualification."""

import argparse
import hashlib
import importlib.util
from pathlib import Path
import sys


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ENGINE = HERE.with_name('cm3_lto_link_controls') / 'probe.py'
ENGINE_SHA = 'CE2C86F8FB1A391977ED385636108CC24307F495D22FAE495FBD2B449DA9F99F'
IDENTITY = HERE / 'identity.py'
IDENTITY_SHA = '360485D634AC85AF37B78AAB45E622E568063CDE32F45250037F4C718F13732B'
POLICY_SOURCES = ((3, 'runtime'), (4, 'boot'), (5, 'exception'), (6, 'expectation'))


def need(condition, message):
    if not condition:
        raise ValueError('cm3-lto-cohort-controls: ' + message)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def load(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def threshold32_flags(flags):
    need(type(flags) is list and all(type(flag) is str for flag in flags), 'literal original compile flags')
    old, new = '-DFIBER_SCHEDULER_BASEPRI=16', '-DFIBER_SCHEDULER_BASEPRI=32'
    need([flag for flag in flags if 'FIBER_SCHEDULER_BASEPRI' in flag] == [old],
         'one original raw BASEPRI16 definition and no counterdefinition')
    need(not any('FIBER_PORT_SCHEDULER_BASEPRI' in flag for flag in flags),
         'no separate canonical BASEPRI counterdefinition')
    need([flag for flag in flags if flag.startswith('-O')] == ['-O2']
         and flags[-2:] == ['-flto', '-fno-fat-lto-objects'], 'original O2 slim recipe')
    return [new if flag == old else flag for flag in flags]


_ENGINE_BYTES = ENGINE.read_bytes()
need(sha(_ENGINE_BYTES) == ENGINE_SHA, 'frozen capture engine')
_engine = load('cm3_cohort_capture_engine', ENGINE, _ENGINE_BYTES)


class Probe(_engine.Probe):
    def __init__(self, args):
        self.sha = sha
        parent_data = _engine.PARENT.read_bytes()
        need(sha(parent_data) == _engine.PARENT_SHA, 'fixed native capture admission')
        identity_data = IDENTITY.read_bytes()
        need(sha(identity_data) == IDENTITY_SHA, 'fixed policy identity grammar')
        parent = load('cm3_cohort_capture_admission', _engine.PARENT, parent_data)
        self.admission = parent.Witness(args)
        a = self.admission
        self.api, self.output, self.watch = a.api, a.output, a.watch
        self.capture = a.authority.result
        for path, expected in ((ENGINE, ENGINE_SHA), (_engine.PARENT, _engine.PARENT_SHA),
                               (IDENTITY, IDENTITY_SHA), (Path(__file__).resolve(), None)):
            a.buffers[path] = self.watch.read(path, expected)
            a.identities[path] = a.identity(path)
        self.identity = load('cm3_cohort_policy_identity', IDENTITY, a.buffers[IDENTITY])
        self.report = dict(Status='FAIL', Scope='CM3_O2_LTO_POLICY_COHORT_CONTROL_CAPTURE_ONLY', Error=None,
            Profile='CM3', Mode='O2-lto', Linkage='direct', CaptureBuild=str(a.root),
            CaptureReceiptSha256=args.capture_receipt_sha256, CaptureArtifactsSha256=args.capture_artifacts_sha256,
            Engine=dict(Path=str(ENGINE), Sha256=ENGINE_SHA), IdentityHelper=dict(Path=str(IDENTITY), Sha256=IDENTITY_SHA),
            Commands=[], AddedSources=[], Links=[], NegativeControls=[], Interpreter=a.report['Interpreter'],
            OriginalTranslationUnits=9, OriginalSlimIRObjects=8, PositiveTranslationUnits=9,
            PositiveSlimIRObjects=8, PositiveStartupObjects=1, RecompiledTranslationUnits=4,
            Thresholds=[16, 32], CompleteLinkControlsQualified=False, PolicyCohortControlsQualified=False,
            StorageMismatchProven=False, RuntimeABIVersionMismatchProven=False,
            FinalLinkContractValidated=False, FinalRootRelocationProof=False, FinalReferenceParity=False,
            FullABIProof=False, SourceIRProof=False, SourceToMachineSemanticProof=False,
            OriginalTranslationUnitOwnership=False, CanonicalProtocolValidated=False,
            InstructionEquivalence=False, PolicyEquivalence=False, CompleteObjectProof=False,
            ArchiveExtraction=False, KernelRuntimeProof=False, Qualification=False,
            CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
            RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
        self.admission.close()

    def compile(self):
        self.recompiled = {}
        directory = self.output / 'objects32'
        directory.mkdir()
        for index, role in POLICY_SOURCES:
            original_row = self.capture['Sources'][index]
            source = Path(original_row['Source'])
            need(source in self.watch.hashes, 'admitted captured source path')
            data = self.watch.read(source, original_row['SourceSha256'])
            copy = self.admission.copy('recompiled-sources/%02d-%s' % (index, source.name), data)
            flags = threshold32_flags(original_row['CompileFlags'])
            obj = directory / ('%02d-%s.o' % (index, source.stem))
            dependency = obj.with_suffix('.d')
            self.command([self.tools.tools['gcc'], *flags, '-MD', '-MF', dependency,
                '-MT', 'pilot-source-' + str(index), '-c', source, '-o', obj],
                'compile policy32 ' + role)
            self.pin_generated(obj)
            self.pin_generated(dependency)
            deps = [Path(path) for path in self.native.read_dependencies(dependency)]
            need(source in deps and all(path in self.watch.hashes for path in deps),
                 'only admitted actual compile dependencies')
            records = [dict(Path=str(path), Sha256=self.watch.hashes[path]) for path in deps]
            self.api.same(records, original_row['ActualCompileDependencies'],
                          'threshold-only compilation must preserve exact dependency membership/hashes')
            for path in deps:
                self.watch.read(path)
            text = self.inspect(obj)
            self.api.require_elf32le(self.watch.read(obj))
            sections = self.api.section_records(text)
            need(any(row['Name'].startswith('.gnu.lto_') for row in sections)
                 and not any(row['Size'] and 'X' in row['Flags'] for row in sections),
                 'genuine slim IR without executable fat fallback')
            row = dict(SourceIndex=index, Role=role, Source=str(source), Original=str(source),
                CapturedSource=str(copy), SourceSha256=sha(data), Object=str(obj),
                ObjectSha256=self.watch.hashes[obj], CompileFlags=flags,
                OriginalCompileFlags=list(original_row['CompileFlags']), OriginalBasepri=16, Basepri=32,
                SlimIR=True, CompileDependenciesVerified=True, ActualCompileDependencies=records,
                DependencyFile=str(dependency), Sections=sections)
            self.report['AddedSources'].append(row)
            self.recompiled[index] = obj
        self.variants = {16: list(self.objects), 32: list(self.objects)}
        for index, _ in POLICY_SOURCES:
            self.variants[32][index] = self.recompiled[index]
        runtime16 = Path(str(self.objects[3]) + '.nm')
        runtime32 = Path(str(self.recompiled[3]) + '.nm')
        need(runtime16 in self.watch.hashes and runtime32 in self.watch.hashes,
             'admitted original and actual recompiled plugin-NM buffers')
        self.identities = self.identity.cohort_pair(self.watch.read(runtime16).decode('ascii'),
                                                  self.watch.read(runtime32).decode('ascii'))
        self.report['CohortIdentities'] = self.identities
        self.report['IdentityInputs'] = [dict(Basepri=value, Path=str(path), Sha256=self.watch.hashes[path])
            for value, path in ((16, runtime16), (32, runtime32))]
        self.report['Variants'] = [dict(Basepri=value, Objects=[dict(SourceIndex=i, Path=str(path),
            Sha256=self.watch.hashes[path]) for i, path in enumerate(self.variants[value])]) for value in (16, 32)]

    def _positive(self, threshold, kind, emit):
        directory = self.output / ('positive-%d' % threshold) / kind
        directory.mkdir(parents=True)
        objects = self.variants[threshold]
        image, link_map = directory / 'image.elf', directory / 'image.map'
        flags = self.api.link_flags(dict(compile_flags=list(self.api.TARGET_FLAGS)), objects,
                                    self.script, image, link_map, emit)
        need(flags.count('-v') == 1, 'positive verbose worker trace retained')
        run = self.command([self.tools.tools['gcc'], *flags], 'link cohort%d %s' % (threshold, kind), cwd=directory)
        observed = self.tools.trace_identities(run.stdout + run.stderr)
        machine = self.api.require_saved_machine_name(directory / 'image.elf.ltrans0.ltrans.o', image)
        resolution = Path(str(image) + '.res')
        need(resolution.is_file(), 'actual positive plugin resolution')
        for path in (image, machine, link_map, resolution):
            self.pin_generated(path)
        self.api.require_elf32le(self.watch.read(machine))
        self.api.require_elf32le(self.watch.read(image), 'EXEC')
        self.inspect(machine)
        self.inspect(image)
        self.report['Links'].append(dict(Basepri=threshold, Kind=kind, Path=str(image),
            Sha256=self.watch.hashes[image], Machine=str(machine), MachineSha256=self.watch.hashes[machine],
            Map=str(link_map), MapSha256=self.watch.hashes[link_map], Resolution=str(resolution),
            ResolutionSha256=self.watch.hashes[resolution], Objects=[str(path) for path in objects],
            VerboseObservedTools=observed, VerboseTrace=True, TranslationUnits=9, SlimIRObjects=8, StartupObjects=1))

    def _negative(self, threshold, index, role):
        foreign = 32 if threshold == 16 else 16
        name = 'base%d-swap-%s-to%d' % (threshold, role, foreign)
        directory = self.output / ('negative-' + name)
        directory.mkdir()
        objects = list(self.variants[threshold])
        objects[index] = self.variants[foreign][index]
        expected_threshold = threshold if index == 3 else foreign
        expected_symbol = self.identities['Private%d' % expected_threshold]
        image, link_map = directory / 'image.elf', directory / 'image.map'
        full_flags = self.api.link_flags(dict(compile_flags=list(self.api.TARGET_FLAGS)), objects,
                                         self.script, image, link_map, False)
        need(full_flags.count('-v') == 1, 'exact one negative verbosity removal')
        flags = [flag for flag in full_flags if flag != '-v']
        label = 'link intended cohort mismatch ' + name
        caught = False
        try:
            self.command([self.tools.tools['gcc'], *flags], label, cwd=directory)
        except ValueError as error:
            if str(error) != 'cm3-lto-probe: command failed/timeout: ' + label:
                raise
            caught = True
        command_index = len(self.tools.report['Commands']) - 1
        record = self.tools.report['Commands'][command_index]
        need(caught and record['Status'] == 'FAIL' and type(record['Exit']) is int and record['Exit'] != 0
             and record['TimedOut'] is False and not image.exists(), 'intended missing-cohort link failure')
        stderr = self.output / ('command-%04d.stderr' % command_index)
        diagnostic = self.identity.require_mismatch(self.watch.read(stderr).decode('ascii'), expected_symbol)
        self.report['NegativeControls'].append(dict(Name=name, Basepri=threshold, SwappedSourceIndex=index,
            SwappedRole=role, ForeignBasepri=foreign, ExpectedMissingSymbol=expected_symbol,
            Status='PASS', CommandIndex=command_index, CommandStatus='FAIL', Exit=record['Exit'],
            Objects=[str(path) for path in objects], TranslationUnits=9, SlimIRObjects=8, StartupObjects=1,
            VerboseTrace=False, RemovedLinkFlags=['-v'], FullVerboseLinkFlags=full_flags, LinkFlags=flags,
            FinalImageAbsent=True, DiagnosticSha256=self.watch.hashes[stderr], Diagnostic=diagnostic))

    def links(self):
        for threshold in (16, 32):
            for kind, emit in (('ordinary', False), ('emit-relocs', True)):
                self._positive(threshold, kind, emit)
        for threshold in (16, 32):
            for index, role in POLICY_SOURCES:
                self._negative(threshold, index, role)
        need(len(self.report['AddedSources']) == 4 and len(self.report['Links']) == 4
             and len(self.report['NegativeControls']) == 8, 'complete four-source/four-positive/eight-negative batch')
        commands = self.report['Commands']
        need(len(commands) == 52 and sum(row['Status'] == 'PASS' for row in commands) == 44
             and sum(row['Status'] == 'FAIL' for row in commands) == 8,
             'exact executed capture command count/outcomes')
        self.pin_generated(self.output / 'commands.json')
        self.api.same(self.watch.structured(self.output / 'commands.json'), commands, 'complete executed command catalog')

    def run(self):
        self.output.mkdir(parents=True)
        try:
            self.prepare()
            self.compile()
            self.links()
            self.admission.close()
            self.report.update(Status='CM3-LTO-COHORT-CONTROL-CAPTURE-PASS-NOT-QUALIFIED', InputClosureVerified=True,
                InputHashes={str(path): value for path, value in sorted(self.watch.hashes.items())})
            self.seal()
        except BaseException as error:
            self.report.update(Status='FAIL', Error=type(error).__name__ + ': ' + str(error), InputClosureVerified=False)
            try:
                self.seal()
            except BaseException as closing:
                self.report['SealError'] = str(closing)
                self.api.save(self.output / 'results.json', self.report)
                self.api.save(self.output / 'artifacts.json', dict(Artifacts={
                    name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items()
                    if name != 'artifacts.json'}))
        return self.report['Status'] != 'FAIL'


def main(argv=None):
    need(not sys.flags.optimize, 'unoptimized interpreter required')
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('capture-build', 'capture-receipt-sha256', 'capture-artifacts-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    probe = Probe(parser.parse_args(argv))
    passed = probe.run()
    print(probe.report['Status'], probe.report.get('Error') or '', str(probe.output))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
