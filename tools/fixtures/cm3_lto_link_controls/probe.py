"""Capture fresh CM3 LTO override/conflict links; not their final qualification."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
from types import SimpleNamespace
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
PARENT = HERE.with_name('cm3_lto_link_contract') / 'witness.py'
PARENT_SHA = '599D384B53F45093F01949A4E95A9DF8A15BC4EABE9EA5E12A1C2E7138F3297E'
FIXTURES = ('panic_override.c', 'duplicate_svc.c', 'duplicate_pendsv.c')


def need(condition, message):
    if not condition:
        raise ValueError('cm3-lto-link-controls: ' + message)


def load(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


class Probe:
    def __init__(self, args):
        import hashlib
        self.sha = lambda data: hashlib.sha256(data).hexdigest().upper()
        data = PARENT.read_bytes()
        need(self.sha(data) == PARENT_SHA, 'fixed native capture admission required')
        parent = load('cm3_controls_admission', PARENT, data)
        self.admission = parent.Witness(args)
        a = self.admission
        self.api, self.output, self.watch = a.api, a.output, a.watch
        self.capture = a.authority.result
        for path in (PARENT, Path(__file__).resolve(), *(HERE / name for name in FIXTURES)):
            a.buffers[path] = self.watch.read(path)
            a.identities[path] = a.identity(path)
        self.report = dict(Status='FAIL', Scope='CM3_O2_LTO_FRESH_LINK_CONTROL_CAPTURE_ONLY', Error=None,
            Profile='CM3', Mode='O2-lto', Linkage='direct', CaptureBuild=str(a.root),
            CaptureReceiptSha256=args.capture_receipt_sha256, CaptureArtifactsSha256=args.capture_artifacts_sha256,
            Commands=[], AddedSources=[], Links=[], NegativeControls=[], Interpreter=a.report['Interpreter'],
            OriginalTranslationUnits=9, OriginalSlimIRObjects=8, PositiveTranslationUnits=10,
            PositiveSlimIRObjects=9, PositiveStartupObjects=1, CompleteLinkControlsQualified=False,
            PanicOverrideQualified=False, DuplicateHandlerControlsQualified=False,
            FinalLinkContractValidated=False, FinalRootRelocationProof=False, FinalReferenceParity=False,
            FullABIProof=False, SourceToMachineSemanticProof=False, ArchiveExtraction=False,
            CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False, RequiredCellsSatisfied=0)
        self.admission.close()

    def pin_generated(self, path):
        path = Path(path)
        need(path.is_relative_to(self.output), 'generated authority outside new output')
        self.watch.read(path)
        identity = self.admission.identity(path)
        need(path not in self.admission.identities or self.admission.identities[path] == identity,
             'generated physical identity changed')
        self.admission.identities[path] = identity
        return self.watch.hashes[path]

    def command(self, argv, label, *, cwd=None):
        self.admission.close()
        index = len(self.tools.report['Commands'])
        try:
            return self.tools.command(argv, label, cwd=cwd)
        finally:
            self.report['Commands'] = self.tools.report['Commands']
            if len(self.report['Commands']) == index + 1:
                record = self.report['Commands'][index]
                path = self.output / ('command-%04d.json' % index)
                self.pin_generated(path)
                self.api.same(self.watch.structured(path), record, 'actual command-record binding')
                for suffix in ('.stdout', '.stderr'):
                    stream = path.with_suffix(suffix)
                    need(record['Exit'] is None or stream.is_file(), 'completed command streams required')
                    if stream.is_file():
                        self.pin_generated(stream)
            self.admission.close()

    def prepare(self):
        a = self.admission
        base = a.authority
        loader = load('cm3_controls_loader', a.base.LOADER, a.buffers[a.base.LOADER])
        graph = loader.FrozenSources(a.buffers)
        seed = Path(self.capture['SeedBuild'])
        with graph.active():
            process = graph.load('cm3_controls_process', seed / 'source/tools/fixtures/freeze_cohorts/process_runner.py')
            self.native = graph.load('cm3_controls_dependency_parser', seed / 'source/tools/fixtures/classic_final_image/run.py')
        self.report['ExecutedSourceBuffers'] = graph.executed
        self.report['CapturedSources'] = [dict(Original=str(path), Sha256=self.sha(data),
            Captured=str(a.copy('input-sources/%04d-%s' % (i, path.name), data)))
            for i, (path, data) in enumerate(sorted(a.buffers.items()))]
        self.tools = self.api.Probe(SimpleNamespace(process=process, output=self.output), SimpleNamespace())
        self.tools.tool_root = Path(self.capture['CapturedCompiler']).parent.parent
        self.tools.tool_hashes = {path: self.watch.hashes[path] for path in self.api.files_under(self.tools.tool_root).values()}
        self.tools.tools = {name: self.tools.tool_root / 'bin' / ('arm-none-eabi-' + name + '.exe')
                            for name in ('gcc', 'readelf', 'objdump', 'nm')}
        self.tools.plugin = Path(self.capture['LTOPlugin']['Path'])
        self.tools.workers = {}
        for name in ('collect2', 'lto-wrapper', 'lto1', 'as'):
            paths = [path for path in self.tools.tool_hashes if path.name == name + '.exe']
            need(len(paths) == 1, 'unambiguous captured worker: ' + name)
            self.tools.workers[name] = paths[0]
        self.tools.environment = self.watch.structured(base.root / 'environment.json')
        temporary = self.output / 'tmp'
        temporary.mkdir()
        self.tools.environment.update(TEMP=str(temporary), TMP=str(temporary))
        self.api.save(self.output / 'environment.json', self.tools.environment)
        self.pin_generated(self.output / 'environment.json')
        self.api.same(self.watch.structured(self.output / 'environment.json'), self.tools.environment,
                      'actual compiler process environment binding')
        rows = self.capture['Sources']
        need(len(rows) == 9 and all(row['SlimIR'] is (i != 8) for i, row in enumerate(rows)),
             'eight original slim IR plus explicit non-LTO startup')
        self.objects = [Path(row['Object']) for row in rows]
        for row in rows:
            self.watch.read(row['Object'], row['ObjectSha256'])
        self.startup = self.objects[8]
        self.script = seed / 'source/tools/fixtures/classic_final_image/link.ld'
        need(self.script in self.watch.hashes, 'captured original linker script')
        self.flags = rows[7]['CompileFlags']
        need([flag for flag in self.flags if flag.startswith('-O')] == ['-O2']
             and self.flags[-2:] == ['-flto', '-fno-fat-lto-objects'], 'fixed O2 slim compile recipe')
        self.tools.verify_tools()

    def inspect(self, path):
        result = None
        for name, flags, suffix in (
            ('readelf', ['-hSWsrA', '-lW'], '.readelf'),
            ('objdump', ['-drwC', '-Mreg-names-std'], '.dis'),
            ('nm', ['--plugin', str(self.tools.plugin), '-P', '-S', '--defined-only'], '.nm')):
            run = self.command([self.tools.tools[name], *flags, path], 'inspect ' + path.name + suffix)
            target = Path(str(path) + suffix)
            target.write_bytes(run.stdout)
            self.pin_generated(target)
            if name == 'readelf':
                result = run.stdout.decode('utf-8')
        return result

    def compile(self):
        self.added = {}
        directory = self.output / 'objects'
        directory.mkdir()
        for index, name in enumerate(FIXTURES):
            original = HERE / name
            data = self.watch.read(original)
            source = self.admission.copy('added-sources/' + name, data)
            obj = directory / (source.stem + '.o')
            dependency = obj.with_suffix('.d')
            self.command([self.tools.tools['gcc'], *self.flags, '-MD', '-MF', dependency,
                '-MT', 'pilot-source-' + str(index), '-c', source, '-o', obj], 'compile ' + name)
            self.pin_generated(obj)
            self.pin_generated(dependency)
            deps = [Path(path) for path in self.native.read_dependencies(dependency)]
            need(source in deps and all(path in self.watch.hashes for path in deps), 'only admitted actual compile dependencies')
            records = []
            for path in deps:
                self.watch.read(path)
                records.append(dict(Path=str(path), Sha256=self.watch.hashes[path]))
            text = self.inspect(obj)
            self.api.require_elf32le(obj.read_bytes())
            sections = self.api.section_records(text)
            need(any(row['Name'].startswith('.gnu.lto_') for row in sections)
                 and not any(row['Size'] and 'X' in row['Flags'] for row in sections), 'actual added slim IR, no machine fallback')
            row = dict(Source=str(source), Original=str(original), SourceSha256=self.sha(data), Object=str(obj),
                ObjectSha256=self.sha(obj.read_bytes()), CompileFlags=list(self.flags), SlimIR=True,
                ActualCompileDependencies=records, DependencyFile=str(dependency), Sections=sections)
            self.report['AddedSources'].append(row)
            self.added[name] = obj
            self.watch.read(obj, row['ObjectSha256'])
            self.admission.identities[obj] = self.admission.identity(obj)

    def links(self):
        objects = [*self.objects[:8], self.added['panic_override.c'], self.startup]
        for kind, emit in (('ordinary', False), ('emit-relocs', True)):
            directory = self.output / kind
            directory.mkdir()
            image, link_map = directory / 'image.elf', directory / 'image.map'
            flags = self.api.link_flags(dict(compile_flags=list(self.api.TARGET_FLAGS)), objects, self.script, image, link_map, emit)
            run = self.command([self.tools.tools['gcc'], *flags], 'link override ' + kind, cwd=directory)
            observed = self.tools.trace_identities(run.stdout + run.stderr)
            machine = self.api.require_saved_machine_name(directory / 'image.elf.ltrans0.ltrans.o', image)
            resolution = Path(str(image) + '.res')
            need(resolution.is_file(), 'actual LTO plugin resolution file')
            for path in (image, machine, link_map, resolution):
                self.pin_generated(path)
            self.api.require_elf32le(machine.read_bytes())
            self.api.require_elf32le(image.read_bytes(), 'EXEC')
            self.inspect(machine)
            self.inspect(image)
            self.report['Links'].append(dict(Kind=kind, Path=str(image), Sha256=self.sha(image.read_bytes()),
                Machine=str(machine), MachineSha256=self.sha(machine.read_bytes()), Map=str(link_map),
                MapSha256=self.sha(link_map.read_bytes()), Resolution=str(resolution),
                ResolutionSha256=self.sha(resolution.read_bytes()), Objects=[str(path) for path in objects],
                VerboseObservedTools=observed, TranslationUnits=10, SlimIRObjects=9, StartupObjects=1))
        for name, symbol in (('duplicate_svc.c', 'SVC_Handler'), ('duplicate_pendsv.c', 'PendSV_Handler')):
            directory = self.output / name.removesuffix('.c')
            directory.mkdir()
            image, link_map = directory / 'image.elf', directory / 'image.map'
            objects = [*self.objects[:8], self.added[name], self.startup]
            flags = self.api.link_flags(dict(compile_flags=list(self.api.TARGET_FLAGS)), objects, self.script, image, link_map, False)
            caught = False
            try:
                self.command([self.tools.tools['gcc'], *flags], 'link intended conflict ' + symbol, cwd=directory)
            except ValueError as error:
                expected = 'cm3-lto-probe: command failed/timeout: link intended conflict ' + symbol
                if str(error) != expected:
                    raise
                caught = True
            record = self.tools.report['Commands'][-1]
            index = len(self.tools.report['Commands']) - 1
            diagnostics = (self.output / ('command-%04d.stderr' % index)).read_bytes().decode('utf-8')
            need(caught and record['Status'] == 'FAIL' and type(record['Exit']) is int and record['Exit'] != 0
                 and record['TimedOut'] is False and not image.exists()
                 and re.search(r'multiple definition of [`\'" ]*' + re.escape(symbol) + r"\b", diagnostics) is not None,
                 'intended duplicate strong handler failure: ' + symbol)
            self.report['NegativeControls'].append(dict(Name=name, Symbol=symbol, Status='PASS', CommandIndex=index,
                CommandStatus='FAIL', Exit=record['Exit'], IntendedDiagnostic=True, FinalImageAbsent=True,
                DiagnosticSha256=self.watch.hashes[self.output / ('command-%04d.stderr' % index)]))
        self.pin_generated(self.output / 'commands.json')
        self.api.same(self.watch.structured(self.output / 'commands.json'), self.report['Commands'],
                      'complete executed command catalog')

    def seal(self):
        self.api.save(self.output / 'results.json', self.report)
        artifacts = {name: self.sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items()
                     if name != 'artifacts.json'}
        manifest = dict(Artifacts=artifacts)
        self.api.save(self.output / 'artifacts.json', manifest)
        manifest_bytes = (self.output / 'artifacts.json').read_bytes()
        self.api.same(json.loads(manifest_bytes, object_pairs_hook=self.api.unique_object), manifest, 'written manifest value')
        self.admission.close()
        need({name: self.sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items()
              if name != 'artifacts.json'} == artifacts, 'closing complete output membership and hashes')
        need((self.output / 'artifacts.json').read_bytes() == manifest_bytes, 'late artifact manifest drift')

    def run(self):
        self.output.mkdir(parents=True)
        try:
            self.prepare()
            self.compile()
            self.links()
            self.admission.close()
            self.report.update(Status='CM3-LTO-FRESH-LINK-CAPTURE-PASS-NOT-QUALIFIED', InputClosureVerified=True,
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
                    name: self.sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items()
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
