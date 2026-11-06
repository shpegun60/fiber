"""Fresh typed declaration and five link controls for admitted CM3 O2-LTO."""
import argparse
import contextlib
import copy
import hashlib
import importlib.abc
import importlib.util
import json
from pathlib import Path
import re
import sys
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PASS = 'CURRENT-CM3-LTO-ABI-CONTROLS-PASS-NOT-QUALIFIED'
SCOPE = 'CURRENT_NATIVE_CM3_O2_LTO_TYPED_DECLARATIONS_AND_FIVE_LINK_CONTROLS_ONLY'
PINS = {
    'admission': ('tools/fixtures/cm3_lto_runtime_bindings/witness.py',
        'DFFA1D51EA6513C31612479720695973006BE627442C53D047AE65FDCD279289'),
    'utility': ('tools/fixtures/cm0_final_cell/controls.py',
        '9FA3297C5C1D3861F8B422977E876D40B0F6D7275AA4431B0AC579AECB777C9A'),
    'probes': ('tools/fixtures/cm0_final_cell/components.py',
        '16490A20B1A75C5DBD2D21A5FED988C5BD82F4DE919350985B33491CE473A5F7'),
    'plan': ('tools/fixtures/ordinary_final_cell/controls.py',
        '10F8203B7AA24502BDCA2274DA8C5B7A8763EF7630E8FE8350C64AC50699F18A'),
    'native': ('tools/fixtures/classic_final_image/run.py',
        'FBCBA0C4FF480E139ADE401ECFA90822E9EA01A6AB554CEF157036EC9DE7F014'),
    'process': ('tools/fixtures/freeze_cohorts/process_runner.py',
        'D00D16DBFC69C3F49DF24D8F8A7329045DD9545AF50CB37A39ACB38EAC48B104'),
}
LOCAL_PINS = {
    'abi': ('tools/fixtures/cm3_lto_abi_controls/abi.py',
        '672508E25F984A6F3F7224E019395C874C2745786D318390699F80BCCD055CC6'),
    'diagnostics': ('tools/fixtures/cm3_lto_abi_controls/diagnostics.py',
        '0A1CD4EB14172C3E3FF1E5B05A733C7837404E7DD95C8D6953323EB26FEA250C'),
    'contract': ('tools/fixtures/cm3_lto_abi_controls/CONTRACT.md',
        'B592F0B7741C5FA69507FEF67DD4B03D424926A1A9245E2A3929D656693623DC'),
}
BUFFER_PINS = {
    'tools/fixtures/ordinary_final_cell/abi.py': '43F2E49D638D0E586A24AD2B32D0B8D86C58CC9A63E134EF6AF064437278CAE5',
    'tools/fixtures/cm0_final_cell/abi.py': 'F5AA5CE6BD21130249D571D0AA03BD72C735DA04832C2B6DBF13EFD548CB4F4B',
}
PROBES = ('types.c', 'attributes.c', 'slot_read.c', 'slot_write.c', 'slot_address.c')
ANCHOR = 'fiber_internal_runtime_port_abi_v1_anchor'


def need(value, message):
    if not value:
        raise ValueError('cm3-lto-abi-controls: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def load(name, path, raw):
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def link_recipe(report, objects):
    """The authenticated capture recipe with only verbose diagnostics removed."""
    need(type(report) is dict and report.get('Profile') == 'CM3' and report.get('Mode') == 'O2-lto'
         and report.get('Linkage') == 'direct' and report.get('LTO') is True,
         'literal native CM3 O2-LTO direct recipe')
    commands = [row for row in report['Commands'] if row.get('Label') == 'link ordinary']
    need(len(commands) == 1, 'one positive link recipe')
    flags = commands[0]['Argv']
    need(type(flags) is list and all(type(flag) is str for flag in flags)
         and flags.count('-v') == 1 and flags.count('-flto') == 1
         and flags.count('-flto-partition=one') == 1 and flags.count('-save-temps=obj') == 1
         and [flag for flag in flags if flag.endswith('.o')] == [str(path) for path in objects],
         'exact genuine LTO recipe and object order')
    return [flag for flag in flags if flag != '-v']


@contextlib.contextmanager
def reader(admitted, binaries):
    """Execute only the admitted ELF reader and its complete captured parser."""
    stable = admitted.base.stable_path
    snapshots = {stable(path): raw for path, raw in admitted.buffers.items()}
    for path in binaries:
        path = stable(path)
        raw = admitted.watch.read(path)
        need(path not in snapshots, 'binary role cannot alias a helper source')
        snapshots[path] = raw
    admitted.watch.close()

    def lexical_resolve(path, strict=False):
        need(type(strict) is bool and strict is False, 'lexical-only immutable reader resolution')
        return stable(path)

    # Real path/physical closing occurs outside the immutable helper scope.
    with patch.object(Path, 'resolve', lexical_resolve):
        with reader_scope(admitted, snapshots) as result:
            yield result


@contextlib.contextmanager
def reader_scope(admitted, snapshots):
    legacy = admitted.base
    loader = load('cm3_abi_immutable_loader', legacy.LOADER, admitted.buffers[legacy.LOADER])
    graph = loader.FrozenSources(admitted.buffers)
    package = Path(admitted.authority.result['SeedBuild']) / 'python/elftools'
    names = {}
    for path in admitted.buffers:
        if path.is_relative_to(package):
            parts = list(path.relative_to(package.parent).with_suffix('').parts)
            is_package = parts[-1] == '__init__'
            if is_package:
                parts.pop()
            name = '.'.join(parts)
            need(name not in names, 'unique admitted parser module')
            names[name] = path, is_package
    need('elftools' in names and not any(name == 'elftools' or name.startswith('elftools.')
         for name in sys.modules), 'initially unimported captured parser')

    class Finder(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname != 'elftools' and not fullname.startswith('elftools.'):
                return None
            need(fullname in names and target is None, 'closed captured parser imports')
            source, is_package = names[fullname]
            spec = graph.spec(fullname, source)
            if is_package:
                spec.submodule_search_locations = [str(source.parent)]
            return spec

    def read_bytes(path):
        key = legacy.stable_path(path)
        need(key in snapshots, 'reader escaped immutable source/binary snapshots')
        return snapshots[key]

    previous = list(sys.meta_path)
    try:
        sys.meta_path.insert(0, Finder())
        with graph.active(), patch.object(Path, 'read_bytes', read_bytes):
            yield graph.load('cm3_abi_final_reader', admitted.authority.core_path), graph
    finally:
        sys.meta_path[:] = previous


def suite_type(utility):
    class Suite(utility.Suite):
        def __init__(self, args, admitted, modules, buffers):
            self.admitted, self.modules = admitted, modules
            self.api, self.watch = admitted.replay_api, admitted.watch
            self.output = self.api.checked_path(args.output_dir, fresh=True)
            self.result = admitted.authority.result
            self.base = self.api.checked_path(self.result['SeedBuild'], directory=True)
            self.bundle = dict(Artifacts=self.watch.structured(self.base / 'artifacts.json')['Artifacts'])
            self.sources = copy.deepcopy(self.result['Sources'])
            self.objects = tuple(self.api.checked_path(row['Object']) for row in self.sources)
            need(len(self.sources) == 9 and all(row['SlimIR'] is (index != 8)
                 for index, row in enumerate(self.sources)), 'eight slim IR sources and one machine startup')
            self.native, self.process = modules['native'], modules['process']
            self.transport = admitted.api
            self.link_argv = link_recipe(self.result, self.objects)
            tool_root = Path(self.result['CapturedCompiler']).parent.parent
            self.tools = {name: self.api.checked_path(tool_root / 'bin' / ('arm-none-eabi-' + name + '.exe'))
                          for name in ('gcc', 'nm', 'objdump', 'readelf')}
            self.tools['ld'] = self.api.checked_path(self.result['ResolvedWorkers']['ld']['Path'])
            self.plugin = self.api.checked_path(self.result['LTOPlugin']['Path'])
            need(all(path in self.watch.hashes for path in (*self.tools.values(), self.plugin)),
                 'only already admitted compiler tools and plugin')
            need(str(self.tools['gcc']) == self.link_argv[0], 'same captured compiler')
            self.environment = self.watch.structured(admitted.root / 'environment.json')
            self.environment.update(TEMP=str(self.output / 'tmp'), TMP=str(self.output / 'tmp'))
            for path, raw in buffers.items():
                need(self.watch.read(path, sha(raw)) == raw, 'same executed source bytes')
                need(path not in admitted.buffers or admitted.buffers[path] == raw, 'conflicting admitted helper bytes')
                admitted.buffers[path] = raw
            denied = {ROOT, admitted.root, *(path.parent for path in self.watch.hashes)}
            need(all(not self.output.is_relative_to(path) and not path.is_relative_to(self.output)
                 for path in denied), 'disjoint fresh command output')
            self.watch.close()
            self.commands, self.expected, self.identities = [], {}, {}
            self._started = self._finished = self._controls_done = False
            self.report = dict(Status='FAIL', Scope=SCOPE, Profile='CM3', Mode='O2-lto', Linkage='direct', LTO=True,
                CaptureBuild=str(admitted.root), CaptureReceiptSha256=args.capture_receipt_sha256,
                CaptureArtifactsSha256=args.capture_artifacts_sha256,
                CurrentInventory=copy.deepcopy(admitted.report['CurrentInventory']),
                CurrentCaptureProducer=copy.deepcopy(admitted.report['CurrentCaptureProducer']),
                SourceInventorySha256=self.result['SourceInventorySha256'],
                SeedAuthority=copy.deepcopy(admitted.report['SeedAuthority']),
                PositiveSources=copy.deepcopy(self.sources),
                PositiveRecipeDelta=[dict(Removed='-v', Count=1, Reason='CLOSED_LINK_DIAGNOSTIC_GRAMMAR')],
                CommandsReconstructed=admitted.report['CommandsReconstructed'],
                Interpreter=copy.deepcopy(admitted.report['Interpreter']),
                BootstrapSources=[dict(Path=str(path), Sha256=sha(raw)) for path, raw in sorted(buffers.items())],
                PositiveLinkRevalidated=False, Controls=[], Compilations=[], Error=None, PrimaryError=None,
                ClosingErrors=[], OutputSealVerified=False, InputClosureVerified=False,
                TypedDeclarationProbesValidated=False, FiveLinkControlsValidated=False,
                RequiredCellSatisfied=False, RequiredCellsSatisfied=0, RequiredCellCount=2774,
                Qualification=False, CellContractSatisfied=False, FullABIProof=False, FullSemanticABIProof=False,
                SourceIRProof=False, SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False,
                FinalReferenceParity=False, CanonicalProtocolValidated=False, WholeSlotAccessIsolation=False,
                PolicyEquivalence=False, ArchiveExtraction=False, CpuExecution=False, BoardExecution=False,
                HostedCIQualified=False, GlobalFreezeQualified=False)

        def start(self):
            super().start()
            info = self.output.stat()
            self.output_identity = info.st_dev, info.st_ino
            (self.output / 'tmp').mkdir()
            self.report['CapturedSources'] = [dict(Original=str(path), Sha256=sha(raw),
                Captured=str(self.write_input('source-buffers/%04d-%s' % (index, path.name), raw)))
                for index, (path, raw) in enumerate(sorted(self.admitted.buffers.items()))]
            return self

        def _link(self, name, objects, expected_failure=False):
            result, elf, link_map = super()._link(name, objects, expected_failure)
            directory = elf.parent
            fixed = {'image.elf.ltrans.out', 'image.elf.ltrans0.ltrans.args.0',
                'image.elf.ltrans0.ltrans.o', 'image.elf.ltrans0.ltrans.s', 'image.elf.ltrans0.ltrans_args',
                'image.elf.ltrans0.o', 'image.elf.ltrans_args', 'image.elf.res', 'image.elf.wpa.args.0',
                ''.join(elf.parts[1:]) + '.lto_wrapper_args'}
            actual = self.api.files_under(directory)
            need(set(actual) <= fixed | {'image.elf', 'image.map'}, 'bounded saved LTO link auxiliaries')
            if not expected_failure:
                need(fixed - {''.join(elf.parts[1:]) + '.lto_wrapper_args'} <= set(actual),
                     'complete saved positive LTO machine and recipe')
            for path in actual.values():
                self.record_output(path)
            wrapper = self.output / (''.join(elf.parts[1:]) + '.lto_wrapper_args')
            if wrapper.exists():
                need(not (directory / wrapper.name).exists(), 'one LTO argument-file owner')
                self.record_output(wrapper)
            return result, elf, link_map

        def inspect_ir(self, obj):
            raw = self.watch.read(obj)
            header = self.transport.require_elf32le(raw)
            result = self.command([str(self.tools['readelf']), '-hSW', str(obj)], 'inspect slim ' + obj.stem)
            sections = self.transport.section_records(result.stdout.decode('ascii'))
            need(len(sections) == header['SectionCount'] and [row['Index'] for row in sections]
                 == list(range(header['SectionCount'])), 'complete indexed section table bound to actual ELF header')
            need(any(row['Name'].startswith('.gnu.lto_') for row in sections)
                 and not any(row['Size'] and 'X' in row['Flags'] for row in sections),
                 'actual slim IR with no executable machine fallback')
            return dict(Object=str(obj), Sha256=sha(raw), SlimIR=True, Sections=sections)

        def _undefined(self, obj, name):
            result = self.command([str(self.tools['nm']), '--plugin', str(self.plugin), '-u', str(obj)], 'imports ' + name)
            names = []
            for line in utility.diagnostic_text(result.stdout).splitlines():
                match = re.fullmatch(r'\s*U ([A-Za-z_][A-Za-z0-9_]*)', line)
                need(match is not None, 'complete plugin undefined row')
                names.append(match[1])
            need(len(names) == len(set(names)), 'unique strong plugin undefined names')
            return names, dict(Object=str(obj), Imports=names, Plugin=str(self.plugin), RawNmSha256=sha(result.stdout))

        def _definitions(self, obj, label):
            result = self.command([str(self.tools['nm']), '--plugin', str(self.plugin), '-P', '-S', '--defined-only',
                str(obj)], 'definitions ' + label)
            rows = []
            for line in utility.diagnostic_text(result.stdout).splitlines():
                match = re.fullmatch(r'(\S+) ([A-Za-z]) 0\s*', line)
                need(match is not None, 'complete slim plugin definition row')
                rows.append(dict(Name=match[1], Kind=match[2], Value=0, Size=None))
            need(len(rows) == len({row['Name'] for row in rows}), 'unique slim plugin definitions')
            return rows

        def run_link_controls(self):
            need(self._started and not self._finished and not getattr(self, '_controls_started', False), 'one link batch')
            self._controls_started = True
            _, positive, link_map = self._link('positive', self.objects)
            self.watch.read(positive)
            with reader(self.admitted, (self.result['Links'][0]['Path'], positive)) as (core, graph):
                twin = core.compare_load_images(Path(self.result['Links'][0]['Path']), positive)
            self.watch.close()
            self.report.update(PositiveLinkRevalidated=True,
                PositiveAuthority=dict(Original=self.result['Links'][0]['Path'], Replayed=str(positive), Map=str(link_map),
                    RawElfByteIdentical=self.watch.read(positive) == self.watch.read(self.result['Links'][0]['Path']),
                    LoadImageComparison=twin, Scope='SAME_SLIM_INPUTS_RECIPE_LOAD_IMAGE_REPRODUCTION_ONLY'),
                ExecutedReaderBuffers=graph.executed)
            runtime = self._definitions(self.objects[3], 'original-runtime')
            private = [row['Name'] for row in runtime if row['Name'].startswith('fiber_port_context_cohort_')]
            need(len(private) == 1 and private[0].count('_g4_') == 1, 'one original priority4 private cohort')
            alternate = private[0].replace('_g4_', '_g5_', 1)
            anchor, anchor_import = self._imports(self.objects[4], 'unchanged-boot-v1', 'fiber_internal_runtime_port_abi_')
            need(anchor == ANCHOR, 'actual unchanged v1 consumer')
            plan = self.modules['plan'].control_plan(dict(target=dict(nvic_priority_bits=4)), 'ARM_CM3', 'arm_cm3')
            wanted = (alternate, 'fiber_port_storage_cohort_arm_cm3_v999_r0', ANCHOR, 'SVC_Handler', 'PendSV_Handler')
            for spec, expected in zip(plan, wanted):
                name, index, added = spec['Name'], spec['Index'], spec['Added']
                record = dict(Name=name, Expected=expected, Status='FAIL', RequiredCellsSatisfied=0)
                self.report['Controls'].append(record)
                self._save('results.json', self.report)
                compiled = self.compile_tuple(index, name=name, mutations=spec['Mutations'], source_bytes=added)
                obj = Path(compiled['Object'])
                self.watch.read(obj, compiled['ObjectSha256'])
                record['SlimIR'] = self.inspect_ir(obj)
                selected = list(self.objects)
                if added is None:
                    selected[index] = obj
                else:
                    selected.append(obj)
                if index in (6, 7):
                    prefix = 'fiber_port_context_cohort_' if index == 6 else 'fiber_port_storage_cohort_'
                    actual, evidence = self._imports(obj, name, prefix)
                    need(actual == expected, 'actual intended alternate identity')
                    record['ImportEvidence'] = evidence
                else:
                    definitions = self._definitions(obj, name)
                    matches = [row for row in definitions if row['Name'] == (
                        'fiber_internal_runtime_port_abi_v2_anchor' if added is None else expected)]
                    need(len(matches) == 1 and matches[0]['Kind'] == ('D' if added is None else 'T'),
                         'one actual changed data anchor or strong handler in slim IR')
                    record['ChangedDefinitions'] = definitions
                    if added is None:
                        need(ANCHOR not in {row['Name'] for row in definitions}, 'changed state does not define v1')
                        imports, evidence = self._undefined(obj, name)
                        need(ANCHOR not in imports, 'unchanged consumers cause missing-v1 failure')
                        record.update(ChangedImports=evidence, ImportEvidence=anchor_import)
                first = len(self.commands)
                result, elf, partial = self._link(name, selected, expected_failure=True)
                diagnostics = self.modules['diagnostics']
                if added is None:
                    machine = self.api.checked_path(str(elf) + '.ltrans0.ltrans.o')
                    machine_bytes = self.watch.read(machine)
                    self.transport.require_elf32le(machine_bytes)
                    classification = diagnostics.classify_undefined(result, expected, self.tools['ld'],
                        machine=machine)
                    record['DiagnosticMachine'] = dict(Path=str(machine), Sha256=sha(machine_bytes),
                        Kind='ACTUAL_SAVED_ARM_ELF32_REL')
                else:
                    classification = diagnostics.classify_duplicate(result, expected, self.tools['ld'], obj,
                        self.objects[3], compiled['Source'])
                self.verify_objects()
                self.watch.close()
                record.update(Status='INTENDED-LINK-REJECTION-PASS', Compilation=compiled, Classification=classification,
                    LinkCommandIndex=first, FinalImageAbsent=not elf.exists(), PartialMap=str(partial) if partial.exists() else None,
                    ConsumedObjects=[dict(Index=position, Path=str(path), Sha256=sha(self.watch.read(path)))
                        for position, path in enumerate(selected)])
                self._save('controls/' + name + '.json', record)
                self._save('results.json', self.report)
            need(tuple(row['Name'] for row in self.report['Controls']) == self.modules['plan'].CONTROLS
                 and all(row['Status'] == 'INTENDED-LINK-REJECTION-PASS' for row in self.report['Controls']),
                 'all five actual intended rejections')
            self._controls_done = True
            self.report['FiveLinkControlsValidated'] = True

        def finish(self, error=None):
            need(not self._finished, 'finish once')
            if error is None and not (self._controls_done and self.report['TypedDeclarationProbesValidated']
                    and self.report['FiveLinkControlsValidated'] and self.report['PositiveLinkRevalidated']
                    and self.modules['plan'].terminal_success(self.commands)):
                error = ValueError('incomplete command/probe/link suite')
            self._finished = True
            if error is not None:
                self._failure(error)
            if not self._started:
                return copy.deepcopy(self.report)
            try:
                self.verify_objects()
                self.watch.close()
                self._verify_outputs()
                self.report.update(Status=PASS if error is None else 'FAIL', OutputSealVerified=error is None,
                    InputClosureVerified=error is None, Commands=self.commands, CommandsSha256=self.expected['commands.json'],
                    InputHashes={str(path): value for path, value in sorted(self.watch.hashes.items())},
                    InputPhysicalIdentities={str(path): self.admitted.identity(path) for path in sorted(self.watch.hashes)},
                    ClosingFilesVerified=len(self.watch.hashes),
                    IntendedLinkRejects=sum(row['Status'] == 'INTENDED-LINK-REJECTION-PASS' for row in self.report['Controls']))
                if error is None:
                    need(succeeded(self.report), 'complete fixed command/probe/control verdict before sealing')
                self._save('results.json', self.report)
                manifest = {name: value for name, value in self.expected.items() if name != 'artifacts.json'}
                self._save('artifacts.json', dict(Artifacts=manifest))
                self.watch.close()
                self._verify_outputs()
            except BaseException as failure:
                self._failure(failure)
                try:
                    self._save('results.json', self.report)
                    self._write('artifacts.json', encoded(dict(Artifacts={name: sha(path.read_bytes())
                        for name, path in self.api.files_under(self.output).items() if name != 'artifacts.json'})))
                except BaseException:
                    pass
            return copy.deepcopy(self.report)

        def _failure(self, error):
            def force():
                self.report.update(Status='FAIL', TypedDeclarationProbesValidated=False, FiveLinkControlsValidated=False,
                    InputClosureVerified=False, OutputSealVerified=False)
            force()
            try:
                super()._failure(error)
            finally:
                force()

    return Suite


def prepare(args):
    need(not sys.flags.optimize and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
         'fresh isolated unoptimized -I -S -B interpreter')
    sources = {}
    for relative, expected in (*PINS.values(), *LOCAL_PINS.values(), *BUFFER_PINS.items()):
        path = ROOT / relative
        raw = path.read_bytes()
        need(sha(raw) == expected, 'fixed helper buffer: ' + relative)
        sources[path] = raw
    sources[Path(__file__).resolve()] = Path(__file__).resolve().read_bytes()
    modules = {name: load('cm3_lto_abi_' + name, ROOT / row[0], sources[ROOT / row[0]])
               for name, row in (*PINS.items(), *LOCAL_PINS.items()) if name != 'contract'}
    admitted, _ = modules['admission'].prepare(args)
    return suite_type(modules['utility'])(args, admitted, modules, sources), modules


def run(suite, modules):
    error = None
    try:
        suite.start()
        root = suite.base / 'source'
        sources = {name[len('source/'):]: suite.watch.read(suite.base / name, digest)
                   for name, digest in suite.bundle['Artifacts'].items() if name.startswith('source/')}
        suite.report['DeclaredProviders'] = modules['abi'].inspect_provider_dependencies(sources,
            suite.watch.read(suite.admitted.root / 'results.json'), source_root=str(root), capture_root=str(suite.admitted.root))
        suite.run_link_controls()
        probes = modules['abi'].emit_probes()
        need(tuple(probes) == PROBES, 'exact five independent ABI probes')
        suite.report['ABIProbes'] = {}
        for name, probe in probes.items():
            record = modules['probes'].compile_probe(suite, name, probe)
            suite.report['ABIProbes'][name] = record
            if name in PROBES[:2]:
                record['SlimIR'] = suite.inspect_ir(Path(record['Object']))
            if name == 'attributes.c':
                facts = modules['abi'].inspect_preprocessed_attributes(suite.watch.read(record['Preprocessed']))
                for direction, path in facts['CanonicalHeaders'].items():
                    expected = root / ('context/context_port_abi.h' if direction == 'forward' else 'context/context_runtime_port_abi.h')
                    need(suite.api.checked_path(path) == expected, 'same accepted attempt canonical declaration header')
                suite.report['PreprocessedAttributes'] = facts
        suite.report['TypedDeclarationProbesValidated'] = True
        suite.write_input('component-facts.json', encoded({name: suite.report[name] for name in
            ('DeclaredProviders', 'ABIProbes', 'PreprocessedAttributes', 'PositiveAuthority', 'Controls')}))
    except BaseException as failure:
        error = failure
    return suite.finish(error)


def succeeded(report):
    if not (type(report) is dict and report.get('Status') == PASS and report.get('Scope') == SCOPE
            and report.get('Profile') == 'CM3' and report.get('Mode') == 'O2-lto'
            and report.get('Linkage') == 'direct' and report.get('LTO') is True
            and report.get('Error') is None and report.get('PrimaryError') is None and report.get('ClosingErrors') == []
            and all(report.get(name) is True for name in ('InputClosureVerified', 'OutputSealVerified',
                'TypedDeclarationProbesValidated', 'FiveLinkControlsValidated', 'PositiveLinkRevalidated'))
            and type(report.get('RequiredCellsSatisfied')) is int and report['RequiredCellsSatisfied'] == 0
            and type(report.get('RequiredCellCount')) is int and report['RequiredCellCount'] == 2774
            and report.get('RequiredCellSatisfied') is False
            and type(report.get('CommandsReconstructed')) is int and report['CommandsReconstructed'] == 57
            and type(report.get('IntendedLinkRejects')) is int and report['IntendedLinkRejects'] == 5):
        return False
    commands = report.get('Commands')
    if not (type(commands) is list and len(commands) == 41 and all(type(row) is dict
            and row.get('State') == 'TERMINAL' and row.get('Status') in ('PASS', 'EXPECTED-NONZERO')
            and type(row.get('Exit')) is int and type(row.get('ExpectedExit')) is int
            and row['Exit'] == row['ExpectedExit'] == (1 if row['Status'] == 'EXPECTED-NONZERO' else 0)
            and row.get('TimedOut') is False and not row.get('JournalErrors') for row in commands)):
        return False
    if tuple(row.get('Label') for row in commands if row['Exit'] == 1) != (
            'link stale-nvic-expectation', 'link stale-storage-application', 'link stale-reverse-anchor',
            'link duplicate-svc', 'link duplicate-pendsv', 'compile probe slot-read',
            'compile probe slot-write', 'compile probe slot-address'):
        return False
    if any(report.get(name) is not False for name in ('Qualification', 'CellContractSatisfied', 'FullABIProof',
            'FullSemanticABIProof', 'SourceIRProof', 'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership',
            'FinalReferenceParity', 'CanonicalProtocolValidated', 'WholeSlotAccessIsolation', 'PolicyEquivalence',
            'ArchiveExtraction', 'CpuExecution', 'BoardExecution', 'HostedCIQualified', 'GlobalFreezeQualified')):
        return False
    probes = report.get('ABIProbes')
    if type(probes) is not dict or set(probes) != set(PROBES):
        return False
    for name, row in probes.items():
        if type(row) is not dict or type(row.get('Classification')) is not dict:
            return False
        expected = name in PROBES[:2]
        if row['Classification'].get('AcceptedCompile') is not expected:
            return False
        if expected:
            if type(row.get('SlimIR')) is not dict or row['SlimIR'].get('SlimIR') is not True:
                return False
        elif row['Classification'].get('ObjectAbsent') is not True:
            return False
    controls = report.get('Controls')
    return (type(controls) is list and len(controls) == 5
        and tuple(row.get('Name') for row in controls if type(row) is dict) == (
            'stale-nvic-expectation', 'stale-storage-application', 'stale-reverse-anchor', 'duplicate-svc', 'duplicate-pendsv')
        and all(row.get('Status') == 'INTENDED-LINK-REJECTION-PASS' and row.get('FinalImageAbsent') is True
            for row in controls))


def persist_failure(suite):
    """Independent diagnostic bytes; no successful seal or managed-tool retry."""
    suite.report.update(Status='FAIL', TypedDeclarationProbesValidated=False, FiveLinkControlsValidated=False,
        InputClosureVerified=False, OutputSealVerified=False)
    root = suite.api.checked_path(suite.output, directory=True)
    info = root.stat()
    need(root == suite.output and (info.st_dev, info.st_ino) == suite.output_identity,
         'failure output retains its created directory identity')
    for name in ('results.json', 'artifacts.json'):
        path = suite.api.checked_path(root / name, fresh=not (root / name).exists())
        need(not path.exists() or path.stat().st_nlink == 1, 'single-linked failure diagnostic destination')
    receipt = encoded(suite.report)
    target = suite.output / 'results.json'
    target.write_bytes(receipt)
    artifacts = {name: sha(path.read_bytes()) for name, path in suite.api.files_under(suite.output).items()
                 if name not in ('results.json', 'artifacts.json')}
    artifacts['results.json'] = sha(receipt)
    manifest = encoded(dict(Artifacts=artifacts))
    (suite.output / 'artifacts.json').write_bytes(manifest)
    need(target.read_bytes() == receipt and (suite.output / 'artifacts.json').read_bytes() == manifest,
         'intended fallback FAIL receipt and manifest bytes')


def revoke_failure(suite, error):
    """Bounded diagnostic writes only; never rerun a tool or grant a good seal."""
    report = suite.report
    message = type(error).__name__ + ': ' + str(error)
    report['PrimaryError'] = report.get('PrimaryError') or report.get('Error') or message
    report['Error'] = report.get('Error') or message
    closing = report.setdefault('ClosingErrors', [])

    def force():
        report.update(Status='FAIL', TypedDeclarationProbesValidated=False, FiveLinkControlsValidated=False,
            InputClosureVerified=False, OutputSealVerified=False)
    force()
    try:
        suite._failure(error)
    except BaseException as secondary:
        closing.append('failure hook: ' + type(secondary).__name__ + ': ' + str(secondary))
    finally:
        force()
    if not getattr(suite, '_started', False):
        return
    for attempt in range(2):
        try:
            persist_failure(suite)
            break
        except BaseException as secondary:
            closing.append('failure persistence %d: %s: %s' % (attempt + 1, type(secondary).__name__, secondary))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('capture-build', 'capture-receipt-sha256', 'capture-artifacts-sha256', 'inventory',
                 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    suite = None
    try:
        suite, modules = prepare(parser.parse_args(argv))
        report = run(suite, modules)
        need(succeeded(report), 'complete sealed bounded suite: ' + str(report.get('Error')))
        print(json.dumps({key: report.get(key) for key in ('Status', 'Scope', 'IntendedLinkRejects',
            'TypedDeclarationProbesValidated', 'InputClosureVerified', 'OutputSealVerified', 'RequiredCellsSatisfied')},
            sort_keys=True), flush=True)
    except BaseException as failure:
        if suite is not None:
            try:
                revoke_failure(suite, failure)
            except BaseException as secondary:
                print('Failure diagnostics: ' + str(secondary), file=sys.stderr)
        print(type(failure).__name__ + ': ' + str(failure), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
