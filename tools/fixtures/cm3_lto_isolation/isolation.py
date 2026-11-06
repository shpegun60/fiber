"""Fresh CPU-free common LTO and bounded merged-machine slot isolation."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PASS = 'CURRENT-CM3-LTO-ISOLATION-PASS-NOT-QUALIFIED'
SCOPE = 'CURRENT_NATIVE_CM3_O2_LTO_CPU_FREE_COMMON_AND_SLOT_ISOLATION_ONLY'
PINS = {
    'controls': ('tools/fixtures/cm3_lto_abi_controls/controls.py',
        '7984A228966FC17641BD83D23486DB7E50BC2B7E5BC12D70A712F6E83800F14F'),
    'ownership': ('tools/fixtures/cm0_final_cell/ownership.py',
        'F9971A707BC30FFA7AF0B816570ED476B2965F24369BC7A747C18784E5B0A552'),
    'slot': ('tools/fixtures/cm3_lto_isolation/slot.py',
        '669F294A622B076984E36F6FA9C73235BD0D3F778AA4A36F496051D49DE822B3'),
    'contract': ('tools/fixtures/cm3_lto_isolation/CONTRACT.md',
        '5327BB040CE5DF0FE96A3F965C4548F555A3FD5B843B07C071DC7E36CF943C1F'),
}
COMMON = ('context/context_core.c', 'context/context_runtime_state.c', 'context/context_panic.c')
FALSE_CLAIMS = ('Qualification', 'CellContractSatisfied', 'RequiredCellSatisfied', 'FullABIProof',
    'FullSemanticABIProof', 'SourceIRProof', 'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership',
    'FinalReferenceParity', 'CanonicalProtocolValidated', 'PolicyEquivalence', 'ArchiveExtraction',
    'CpuExecution', 'BoardExecution', 'HostedCIQualified', 'GlobalFreezeQualified',
    'TypedDeclarationProbesValidated', 'FiveLinkControlsValidated')
PHASES = ('CpuFreeCommonValidated', 'SourceOwnershipValidated', 'WholeSlotAccessIsolation',
          'PositiveLinkRevalidated', 'InputClosureVerified', 'OutputSealVerified')


def need(condition, message):
    if not condition:
        raise ValueError('cm3-lto-isolation: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def load(name, path, raw):
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def common_flags(components, original, root):
    need(type(original) is list and original.count('-flto') == 1
         and original.count('-fno-fat-lto-objects') == 1 and original.count('-O2') == 1,
         'actual O2 slim-LTO common compile flags')
    flags = components.isolated_flags(original, root)
    need(flags.count('-flto') == 1 and flags.count('-fno-fat-lto-objects') == 1
         and flags.count('-O2') == 1 and '-include' not in flags,
         'isolation preserves optimization and real slim LTO')
    return flags


def command_plan():
    return tuple(label for name in COMMON for label in (
        'discover isolated ' + Path(name).stem, 'compile isolated ' + Path(name).stem,
        'inspect slim ' + Path(name).stem)) + (
        'link isolated-common', 'link isolated-common-emit', 'disassemble isolated-common-emit')


def commands_pass(commands):
    return (type(commands) is list and tuple(row.get('Label') for row in commands if type(row) is dict) == command_plan()
        and all(type(row) is dict and row.get('State') == 'TERMINAL' and row.get('Status') == 'PASS'
            and type(row.get('Exit')) is int and row['Exit'] == 0
            and type(row.get('ExpectedExit')) is int and row['ExpectedExit'] == 0
            and row.get('TimedOut') is False and not row.get('JournalErrors') for row in commands))


def require_slot_result(proof, port_source, assembly, image):
    need(type(proof) is dict and proof.get('Status') == 'CM3-LTO-SLOT-ISOLATION-PASS-NOT-QUALIFIED'
         and proof.get('Scope') == 'NATIVE_CM3_O2_LTO_MERGED_MACHINE_SECTION_MEDIATED_SLOT_ACCESSES_ONLY'
         and proof.get('Profile') == 'CM3' and proof.get('Mode') == 'O2-lto'
         and proof.get('Linkage') == 'direct' and proof.get('EmitRelocs') is True,
         'bounded slot leaf disposition')
    need(all(proof.get(name) is True for name in ('SlotIsolationValidated', 'RawSectionSymbolsPreserved',
        'AllSectionMediatedSlotReferencesValidated')), 'complete section-mediated slot leaf')
    for name, value in (('HandlerLoadPairs', 2), ('ClosedCommonBodies', 6), ('CommonLoads', 5),
            ('CommonStores', 1), ('SlotReferences', 8), ('AppliedSlotReferences', 8), ('RequiredCellsSatisfied', 0)):
        need(type(proof.get(name)) is int and proof[name] == value, 'literal bounded slot count: ' + name)
    need(proof.get('Publisher') == 'fiber_internal_runtime_publish_current_context'
         and proof.get('SourceSha256') == sha(port_source) and proof.get('AssemblySha256') == sha(assembly)
         and proof.get('MachineSha256') == sha(image.prelink.data)
         and proof.get('FinalSha256') == sha(image.final.data)
         and proof.get('LinkMapSha256') == image.link_map_hash, 'slot leaf input identity')
    need(all(proof.get(name) is False for name in ('CommonSourceOwnershipValidated',
        'CompleteHandlerBodiesValidated', 'ArbitraryPointerAliasProof', 'WholeProgramMemorySafetyProof',
        'FullSemanticABIProof', 'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership',
        'Qualification', 'CellContractSatisfied', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified',
        'RequiredCellSatisfied')), 'slot leaf cannot grant stronger evidence')


def compile_common(suite, index):
    need(type(index) is int and 0 <= index < 3, 'one of three common sources')
    row, root = suite.source(index), suite.base / 'source'
    source = suite.api.checked_path(row['Source'])
    need(source == root / COMMON[index] and row['SlimIR'] is True,
         'exact common provider from admitted capture')
    suite.watch.read(source, row['SourceSha256'])
    flags = common_flags(suite.modules['probes'], row['CompileFlags'], root)
    stem = source.stem
    directory = suite.output / 'isolated-common'
    directory.mkdir(exist_ok=True)
    obj = directory / (stem + '.o')
    discovery, actual = obj.with_suffix('.discovery.d'), obj.with_suffix('.compile.d')
    gcc, target, first = str(suite.tools['gcc']), 'pilot-source-' + str(index), len(suite.commands)
    admitted = {Path(item['Path']): item['Sha256'] for item in row['ActualCompileDependencies']}
    need(len(admitted) == len(row['ActualCompileDependencies']) and source in admitted,
         'same-attempt unique source dependency authority')

    def dependencies(path):
        paths = [suite.api.checked_path(item) for item in suite.native.read_dependencies(path)]
        records = suite.modules['probes'].isolated_dependencies(paths, admitted,
            root=root, cmsis=suite.base / 'cmsis')
        need(source in paths, 'isolated dependency list includes actual common source')
        for item in records:
            suite.watch.read(item['Path'], item['Sha256'])
        return records

    result = suite.command([gcc, *flags, '-M', '-MF', str(discovery), '-MT', target, str(source)],
                           'discover isolated ' + stem)
    need(result.stdout == b'' and result.stderr == b'', 'clean dependency discovery')
    suite.record_output(discovery)
    before = dependencies(discovery)
    result = suite.command([gcc, *flags, '-MD', '-MF', str(actual), '-MT', target,
                           '-c', str(source), '-o', str(obj)], 'compile isolated ' + stem)
    need(result.stdout == b'' and result.stderr == b'', 'clean CPU-free common LTO compilation')
    suite.record_output(actual)
    object_record = suite.record_output(obj)
    after = dependencies(actual)
    suite.native.require_compile_dependencies(before, after)
    slim = suite.inspect_ir(obj)
    return dict(Source=str(source), SourceSha256=row['SourceSha256'], TemplateIndex=index,
        OriginalObject=row['Object'], OriginalObjectSha256=row['ObjectSha256'],
        Object=str(obj), ObjectSha256=object_record['Sha256'], SlimIR=slim,
        OriginalCompileFlags=row['CompileFlags'], CompileFlags=flags,
        IncludeDelta=dict(RemovedForcedHeader=str(root / 'tools/fixtures/classic_final_image/main.h'),
            ReplacementSearchPaths=[str(root / name) for name in ('context', 'fiber')] + [str(root)],
            OtherSemanticFlagsUnchanged=True),
        DiscoveryFlags=flags, DiscoveryDependencies=before, Dependencies=after,
        DiscoveryDependencyFile=str(discovery), CompileDependencyFile=str(actual),
        CommandIndices=list(range(first, len(suite.commands))), CompileDependenciesVerified=True,
        ForcedMainHeaderRemoved=True, CmsisAndSelectedPortIncludesRemoved=True,
        RawIRIdentityClaim=False, SourceToMachineSemanticProof=False)


def suite_type(base_class):
    class Suite(base_class):
        def __init__(self, args, admitted, modules, buffers):
            super().__init__(args, admitted, modules, buffers)
            self.report.update(Status='FAIL', Scope=SCOPE,
                **{name: False for name in (*FALSE_CLAIMS, *PHASES)},
                IsolatedCommon=[], SlotProofs=[], RawIRIdentityClaim=False,
                WholeSlotAccessIsolationScope='SECTION_MEDIATED_CURRENT_CM3_O2_LTO_ONLY')
            self._isolation_done = False

        def _failure(self, error):
            self.report.update(Status='FAIL', **{name: False for name in PHASES})
            try:
                super()._failure(error)
            finally:
                self.report.update(Status='FAIL', **{name: False for name in PHASES})

        def link_emit(self, objects):
            name = 'isolated-common-emit'
            directory = self.output / 'links' / name
            need(not directory.exists(), 'fresh emit-relocs link namespace')
            directory.mkdir(parents=True)
            elf, link_map = directory / 'image.elf', directory / 'image.map'
            argv, inserted = [], False
            for value in self.link_argv:
                if value in [str(path) for path in self.objects]:
                    if not inserted:
                        argv.extend(str(path) for path in objects)
                        inserted = True
                elif value.startswith('-Wl,-Map='):
                    argv.append('-Wl,-Map=' + str(link_map))
                elif value == self.result['Links'][0]['Path']:
                    argv.append(str(elf))
                else:
                    argv.append(value)
            need(inserted and [flag for flag in argv if flag.endswith('.o')] == [str(path) for path in objects]
                 and not any('--emit-relocs' in flag for flag in argv), 'exact substituted object order')
            argv.append('-Wl,--emit-relocs')
            result = self.command(argv, 'link ' + name)
            need(result.stdout == b'' and result.stderr == b'', 'clean emitted relocation link')
            for path in self.api.files_under(directory).values():
                self.record_output(path)
            fixed = {'image.elf', 'image.map', 'image.elf.ltrans.out', 'image.elf.ltrans0.ltrans.args.0',
                'image.elf.ltrans0.ltrans.o', 'image.elf.ltrans0.ltrans.s', 'image.elf.ltrans0.ltrans_args',
                'image.elf.ltrans0.o', 'image.elf.ltrans_args', 'image.elf.res', 'image.elf.wpa.args.0'}
            need(set(self.api.files_under(directory)) == fixed, 'complete bounded emitted LTO output set')
            wrapper = self.output / (''.join(elf.parts[1:]) + '.lto_wrapper_args')
            self.record_output(wrapper)
            self.verify_objects()
            return elf, link_map

        def finish(self, error=None):
            need(not self._finished, 'finish isolation exactly once')
            if error is None and not (self._isolation_done and commands_pass(self.commands)
                    and all(self.report[name] is True for name in PHASES[:-2])):
                error = ValueError('incomplete isolation phases or terminal commands')
            self._finished = True
            if error is not None:
                revoke_failure(self, error)
                return copy.deepcopy(self.report)
            if not self._started:
                return copy.deepcopy(self.report)
            try:
                self.verify_objects()
                self.watch.close()
                self._verify_outputs()
                self.report.update(Status=PASS if error is None else 'FAIL',
                    OutputSealVerified=error is None, InputClosureVerified=error is None,
                    Commands=self.commands, CommandsSha256=self.expected['commands.json'],
                    InputHashes={str(path): value for path, value in sorted(self.watch.hashes.items())},
                    InputPhysicalIdentities={str(path): self.admitted.identity(path) for path in sorted(self.watch.hashes)},
                    ClosingFilesVerified=len(self.watch.hashes))
                if error is None:
                    need(succeeded(self.report), 'complete isolation verdict before seal')
                self._save('results.json', self.report)
                self._save('artifacts.json', dict(Artifacts={name: value for name, value in self.expected.items()
                    if name != 'artifacts.json'}))
                self.watch.close()
                self._verify_outputs()
            except BaseException as failure:
                revoke_failure(self, failure)
            return copy.deepcopy(self.report)

    return Suite


def prepare(args):
    need(not sys.flags.optimize and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
         'fresh isolated unoptimized -I -S -B interpreter')
    buffers = {}
    for path, digest in PINS.values():
        path = ROOT / path
        raw = path.read_bytes()
        need(sha(raw) == digest, 'fixed helper: ' + str(path))
        buffers[path] = raw
    buffers[Path(__file__).resolve()] = Path(__file__).resolve().read_bytes()
    modules = {name: load('cm3_lto_isolation_' + name, ROOT / path, buffers[ROOT / path])
               for name, (path, _) in PINS.items() if name != 'contract'}
    original, inherited = modules['controls'].prepare(args)
    inherited.update(modules)
    suite = suite_type(type(original))(args, original.admitted, inherited, buffers)
    return suite, inherited


def run(suite, modules):
    error = None
    try:
        suite.start()
        root = suite.base / 'source'
        sources = {name[len('source/'):]: suite.watch.read(suite.base / name, digest)
            for name, digest in suite.bundle['Artifacts'].items() if name.startswith('source/')}
        suite.report['SourceOwnership'] = modules['ownership'].validate_common_sources(
            {name: sources[name] for name in modules['ownership'].REQUIRED_SOURCES})
        suite.report['SourceOwnershipValidated'] = True
        for index in range(3):
            suite.report['IsolatedCommon'].append(compile_common(suite, index))
        suite.report['CpuFreeCommonValidated'] = True
        objects = [Path(row['Object']) for row in suite.report['IsolatedCommon']] + list(suite.objects[3:])
        result, ordinary, ordinary_map = suite._link('isolated-common', objects)
        need(result.stdout == b'' and result.stderr == b'', 'clean isolated-common link')
        emitted, emitted_map = suite.link_emit(objects)
        dis = Path(str(emitted) + '.dis')
        result = suite.command([str(suite.tools['objdump']), '-d', str(emitted)],
                               'disassemble isolated-common-emit')
        need(result.stderr == b'' and result.stdout, 'nonempty clean final disassembly')
        suite.write_input(dis.relative_to(suite.output).as_posix(), result.stdout)
        original = suite.result['Links'][0]
        original_emit = suite.result['Links'][1]
        emitted_machine = Path(str(emitted) + '.ltrans0.ltrans.o')
        original_machine = Path(original_emit['Machine'])
        startup = suite.objects[-1]
        original_dis = Path(str(original_emit['Path']) + '.dis')
        original_assembly = Path(str(original_emit['Path']) + '.ltrans0.ltrans.s')
        emitted_assembly = Path(str(emitted) + '.ltrans0.ltrans.s')
        roles = (Path(original['Path']), ordinary, emitted, emitted_machine, original_machine,
            Path(original_emit['Path']), original_dis, Path(original_emit['Map']), emitted_map, dis, startup)
        assembly = {'Original': suite.watch.read(original_assembly), 'Isolated': suite.watch.read(emitted_assembly)}
        port_source = sources['fiber/port/ARM_CM3/fiber_port.c']
        with modules['controls'].reader(suite.admitted, roles) as (core, graph):
            comparisons = dict(OriginalToIsolated=core.compare_load_images(Path(original['Path']), ordinary),
                IsolatedTwins=core.compare_load_images(ordinary, emitted),
                OriginalTwins=core.compare_load_images(Path(original['Path']), Path(original_emit['Path'])))
            for label, machine, final, dump, link_map in (
                    ('Original', original_machine, Path(original_emit['Path']), original_dis, Path(original_emit['Map'])),
                    ('Isolated', emitted_machine, emitted, dis, emitted_map)):
                image = core.FinalImage(machine, final, dump,
                    provider_objects={str(machine): machine, str(startup): startup}, link_map=link_map, float_abi='soft')
                proof = modules['slot'].inspect(port_source, assembly[label], image, core)
                require_slot_result(proof, port_source, assembly[label], image)
                suite.report['SlotProofs'].append(dict(Kind=label, Proof=proof))
        suite.watch.close()
        suite.report.update(WholeSlotAccessIsolation=True, PositiveLinkRevalidated=True,
            LoadImageComparisons=comparisons, ExecutedReaderBuffers=graph.executed,
            IsolatedLinkedObjects=[dict(Path=str(path), Sha256=sha(suite.watch.read(path))) for path in objects],
            IsolatedLinkMap=str(ordinary_map), EmitLinkDelta=['-Wl,--emit-relocs'])
        suite._isolation_done = True
    except BaseException as failure:
        error = failure
    return suite.finish(error)


def succeeded(report):
    return (type(report) is dict and report.get('Status') == PASS and report.get('Scope') == SCOPE
        and report.get('Profile') == 'CM3' and report.get('Mode') == 'O2-lto'
        and report.get('Linkage') == 'direct' and report.get('LTO') is True
        and report.get('Error') is None and report.get('PrimaryError') is None and report.get('ClosingErrors') == []
        and all(report.get(name) is True for name in PHASES)
        and all(report.get(name) is False for name in FALSE_CLAIMS)
        and type(report.get('RequiredCellsSatisfied')) is int and report['RequiredCellsSatisfied'] == 0
        and type(report.get('RequiredCellCount')) is int and report['RequiredCellCount'] == 2774
        and report.get('RawIRIdentityClaim') is False and commands_pass(report.get('Commands'))
        and report.get('WholeSlotAccessIsolationScope') == 'SECTION_MEDIATED_CURRENT_CM3_O2_LTO_ONLY'
        and evidence_records_pass(report))


def evidence_records_pass(report):
    """Receipt shape closure supplements, never replaces, the executed readers."""
    def digest(value):
        return type(value) is str and re.fullmatch(r'[0-9A-F]{64}', value) is not None
    rows = report.get('IsolatedCommon')
    if type(rows) is not list or len(rows) != 3:
        return False
    for index, row in enumerate(rows):
        if not (type(row) is dict and type(row.get('TemplateIndex')) is int and row['TemplateIndex'] == index
                and type(row.get('Source')) is str and row['Source'].replace('\\', '/').endswith('/' + COMMON[index])
                and digest(row.get('SourceSha256')) and digest(row.get('ObjectSha256'))
                and type(row.get('Object')) is str and row['Object']
                and all(row.get(name) is True for name in ('CompileDependenciesVerified', 'ForcedMainHeaderRemoved',
                    'CmsisAndSelectedPortIncludesRemoved'))
                and row.get('RawIRIdentityClaim') is False and row.get('SourceToMachineSemanticProof') is False
                and row.get('CommandIndices') == list(range(index * 3, index * 3 + 3))
                and all(type(value) is int for value in row['CommandIndices'])):
            return False
        slim = row.get('SlimIR')
        if not (type(slim) is dict and slim.get('SlimIR') is True and slim.get('Object') == row['Object']
                and slim.get('Sha256') == row['ObjectSha256'] and type(slim.get('Sections')) is list and slim['Sections']):
            return False
        for name in ('CompileFlags', 'OriginalCompileFlags'):
            flags = row.get(name)
            if not (type(flags) is list and all(type(flag) is str for flag in flags)
                    and flags.count('-flto') == flags.count('-fno-fat-lto-objects') == flags.count('-O2') == 1):
                return False
        dependencies = row.get('Dependencies')
        if not (type(dependencies) is list and dependencies and row.get('DiscoveryDependencies') == dependencies
                and all(type(item) is dict and type(item.get('Path')) is str and item['Path']
                    and digest(item.get('Sha256')) for item in dependencies)):
            return False
    slots = report.get('SlotProofs')
    if type(slots) is not list or len(slots) != 2:
        return False
    for label, row in zip(('Original', 'Isolated'), slots):
        if not (type(row) is dict and row.get('Kind') == label and type(row.get('Proof')) is dict):
            return False
        proof = row['Proof']
        if not (proof.get('SlotIsolationValidated') is True
                and proof.get('AllSectionMediatedSlotReferencesValidated') is True
                and proof.get('CompleteHandlerBodiesValidated') is False
                and type(proof.get('HandlerLoads')) is list and len(proof['HandlerLoads']) == 2
                and type(proof.get('CommonBodies')) is list and len(proof['CommonBodies']) == 6
                and all(type(body) is dict and body.get('CompleteBodyValidated') is True
                    and digest(body.get('MachineBodySha256')) and digest(body.get('FinalBodySha256'))
                    for body in proof['CommonBodies'])
                and all(digest(proof.get(name)) for name in ('SourceSha256', 'AssemblySha256', 'MachineSha256',
                    'FinalSha256', 'LinkMapSha256'))):
            return False
    comparisons = report.get('LoadImageComparisons')
    return (type(comparisons) is dict and set(comparisons) == {'OriginalToIsolated', 'IsolatedTwins', 'OriginalTwins'}
        and all(type(row) is dict and row.get('Identical') is True and type(row.get('Segments')) is list
            and row['Segments'] for row in comparisons.values()))


def revoke_failure(suite, error):
    """Revoke isolation before a fallible hook; bounded diagnostic writes only."""
    report = suite.report
    message = type(error).__name__ + ': ' + str(error)
    report['PrimaryError'] = report.get('PrimaryError') or report.get('Error') or message
    report['Error'] = report.get('Error') or message
    closing = report.setdefault('ClosingErrors', [])

    def force():
        report.update(Status='FAIL', **{name: False for name in PHASES},
            TypedDeclarationProbesValidated=False, FiveLinkControlsValidated=False)
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
        force()
        try:
            suite.modules['controls'].persist_failure(suite)
            break
        except BaseException as secondary:
            closing.append('failure persistence %d: %s: %s' % (attempt + 1, type(secondary).__name__, secondary))
        finally:
            force()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('capture-build', 'capture-receipt-sha256', 'capture-artifacts-sha256', 'inventory',
                 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    suite = modules = None
    try:
        suite, modules = prepare(parser.parse_args(argv))
        report = run(suite, modules)
        need(succeeded(report), 'sealed isolation component: ' + str(report.get('Error')))
        print(json.dumps({key: report[key] for key in ('Status', 'Scope', 'CpuFreeCommonValidated',
            'WholeSlotAccessIsolation', 'InputClosureVerified', 'OutputSealVerified', 'RequiredCellsSatisfied')},
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
