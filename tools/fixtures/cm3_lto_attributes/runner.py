"""Fresh actual-three-TU CM3 hostile slim-LTO attribute-effect component."""
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
PASS = 'CURRENT-CM3-LTO-ATTRIBUTES-PASS-NOT-QUALIFIED'
SCOPE = 'CURRENT_NATIVE_CM3_O2_LTO_CONTEXT_ATTRIBUTE_EFFECT_COMPONENT_ONLY'
PINS = {
    'controls': ('tools/fixtures/cm3_lto_abi_controls/controls.py',
        '7984A228966FC17641BD83D23486DB7E50BC2B7E5BC12D70A712F6E83800F14F'),
    'ownership': ('tools/fixtures/cm0_final_cell/ownership.py',
        'F9971A707BC30FFA7AF0B816570ED476B2965F24369BC7A747C18784E5B0A552'),
    'attributes': ('tools/fixtures/cm3_lto_attributes/attributes.py',
        '93275A5903A67CB2DAEABB76BEF1431B052878BB478455E54343DB20881E83C0'),
    'contract': ('tools/fixtures/cm3_lto_attributes/CONTRACT.md',
        '47E6E37823358DD1025A1BA5D6A5491F1A2A1FF91FAC62CB20B2F00D7F22635F'),
}
ROLES = ('engine', 'state', 'panic')
COMMON = ('context/context_core.c', 'context/context_runtime_state.c', 'context/context_panic.c')
LOWERS = ('positive', 'mutant-engine', 'mutant-state', 'mutant-panic', 'stress-protected', 'stress-unprotected')
ROOTS = ('fiber_internal_task_return', 'ctxrt_v1_init', 'ctxrt_v1_current', 'ctxrt_v1_start',
    'ctxrt_v1_set_dispatcher', 'ctxrt_v1_yield', 'fiber_internal_runtime_load_current_context',
    'fiber_internal_runtime_select_scheduler_candidate', 'fiber_internal_runtime_publish_current_context',
    'fiber_internal_runtime_require_current_context', 'fiber_internal_scheduler_is_configured',
    'fiber_internal_runtime_close_context_configuration', 'fiber_internal_runtime_context_configuration_is_open',
    'fiber_panic')
MUTANTS = dict(zip(LOWERS[1:4], ('ctxrt_v1_current', 'fiber_internal_runtime_load_current_context', 'fiber_panic')))
PHASES = ('SourceAnnotationsValidated', 'CpuFreeHostileCommonValidated', 'DriverAdapterValidated',
    'ActualLtransOptionsValidated', 'ProtectedEffectsValidated', 'AnnotationControlsValidated',
    'DispatcherStressValidated', 'InputClosureVerified', 'OutputSealVerified')
FALSE_CLAIMS = ('Qualification', 'CellContractSatisfied', 'RequiredCellSatisfied', 'FullABIProof',
    'FullSemanticABIProof', 'SourceIRProof', 'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership',
    'FinalReferenceParity', 'CanonicalProtocolValidated', 'PolicyEquivalence', 'ArchiveExtraction',
    'CpuExecution', 'BoardExecution', 'HostedCIQualified', 'GlobalFreezeQualified',
    'TypedDeclarationProbesValidated', 'FiveLinkControlsValidated', 'WholeSlotAccessIsolation',
    'PositiveLinkRevalidated', 'GeneralRegistersOnlyEffectProved', 'FullAttributeEquivalence',
    'TransitiveProtection', 'RuntimeLibraryProvided')


def need(condition, message):
    if not condition:
        raise ValueError('cm3-lto-attribute-runner: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def load(name, path, raw):
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def flags_for(suite, index, root):
    original = suite.source(index)['CompileFlags']
    need(type(original) is list and all(original.count(flag) == 1
        for flag in ('-flto', '-fno-fat-lto-objects', '-O2')), 'actual captured slim-O2 flags')
    seed_root = suite.base / 'source'
    result = suite.modules['probes'].isolated_flags(original, seed_root)
    replacements = {'-I' + str(seed_root / name): '-I' + str(root / name)
        for name in ('context', 'fiber')}
    replacements['-I' + str(seed_root)] = '-I' + str(root)
    need(all(result.count(flag) == 1 for flag in replacements), 'three canonical isolated includes')
    result = [replacements.get(flag, flag) for flag in result]
    raw = list(suite.modules['attributes'].HOSTILE_FLAGS)
    need(not any(flag in result for flag in raw), 'hostile flags added exactly once')
    return result + raw


def command_plan():
    result = ['dump compiler specs']
    for group, names in (('positive', tuple(Path(name).stem for name in COMMON)),
            *((name, (Path(COMMON[index]).stem,)) for index, name in enumerate(LOWERS[1:4])),
            ('stress-protected', ('stress',)), ('stress-unprotected', ('stress',))):
        for stem in names:
            result.extend(('discover ' + group + ' ' + stem, 'compile ' + group + ' ' + stem,
                'inspect slim ' + stem, 'imports ' + group + ' ' + stem))
        result.extend(('lower ' + group, 'disassemble ' + group))
    return tuple(result)


def commands_pass(commands):
    return (type(commands) is list
        and tuple(row.get('Label') for row in commands if type(row) is dict) == command_plan()
        and all(type(row) is dict and row.get('State') == 'TERMINAL' and row.get('Status') == 'PASS'
            and type(row.get('Exit')) is int and row['Exit'] == 0
            and type(row.get('ExpectedExit')) is int and row['ExpectedExit'] == 0
            and row.get('TimedOut') is False and not row.get('JournalErrors') for row in commands))


def compile_ir(suite, group, index, root, sources, *, stress=False):
    """Discovery and actual compile consume only admitted or exact copied bytes."""
    need(type(index) is int and 0 <= index < 3 and group in LOWERS, 'fixed compile role')
    relative = 'stress.c' if stress else COMMON[index]
    source = root / relative
    need(relative in sources, 'source bytes are prebound')
    suite.watch.read(source, sha(sources[relative]))
    flags = flags_for(suite, index, root)
    directory = suite.output / 'ir' / group
    directory.mkdir(parents=True, exist_ok=True)
    obj = directory / (source.stem + '.o')
    discovery, actual = obj.with_suffix('.discovery.d'), obj.with_suffix('.compile.d')
    target, start = 'pilot-source-' + str(index), len(suite.commands)
    original_root = suite.base / 'source'
    admitted = {}
    for row in suite.sources[:3]:
        for item in row['ActualCompileDependencies']:
            path = Path(item['Path'])
            if not path.is_relative_to(original_root):
                need(path not in admitted or admitted[path] == item['Sha256'], 'unique tool header bytes')
                admitted[path] = item['Sha256']
    admitted.update({root / name: sha(raw) for name, raw in sources.items()})

    def dependencies(path):
        paths = [suite.api.checked_path(name) for name in suite.native.read_dependencies(path)]
        records = suite.modules['probes'].isolated_dependencies(paths, admitted,
            root=root, cmsis=suite.base / 'cmsis')
        need(source in paths, 'dependency set includes actual source')
        for item in records:
            suite.watch.read(item['Path'], item['Sha256'])
        return records

    gcc = str(suite.tools['gcc'])
    result = suite.command([gcc, *flags, '-M', '-MF', str(discovery), '-MT', target, str(source)],
        'discover ' + group + ' ' + source.stem)
    need(result.stdout == result.stderr == b'', 'clean dependency discovery')
    suite.record_output(discovery)
    before = dependencies(discovery)
    result = suite.command([gcc, *flags, '-MD', '-MF', str(actual), '-MT', target,
        '-c', str(source), '-o', str(obj)], 'compile ' + group + ' ' + source.stem)
    need(result.stdout == result.stderr == b'', 'clean hostile compilation')
    suite.record_output(actual)
    record = suite.record_output(obj)
    note = suite.record_output(obj.with_suffix('.gcno'), required=False)
    after = dependencies(actual)
    suite.native.require_compile_dependencies(before, after)
    slim = suite.inspect_ir(obj)
    names, imports = suite._undefined(obj, group + ' ' + source.stem)
    role = ROLES[index]
    if not stress:
        identity = suite.modules['attributes'].inspect_ir_undefined(names, role,
            mutation=group != 'positive')
    else:
        # Machine effects, not plugin IR names, decide the annotation controls.
        need(set(names) <= set(suite.modules['attributes'].HOOKS)
            | set(suite.modules['attributes'].FORWARD) | set(suite.modules['attributes'].PROTECTED)
            | {suite.modules['attributes'].COLD}, 'bounded private-control IR dependencies')
        identity = dict(UndefinedValidated=True, MachineCodeValidated=False, Control=True)
    row = dict(Group=group, Role=role, TemplateIndex=index, Source=str(source),
        SourceSha256=sha(sources[relative]), Object=str(obj), ObjectSha256=record['Sha256'],
        OriginalCompileFlags=suite.source(index)['CompileFlags'], CompileFlags=flags,
        SlimIR=slim, IRImports=imports, IRImportProof=identity, CoverageNotes=note,
        DiscoveryDependencies=before, Dependencies=after, CompileDependenciesVerified=True,
        CommandIndices=list(range(start, len(suite.commands))), CpuFreeIncludes=True,
        RawIRIdentityClaim=False, SourceToMachineSemanticProof=False)
    suite.report['Compilations'].append(row)
    return obj


def argument_lines(raw):
    need(type(raw) is bytes and raw and b'\x00' not in raw, 'saved arguments bytes')
    lines = raw.decode('utf-8').splitlines()
    need(all(line and line == line.strip() for line in lines), 'saved argument grammar')
    # GCC's save-temps argument serialization doubles Windows backslashes.
    return [line.replace('\\\\', '\\') for line in lines]


def worker_diagnostics(suite, raw, lowered):
    """Bind compiler-reported executed WPA/LTRANS commands, not copied metadata."""
    need(type(raw) is bytes and raw and raw.isascii() and b'\x00' not in raw, 'verbose worker transcript')
    text = raw.decode('ascii')
    need(not re.search(r'(?im)(?:^|\s)(?:fatal error|error|warning):', text), 'no lower warnings/errors')
    lines = [line.strip() for line in text.splitlines() if re.match(r'^\s+\S+[/\\]lto1[.]exe ', line)]
    need(len(lines) == 2, 'one actual WPA and one actual LTRANS invocation')
    records = []
    for line, marker, response in ((lines[0], '-fwpa', str(lowered) + '.wpa.args.0'),
            (lines[1], '-fltrans', str(lowered) + '.ltrans0.ltrans.args.0')):
        need('"' not in line and "'" not in line, 'bounded unquoted captured worker invocation')
        values = line.split()
        executable = suite.api.checked_path(suite.admitted.base.stable_path(values[0]))
        expected = suite.result['ResolvedWorkers']['lto1']
        need(executable == Path(expected['Path']) and marker in values
            and values.count('@' + response) == 1, 'actual worker executable/stage/response identity')
        need(all(flag in values for flag in suite.modules['attributes'].HOSTILE_FLAGS),
            'all six raw flags reach actual lto1 invocation')
        need([value for value in values if value.startswith('@')] == ['@' + response],
            'no unbound worker response input')
        if marker == '-fltrans':
            need(values.count('-o') == 1 and values[values.index('-o') + 1]
                == str(lowered) + '.ltrans0.ltrans.s', 'actual LTRANS assembly output')
        suite.watch.read(executable, expected['Sha256'])
        records.append(dict(Stage=marker, Executable=str(executable), ExecutableSha256=expected['Sha256'],
            Argv=values, Response=response, ResponseSha256=sha(suite.watch.read(Path(response)))))
    assembly_lines = [line.strip() for line in text.splitlines() if re.match(r'^\s+\S+[/\\]as[.]exe ', line)]
    need(len(assembly_lines) == 1, 'one actual machine-producing assembler invocation')
    values = assembly_lines[0].split()
    expected = suite.result['ResolvedWorkers']['as']
    executable = suite.api.checked_path(suite.admitted.base.stable_path(values[0]))
    need(executable == Path(expected['Path']) and values.count('-o') == 1
        and values[values.index('-o') + 1] == str(lowered) + '.ltrans0.ltrans.o'
        and values[-1] == str(lowered) + '.ltrans0.ltrans.s'
        and not any(value.startswith('@') for value in values), 'assembler exact executable and machine chain')
    suite.watch.read(executable, expected['Sha256'])
    return dict(CompilerReportedWorkerExecutionVerified=True, OsProcessTraceVerified=False,
        TranscriptSha256=sha(raw), WorkerInvocations=records,
        Assembler=dict(Executable=str(executable), ExecutableSha256=expected['Sha256'], Argv=values))


def worker_chain(suite, lowered, objects, specs, diagnostics):
    prefix = str(lowered)
    wpa_file = Path(prefix + '.ltrans_args')
    worker_file = Path(prefix + '.ltrans0.ltrans_args')
    wpa_raw, worker_raw = suite.watch.read(wpa_file), suite.watch.read(worker_file)
    proof = suite.modules['attributes'].require_hostile_options(wpa_raw, worker_raw)
    wpa, worker = argument_lines(wpa_raw), argument_lines(worker_raw)
    expected_spec = '-specs=' + str(specs)
    for values in (wpa, worker):
        need(values.count(expected_spec) == 1, 'exact owned specs on actual worker')
    need([value for value in wpa if value.endswith('.o')] == [str(path) for path in objects],
        'WPA consumes exact ordered IR cohort')
    need(argument_lines(suite.watch.read(Path(prefix + '.wpa.args.0'))) == [str(path) for path in objects],
        'actual WPA response consumes exact ordered IR cohort')
    intermediate = Path(prefix + '.ltrans0.o')
    machine = Path(prefix + '.ltrans0.ltrans.o')
    need(worker[-1] == str(intermediate) and worker.count('-o') == 1
        and worker[worker.index('-o') + 1] == str(machine), 'LTRANS exact input/output chain')
    args0 = argument_lines(suite.watch.read(Path(prefix + '.ltrans0.ltrans.args.0')))
    need(args0 == [str(intermediate)], 'LTRANS input response bytes')
    listed = suite.watch.read(Path(prefix + '.ltrans.out')).decode('ascii').splitlines()
    need(len(listed) == 2 and re.fullmatch(r'[0-9]+', listed[0])
        and listed[1] == str(intermediate), 'WPA one-partition output list')
    result = suite.transport.require_elf32le(suite.watch.read(machine))
    proof.update(WpaArguments=str(wpa_file), LtransArguments=str(worker_file),
        WpaInputs=[dict(Path=str(path), Sha256=sha(suite.watch.read(path))) for path in objects],
        Intermediate=str(intermediate), IntermediateSha256=sha(suite.watch.read(intermediate)),
        Machine=str(machine), MachineSha256=sha(suite.watch.read(machine)),
        MachineHeader=result, DriverSpecs=str(specs), DriverSpecsSha256=sha(suite.watch.read(specs)),
        AdmittedResolvedWorker=copy.deepcopy(suite.result['ResolvedWorkers']['lto1']),
        Execution=worker_diagnostics(suite, diagnostics, lowered))
    return machine, proof


def lower(suite, group, objects, specs, *, mutation=None, stress=False):
    need(group in LOWERS and len(objects) == (1 if stress else 3), 'exact lowering cohort')
    directory = suite.output / 'lowered' / group
    need(not directory.exists(), 'fresh lower namespace')
    directory.mkdir(parents=True)
    lowered = directory / 'aggregate.o'
    root = suite.base / 'source'
    flags = flags_for(suite, 0, root)
    start = len(suite.commands)
    result = suite.command([str(suite.tools['gcc']), *flags, '-specs=' + str(specs), '-v',
        '-flto-partition=one', '-save-temps=obj', '-Wl,-plugin-opt=-save-temps',
        '-nostdlib', '-r', '-flinker-output=nolto-rel', *(str(path) for path in objects),
        '-o', str(lowered)], 'lower ' + group)
    need(result.stdout == b'' and result.stderr, 'retained actual verbose hostile lowering')
    diagnostics = result.stderr
    fixed = {'aggregate.o', 'aggregate.o.ltrans.out', 'aggregate.o.ltrans0.ltrans.args.0',
        'aggregate.o.ltrans0.ltrans.o', 'aggregate.o.ltrans0.ltrans.s', 'aggregate.o.ltrans0.ltrans_args',
        'aggregate.o.ltrans0.o', 'aggregate.o.ltrans_args', 'aggregate.o.res', 'aggregate.o.wpa.args.0'}
    optional = {'aggregate.o.wpa.gcno', 'aggregate.o.ltrans0.ltrans.gcno', 'aggregate.o.lto_wrapper_args'}
    actual = suite.api.files_under(directory)
    need(fixed <= set(actual) <= fixed | optional, 'complete bounded genuine lowering outputs')
    for path in actual.values():
        suite.record_output(path)
    local_wrapper = directory / 'aggregate.o.lto_wrapper_args'
    external_wrapper = suite.output / (''.join(lowered.parts[1:]) + '.lto_wrapper_args')
    need(local_wrapper.exists() is not external_wrapper.exists(), 'one saved wrapper argument owner')
    wrapper = local_wrapper if local_wrapper.exists() else external_wrapper
    suite.record_output(wrapper)
    machine, chain = worker_chain(suite, lowered, objects, specs, diagnostics)
    result = suite.command([str(suite.tools['objdump']), '-drwC', str(lowered)], 'disassemble ' + group)
    need(result.stdout and result.stderr == b'', 'clean real machine disassembly')
    dis = suite.write_input('lowered/' + group + '/aggregate.dis', result.stdout)
    suite.watch.close()
    row = dict(Group=group, Object=str(lowered), ObjectSha256=sha(suite.watch.read(lowered)),
        Inputs=[dict(Path=str(path), Sha256=sha(suite.watch.read(path))) for path in objects],
        ActualWorker=chain, Disassembly=str(dis), Mutation=mutation, Stress=stress,
        DisassemblySha256=sha(result.stdout), WrapperArgs=str(wrapper),
        CommandIndices=list(range(start, len(suite.commands))))
    suite.report['Lowerings'].append(row)
    return row


def inspect_lowerings(suite):
    """One initially fresh immutable parser scope covers all genuine outputs."""
    rows = suite.report['Lowerings']
    need(type(rows) is list and tuple(row['Group'] for row in rows) == LOWERS, 'exact six lowering groups')
    paths = tuple(Path(path) for row in rows for path in (row['Object'], row['ActualWorker']['Machine']))
    need(len(paths) == len(set(paths)) == 12, 'twelve distinct generated machine roles')
    with suite.modules['controls'].reader(suite.admitted, paths) as (core, graph):
        for row in rows:
            mutation, stress = row['Mutation'], row['Stress']
            expected_mutation = 'ctxrt_attribute_stress' if row['Group'] == 'stress-unprotected' else MUTANTS.get(row['Group'])
            need(mutation == expected_mutation and type(stress) is bool
                and stress is row['Group'].startswith('stress-'), 'fixed group mutation/stress role')
            image = core._ELF(Path(row['Object']), 'ET_REL')
            worker_image = core._ELF(Path(row['ActualWorker']['Machine']), 'ET_REL')
            proof = suite.modules['attributes'].inspect_lowered(image, core, mutation=mutation, stress=stress)
            worker_proof = suite.modules['attributes'].inspect_lowered(worker_image, core, mutation=mutation, stress=stress)
            rejected = False
            if mutation is not None:
                try:
                    suite.modules['attributes'].inspect_lowered(image, core, stress=stress)
                except suite.modules['attributes'].Rejected:
                    rejected = True
                need(rejected, 'unchanged protected predicate rejects intended compiled mutant')
            need(proof['UnresolvedAttribution'] == worker_proof['UnresolvedAttribution'] == [],
                'no unproved inline attribution')
            need(proof['Status'] == worker_proof['Status'] and proof['Undefined'] == worker_proof['Undefined'],
                'worker and combined lower agree on attribute disposition')
            row.update(Effects=proof, WorkerEffects=worker_proof, OriginalProtectedPredicateRejected=rejected)
        suite.report['ExecutedReaderBuffers'] = copy.deepcopy(graph.executed)
    suite.watch.close()


def suite_type(base_class):
    class Suite(base_class):
        def __init__(self, args, admitted, modules, buffers):
            super().__init__(args, admitted, modules, buffers)
            self.report.update(Status='FAIL', Scope=SCOPE,
                **{name: False for name in (*FALSE_CLAIMS, *PHASES)},
                Compilations=[], Lowerings=[], AnnotationControls=[], RawIRIdentityClaim=False)
            self._attributes_done = False

        def _failure(self, error):
            self.report.update(Status='FAIL', **{name: False for name in PHASES})
            try:
                super()._failure(error)
            finally:
                self.report.update(Status='FAIL', **{name: False for name in PHASES})

        def finish(self, error=None):
            need(not self._finished, 'finish exactly once')
            if error is None and not (self._attributes_done and commands_pass(self.commands)
                    and all(self.report[name] is True for name in PHASES[:-2])):
                error = ValueError('incomplete hostile attribute phases or commands')
            self._finished = True
            if error is not None:
                revoke_failure(self, error)
                return copy.deepcopy(self.report)
            try:
                self.verify_objects()
                self.watch.close()
                self._verify_outputs()
                self.report.update(Status=PASS, OutputSealVerified=True, InputClosureVerified=True,
                    Commands=self.commands, CommandsSha256=self.expected['commands.json'],
                    InputHashes={str(path): digest for path, digest in sorted(self.watch.hashes.items())},
                    InputPhysicalIdentities={str(path): self.admitted.identity(path) for path in sorted(self.watch.hashes)},
                    ClosingFilesVerified=len(self.watch.hashes))
                need(succeeded(self.report), 'complete effects verdict before seal')
                self._save('results.json', self.report)
                self._save('artifacts.json', dict(Artifacts={name: digest for name, digest in self.expected.items()
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
    own = Path(__file__).resolve()
    buffers[own] = own.read_bytes()
    modules = {name: load('cm3_attribute_' + name, ROOT / path, buffers[ROOT / path])
        for name, (path, _) in PINS.items() if name != 'contract'}
    original, inherited = modules['controls'].prepare(args)
    inherited.update(modules)
    suite = suite_type(type(original))(args, original.admitted, inherited, buffers)
    return suite, inherited


def source_buffers(suite):
    root = suite.base / 'source'
    paths = set(suite.modules['ownership'].REQUIRED_SOURCES)
    for row in suite.sources[:3]:
        for dep in row['ActualCompileDependencies']:
            path = Path(dep['Path'])
            if path.is_relative_to(root) and not path.is_relative_to(root / 'tools/fixtures/classic_final_image'):
                paths.add(path.relative_to(root).as_posix())
    result = {}
    for name in sorted(paths):
        key = 'source/' + name
        need(key in suite.bundle['Artifacts'], 'admitted source-copy authority: ' + name)
        result[name] = suite.watch.read(root / name, suite.bundle['Artifacts'][key])
    return result


def copy_sources(suite, label, buffers):
    root = suite.output / 'private' / label
    need(not root.exists(), 'fresh private source namespace')
    for name, raw in sorted(buffers.items()):
        suite.write_input('private/' + label + '/' + name, raw)
    return root


def run(suite, modules):
    error = None
    try:
        suite.start()
        sources = source_buffers(suite)
        suite.report['SourceOwnership'] = modules['ownership'].validate_common_sources(
            {name: sources[name] for name in modules['ownership'].REQUIRED_SOURCES})
        suite.report['SourceAnnotations'] = modules['attributes'].inspect_sources(sources)
        suite.report['SourceAnnotationsValidated'] = True
        result = suite.command([str(suite.tools['gcc']), '-dumpspecs'], 'dump compiler specs')
        need(result.stdout and result.stderr == b'', 'clean authenticated fresh dumpspecs')
        original_specs = suite.write_input('driver/original.specs', result.stdout)
        adapter = modules['attributes'].adapt_specs(result.stdout)
        specs = suite.write_input('driver/no-auto-gcov.specs', adapter['Specs'])
        suite.report['DriverAdapter'] = {key: value for key, value in adapter.items() if key != 'Specs'}
        suite.report['DriverAdapter'].update(OriginalPath=str(original_specs), AdaptedPath=str(specs))
        suite.report['DriverAdapterValidated'] = True
        positive = [compile_ir(suite, 'positive', index, suite.base / 'source', sources) for index in range(3)]
        suite.report['CpuFreeHostileCommonValidated'] = True
        lower(suite, 'positive', positive, specs)
        for index, role in enumerate(ROLES):
            plan = modules['attributes'].annotation_mutant(role, sources)
            label = 'mutant-' + role
            root = copy_sources(suite, label, plan['Sources'])
            replacement = compile_ir(suite, label, index, root, plan['Sources'])
            objects = list(positive)
            objects[index] = replacement
            lower(suite, label, objects, specs, mutation=plan['Function'])
            suite.report['AnnotationControls'].append(dict(Role=role, Function=plan['Function'], Edits=plan['Edits'],
                ReplacedIRRole=role, UnchangedIR=[str(path) for path in positive if path != positive[index]],
                Detected=False, OriginalProtectedPredicateRejected=False))
        stress = modules['attributes'].stress_sources()
        for name, key, mutation in (('stress-protected', 'Protected', None),
                ('stress-unprotected', 'Unprotected', modules['attributes'].STRESS)):
            inputs = dict(sources, **{'stress.c': stress[key]})
            root = copy_sources(suite, name, inputs)
            obj = compile_ir(suite, name, 0, root, inputs, stress=True)
            lower(suite, name, [obj], specs, mutation=mutation, stress=True)
        inspect_lowerings(suite)
        for control, lowered in zip(suite.report['AnnotationControls'], suite.report['Lowerings'][1:4]):
            control.update(Detected=lowered['Effects']['CompiledAnnotationMutantDetected'],
                OriginalProtectedPredicateRejected=lowered['OriginalProtectedPredicateRejected'])
        suite.report.update(ProtectedEffectsValidated=True, AnnotationControlsValidated=True,
            DispatcherStressValidated=True, ActualLtransOptionsValidated=True,
            PairedStress=dict(Function=stress['Function'], RequiredFamilies=stress['RequiredFamilies'],
                OnlyDifference=stress['OnlyDifference'], ProtectedSha256=sha(stress['Protected']),
                UnprotectedSha256=sha(stress['Unprotected'])))
        suite._attributes_done = True
    except BaseException as failure:
        error = failure
    return suite.finish(error)


def succeeded(report):
    if not (type(report) is dict and report.get('Status') == PASS and report.get('Scope') == SCOPE
            and report.get('Profile') == 'CM3' and report.get('Mode') == 'O2-lto'
            and report.get('Linkage') == 'direct' and report.get('LTO') is True
            and report.get('Error') is None and report.get('PrimaryError') is None and report.get('ClosingErrors') == []
            and all(report.get(name) is True for name in PHASES)
            and all(report.get(name) is False for name in FALSE_CLAIMS)
            and type(report.get('RequiredCellsSatisfied')) is int and report['RequiredCellsSatisfied'] == 0
            and type(report.get('RequiredCellCount')) is int and report['RequiredCellCount'] == 2774
            and report.get('RawIRIdentityClaim') is False and commands_pass(report.get('Commands'))):
        return False
    compiled, lowered, mutants = (report.get(name) for name in ('Compilations', 'Lowerings', 'AnnotationControls'))
    if not (type(compiled) is list and len(compiled) == 8
            and type(lowered) is list and len(lowered) == 6
            and type(mutants) is list and len(mutants) == 3):
        return False
    for group, row in zip(LOWERS, lowered):
        if not (type(row) is dict and row.get('Group') == group
                and worker_evidence_pass(row.get('ActualWorker'))
                and effects_pass(row.get('Effects'), group, row.get('ObjectSha256'))
                and effects_pass(row.get('WorkerEffects'), group, row['ActualWorker'].get('MachineSha256'))):
            return False
        mutation = group.startswith('mutant-') or group == 'stress-unprotected'
        expected = ('CONTEXT-LTO-ANNOTATION-MUTANT-DETECTED' if mutation else
            'CONTEXT-LTO-DIRECT-ATTRIBUTE-CHECKS-PASS')
        if not (row['Effects'].get('Status') == row['WorkerEffects'].get('Status') == expected
                and row.get('OriginalProtectedPredicateRejected') is mutation):
            return False
    return (all(type(row) is dict and row.get('CompileDependenciesVerified') is True
        and row.get('CpuFreeIncludes') is True and type(row.get('SlimIR')) is dict
        and row['SlimIR'].get('SlimIR') is True for row in compiled)
        and all(type(row) is dict and row.get('Role') == role and row.get('Detected') is True
            and row.get('OriginalProtectedPredicateRejected') is True for role, row in zip(ROLES, mutants))
        and lowered[-1]['Effects'].get('StressFamiliesActivated') is True
        and lowered[-2]['Effects'].get('AllProtectedBodiesClean') is True)


def worker_evidence_pass(proof):
    def digest(value):
        return type(value) is str and re.fullmatch(r'[0-9A-F]{64}', value) is not None
    if not (type(proof) is dict and proof.get('ActualHostileOptionsVerified') is True
            and proof.get('RuntimeLibraryProvided') is False and digest(proof.get('MachineSha256'))
            and digest(proof.get('DriverSpecsSha256')) and type(proof.get('Execution')) is dict):
        return False
    execution = proof['Execution']
    if not (execution.get('CompilerReportedWorkerExecutionVerified') is True
            and execution.get('OsProcessTraceVerified') is False and digest(execution.get('TranscriptSha256'))
            and type(execution.get('WorkerInvocations')) is list and len(execution['WorkerInvocations']) == 2
            and type(execution.get('Assembler')) is dict and digest(execution['Assembler'].get('ExecutableSha256'))
            and type(execution['Assembler'].get('Argv')) is list and execution['Assembler']['Argv']):
        return False
    for marker, row in zip(('-fwpa', '-fltrans'), execution['WorkerInvocations']):
        if not (type(row) is dict and row.get('Stage') == marker and digest(row.get('ExecutableSha256'))
                and digest(row.get('ResponseSha256')) and type(row.get('Argv')) is list
                and marker in row['Argv']):
            return False
    return True


def effects_pass(proof, group, object_hash):
    """Close returned leaf shape; actual frozen-reader execution remains required."""
    def digest(value):
        return type(value) is str and re.fullmatch(r'[0-9A-F]{64}', value) is not None
    stress = group.startswith('stress-')
    names = ('ctxrt_attribute_stress',) if stress else ROOTS
    mutation = 'ctxrt_attribute_stress' if group == 'stress-unprotected' else MUTANTS.get(group)
    if not (type(proof) is dict and digest(object_hash) and proof.get('ObjectSha256') == object_hash
            and proof.get('Scope') == 'CM3_O2_LTO_CONTEXT_ATTRIBUTE_EFFECT_COMPONENT_ONLY'
            and proof.get('UnresolvedAttribution') == []
            and type(proof.get('ProtectedFunctions')) is int and proof['ProtectedFunctions'] == len(names)
            and type(proof.get('RequiredCellCount')) is int and proof['RequiredCellCount'] == 0
            and all(proof.get(name) is False for name in ('TransitiveProtection', 'FullABI', 'FullIRSemantics',
                'FullInstructionSemantics', 'FullAttributeEquivalence', 'CPUExecution', 'BoardExecution',
                'GlobalQualification'))
            and proof.get('AllProtectedBodiesClean') is (mutation is None)
            and proof.get('CompiledAnnotationMutantDetected') is (mutation is not None)
            and proof.get('StressFamiliesActivated') is (group == 'stress-unprotected')
            and proof.get('ThreadSectionValidated') is (not stress)
            and proof.get('OrdinaryColdActivityValidated') is (not stress)
            and proof.get('ColdInlineAttributionValidated') is True):
        return False
    rows = proof.get('RootEvidence')
    if not (type(rows) is list and len(rows) == len(names)):
        return False
    for name, row in zip(names, rows):
        if not (type(row) is dict and row.get('Name') == name and digest(row.get('BodySha256'))
                and type(row.get('InstructionCount')) is int and row['InstructionCount'] > 0
                and type(row.get('References')) is list and type(row.get('MappedData')) is list
                and type(row.get('Symbol')) is dict and row['Symbol'].get('name') == name
                and type(row.get('DirectCompilerEffects')) is int
                and row.get('AnnotationMutant') is (name == mutation)):
            return False
        effects = [ref for ref in row['References'] if type(ref) is dict
            and (ref.get('CompilerHook') is True or ref.get('CompilerCounter') is True)]
        if row['DirectCompilerEffects'] != len(effects) or (name != mutation and effects):
            return False
        if name == mutation:
            transfers = {ref['Target']['name'] for ref in effects
                if ref.get('OriginalHookTransferValidated') is True and type(ref.get('Target')) is dict
                and type(ref['Target'].get('name')) is str}
            required = {'__cyg_profile_func_enter'}
            if name != 'fiber_panic':
                required.add('__cyg_profile_func_exit')
            if not required <= transfers:
                return False
    return True


def revoke_failure(suite, error):
    """Revoke new claims before any fallible inherited failure/persistence hook."""
    report = suite.report
    message = type(error).__name__ + ': ' + str(error)
    report['PrimaryError'] = report.get('PrimaryError') or report.get('Error') or message
    report['Error'] = report.get('Error') or message
    closing = report.setdefault('ClosingErrors', [])

    def force():
        report.update(Status='FAIL', **{name: False for name in PHASES})
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
    suite = None
    try:
        suite, modules = prepare(parser.parse_args(argv))
        report = run(suite, modules)
        need(succeeded(report), 'sealed attribute component: ' + str(report.get('Error')))
        print(json.dumps({key: report[key] for key in ('Status', 'Scope', 'ProtectedEffectsValidated',
            'AnnotationControlsValidated', 'DispatcherStressValidated', 'RequiredCellsSatisfied')}, sort_keys=True), flush=True)
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
