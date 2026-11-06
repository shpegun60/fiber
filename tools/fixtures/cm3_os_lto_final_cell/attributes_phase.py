"""Build-only Os common-attribute phase; all machine effects remain deferred.

The caller authenticates the session, modules and source buffers before output.
Neutral generators/CPP-independent import checks are supplied explicitly. No O2
constructor, flag builder, worker-option verdict, parser or phase driver runs.
This component executes 45 managed commands in [53, 98), never seals a PASS.
"""

import copy
import hashlib
import json
from pathlib import Path


MODE = 'Os-lto'
SCOPE = 'NATIVE_CM3_OS_LTO_COMMON_ATTRIBUTES_BUILD_ONLY_PENDING_READER'
COMMON = ('context/context_core.c', 'context/context_runtime_state.c', 'context/context_panic.c')
ROLES = ('engine', 'state', 'panic')
LOWERS = ('positive', 'mutant-engine', 'mutant-state', 'mutant-panic', 'stress-protected', 'stress-unprotected')
RAW_FLAGS = ('-finstrument-functions', '-fstack-protector-all', '-fprofile-arcs',
             '-ftest-coverage', '-fsanitize=undefined', '-fsanitize-coverage=trace-pc')
MODULES = ('recipes', 'attributes', 'attribute_runner', 'ownership', 'probes')
DEFERRED = ('ProtectedEffectsValidated', 'AnnotationControlsValidated', 'DispatcherStressValidated',
            'ActualLtransOptionsValidated', 'CommonAttributePolicyProven')
HELPER_PINS = {
    'attributes': '93275A5903A67CB2DAEABB76BEF1431B052878BB478455E54343DB20881E83C0',
    'attribute_runner': '9C99D38EACC8F3E3B2B63F343CA79555A66264AC76A3CA11957D2BEB0745987A',
    'ownership': 'F9971A707BC30FFA7AF0B816570ED476B2965F24369BC7A747C18784E5B0A552',
    'probes': '16490A20B1A75C5DBD2D21A5FED988C5BD82F4DE919350985B33491CE473A5F7',
    'recipes': 'C15D57AA9FE3963FF84F22D831F4E1F5F941AC351571AB347ECBC29E9172004B',
}


class Rejected(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected('cm3-os-lto-attributes-phase: ' + message)


def sha(raw):
    need(type(raw) is bytes, 'immutable bytes')
    return hashlib.sha256(raw).hexdigest().upper()


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


def flags_for(suite, index, root, modules):
    need(type(index) is int and 0 <= index < 3, 'common source index')
    original = suite.source(index)['CompileFlags']
    need(original == modules['recipes'].compile_flags(suite.result, index), 'admitted actual Os flags')
    need(type(original) is list and original.count('-Os') == 1
         and not any(flag.startswith('-O') and flag != '-Os' for flag in original), 'sole Os optimization')
    seed = suite.base / 'source'
    result = modules['probes'].isolated_flags(original, seed)
    replacements = {'-I' + str(seed / name): '-I' + str(root / name) for name in ('context', 'fiber')}
    replacements['-I' + str(seed)] = '-I' + str(root)
    need(all(result.count(flag) == 1 for flag in replacements), 'canonical isolated includes')
    need(tuple(modules['attributes'].HOSTILE_FLAGS) == RAW_FLAGS, 'fixed six raw hostile flags')
    need(not any(flag in result for flag in RAW_FLAGS), 'hostile options added exactly once')
    return [replacements.get(flag, flag) for flag in result] + list(RAW_FLAGS)


def _sources(suite, modules):
    root = suite.base / 'source'
    names = set(modules['ownership'].REQUIRED_SOURCES)
    for row in suite.sources[:3]:
        for item in row['ActualCompileDependencies']:
            path = Path(item['Path'])
            if path.is_relative_to(root) and not path.is_relative_to(root / 'tools/fixtures/classic_final_image'):
                names.add(path.relative_to(root).as_posix())
    result = {}
    for name in sorted(names):
        key = 'source/' + name
        need(key in suite.bundle['Artifacts'], 'source-copy membership: ' + name)
        result[name] = suite.watch.read(root / name, suite.bundle['Artifacts'][key])
    return result


def compile_ir(suite, group, index, root, sources, modules, *, stress=False):
    need(type(index) is int and 0 <= index < 3 and group in LOWERS and type(stress) is bool,
         'fixed compile role')
    relative = 'stress.c' if stress else COMMON[index]
    source = root / relative
    need(relative in sources, 'prebound source bytes')
    suite.watch.read(source, sha(sources[relative]))
    flags = flags_for(suite, index, root, modules)
    directory = suite.output / 'attributes/ir' / group
    directory.mkdir(parents=True, exist_ok=True)
    obj = directory / (source.stem + '.o')
    discovery, actual = obj.with_suffix('.discovery.d'), obj.with_suffix('.compile.d')
    target, start = 'pilot-source-' + str(index), len(suite.commands)
    seed, admitted = suite.base / 'source', {}
    for row in suite.sources[:3]:
        for item in row['ActualCompileDependencies']:
            path = Path(item['Path'])
            if not path.is_relative_to(seed):
                need(path not in admitted or admitted[path] == item['Sha256'], 'consistent external header declaration')
                admitted[path] = item['Sha256']
    admitted.update({root / name: sha(raw) for name, raw in sources.items()})

    def dependencies(path):
        paths = [suite.api.checked_path(name) for name in suite.native.read_dependencies(path)]
        rows = modules['probes'].isolated_dependencies(paths, admitted, root=root, cmsis=suite.base / 'cmsis')
        need(source in paths, 'actual source dependency required')
        for item in rows:
            suite.watch.read(item['Path'], item['Sha256'])
        return rows

    gcc = str(suite.tools['gcc'])
    result = suite.command([gcc, *flags, '-M', '-MF', str(discovery), '-MT', target, str(source)],
                           'discover ' + group + ' ' + source.stem)
    need(result.stdout == result.stderr == b'', 'clean dependency discovery')
    suite.record_output(discovery)
    before = dependencies(discovery)
    result = suite.command([gcc, *flags, '-MD', '-MF', str(actual), '-MT', target, '-c', str(source), '-o', str(obj)],
                           'compile ' + group + ' ' + source.stem)
    need(result.stdout == result.stderr == b'', 'clean hostile compilation')
    suite.record_output(actual)
    output = suite.record_output(obj)
    note = suite.record_output(obj.with_suffix('.gcno'), required=False)
    after = dependencies(actual)
    suite.native.require_compile_dependencies(before, after)
    slim = suite.inspect_ir(obj)
    names, imports = suite._undefined(obj, group + ' ' + source.stem)
    if stress:
        attrs = modules['attributes']
        need(set(names) <= set(attrs.HOOKS) | set(attrs.FORWARD) | set(attrs.PROTECTED) | {attrs.COLD},
             'bounded stress IR imports')
        proof = dict(UndefinedValidated=True, MachineCodeValidated=False, Control=True)
    else:
        proof = modules['attributes'].inspect_ir_undefined(names, ROLES[index], mutation=group != 'positive')
    row = dict(Group=group, Role=ROLES[index], TemplateIndex=index, Source=str(source), SourceSha256=sha(sources[relative]),
        Object=str(obj), ObjectSha256=output['Sha256'], OriginalCompileFlags=suite.source(index)['CompileFlags'],
        CompileFlags=flags, SlimIR=slim, IRImports=imports, IRImportProof=proof, CoverageNotes=note,
        DiscoveryDependencies=before, Dependencies=after, CompileDependenciesVerified=True, CpuFreeIncludes=True,
        CommandIndices=list(range(start, len(suite.commands))), RawIRIdentityClaim=False,
        SourceToMachineSemanticProof=False)
    suite.report['Compilations'].append(row)
    return obj, row


def _binding(suite, path):
    return dict(Path=str(path), Sha256=sha(suite.watch.read(path)))


def lower(suite, group, objects, specs, modules, *, mutation=None, stress=False):
    need(group in LOWERS and type(stress) is bool and len(objects) == (1 if stress else 3), 'fixed lower cohort')
    directory = suite.output / 'attributes/lowered' / group
    need(not directory.exists(), 'fresh lowering namespace')
    directory.mkdir(parents=True)
    aggregate = directory / 'aggregate.o'
    flags = flags_for(suite, 0, suite.base / 'source', modules)
    start = len(suite.commands)
    result = suite.command([str(suite.tools['gcc']), *flags, '-specs=' + str(specs), '-v',
        '-flto-partition=one', '-save-temps=obj', '-Wl,-plugin-opt=-save-temps', '-nostdlib', '-r',
        '-flinker-output=nolto-rel', *(str(path) for path in objects), '-o', str(aggregate)], 'lower ' + group)
    need(result.stdout == b'' and result.stderr, 'actual verbose lower transcript')
    fixed = {'aggregate.o', 'aggregate.o.ltrans.out', 'aggregate.o.ltrans0.ltrans.args.0',
        'aggregate.o.ltrans0.ltrans.o', 'aggregate.o.ltrans0.ltrans.s', 'aggregate.o.ltrans0.ltrans_args',
        'aggregate.o.ltrans0.o', 'aggregate.o.ltrans_args', 'aggregate.o.res', 'aggregate.o.wpa.args.0'}
    optional = {'aggregate.o.wpa.gcno', 'aggregate.o.ltrans0.ltrans.gcno', 'aggregate.o.lto_wrapper_args'}
    actual = suite.api.files_under(directory)
    need(fixed <= set(actual) <= fixed | optional, 'complete bounded lowering outputs')
    for path in actual.values():
        suite.record_output(path)
    local = directory / 'aggregate.o.lto_wrapper_args'
    external = suite.output / (''.join(aggregate.parts[1:]) + '.lto_wrapper_args')
    need(local.exists() is not external.exists(), 'one saved wrapper owner')
    wrapper = local if local.exists() else external
    suite.record_output(wrapper)
    disassembled = suite.command([str(suite.tools['objdump']), '-drwC', '-z', str(aggregate)], 'disassemble ' + group)
    need(disassembled.stdout and disassembled.stderr == b'', 'clean zero-inclusive generated disassembly')
    dis = suite.write_input('attributes/lowered/' + group + '/aggregate.dis', disassembled.stdout)
    role_paths = dict(Object=aggregate, Machine=Path(str(aggregate) + '.ltrans0.ltrans.o'), Disassembly=dis,
        WpaArguments=Path(str(aggregate) + '.ltrans_args'), LtransArguments=Path(str(aggregate) + '.ltrans0.ltrans_args'),
        WpaResponse=Path(str(aggregate) + '.wpa.args.0'), LtransResponse=Path(str(aggregate) + '.ltrans0.ltrans.args.0'),
        PartitionList=Path(str(aggregate) + '.ltrans.out'), Intermediate=Path(str(aggregate) + '.ltrans0.o'),
        Resolution=Path(str(aggregate) + '.res'), Assembly=Path(str(aggregate) + '.ltrans0.ltrans.s'),
        WrapperArgs=wrapper, DriverSpecs=specs, Diagnostics=suite.output / ('commands/%03d.stderr' % start))
    row = dict(Group=group, Inputs=[_binding(suite, path) for path in objects], Mutation=mutation, Stress=stress,
        Roles={name: _binding(suite, path) for name, path in role_paths.items()},
        CommandIndices=list(range(start, len(suite.commands))), DisassemblyIncludesZeroes=True,
        WorkerOptionsValidated=False, EffectsValidated=False, ValidationDeferred=True)
    suite.watch.close()
    return row


def _commands(suite, recipes):
    expected = recipes.batch_plan()['Commands'][53:98]
    rows = suite.commands[53:]
    need(len(rows) == len(expected) == 45 and tuple(item['Label'] for item in expected) == command_plan(),
         'exact CommonAttributes recipe labels and range')
    for actual, wanted in zip(rows, expected):
        need(type(actual) is dict and actual.get('Label') == wanted['Label'] and wanted['ExpectedExit'] == 0
             and actual.get('State') == 'TERMINAL' and actual.get('Status') == 'PASS'
             and actual.get('TimedOut') is False and type(actual.get('Exit')) is int and actual['Exit'] == 0
             and type(actual.get('ExpectedExit')) is int and actual['ExpectedExit'] == 0
             and not actual.get('JournalErrors'), 'exact terminal attribute command/' + wanted['Label'])


def build(suite, modules):
    """Execute the third phase; leave worker/effect inspection to the final reader.

    modules supplies recipes, attributes, attribute_runner, ownership and probes.
    Their source hashes and this module must be admitted before session.start().
    The parent owns final failure recovery/sealing; no subprocess is retried here.
    """
    need(type(modules) is dict and all(name in modules for name in MODULES), 'explicit authenticated modules')
    need(not getattr(suite, '_common_attributes_started', False), 'attribute phase cannot retry')
    need(type(suite.phases) is list and len(suite.phases) == 2
         and all(type(row) is dict and all(type(row.get(key)) is int for key in ('First', 'Stop', 'Commands'))
                 for row in suite.phases), 'literal completed prefix phase ranges')
    need(suite._started and not suite._finished and len(suite.commands) == 53
         and suite.phase_start is None and suite.phases == [dict(Name='ABIControls', First=0, Stop=41, Commands=41),
             dict(Name='Isolation', First=41, Stop=53, Commands=12)], 'after ABI and Isolation at command 53')
    need(suite.report.get('Status') == 'FAIL' and type(suite.report.get('RequiredCellsSatisfied')) is int
         and suite.report['RequiredCellsSatisfied'] == 0, 'unpromoted batch')
    for value in (suite.result, suite.report):
        need(type(value) is dict and value.get('Profile') == 'CM3' and value.get('Mode') == MODE
             and value.get('Linkage') == 'direct' and value.get('LTO') is True, 'actual Os metadata')
    modules['recipes'].require_capture_sources(suite.result)
    need(modules['attribute_runner'].command_plan() == command_plan(), 'unchanged neutral frozen plan')
    suite._common_attributes_started = True
    suite.begin_phase('CommonAttributes')
    suite.report.update(CommonAttributesBuilt=False, **dict.fromkeys(DEFERRED, False))
    try:
        sources = _sources(suite, modules)
        ownership = modules['ownership'].validate_common_sources(
            {name: sources[name] for name in modules['ownership'].REQUIRED_SOURCES})
        annotations = modules['attributes'].inspect_sources(sources)
        result = suite.command([str(suite.tools['gcc']), '-dumpspecs'], 'dump compiler specs')
        need(result.stdout and result.stderr == b'', 'clean fresh dumpspecs')
        original = suite.write_input('attributes/driver/original.specs', result.stdout)
        adapted = modules['attributes'].adapt_specs(result.stdout)
        specs = suite.write_input('attributes/driver/no-auto-gcov.specs', adapted['Specs'])
        adapter = {key: value for key, value in adapted.items() if key != 'Specs'}
        adapter.update(OriginalPath=str(original), AdaptedPath=str(specs))
        compiled, lowered, mutations = [], [], []
        positive = []
        for index in range(3):
            obj, row = compile_ir(suite, 'positive', index, suite.base / 'source', sources, modules)
            positive.append(obj)
            compiled.append(row)
        lowered.append(lower(suite, 'positive', positive, specs, modules))
        for index, role in enumerate(ROLES):
            plan = modules['attributes'].annotation_mutant(role, sources)
            group = 'mutant-' + role
            root = modules['attribute_runner'].copy_sources(suite, 'attributes-' + group, plan['Sources'])
            replacement, row = compile_ir(suite, group, index, root, plan['Sources'], modules)
            compiled.append(row)
            objects = list(positive)
            objects[index] = replacement
            lowered.append(lower(suite, group, objects, specs, modules, mutation=plan['Function']))
            mutations.append(dict(Role=role, Function=plan['Function'], Edits=copy.deepcopy(plan['Edits']),
                ReplacedIRRole=role, UnchangedIR=[str(path) for path in positive if path != positive[index]],
                Detected=False, OriginalProtectedPredicateRejected=False))
        stress = modules['attributes'].stress_sources()
        for group, key, mutation in (('stress-protected', 'Protected', None),
                ('stress-unprotected', 'Unprotected', modules['attributes'].STRESS)):
            inputs = dict(sources, **{'stress.c': stress[key]})
            root = modules['attribute_runner'].copy_sources(suite, 'attributes-' + group, inputs)
            obj, row = compile_ir(suite, group, 0, root, inputs, modules, stress=True)
            compiled.append(row)
            lowered.append(lower(suite, group, [obj], specs, modules, mutation=mutation, stress=True))
        _commands(suite, modules['recipes'])
        need(len(compiled) == 8 and tuple(row['Group'] for row in lowered) == LOWERS, 'eight IR builds and six lowers')
        suite.verify_objects()
        suite.watch.close()
        record = dict(Status='BUILT-PENDING-READER', Scope=SCOPE, Profile='CM3', Mode=MODE, Linkage='direct', LTO=True,
            First=53, Stop=98, Commands=45, Compilations=compiled, Lowerings=lowered, AnnotationControls=mutations,
            SourceOwnership=ownership, SourceAnnotations=annotations, DriverAdapter=adapter,
            PairedStress=dict(Function=stress['Function'], RequiredFamilies=copy.deepcopy(stress['RequiredFamilies']),
                OnlyDifference=stress['OnlyDifference'], ProtectedSha256=sha(stress['Protected']),
                UnprotectedSha256=sha(stress['Unprotected'])), DeferredReaderRequired=True,
            Qualification=False, CellContractSatisfied=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0,
            SourceIRProof=False, SourceToMachineSemanticProof=False, FullABIProof=False, FullSemanticABIProof=False,
            CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False, **dict.fromkeys(DEFERRED, False))
        suite.report.update(CommonAttributesBuilt=True, CommonAttributesDeferredReader=record)
        suite.write_input('attributes/build.json', (json.dumps(record, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii'))
        suite.end_phase()
        suite._save('results.json', suite.report)
        return copy.deepcopy(record)
    except BaseException as error:
        suite.report.update(Status='FAIL', CommonAttributesBuilt=False, **dict.fromkeys(DEFERRED, False),
            RequiredCellSatisfied=False, RequiredCellsSatisfied=0, CellContractSatisfied=False,
            InputClosureVerified=False, OutputSealVerified=False)
        message = type(error).__name__ + ': ' + str(error)
        if not suite.report.get('PrimaryError'):
            suite.report['PrimaryError'] = message
        elif suite.report['PrimaryError'] != message:
            suite.report.setdefault('ClosingErrors', []).append(message)
        suite.report['Error'] = suite.report['PrimaryError']
        try:
            suite._save('results.json', suite.report)
        except BaseException as secondary:
            suite.report.setdefault('ClosingErrors', []).append(type(secondary).__name__ + ': ' + str(secondary))
        raise
