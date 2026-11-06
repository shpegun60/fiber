"""Build-only Os selected-port policy phase [98,134), never a qualifier.

Caller-authenticated neutral saved-worker/specs/IR-definition helpers are reused
explicitly. O2 flag builders, drivers, constructors, readers and verdicts are
not called. All generated-machine census, stress activation, final map/target
and complete transfer-root obligations remain pending for one final reader.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace


SCOPE = 'NATIVE_CM3_OS_LTO_PORT_POLICY_BUILD_ONLY_PENDING_READER'
SELECTED = ('fiber/port/ARM_CM3/fiber_port.c', 'fiber/port/ARM_CM3/fiber_port_boot.c',
            'fiber/port/ARM_CM3/fiber_port_exception.c')
GROUPS = ('selected', 'stress-supported', 'stress-raw')
RAW_FLAGS = ('-finstrument-functions', '-fstack-protector-all', '-fprofile-arcs',
             '-ftest-coverage', '-fsanitize=undefined', '-fsanitize-coverage=trace-pc')
COUNTER_FLAGS = ('-fno-instrument-functions', '-fno-stack-protector', '-fno-profile-arcs',
                 '-fno-test-coverage', '-fno-sanitize=all', '-fno-sanitize-coverage=trace-pc', '-mgeneral-regs-only')
HELPER_PINS = {
    'recipes': ('tools/fixtures/cm3_os_lto_final_cell/batch_recipes.py',
        'C15D57AA9FE3963FF84F22D831F4E1F5F941AC351571AB347ECBC29E9172004B'),
    'workers': ('tools/fixtures/cm3_lto_port_policy/runner.py',
        'E06E55AC26B3828EDA54333DC7D5E0982DCC791694A2E9FE64E2A31C3BBE9AAB'),
    'policy': ('tools/fixtures/cm3_lto_port_policy/policy.py',
        '8FC3AD729BF8903D716E34579700FC22D417040156EFCF0B434D2C43D75F0CA0'),
    'attributes': ('tools/fixtures/cm3_lto_attributes/attributes.py',
        '93275A5903A67CB2DAEABB76BEF1431B052878BB478455E54343DB20881E83C0'),
}


class Rejected(ValueError):
    pass


def need(value, message):
    if not value:
        raise Rejected('cm3-os-port-policy-build: ' + message)


def sha(raw):
    need(type(raw) is bytes, 'immutable bytes')
    return hashlib.sha256(raw).hexdigest().upper()


def require_effective_options(argv, *, supported):
    """Own Os argv contract, not an O2 surrogate or instruction-effect proof."""
    need(type(supported) is bool and type(argv) is list and argv
         and all(type(flag) is str and flag and '\0' not in flag for flag in argv), 'literal effective argv')
    need(all(flag in argv for flag in ('-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-Os')),
         'actual Os target in effective options')
    for flag in argv:
        need(not flag.startswith('-O') or flag == '-Os', 'foreign optimization')
        need(not flag.startswith('-mcpu=') or flag == '-mcpu=cortex-m3', 'foreign CPU')
        need(not flag.startswith('-mfloat-abi=') or flag == '-mfloat-abi=soft', 'foreign float ABI')
        if flag.startswith(('-march', '-mlibarch')):
            need(flag in ('-march=armv7-m', '-mlibarch=armv7-m'), 'foreign canonical worker architecture')
        need(not flag.startswith(('-mfpu', '-mno-general-regs-only',
                                 '-finstrument-functions-exclude-', '-fno-lto', '-ffat-lto-objects')),
             'unsupported target, instrumentation or LTO override')
        if flag.startswith(('-finstrument-functions', '-fstack-protector', '-fprofile-arcs', '-ftest-coverage',
                            '-fsanitize', '-fno-instrument', '-fno-stack-protector', '-fno-profile',
                            '-fno-test-coverage', '-fno-sanitize')):
            need(flag in RAW_FLAGS + COUNTER_FLAGS, 'unclassified supported/raw option')
    if supported:
        need(all(flag in argv for flag in COUNTER_FLAGS), 'all seven supported counters')
        # Actual GCC worker argv groups target GRO ahead of the six -f counters.
        positions = [max(index for index, actual in enumerate(argv) if actual == flag) for flag in COUNTER_FLAGS[:-1]]
        need(positions == sorted(positions), 'six counter options retain their effective order')
        for positive, last in zip(RAW_FLAGS, positions):
            need(all(index < last for index, flag in enumerate(argv) if flag == positive),
                 'late positive option overrides supported policy')
    else:
        need(all(flag in argv for flag in RAW_FLAGS) and not any(flag in argv for flag in COUNTER_FLAGS),
             'six uncancelled raw controls and no supported counters')
    return dict(Mode='Os-lto', SupportedPolicy=supported, EffectiveOptionsVerified=True,
        CanonicalWorkerArchitecture=[flag for flag in argv if flag.startswith(('-march', '-mlibarch'))],
        RawPresent=[flag for flag in RAW_FLAGS if flag in argv],
        CanonicalizedRawAbsent=[flag for flag in RAW_FLAGS if flag not in argv],
        Counters=list(COUNTER_FLAGS) if supported else [], AttributeEffectsValidated=False)


def flags_for(suite, modules, index, *, supported=True):
    need(type(index) is int and index in (3, 4, 5) and type(supported) is bool, 'selected source template and policy')
    original = suite.source(index)['CompileFlags']
    need(original == modules['recipes'].compile_flags(suite.result, index), 'exact original Os capture flags')
    need([flag for flag in original if flag.startswith('-O')] == ['-Os']
         and all(original.count(flag) == 1 for flag in
                 ('-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-flto', '-fno-fat-lto-objects')),
         'genuine soft CM3 Os slim input')
    need(not any(flag in RAW_FLAGS + COUNTER_FLAGS or flag.startswith(('-march', '-mfpu', '-mno-general-regs-only',
        '-finstrument', '-fno-instrument', '-fstack-protector', '-fno-stack-protector', '-fprofile', '-fno-profile',
        '-ftest-coverage', '-fno-test-coverage', '-fsanitize', '-fno-sanitize', '-fno-lto', '-ffat-lto-objects'))
        for flag in original), 'no hidden policy/target override')
    need(original.count('-include') == 1 and any('cmsis' in flag.lower() for flag in original),
         'selected forced configuration and CMSIS retained')
    result = list(original) + list(RAW_FLAGS) + (list(COUNTER_FLAGS) if supported else [])
    require_effective_options(result, supported=supported)
    return result


def command_plan():
    rows = ['dump compiler specs']
    for group, names in (('selected', tuple(Path(name).stem for name in SELECTED)),
                         ('stress-supported', ('stress',)), ('stress-raw', ('stress',))):
        for name in names:
            rows.extend(('discover ' + group + ' ' + name, 'compile ' + group + ' ' + name,
                         'inspect slim ' + name, 'imports ' + group + ' ' + name))
            if group == 'selected':
                rows.append('definitions ' + group + ' ' + name)
        rows.extend(('lower ' + group, 'disassemble ' + group, 'disassemble worker ' + group))
    rows.extend(('link final-supported', 'disassemble final-supported', 'disassemble worker final-supported'))
    return tuple(rows)


def _worker_view(suite):
    """Explicit private adapter; neither the session nor qualified globals change.

    The frozen worker routines use only these neutral members. Their option
    callback is our actual Os contract; raw/report argv are never rewritten.
    """
    return SimpleNamespace(watch=suite.watch, api=suite.api, result=suite.result,
        objects=suite.objects, transport=suite.transport,
        modules={'policy': SimpleNamespace(require_effective_options=require_effective_options)},
        admitted=SimpleNamespace(base=SimpleNamespace(
            stable_path=lambda path: Path(os.path.abspath(os.fspath(path))))))


def _compile(suite, modules, group, index, *, stress=None):
    need(group in GROUPS and (group == 'selected') is (stress is None), 'fixed selected/stress role')
    template = suite.source(index)
    source = Path(template['Source'])
    if stress is None:
        need(source == suite.base / 'source' / SELECTED[index - 3], 'exact unchanged selected provider')
        raw = suite.watch.read(source, template['SourceSha256'])
    else:
        need(type(stress) is bytes and stress, 'ordinary identical stress bytes')
        raw = stress
        source = suite.write_input('port-policy/private/' + group + '/stress.c', raw)
    flags = flags_for(suite, modules, index, supported=group != 'stress-raw')
    directory = suite.output / 'port-policy/ir' / group
    directory.mkdir(parents=True, exist_ok=True)
    obj = directory / (source.stem + '.o')
    discovery, actual = obj.with_suffix('.discovery.d'), obj.with_suffix('.compile.d')
    target, first = 'pilot-source-' + str(index), len(suite.commands)
    h = modules['workers']
    admitted = h.admitted_dependencies(suite)
    admitted[source] = sha(raw)

    def dependencies(path):
        paths = [suite.api.checked_path(value) for value in suite.native.read_dependencies(path)]
        need(paths and len(paths) == len(set(paths)) and source in paths
             and all(path in admitted for path in paths), 'complete unique admitted source/header dependencies')
        return [dict(Path=str(path), Sha256=sha(suite.watch.read(path, admitted[path]))) for path in paths]

    gcc = str(suite.tools['gcc'])
    result = suite.command([gcc, *flags, '-M', '-MF', str(discovery), '-MT', target, str(source)],
                           'discover ' + group + ' ' + source.stem)
    need(result.stdout == result.stderr == b'', 'clean policy dependency discovery')
    suite.record_output(discovery)
    before = dependencies(discovery)
    result = suite.command([gcc, *flags, '-MD', '-MF', str(actual), '-MT', target, '-c', str(source), '-o', str(obj)],
                           'compile ' + group + ' ' + source.stem)
    need(result.stdout == result.stderr == b'', 'clean policy/stress compile')
    suite.record_output(actual)
    object_record = suite.record_output(obj)
    coverage = suite.record_output(obj.with_suffix('.gcno'), required=False)
    after = dependencies(actual)
    suite.native.require_compile_dependencies(before, after)
    slim = suite.inspect_ir(obj)
    need(type(slim) is dict and slim.get('SlimIR') is True and slim.get('Object') == str(obj)
         and slim.get('Sha256') == object_record['Sha256'], 'actual generated slim object identity')
    names, imports = suite._undefined(obj, group + ' ' + source.stem)
    need(type(names) is list and len(names) == len(set(names)), 'complete unique plugin import declarations')
    definitions = None
    if group == 'selected':
        result = suite.command([str(suite.tools['nm']), '--plugin', str(suite.plugin), '-P', '-S',
                                '--defined-only', str(obj)], 'definitions ' + group + ' ' + source.stem)
        need(result.stderr == b'', 'clean complete plugin definition query')
        definitions = h.parse_ir_definitions(result.stdout)
    row = dict(Group=group, TemplateIndex=index, Source=str(source), SourceSha256=sha(raw),
        Object=str(obj), ObjectSha256=object_record['Sha256'], OriginalCompileFlags=template['CompileFlags'],
        CompileFlags=flags, SlimIR=slim, IRImports=imports, IRDefinitions=definitions, CoverageNotes=coverage,
        DiscoveryDependencyFile=str(discovery), CompileDependencyFile=str(actual),
        DiscoveryDependencies=before, Dependencies=after, CompileDependenciesVerified=True,
        OriginalSelectedSourceUnchanged=stress is None, SupportedPolicy=group != 'stress-raw',
        CommandIndices=list(range(first, len(suite.commands))), RawIRIdentityClaim=False,
        SourceToMachineSemanticProof=False)
    suite.report['PortPolicyCompilations'].append(row)
    return obj


def _saved(suite, helpers, output):
    wrapper = helpers['workers'].saved_outputs(suite, output)
    records = [dict(Path=str(path), Sha256=sha(suite.watch.read(path)))
               for path in suite.api.files_under(output.parent).values()]
    if wrapper not in {Path(row['Path']) for row in records}:
        records.append(dict(Path=str(wrapper), Sha256=sha(suite.watch.read(wrapper))))
    return wrapper, records


def _lower(suite, modules, group, objects, *, specs=None):
    supported = group != 'stress-raw'
    need(group in GROUPS and len(objects) == (3 if supported and group == 'selected' else 1)
         and (specs is None) is supported, 'exact lowering roles and raw-only specs adapter')
    directory = suite.output / 'port-policy/lowered' / group
    need(not directory.exists(), 'fresh lowering namespace')
    directory.mkdir(parents=True)
    output = directory / 'aggregate.o'
    argv = [str(suite.tools['gcc']), *flags_for(suite, modules, 3, supported=supported)]
    if specs is not None:
        argv.append('-specs=' + str(specs))
    argv.extend(('-v', '-flto-partition=one', '-save-temps=obj', '-Wl,-plugin-opt=-save-temps',
                 '-nostdlib', '-r', '-flinker-output=nolto-rel', *map(str, objects), '-o', str(output)))
    first = len(suite.commands)
    result = suite.command(argv, 'lower ' + group)
    need(result.stdout == b'' and result.stderr, 'actual verbose lowering transcript')
    wrapper, saved = _saved(suite, modules, output)
    h = modules['workers']
    worker = h.worker_chain(_worker_view(suite), output, objects, result.stderr, supported=supported, specs=specs)
    row = dict(Group=group, Object=str(output), ObjectSha256=sha(suite.watch.read(output)),
        Inputs=[dict(Path=str(path), Sha256=sha(suite.watch.read(path))) for path in objects],
        ActualWorker=worker, Disassembly=h.disassemble(suite, output, 'disassemble ' + group),
        WorkerDisassembly=h.disassemble(suite, Path(worker['Machine']), 'disassemble worker ' + group),
        WrapperArgs=str(wrapper), WrapperArgsSha256=sha(suite.watch.read(wrapper)), SavedOutputs=saved,
        SupportedPolicy=supported, CommandIndices=list(range(first, len(suite.commands))),
        MachineEffectsValidated=False, StressActivationValidated=False)
    suite.report['PortPolicyLowerings'].append(row)
    return row


def final_arguments(suite, modules, selected, output, link_map):
    need(type(selected) in (list, tuple) and len(selected) == len(set(selected)) == 3, 'three fresh selected IR objects')
    commands = [row for row in suite.result['Commands'] if row.get('Label') == 'link ordinary']
    need(len(commands) == 1, 'one admitted normal final recipe')
    original = commands[0]['Argv']
    need(type(original) is list and original.count('-v') == 1
         and [flag for flag in original if flag.startswith('-O')] == ['-Os']
         and not any(flag in RAW_FLAGS + COUNTER_FLAGS or '--emit-relocs' in flag for flag in original),
         'actual Os normal final-stage options, no policy already injected')
    objects = list(suite.objects)
    objects[3:6] = selected
    names = [str(path) for path in suite.objects]
    result = []
    for value in original:
        if value in names:
            result.append(str(objects[names.index(value)]))
        elif value.startswith('-Wl,-Map='):
            result.append('-Wl,-Map=' + str(link_map))
        elif value == suite.result['Links'][0]['Path']:
            result.append(str(output))
        else:
            result.append(value)
    first = result.index(str(objects[0]))
    result[first:first] = ['-Wl,--emit-relocs', *RAW_FLAGS, *COUNTER_FLAGS]
    need([flag for flag in result if flag.endswith('.o')] == [str(path) for path in objects],
         'three selected replacements only, original remaining six and order')
    require_effective_options(result, supported=True)
    return result, objects


def _final(suite, modules, selected):
    directory = suite.output / 'port-policy/final-supported'
    need(not directory.exists(), 'fresh supported final namespace')
    directory.mkdir(parents=True)
    output, link_map = directory / 'image.elf', directory / 'image.map'
    argv, objects = final_arguments(suite, modules, selected, output, link_map)
    first = len(suite.commands)
    result = suite.command(argv, 'link final-supported')
    need(result.stdout == b'' and result.stderr, 'actual verbose final-link transcript')
    wrapper, saved = _saved(suite, modules, output)
    h = modules['workers']
    worker = h.worker_chain(_worker_view(suite), output, objects, result.stderr, supported=True)
    return dict(Path=str(output), Sha256=sha(suite.watch.read(output)), Map=str(link_map),
        MapSha256=sha(suite.watch.read(link_map)), ActualWorker=worker,
        Disassembly=h.disassemble(suite, output, 'disassemble final-supported'),
        WorkerDisassembly=h.disassemble(suite, Path(worker['Machine']), 'disassemble worker final-supported'),
        Objects=[str(path) for path in objects],
        UnchangedOtherSixObjects=[dict(Index=index, Path=str(objects[index]),
            Sha256=sha(suite.watch.read(objects[index], suite.sources[index]['ObjectSha256'])))
            for index in (0, 1, 2, 6, 7, 8)],
        OriginalFinalStageArgv=copy.deepcopy(next(row['Argv'] for row in suite.result['Commands'] if row['Label'] == 'link ordinary')),
        Argv=argv, WrapperArgs=str(wrapper), WrapperArgsSha256=sha(suite.watch.read(wrapper)), SavedOutputs=saved,
        GlobalSupportedCounterPolicy=True, RawCommonAttributesAloneProved=False,
        UnchangedOtherSixGeneratedBodies=False, OriginalTranslationUnitOwnership=False,
        MachineEffectsValidated=False, FinalMappingValidated=False, CommandIndices=list(range(first, len(suite.commands))))


def _deferred(suite):
    roles = []
    for row in suite.report['PortPolicyLowerings']:
        group = row['Group']
        roles.extend(((group + '/Aggregate', row['Object']), (group + '/AggregateDisassembly', row['Disassembly']['Path']),
            (group + '/Machine', row['ActualWorker']['Machine']), (group + '/MachineDisassembly', row['WorkerDisassembly']['Path'])))
    final = suite.report['PortPolicyFinalLink']
    roles.extend((('Final/ELF', final['Path']), ('Final/Map', final['Map']), ('Final/Disassembly', final['Disassembly']['Path']),
        ('Final/Machine', final['ActualWorker']['Machine']), ('Final/MachineDisassembly', final['WorkerDisassembly']['Path']),
        ('Final/Startup', str(suite.objects[8]))))
    return dict(Status='PENDING', ValidationDeferred=True,
        Scope='OS_SELECTED_AGGREGATE_WORKER_FINAL_AND_PAIRED_STRESS_MACHINE_REPLAY_REQUIRED',
        Inputs=[dict(Role=role, Path=str(path), Sha256=sha(suite.watch.read(path))) for role, path in roles],
        RequiredMachineRoles=8, RequiredStressRoles=4, RequiredSelectedSurface=dict(PublicFunctions=29,
            CohortObjects=2, ForwardFunctions=8, NakedFunctions=3),
        MachineEffectsValidated=False, StressActivationValidated=False, FinalMappingValidated=False,
        FinalTransferRootsValidated=False, RawCommonAttributesAloneProved=False,
        WholeCellProof=False, Qualification=False, RequiredCellsSatisfied=0)


def _guards(suite, modules):
    need(type(modules) is dict and all(name in modules for name in HELPER_PINS), 'explicit authenticated helpers')
    need(not getattr(suite, '_os_port_policy_started', False), 'port-policy phase cannot retry')
    need(suite._started and not suite._finished and len(suite.commands) == 98, 'active session after 98 commands')
    expected = [dict(Name=name, First=first, Stop=stop, Commands=stop-first) for name, first, stop in
                (('ABIControls', 0, 41), ('Isolation', 41, 53), ('CommonAttributes', 53, 98))]
    need(suite.phases == expected and all(type(row[key]) is int for row in suite.phases for key in ('First', 'Stop', 'Commands')),
         'three exact preceding phase ranges')
    for row in (suite.result, suite.report):
        need(row.get('Profile') == 'CM3' and row.get('Mode') == 'Os-lto' and row.get('Linkage') == 'direct'
             and row.get('LTO') is True, 'explicit genuine Os session')
    need(suite.report.get('Status') == 'FAIL' and type(suite.report.get('RequiredCellsSatisfied')) is int
         and suite.report['RequiredCellsSatisfied'] == 0, 'unpromoted zero-credit session')
    need(all(suite.report.get(name) is True for name in ('ABIControlsBuilt', 'IsolationBuilt', 'CommonAttributesBuilt')),
         'three earlier build phases complete')
    modules['recipes'].require_capture_sources(suite.result)
    need(suite.link_argv == modules['recipes'].link_recipe(suite.result, suite.objects), 'unchanged admitted Os link recipe')
    plan = modules['recipes'].batch_plan()['Components'][3]
    need(plan['Name'] == 'PortPolicy' and (plan['Start'], plan['Stop'], plan['Count']) == (98, 134, 36)
         and tuple(plan['Labels']) == command_plan(), 'closed 36-command port-policy range')
    need(tuple(modules['policy'].RAW_FLAGS) == RAW_FLAGS and tuple(modules['policy'].COUNTER_FLAGS) == COUNTER_FLAGS,
         'same explicit six hostile and seven supported policy options')


def build(suite, modules):
    """Build [98,134) only; actual semantics remain pending and credit stays zero.

    Explicit helpers: recipes, workers (neutral saved-file/argv routines only),
    policy (pure IR definitions and stress source only), and attributes (specs
    adapter/stress source only). Their bytes must match HELPER_PINS before exec.
    """
    _guards(suite, modules)
    suite._os_port_policy_started = True
    suite.begin_phase('PortPolicy')
    suite.report.update(PortPolicyBuilt=False, PortPolicyCompilations=[], PortPolicyLowerings=[],
                        PortPolicyFinalLink=None, SelectedPortAttributePolicyProven=False)
    try:
        h = modules['workers']
        sources = h.source_buffers(suite)
        suite.report['PortPolicySelectedSourceHashes'] = {name: sha(sources[name]) for name in SELECTED}
        result = suite.command([str(suite.tools['gcc']), '-dumpspecs'], 'dump compiler specs')
        need(result.stdout and result.stderr == b'', 'clean actual compiler specs')
        original = suite.write_input('port-policy/driver/original.specs', result.stdout)
        adapter = modules['attributes'].adapt_specs(result.stdout)
        specs = suite.write_input('port-policy/driver/no-auto-gcov.specs', adapter['Specs'])
        suite.report['PortPolicyDriverAdapter'] = {key: value for key, value in adapter.items() if key != 'Specs'}
        suite.report['PortPolicyDriverAdapter'].update(OriginalPath=str(original), AdaptedPath=str(specs))
        selected = [_compile(suite, modules, 'selected', index) for index in (3, 4, 5)]
        suite.report['PortPolicyIRDefinitionSurface'] = modules['policy'].inspect_ir_definitions({
            role: row['IRDefinitions'] for role, row in zip(('runtime', 'boot', 'exception'), suite.report['PortPolicyCompilations'])})
        _lower(suite, modules, 'selected', selected)
        stress_plan = modules['policy'].stress_source(modules['attributes'])
        stress = stress_plan['Source']
        need(type(stress) is bytes and stress and sha(stress) == stress_plan['SourceSha256'], 'one exact ordinary unprotected stress source')
        for group in GROUPS[1:]:
            obj = _compile(suite, modules, group, 3, stress=stress)
            _lower(suite, modules, group, [obj], specs=specs if group == 'stress-raw' else None)
        suite.report['PortPolicyPairedStress'] = dict(SourceSha256=sha(stress), SameSourceBytes=True,
            OnlyPolicyFlagDifference=list(COUNTER_FLAGS), RawOnlySpecsAdapter=True,
            StressActivationValidated=False, RawAttributesProof=False)
        suite.report['PortPolicyFinalLink'] = _final(suite, modules, selected)
        suite.report['PortPolicyDeferredReader'] = _deferred(suite)
        rows = suite.commands[98:]
        need(len(rows) == 36 and tuple(row.get('Label') for row in rows) == command_plan()
             and all(row.get('State') == 'TERMINAL' and row.get('Status') == 'PASS'
                 and type(row.get('Exit')) is int and row['Exit'] == 0
                 and type(row.get('ExpectedExit')) is int and row['ExpectedExit'] == 0
                 and row.get('TimedOut') is False and not row.get('JournalErrors') for row in rows), 'exact typed successful port-policy commands')
        suite.verify_objects()
        suite.watch.close()
        record = dict(Status='BUILT-PENDING-READER', Scope=SCOPE, Profile='CM3', Mode='Os-lto', Linkage='direct',
            LTO=True, First=98, Stop=134, Commands=36, SelectedSlimIRObjects=3, StressSlimIRObjects=2,
            SavedMachineRoles=8, ActualWorkerChains=4, GlobalSupportedCounterPolicy=True,
            RawFlags=list(RAW_FLAGS), SupportedCounterFlags=list(COUNTER_FLAGS),
            WholeSelectedBodiesValidated=False, PairedStressValidated=False, FinalExecutableValidated=False,
            SelectedPortAttributePolicyProven=False, RawCommonAttributesAloneProved=False,
            UnchangedOtherSixGeneratedBodies=False, GeneralRegistersOnlyEffectProved=False,
            FullInstructionSemantics=False, FullABIProof=False, FullSemanticABIProof=False,
            CellContractSatisfied=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0,
            Qualification=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False)
        suite.report.update(PortPolicyBuild=record, PortPolicyBuilt=True)
        suite.write_input('port-policy-build.json', (json.dumps(dict(Build=record,
            Compilations=suite.report['PortPolicyCompilations'], Lowerings=suite.report['PortPolicyLowerings'],
            FinalLink=suite.report['PortPolicyFinalLink'], DeferredReader=suite.report['PortPolicyDeferredReader']),
            indent=2, sort_keys=True, allow_nan=False) + '\n').encode('ascii'))
        suite.end_phase()
        suite._save('results.json', suite.report)
        return copy.deepcopy(record)
    except BaseException as error:
        suite.report.update(Status='FAIL', PortPolicyBuilt=False, SelectedPortAttributePolicyProven=False,
            CellContractSatisfied=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0,
            InputClosureVerified=False, OutputSealVerified=False)
        message = type(error).__name__ + ': ' + str(error)
        if not suite.report.get('PrimaryError'):
            suite.report['PrimaryError'] = message
        elif suite.report['PrimaryError'] != message:
            suite.report.setdefault('ClosingErrors', []).append(message)
        suite.report['Error'] = suite.report['PrimaryError']
        try:
            suite._save('results.json', suite.report)
        except BaseException as closing:
            suite.report.setdefault('ClosingErrors', []).append(type(closing).__name__ + ': ' + str(closing))
        raise
