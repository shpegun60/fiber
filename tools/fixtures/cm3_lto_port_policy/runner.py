"""Fresh selected-port CM3 O2-LTO supported-policy component, never cell credit."""
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
PASS = 'CURRENT-CM3-LTO-PORT-POLICY-PASS-NOT-QUALIFIED'
SCOPE = 'CURRENT_NATIVE_CM3_O2_LTO_SELECTED_PORT_SUPPORTED_POLICY_ONLY'
PINS = {
    'controls': ('tools/fixtures/cm3_lto_abi_controls/controls.py',
        '7984A228966FC17641BD83D23486DB7E50BC2B7E5BC12D70A712F6E83800F14F'),
    'attributes': ('tools/fixtures/cm3_lto_attributes/attributes.py',
        '93275A5903A67CB2DAEABB76BEF1431B052878BB478455E54343DB20881E83C0'),
    'attribute_runner': ('tools/fixtures/cm3_lto_attributes/runner.py',
        '9C99D38EACC8F3E3B2B63F343CA79555A66264AC76A3CA11957D2BEB0745987A'),
    'transport_roots': ('tools/fixtures/cm3_lto_roots/native.py',
        'D4BA0378FA50E11A570D40180149794B16EB0807E36DC902C19840E32D1AF05D'),
    'policy': ('tools/fixtures/cm3_lto_port_policy/policy.py',
        '8FC3AD729BF8903D716E34579700FC22D417040156EFCF0B434D2C43D75F0CA0'),
    'contract': ('tools/fixtures/cm3_lto_port_policy/CONTRACT.md',
        '05A871A63F6EDACA98AFFFEF7A78533F1F0CE8CE81023A9C7C2D489DC69781B9'),
}
RAW_FLAGS = ('-finstrument-functions', '-fstack-protector-all', '-fprofile-arcs',
    '-ftest-coverage', '-fsanitize=undefined', '-fsanitize-coverage=trace-pc')
COUNTER_FLAGS = ('-fno-instrument-functions', '-fno-stack-protector', '-fno-profile-arcs',
    '-fno-test-coverage', '-fno-sanitize=all', '-fno-sanitize-coverage=trace-pc', '-mgeneral-regs-only')
SELECTED = ('fiber/port/ARM_CM3/fiber_port.c', 'fiber/port/ARM_CM3/fiber_port_boot.c',
    'fiber/port/ARM_CM3/fiber_port_exception.c')
GROUPS = ('selected', 'stress-supported', 'stress-raw')
PUBLIC_FUNCTIONS = (
    'fiber_port_init_context_frame', 'fiber_port_panic_wait',
    'fiber_port_require_scheduler_configuration_environment', 'fiber_port_runtime_memory_barrier',
    'fiber_port_runtime_prepare_start', 'fiber_port_runtime_schedule', 'fiber_port_runtime_select_first',
    'fiber_port_runtime_start_first', 'fiber_port_scheduler_pick_first_from_start',
    'fiber_port_scheduler_pick_next_from_pendsv', 'fiber_port_start_first_context', 'SVC_Handler', 'PendSV_Handler',
    'fiber_fallback_initial_msp', 'fiber_port_runtime_prepare', 'fiber_port_boot_prepare_msp_for_start',
    'fiber_port_boot_record_compute_hash', 'fiber_port_boot_record_fast_check', 'fiber_port_boot_record_check',
    'fiber_port_boot_create', 'fiber_port_boot_check', 'fiber_port_require_start_environment',
    'fiber_port_context_init', 'fiber_port_context_validate_save_current', 'fiber_port_context_validate_restore',
    'fiber_port_context_prepare_first_start', 'fiber_port_require_start_interrupt_state',
    'fiber_exception_runtime_check', 'fiber_pendsv_init_lowest_priority')
LOCAL_FUNCTIONS = (
    'fiber_port_capture_scheduler_cpu_state', 'fiber_port_validate_scheduler_cpu_state',
    'fiber_port_boot_simple_check', 'fiber_port_prepare_start_msp_plan', 'fiber_port_validate_start_msp_for_boot',
    'fiber_port_validate_context_pointer', 'fiber_boot_hash32_accum', 'fiber_port_validate_stack_canary',
    'fiber_port_capture_validation_cpu_state', 'fiber_port_validate_validation_cpu_state',
    'fiber_port_fallback_initial_msp_checked', 'fiber_require_privileged_thread_msp', 'fiber_validate_vector_entry',
    'fiber_validate_pendsv_priority', 'fiber_validate_svc_priority', 'fiber_probe_implemented_priority_mask',
    'fiber_count_implemented_priority_bits', 'fiber_validate_basepri_priority_mask',
    'fiber_validate_priority_grouping', 'fiber_validate_feature_policy')
PHASES = ('SourceProvidersValidated', 'SelectedSlimIRValidated', 'DriverAdapterValidated',
    'ActualWorkerPolicyValidated', 'WholeSelectedBodiesValidated', 'PairedStressValidated',
    'FinalExecutableValidated', 'InputClosureVerified', 'OutputSealVerified')
FALSE_CLAIMS = ('Qualification', 'CellContractSatisfied', 'RequiredCellSatisfied', 'FullABIProof',
    'FullSemanticABIProof', 'SourceIRProof', 'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership',
    'FinalReferenceParity', 'CanonicalProtocolValidated', 'PolicyEquivalence', 'ArchiveExtraction',
    'CpuExecution', 'BoardExecution', 'HostedCIQualified', 'GlobalFreezeQualified',
    'TypedDeclarationProbesValidated', 'FiveLinkControlsValidated', 'WholeSlotAccessIsolation',
    'PositiveLinkRevalidated', 'GeneralRegistersOnlyEffectProved', 'FullAttributeEquivalence',
    'TransitiveProtection', 'RuntimeLibraryProvided', 'RawAttributesAloneProved',
    'UnchangedOtherSixGeneratedBodies', 'FullInstructionSemantics')


def need(condition, message):
    if not condition:
        raise ValueError('cm3-lto-port-policy: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def digest(value):
    return type(value) is str and re.fullmatch(r'[0-9A-F]{64}', value) is not None


def load(name, path, raw):
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def policy_flags(supported):
    need(type(supported) is bool, 'literal supported-policy selection')
    return list(RAW_FLAGS + (COUNTER_FLAGS if supported else ()))


def flags_for(suite, index, *, supported=True):
    need(type(index) is int and index in (3, 4, 5), 'selected-port template index')
    original = suite.source(index)['CompileFlags']
    need(type(original) is list and all(type(flag) is str for flag in original), 'captured flags array')
    need(all(original.count(flag) == 1 for flag in ('-mcpu=cortex-m3', '-mthumb',
        '-mfloat-abi=soft', '-O2', '-flto', '-fno-fat-lto-objects')), 'captured CM3 soft slim O2')
    need(not any(flag.startswith(('-march', '-mfpu', '-finstrument', '-fno-instrument',
        '-fstack-protector', '-fno-stack-protector', '-fprofile', '-fno-profile', '-ftest-coverage',
        '-fno-test-coverage', '-fsanitize', '-fno-sanitize', '-mgeneral-regs-only')) for flag in original),
        'no hidden policy or target override in seed')
    need(original.count('-include') == 1 and any('cmsis' in flag.lower() for flag in original),
        'real selected-port forced configuration and CMSIS retained')
    return list(original) + policy_flags(supported)


def command_plan():
    result = ['dump compiler specs']
    for group, names in (('selected', tuple(Path(name).stem for name in SELECTED)),
            ('stress-supported', ('stress',)), ('stress-raw', ('stress',))):
        for stem in names:
            result.extend(('discover ' + group + ' ' + stem, 'compile ' + group + ' ' + stem,
                'inspect slim ' + stem, 'imports ' + group + ' ' + stem))
            if group == 'selected':
                result.append('definitions ' + group + ' ' + stem)
        result.extend(('lower ' + group, 'disassemble ' + group, 'disassemble worker ' + group))
    result.extend(('link final-supported', 'disassemble final-supported', 'disassemble worker final-supported'))
    return tuple(result)


def commands_pass(rows):
    return (type(rows) is list and len(rows) == len(command_plan())
        and all(type(row) is dict for row in rows)
        and tuple(row.get('Label') for row in rows) == command_plan()
        and all(row.get('State') == 'TERMINAL' and row.get('Status') == 'PASS'
            and type(row.get('Exit')) is int and row['Exit'] == 0
            and type(row.get('ExpectedExit')) is int and row['ExpectedExit'] == 0
            and row.get('TimedOut') is False and not row.get('JournalErrors') for row in rows))


def admitted_dependencies(suite):
    result = {}
    for row in suite.sources:
        for item in row['ActualCompileDependencies']:
            path, expected = Path(item['Path']), item['Sha256']
            need(path not in result or result[path] == expected, 'consistent admitted dependencies')
            result[path] = expected
    return result


def parse_ir_definitions(raw):
    need(type(raw) is bytes and raw and b'\0' not in raw, 'actual plugin definition bytes')
    result = []
    for line in raw.decode('ascii').splitlines():
        match = re.fullmatch(r'(\S+) ([A-Za-z?]) ([0-9a-fA-F]+)(?: ([0-9a-fA-F]+))?[ \t]*', line)
        need(match is not None, 'complete plugin definition row')
        result.append(dict(Name=match[1], Kind=match[2], Value=int(match[3], 16),
            Size=None if match[4] is None else int(match[4], 16)))
    return result


def compile_ir(suite, group, index, *, stress_source=None):
    need(group in GROUPS and ((group == 'selected') is (stress_source is None)), 'fixed compile role')
    record = suite.source(index)
    source = Path(record['Source'])
    if stress_source is None:
        need(source == suite.base / 'source' / SELECTED[index - 3], 'exact selected provider')
        source_raw = suite.watch.read(source, record['SourceSha256'])
    else:
        need(type(stress_source) is bytes and stress_source, 'one ordinary stress source')
        source_raw = stress_source
        source = suite.write_input('private/' + group + '/stress.c', source_raw)
    flags = flags_for(suite, index, supported=group != 'stress-raw')
    directory = suite.output / 'ir' / group
    directory.mkdir(parents=True, exist_ok=True)
    obj = directory / (source.stem + '.o')
    discovery, actual = obj.with_suffix('.discovery.d'), obj.with_suffix('.compile.d')
    target, start = 'pilot-source-' + str(index), len(suite.commands)
    admitted = admitted_dependencies(suite)
    admitted[source] = sha(source_raw)

    def dependencies(path):
        paths = [suite.api.checked_path(value) for value in suite.native.read_dependencies(path)]
        need(paths and len(paths) == len(set(paths)) and source in paths, 'complete unique actual dependency set')
        need(all(path in admitted for path in paths), 'no foreign source/header dependency')
        return [dict(Path=str(path), Sha256=sha(suite.watch.read(path, admitted[path]))) for path in paths]

    gcc = str(suite.tools['gcc'])
    result = suite.command([gcc, *flags, '-M', '-MF', str(discovery), '-MT', target, str(source)],
        'discover ' + group + ' ' + source.stem)
    need(result.stdout == result.stderr == b'', 'clean dependency discovery')
    suite.record_output(discovery)
    before = dependencies(discovery)
    result = suite.command([gcc, *flags, '-MD', '-MF', str(actual), '-MT', target,
        '-c', str(source), '-o', str(obj)], 'compile ' + group + ' ' + source.stem)
    need(result.stdout == result.stderr == b'', 'clean supported/raw compilation')
    suite.record_output(actual)
    object_record = suite.record_output(obj)
    note = suite.record_output(obj.with_suffix('.gcno'), required=False)
    after = dependencies(actual)
    suite.native.require_compile_dependencies(before, after)
    slim = suite.inspect_ir(obj)
    names, imports = suite._undefined(obj, group + ' ' + source.stem)
    need(type(names) is list and len(names) == len(set(names)), 'actual unique plugin import surface')
    definitions = None
    if group == 'selected':
        result = suite.command([str(suite.tools['nm']), '--plugin', str(suite.plugin), '-P', '-S',
            '--defined-only', str(obj)], 'definitions ' + group + ' ' + source.stem)
        need(result.stderr == b'', 'clean actual plugin definition query')
        definitions = parse_ir_definitions(result.stdout)
    row = dict(Group=group, TemplateIndex=index, Source=str(source), SourceSha256=sha(source_raw),
        Object=str(obj), ObjectSha256=object_record['Sha256'], OriginalCompileFlags=record['CompileFlags'],
        CompileFlags=flags, SlimIR=slim, IRImports=imports, IRDefinitions=definitions, CoverageNotes=note,
        DiscoveryDependencyFile=str(discovery), CompileDependencyFile=str(actual),
        DiscoveryDependencies=before, Dependencies=after, CompileDependenciesVerified=True,
        OriginalSelectedSourceUnchanged=stress_source is None, CpuFreeIncludes=False,
        SupportedPolicy=group != 'stress-raw', CommandIndices=list(range(start, len(suite.commands))),
        RawIRIdentityClaim=False, SourceToMachineSemanticProof=False)
    suite.report['Compilations'].append(row)
    return obj


def argument_lines(raw):
    need(type(raw) is bytes and raw and b'\0' not in raw, 'saved argument bytes')
    lines = raw.decode('utf-8').splitlines()
    need(all(value and value == value.strip() for value in lines), 'saved argument grammar')
    return [value.replace('\\\\', '\\') for value in lines]


def worker_diagnostics(suite, raw, output, *, supported):
    need(type(raw) is bytes and raw and raw.isascii() and b'\0' not in raw, 'actual verbose worker stderr')
    text = raw.decode('ascii')
    need(not re.search(r'(?im)(?:^|\s)(?:fatal error|error|warning):', text), 'no worker warnings/errors')
    lines = [line.strip() for line in text.splitlines() if re.match(r'^\s+\S+[/\\]lto1[.]exe ', line)]
    need(len(lines) == 2, 'exact actual WPA/LTRANS invocations')
    rows = []
    for line, marker, response in ((lines[0], '-fwpa', str(output) + '.wpa.args.0'),
            (lines[1], '-fltrans', str(output) + '.ltrans0.ltrans.args.0')):
        need('"' not in line and "'" not in line, 'bounded actual invocation grammar')
        values = line.split()
        executable = suite.api.checked_path(suite.admitted.base.stable_path(values[0]))
        expected = suite.result['ResolvedWorkers']['lto1']
        need(executable == Path(expected['Path']) and marker in values
            and [value for value in values if value.startswith('@')] == ['@' + response],
            'actual worker executable/stage/response')
        suite.watch.read(executable, expected['Sha256'])
        if marker == '-fltrans':
            need(values.count('-o') == 1 and values[values.index('-o') + 1]
                == str(output) + '.ltrans0.ltrans.s', 'exact compiler assembly output')
        rows.append(dict(Stage=marker, Executable=str(executable), ExecutableSha256=expected['Sha256'],
            Argv=values, Response=response, ResponseSha256=sha(suite.watch.read(Path(response)))))
    effective = [suite.modules['policy'].require_effective_options(row['Argv'], supported=supported)
        for row in rows]
    assembly = [line.strip() for line in text.splitlines() if re.match(r'^\s+\S+[/\\]as[.]exe ', line)]
    need(len(assembly) == 1, 'one actual assembler invocation')
    values = assembly[0].split()
    expected = suite.result['ResolvedWorkers']['as']
    executable = suite.api.checked_path(suite.admitted.base.stable_path(values[0]))
    need(executable == Path(expected['Path']) and values.count('-o') == 1
        and values[values.index('-o') + 1] == str(output) + '.ltrans0.ltrans.o'
        and values[-1] == str(output) + '.ltrans0.ltrans.s'
        and not any(value.startswith('@') for value in values), 'actual assembly-to-machine chain')
    suite.watch.read(executable, expected['Sha256'])
    return dict(CompilerReportedWorkerExecutionVerified=True, OsProcessTraceVerified=False,
        TranscriptSha256=sha(raw), WorkerInvocations=rows, EffectiveOptions=effective,
        Assembler=dict(Executable=str(executable), ExecutableSha256=expected['Sha256'], Argv=values))


def worker_chain(suite, output, objects, diagnostics, *, supported, specs=None):
    prefix = str(output)
    wpa_path, ltrans_path = Path(prefix + '.ltrans_args'), Path(prefix + '.ltrans0.ltrans_args')
    wpa_raw, ltrans_raw = suite.watch.read(wpa_path), suite.watch.read(ltrans_path)
    wpa, ltrans = argument_lines(wpa_raw), argument_lines(ltrans_raw)
    proof = dict(SupportedPolicy=supported, EffectiveOptionsVerified=True,
        WpaOptions=suite.modules['policy'].require_effective_options(wpa, supported=supported),
        LtransOptions=suite.modules['policy'].require_effective_options(ltrans, supported=supported))
    for values in (wpa, ltrans):
        actual = [value for value in values if value.startswith('-specs=')]
        need(actual == ([] if specs is None else ['-specs=' + str(specs)]), 'only exact raw-stress specs adapter')
    ir = [path for path in objects if path != suite.objects[8]]
    need([value for value in wpa if value.endswith('.o')] == [str(path) for path in ir], 'exact ordered WPA IR cohort')
    need(argument_lines(suite.watch.read(Path(prefix + '.wpa.args.0'))) == [str(path) for path in ir],
        'actual WPA response object order')
    intermediate, machine = Path(prefix + '.ltrans0.o'), Path(prefix + '.ltrans0.ltrans.o')
    need(ltrans[-1] == str(intermediate) and ltrans.count('-o') == 1
        and ltrans[ltrans.index('-o') + 1] == str(machine), 'actual LTRANS input/output')
    need(argument_lines(suite.watch.read(Path(prefix + '.ltrans0.ltrans.args.0'))) == [str(intermediate)],
        'actual LTRANS response bytes')
    listed = suite.watch.read(Path(prefix + '.ltrans.out')).decode('ascii').splitlines()
    need(len(listed) == 2 and re.fullmatch(r'[0-9]+', listed[0]) and listed[1] == str(intermediate),
        'one real machine partition')
    header = suite.transport.require_elf32le(suite.watch.read(machine))
    proof.update(Machine=str(machine), MachineSha256=sha(suite.watch.read(machine)), MachineHeader=header,
        WpaArguments=str(wpa_path), LtransArguments=str(ltrans_path),
        WpaInputs=[dict(Path=str(path), Sha256=sha(suite.watch.read(path))) for path in ir],
        Intermediate=str(intermediate), IntermediateSha256=sha(suite.watch.read(intermediate)),
        DriverSpecs=None if specs is None else dict(Path=str(specs), Sha256=sha(suite.watch.read(specs))),
        Execution=worker_diagnostics(suite, diagnostics, output, supported=supported))
    return proof


def saved_outputs(suite, output):
    prefix, directory = output.name, output.parent
    suffixes = ('.ltrans.out', '.ltrans0.ltrans.args.0', '.ltrans0.ltrans.o', '.ltrans0.ltrans.s',
        '.ltrans0.ltrans_args', '.ltrans0.o', '.ltrans_args', '.res', '.wpa.args.0')
    fixed = {prefix, *(prefix + suffix for suffix in suffixes)}
    if output.suffix == '.elf':
        fixed.add('image.map')
    optional = {prefix + suffix for suffix in ('.wpa.gcno', '.ltrans0.ltrans.gcno', '.lto_wrapper_args')}
    actual = suite.api.files_under(directory)
    need(fixed <= set(actual) <= fixed | optional, 'complete bounded saved machine artifacts')
    for path in actual.values():
        suite.record_output(path)
    local = directory / (prefix + '.lto_wrapper_args')
    external = suite.output / (''.join(output.parts[1:]) + '.lto_wrapper_args')
    need(local.exists() is not external.exists(), 'one saved wrapper argument owner')
    wrapper = local if local.exists() else external
    suite.record_output(wrapper)
    return wrapper


def disassemble(suite, path, label):
    result = suite.command([str(suite.tools['objdump']), '-drwC', '-z', str(path)], label)
    need(result.stdout and result.stderr == b'', 'complete clean actual disassembly')
    saved = suite.write_input(path.relative_to(suite.output).as_posix() + '.dis', result.stdout)
    return dict(Path=str(saved), Sha256=sha(result.stdout))


def lower(suite, group, objects, *, specs=None):
    need(group in GROUPS and len(objects) == (3 if group == 'selected' else 1), 'fixed lowering input roles')
    supported = group != 'stress-raw'
    need((specs is None) is supported, 'only raw stress uses specs adapter')
    directory = suite.output / 'lowered' / group
    need(not directory.exists(), 'fresh lowering namespace')
    directory.mkdir(parents=True)
    output = directory / 'aggregate.o'
    argv = [str(suite.tools['gcc']), *flags_for(suite, 3, supported=supported)]
    if specs is not None:
        argv.append('-specs=' + str(specs))
    argv.extend(('-v', '-flto-partition=one', '-save-temps=obj', '-Wl,-plugin-opt=-save-temps',
        '-nostdlib', '-r', '-flinker-output=nolto-rel', *(str(path) for path in objects), '-o', str(output)))
    start = len(suite.commands)
    result = suite.command(argv, 'lower ' + group)
    need(result.stdout == b'' and result.stderr, 'retained actual verbose lowering')
    wrapper = saved_outputs(suite, output)
    worker = worker_chain(suite, output, objects, result.stderr, supported=supported, specs=specs)
    dis = disassemble(suite, output, 'disassemble ' + group)
    worker_dis = disassemble(suite, Path(worker['Machine']), 'disassemble worker ' + group)
    row = dict(Group=group, Object=str(output), ObjectSha256=sha(suite.watch.read(output)),
        Inputs=[dict(Path=str(path), Sha256=sha(suite.watch.read(path))) for path in objects],
        ActualWorker=worker, Disassembly=dis, WorkerDisassembly=worker_dis, WrapperArgs=str(wrapper),
        SupportedPolicy=supported, CommandIndices=list(range(start, len(suite.commands))))
    suite.report['Lowerings'].append(row)
    return row


def final_arguments(suite, selected, output, link_map):
    need(len(selected) == 3 and len(set(selected)) == 3, 'three fresh selected IR roles')
    objects = list(suite.objects)
    objects[3:6] = selected
    original = next(row['Argv'] for row in suite.result['Commands'] if row['Label'] == 'link ordinary')
    need(original.count('-v') == 1 and not any(value in RAW_FLAGS + COUNTER_FLAGS for value in original),
        'normal captured final-stage options')
    result = []
    for value in original:
        if value in [str(path) for path in suite.objects]:
            result.append(str(objects[[str(path) for path in suite.objects].index(value)]))
        elif value.startswith('-Wl,-Map='):
            result.append('-Wl,-Map=' + str(link_map))
        elif value == suite.result['Links'][0]['Path']:
            result.append(str(output))
        else:
            result.append(value)
    first = result.index(str(objects[0]))
    result[first:first] = ['-Wl,--emit-relocs', *policy_flags(True)]
    need([value for value in result if value.endswith('.o')] == [str(path) for path in objects],
        'fresh selected three and byte-identical remaining six in original order')
    return result, objects


def link_final(suite, selected):
    directory = suite.output / 'final-supported'
    need(not directory.exists(), 'fresh final link namespace')
    directory.mkdir(parents=True)
    output, link_map = directory / 'image.elf', directory / 'image.map'
    argv, objects = final_arguments(suite, selected, output, link_map)
    start = len(suite.commands)
    result = suite.command(argv, 'link final-supported')
    need(result.stdout == b'' and result.stderr, 'verbose final link diagnostics retained')
    wrapper = saved_outputs(suite, output)
    worker = worker_chain(suite, output, objects, result.stderr, supported=True)
    dis = disassemble(suite, output, 'disassemble final-supported')
    worker_dis = disassemble(suite, Path(worker['Machine']), 'disassemble worker final-supported')
    unchanged = [dict(Index=index, Path=str(objects[index]), Sha256=sha(suite.watch.read(objects[index],
        suite.sources[index]['ObjectSha256']))) for index in (0, 1, 2, 6, 7, 8)]
    row = dict(Path=str(output), Sha256=sha(suite.watch.read(output)), Map=str(link_map),
        MapSha256=sha(suite.watch.read(link_map)), Disassembly=dis, WorkerDisassembly=worker_dis,
        ActualWorker=worker, Objects=[str(path) for path in objects], UnchangedOtherSixObjects=unchanged,
        OriginalFinalStageArgv=copy.deepcopy(next(row['Argv'] for row in suite.result['Commands']
            if row['Label'] == 'link ordinary')), Argv=argv, WrapperArgs=str(wrapper),
        GlobalSupportedCounterPolicy=True, UnchangedOtherSixGeneratedBodies=False,
        OriginalTranslationUnitOwnership=False, CommandIndices=list(range(start, len(suite.commands))))
    suite.report['FinalLink'] = row
    return row


def require_raw_stress_rejected(suite, image, core, disassembly):
    rejected = False
    try:
        suite.modules['policy'].inspect_stress(image, core, disassembly,
            suite.modules['attributes'], supported=True)
    except (suite.modules['policy'].Rejected, suite.modules['attributes'].Rejected):
        rejected = True
    need(rejected, 'same clean predicate rejects actual raw stress effects')


def inspect_outputs(suite):
    rows, final = suite.report['Lowerings'], suite.report['FinalLink']
    need(tuple(row['Group'] for row in rows) == GROUPS, 'all three completed lowerings')
    paths = [Path(value) for row in rows for value in (row['Object'], row['ActualWorker']['Machine'],
        row['Disassembly']['Path'], row['WorkerDisassembly']['Path'])]
    paths.extend(Path(value) for value in (final['Path'], final['Map'], final['Disassembly']['Path'],
        final['ActualWorker']['Machine'], final['WorkerDisassembly']['Path'], str(suite.objects[8])))
    need(len(paths) == len(set(paths)), 'distinct reader binary roles')
    with suite.modules['controls'].reader(suite.admitted, paths) as (core, graph):
        for row in rows:
            stress, raw = row['Group'] != 'selected', row['Group'] == 'stress-raw'
            aggregate = core._ELF(Path(row['Object']), 'ET_REL')
            machine = core._ELF(Path(row['ActualWorker']['Machine']), 'ET_REL')
            dis = Path(row['Disassembly']['Path']).read_bytes()
            worker_dis = Path(row['WorkerDisassembly']['Path']).read_bytes()
            if stress:
                row['Effects'] = suite.modules['policy'].inspect_stress(aggregate, core, dis,
                    suite.modules['attributes'], supported=not raw)
                row['WorkerEffects'] = suite.modules['policy'].inspect_stress(machine, core, worker_dis,
                    suite.modules['attributes'], supported=not raw)
            else:
                row['Effects'] = suite.modules['policy'].inspect_lowered(aggregate, core, dis,
                    suite.report['IRDefinitionSurface'])
                row['WorkerEffects'] = suite.modules['policy'].inspect_lowered(machine, core, worker_dis,
                    suite.report['IRDefinitionSurface'])
            row['OriginalCleanPredicateRejected'] = False
            need(machine_pass(row['Effects'], row['ObjectSha256'], row['Disassembly']['Sha256'])
                and machine_pass(row['WorkerEffects'], row['ActualWorker']['MachineSha256'],
                    row['WorkerDisassembly']['Sha256']) if not stress else
                stress_pass(suite.modules['attribute_runner'], row['Effects'], row['ObjectSha256'],
                    row['Disassembly']['Sha256'], raw=raw)
                and stress_pass(suite.modules['attribute_runner'], row['WorkerEffects'],
                    row['ActualWorker']['MachineSha256'], row['WorkerDisassembly']['Sha256'], raw=raw),
                'complete pure lowering result schema')
            if raw:
                for image, text in ((aggregate, dis), (machine, worker_dis)):
                    require_raw_stress_rejected(suite, image, core, text)
                row['OriginalCleanPredicateRejected'] = True
        final_machine = core._ELF(Path(final['ActualWorker']['Machine']), 'ET_REL')
        final_image = core._ELF(Path(final['Path']), 'ET_EXEC')
        final['WorkerEffects'] = suite.modules['policy'].inspect_lowered(final_machine, core,
            Path(final['WorkerDisassembly']['Path']).read_bytes(), suite.report['IRDefinitionSurface'], whole_image=True)
        final['Effects'] = suite.modules['policy'].inspect_final(final_image, core,
            Path(final['Disassembly']['Path']).read_bytes(), suite.report['IRDefinitionSurface'])
        image = suite.modules['transport_roots'].NativeCM3LTOImage(core,
            Path(final['ActualWorker']['Machine']), Path(final['Path']), Path(final['Disassembly']['Path']),
            provider_objects={final['ActualWorker']['Machine']: Path(final['ActualWorker']['Machine']),
                str(suite.objects[8]): suite.objects[8]}, link_map=Path(final['Map']))
        final['TransferRoots'] = [image.function(name) for name in
            ('fiber_port_start_first_context', 'SVC_Handler', 'PendSV_Handler')]
        suite.report['ExecutedReaderBuffers'] = copy.deepcopy(graph.executed)
    suite.watch.close()


def suite_type(base_class):
    class Suite(base_class):
        def __init__(self, args, admitted, modules, buffers):
            super().__init__(args, admitted, modules, buffers)
            self.report.update(Status='FAIL', Scope=SCOPE,
                **{name: False for name in (*FALSE_CLAIMS, *PHASES)},
                Compilations=[], Lowerings=[], FinalLink=None, RawIRIdentityClaim=False,
                RawFlags=list(RAW_FLAGS), SupportedCounterFlags=list(COUNTER_FLAGS))
            self._policy_done = False

        def _failure(self, error):
            self.report.update(Status='FAIL', **{name: False for name in PHASES})
            try:
                super()._failure(error)
            finally:
                self.report.update(Status='FAIL', **{name: False for name in PHASES})

        def finish(self, error=None):
            need(not self._finished, 'finish once')
            if error is None and not (self._policy_done and commands_pass(self.commands)
                    and all(self.report.get(name) is True for name in PHASES[:-2])):
                error = ValueError('incomplete supported-policy stages')
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
                    InputHashes={str(path): value for path, value in sorted(self.watch.hashes.items())},
                    InputPhysicalIdentities={str(path): self.admitted.identity(path) for path in sorted(self.watch.hashes)},
                    ClosingFilesVerified=len(self.watch.hashes))
                need(succeeded(self.report, attribute_runner=self.modules['attribute_runner']),
                    'complete returned leaf evidence before PASS persistence')
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
    for relative, expected in PINS.values():
        path = ROOT / relative
        raw = path.read_bytes()
        need(digest(expected) and sha(raw) == expected, 'fixed helper pin: ' + str(path))
        buffers[path] = raw
    own = Path(__file__).resolve()
    buffers[own] = own.read_bytes()
    modules = {name: load('cm3_port_policy_' + name, ROOT / relative, buffers[ROOT / relative])
        for name, (relative, _) in PINS.items() if name != 'contract'}
    need(tuple(modules['policy'].RAW_FLAGS) == RAW_FLAGS
        and tuple(modules['policy'].COUNTER_FLAGS) == COUNTER_FLAGS, 'explicit seven-counter supported policy')
    original, inherited = modules['controls'].prepare(args)
    inherited.update(modules)
    suite = suite_type(type(original))(args, original.admitted, inherited, buffers)
    return suite, inherited


def source_buffers(suite):
    root, result = suite.base / 'source', {}
    for path, expected in admitted_dependencies(suite).items():
        if path.is_relative_to(root):
            name = path.relative_to(root).as_posix()
            need('source/' + name in suite.bundle['Artifacts']
                and suite.bundle['Artifacts']['source/' + name] == expected, 'source-copy hash authority')
            result[name] = suite.watch.read(path, expected)
    need(all(name in result for name in SELECTED), 'actual unchanged selected providers captured')
    return result


def run(suite, modules):
    error = None
    try:
        suite.start()
        sources = source_buffers(suite)
        suite.report['SelectedSourceHashes'] = {name: sha(sources[name]) for name in SELECTED}
        result = suite.command([str(suite.tools['gcc']), '-dumpspecs'], 'dump compiler specs')
        need(result.stdout and result.stderr == b'', 'fresh clean specs output')
        original = suite.write_input('driver/original.specs', result.stdout)
        adapter = modules['attributes'].adapt_specs(result.stdout)
        specs = suite.write_input('driver/no-auto-gcov.specs', adapter['Specs'])
        suite.report['DriverAdapter'] = {key: value for key, value in adapter.items() if key != 'Specs'}
        suite.report['DriverAdapter'].update(OriginalPath=str(original), AdaptedPath=str(specs))
        suite.report['DriverAdapterValidated'] = True
        selected = [compile_ir(suite, 'selected', index) for index in (3, 4, 5)]
        suite.report['IRDefinitionSurface'] = modules['policy'].inspect_ir_definitions({role: row['IRDefinitions']
            for role, row in zip(('runtime', 'boot', 'exception'), suite.report['Compilations'])})
        suite.report['SourceProvidersValidated'] = True
        suite.report['SelectedSlimIRValidated'] = True
        lower(suite, 'selected', selected)
        stress_plan = modules['policy'].stress_source(modules['attributes'])
        stress = stress_plan['Source']
        need(type(stress) is bytes and stress and sha(stress) == stress_plan['SourceSha256'],
            'same ordinary unprotected stress bytes')
        for group in GROUPS[1:]:
            obj = compile_ir(suite, group, 3, stress_source=stress)
            lower(suite, group, [obj], specs=specs if group == 'stress-raw' else None)
        suite.report['PairedStress'] = dict(SourceSha256=sha(stress), SameSourceBytes=True,
            OnlyDifference='EXPLICIT_SEVEN_SUPPORTED_COUNTERFLAGS', RawAttributesProof=False)
        link_final(suite, selected)
        inspect_outputs(suite)
        suite.report.update(ActualWorkerPolicyValidated=True, WholeSelectedBodiesValidated=True,
            PairedStressValidated=True, FinalExecutableValidated=True)
        suite._policy_done = True
    except BaseException as failure:
        error = failure
    return suite.finish(error)


def options_pass(proof, supported):
    return (type(proof) is dict and proof.get('SupportedPolicy') is supported
        and proof.get('EffectiveOptionsVerified') is True and proof.get('AttributeEffectsValidated') is False
        and proof.get('Counters') == (list(COUNTER_FLAGS) if supported else [])
        and type(proof.get('RawPresent')) is list and type(proof.get('CanonicalizedRawAbsent')) is list
        and set(proof['RawPresent']) | set(proof['CanonicalizedRawAbsent']) == set(RAW_FLAGS))


def worker_pass(proof, supported=True):
    if not (type(proof) is dict and digest(proof.get('MachineSha256')) and type(proof.get('Execution')) is dict):
        return False
    if not (proof.get('SupportedPolicy') is supported and proof.get('EffectiveOptionsVerified') is True
            and all(options_pass(proof.get(name), supported) for name in ('WpaOptions', 'LtransOptions'))):
        return False
    execution = proof['Execution']
    if not (execution.get('CompilerReportedWorkerExecutionVerified') is True
            and execution.get('OsProcessTraceVerified') is False and digest(execution.get('TranscriptSha256'))
            and type(execution.get('WorkerInvocations')) is list and len(execution['WorkerInvocations']) == 2
            and type(execution.get('Assembler')) is dict and digest(execution['Assembler'].get('ExecutableSha256'))
            and type(execution.get('EffectiveOptions')) is list and len(execution['EffectiveOptions']) == 2
            and all(options_pass(row, supported) for row in execution['EffectiveOptions'])):
        return False
    return all(type(row) is dict and row.get('Stage') == marker and digest(row.get('ExecutableSha256'))
        and digest(row.get('ResponseSha256')) and type(row.get('Argv')) is list and marker in row['Argv']
        for marker, row in zip(('-fwpa', '-fltrans'), execution['WorkerInvocations']))


def machine_pass(proof, expected_hash, disassembly_hash, *, mandatory=None):
    mandatory = PUBLIC_FUNCTIONS + LOCAL_FUNCTIONS if mandatory is None else mandatory
    return (type(proof) is dict and digest(expected_hash) and proof.get('ObjectSha256') == expected_hash
        and digest(disassembly_hash) and proof.get('DisassemblySha256') == disassembly_hash
        and proof.get('Status') == 'CM3-LTO-PORT-POLICY-MACHINE-PASS'
        and proof.get('Scope') == 'CM3_O2_LTO_SUPPORTED_PORT_POLICY_COMPONENT_ONLY'
        and type(proof.get('FinalELF')) is bool
        and type(proof.get('FunctionsAudited')) is int and proof['FunctionsAudited'] > 0
        and type(proof.get('FunctionEvidence')) is list and len(proof['FunctionEvidence']) == proof['FunctionsAudited']
        and all(type(row) is dict and type(row.get('Name')) is str and row['Name']
            and digest(row.get('BodySha256')) and type(row.get('Instructions')) is int
            and row['Instructions'] > 0 and type(row.get('References')) is list
            for row in proof['FunctionEvidence'])
        and len({row['Name'] for row in proof['FunctionEvidence']}) == proof['FunctionsAudited']
        and set(mandatory) <= {row['Name'] for row in proof['FunctionEvidence']}
        and all(proof.get(name) is True for name in ('CompleteExecutableCensus', 'ForbiddenDependenciesAbsent',
            'RecognizedForbiddenFormsAbsent')) and type(proof.get('RecognizedForbiddenForms')) is list
        and bool(proof['RecognizedForbiddenForms'])
        and proof.get('FullInstructionSemantics') is False and proof.get('OriginalTranslationUnitOwnership') is False
        and all(proof.get(name) is False for name in ('SourceIRSemantics', 'AttributeOnlyProtection',
            'GeneralRegistersOnlyEffectProved', 'CPUExecution', 'BoardExecution', 'GlobalQualification'))
        and proof.get('RequiredCellsSatisfied') == 0
        and type(proof.get('RequiredCellsSatisfied')) is int)


def stress_pass(attribute_runner, proof, expected_hash, disassembly_hash, *, raw):
    if not (type(proof) is dict and proof.get('SupportedPolicy') is (not raw)
            and type(proof.get('RequiredCellsSatisfied')) is int and proof['RequiredCellsSatisfied'] == 0
            and attribute_runner.effects_pass(proof.get('Effects'),
                'stress-unprotected' if raw else 'stress-protected', expected_hash)):
        return False
    if raw:
        effects = proof['Effects']
        counter = effects.get('StressCounterEvidence')
        imports = effects.get('CompilerImports')
        return (proof.get('Status') == 'CM3-LTO-PORT-POLICY-STRESS-EFFECTS-DETECTED'
            and proof.get('CleanPredicateRejected') is True and effects.get('StressFamiliesActivated') is True
            and type(counter) is dict and type(counter.get('Definition')) is dict
            and counter['Definition'].get('name') == '__gcov0.ctxrt_attribute_stress'
            and type(counter.get('References')) is list and bool(counter['References'])
            and type(imports) is list and {'__cyg_profile_func_enter', '__cyg_profile_func_exit',
                '__stack_chk_guard', '__stack_chk_fail', '__gcov_init', '__gcov_exit', '__gcov_merge_add',
                '__ubsan_handle_add_overflow', '__ubsan_handle_out_of_bounds', '__sanitizer_cov_trace_pc'} <= set(imports))
    clean = proof.get('CleanMachine')
    return (proof.get('Status') == 'CM3-LTO-PORT-POLICY-STRESS-CLEAN' and type(clean) is dict
        and machine_pass(clean, expected_hash, disassembly_hash, mandatory=('ctxrt_attribute_stress',))
        and proof['Effects'].get('StressCounterEvidence') is None and proof['Effects'].get('CompilerImports') == [])


def succeeded(report, *, attribute_runner):
    if not (type(report) is dict and report.get('Status') == PASS and report.get('Scope') == SCOPE
            and report.get('Profile') == 'CM3' and report.get('Mode') == 'O2-lto'
            and report.get('Linkage') == 'direct' and report.get('LTO') is True
            and report.get('Error') is None and report.get('PrimaryError') is None and report.get('ClosingErrors') == []
            and all(report.get(name) is True for name in PHASES)
            and all(report.get(name) is False for name in FALSE_CLAIMS)
            and type(report.get('RequiredCellsSatisfied')) is int and report['RequiredCellsSatisfied'] == 0
            and type(report.get('RequiredCellCount')) is int and report['RequiredCellCount'] == 2774
            and report.get('RawFlags') == list(RAW_FLAGS) and report.get('SupportedCounterFlags') == list(COUNTER_FLAGS)
            and commands_pass(report.get('Commands'))):
        return False
    compiled, rows, final = (report.get(name) for name in ('Compilations', 'Lowerings', 'FinalLink'))
    if not (type(compiled) is list and len(compiled) == 5 and type(rows) is list and len(rows) == 3
            and type(final) is dict):
        return False
    surface = report.get('IRDefinitionSurface')
    if not (type(surface) is dict and surface.get('IRDefinitionsValidated') is True
            and type(surface.get('PublicFunctions')) is int and surface['PublicFunctions'] == 29
            and type(surface.get('CohortObjects')) is int and surface['CohortObjects'] == 2
            and type(surface.get('Definitions')) is list and len(surface['Definitions']) == 31
            and all(type(row) is dict and type(row.get('Name')) is str and type(row.get('Value')) is int
                and row['Value'] == 0 and row.get('Size') is None
                and row.get('Role') in ('runtime', 'boot', 'exception') for row in surface['Definitions'])
            and len({row['Name'] for row in surface['Definitions']}) == 31
            and {row['Name'] for row in surface['Definitions'] if row.get('Kind') in ('T', 'W')} == set(PUBLIC_FUNCTIONS)):
        return False
    for row, group, index in zip(compiled, ('selected',) * 3 + GROUPS[1:], (3, 4, 5, 3, 3)):
        if not (type(row) is dict and row.get('Group') == group and type(row.get('TemplateIndex')) is int
                and row['TemplateIndex'] == index and row.get('CompileDependenciesVerified') is True
                and type(row.get('SlimIR')) is dict and row['SlimIR'].get('SlimIR') is True
                and row.get('CpuFreeIncludes') is False and row.get('SupportedPolicy') is (group != 'stress-raw')
                and digest(row.get('SourceSha256')) and digest(row.get('ObjectSha256'))):
            return False
    if compiled[-1]['SourceSha256'] != compiled[-2]['SourceSha256']:
        return False
    for row, group in zip(rows, GROUPS):
        if not (type(row) is dict and row.get('Group') == group
                and worker_pass(row.get('ActualWorker'), supported=group != 'stress-raw')
                and row.get('OriginalCleanPredicateRejected') is (group == 'stress-raw')):
            return False
        if group == 'selected' and not (machine_pass(row.get('Effects'), row.get('ObjectSha256'),
                row['Disassembly'].get('Sha256')) and machine_pass(row.get('WorkerEffects'),
                row['ActualWorker'].get('MachineSha256'), row['WorkerDisassembly'].get('Sha256'))
                and row['Effects'].get('FinalELF') is False and row['WorkerEffects'].get('FinalELF') is False):
            return False
        if group != 'selected':
            for key, expected, text in (('Effects', row.get('ObjectSha256'), row['Disassembly'].get('Sha256')),
                    ('WorkerEffects', row['ActualWorker'].get('MachineSha256'), row['WorkerDisassembly'].get('Sha256'))):
                if not stress_pass(attribute_runner, row.get(key), expected, text, raw=group == 'stress-raw'):
                    return False
    proof = final.get('Effects')
    return (worker_pass(final.get('ActualWorker')) and type(proof) is dict
        and machine_pass(proof, final.get('Sha256'), final['Disassembly'].get('Sha256'), mandatory=PUBLIC_FUNCTIONS)
        and proof.get('FinalELF') is True
        and machine_pass(final.get('WorkerEffects'), final['ActualWorker'].get('MachineSha256'),
            final['WorkerDisassembly'].get('Sha256'), mandatory=PUBLIC_FUNCTIONS)
        and final['WorkerEffects'].get('FinalELF') is False
        and type(proof.get('FinalRootVectorBindings')) is dict
        and proof['FinalRootVectorBindings'].get('Words') == 256
        and proof['FinalRootVectorBindings'].get('CanonicalRootProtocolsValidated') is False
        and type(final.get('TransferRoots')) is list and len(final['TransferRoots']) == 3
        and [row.get('Name') for row in final['TransferRoots'] if type(row) is dict]
            == ['fiber_port_start_first_context', 'SVC_Handler', 'PendSV_Handler']
        and all(row.get('GeneratedMachineBoundRootPreservation') is True
            and row.get('OriginalTranslationUnitOwnership') is False and digest(row.get('BodySha256'))
            and type(row.get('References')) is list and bool(row['References']) for row in final['TransferRoots'])
        and final.get('GlobalSupportedCounterPolicy') is True and final.get('UnchangedOtherSixGeneratedBodies') is False
        and type(final.get('UnchangedOtherSixObjects')) is list
        and [row.get('Index') for row in final['UnchangedOtherSixObjects'] if type(row) is dict] == [0, 1, 2, 6, 7, 8]
        and all(digest(row.get('Sha256')) for row in final['UnchangedOtherSixObjects']))


def revoke_failure(suite, error):
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
        need(succeeded(report, attribute_runner=modules['attribute_runner']),
            'sealed supported-policy component: ' + str(report.get('Error')))
        print(json.dumps({key: report[key] for key in ('Status', 'Scope', 'WholeSelectedBodiesValidated',
            'PairedStressValidated', 'FinalExecutableValidated', 'RequiredCellsSatisfied')}, sort_keys=True), flush=True)
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
