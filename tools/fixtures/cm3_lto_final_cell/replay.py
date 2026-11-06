"""Read-only recipe and machine replay for four fixed CM3 O2-LTO components.

Authentication, one immutable reader scope, and outer closing/sealing are owned
by the caller. No component lifecycle or tool execution is performed here.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace


ROLES = ('ABIControls', 'Isolation', 'CommonAttributes', 'PortPolicy')
COUNTS = dict(zip(ROLES, (41, 12, 45, 36)))
SCOPE = 'CM3_O2_LTO_FOUR_COMPONENT_RECIPE_AND_MACHINE_REPLAY_ONLY'
FALSE_CLAIMS = dict(CellContractSatisfied=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0,
    FullABIProof=False, FullSemanticABIProof=False, SourceToMachineSemanticProof=False,
    OriginalTranslationUnitOwnership=False, FinalReferenceParity=False, CpuExecution=False,
    BoardExecution=False, HostedCIQualified=False, GlobalFreezeQualified=False)


class Rejected(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected('cm3-lto-final-replay: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def same(actual, expected, message):
    need(encoded(actual) == encoded(expected), message)


def path(value):
    need(type(value) is str or isinstance(value, Path), 'literal path')
    result = Path(os.path.abspath(os.fspath(value)))
    forbidden = {'cm33f_secure_transfer_reference', 'm55_secure_closed_parity',
        'test_cm33f_secure_transfer_reference.ps1', 'test_m55_secure_closed_parity.ps1'}
    need(not forbidden.intersection(part.lower() for part in result.parts), 'protected stopped work is out of scope')
    return result


def _pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate JSON member')
        result[key] = value
    return result


def _json(raw):
    return json.loads(raw, object_pairs_hook=_pairs,
        parse_constant=lambda value: need(False, 'nonfinite JSON constant'))


def _maps(suites, bundles, modules=None):
    need(type(suites) is dict and type(bundles) is dict and set(suites) == set(bundles) == set(ROLES),
        'exact four component roles')
    if modules is not None:
        need(type(modules) is dict and set(ROLES) <= set(modules), 'four authenticated component modules')
    base = suites[ROLES[0]].admitted
    for role in ROLES:
        suite, bundle = suites[role], bundles[role]
        need(type(bundle) is dict and {'Root', 'Result', 'Artifacts', 'Descriptor'} <= set(bundle), 'bundle shape')
        need(suite.admitted is base and suite.watch is base.watch and path(suite.output) == path(bundle['Root']),
            'same admitted capture/watch and exact component root')
        same(suite.report, bundle['Result'], 'suite report must be its authenticated component result')
        need(type(bundle['Artifacts']) is dict and all(type(name) is str and name and
            not Path(name).is_absolute() and '\\' not in name and ':' not in name and
            all(part not in ('', '.', '..') for part in name.split('/')) and
            type(value) is str and re.fullmatch('[0-9A-F]{64}', value)
            for name, value in bundle['Artifacts'].items()), 'flat contained artifact hash map')


def _read(suite, bundle, name):
    selected = path(name)
    root = path(bundle['Root'])
    if selected.is_relative_to(root):
        relative = selected.relative_to(root).as_posix()
        need(relative in bundle['Artifacts'], 'consumed component file missing from artifact map: ' + relative)
        return suite.watch.read(selected, bundle['Artifacts'][relative])
    need(selected in suite.watch.hashes, 'external input must be pre-admitted: ' + str(selected))
    return suite.watch.read(selected, suite.watch.hashes[selected])


def binary_paths(suites, bundles):
    """Bounded superset of component/capture binaries and reader support files."""
    _maps(suites, bundles)
    result = set()
    suffixes = ('.o', '.elf', '.dis', '.map', '.attributes', '.readelf', '.s', '.i', '.d')
    for role in ROLES:
        suite, bundle = suites[role], bundles[role]
        root = path(bundle['Root'])
        for name in bundle['Artifacts']:
            if name.endswith(suffixes):
                result.add(root / name)
        result.add(path(suite.objects[8]))
        result.add(path(suite.base / 'source/fiber/port/ARM_CM3/fiber_port.c'))
        for source in suite.sources:
            result.update(path(item['Path']) for item in source['ActualCompileDependencies'])
        for row in suite.result['Links']:
            result.update(path(row[key]) for key in ('Path', 'Machine', 'Map'))
            result.add(path(str(row['Path']) + '.dis'))
            result.add(path(str(row['Path']) + '.ltrans0.ltrans.s'))
    return sorted(result)


def journals(suite, bundle, expected):
    root, report = path(bundle['Root']), bundle['Result']
    rows = _json(_read(suite, bundle, root / 'commands.json'))
    same(rows, report['Commands'], 'raw command journal differs from report')
    need(type(rows) is list and len(rows) == expected, 'complete fixed command count')
    results = []
    for index, row in enumerate(rows):
        need(type(row) is dict and row.get('State') == 'TERMINAL' and type(row.get('Exit')) is int
            and type(row.get('ExpectedExit')) is int and row['Exit'] == row['ExpectedExit']
            and row['Exit'] in (0, 1) and row.get('TimedOut') is False and not row.get('JournalErrors')
            and row.get('Status') == ('PASS' if row['Exit'] == 0 else 'EXPECTED-NONZERO')
            and type(row.get('Argv')) is list and row['Argv'] and
            all(type(value) is str and value for value in row['Argv']) and path(row['Cwd']) == root,
            'terminal typed compiler/inspection journal row')
        prefix = 'commands/%03d' % index
        same(_json(_read(suite, bundle, root / (prefix + '.json'))), row, 'per-command raw journal binding')
        same([row['Stdout'], row['Stderr']], [prefix + '.stdout', prefix + '.stderr'], 'fixed stream roles')
        stdout, stderr = (_read(suite, bundle, root / row[key]) for key in ('Stdout', 'Stderr'))
        same([sha(stdout), sha(stderr)], [row['StdoutSha256'], row['StderrSha256']], 'command stream hashes')
        results.append(SimpleNamespace(stdout=stdout, stderr=stderr, returncode=row['Exit'], timed_out=False))
    return rows, results


def _command(rows, label, argv, *, failure=False):
    matches = [index for index, row in enumerate(rows) if row['Label'] == label]
    need(len(matches) == 1, 'one actual command label: ' + label)
    index = matches[0]
    same(rows[index]['Argv'], [str(value) for value in argv], 'exact reconstructed argv: ' + label)
    need(rows[index]['Exit'] == (1 if failure else 0), 'command disposition: ' + label)
    return index


def _dependencies(raw, target):
    """The fixed GNU make dependency grammar, over authenticated bytes only."""
    text = raw.decode('utf-8').replace('\\\r\n', '').replace('\\\n', '')
    actual, separator, rest = text.partition(': ')
    need(separator and actual == target and re.fullmatch('pilot-source-[0-8]', actual), 'dependency target grammar')
    tokens = re.findall(r'(?:\\[ \t#]|[^\s])+', rest)
    need(tokens, 'nonempty compiler dependencies')
    return sorted({path(re.sub(r'\\([ \t#])', r'\1', token)) for token in tokens})


def dependencies(suite, bundle, record, source, index):
    target = 'pilot-source-' + str(index)
    obj = path(record['Object']) if record.get('Object') else path(source).with_name(Path(source).stem.replace('_', '-') + '.o')
    before = _dependencies(_read(suite, bundle, record.get('DiscoveryDependencyFile', obj.with_suffix('.discovery.d'))), target)
    after = _dependencies(_read(suite, bundle, record.get('CompileDependencyFile', obj.with_suffix('.compile.d'))), target)
    need(before == after and path(source) in before, 'same-attempt source dependency membership')
    recorded = record['Dependencies']
    need(type(recorded) is list and len(recorded) == len(after), 'complete dependency records')
    need([path(row['Path']) for row in recorded] == after, 'declared and raw dependency identities/order')
    for row in recorded:
        need(sha(_read(suite, bundle, row['Path'])) == row['Sha256'], 'actual dependency source bytes')
    if 'DiscoveryDependencies' in record:
        same(record['DiscoveryDependencies'], recorded, 'retained discovery dependency records')
    return copy.deepcopy(recorded)


def _slim_record(suite, bundle, record, rows, results):
    obj = record['Object']
    label = 'inspect slim ' + Path(obj).stem
    argv = [str(value) for value in (suite.tools['readelf'], '-hSW', obj)]
    # Positive and annotation-mutant groups deliberately reuse source stems.
    # The complete command identity includes the exact distinct IR object path.
    matches = [index for index, row in enumerate(rows) if row['Label'] == label and row['Argv'] == argv]
    need(len(matches) == 1, 'one exact label/argv slim inspection')
    index = matches[0]
    need(type(rows[index]['Exit']) is int and rows[index]['Exit'] == 0, 'successful exact slim inspection')
    raw = _read(suite, bundle, obj)
    header = suite.transport.require_elf32le(raw)
    sections = suite.transport.section_records(results[index].stdout.decode('ascii'))
    need(results[index].stderr == b'' and len(sections) == header['SectionCount'] and
        [row['Index'] for row in sections] == list(range(header['SectionCount'])) and
        any(row['Name'].startswith('.gnu.lto_') for row in sections) and
        not any(row['Size'] and 'X' in row['Flags'] for row in sections), 'actual slim IR and readelf surface')
    proof = dict(Object=str(obj), Sha256=sha(raw), SlimIR=True, Sections=sections)
    same(proof, record['SlimIR'], 'slim record replay')
    return proof


def _compile(suite, bundle, row, rows, results, *, label, index, flags, source=None, accepted=True):
    source = row['Source'] if source is None else str(source)
    same(row['CompileFlags'], flags, 'compile flags: ' + label)
    need(sha(_read(suite, bundle, source)) == row['SourceSha256'], 'compile source bytes: ' + label)
    obj = row.get('Object') or str(path(source).with_name(Path(source).stem.replace('_', '-') + '.o'))
    discovery = row.get('DiscoveryDependencyFile', path(obj).with_suffix('.discovery.d'))
    actual = row.get('CompileDependencyFile', path(obj).with_suffix('.compile.d'))
    discovery_flags = row.get('DiscoveryFlags', flags)
    first = _command(rows, 'discover ' + label, [suite.tools['gcc'], *discovery_flags,
        '-M', '-MF', discovery, '-MT', 'pilot-source-' + str(index), source])
    second = _command(rows, 'compile ' + label, [suite.tools['gcc'], *flags,
        '-MD', '-MF', actual, '-MT', 'pilot-source-' + str(index), '-c', source, '-o', obj], failure=not accepted)
    need(results[first].stdout == results[first].stderr == b'', 'clean successful discovery')
    if accepted:
        need(results[second].stdout == results[second].stderr == b'', 'clean accepted compile')
    dependencies(suite, bundle, row, source, index)
    return second


def _link_arguments(suite, objects, output, link_map, *, emit=False):
    result, inserted = [], False
    original_objects = [str(value) for value in suite.objects]
    for value in suite.link_argv:
        if value in original_objects:
            if not inserted:
                result.extend(str(value) for value in objects)
                inserted = True
        elif value.startswith('-Wl,-Map='):
            result.append('-Wl,-Map=' + str(link_map))
        elif value == suite.result['Links'][0]['Path']:
            result.append(str(output))
        else:
            result.append(value)
    need(inserted, 'closed original nine-object recipe')
    if emit:
        result.append('-Wl,--emit-relocs')
    return result


def _imports(raw):
    names = []
    for line in raw.decode('ascii').splitlines():
        match = re.fullmatch(r'\s*U ([A-Za-z_][A-Za-z0-9_]*)', line)
        need(match is not None, 'complete actual plugin undefined row')
        names.append(match[1])
    need(len(names) == len(set(names)), 'unique actual imports')
    return names


def _definitions(raw):
    result = []
    for line in raw.decode('ascii').splitlines():
        match = re.fullmatch(r'(\S+) ([A-Za-z]) 0\s*', line)
        need(match is not None, 'complete actual slim definition row')
        result.append(dict(Name=match[1], Kind=match[2], Value=0, Size=None))
    need(len(result) == len({row['Name'] for row in result}), 'unique actual slim definitions')
    return result


def _nm(suite, rows, results, obj, label, *, defined=False, parser=None):
    flags = ['-P', '-S', '--defined-only'] if defined else ['-u']
    index = _command(rows, ('definitions ' if defined else 'imports ') + label,
        [suite.tools['nm'], '--plugin', suite.plugin, *flags, obj])
    need(results[index].stderr == b'', 'clean actual plugin query')
    return (parser or (_definitions if defined else _imports))(results[index].stdout)


def _source_buffers(suite, bundle):
    return {name[len('source/'):]: _read(suite, bundle, suite.base / name)
        for name in suite.bundle['Artifacts'] if name.startswith('source/')}


def _source_plan(suite, bundle, spec, row):
    original = suite.source(spec['Index'])
    directory = path(bundle['Root']) / 'compilations' / spec['Name']
    root = path(suite.base) / 'source'
    flags = list(original['CompileFlags'])
    deltas = []
    if spec['Added'] is not None:
        source = directory / (spec['Name'].replace('-', '_') + '.c')
        need(_read(suite, bundle, source) == spec['Added'], 'exact strong-handler control source')
        deltas.append(dict(Kind='ADDED-CONTROL-TU', Source=str(source), Sha256=sha(spec['Added'])))
    else:
        copied = directory / 'source'
        changes = {name: (before, after) for name, before, after in spec['Mutations']}
        found = set()
        for name, raw in _source_buffers(suite, bundle).items():
            changed = raw
            if name in changes:
                before, after = changes[name]
                need(raw.count(before) == 1, 'one source-derived control mutation anchor')
                changed = raw.replace(before, after, 1)
                found.add(name)
                deltas.append(dict(Original=str(root / name), Copy=str(copied / name), BeforeSha256=sha(raw),
                    AfterSha256=sha(changed), Before=before.hex(), After=after.hex(), Count=1))
            need(_read(suite, bundle, copied / name) == changed, 'complete unchanged/private source plan')
        need(found == set(changes), 'all intended source mutations present')
        source = copied / path(original['Source']).relative_to(root)
        flags = [flag.replace(str(root), str(copied)) for flag in flags]
    same(row['SourceDeltas'], deltas, 'declared source mutation plan')
    need(path(row['Source']) == source and row['TemplateIndex'] == spec['Index']
        and type(row['TemplateIndex']) is int, 'control source/provider role')
    return source, flags


def _abi_records(suite, bundle, runner, rows, results):
    report, root = bundle['Result'], path(bundle['Root'])
    pure = suite.modules
    sources = _source_buffers(suite, bundle)
    provider = pure['abi'].inspect_provider_dependencies(sources,
        _read(suite, bundle, path(suite.admitted.root) / 'results.json'),
        source_root=str(suite.base / 'source'), capture_root=str(suite.admitted.root))
    same(provider, report['DeclaredProviders'], 'recomputed exact nine-source declaration/provider admission')
    positive = root / 'links/positive/image.elf'
    _command(rows, 'link positive', _link_arguments(suite, suite.objects, positive, positive.with_suffix('.map')))
    _saved_chain(suite, bundle, positive, suite.objects)
    definitions = _nm(suite, rows, results, suite.objects[3], 'original-runtime', defined=True)
    private = [row['Name'] for row in definitions if row['Name'].startswith('fiber_port_context_cohort_')]
    need(len(private) == 1 and private[0].count('_g4_') == 1, 'actual selected private identity')
    boot = _nm(suite, rows, results, suite.objects[4], 'unchanged-boot-v1')
    need([name for name in boot if name.startswith('fiber_internal_runtime_port_abi_')]
        == ['fiber_internal_runtime_port_abi_v1_anchor'], 'actual unchanged reverse-v1 consumer')
    plan = pure['plan'].control_plan(dict(target=dict(nvic_priority_bits=4)), 'ARM_CM3', 'arm_cm3')
    expected = (private[0].replace('_g4_', '_g5_', 1), 'fiber_port_storage_cohort_arm_cm3_v999_r0',
        'fiber_internal_runtime_port_abi_v1_anchor', 'SVC_Handler', 'PendSV_Handler')
    need(len(report['Controls']) == len(report['Compilations']) == 5, 'five complete link controls')
    labels = ['link positive', 'definitions original-runtime', 'imports unchanged-boot-v1']
    controls = []
    for spec, name, row, compilation in zip(plan, expected, report['Controls'], report['Compilations']):
        need(row['Name'] == spec['Name'] and row['Expected'] == name, 'fixed control identity')
        same(row['Compilation'], compilation, 'same retained compilation record')
        source, flags = _source_plan(suite, bundle, spec, compilation)
        _compile(suite, bundle, compilation, rows, results, label=spec['Name'], index=spec['Index'],
            flags=flags, source=source)
        slim = _slim_record(suite, bundle, dict(compilation, SlimIR=row['SlimIR']), rows, results)
        obj = path(compilation['Object'])
        labels.extend(('discover ' + spec['Name'], 'compile ' + spec['Name'], 'inspect slim ' + obj.stem))
        if spec['Index'] in (6, 7):
            imports = _nm(suite, rows, results, obj, spec['Name'])
            prefix = 'fiber_port_context_cohort_' if spec['Index'] == 6 else 'fiber_port_storage_cohort_'
            need([value for value in imports if value.startswith(prefix)] == [name], 'intended alternate raw IR import')
            labels.append('imports ' + spec['Name'])
        else:
            defined = _nm(suite, rows, results, obj, spec['Name'], defined=True)
            wanted = 'fiber_internal_runtime_port_abi_v2_anchor' if spec['Added'] is None else name
            matches = [item for item in defined if item['Name'] == wanted]
            need(len(matches) == 1 and matches[0]['Kind'] == ('D' if spec['Added'] is None else 'T'),
                'actual changed anchor or strong duplicate handler')
            same(defined, row['ChangedDefinitions'], 'changed provider definitions replay')
            labels.append('definitions ' + spec['Name'])
            if spec['Added'] is None:
                imported = _nm(suite, rows, results, obj, spec['Name'])
                need('fiber_internal_runtime_port_abi_v1_anchor' not in imported
                    and 'fiber_internal_runtime_port_abi_v1_anchor' not in {item['Name'] for item in defined},
                    'actual changed state cannot satisfy reverse-v1')
                labels.append('imports ' + spec['Name'])
        objects = list(suite.objects)
        if spec['Added'] is None:
            objects[spec['Index']] = obj
        else:
            objects.append(obj)
        elf = root / 'links' / spec['Name'] / 'image.elf'
        index = _command(rows, 'link ' + spec['Name'], _link_arguments(suite, objects, elf, elf.with_suffix('.map')), failure=True)
        need(type(row['LinkCommandIndex']) is int and row['LinkCommandIndex'] == index, 'bound diagnostic command index')
        need(elf.relative_to(root).as_posix() not in bundle['Artifacts'] and not elf.exists(), 'failed link has no final ELF')
        if spec['Added'] is None:
            machine = path(str(elf) + '.ltrans0.ltrans.o')
            need(path(row['DiagnosticMachine']['Path']) == machine and
                sha(_read(suite, bundle, machine)) == row['DiagnosticMachine']['Sha256'], 'actual diagnostic machine bytes')
            classification = pure['diagnostics'].classify_undefined(results[index], name, suite.tools['ld'], machine=machine)
            _saved_chain(suite, bundle, elf, objects)
        else:
            classification = pure['diagnostics'].classify_duplicate(results[index], name, suite.tools['ld'],
                obj, suite.objects[3], source)
        same(classification, row['Classification'], 'fresh intended link diagnostic classification')
        expected_objects = [dict(Index=i, Path=str(value), Sha256=sha(_read(suite, bundle, value)))
            for i, value in enumerate(objects)]
        same(row['ConsumedObjects'], expected_objects, 'actual negative link provider set')
        labels.append('link ' + spec['Name'])
        controls.append(dict(Name=spec['Name'], Classification=classification, SlimIR=slim))
    probes = pure['abi'].emit_probes()
    need(set(report['ABIProbes']) == set(probes), 'five exact ABI probes')
    probe_records = {}
    for name, model in probes.items():
        row = report['ABIProbes'][name]
        source, accepted = root / 'abi' / name, model['ExpectedCompile']
        raw = model['Source'].encode('ascii')
        need(_read(suite, bundle, source) == raw, 'independent typed/slot probe source bytes')
        before, flags = pure['probes'].probe_flags(suite.source(0)['CompileFlags'], model['RequiredCFlags'], accepted)
        same(before, row['DiscoveryFlags'], 'typed probe discovery flags')
        stem = name[:-2].replace('_', '-')
        index = _compile(suite, bundle, row, rows, results, label='probe ' + stem,
            index=0, flags=flags, source=source, accepted=accepted)
        labels.extend(('discover probe ' + stem, 'compile probe ' + stem))
        if accepted:
            _slim_record(suite, bundle, row, rows, results)
            classification = dict(AcceptedCompile=True)
            labels.append('inspect slim ' + path(row['Object']).stem)
        else:
            obj = source.with_name(stem + '.o')
            need(obj.relative_to(root).as_posix() not in bundle['Artifacts'] and not obj.exists(), 'rejected slot probe object absent')
            classification = pure['probes'].classify_undeclared(results[index], model['DiagnosticIdentifier'],
                object_exists=False, source_path=source, source_bytes=raw)
        same(classification, row['Classification'], 'fresh accepted/undeclared diagnostic classification')
        probe_records[name] = classification
    facts = pure['abi'].inspect_preprocessed_attributes(_read(suite, bundle, report['ABIProbes']['attributes.c']['Preprocessed']))
    same(facts, report['PreprocessedAttributes'], 'accepted same-attempt attribute declaration origins')
    for direction, value in facts['CanonicalHeaders'].items():
        suffix = 'context/context_port_abi.h' if direction == 'forward' else 'context/context_runtime_port_abi.h'
        need(path(value) == path(suite.base / 'source' / suffix), 'canonical accepted CPP header origin')
    same([row['Label'] for row in rows], labels, 'complete fixed ABI command order')
    return dict(DeclaredProviders=provider, Controls=controls, ABIProbes=probe_records, PreprocessedAttributes=facts)


def _isolation_records(suite, bundle, runner, rows, results):
    report, root = bundle['Result'], path(bundle['Root'])
    need(runner.commands_pass(rows) and len(report['IsolatedCommon']) == 3, 'complete twelve-command isolation recipe')
    sources = _source_buffers(suite, bundle)
    ownership = suite.modules['ownership'].validate_common_sources(
        {name: sources[name] for name in suite.modules['ownership'].REQUIRED_SOURCES})
    same(ownership, report['SourceOwnership'], 'isolated common source ownership replay')
    for index, row in enumerate(report['IsolatedCommon']):
        original = suite.source(index)
        flags = runner.common_flags(suite.modules['probes'], original['CompileFlags'], suite.base / 'source')
        same(row['OriginalCompileFlags'], original['CompileFlags'], 'original isolated compile authority')
        need(path(row['Source']) == path(original['Source']) and type(row['TemplateIndex']) is int
            and row['TemplateIndex'] == index, 'exact common provider role')
        _compile(suite, bundle, row, rows, results, label='isolated ' + path(row['Source']).stem, index=index, flags=flags)
        _slim_record(suite, bundle, row, rows, results)
        admitted = {path(item['Path']): item['Sha256'] for item in original['ActualCompileDependencies']}
        actual = suite.modules['probes'].isolated_dependencies([path(item['Path']) for item in row['Dependencies']],
            admitted, root=suite.base / 'source', cmsis=suite.base / 'cmsis')
        same(actual, row['Dependencies'], 'CPU-free dependency closure replay')
    objects = [path(row['Object']) for row in report['IsolatedCommon']] + list(suite.objects[3:])
    for label, emit in (('isolated-common', False), ('isolated-common-emit', True)):
        elf = root / 'links' / label / 'image.elf'
        index = _command(rows, 'link ' + label,
            _link_arguments(suite, objects, elf, elf.with_suffix('.map'), emit=emit))
        need(results[index].stdout == results[index].stderr == b'', 'clean actual isolation link')
        _saved_chain(suite, bundle, elf, objects)
    final = root / 'links/isolated-common-emit/image.elf'
    index = _command(rows, 'disassemble isolated-common-emit', [suite.tools['objdump'], '-d', final])
    need(results[index].stdout == _read(suite, bundle, str(final) + '.dis') and results[index].stderr == b'',
        'retained isolated final disassembly stream')
    same(report['IsolatedLinkedObjects'], [dict(Path=str(value), Sha256=sha(_read(suite, bundle, value)))
        for value in objects], 'three isolated and six exact original link inputs')
    return dict(SourceOwnership=ownership, Compilations=3, LinkedObjects=copy.deepcopy(report['IsolatedLinkedObjects']))


def _saved_chain(suite, bundle, elf, objects):
    prefix = str(elf)
    ir = [str(value) for value in objects if path(value) != path(suite.objects[8])]
    def lines(suffix):
        raw = _read(suite, bundle, prefix + suffix)
        need(type(raw) is bytes and raw and b'\0' not in raw, 'saved LTO chain bytes')
        values = raw.decode('utf-8').splitlines()
        need(all(value and value == value.strip() for value in values), 'saved LTO argument grammar')
        return [value.replace('\\\\', '\\') for value in values]
    wpa = lines('.ltrans_args')
    same([value for value in wpa if value.endswith('.o')], ir, 'actual ordered WPA input list')
    same(lines('.wpa.args.0'), ir, 'actual ordered WPA response')
    intermediate, machine = prefix + '.ltrans0.o', prefix + '.ltrans0.ltrans.o'
    ltrans = lines('.ltrans0.ltrans_args')
    need(ltrans[-1] == intermediate and ltrans.count('-o') == 1
        and ltrans[ltrans.index('-o') + 1] == machine, 'actual saved machine producer chain')
    same(lines('.ltrans0.ltrans.args.0'), [intermediate], 'actual LTRANS input response')
    output = lines('.ltrans.out')
    need(len(output) == 2 and re.fullmatch('[0-9]+', output[0]) and output[1] == intermediate, 'one LTO partition')
    suite.transport.require_elf32le(_read(suite, bundle, machine))
    return dict(Machine=machine, MachineSha256=sha(_read(suite, bundle, machine)),
        IntermediateSha256=sha(_read(suite, bundle, intermediate)), WPAInputs=ir,
        OsProcessTraceVerified=False, SourceToMachineSemanticProof=False)


def _copy_plan(suite, bundle, root, sources):
    for relative, raw in sources.items():
        need(_read(suite, bundle, path(root) / relative) == raw, 'exact private source/control plan: ' + relative)


def _attrs_records(suite, bundle, runner, rows, results):
    report, root = bundle['Result'], path(bundle['Root'])
    need(runner.commands_pass(rows), 'complete forty-five-command common attribute recipe')
    sources = runner.source_buffers(suite)
    ownership = suite.modules['ownership'].validate_common_sources(
        {name: sources[name] for name in suite.modules['ownership'].REQUIRED_SOURCES})
    annotations = suite.modules['attributes'].inspect_sources(sources)
    same(ownership, report['SourceOwnership'], 'hostile source ownership')
    same(annotations, report['SourceAnnotations'], 'fourteen independent declaration/definition annotations')
    specs = _driver_adapter(suite, bundle, rows, results)
    stress = suite.modules['attributes'].stress_sources()
    plans, compile_plan = {}, [('positive', index, suite.base / 'source', sources, runner.COMMON[index]) for index in range(3)]
    for index, role in enumerate(runner.ROLES):
        plan = suite.modules['attributes'].annotation_mutant(role, sources)
        label = 'mutant-' + role
        plans[label] = plan
        private = root / 'private' / label
        _copy_plan(suite, bundle, private, plan['Sources'])
        compile_plan.append((label, index, private, plan['Sources'], runner.COMMON[index]))
        control = report['AnnotationControls'][index]
        same(control['Edits'], plan['Edits'], 'source-derived two-site annotation mutation')
        same([control['Role'], control['Function'], control['ReplacedIRRole']], [role, plan['Function'], role], 'mutation role')
    for label, key in (('stress-protected', 'Protected'), ('stress-unprotected', 'Unprotected')):
        private = root / 'private' / label
        buffers = dict(sources, **{'stress.c': stress[key]})
        _copy_plan(suite, bundle, private, buffers)
        compile_plan.append((label, 0, private, buffers, 'stress.c'))
    need(len(report['Compilations']) == len(compile_plan) == 8, 'exact eight actual hostile compilations')
    by_group = {}
    for row, (label, index, source_root, buffers, relative) in zip(report['Compilations'], compile_plan):
        source = path(source_root) / relative
        need(row['Group'] == label and type(row['TemplateIndex']) is int and row['TemplateIndex'] == index
            and path(row['Source']) == source and _read(suite, bundle, source) == buffers[relative], 'hostile compile source role')
        flags = runner.flags_for(suite, index, source_root)
        _compile(suite, bundle, row, rows, results, label=label + ' ' + source.stem, index=index, flags=flags)
        _slim_record(suite, bundle, row, rows, results)
        names = _nm(suite, rows, results, row['Object'], label + ' ' + source.stem)
        if not label.startswith('stress-'):
            proof = suite.modules['attributes'].inspect_ir_undefined(names, runner.ROLES[index], mutation=label != 'positive')
            same(proof, row['IRImportProof'], 'actual hostile plugin source/import surface')
        same(names, row['IRImports']['Imports'], 'retained plugin undefined surface')
        by_group.setdefault(label, []).append(path(row['Object']))
    positive = by_group['positive']
    wanted = {'positive': positive, 'stress-protected': by_group['stress-protected'],
        'stress-unprotected': by_group['stress-unprotected']}
    for index, label in enumerate(runner.LOWERS[1:4]):
        value = list(positive)
        value[index] = by_group[label][0]
        wanted[label] = value
    need(tuple(row['Group'] for row in report['Lowerings']) == runner.LOWERS, 'all six actual lowering groups')
    for row in report['Lowerings']:
        label, objects = row['Group'], wanted[row['Group']]
        _lower_record(suite, bundle, runner, row, rows, results, objects, specs=specs, port=False)
    paired = dict(Function=stress['Function'], RequiredFamilies=stress['RequiredFamilies'], OnlyDifference=stress['OnlyDifference'],
        ProtectedSha256=sha(stress['Protected']), UnprotectedSha256=sha(stress['Unprotected']))
    same(paired, report['PairedStress'], 'protected/unprotected stress source token difference')
    return dict(SourceOwnership=ownership, SourceAnnotations=annotations, SourceMutations=len(plans),
        Compilations=8, Lowerings=6, PairedStress=paired)


def _driver_adapter(suite, bundle, rows, results):
    index = _command(rows, 'dump compiler specs', [suite.tools['gcc'], '-dumpspecs'])
    need(results[index].stdout and results[index].stderr == b'', 'actual fresh dumpspecs stream')
    original = _read(suite, bundle, bundle['Result']['DriverAdapter']['OriginalPath'])
    need(results[index].stdout == original, 'actual original compiler specs bytes')
    adapted = suite.modules['attributes'].adapt_specs(original)
    need(adapted['Specs'] == _read(suite, bundle, bundle['Result']['DriverAdapter']['AdaptedPath']), 'only bounded -lgcov specs delta')
    expected = {key: value for key, value in adapted.items() if key != 'Specs'}
    expected.update(OriginalPath=bundle['Result']['DriverAdapter']['OriginalPath'],
        AdaptedPath=bundle['Result']['DriverAdapter']['AdaptedPath'])
    same(expected, bundle['Result']['DriverAdapter'], 'retained specs adapter metadata')
    return path(expected['AdaptedPath'])


def _lower_record(suite, bundle, runner, row, rows, results, objects, *, specs, port):
    label, output = row['Group'], path(row['Object'])
    if port:
        supported = label != 'stress-raw'
        flags = runner.flags_for(suite, 3, supported=supported)
    else:
        flags = runner.flags_for(suite, 0, suite.base / 'source')
    argv = [str(suite.tools['gcc']), *flags]
    if specs is not None:
        argv.append('-specs=' + str(specs))
    argv.extend(('-v', '-flto-partition=one', '-save-temps=obj', '-Wl,-plugin-opt=-save-temps',
        '-nostdlib', '-r', '-flinker-output=nolto-rel', *(str(value) for value in objects), '-o', str(output)))
    index = _command(rows, 'lower ' + label, argv)
    need(results[index].stdout == b'' and results[index].stderr, 'actual verbose lower stream')
    expected_inputs = [dict(Path=str(value), Sha256=sha(_read(suite, bundle, value))) for value in objects]
    same(row['Inputs'], expected_inputs, 'actual lowering machine ownership inputs')
    if port:
        worker = runner.worker_chain(suite, output, objects, results[index].stderr,
            supported=label != 'stress-raw', specs=specs)
    else:
        machine, worker = runner.worker_chain(suite, output, objects, specs, results[index].stderr)
        need(path(worker['Machine']) == path(machine), 'actual common machine owner')
    same(worker, row['ActualWorker'], 'recomputed saved and executed worker chain')
    options = ['-drwC', '-z'] if port else ['-drwC']
    dis = row['Disassembly']['Path'] if port else row['Disassembly']
    at = _command(rows, 'disassemble ' + label, [suite.tools['objdump'], *options, output])
    need(results[at].stdout == _read(suite, bundle, dis) and results[at].stderr == b'', 'aggregate disassembly binding')
    if port:
        at = _command(rows, 'disassemble worker ' + label, [suite.tools['objdump'], *options, worker['Machine']])
        need(results[at].stdout == _read(suite, bundle, row['WorkerDisassembly']['Path']) and results[at].stderr == b'',
            'actual worker disassembly binding')
    return worker


def _port_records(suite, bundle, runner, rows, results):
    report, root, pure = bundle['Result'], path(bundle['Root']), suite.modules['policy']
    need(runner.commands_pass(rows) and len(report['Compilations']) == 5, 'complete selected-port command/compile set')
    specs = _driver_adapter(suite, bundle, rows, results)
    stress = pure.stress_source(suite.modules['attributes'])
    definitions, grouped = {}, {}
    for row, group, index in zip(report['Compilations'], ('selected',) * 3 + runner.GROUPS[1:], (3, 4, 5, 3, 3)):
        need(row['Group'] == group and type(row['TemplateIndex']) is int and row['TemplateIndex'] == index,
            'fixed selected/stress provider roles')
        source = path(suite.source(index)['Source']) if group == 'selected' else root / 'private' / group / 'stress.c'
        if group != 'selected':
            need(_read(suite, bundle, source) == stress['Source'], 'identical ordinary policy stress source')
        else:
            need(_read(suite, bundle, source) == _read(suite, bundle, suite.source(index)['Source']), 'unchanged selected provider source')
        need(path(row['Source']) == source, 'exact selected/stress source path')
        flags = runner.flags_for(suite, index, supported=group != 'stress-raw')
        _compile(suite, bundle, row, rows, results, label=group + ' ' + source.stem, index=index, flags=flags, source=source)
        _slim_record(suite, bundle, row, rows, results)
        imports = _nm(suite, rows, results, row['Object'], group + ' ' + source.stem)
        same(imports, row['IRImports']['Imports'], 'actual selected/stress plugin imports')
        if group == 'selected':
            records = _nm(suite, rows, results, row['Object'], group + ' ' + source.stem,
                defined=True, parser=runner.parse_ir_definitions)
            same(records, row['IRDefinitions'], 'actual three provider definition streams')
            definitions[('runtime', 'boot', 'exception')[index - 3]] = records
        grouped.setdefault(group, []).append(path(row['Object']))
    surface = pure.inspect_ir_definitions(definitions)
    same(surface, report['IRDefinitionSurface'], 'fixed 31-definition selected IR surface replay')
    same(report['SelectedSourceHashes'], {name: sha(_read(suite, bundle, suite.base / 'source' / name))
        for name in runner.SELECTED}, 'selected source identity')
    need(tuple(row['Group'] for row in report['Lowerings']) == runner.GROUPS, 'all selected and paired stress lowers')
    for row in report['Lowerings']:
        group = row['Group']
        _lower_record(suite, bundle, runner, row, rows, results, grouped[group],
            specs=specs if group == 'stress-raw' else None, port=True)
    final = report['FinalLink']
    argv, objects = runner.final_arguments(suite, grouped['selected'], path(final['Path']), path(final['Map']))
    index = _command(rows, 'link final-supported', argv)
    same(argv, final['Argv'], 'global seven-counter final recipe')
    same([str(value) for value in objects], final['Objects'], 'exact final nine input objects')
    worker = runner.worker_chain(suite, path(final['Path']), objects, results[index].stderr, supported=True)
    same(worker, final['ActualWorker'], 'actual final worker option/input/machine chain')
    for label, obj, dis in (('disassemble final-supported', final['Path'], final['Disassembly']),
            ('disassemble worker final-supported', worker['Machine'], final['WorkerDisassembly'])):
        index = _command(rows, label, [suite.tools['objdump'], '-drwC', '-z', obj])
        need(results[index].stdout == _read(suite, bundle, dis['Path']) and results[index].stderr == b'',
            'complete -z final/worker disassembly streams')
    same(final['UnchangedOtherSixObjects'], [dict(Index=index, Path=str(objects[index]),
        Sha256=sha(_read(suite, bundle, objects[index]))) for index in (0, 1, 2, 6, 7, 8)],
        'other six input object bytes, not generated-body identity')
    need(report['Compilations'][-1]['SourceSha256'] == report['Compilations'][-2]['SourceSha256'] == stress['SourceSha256'],
        'same actual source in paired policy control')
    return dict(IRDefinitionSurface=surface, Compilations=5, Lowerings=3, FinalInputs=final['Objects'],
        GlobalSevenCounterFinal=True, OtherSixInputObjectsUnchanged=True, OtherSixGeneratedBodiesUnchanged=False)


def verify_records(suites, bundles, modules, watch):
    """Reconstruct all 134 actual command recipes and their retained evidence."""
    _maps(suites, bundles, modules)
    need(all(suites[role].watch is watch for role in ROLES), 'one enclosing admission watch')
    handlers = dict(zip(ROLES, (_abi_records, _isolation_records, _attrs_records, _port_records)))
    evidence = {}
    for role in ROLES:
        suite, bundle = suites[role], bundles[role]
        rows, results = journals(suite, bundle, COUNTS[role])
        evidence[role] = handlers[role](suite, bundle, modules[role], rows, results)
    return dict(Status='CM3-LTO-COMPONENT-RECORD-REPLAY-PASS', Scope=SCOPE,
        CommandCounts=dict(COUNTS), CommandsReclassified=sum(COUNTS.values()), Components=evidence,
        PriorComponentPASSAuthority=False, CompilerExecuted=False, **FALSE_CLAIMS)


def _slim_machines(suite, bundle, core):
    report = bundle['Result']
    rows = list(report['IsolatedCommon'] if 'IsolatedCommon' in report else report['Compilations'])
    if 'ABIProbes' in report:
        rows += [row for row in report['ABIProbes'].values() if row.get('Object')]
    evidence = []
    for row in rows:
        image = core._ELF(path(row['Object']), 'ET_REL')
        need(sha(image.data) == row.get('ObjectSha256', row.get('SlimIR', {}).get('Sha256')),
            'same slim object bytes in supplied reader')
        need(any(section.name.startswith('.gnu.lto_') for section in image.sections)
            and not any(section.header.sh_size and section.header.sh_flags & 4 for section in image.sections),
            'actual slim IR, no native executable fallback')
        evidence.append(dict(Path=str(path(row['Object'])), Sha256=sha(image.data), SlimIR=True))
    return evidence


def _abi_machines(suite, bundle, core):
    report = bundle['Result']
    positive = core.compare_load_images(path(suite.result['Links'][0]['Path']), path(report['PositiveAuthority']['Replayed']))
    same(positive, report['PositiveAuthority']['LoadImageComparison'], 'recomputed ABI positive load-image reproduction')
    raw_equal = _read(suite, bundle, suite.result['Links'][0]['Path']) == _read(suite, bundle, report['PositiveAuthority']['Replayed'])
    need(raw_equal is report['PositiveAuthority']['RawElfByteIdentical'], 'actual positive raw ELF comparison')
    evidence = []
    for row in report['Controls'][:3]:
        image = core._ELF(path(row['DiagnosticMachine']['Path']), 'ET_REL')
        need(sha(image.data) == row['DiagnosticMachine']['Sha256'], 'actual negative diagnostic machine')
        undefined = {symbol['name'] for symbol in image.symbols if symbol['section'] == 'SHN_UNDEF' and symbol['name']}
        need(row['Expected'] in undefined, 'the intended link failure exists in actual generated machine symbols')
        sites = {(image.names[section], offset) for (section, offset), (kind, target) in image.relocations.items()
            if target['name'] == row['Expected'] and target['section'] == 'SHN_UNDEF'}
        need(sites and all((ref['Section'], ref['Offset']) in sites for ref in row['Classification']['References']),
            'undefined transcript references bind actual original machine REL sites')
        evidence.append(dict(Name=row['Name'], MachineSha256=sha(image.data), IntendedUndefined=row['Expected'],
            ReferenceSites=[dict(Section=section, Offset=offset) for section, offset in sorted(sites)]))
    return dict(PositiveLoadImageComparison=positive, NegativeMachines=evidence,
        DuplicateIRProvidersReclassifiedInRecords=True)


def _isolation_machines(suite, bundle, runner, core):
    report, root = bundle['Result'], path(bundle['Root'])
    original, original_emit = suite.result['Links']
    ordinary, emitted = root / 'links/isolated-common/image.elf', root / 'links/isolated-common-emit/image.elf'
    comparisons = dict(OriginalToIsolated=core.compare_load_images(path(original['Path']), ordinary),
        IsolatedTwins=core.compare_load_images(ordinary, emitted),
        OriginalTwins=core.compare_load_images(path(original['Path']), path(original_emit['Path'])))
    same(comparisons, report['LoadImageComparisons'], 'three recomputed structural load comparisons')
    source = _read(suite, bundle, suite.base / 'source/fiber/port/ARM_CM3/fiber_port.c')
    proofs = []
    for label, machine, final, dis, link_map, assembly in (
            ('Original', path(original_emit['Machine']), path(original_emit['Path']), path(str(original_emit['Path']) + '.dis'),
             path(original_emit['Map']), path(str(original_emit['Path']) + '.ltrans0.ltrans.s')),
            ('Isolated', path(str(emitted) + '.ltrans0.ltrans.o'), emitted, path(str(emitted) + '.dis'),
             emitted.with_suffix('.map'), path(str(emitted) + '.ltrans0.ltrans.s'))):
        image = core.FinalImage(machine, final, dis, provider_objects={str(machine): machine,
            str(suite.objects[8]): path(suite.objects[8])}, link_map=link_map, float_abi='soft')
        raw = _read(suite, bundle, assembly)
        proof = suite.modules['slot'].inspect(source, raw, image, core)
        runner.require_slot_result(proof, source, raw, image)
        proofs.append(dict(Kind=label, Proof=proof))
    same(proofs, report['SlotProofs'], 'two complete bounded slot proofs, all original/applied references')
    return dict(LoadImageComparisons=comparisons, SlotProofs=proofs)


def _attrs_machines(suite, bundle, runner, core):
    report, proofs = bundle['Result'], []
    for row in report['Lowerings']:
        label = row['Group']
        mutation = 'ctxrt_attribute_stress' if label == 'stress-unprotected' else runner.MUTANTS.get(label)
        stress = label.startswith('stress-')
        need(row['Mutation'] == mutation and type(row['Stress']) is bool and row['Stress'] is stress,
            'fixed attribute machine role')
        aggregate, worker = (core._ELF(path(value), 'ET_REL') for value in (row['Object'], row['ActualWorker']['Machine']))
        left = suite.modules['attributes'].inspect_lowered(aggregate, core, mutation=mutation, stress=stress)
        right = suite.modules['attributes'].inspect_lowered(worker, core, mutation=mutation, stress=stress)
        same(left, row['Effects'], 'complete recomputed common aggregate effects')
        same(right, row['WorkerEffects'], 'complete recomputed common actual worker effects')
        rejected = False
        if mutation is not None:
            try:
                suite.modules['attributes'].inspect_lowered(aggregate, core, stress=stress)
            except suite.modules['attributes'].Rejected:
                rejected = True
            need(rejected, 'unchanged common clean predicate rejects actual compiled control')
        need(row['OriginalProtectedPredicateRejected'] is rejected, 'actual attribute negative disposition')
        proofs.append(dict(Group=label, Effects=left, WorkerEffects=right, CleanPredicateRejected=rejected))
    need(len(proofs) == 6, 'all twelve aggregate/worker attribute body proofs')
    return dict(Lowerings=proofs, ActualMachineRoles=12, CleanPredicateRefusals=4)


def _port_machines(suite, bundle, runner, core):
    report, pure = bundle['Result'], suite.modules['policy']
    surface = pure.inspect_ir_definitions({role: row['IRDefinitions'] for role, row in zip(
        ('runtime', 'boot', 'exception'), report['Compilations'][:3])})
    proofs = []
    for row in report['Lowerings']:
        group = row['Group']
        current = {}
        for key, obj, dis in (('Effects', row['Object'], row['Disassembly']['Path']),
                ('WorkerEffects', row['ActualWorker']['Machine'], row['WorkerDisassembly']['Path'])):
            image = core._ELF(path(obj), 'ET_REL')
            raw = _read(suite, bundle, dis)
            if group == 'selected':
                proof = pure.inspect_lowered(image, core, raw, surface)
            else:
                proof = pure.inspect_stress(image, core, raw, suite.modules['attributes'], supported=group != 'stress-raw')
                if group == 'stress-raw':
                    runner.require_raw_stress_rejected(suite, image, core, raw)
            same(proof, row[key], 'complete selected-port/paired stress machine replay')
            current[key] = proof
        proofs.append(dict(Group=group, **current))
    final = report['FinalLink']
    machine, image = core._ELF(path(final['ActualWorker']['Machine']), 'ET_REL'), core._ELF(path(final['Path']), 'ET_EXEC')
    worker = pure.inspect_lowered(machine, core, _read(suite, bundle, final['WorkerDisassembly']['Path']), surface, whole_image=True)
    emitted = pure.inspect_final(image, core, _read(suite, bundle, final['Disassembly']['Path']), surface)
    same(worker, final['WorkerEffects'], 'four linker-script imports only in actual final LTRANS worker')
    same(emitted, final['Effects'], 'undefined-free complete final executable policy census/vector proof')
    transport = suite.modules['transport_roots'].NativeCM3LTOImage(core, path(final['ActualWorker']['Machine']),
        path(final['Path']), path(final['Disassembly']['Path']), provider_objects={
            final['ActualWorker']['Machine']: path(final['ActualWorker']['Machine']),
            str(suite.objects[8]): path(suite.objects[8])}, link_map=path(final['Map']))
    roots = [transport.function(name) for name in ('fiber_port_start_first_context', 'SVC_Handler', 'PendSV_Handler')]
    same(roots, final['TransferRoots'], 'three complete original/applied root/origin preservation proofs')
    return dict(Lowerings=proofs, FinalWorkerEffects=worker, FinalEffects=emitted, TransferRoots=roots, ActualMachineRoles=8)


def inspect_machines(suites, bundles, modules, core, graph):
    """Recompute all machine predicates in the caller's ONE immutable scope."""
    _maps(suites, bundles, modules)
    need(core is not None and graph is not None, 'caller-owned supplied reader scope')
    slim = {role: _slim_machines(suites[role], bundles[role], core) for role in ROLES}
    expected = dict(zip(ROLES, (7, 3, 8, 5)))
    need({role: len(rows) for role, rows in slim.items()} == expected, 'all twenty-three actual slim objects')
    evidence = {
        'ABIControls': _abi_machines(suites['ABIControls'], bundles['ABIControls'], core),
        'Isolation': _isolation_machines(suites['Isolation'], bundles['Isolation'], modules['Isolation'], core),
        'CommonAttributes': _attrs_machines(suites['CommonAttributes'], bundles['CommonAttributes'], modules['CommonAttributes'], core),
        'PortPolicy': _port_machines(suites['PortPolicy'], bundles['PortPolicy'], modules['PortPolicy'], core),
    }
    return dict(Status='CM3-LTO-COMPONENT-MACHINE-REPLAY-PASS', Scope=SCOPE, SlimIR=slim,
        Components=evidence, SuppliedSingleReaderScope=True, NestedReaderContextOpened=False,
        PriorComponentPASSAuthority=False, CompilerExecuted=False,
        ExecutedReaderBuffers=copy.deepcopy(graph.executed), **FALSE_CLAIMS)
