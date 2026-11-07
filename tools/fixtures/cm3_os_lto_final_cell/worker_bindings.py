"""Pure journal/cohort bindings for ten caller-admitted Os worker replays.

The caller admits batch, native and root/artifacts.json before calling bind.
Every read goes through the supplied immutable reader; physical closure, helper
authentication, worker proof comparison and machine predicates remain caller-owned.
"""

import copy
import hashlib
import json
import math
from pathlib import Path
import re


COMMON = ('positive', 'mutant-engine', 'mutant-state', 'mutant-panic',
          'stress-protected', 'stress-unprotected')
PORT = ('selected', 'stress-supported', 'stress-raw')
STEMS = ('context_core', 'context_runtime_state', 'context_panic')
PORT_STEMS = ('fiber_port', 'fiber_port_boot', 'fiber_port_exception')
MUTATIONS = (None, 'ctxrt_v1_current', 'fiber_internal_runtime_load_current_context',
             'fiber_panic', None, 'ctxrt_attribute_stress')
RAW = ('-finstrument-functions', '-fstack-protector-all', '-fprofile-arcs',
       '-ftest-coverage', '-fsanitize=undefined', '-fsanitize-coverage=trace-pc')
COUNTERS = ('-fno-instrument-functions', '-fno-stack-protector', '-fno-profile-arcs',
            '-fno-test-coverage', '-fno-sanitize=all', '-fno-sanitize-coverage=trace-pc',
            '-mgeneral-regs-only')
LOWER = ('-flto-partition=one', '-nostdlib', '-r', '-flinker-output=nolto-rel')
SAVED = ('-v', '-flto-partition=one', '-save-temps=obj', '-Wl,-plugin-opt=-save-temps')


class Rejected(ValueError):
    pass


def need(value, detail):
    if not value:
        raise Rejected('REJECT:CM3-OS-LTO-WORKER-BINDINGS:' + detail)


def sha(raw):
    need(type(raw) is bytes, 'immutable bytes')
    return hashlib.sha256(raw).hexdigest().upper()


def _hash(value):
    need(type(value) is str and re.fullmatch('[0-9A-F]{64}', value) is not None, 'literal SHA256')
    return value


def _path(value):
    need(isinstance(value, Path) or type(value) is str, 'literal path')
    need(str(value) and not any(char in str(value) for char in '\0\r\n'), 'path grammar')
    path = Path(value)
    need(path.is_absolute() and '..' not in path.parts, 'absolute lexical path')
    return path


def _argv(value):
    need(type(value) is list and value and all(type(arg) is str and arg
         and not any(char in arg for char in '\0\r\n') for arg in value), 'literal argv')
    return value


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key/' + key)
            result[key] = value
        return result

    def constant(value):
        raise Rejected('REJECT:CM3-OS-LTO-WORKER-BINDINGS:nonfinite JSON/' + value)

    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Rejected('REJECT:CM3-OS-LTO-WORKER-BINDINGS:journal JSON') from error


def bind(batch, root, native, read, helpers):
    """Return ordered replay plans, without consulting stored worker evidence.

    helpers has exactly attributes.adapt_specs, port_policy.require_effective_options,
    attribute_runner.argument_lines and guard._same. read must already admit the
    manifest itself and all native objects separately from generated batch files.
    Compilation records select cohorts and bind recorded discovery/compile
    commands to admitted source bytes. Source-to-IR semantics are not proved.
    No filesystem operation, tool execution or machine verdict is performed here.
    """
    root = _path(root)
    need(type(helpers) is dict and set(helpers) ==
         {'attributes', 'port_policy', 'attribute_runner', 'guard'}, 'explicit helper roles')
    for name, method in (('attributes', 'adapt_specs'), ('port_policy', 'require_effective_options'),
                         ('attribute_runner', 'argument_lines'), ('guard', '_same')):
        need(callable(getattr(helpers[name], method, None)), 'explicit helper/' + name)
    need(callable(read), 'immutable reader')

    def same(left, right, label):
        try:
            helpers['guard']._same(left, right, label)
        except ValueError as error:
            raise Rejected('REJECT:CM3-OS-LTO-WORKER-BINDINGS:' + label) from error

    for record, status in ((batch, 'BUILT-PENDING-READER'), (native, 'PASS')):
        need(type(record) is dict and record.get('Status') == status
             and record.get('Profile') == 'CM3' and record.get('Mode') == 'Os-lto'
             and record.get('Linkage') == 'direct' and record.get('LTO') is True, 'actual Os disposition')
    hashes = batch.get('InputHashes')
    need(type(hashes) is dict and hashes, 'admitted input hashes')
    authority = {}
    for name, digest in hashes.items():
        path = _path(name)
        need(path not in authority, 'ambiguous input path')
        authority[path] = _hash(digest)

    manifest_raw = read(root / 'artifacts.json')
    sha(manifest_raw)
    manifest = _json(manifest_raw)
    need(type(manifest) is dict and set(manifest) == {'Artifacts'}
         and type(manifest['Artifacts']) is dict and manifest['Artifacts'], 'admitted artifact manifest')
    artifacts = {}
    for name, digest in manifest['Artifacts'].items():
        need(type(name) is str and name and '\\' not in name and ':' not in name
             and not any(char in name for char in '\0\r\n')
             and all(part not in ('', '.', '..') for part in name.split('/'))
             and name != 'artifacts.json', 'relative artifact key')
        path = root.joinpath(*name.split('/'))
        need(path.is_relative_to(root) and path not in artifacts, 'distinct owned artifact')
        artifacts[path] = _hash(digest)
        if path in authority:
            same(artifacts[path], authority[path], 'manifest/input hash')

    consumed = {}

    def raw(path, expected=None):
        path = _path(path)
        registry = artifacts if path.is_relative_to(root) else authority
        need(path in registry, 'read outside admitted manifest/inputs/' + str(path))
        digest = registry[path]
        if expected is not None:
            same(_hash(expected), digest, 'declared read hash/' + str(path))
        value = read(path, digest)
        need(sha(value) == digest, 'read hash/' + str(path))
        need(path not in consumed or consumed[path] == value, 'immutable repeated read')
        consumed[path] = value
        return value

    commands = batch.get('Commands')
    need(type(commands) is list and len(commands) == 134, '134-command batch')
    same(_json(raw(root / 'commands.json', _hash(batch.get('CommandsSha256')))), commands, 'complete command journal')
    gcc = _path(native.get('CapturedCompiler'))
    objdump = gcc.with_name('arm-none-eabi-objdump.exe')

    def command(index, label):
        need(type(index) is int and 0 <= index < 134, 'fixed journal index')
        row = commands[index]
        need(type(row) is dict and row.get('Label') == label and row.get('State') == 'TERMINAL'
             and row.get('Status') == 'PASS' and row.get('TimedOut') is False
             and type(row.get('Exit')) is int and row['Exit'] == 0
             and type(row.get('ExpectedExit')) is int and row['ExpectedExit'] == 0
             and type(row.get('JournalErrors', [])) is list and row.get('JournalErrors', []) == []
             and row.get('Error') is None and row.get('Cwd') == str(root), 'terminal journal/' + str(index))
        need(type(row.get('Seconds')) in (int, float) and math.isfinite(row['Seconds'])
             and row['Seconds'] >= 0, 'finite journal duration')
        _argv(row.get('Argv'))
        prefix = 'commands/%03d' % index
        same(_json(raw(root / (prefix + '.json'))), row, 'per-command journal/' + str(index))
        streams = []
        for field, suffix in (('Stdout', '.stdout'), ('Stderr', '.stderr')):
            same(row.get(field), prefix + suffix, 'fixed stream path/' + field)
            streams.append(raw(root / (prefix + suffix), _hash(row.get(field + 'Sha256'))))
        return row, streams[0], streams[1]

    def indices(row, first, stop):
        need(type(row) is dict, 'phase row')
        same(row.get('CommandIndices'), list(range(first, stop)), 'fixed row command range')

    def specs_adapter(record, directory, index):
        original, adapted = root / directory / 'original.specs', root / directory / 'no-auto-gcov.specs'
        row, stdout, stderr = command(index, 'dump compiler specs')
        same(row['Argv'], [str(gcc), '-dumpspecs'], 'dumpspecs argv')
        need(stdout and stderr == b'', 'clean actual dumpspecs stdout')
        need(type(record) is dict, 'specs adapter record')
        source = raw(original, _hash(record.get('OriginalSha256')))
        need(source == stdout, 'original specs are dumpspecs stdout')
        try:
            rebuilt = helpers['attributes'].adapt_specs(source)
        except ValueError as error:
            raise Rejected('REJECT:CM3-OS-LTO-WORKER-BINDINGS:specs reconstruction') from error
        need(type(rebuilt) is dict and type(rebuilt.get('Specs')) is bytes, 'adapted specs result')
        expected = {key: value for key, value in rebuilt.items() if key != 'Specs'}
        expected.update(OriginalPath=str(original), AdaptedPath=str(adapted))
        same(record, expected, 'entire reconstructed specs adapter')
        need(raw(adapted, _hash(record.get('AdaptedSha256'))) == rebuilt['Specs'], 'exact adapted specs bytes')
        return adapted

    common = batch.get('CommonAttributesDeferredReader')
    need(type(common) is dict, 'common deferred record')
    common_specs = specs_adapter(common.get('DriverAdapter'), 'attributes/driver', 53)
    port_specs = specs_adapter(batch.get('PortPolicyDriverAdapter'), 'port-policy/driver', 98)

    sources = native.get('Sources')
    need(type(sources) is list and len(sources) == 9, 'nine separately admitted native source/object records')

    def native_source(index):
        row = sources[index]
        need(type(row) is dict, 'native source record')
        path = _path(row.get('Source'))
        need(not path.is_relative_to(root), 'native source is not a generated batch source')
        digest = _hash(row.get('SourceSha256'))
        same(authority.get(path), digest, 'separately admitted native source hash')
        return path, digest

    def compilation(row, group, index, first, stop, path, source, *, role=None, source_hash=None):
        indices(row, first, stop)
        same(row.get('Group'), group, 'compilation group')
        same(row.get('TemplateIndex'), index, 'compilation template')
        if role is not None:
            same(row.get('Role'), role, 'common compilation role')
        same(row.get('Object'), str(path), 'fixed compiled IR object')
        same(row.get('Source'), str(source), 'independent compilation source path')
        digest = _hash(row.get('SourceSha256'))
        same(authority.get(source), digest, 'compilation source InputHashes binding')
        if source_hash is not None:
            same(digest, source_hash, 'native compilation source hash')
        raw(source, digest)
        raw(path, _hash(row.get('ObjectSha256')))
        flags = _argv(row.get('CompileFlags'))
        discovery, actual = path.with_suffix('.discovery.d'), path.with_suffix('.compile.d')
        for field, expected in (('DiscoveryDependencyFile', discovery), ('CompileDependencyFile', actual)):
            if field in row:
                same(row[field], str(expected), 'recorded dependency path/' + field)
        target = 'pilot-source-' + str(index)
        discover, stdout, stderr = command(first, 'discover ' + group + ' ' + path.stem)
        same(discover['Argv'], [str(gcc), *flags, '-M', '-MF', str(discovery), '-MT', target, str(source)],
             'recorded discovery argv/' + str(first))
        need(stdout == stderr == b'', 'clean discovery streams/' + str(first))
        compile_row, stdout, stderr = command(first + 1, 'compile ' + group + ' ' + path.stem)
        same(compile_row['Argv'], [str(gcc), *flags, '-MD', '-MF', str(actual), '-MT', target,
                                 '-c', str(source), '-o', str(path)], 'recorded compile argv/' + str(first + 1))
        need(stdout == stderr == b'', 'clean compile streams/' + str(first + 1))
        return path

    compiled = common.get('Compilations')
    need(type(compiled) is list and len(compiled) == 8, 'eight ordered common compilations')
    common_ir = []
    for position, (group, index, first) in enumerate((('positive', 0, 54), ('positive', 1, 58),
            ('positive', 2, 62), ('mutant-engine', 0, 68), ('mutant-state', 1, 74),
            ('mutant-panic', 2, 80), ('stress-protected', 0, 86), ('stress-unprotected', 0, 92))):
        stem = 'stress' if position >= 6 else STEMS[index]
        path = root / 'attributes/ir' / group / (stem + '.o')
        if position < 3:
            source, source_hash = native_source(index)
        else:
            private = root / 'private' / ('attributes-' + group)
            source = private / 'stress.c' if position >= 6 else private / 'context' / (stem + '.c')
            source_hash = None
        common_ir.append(compilation(compiled[position], group, index, first, first + 4, path, source,
                                     role=('engine', 'state', 'panic')[index], source_hash=source_hash))
    positive = common_ir[:3]
    cohorts = [list(positive)]
    for index in range(3):
        cohort = list(positive)
        cohort[index] = common_ir[3 + index]
        cohorts.append(cohort)
    cohorts.extend(([common_ir[6]], [common_ir[7]]))

    port_compiled = batch.get('PortPolicyCompilations')
    need(type(port_compiled) is list and len(port_compiled) == 5, 'five ordered port compilations')
    port_ir = []
    for position, (group, index, first, count) in enumerate((('selected', 3, 99, 5),
            ('selected', 4, 104, 5), ('selected', 5, 109, 5),
            ('stress-supported', 3, 117, 4), ('stress-raw', 3, 124, 4))):
        stem = PORT_STEMS[position] if position < 3 else 'stress'
        path = root / 'port-policy/ir' / group / (stem + '.o')
        need(type(port_compiled[position]) is dict, 'port compilation row')
        same(port_compiled[position].get('SupportedPolicy'), group != 'stress-raw', 'compiled port policy')
        if position < 3:
            source, source_hash = native_source(index)
        else:
            source, source_hash = root / 'port-policy/private' / group / 'stress.c', None
        port_ir.append(compilation(port_compiled[position], group, index, first, first + count, path, source,
                                   source_hash=source_hash))
    need(len(set(common_ir + port_ir)) == 13, 'thirteen distinct fresh IR objects')

    originals = []
    for row in sources:
        need(type(row) is dict, 'native source record')
        path = _path(row.get('Object'))
        need(not path.is_relative_to(root), 'native objects are not generated batch objects')
        raw(path, _hash(row.get('ObjectSha256')))
        originals.append(path)
    need(len(set(originals)) == 9, 'distinct native objects')

    def options(argv, specs, supported, *, stage=None, output=None, final=False):
        _argv(argv)
        wanted_specs = [] if specs is None else ['-specs=' + str(specs)]
        same([arg for arg in argv if arg.startswith(('-specs', '--specs'))], wanted_specs, 'exact unsplit specs')
        need(not any(arg.startswith('@') for arg in argv), 'no unbound response indirection')
        metadata = [arg for arg in argv if arg.startswith(('-fltrans-output-list', '--fltrans-output-list'))]
        same(metadata, ['-fltrans-output-list=' + str(output) + '.ltrans.out'] if stage == '-fwpa' else [],
             'exact owned WPA output-list metadata')
        markers = [arg for arg in argv if arg.startswith(('-fwpa', '-fltrans', '--fwpa', '--fltrans'))
                   and arg not in metadata]
        same(markers, [] if stage is None else [stage], 'exact worker stage')
        need(not any(arg in ('-marm', '-lgcov') or arg.startswith(('--march', '--mlibarch')) for arg in argv),
             'foreign target/runtime spelling')
        try:
            helpers['port_policy'].require_effective_options(argv, supported=supported is True)
        except ValueError as error:
            raise Rejected('REJECT:CM3-OS-LTO-WORKER-BINDINGS:effective Os options') from error
        for arg in argv:
            need(not arg.startswith('-flto-partition') or arg == '-flto-partition=one', 'one partition option')
            need(not arg.startswith('-flinker-output') or arg ==
                 ('-flinker-output=exec' if final else '-flinker-output=nolto-rel'),
                 'exact lowering kind')
        for flag in (('-flto-partition=one', '-nostdlib') if final else LOWER):
            need(flag in argv, 'required lowering/link flag/' + flag)
        if final:
            need('-r' not in argv, 'final link is not relocatable lowering')

    def disassembly(index, label, target, binding, saved_path=None):
        row, stdout, stderr = command(index, label)
        same(row['Argv'], [str(objdump), '-drwC', '-z', str(target)], 'zero-inclusive disassembly argv')
        need(stdout and stderr == b'', 'clean actual disassembly stream')
        need(type(binding) is dict, 'disassembly binding')
        path = _path(binding.get('Path'))
        same(str(path), str(saved_path or Path(str(target) + '.dis')), 'fixed disassembly path')
        need(raw(path, _hash(binding.get('Sha256'))) == stdout, 'disassembly equals command stdout')

    def plan(component, group, row, output, objects, specs, supported, first, flags, *, final=False):
        indices(row, first, first + (2 if component == 'CommonAttributes' else 3))
        need(len(objects) == len(set(objects)), 'distinct ordered IR cohort')
        label = 'link final-supported' if final else 'lower ' + group
        journal, stdout, diagnostics = command(first, label)
        need(stdout == b'' and diagnostics, 'actual verbose worker stderr')
        options(journal['Argv'], specs, supported, output=output, final=final)
        need(journal['Argv'].count('-o') == 1, 'one driver output option')
        same(journal['Argv'][-2:], ['-o', str(output)], 'exact trailing driver output pair')
        same([arg for arg in journal['Argv'][:-2] if arg.endswith('.o')],
             [str(path) for path in objects], 'ordered driver objects')
        if not final:
            expected = [str(gcc), *flags, *([] if specs is None else ['-specs=' + str(specs)]),
                        *SAVED, '-nostdlib', '-r', '-flinker-output=nolto-rel', *map(str, objects), '-o', str(output)]
            same(journal['Argv'], expected, 'complete lowering argv')
        for suffix, stage in (('.ltrans_args', '-fwpa'), ('.ltrans0.ltrans_args', '-fltrans')):
            try:
                args = helpers['attribute_runner'].argument_lines(raw(Path(str(output) + suffix)))
            except (ValueError, UnicodeError) as error:
                raise Rejected('REJECT:CM3-OS-LTO-WORKER-BINDINGS:saved argument grammar') from error
            options(args, specs, supported, stage=stage, output=output, final=final)
        if component == 'CommonAttributes':
            roles = row.get('Roles')
            need(type(roles) is dict, 'common role bindings')
            for role, path in (('Object', output), ('Machine', Path(str(output) + '.ltrans0.ltrans.o')),
                    ('WpaArguments', Path(str(output) + '.ltrans_args')),
                    ('LtransArguments', Path(str(output) + '.ltrans0.ltrans_args')),
                    ('DriverSpecs', specs), ('Diagnostics', root / journal['Stderr'])):
                need(type(roles.get(role)) is dict, 'common role/' + role)
                same(roles[role].get('Path'), str(path), 'common role path/' + role)
                same(_hash(roles[role].get('Sha256')), artifacts.get(path), 'common role hash/' + role)
            need(raw(root / journal['Stderr'], roles['Diagnostics']['Sha256']) == diagnostics, 'same common diagnostics journal')
            disassembly(first + 1, 'disassemble ' + group, output, roles.get('Disassembly'), output.with_suffix('.dis'))
            stored = None
        else:
            if not final:
                same(row.get('SupportedPolicy'), supported, 'port policy selector')
            disassembly(first + 1, 'disassemble ' + group, output, row.get('Disassembly'))
            disassembly(first + 2, 'disassemble worker ' + group,
                        Path(str(output) + '.ltrans0.ltrans.o'), row.get('WorkerDisassembly'))
            need(type(row.get('ActualWorker')) is dict, 'stored worker comparison target')
            stored = copy.deepcopy(row['ActualWorker'])
        return dict(Component=component, Group='Final' if final else group, Output=output, Objects=list(objects), Specs=specs,
                    Diagnostics=diagnostics, Supported=supported, StoredWorker=stored)

    lowers = common.get('Lowerings')
    need(type(lowers) is list and len(lowers) == 6, 'six ordered common lowerings')
    plans = []
    for position, (group, first) in enumerate(zip(COMMON, (66, 72, 78, 84, 90, 96))):
        row, objects = lowers[position], cohorts[position]
        need(type(row) is dict, 'common lowering row')
        same(row.get('Group'), group, 'common group')
        same(row.get('Mutation'), MUTATIONS[position], 'common mutation')
        same(row.get('Stress'), position >= 4, 'literal common stress selector')
        same(row.get('Inputs'), [dict(Path=str(path), Sha256=artifacts[path]) for path in objects], 'common input records')
        output = root / 'attributes/lowered' / group / 'aggregate.o'
        plans.append(plan('CommonAttributes', group, row, output, objects, common_specs, None, first,
                          compiled[0]['CompileFlags']))
    lowers = batch.get('PortPolicyLowerings')
    need(type(lowers) is list and len(lowers) == 3, 'three ordered port lowerings')
    for position, (group, first, objects) in enumerate(zip(PORT, (114, 121, 128),
                                                         (port_ir[:3], [port_ir[3]], [port_ir[4]]))):
        row = lowers[position]
        need(type(row) is dict, 'port lowering row')
        output = root / 'port-policy/lowered' / group / 'aggregate.o'
        same(row.get('Group'), group, 'port group')
        same(row.get('Object'), str(output), 'port aggregate path')
        same(_hash(row.get('ObjectSha256')), artifacts.get(output), 'port aggregate hash')
        same(row.get('Inputs'), [dict(Path=str(path), Sha256=artifacts[path]) for path in objects], 'port input records')
        flags = port_compiled[0 if position < 2 else 4]['CompileFlags']
        plans.append(plan('PortPolicy', group, row, output, objects, port_specs if position == 2 else None,
                          position != 2, first, flags))

    final = batch.get('PortPolicyFinalLink')
    need(type(final) is dict, 'port final record')
    output, link_map = root / 'port-policy/final-supported/image.elf', root / 'port-policy/final-supported/image.map'
    objects = originals[:3] + port_ir[:3] + originals[6:]
    same(final.get('Objects'), list(map(str, objects)), 'final nine-object cohort')
    same(final.get('UnchangedOtherSixObjects'), [dict(Index=index, Path=str(originals[index]),
         Sha256=sources[index]['ObjectSha256']) for index in (0, 1, 2, 6, 7, 8)], 'six separately admitted originals')
    same(final.get('Path'), str(output), 'final output path')
    same(_hash(final.get('Sha256')), artifacts.get(output), 'final output hash')
    same(final.get('Map'), str(link_map), 'final map path')
    same(_hash(final.get('MapSha256')), artifacts.get(link_map), 'final map hash')
    original_commands = native.get('Commands')
    need(type(original_commands) is list, 'native command journal')
    ordinary = [row for row in original_commands if type(row) is dict and row.get('Label') == 'link ordinary']
    links = native.get('Links')
    need(len(ordinary) == 1 and type(links) is list and links and type(links[0]) is dict, 'one native ordinary recipe')
    original = _argv(ordinary[0].get('Argv'))
    same(original[0], str(gcc), 'native final compiler')
    same([arg for arg in original if arg.endswith('.o')], list(map(str, originals)), 'native final object order')
    need(original.count('-v') == 1 and not any(arg in RAW + COUNTERS or '--emit-relocs' in arg for arg in original),
         'ordinary native final recipe without injected policy')
    same(final.get('OriginalFinalStageArgv'), original, 'original final recipe')
    replacements = {str(old): str(new) for old, new in zip(originals, objects)}
    replacements[links[0]['Path']] = str(output)
    expected = [('-Wl,-Map=' + str(link_map)) if arg.startswith('-Wl,-Map=')
                else replacements.get(arg, arg) for arg in original]
    need(expected.count(str(objects[0])) == 1, 'first final object placement')
    start = expected.index(str(objects[0]))
    expected[start:start] = ['-Wl,--emit-relocs', *RAW, *COUNTERS]
    same(final.get('Argv'), expected, 'reconstructed final argv')
    need(type(commands[131]) is dict, 'final journal row')
    same(commands[131].get('Argv'), expected, 'journaled final argv')
    plans.append(plan('PortPolicy', 'final-supported', final, output, objects, None, True, 131, [], final=True))
    need(len(plans) == 10, 'ten ordered replay plans')
    return plans
