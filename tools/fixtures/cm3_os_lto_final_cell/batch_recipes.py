"""Pure CM3 Os-LTO batch recipes, never capture admission or execution proof.

The caller authenticates the current capture, seed, tools, dependencies and
physical closure. This model checks supplied metadata/argv consistency only.
Returned flags remain the actual recorded strings; no O2 surrogate is made.
"""

import math
import ntpath
from pathlib import PurePath
import re


ROUTE = 'CM3/Os-lto/direct'
COHORT = 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default'
INVENTORY = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
SOURCES = ('context/context_core.c', 'context/context_runtime_state.c', 'context/context_panic.c',
    'fiber/port/ARM_CM3/fiber_port.c', 'fiber/port/ARM_CM3/fiber_port_boot.c',
    'fiber/port/ARM_CM3/fiber_port_exception.c', 'fiber/port/fiber_port_context_cohort_expectation.c',
    'tools/fixtures/classic_final_image/application.c', 'tools/fixtures/classic_final_image/startup.S')
CONTROLS = ('stale-nvic-expectation', 'stale-storage-application', 'stale-reverse-anchor',
            'duplicate-svc', 'duplicate-pendsv')
COMPONENT_COUNTS = (('ABIControls', 41), ('Isolation', 12), ('CommonAttributes', 45), ('PortPolicy', 36))
TARGET = ('-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft')


class Rejected(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected('REJECT:CM3-OS-LTO-BATCH-RECIPES:' + message)


def _path(value):
    need(type(value) is str and value and not any(c in value for c in '\x00\r\n'), 'literal path')
    need(re.match(r'^[A-Za-z]:[\\/]', value) is not None, 'absolute drive-qualified path')
    parts = value[3:].replace('\\', '/').split('/')
    need(parts and all(part and part not in ('.', '..') and ':' not in part
                       and part == part.rstrip(' .') for part in parts), 'unambiguous lexical path')
    return value.replace('\\', '/').casefold()


def _join(root, relative):
    return ntpath.join(root, *relative.split('/'))


def _hash(value):
    need(type(value) is str and re.fullmatch(r'[A-F0-9]{64}', value) is not None, 'uppercase SHA256 declaration')


def _argv(value):
    need(type(value) is list and value and all(type(x) is str and x and not any(c in x for c in '\x00\r\n')
         for x in value), 'literal nonempty argv/flags')
    result = []
    for item in value:
        if re.match(r'^[A-Za-z]:[\\/]', item):
            result.append(_path(item))
        elif item.startswith('-I'):
            result.append('-I' + _path(item[2:]))
        elif item.startswith('-Wl,-Map='):
            result.append('-Wl,-Map=' + _path(item[len('-Wl,-Map='):]))
        else:
            result.append(item)
    return result


def _seed_flags(seed, relative, index):
    if index == 8:
        return [*TARGET, '-O2', '-g0', '-DPILOT_HAS_VTOR=1']
    root = _join(seed, 'source')
    includes = ('tools/fixtures/classic_final_image', 'fiber/port/ARM_CM3',
                'fiber/port', 'fiber', 'context', '')
    return [*TARGET, '-O2', '-std=gnu11', '-g0', '-ffreestanding', '-ffunction-sections',
        '-fdata-sections', '-Wall', '-Wextra', '-Werror=implicit-function-declaration',
        '-Werror=attributes', '-Werror=ignored-attributes', '-DFIBER_PORT_ARMV7M=1',
        '-DFIBER_PORT_BUILD_SELECTED=1', '-DFIBER_SCHEDULER_BASEPRI=16',
        *('-I' + (_join(root, name) if name else root) for name in includes),
        '-I' + _join(seed, 'cmsis'), '-include', _join(root, 'tools/fixtures/classic_final_image/main.h'),
        '-I' + _join(root, relative.rsplit('/', 1)[0])]


def _terminal(row):
    need(type(row) is dict and type(row.get('Label')) is str and row['Label'], 'command row/label')
    need(row.get('State') == 'TERMINAL' and row.get('Status') == 'PASS'
         and type(row.get('Exit')) is int and row['Exit'] == 0 and row.get('TimedOut') is False,
         'successful terminal capture command')
    seconds = row.get('Seconds')
    need(type(seconds) in (int, float) and math.isfinite(seconds) and seconds >= 0, 'finite command duration')
    need(not row.get('JournalErrors'), 'capture command journal failure')
    return _argv(row.get('Argv'))


def _capture(report):
    need(type(report) is dict, 'capture object')
    for key, value in (('Status', 'PASS'), ('Scope', 'NATIVE_CM3_OS_LTO_CAPTURE_FEASIBILITY_ONLY'),
            ('Profile', 'CM3'), ('Mode', 'Os-lto'), ('Linkage', 'direct'), ('SeedMode', 'O2'),
            ('Cohort', COHORT), ('SourceInventorySha256', INVENTORY)):
        need(type(report.get(key)) is str and report[key] == value, 'capture/' + key)
    need(report.get('LTO') is True and report.get('Qualification') is False
         and report.get('RequiredCellSatisfied') is False, 'capture literal scope flags')
    need(report.get('Error') is None and report.get('PrimaryError') is None
         and type(report.get('ClosingErrors')) is list and report['ClosingErrors'] == []
         and report.get('InputClosureVerified') is True and report.get('OutputSealVerified') is True,
         'completed capture disposition declarations')
    for key, value in (('TranslationUnits', 9), ('SlimIRObjects', 8), ('RequiredCellsSatisfied', 0)):
        need(type(report.get(key)) is int and report[key] == value, 'capture literal count/' + key)
    seed, gcc = report.get('SeedBuild'), report.get('CapturedCompiler')
    _path(seed)
    _path(gcc)
    root = ntpath.dirname(ntpath.dirname(ntpath.dirname(gcc)))
    need(_path(gcc) == _path(_join(root, 'toolchain/bin/arm-none-eabi-gcc.exe')), 'captured compiler location')
    source_root = _join(seed, 'source')
    need(not _path(root).startswith(_path(seed) + '/') and not _path(seed).startswith(_path(root) + '/')
         and _path(root) != _path(seed), 'distinct capture/seed roots')
    rows = report.get('Sources')
    need(type(rows) is list and len(rows) == 9, 'nine ordered source records')
    roles = set()
    for index, (relative, row) in enumerate(zip(SOURCES, rows)):
        need(type(row) is dict, 'source row')
        source = _join(source_root, relative)
        stem = relative.rsplit('/', 1)[-1].rsplit('.', 1)[0]
        obj = _join(root, 'objects/%02d-%s.o' % (index, stem))
        for field, expected in (('Source', source), ('Object', obj), ('DependencyFile', obj[:-2] + '.d')):
            key = _path(row.get(field))
            need(key == _path(expected) and key not in roles, 'ordered unique source/object/dependency role: ' + field)
            roles.add(key)
        _hash(row.get('SourceSha256'))
        _hash(row.get('ObjectSha256'))
        need(row.get('SlimIR') is (index != 8) and row.get('CompileDependenciesVerified') is True,
             'eight slim C objects, native startup and verified dependency declaration')
        seed_flags, actual = row.get('SeedCompileFlags'), row.get('CompileFlags')
        need(_argv(seed_flags) == _argv(_seed_flags(seed, relative, index)), 'exact ordinary seed flags/order')
        expected = ['-Os' if flag == '-O2' else flag for flag in seed_flags]
        if index != 8:
            expected += ['-flto', '-fno-fat-lto-objects']
        _argv(actual)
        need(actual == expected, 'sole seed optimization transform and C-only genuine slim flags')
        dependencies = row.get('ActualCompileDependencies')
        need(type(dependencies) is list and dependencies, 'nonempty actual dependency declarations')
        found = {}
        for item in dependencies:
            need(type(item) is dict and set(item) == {'Path', 'Sha256'}, 'dependency declaration shape')
            key = _path(item['Path'])
            _hash(item['Sha256'])
            need(key not in found, 'unique dependency physical-role declaration')
            found[key] = item['Sha256']
        need(found.get(_path(source)) == row['SourceSha256'], 'own source hash in actual dependencies')
    commands = report.get('Commands')
    need(type(commands) is list and commands and all(type(row) is dict and type(row.get('Label')) is str
         for row in commands), 'capture command declarations')
    for index, row in enumerate(rows):
        label = 'compile ' + SOURCES[index].rsplit('/', 1)[-1]
        matches = [command for command in commands if command['Label'] == label]
        need(len(matches) == 1, 'one actual source compile record: ' + label)
        expected = [gcc, *row['CompileFlags'], '-MD', '-MF', row['DependencyFile'], '-MT',
                    'pilot-source-' + str(index), '-c', row['Source'], '-o', row['Object']]
        need(_terminal(matches[0]) == _argv(expected), 'exact recorded source compile argv')
    compiler_compiles = [row for row in commands if type(row.get('Argv')) is list and row['Argv']
                        and type(row['Argv'][0]) is str and row['Argv'][0].replace('\\', '/').casefold() == _path(gcc)
                        and '-c' in row['Argv']]
    need(len(compiler_compiles) == 9, 'exact captured-compiler source count, not foreign -c commands')
    links = report.get('Links')
    need(type(links) is list and len(links) == 2 and all(type(row) is dict for row in links)
         and [row.get('Kind') for row in links] == ['ordinary', 'emit-relocs'], 'ordered genuine direct twins')
    objects = [row['Object'] for row in rows]
    for kind, row in zip(('ordinary', 'emit-relocs'), links):
        for field, relative in (('Path', kind + '/image.elf'), ('Map', kind + '/image.map'),
                                ('Machine', kind + '/image.elf.ltrans0.ltrans.o')):
            need(_path(row.get(field)) == _path(_join(root, relative)), 'own twin output role/' + field)
        _hash(row.get('Sha256'))
        expected = [gcc, *TARGET, '-Os', '-flto', '-flto-partition=one', '-save-temps=obj', '-v',
                    '-nostdlib', '-Wl,-plugin-opt=-save-temps',
                    '-Wl,--gc-sections,--no-undefined,--fatal-warnings,--build-id=none,-z,noexecstack',
                    '-T', _join(source_root, 'tools/fixtures/classic_final_image/link.ld'), *objects]
        if kind == 'emit-relocs':
            expected.append('-Wl,--emit-relocs')
        expected += ['-Wl,-Map=' + row['Map'], '-o', row['Path']]
        matches = [command for command in commands if command['Label'] == 'link ' + kind]
        need(len(matches) == 1 and _terminal(matches[0]) == _argv(expected), 'exact own-twin link argv/' + kind)
    return rows, commands


def require_capture_sources(report):
    """Check metadata/argv for the whole capture; caller owns byte authority."""
    _capture(report)


def compile_flags(report, index):
    need(type(index) is int and 0 <= index < 9, 'literal source index 0..8')
    rows, _ = _capture(report)
    return list(rows[index]['CompileFlags'])


def link_recipe(report, objects):
    rows, commands = _capture(report)
    need(type(objects) in (list, tuple) and len(objects) == 9
         and all(type(path) is str or isinstance(path, PurePath) for path in objects), 'nine explicit object paths')
    supplied = [str(path) for path in objects]
    need(supplied == [row['Object'] for row in rows], 'exact actual captured object strings/order')
    original = next(row['Argv'] for row in commands if row['Label'] == 'link ordinary')
    need(original.count('-v') == 1, 'one verbose flag removed for closed negative diagnostics')
    return [flag for flag in original if flag != '-v']


def _plans():
    abi = ['link positive', 'definitions original-runtime', 'imports unchanged-boot-v1']
    stems = ('06-fiber_port_context_cohort_expectation', '07-application', '01-context_runtime_state',
             '03-duplicate_svc', '03-duplicate_pendsv')
    for index, (name, stem) in enumerate(zip(CONTROLS, stems)):
        abi.extend(('discover ' + name, 'compile ' + name, 'inspect slim ' + stem,
                    ('imports ' if index < 2 else 'definitions ') + name))
        if index == 2:
            abi.append('imports ' + name)
        abi.append('link ' + name)
    for name in ('types', 'attributes', 'slot-read', 'slot-write', 'slot-address'):
        abi.extend(('discover probe ' + name, 'compile probe ' + name))
        if name in ('types', 'attributes'):
            abi.append('inspect slim ' + name)
    common = ('context_core', 'context_runtime_state', 'context_panic')
    isolation = [label for name in common for label in ('discover isolated ' + name,
                 'compile isolated ' + name, 'inspect slim ' + name)]
    isolation.extend(('link isolated-common', 'link isolated-common-emit', 'disassemble isolated-common-emit'))
    attributes = ['dump compiler specs']
    for group, names in (('positive', common), ('mutant-engine', common[:1]),
            ('mutant-state', common[1:2]), ('mutant-panic', common[2:]),
            ('stress-protected', ('stress',)), ('stress-unprotected', ('stress',))):
        for name in names:
            attributes.extend(('discover ' + group + ' ' + name, 'compile ' + group + ' ' + name,
                               'inspect slim ' + name, 'imports ' + group + ' ' + name))
        attributes.extend(('lower ' + group, 'disassemble ' + group))
    policy = ['dump compiler specs']
    for group, names in (('selected', ('fiber_port', 'fiber_port_boot', 'fiber_port_exception')),
                         ('stress-supported', ('stress',)), ('stress-raw', ('stress',))):
        for name in names:
            policy.extend(('discover ' + group + ' ' + name, 'compile ' + group + ' ' + name,
                           'inspect slim ' + name, 'imports ' + group + ' ' + name))
            if group == 'selected':
                policy.append('definitions ' + group + ' ' + name)
        policy.extend(('lower ' + group, 'disassemble ' + group, 'disassemble worker ' + group))
    policy.extend(('link final-supported', 'disassemble final-supported', 'disassemble worker final-supported'))
    return dict(ABIControls=tuple(abi), Isolation=tuple(isolation), CommonAttributes=tuple(attributes), PortPolicy=tuple(policy))


def batch_plan(*, plan_helpers=None):
    """Fresh planned ranges; optional authenticated frozen helpers cross-check labels.

    plan_helpers has exactly Isolation/CommonAttributes/PortPolicy modules (or
    objects) exposing pure command_plan(). The ABI executor has no plan export;
    its fixed 41-label sequence is transcribed here, not inferred from a PASS.
    """
    plans = _plans()
    if plan_helpers is not None:
        need(type(plan_helpers) is dict and set(plan_helpers) == {'Isolation', 'CommonAttributes', 'PortPolicy'},
             'exact three optional frozen plan helpers')
        for name, helper in plan_helpers.items():
            method = getattr(helper, 'command_plan', None)
            need(callable(method), 'pure command_plan helper/' + name)
            value = method()
            need(type(value) is tuple and value == plans[name], 'unchanged complete frozen plan/' + name)
    components, commands, start = [], [], 0
    failures = {'link ' + name for name in CONTROLS} | {'compile probe slot-' + name for name in ('read', 'write', 'address')}
    for name, count in COMPONENT_COUNTS:
        labels = plans[name]
        need(len(labels) == count, 'fixed planned command count/' + name)
        components.append(dict(Name=name, Start=start, Stop=start + count, Count=count, Labels=list(labels)))
        commands.extend(dict(Index=start + index, Component=name, LocalIndex=index, Label=label,
                             ExpectedExit=1 if name == 'ABIControls' and label in failures else 0)
                        for index, label in enumerate(labels))
        start += count
    need(start == 134, '134 planned commands')
    return dict(SchemaVersion=1, Route=ROUTE, Profile='CM3', Mode='Os-lto', Linkage='direct',
        Components=components, Commands=commands, TotalCommands=134, PlannedExpectedNonzeroCommands=8,
        PlanOnly=True, CaptureAdmissionPerformed=False, ExecutionPerformed=False,
        Qualification=False, CellContractSatisfied=False, RequiredCellSatisfied=False,
        RequiredCellsSatisfied=0, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False)


def component_ranges(*, plan_helpers=None):
    return [{key: row[key] for key in ('Name', 'Start', 'Stop', 'Count')}
            for row in batch_plan(plan_helpers=plan_helpers)['Components']]
