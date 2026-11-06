"""Build-only Os common isolation in the already admitted integrated session.

The neutral component flag/dependency and source-ownership predicates are caller
supplied and authenticated. No O2 constructor, driver, reader or verdict is used.
Actual image reproduction, map/provider origins and slot protocols are deferred
to the enclosing single immutable reader; this module cannot grant cell credit.
"""

import copy
import hashlib
import json
from pathlib import Path


COMMON = ('context/context_core.c', 'context/context_runtime_state.c', 'context/context_panic.c')
MODE = 'Os-lto'
SCOPE = 'NATIVE_CM3_OS_LTO_ISOLATION_BUILD_ONLY_PENDING_READER'
HELPER_PINS = {
    'probes': ('tools/fixtures/cm0_final_cell/components.py',
        '16490A20B1A75C5DBD2D21A5FED988C5BD82F4DE919350985B33491CE473A5F7'),
    'ownership': ('tools/fixtures/cm0_final_cell/ownership.py',
        'F9971A707BC30FFA7AF0B816570ED476B2965F24369BC7A747C18784E5B0A552'),
    'recipes': ('tools/fixtures/cm3_os_lto_final_cell/batch_recipes.py',
        'C15D57AA9FE3963FF84F22D831F4E1F5F941AC351571AB347ECBC29E9172004B'),
}


class Rejected(ValueError):
    pass


def need(value, message):
    if not value:
        raise Rejected('cm3-os-lto-isolation-build: ' + message)


def sha(raw):
    need(type(raw) is bytes, 'immutable byte buffer')
    return hashlib.sha256(raw).hexdigest().upper()


def common_flags(components, original, root):
    """Remove only include authority; preserve actual Os, target and slim flags."""
    need(type(original) is list and all(type(flag) is str for flag in original), 'literal actual flags')
    need([flag for flag in original if flag.startswith('-O')] == ['-Os']
         and original.count('-flto') == original.count('-fno-fat-lto-objects') == 1
         and '-fno-lto' not in original and '-ffat-lto-objects' not in original,
         'actual sole Os optimization and genuine slim-LTO options')
    flags = components.isolated_flags(original, root)
    need(type(flags) is list and flags.count('-Os') == flags.count('-flto')
         == flags.count('-fno-fat-lto-objects') == 1 and '-include' not in flags,
         'neutral transform preserves Os and slim LTO')
    return flags


def command_plan():
    return tuple(label for name in COMMON for label in (
        'discover isolated ' + Path(name).stem, 'compile isolated ' + Path(name).stem,
        'inspect slim ' + Path(name).stem)) + (
        'link isolated-common', 'link isolated-common-emit', 'disassemble isolated-common-emit')


def compile_common(suite, index, modules):
    """Two same-attempt dependency sets and actual slim inspection, no IR equality."""
    need(type(index) is int and 0 <= index < 3, 'one of three ordered common providers')
    row, root = suite.source(index), suite.base / 'source'
    source = suite.api.checked_path(row['Source'])
    need(source == root / COMMON[index] and row['SlimIR'] is True,
         'exact admitted common provider')
    need(row['CompileFlags'] == modules['recipes'].compile_flags(suite.result, index),
         'unchanged actual Os capture flags')
    suite.watch.read(source, row['SourceSha256'])
    flags = common_flags(modules['probes'], row['CompileFlags'], root)
    directory = suite.output / 'isolated-common'
    directory.mkdir(exist_ok=True)
    obj = directory / (source.stem + '.o')
    discovery, actual = obj.with_suffix('.discovery.d'), obj.with_suffix('.compile.d')
    first, gcc, target = len(suite.commands), str(suite.tools['gcc']), 'pilot-source-' + str(index)
    rows = row.get('ActualCompileDependencies')
    need(type(rows) is list and rows and all(type(item) is dict and set(item) == {'Path', 'Sha256'} for item in rows),
         'nonempty actual capture dependency declarations')
    admitted = {suite.api.checked_path(item['Path']): item['Sha256'] for item in rows}
    need(len(admitted) == len(rows) and admitted.get(source) == row['SourceSha256'],
         'unique actual same-source dependency hash authority')

    def dependencies(path):
        paths = [suite.api.checked_path(item) for item in suite.native.read_dependencies(path)]
        records = modules['probes'].isolated_dependencies(paths, admitted,
            root=root, cmsis=suite.base / 'cmsis')
        need(source in paths, 'isolated dependencies include the exact common provider')
        for item in records:
            suite.watch.read(item['Path'], item['Sha256'])
        return records

    result = suite.command([gcc, *flags, '-M', '-MF', str(discovery), '-MT', target, str(source)],
                           'discover isolated ' + source.stem)
    need(result.stdout == b'' and result.stderr == b'', 'clean isolated dependency discovery')
    suite.record_output(discovery)
    before = dependencies(discovery)
    result = suite.command([gcc, *flags, '-MD', '-MF', str(actual), '-MT', target,
                           '-c', str(source), '-o', str(obj)], 'compile isolated ' + source.stem)
    need(result.stdout == b'' and result.stderr == b'', 'clean isolated common compile')
    suite.record_output(actual)
    object_record = suite.record_output(obj)
    after = dependencies(actual)
    suite.native.require_compile_dependencies(before, after)
    slim = suite.inspect_ir(obj)
    need(type(slim) is dict and slim.get('SlimIR') is True and slim.get('Object') == str(obj)
         and slim.get('Sha256') == object_record['Sha256'], 'same actual generated slim object inspection')
    return dict(Source=str(source), SourceSha256=row['SourceSha256'], TemplateIndex=index,
        OriginalObject=row['Object'], OriginalObjectSha256=row['ObjectSha256'],
        Object=str(obj), ObjectSha256=object_record['Sha256'], SlimIR=slim,
        OriginalCompileFlags=copy.deepcopy(row['CompileFlags']), CompileFlags=flags, DiscoveryFlags=list(flags),
        IncludeDelta=dict(RemovedForcedHeader=str(root / 'tools/fixtures/classic_final_image/main.h'),
            ReplacementSearchPaths=[str(root / name) for name in ('context', 'fiber')] + [str(root)],
            OtherSemanticFlagsUnchanged=True),
        DiscoveryDependencies=before, Dependencies=after, CompileDependenciesVerified=True,
        DiscoveryDependencyFile=str(discovery), CompileDependencyFile=str(actual),
        CommandIndices=list(range(first, len(suite.commands))), ForcedMainHeaderRemoved=True,
        CmsisAndSelectedPortIncludesRemoved=True, RawIRIdentityClaim=False,
        IRImportClosureValidated=False, SourceToMachineSemanticProof=False)


def _emit(suite, objects):
    """Same admitted ordinary recipe with one explicit emitted-REL addition."""
    directory = suite.output / 'links/isolated-common-emit'
    need(not directory.exists(), 'fresh emitted link namespace')
    directory.mkdir(parents=True)
    elf, link_map = directory / 'image.elf', directory / 'image.map'
    originals = [str(path) for path in suite.objects]
    argv, inserted = [], False
    for value in suite.link_argv:
        if value in originals:
            if not inserted:
                argv.extend(str(path) for path in objects)
                inserted = True
        elif value.startswith('-Wl,-Map='):
            argv.append('-Wl,-Map=' + str(link_map))
        elif value == suite.result['Links'][0]['Path']:
            argv.append(str(elf))
        else:
            argv.append(value)
    need(inserted and [flag for flag in argv if flag.endswith('.o')] == [str(path) for path in objects]
         and not any('--emit-relocs' in flag for flag in argv), 'exact substituted Os link object order')
    argv.append('-Wl,--emit-relocs')
    result = suite.command(argv, 'link isolated-common-emit')
    need(result.stdout == b'' and result.stderr == b'', 'clean emitted isolated-common link')
    fixed = {'image.elf', 'image.map', 'image.elf.ltrans.out', 'image.elf.ltrans0.ltrans.args.0',
        'image.elf.ltrans0.ltrans.o', 'image.elf.ltrans0.ltrans.s', 'image.elf.ltrans0.ltrans_args',
        'image.elf.ltrans0.o', 'image.elf.ltrans_args', 'image.elf.res', 'image.elf.wpa.args.0'}
    wrapper_name = ''.join(elf.parts[1:]) + '.lto_wrapper_args'
    actual = suite.api.files_under(directory)
    need(fixed <= set(actual) <= fixed | {wrapper_name}, 'complete bounded emitted-link saved files')
    wrappers = [path for path in (directory / wrapper_name, suite.output / wrapper_name) if path.exists()]
    need(len(wrappers) == 1, 'one actual owned LTO wrapper-argument file')
    for path in actual.values():
        suite.record_output(path)
    if wrappers[0].parent != directory:
        suite.record_output(wrappers[0])
    suite.verify_objects()
    return elf, link_map


def _deferred(suite, ordinary, ordinary_map, emitted, emitted_map, disassembly, common):
    original, original_emit = suite.result['Links']
    roles = (
        ('OriginalOrdinaryELF', original['Path']), ('OriginalEmitELF', original_emit['Path']),
        ('OriginalMachine', original_emit['Machine']),
        ('OriginalAssembly', str(original_emit['Path']) + '.ltrans0.ltrans.s'),
        ('OriginalDisassembly', str(original_emit['Path']) + '.dis'), ('OriginalMap', original_emit['Map']),
        ('IsolatedOrdinaryELF', ordinary), ('IsolatedOrdinaryMap', ordinary_map),
        ('IsolatedEmitELF', emitted), ('IsolatedMachine', str(emitted) + '.ltrans0.ltrans.o'),
        ('IsolatedAssembly', str(emitted) + '.ltrans0.ltrans.s'), ('IsolatedMap', emitted_map),
        ('IsolatedDisassembly', disassembly), ('StartupObject', suite.objects[8]),
        ('PortSource', suite.source(3)['Source']),
        *((('IsolatedIR' + str(index)), row['Object']) for index, row in enumerate(common)),
    )
    inputs = []
    for role, path in roles:
        path = suite.api.checked_path(path)
        inputs.append(dict(Role=role, Path=str(path), Sha256=sha(suite.watch.read(path))))
    return dict(Status='PENDING', Scope='OS_ISOLATED_LOAD_IMAGES_SLOT_AND_PROVIDER_REPLAY_REQUIRED',
        ValidationDeferred=True, Inputs=inputs,
        LoadImageComparisons=[dict(Name=name, Left=left, Right=right) for name, left, right in (
            ('OriginalToIsolated', 'OriginalOrdinaryELF', 'IsolatedOrdinaryELF'),
            ('IsolatedTwins', 'IsolatedOrdinaryELF', 'IsolatedEmitELF'),
            ('OriginalTwins', 'OriginalOrdinaryELF', 'OriginalEmitELF'))],
        SlotProofs=[dict(Kind=kind, Machine=prefix + 'Machine', Final=prefix + 'EmitELF',
            Assembly=prefix + 'Assembly', Disassembly=prefix + 'Disassembly', Map=prefix + 'Map',
            PortSource='PortSource', Startup='StartupObject') for kind, prefix in
            (('Original', 'Original'), ('Isolated', 'Isolated'))],
        GeneratedCommonProviderValidationRequired=True, IRImportClosureValidated=False,
        RawIRIdentityClaim=False, WholeSlotAccessIsolation=False, PositiveLinkRevalidated=False,
        RequiredCellsSatisfied=0)


def _guards(suite, modules):
    need(type(modules) is dict and all(name in modules for name in HELPER_PINS), 'explicit authenticated helpers')
    need(not getattr(suite, '_os_isolation_started', False), 'isolation phase cannot retry')
    need(suite._started and not suite._finished and len(suite.commands) == 41,
         'active session after exact 41 ABI commands')
    expected_phase = [dict(Name='ABIControls', First=0, Stop=41, Commands=41)]
    need(suite.phases == expected_phase and all(type(row[key]) is int for row in suite.phases
         for key in ('First', 'Stop', 'Commands')), 'completed first ABI phase range')
    for report in (suite.result, suite.report):
        need(type(report) is dict and report.get('Profile') == 'CM3' and report.get('Mode') == MODE
             and report.get('Linkage') == 'direct' and report.get('LTO') is True, 'explicit actual Os session')
    need(suite.report.get('Status') == 'FAIL' and type(suite.report.get('RequiredCellsSatisfied')) is int
         and suite.report['RequiredCellsSatisfied'] == 0 and suite.report.get('ABIControlsBuilt') is True,
         'unpromoted batch with built ABI phase')
    modules['recipes'].require_capture_sources(suite.result)
    need(suite.link_argv == modules['recipes'].link_recipe(suite.result, suite.objects),
         'same admitted Os ordinary link recipe')
    plan = modules['recipes'].batch_plan()
    component = plan['Components'][1]
    need(component['Name'] == 'Isolation' and component['Start'] == 41 and component['Stop'] == 53
         and component['Count'] == 12 and tuple(component['Labels']) == command_plan(), 'exact Isolation recipe range')


def build(suite, modules):
    """Build [41,53), leaving the batch FAIL/zero with explicit pending proofs.

    No start/finish/run/reader is called. The caller must authenticate HELPER_PINS
    before helper execution, and independently revoke/seal on propagated errors.
    """
    _guards(suite, modules)
    suite._os_isolation_started = True
    suite.begin_phase('Isolation')
    suite.report.update(IsolationBuilt=False, CpuFreeCommonValidated=False,
        WholeSlotAccessIsolation=False, PositiveLinkRevalidated=False, IsolatedCommon=[])
    try:
        ownership = modules['ownership']
        sources = {}
        for name in ownership.REQUIRED_SOURCES:
            key = 'source/' + name
            need(key in suite.bundle['Artifacts'], 'admitted canonical ownership source')
            sources[name] = suite.watch.read(suite.base / key, suite.bundle['Artifacts'][key])
        suite.report['SourceOwnership'] = ownership.validate_common_sources(sources)
        suite.report['SourceOwnershipValidated'] = True
        suite.report['SourceOwnershipInputs'] = [dict(Source=name, Path=str(suite.base / 'source' / name),
            Sha256=sha(raw)) for name, raw in sources.items()]
        for index in range(3):
            suite.report['IsolatedCommon'].append(compile_common(suite, index, modules))
        common = suite.report['IsolatedCommon']
        objects = [Path(row['Object']) for row in common] + list(suite.objects[3:])
        need(len(objects) == 9 and len(set(objects)) == 9, 'three replacement and six unchanged distinct objects')
        result, ordinary, ordinary_map = suite._link('isolated-common', objects)
        need(result.stdout == b'' and result.stderr == b'', 'clean ordinary isolated-common link')
        emitted, emitted_map = _emit(suite, objects)
        disassembly = Path(str(emitted) + '.dis')
        result = suite.command([str(suite.tools['objdump']), '-drwC', '-z', str(emitted)],
                               'disassemble isolated-common-emit')
        need(result.stderr == b'' and result.stdout, 'nonempty clean complete zero-inclusive disassembly')
        suite.write_input(disassembly.relative_to(suite.output).as_posix(), result.stdout)
        suite.report['IsolationDeferredReader'] = _deferred(
            suite, ordinary, ordinary_map, emitted, emitted_map, disassembly, common)
        suite.report['IsolatedLinkedObjects'] = [dict(Index=index, Path=str(path),
            Sha256=sha(suite.watch.read(path)), OriginalUnchanged=index >= 3)
            for index, path in enumerate(objects)]
        suite.report['IsolatedLinkMap'] = str(ordinary_map)
        suite.report['EmitLinkDelta'] = ['-Wl,--emit-relocs']
        rows = suite.commands[41:]
        need(len(rows) == 12 and tuple(row.get('Label') for row in rows) == command_plan()
             and all(row.get('State') == 'TERMINAL' and row.get('Status') == 'PASS'
                 and type(row.get('Exit')) is int and row['Exit'] == 0
                 and type(row.get('ExpectedExit')) is int and row['ExpectedExit'] == 0
                 and row.get('TimedOut') is False and not row.get('JournalErrors') for row in rows),
             'twelve exact typed successful terminal Isolation commands')
        suite.verify_objects()
        suite.watch.close()
        record = dict(Status='BUILT-PENDING-READER', Scope=SCOPE, Profile='CM3', Mode=MODE,
            Linkage='direct', LTO=True, First=41, Stop=53, Commands=12, IsolatedCommonObjects=3,
            OriginalObjectsUnchanged=6, DeferredReaderRequired=True, CpuFreeCommonValidated=False,
            WholeSlotAccessIsolation=False, PositiveLinkRevalidated=False, RawIRIdentityClaim=False,
            Qualification=False, CellContractSatisfied=False, RequiredCellSatisfied=False,
            RequiredCellsSatisfied=0, FullABIProof=False, FullSemanticABIProof=False,
            SourceToMachineSemanticProof=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False)
        suite.report.update(IsolationBuild=record, IsolationBuilt=True)
        suite.write_input('isolation-build.json', (json.dumps(dict(Build=record,
            IsolatedCommon=common, SourceOwnership=suite.report['SourceOwnership'],
            DeferredReader=suite.report['IsolationDeferredReader'], Objects=suite.report['IsolatedLinkedObjects']),
            sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii'))
        suite.end_phase()
        suite._save('results.json', suite.report)
        return copy.deepcopy(record)
    except BaseException as error:
        suite.report.update(Status='FAIL', IsolationBuilt=False, CpuFreeCommonValidated=False,
            WholeSlotAccessIsolation=False, PositiveLinkRevalidated=False, SourceOwnershipValidated=False,
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
        except BaseException as closing:
            suite.report.setdefault('ClosingErrors', []).append(type(closing).__name__ + ': ' + str(closing))
        raise
