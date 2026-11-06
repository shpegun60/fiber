"""Retained CM0/O2 component orchestration; no cell or semantic ABI credit.

All commands and artifact/input sealing belong to the pinned controls.Suite.
Importing this module does not load helpers or execute tools.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PINS = dict(controls='9FA3297C5C1D3861F8B422977E876D40B0F6D7275AA4431B0AC579AECB777C9A',
            abi='F5AA5CE6BD21130249D571D0AA03BD72C735DA04832C2B6DBF13EFD548CB4F4B',
            ownership='F9971A707BC30FFA7AF0B816570ED476B2965F24369BC7A747C18784E5B0A552',
            slot='3A6B3D91A51255789CEB3703BEC98550A8FC73C897225C646263828B70104A01')
PROBES = ('types.c', 'attributes.c', 'slot_read.c', 'slot_write.c', 'slot_address.c')
REQUIRED_FLAGS = ('-std=gnu11', '-Werror=incompatible-pointer-types', '-Werror=attributes')
SLOT = 'fiber_internal_runtime_current_context_slot'
COMPONENT_SCOPE = 'CM0_O2_DECLARATION_SLOT_OWNERSHIP_COMPONENTS_ONLY'
SLOT_PROBES = {
    'slot_read.c': ('void', '(void)' + SLOT + ';'),
    'slot_write.c': ('struct FiberContext *value', SLOT + ' = value;'),
    'slot_address.c': ('void', '(void)&' + SLOT + ';'),
}


class Rejected(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected('cm0-components: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def load_helpers():
    """Authenticate every helper buffer before executing any of them."""
    need(not sys.flags.optimize, 'unoptimized Python required')
    buffers = {name: (HERE / (name + '.py')).read_bytes() for name in PINS}
    for name, raw in buffers.items():
        need(sha(raw) == PINS[name], 'fixed helper: ' + name)
    modules = {}
    for name, raw in buffers.items():
        path = HERE / (name + '.py')
        spec = importlib.util.spec_from_file_location('_cm0_components_' + name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        exec(compile(raw, str(path), 'exec'), module.__dict__)
        modules[name] = module
    return modules, buffers


def probe_flags(base, required, accepted):
    need(type(base) is list and all(type(flag) is str for flag in base), 'base flags')
    need(type(required) is list and required == list(REQUIRED_FLAGS), 'fixed probe flags')
    need(type(accepted) is bool and '-save-temps=obj' not in base, 'literal probe disposition')
    discovery = base + [flag for flag in required if flag not in base]
    return discovery, discovery + (['-save-temps=obj'] if accepted else [])


def classify_undeclared(result, identifier, *, object_exists, source_path, source_bytes):
    need(identifier == SLOT and type(object_exists) is bool, 'fixed absent slot')
    need(type(result.returncode) is int and result.returncode == 1 and result.timed_out is False
         and type(result.stdout) is bytes and result.stdout == b'' and type(result.stderr) is bytes
         and not object_exists, 'negative compile result')
    source = Path(source_path)
    need(source.is_absolute() and source.name in SLOT_PROBES and type(source_bytes) is bytes, 'fixed probe source')
    parameters, statement = SLOT_PROBES[source.name]
    function = 'cm0_abi_' + source.stem
    lines = ['#include "context/context_port_abi.h"', '#include "context/context_runtime_port_abi.h"',
             'void ' + function + '(' + parameters + ')', '{', '    ' + statement, '}']
    need(source_bytes == ('\n'.join(lines) + '\n').encode('ascii'), 'exact undeclared probe source context')
    column = lines[4].index(SLOT) + 1
    location = str(source) + ':5:' + str(column)
    suggestion = 'fiber_internal_runtime_require_current_context'
    marker = '      | ' + ' ' * (column - 1)
    expected = [str(source) + ": In function '" + function + "':",
        location + ": error: '" + SLOT + "' undeclared (first use in this function); did you mean '" + suggestion + "'?",
        '    5 | ' + lines[4], marker + '^' + '~' * (len(SLOT) - 1), marker + suggestion,
        location + ': note: each undeclared identifier is reported only once for each function it appears in']
    text = result.stderr.decode('utf-8', errors='strict').replace('\r\n', '\n')
    need(text == '\n'.join(expected) + '\n', 'closed GCC14 undeclared diagnostic/source binding')
    return dict(AcceptedCompile=False, UndeclaredIdentifier=identifier,
                DiagnosticSha256=sha(result.stderr), ObjectAbsent=True)


def compile_probe(suite, name, probe):
    need(name in PROBES and type(probe['ExpectedCompile']) is bool, 'fixed probe')
    success = name in PROBES[:2]
    need(probe['ExpectedCompile'] is success and probe['DiagnosticIdentifier'] == (None if success else SLOT),
         'fixed probe disposition')
    raw = probe['Source'].encode('ascii')
    need(sha(raw) == probe['SourceSha256'], 'probe source hash')
    stem = name.removesuffix('.c').replace('_', '-')
    source = suite.write_input('abi/' + name, raw)
    obj = source.parent / (stem + '.o')
    discovery, actual = obj.with_suffix('.discovery.d'), obj.with_suffix('.compile.d')
    discovery_flags, flags = probe_flags(suite.source(0)['CompileFlags'], probe['RequiredCFlags'], success)
    gcc, target, start = str(suite.tools['gcc']), 'pilot-source-0', len(suite.commands)
    suite.command([gcc, *discovery_flags, '-M', '-MF', str(discovery), '-MT', target, str(source)], 'discover probe ' + stem)
    suite.record_output(discovery)
    def dependencies(path):
        rows = []
        for item in suite.native.read_dependencies(path):
            item = suite.api.checked_path(item)
            need(item in suite.watch.hashes, 'admitted probe dependency')
            rows.append(dict(Path=str(item), Sha256=sha(suite.watch.read(item))))
        required = {source, *(suite.base / 'source/context' / name for name in
                             ('context_port_abi.h', 'context_runtime_port_abi.h'))}
        need(required <= {Path(row['Path']) for row in rows}, 'probe source and both same-attempt canonical ABI headers')
        return rows
    before = dependencies(discovery)
    result = suite.command([gcc, *flags, '-MD', '-MF', str(actual), '-MT', target, '-c', str(source), '-o', str(obj)],
                           'compile probe ' + stem, expected_failure=not success)
    suite.record_output(actual)
    after = dependencies(actual)
    suite.native.require_compile_dependencies(before, after)
    if success:
        for path in (obj, obj.with_suffix('.i'), obj.with_suffix('.s')):
            suite.record_output(path)
        need(type(result.returncode) is int and result.returncode == 0 and result.timed_out is False
             and result.stdout == b'' and result.stderr == b'', 'accepted probe without diagnostics')
        classification = dict(AcceptedCompile=True)
    else:
        classification = classify_undeclared(result, probe['DiagnosticIdentifier'], object_exists=obj.exists(),
                                              source_path=source, source_bytes=raw)
    return dict(Source=str(source), SourceSha256=sha(raw), Object=str(obj) if success else None,
        Preprocessed=str(obj.with_suffix('.i')) if success else None, CompileFlags=flags, DiscoveryFlags=discovery_flags,
        Dependencies=after, CompileDependenciesVerified=True, DiscoveryDependencyFile=str(discovery),
        CompileDependencyFile=str(actual), CommandIndices=list(range(start, len(suite.commands))), Classification=classification)


def isolated_flags(original, root):
    need(type(original) is list and all(type(flag) is str for flag in original), 'isolated flags')
    flags, cursor, forced = [], 0, 0
    while cursor < len(original):
        flag = original[cursor]
        if flag == '-include':
            need(cursor + 1 < len(original) and Path(original[cursor + 1]) == root / 'tools/fixtures/classic_final_image/main.h',
                 'exact forced main header')
            forced += 1
            cursor += 2
            continue
        need(not flag.startswith(('-include', '-imacros', '-isystem', '-iquote', '-idirafter')), 'unsupported include spelling')
        if flag == '-I':
            need(cursor + 1 < len(original) and not original[cursor + 1].startswith('-'), 'include path argument')
            cursor += 2
            continue
        if not flag.startswith('-I'):
            flags.append(flag)
        cursor += 1
    need(forced == 1, 'one removed forced main header')
    return flags + ['-I' + str(root / name) for name in ('context', 'fiber')] + ['-I' + str(root)]


def isolated_dependencies(paths, admitted, *, root, cmsis):
    need(paths and len(paths) == len(set(paths)), 'nonempty unique isolated dependencies')
    rows = []
    for path in paths:
        need(path.is_absolute() and path in admitted and not path.is_relative_to(cmsis)
             and not path.is_relative_to(root / 'fiber/port'), 'CPU-independent consumed dependency')
        rows.append(dict(Path=str(path), Sha256=admitted[path]))
    return rows


def isolated_common(suite, index):
    need(type(index) is int and 0 <= index < 3, 'common source index')
    source, root = suite.source(index), suite.base / 'source'
    flags = isolated_flags(source['CompileFlags'], root)
    stem, directory = Path(source['Source']).stem, suite.output / 'isolated-common'
    directory.mkdir(exist_ok=True)
    obj, dep = directory / (stem + '.o'), directory / (stem + '.d')
    first = len(suite.commands)
    result = suite.command([str(suite.tools['gcc']), *flags, '-MD', '-MF', str(dep), '-MT', 'pilot-source-' + str(index),
                            '-c', source['Source'], '-o', str(obj)], 'isolated common ' + stem)
    need(result.stdout == b'' and result.stderr == b'', 'isolated common diagnostic')
    suite.record_output(obj)
    suite.record_output(dep)
    raw = suite.watch.read(obj)
    need(raw == suite.watch.read(source['Object'], source['ObjectSha256']), 'isolated whole-object identity')
    admitted = {Path(row['Path']): row['Sha256'] for row in source['Dependencies']}
    dependencies = isolated_dependencies(suite.native.read_dependencies(dep), admitted, root=root, cmsis=suite.base / 'cmsis')
    for row in dependencies:
        suite.watch.read(row['Path'], row['Sha256'])
    return dict(Source=source['Source'], Object=str(obj), ObjectSha256=sha(raw), WholeObjectByteIdentical=True,
        CompileFlags=flags, Dependencies=dependencies, CommandIndex=first, ForcedMainHeaderRemoved=True,
        CmsisAndSelectedPortIncludesRemoved=True)


def run_components(native_build, *, native_receipt_sha256, native_artifacts_sha256, output_dir):
    modules, buffers = load_helpers()
    controls, abi, ownership, slot = (modules[name] for name in ('controls', 'abi', 'ownership', 'slot'))
    suite = controls.Suite(native_build, native_receipt_sha256=native_receipt_sha256,
                           native_artifacts_sha256=native_artifacts_sha256, output_dir=output_dir)
    suite.watch.read(Path(__file__).resolve())
    for name, raw in buffers.items():
        need(suite.watch.read(HERE / (name + '.py'), PINS[name]) == raw, 'executed helper buffer')
    denied = suite.watch.denied | {path.parent for path in suite.watch.hashes}
    need(all(not suite.output.is_relative_to(path) and not path.is_relative_to(suite.output) for path in denied),
         'output overlaps component inputs')
    root = suite.base / 'source'
    names = sorted(name[len('source/'):] for name in suite.bundle['Artifacts'] if name.startswith('source/'))
    sources = {name: suite.watch.read(root / name) for name in names}
    source_facts = ownership.validate_common_sources({name: sources[name] for name in ownership.REQUIRED_SOURCES})
    provider_facts = abi.inspect_provider_dependencies(sources, suite.watch.read(suite.base / 'results.json'), source_root=str(root))
    suite.report.update(ComponentScope=COMPONENT_SCOPE, ComponentPhasesComplete=False,
                        ComponentHelpers={name: dict(Path=str(HERE / (name + '.py')), Sha256=PINS[name]) for name in PINS})
    error = None
    try:
        suite.start()
        suite.report.update(SourceOwnership=source_facts, DeclaredProviderDependencies=provider_facts)
        suite.run_link_controls()
        replay = suite.compile_tuple(3, name='runtime-slot-replay', save_temps=True)
        controls.same(replay['Dependencies'], suite.source(3)['Dependencies'], 'exact runtime consumed dependencies')
        suite.report['GeneratedSlot'] = slot.check_generated(suite.watch.read(replay['Source'], replay['SourceSha256']),
            suite.watch.read(replay['Assembly']['Path'], replay['Assembly']['Sha256']),
            suite.watch.read(replay['OriginalObject'], replay['OriginalObjectSha256']), suite.watch.read(replay['Object'], replay['ObjectSha256']))
        probes = abi.emit_probes()
        need(tuple(probes) == PROBES, 'five ordered ABI probes')
        suite.report['ABIProbes'] = {}
        for name, probe in probes.items():
            record = compile_probe(suite, name, probe)
            suite.report['ABIProbes'][name] = record
            if name == 'attributes.c':
                check = abi.inspect_preprocessed_attributes(suite.watch.read(record['Preprocessed']))
                for direction, path in check['CanonicalHeaders'].items():
                    expected = root / ('context/context_port_abi.h' if direction == 'forward' else 'context/context_runtime_port_abi.h')
                    need(suite.api.checked_path(path) == expected, 'same accepted attempt canonical header')
                suite.report['PreprocessedAttributes'] = check
        suite.report['IsolatedCommon'] = [isolated_common(suite, index) for index in range(3)]
        suite.write_input('component-facts.json', controls.encoded({key: suite.report[key] for key in
            ('ComponentScope', 'GeneratedSlot', 'SourceOwnership', 'DeclaredProviderDependencies', 'ABIProbes',
             'PreprocessedAttributes', 'IsolatedCommon')}))
        suite.report['ComponentPhasesComplete'] = True
    except BaseException as failure:
        error = failure
    return suite.finish(error)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('native-build', 'native-receipt-sha256', 'native-artifacts-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    try:
        report = run_components(args.native_build, native_receipt_sha256=args.native_receipt_sha256,
                                native_artifacts_sha256=args.native_artifacts_sha256, output_dir=args.output_dir)
    except BaseException as failure:
        print('CM0 component admission failed: ' + type(failure).__name__ + ': ' + str(failure), file=sys.stderr)
        return 1
    print(json.dumps({key: report.get(key) for key in ('Status', 'ComponentScope', 'ComponentPhasesComplete',
        'Error', 'PrimaryError', 'ClosingErrors', 'IntendedLinkRejects', 'OutputSealVerified', 'InputClosureVerified',
        'ClosingFilesVerified', 'RequiredCellsSatisfied')}, sort_keys=True))
    return 0 if (report['Status'] == 'CM0-O2-DIRECT-LINK-CONTROLS-PASS' and report.get('ComponentPhasesComplete') is True
                 and report.get('InputClosureVerified') is True and report.get('OutputSealVerified') is True) else 1


if __name__ == '__main__':
    raise SystemExit(main())
