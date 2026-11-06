"""Fresh components for one of thirty ordinary direct routes; zero cell credit.

CLI admission uses explicit producer and inventory descriptors, never old
receipts to discover tools. Only the selected Suite executes managed host tools.
No helper loads or commands occur on import. All supplied helper modules in the
Python API must have been executed from the caller-authenticated source buffers.
"""
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
REPLAY = 'tools/freeze_replay.py'
REPLAY_SHA = '142BDDE647122DB2D66EF66E4C44A33ECEAA9292FFE304EF3C7CBCC740283275'
SCOPE = 'ORDINARY_SELECTED_NATIVE_DECLARATION_SLOT_OWNERSHIP_COMPONENTS_ONLY'
PROBES = ('types.c', 'attributes.c', 'slot_read.c', 'slot_write.c', 'slot_address.c')
SLOT = 'fiber_internal_runtime_current_context_slot'
LOCAL_PINS = {
    'controls': ('ordinary_final_cell/controls.py', '10F8203B7AA24502BDCA2274DA8C5B7A8763EF7630E8FE8350C64AC50699F18A'),
    'profiles': ('ordinary_final_cell/profiles.py', 'BDD5C9A1F490FF3156CB4DC752F0C411F6FA07852BA5024124E91CC05601CFCD'),
    'abi': ('ordinary_final_cell/abi.py', '43F2E49D638D0E586A24AD2B32D0B8D86C58CC9A63E134EF6AF064437278CAE5'),
    'cm0_controls': ('cm0_final_cell/controls.py', '9FA3297C5C1D3861F8B422977E876D40B0F6D7275AA4431B0AC579AECB777C9A'),
    'cm0_components': ('cm0_final_cell/components.py', '16490A20B1A75C5DBD2D21A5FED988C5BD82F4DE919350985B33491CE473A5F7'),
    'ownership': ('cm0_final_cell/ownership.py', 'F9971A707BC30FFA7AF0B816570ED476B2965F24369BC7A747C18784E5B0A552'),
    'slot': ('cm0_final_cell/slot.py', '3A6B3D91A51255789CEB3703BEC98550A8FC73C897225C646263828B70104A01'),
    'cm0_abi': ('cm0_final_cell/abi.py', 'F5AA5CE6BD21130249D571D0AA03BD72C735DA04832C2B6DBF13EFD548CB4F4B'),
    'facade': ('context_facade/run.py', '7D08E0311C11B611F380262900B6A6DAAF5E65924B95051055069494DB532A13'),
}
SHARED = {
    'native': 'tools/fixtures/classic_final_image/run.py',
    'recipe': 'tools/fixtures/freeze_cohorts/build_recipe.py',
    'process': 'tools/fixtures/freeze_cohorts/process_runner.py',
}


def need(condition, message):
    if not condition:
        raise ValueError('ordinary-cell-components: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def module(name, path, raw):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def load_helpers():
    need(not sys.flags.optimize, 'unoptimized Python required')
    path = ROOT / REPLAY
    raw = path.read_bytes()
    need(sha(raw) == REPLAY_SHA, 'fixed admission utility')
    api = module('_ordinary_components_admission', path, raw)
    watch = api.Closure()
    need(watch.read(path, REPLAY_SHA) == raw, 'executed admission buffer')
    watch.read(Path(__file__).resolve())
    paths = {name: (ROOT / relative, api.SOURCE_PINS[relative]) for name, relative in SHARED.items()}
    paths.update({name: (HERE.parent / relative, digest) for name, (relative, digest) in LOCAL_PINS.items()})
    # Validate the complete helper set before any of its modules executes.
    buffers = {name: watch.read(path, digest) for name, (path, digest) in paths.items()}
    helpers = {'api': api}
    for name, (path, _) in paths.items():
        helpers[name] = module('_ordinary_components_' + name, path, buffers[name])
    return helpers, watch


def scoped(record, scope, profile, mode):
    result = copy.deepcopy(record)
    result.update(UnderlyingScope=copy.deepcopy(record.get('Scope')), Scope=scope, Profile=profile, Mode=mode)
    return result


def slot_source_trivia(source):
    """Normalize only block-comment trivia in the two exact literal gaps."""
    need(type(source) is bytes, 'literal slot source bytes')
    text = source.decode('ascii')
    need(len(re.findall(r'\b' + re.escape(SLOT) + r'\b', text)) == 2, 'two original slot mentions only')
    comment = r'/\*(?:[^*]|\*(?!/))*\*/'
    pair = re.compile(r'"ldr[ \t]+(?P<register>r[01]),[ \t]*=' + re.escape(SLOT)
        + r'[ \t]*\\n"(?P<gap>(?:[ \t\r\n]|' + comment + r')*)'
          r'"ldr[ \t]+(?P=register),[ \t]*\[(?P=register)\][ \t]*\\n"')
    pairs = list(pair.finditer(text))
    need(len(pairs) == 2 and {row['register'] for row in pairs} == {'r0', 'r1'},
         'two exact original address/load literal pairs with block-comment trivia only')
    normalized, transformations = bytearray(source), []
    for row in pairs:
        gap = row['gap']
        need('\\' not in gap, 'no phase-two escapes in slot trivia')
        comments = list(re.finditer(comment, gap))
        if not comments:
            continue
        replacement = re.sub(comment, lambda item: re.sub(r'[^\r\n]', ' ', item[0]), gap)
        start, end = row.span('gap')
        raw = replacement.encode('ascii')
        normalized[start:end] = raw
        transformations.append(dict(Register=row['register'], Offset=start, Size=end - start,
            BlockComments=len(comments), OriginalHex=source[start:end].hex(), QualifiedHex=raw.hex()))
    normalized = bytes(normalized)
    need(len(normalized) == len(source), 'slot source byte length preserved')
    return normalized, dict(Scope='TWO_EXACT_SOURCE_LITERAL_GAPS_BLOCK_COMMENT_TRIVIA_ONLY',
        OriginalSourceSha256=sha(source), QualifiedNormalizedSourceSha256=sha(normalized),
        OriginalSlotMentions=2, ExactSourceStringPairs=2, ByteLengthPreserved=True, Transformations=transformations)


def check_slot(slot, source, assembly, original_object, replayed_object, *, profile, mode):
    normalized, trivia = slot_source_trivia(source)
    need(slot.SLOT == SLOT, 'qualified slot identity')
    qualified = slot.check_generated(normalized, assembly, original_object, replayed_object)
    need(qualified['SourceSha256'] == sha(normalized), 'qualified normalized source binding')
    result = scoped(qualified, 'ORDINARY_TWO_DIRECT_SLOT_LOADS_ONLY', profile, mode)
    result.update(SourceSha256=sha(source), OriginalSourceSha256=sha(source),
                  QualifiedNormalizedSourceSha256=sha(normalized), SourceTrivia=trivia,
                  QualifiedSourceCheck=copy.deepcopy(qualified))
    return result


def run_components(native_bundle, *, profile, mode, inventory, helpers, watch, output_dir):
    """One fresh batched suite; no positive pair recapture or target execution."""
    suite = helpers['controls'].create_suite(native_bundle, profile=profile, mode=mode,
        inventory=inventory, helpers=helpers, watch=watch, output_dir=output_dir)
    watch.read(Path(__file__).resolve())
    root = suite.base / 'source'
    sources = {name[len('source/'):]: watch.read(suite.base / name, digest)
               for name, digest in sorted(native_bundle['Artifacts'].items()) if name.startswith('source/')}
    ownership, abi, core, slot = (helpers[key] for key in ('ownership', 'abi', 'cm0_components', 'slot'))
    common = ownership.validate_common_sources({name: sources[name] for name in ownership.REQUIRED_SOURCES})
    providers = abi.inspect_provider_dependencies(profile, sources, watch.read(suite.base / 'results.json'), source_root=str(root))
    need(providers['Profile'] == profile and providers['Mode'] == mode, 'same provider profile and mode')
    suite.report.update(ComponentScope=SCOPE, ComponentPhasesComplete=False)
    error = None
    try:
        suite.start()
        suite.report['SourceOwnership'] = scoped(common, 'ORDINARY_COMMON_SOURCE_BOUNDARY_PREDICATES_ONLY', profile, mode)
        suite.report['DeclaredProviderDependencies'] = providers
        suite.run_link_controls()
        replay = suite.compile_tuple(3, name='runtime-slot-replay', save_temps=True)
        helpers['cm0_controls'].same(replay['Dependencies'], suite.source(3)['Dependencies'], 'same runtime consumed dependencies')
        generated = check_slot(slot, watch.read(replay['Source'], replay['SourceSha256']),
            watch.read(replay['Assembly']['Path'], replay['Assembly']['Sha256']),
            watch.read(replay['OriginalObject'], replay['OriginalObjectSha256']), watch.read(replay['Object'], replay['ObjectSha256']),
            profile=profile, mode=mode)
        suite.report['GeneratedSlot'] = generated
        probes = abi.emit_probes(profile)
        need(tuple(probes) == PROBES, 'five fixed ordered probes')
        suite.report['ABIProbes'] = {}
        for name, probe in probes.items():
            record = core.compile_probe(suite, name, probe)
            suite.report['ABIProbes'][name] = record
            if name == 'attributes.c':
                preprocessed = abi.inspect_preprocessed_attributes(profile, watch.read(record['Preprocessed']))
                need(set(preprocessed['CanonicalHeaders']) == {'forward', 'reverse'}, 'both canonical declaration origins')
                for direction, path in preprocessed['CanonicalHeaders'].items():
                    expected = root / ('context/context_port_abi.h' if direction == 'forward' else 'context/context_runtime_port_abi.h')
                    need(suite.api.checked_path(path) == expected, 'same-attempt preprocessed canonical header')
                suite.report['PreprocessedAttributes'] = preprocessed
        suite.report['IsolatedCommon'] = [core.isolated_common(suite, index) for index in range(3)]
        suite.write_input('component-facts.json', helpers['cm0_controls'].encoded({key: suite.report[key] for key in
            ('ComponentScope', 'SourceOwnership', 'DeclaredProviderDependencies', 'GeneratedSlot',
             'ABIProbes', 'PreprocessedAttributes', 'IsolatedCommon')}))
        suite.report['ComponentPhasesComplete'] = True
    except BaseException as failure:
        error = failure
    return suite.finish(error)


def prepare(args):
    helpers, watch = load_helpers()
    api = helpers['api']
    admission = api.Admission(watch)
    inventory = admission.snapshot(dict(Build=args.inventory, ReceiptSha256=api.digest(args.inventory_receipt_sha256),
        ArtifactsSha256=api.digest(args.inventory_artifacts_sha256)), current=True)
    native = admission.bundle(dict(Build=args.native_build, ReceiptSha256=api.digest(args.native_receipt_sha256),
        ArtifactsSha256=api.digest(args.native_artifacts_sha256)))
    admission.require_inventory_binding(native, inventory)
    return native, inventory, helpers, watch


def succeeded(report):
    return (report.get('Status') == 'ORDINARY-DIRECT-LINK-CONTROLS-PASS'
        and report.get('ComponentPhasesComplete') is True and report.get('InputClosureVerified') is True
        and report.get('OutputSealVerified') is True and report.get('Error') is None
        and report.get('PrimaryError') is None and report.get('ClosingErrors') == []
        and type(report.get('RequiredCellsSatisfied')) is int and report['RequiredCellsSatisfied'] == 0)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('native-build', 'native-receipt-sha256', 'native-artifacts-sha256', 'profile', 'mode',
                 'inventory', 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    try:
        native, inventory, helpers, watch = prepare(args)
        report = run_components(native, profile=args.profile, mode=args.mode, inventory=inventory,
                                helpers=helpers, watch=watch, output_dir=args.output_dir)
    except BaseException as error:
        print('Ordinary component admission failed: ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps({name: report.get(name) for name in ('Status', 'Profile', 'Mode', 'ComponentScope',
        'ComponentPhasesComplete', 'Error', 'PrimaryError', 'ClosingErrors', 'IntendedLinkRejects',
        'InputClosureVerified', 'OutputSealVerified', 'ClosingFilesVerified', 'RequiredCellsSatisfied')}, sort_keys=True))
    return 0 if succeeded(report) else 1


if __name__ == '__main__':
    raise SystemExit(main())
