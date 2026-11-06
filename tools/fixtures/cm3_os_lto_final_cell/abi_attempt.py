"""Execute the current Os ABI phase, then replay its deferred reader duties.

This staged driver is not the 134-command batch or a whole-cell qualifier.
Every source/tool/capture input is enrolled before admission closes. The
managed command session owns process cleanup, journals and dependency bytes.
Only after all commands finish does one immutable reader inspect outputs.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PASS = 'CURRENT-CM3-OS-LTO-ABI-CONTROLS-PASS-NOT-QUALIFIED'
SCOPE = 'CURRENT_CM3_OS_LTO_ABI_CONTROLS_COMPONENT_ONLY'
RUNNER_SHA256 = '1B4BFC82D20398FA4F128B368104360C888C27DDBF5104ED74A80819F4371716'
ARGUMENTS = ('native-build', 'native-receipt-sha256', 'native-artifacts-sha256',
    'reference-build', 'reference-receipt-sha256', 'reference-artifacts-sha256',
    'inventory', 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir')
PINS = {
    'session': ('tools/fixtures/cm3_os_lto_final_cell/batch_session.py',
        'E600788C8563ED44327A61CED2B5D518A354DE19B33BA6614B04733E3E5D4FB6'),
    'recipes': ('tools/fixtures/cm3_os_lto_final_cell/batch_recipes.py',
        'C15D57AA9FE3963FF84F22D831F4E1F5F941AC351571AB347ECBC29E9172004B'),
    'utility': ('tools/fixtures/cm0_final_cell/controls.py',
        '9FA3297C5C1D3861F8B422977E876D40B0F6D7275AA4431B0AC579AECB777C9A'),
    'lto': ('tools/fixtures/cm3_lto_abi_controls/controls.py',
        '7984A228966FC17641BD83D23486DB7E50BC2B7E5BC12D70A712F6E83800F14F'),
    'native': ('tools/fixtures/classic_final_image/run.py',
        'FBCBA0C4FF480E139ADE401ECFA90822E9EA01A6AB554CEF157036EC9DE7F014'),
    'process': ('tools/fixtures/freeze_cohorts/process_runner.py',
        'D00D16DBFC69C3F49DF24D8F8A7329045DD9545AF50CB37A39ACB38EAC48B104'),
    'probes': ('tools/fixtures/cm0_final_cell/components.py',
        '16490A20B1A75C5DBD2D21A5FED988C5BD82F4DE919350985B33491CE473A5F7'),
    'plan': ('tools/fixtures/ordinary_final_cell/controls.py',
        '10F8203B7AA24502BDCA2274DA8C5B7A8763EF7630E8FE8350C64AC50699F18A'),
    'ordinary': ('tools/fixtures/ordinary_final_cell/abi.py',
        '43F2E49D638D0E586A24AD2B32D0B8D86C58CC9A63E134EF6AF064437278CAE5'),
    'diagnostics': ('tools/fixtures/cm3_lto_abi_controls/diagnostics.py',
        '0A1CD4EB14172C3E3FF1E5B05A733C7837404E7DD95C8D6953323EB26FEA250C'),
}
# New leaf pins are added only after their owners freeze reviewed test bytes.
LEAF_PINS = {
    'declarations': ('tools/fixtures/cm3_os_lto_final_cell/declarations.py',
        'B502C330A5F00CE10393390866F160030EE604E8A9BC8080F8633D9BF66245B2'),
    'abi_controls': ('tools/fixtures/cm3_os_lto_final_cell/abi_controls.py',
        'A05048E4A5047EDF0090C39AD8199C5D5A6B5981A1E0EBA9FA69ACD2850F8379'),
}
DOCUMENTS = {
    'tools/fixtures/cm0_final_cell/abi.py':
        'F5AA5CE6BD21130249D571D0AA03BD72C735DA04832C2B6DBF13EFD548CB4F4B',
    'tools/fixtures/cm3_os_lto_final_cell/BATCH_CONTRACT.md':
        'D9EAE7806028289EDB5A69B6317DA6247A19E1B15ACED5B75FF5D6194DE8EE66',
}
NONCLAIMS = ('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'TypedABIProof',
    'CurrentSlotIsolationProven', 'CanonicalProtocolValidated', 'FinalRootRelocationProof',
    'CommonAttributePolicyProven', 'SelectedPortAttributePolicyProven', 'FinalReferenceParity',
    'CompleteObjectProof', 'PolicyEquivalence', 'SourceIRProof', 'SourceToMachineSemanticProof',
    'OriginalTranslationUnitOwnership', 'KernelRuntimeProof', 'CpuExecution', 'BoardExecution',
    'HostedCIQualified', 'ArchiveQualification', 'GlobalFreezeQualified', 'RequiredCellSatisfied',
    'CellContractSatisfied', 'ProducerCompilersReexecuted')


def need(value, message):
    if not value:
        raise ValueError('cm3-os-lto-abi-attempt: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def load(name, path, raw):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def prepare(args):
    need(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and not sys.flags.optimize,
         'fresh isolated unoptimized -I -S -B interpreter')
    need(not any(name == 'elftools' or name.startswith('elftools.') for name in sys.modules),
         'no inherited parser state')
    path = HERE / 'runner.py'
    raw = path.read_bytes()
    need(sha(raw) == RUNNER_SHA256, 'frozen Os admission/reader entrypoint')
    runner = load('_os_abi_attempt_runner', path, raw)
    need(set(LEAF_PINS) == {'declarations', 'abi_controls'}, 'reviewed leaf pins required before execution')
    buffers = {path: raw}
    for relative, digest in (*runner.PINS.values(), *runner.DOCUMENTS.items(),
                             *PINS.values(), *LEAF_PINS.values(), *DOCUMENTS.items()):
        path, raw = ROOT / relative, (ROOT / relative).read_bytes()
        need(sha(raw) == digest and (path not in buffers or buffers[path] == raw),
             'fixed authenticated source: ' + relative)
        buffers[path] = raw
    own = Path(__file__).resolve()
    buffers[own] = own.read_bytes()
    modules = {name: load('_os_abi_attempt_' + name, ROOT / row[0], buffers[ROOT / row[0]])
               for name, row in runner.PINS.items()}
    witness = modules['admission'].witness_type(modules['legacy'], modules['capture'], extra_sources=buffers)(args)
    environment = dict(Witness=witness, Modules=modules)

    def read_bytes(path):
        need(path in buffers, 'bootstrap read outside authenticated source buffers: ' + str(path))
        return buffers[path]

    with patch.object(Path, 'read_bytes', read_bytes):
        helpers = {name: load('_os_abi_attempt_helper_' + name, ROOT / row[0], buffers[ROOT / row[0]])
                   for name, row in (*PINS.items(), *LEAF_PINS.items())}
    suite = helpers['session'].suite_type(helpers['utility'], helpers['lto'])(environment, helpers, buffers)
    suite.report = dict(runner.base_report(witness), **suite.report)
    suite.report['Scope'] = SCOPE
    return runner, environment, helpers, suite


def replay(runner, environment, suite):
    witness = environment['Witness']
    capture = witness.groups['Native']['Root']
    positive = suite.report['PositiveAuthority']
    project = {name[len('source/'):]: suite.base / name for name in suite.bundle['Artifacts']
               if name.startswith('source/')}
    roles = dict(Reproduction=dict(Original=Path(positive['Original']), Replayed=Path(positive['Replayed']),
        Map=Path(positive['Map'])), ProjectSources=project,
        Declarations=dict(Capture=capture / 'results.json',
                          Attributes=Path(suite.report['ABIProbes']['attributes.c']['Preprocessed'])))
    with runner.reader(environment, roles) as (core, rules, frozen):
        def frozen_load(name, relative):
            spec = importlib.util.spec_from_file_location(name, ROOT / relative)
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
            return module
        ordinary = frozen_load('_os_abi_reader_ordinary', PINS['ordinary'][0])
        declarations = frozen_load('_os_abi_reader_declarations', LEAF_PINS['declarations'][0])
        providers = declarations.inspect_provider_dependencies(
            {name: path.read_bytes() for name, path in project.items()},
            roles['Declarations']['Capture'].read_bytes(), source_root=str(suite.base / 'source'),
            capture_root=str(capture), ordinary=ordinary)
        need(providers == suite.report['DeclaredProviders'], 'recomputed provider declarations agree')
        attributes = declarations.inspect_preprocessed_attributes(
            roles['Declarations']['Attributes'].read_bytes(), ordinary=ordinary)
        need(attributes == suite.report['PreprocessedAttributes'], 'recomputed same-attempt CPP declarations agree')
        comparison = core.compare_load_images(roles['Reproduction']['Original'], roles['Reproduction']['Replayed'])
    witness.close()
    positive.update(LoadImageComparison=comparison, LoadImageValidated=True, ValidationDeferred=False,
        Scope='SAME_OS_SLIM_INPUTS_RECIPE_LOAD_IMAGE_REPRODUCTION_ONLY')
    suite.report['ABIControlsDeferredReader'].update(Status='REPLAYED', ValidationDeferred=False,
        PositiveLinkRevalidated=True, LoadImageComparison=comparison)
    suite.report.update(PositiveLinkRevalidated=True, ImmutableInputsConsumed=True, Reader=frozen)


def require_completed(report, helpers):
    need(type(report) is dict and report.get('Status') == PASS and report.get('Scope') == SCOPE
         and report.get('Profile') == 'CM3' and report.get('Mode') == 'Os-lto'
         and report.get('Linkage') == 'direct' and report.get('LTO') is True, 'bounded Os component disposition')
    for key in ('ABIControlsBuilt', 'PositiveLinkRevalidated', 'FiveLinkControlsValidated',
                'TypedDeclarationProbesValidated', 'NegativeLinkControlsExecuted',
                'ImmutableInputsConsumed', 'InputClosureVerified', 'OutputSealVerified'):
        need(report.get(key) is True, 'completed fact/' + key)
    commands = report.get('Commands')
    expected = helpers['recipes'].batch_plan()['Commands'][:41]
    need(type(commands) is list and len(commands) == len(expected) == 41, 'complete command journal')
    for actual, wanted in zip(commands, expected):
        need(type(actual) is dict and actual.get('Label') == wanted['Label']
             and actual.get('State') == 'TERMINAL' and actual.get('TimedOut') is False
             and actual.get('Status') == ('EXPECTED-NONZERO' if wanted['ExpectedExit'] else 'PASS')
             and type(actual.get('Exit')) is int and type(actual.get('ExpectedExit')) is int
             and actual['Exit'] == actual['ExpectedExit'] == wanted['ExpectedExit']
             and not actual.get('JournalErrors'), 'typed actual command/' + wanted['Label'])
    phases = report.get('Phases')
    need(type(phases) is list and len(phases) == 1 and type(phases[0]) is dict
         and set(phases[0]) == {'Name', 'First', 'Stop', 'Commands'}
         and type(phases[0]['Name']) is str and phases[0]['Name'] == 'ABIControls', 'one exact phase')
    for key, value in (('First', 0), ('Stop', 41), ('Commands', 41)):
        need(type(phases[0][key]) is int and phases[0][key] == value, 'literal phase counter/' + key)
    for key, value in (('RequiredCellCount', 2774), ('RequiredCellsSatisfied', 0)):
        need(type(report.get(key)) is int and report[key] == value, 'literal coverage counter/' + key)
    for key in NONCLAIMS:
        need(report.get(key) is False, 'bounded nonclaim/' + key)
    need('Error' in report and report['Error'] is None and 'PrimaryError' in report
         and report['PrimaryError'] is None and type(report.get('ClosingErrors')) is list
         and report['ClosingErrors'] == [],
         'no primary, closing or journal failures')


def revoke(runner, report, error):
    runner.revoke(report, error)
    report.update(ABIControlsBuilt=False, PositiveLinkRevalidated=False,
        FiveLinkControlsValidated=False, TypedDeclarationProbesValidated=False)


def run(runner, environment, helpers, suite):
    witness = environment['Witness']
    try:
        suite.start()
        helpers['abi_controls'].build(suite, helpers)
        suite.report['NegativeLinkControlsExecuted'] = True
        replay(runner, environment, suite)
        suite.verify_objects()
        witness.close()
        suite._verify_outputs()
        suite.report.update(Status=PASS, Commands=suite.commands,
            CommandsSha256=suite.expected['commands.json'], ToolInvocations=len(suite.commands),
            CompilerInvocations=sum(row['Argv'][0] == str(suite.tools['gcc']) for row in suite.commands),
            InputHashes={str(path): digest for path, digest in sorted(witness.watch.hashes.items())},
            InputPhysicalIdentities={str(path): list(witness._physical(path)) for path in sorted(witness.watch.hashes)},
            ClosingFilesVerified=len(witness.watch.hashes), InputClosureVerified=True, OutputSealVerified=True)
        require_completed(suite.report, helpers)
        suite._save('results.json', suite.report)
        suite._save('artifacts.json', dict(Artifacts=dict(suite.expected)))
        witness.close()
        suite._verify_outputs()
        print(json.dumps(dict(Status=PASS, Commands=len(suite.commands), IntendedLinkRejects=5,
            UndeclaredSlotRejects=3, RequiredCellsSatisfied=0, Output=str(suite.output),
            ReceiptSha256=sha((suite.output / 'results.json').read_bytes()),
            ArtifactsSha256=sha((suite.output / 'artifacts.json').read_bytes())), sort_keys=True), flush=True)
        return suite.report
    except BaseException as error:
        revoke(runner, suite.report, error)
        runner.recover(environment, suite.report)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ARGUMENTS:
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    runner, environment, helpers, suite = prepare(args)
    run(runner, environment, helpers, suite)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
