"""Build-only 41-command Os ABI phase for an authenticated batch session.

No constructor, parser, module loader, run, finish or verdict from an O2 fixture
is called. The positive link is built here; load-image reproduction MUST be
recomputed later in the enclosing single immutable reader. Authenticated source,
tool, command-journal and output closure remain the batch owner's obligations.
"""

import copy
import hashlib
import json
from pathlib import Path


MODE = 'Os-lto'
SCOPE = 'NATIVE_CM3_OS_LTO_ABI_CONTROLS_BUILD_ONLY_PENDING_READER'
PROBES = ('types.c', 'attributes.c', 'slot_read.c', 'slot_write.c', 'slot_address.c')
CONTROLS = ('stale-nvic-expectation', 'stale-storage-application', 'stale-reverse-anchor',
            'duplicate-svc', 'duplicate-pendsv')
ANCHOR = 'fiber_internal_runtime_port_abi_v1_anchor'
MODULES = ('recipes', 'declarations', 'ordinary', 'probes', 'plan', 'diagnostics')


class Rejected(ValueError):
    pass


def need(value, message):
    if not value:
        raise Rejected('cm3-os-lto-abi-controls: ' + message)


def sha(raw):
    need(type(raw) is bytes, 'immutable byte buffer')
    return hashlib.sha256(raw).hexdigest().upper()


def _os(record, label):
    need(type(record) is dict and record.get('Profile') == 'CM3'
         and record.get('Mode') == MODE and record.get('Linkage') == 'direct'
         and record.get('LTO') is True, 'explicit Os declaration metadata: ' + label)


def _binding(suite, path, role):
    path = suite.api.checked_path(path)
    return dict(Role=role, Path=str(path), Sha256=sha(suite.watch.read(path)))


def _positive(suite):
    _, positive, link_map = suite._link('positive', suite.objects)
    original = suite.result['Links'][0]['Path']
    inputs = [_binding(suite, original, 'OriginalELF'), _binding(suite, positive, 'ReproducedELF')]
    map_record = _binding(suite, link_map, 'ReproducedMap')
    suite.report['PositiveAuthority'] = dict(
        Original=inputs[0]['Path'], OriginalSha256=inputs[0]['Sha256'],
        Replayed=inputs[1]['Path'], ReplayedSha256=inputs[1]['Sha256'],
        Map=map_record['Path'], MapSha256=map_record['Sha256'],
        RawElfByteIdentical=inputs[0]['Sha256'] == inputs[1]['Sha256'],
        Scope='SAME_OS_SLIM_INPUTS_RECIPE_LOAD_IMAGE_REPRODUCTION_PENDING',
        LoadImageComparison=None, LoadImageValidated=False, ValidationDeferred=True,
        LinkCommandIndex=0, ReaderInputs=inputs)
    # This describes obligations, not a successful semantic reader result.
    suite.report['ABIControlsDeferredReader'] = dict(
        Kind='OS_POSITIVE_LOAD_IMAGE_REPRODUCTION', Status='PENDING',
        ValidationDeferred=True, Inputs=inputs, Map=map_record,
        PositiveLinkRevalidated=False, RequiredCellsSatisfied=0)


def _links(suite, modules):
    runtime = suite._definitions(suite.objects[3], 'original-runtime')
    private = [row['Name'] for row in runtime if row['Name'].startswith('fiber_port_context_cohort_')]
    need(len(private) == 1 and private[0].count('_g4_') == 1, 'one actual priority4 private cohort')
    alternate = private[0].replace('_g4_', '_g5_', 1)
    anchor, anchor_import = suite._imports(suite.objects[4], 'unchanged-boot-v1',
                                          'fiber_internal_runtime_port_abi_')
    need(anchor == ANCHOR, 'actual unchanged v1 boot consumer')
    plan = modules['plan'].control_plan(dict(target=dict(nvic_priority_bits=4)), 'ARM_CM3', 'arm_cm3')
    need(type(plan) in (tuple, list) and len(plan) == 5
         and tuple(row['Name'] for row in plan) == CONTROLS, 'exact source-derived control plan')
    wanted = (alternate, 'fiber_port_storage_cohort_arm_cm3_v999_r0', ANCHOR, 'SVC_Handler', 'PendSV_Handler')
    for spec, expected in zip(plan, wanted):
        name, index, added = spec['Name'], spec['Index'], spec['Added']
        record = dict(Name=name, Expected=expected, Status='FAIL', RequiredCellsSatisfied=0)
        suite.report['Controls'].append(record)
        suite._save('results.json', suite.report)
        compiled = suite.compile_tuple(index, name=name, mutations=spec['Mutations'], source_bytes=added)
        obj = Path(compiled['Object'])
        suite.watch.read(obj, compiled['ObjectSha256'])
        record['SlimIR'] = suite.inspect_ir(obj)
        selected = list(suite.objects)
        if added is None:
            selected[index] = obj
        else:
            selected.append(obj)
        if index in (6, 7):
            prefix = 'fiber_port_context_cohort_' if index == 6 else 'fiber_port_storage_cohort_'
            actual, evidence = suite._imports(obj, name, prefix)
            need(actual == expected, 'actual intended alternate identity')
            record['ImportEvidence'] = evidence
        else:
            definitions = suite._definitions(obj, name)
            matches = [row for row in definitions if row['Name'] == (
                'fiber_internal_runtime_port_abi_v2_anchor' if added is None else expected)]
            need(len(matches) == 1 and matches[0]['Kind'] == ('D' if added is None else 'T'),
                 'actual changed data anchor or strong handler')
            record['ChangedDefinitions'] = definitions
            if added is None:
                need(ANCHOR not in {row['Name'] for row in definitions}, 'changed state must not define v1')
                imports, evidence = suite._undefined(obj, name)
                need(ANCHOR not in imports, 'changed state must not create the missing-v1 consumer')
                record.update(ChangedImports=evidence, ImportEvidence=anchor_import)
        first = len(suite.commands)
        result, elf, partial = suite._link(name, selected, expected_failure=True)
        if added is None:
            machine = suite.api.checked_path(str(elf) + '.ltrans0.ltrans.o')
            raw = suite.watch.read(machine)
            suite.transport.require_elf32le(raw)
            classification = modules['diagnostics'].classify_undefined(
                result, expected, suite.tools['ld'], machine=machine)
            record['DiagnosticMachine'] = dict(Path=str(machine), Sha256=sha(raw),
                                               Kind='ACTUAL_SAVED_ARM_ELF32_REL')
        else:
            classification = modules['diagnostics'].classify_duplicate(
                result, expected, suite.tools['ld'], obj, suite.objects[3], compiled['Source'])
        need(not elf.exists(), 'intended failed link cannot retain a final image')
        suite.verify_objects()
        suite.watch.close()
        record.update(Status='INTENDED-LINK-REJECTION-PASS', Compilation=compiled,
            Classification=classification, LinkCommandIndex=first, FinalImageAbsent=True,
            PartialMap=str(partial) if partial.exists() else None,
            ConsumedObjects=[dict(Index=position, Path=str(path), Sha256=sha(suite.watch.read(path)))
                             for position, path in enumerate(selected)])
        suite._save('controls/' + name + '.json', record)
        suite._save('results.json', suite.report)
    need(tuple(row['Name'] for row in suite.report['Controls']) == CONTROLS
         and all(row['Status'] == 'INTENDED-LINK-REJECTION-PASS' for row in suite.report['Controls']),
         'all five actual intended link rejections')
    suite.report['FiveLinkControlsValidated'] = True


def _declarations(suite, modules):
    root = suite.base / 'source'
    capture = suite.witness.groups['Native']['Root']
    sources = {name[len('source/'):]: suite.watch.read(suite.base / name, digest)
               for name, digest in suite.bundle['Artifacts'].items() if name.startswith('source/')}
    record = modules['declarations'].inspect_provider_dependencies(
        sources, suite.watch.read(Path(capture) / 'results.json'),
        source_root=str(root), capture_root=str(capture), ordinary=modules['ordinary'])
    _os(record, 'providers')
    need(record.get('DeclaredProviderDependenciesBound') is True
         and type(record.get('Providers')) is list and len(record['Providers']) == 9,
         'nine bound Os provider dependency declarations')
    suite.report['DeclaredProviders'] = record


def _probes(suite, modules):
    declarations = modules['declarations']
    probes = declarations.emit_probes(ordinary=modules['ordinary'])
    need(type(probes) is dict and tuple(probes) == PROBES, 'exact five independently typed probes')
    suite.report['ABIProbes'] = {}
    for name, probe in probes.items():
        _os(probe, 'probe/' + name)
        record = modules['probes'].compile_probe(suite, name, probe)
        suite.report['ABIProbes'][name] = record
        if name in PROBES[:2]:
            record['SlimIR'] = suite.inspect_ir(Path(record['Object']))
        if name == 'attributes.c':
            facts = declarations.inspect_preprocessed_attributes(suite.watch.read(record['Preprocessed']),
                                                                  ordinary=modules['ordinary'])
            _os(facts, 'accepted CPP attributes')
            headers = facts.get('CanonicalHeaders')
            need(type(headers) is dict and set(headers) == {'forward', 'reverse'},
                 'two accepted-attempt canonical declaration origins')
            for direction, path in headers.items():
                header = 'context_port_abi.h' if direction == 'forward' else 'context_runtime_port_abi.h'
                need(suite.api.checked_path(path) == suite.base / 'source/context' / header,
                     'same accepted attempt canonical declaration header')
            suite.report['PreprocessedAttributes'] = facts
    suite.report['TypedDeclarationProbesValidated'] = True


def _commands(suite, recipes):
    plan = recipes.batch_plan()
    rows = plan['Components']
    need(type(rows) is list and rows and rows[0]['Name'] == 'ABIControls'
         and rows[0]['Start'] == 0 and rows[0]['Stop'] == rows[0]['Count'] == 41,
         'fixed first phase recipe')
    expected = plan['Commands'][:41]
    need(len(suite.commands) == len(expected) == 41, 'exact ABI command count')
    for actual, wanted in zip(suite.commands, expected):
        need(actual.get('Label') == wanted['Label'] and actual.get('State') == 'TERMINAL'
             and actual.get('Status') == ('EXPECTED-NONZERO' if wanted['ExpectedExit'] else 'PASS')
             and type(actual.get('Exit')) is int and type(actual.get('ExpectedExit')) is int
             and actual['Exit'] == actual['ExpectedExit'] == wanted['ExpectedExit']
             and actual.get('TimedOut') is False and not actual.get('JournalErrors'),
             'exact typed terminal ABI recipe command/' + wanted['Label'])


def build(suite, modules):
    """Execute only this phase. Exceptions propagate to the batch failure seal.

    Required modules are recipes, declarations, ordinary, probes, plan and diagnostics.
    The supplied session owns all real tools/processes and byte/physical closure.
    declarations must export inspect_provider_dependencies, emit_probes and
    inspect_preprocessed_attributes, each accepting ordinary= and returning
    explicit Os metadata. The caller loads ordinary under its admitted buffers.
    """
    need(type(modules) is dict and all(name in modules for name in MODULES), 'explicit authenticated phase modules')
    need(not getattr(suite, '_abi_controls_started', False), 'ABI phase cannot retry')
    need(suite._started and not suite._finished and not suite.commands and not suite.phases,
         'ABI is the first phase of an active session')
    _os(suite.result, 'capture')
    _os(suite.report, 'batch')
    need(suite.report.get('Status') == 'FAIL' and type(suite.report.get('RequiredCellsSatisfied')) is int
         and suite.report['RequiredCellsSatisfied'] == 0, 'unpromoted zero-credit batch')
    modules['recipes'].require_capture_sources(suite.result)
    for index in range(9):
        need(suite.source(index)['CompileFlags'] == modules['recipes'].compile_flags(suite.result, index),
             'same actual Os source flags')
    need(suite.link_argv == modules['recipes'].link_recipe(suite.result, suite.objects),
         'same actual Os link recipe')
    suite._abi_controls_started = True
    suite.begin_phase('ABIControls')
    suite.report.update(ABIControlsBuilt=False, PositiveLinkRevalidated=False,
                        FiveLinkControlsValidated=False, TypedDeclarationProbesValidated=False)
    try:
        _declarations(suite, modules)
        _positive(suite)
        _links(suite, modules)
        _probes(suite, modules)
        _commands(suite, modules['recipes'])
        suite.verify_objects()
        suite.watch.close()
        record = dict(Status='BUILT-PENDING-READER', Scope=SCOPE, Profile='CM3', Mode=MODE,
            Linkage='direct', LTO=True, Commands=41, First=0, Stop=41,
            IntendedLinkRejects=5, AcceptedTypedProbes=2, UndeclaredSlotRejects=3,
            PositiveLinkRevalidated=False, DeferredReaderRequired=True,
            Qualification=False, CellContractSatisfied=False, RequiredCellSatisfied=False,
            RequiredCellsSatisfied=0, FullABIProof=False, FullSemanticABIProof=False,
            CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False)
        suite.report['ABIControlsBuild'] = record
        suite.report['ABIControlsBuilt'] = True
        suite.write_input('abi-controls-build.json', (json.dumps(dict(Build=record,
            DeclaredProviders=suite.report['DeclaredProviders'], ABIProbes=suite.report['ABIProbes'],
            PreprocessedAttributes=suite.report['PreprocessedAttributes'],
            PositiveAuthority=suite.report['PositiveAuthority'], Controls=suite.report['Controls']),
            sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii'))
        suite.end_phase()
        suite._save('results.json', suite.report)
        return copy.deepcopy(record)
    except BaseException as error:
        suite.report.update(Status='FAIL', ABIControlsBuilt=False, PositiveLinkRevalidated=False,
            FiveLinkControlsValidated=False, TypedDeclarationProbesValidated=False,
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
