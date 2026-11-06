"""Five ordinary direct-link controls for an explicitly admitted native build.

create_suite() launches nothing. Its caller authenticates both the complete
Admission.bundle/snapshot and the exact buffers used to load helpers. Helpers:
api (freeze_replay), cm0_controls (qualified generic Suite mechanics), native,
recipe, profiles, facade, process. The independent profiles.profile contract and
profiles.require_native metadata guard remain unchanged.

start/command/compile_tuple/run_link_controls/finish match the qualified Suite
interface. Only fresh output/control copies may change. No cell credit, target
execution, reference comparison, or learned positive-object oracle is provided.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from types import SimpleNamespace


PROFILES = ('CM0', 'CM0PLUS', 'CM0PLUSVTOR', 'CM3', 'CM4', 'CM7')
MODES = ('O0', 'Og', 'O2', 'Os', 'O3')
CONTROLS = ('stale-nvic-expectation', 'stale-storage-application', 'stale-reverse-anchor', 'duplicate-svc', 'duplicate-pendsv')
ANCHOR = 'fiber_internal_runtime_port_abi_v1_anchor'
PASS = 'ORDINARY-DIRECT-LINK-CONTROLS-PASS'
SCOPE = 'ORDINARY_SELECTED_NATIVE_FIVE_DIRECT_LINK_CONTROLS_ONLY'
FIXTURE = 'tools/fixtures/classic_final_image'


class Rejected(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected('ordinary-cell-controls: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def same(actual, expected, message):
    need(encoded(actual) == encoded(expected), message)


def control_plan(artifact, port_directory, storage_family):
    """Source-derived mutations; the missing private import is also NM-bound."""
    bits = artifact['target']['nvic_priority_bits']
    need(type(bits) is int and bits in (2, 4), 'ordinary NVIC2/4 only')
    need(type(port_directory) is str and re.fullmatch(r'ARM_CM(?:0|3|4|7/r0p1)', port_directory), 'selected port directory')
    need(storage_family in ('arm_cm0', 'arm_cm3', 'arm_cm4', 'arm_cm7_r0p1'), 'selected storage family')
    return (
        dict(Name=CONTROLS[0], Index=6, Mutations=((FIXTURE + '/main.h',
             ('#define __NVIC_PRIO_BITS %dU' % bits).encode('ascii'),
             ('#define __NVIC_PRIO_BITS %dU' % (bits + 1)).encode('ascii')),), Added=None),
        dict(Name=CONTROLS[1], Index=7, Mutations=(('fiber/port/' + port_directory + '/fiber_port_types.h',
             b'#define FIBER_PORT_STORAGE_COHORT_REVISION 1', b'#define FIBER_PORT_STORAGE_COHORT_REVISION 999'),), Added=None),
        dict(Name=CONTROLS[2], Index=1, Mutations=(('context/context_runtime_state.c',
             b'const unsigned char fiber_internal_runtime_port_abi_v1_anchor =',
             b'const unsigned char fiber_internal_runtime_port_abi_v2_anchor ='),), Added=None),
        dict(Name=CONTROLS[3], Index=3, Mutations=(), Added=b'void SVC_Handler(void) { for (;;) { } }\n'),
        dict(Name=CONTROLS[4], Index=3, Mutations=(), Added=b'void PendSV_Handler(void) { for (;;) { } }\n'),
    )


def alternate_private(nm_text, bits):
    need(type(nm_text) is str and type(bits) is int and bits in (2, 4), 'private identity inputs')
    names = [line.split()[0] for line in nm_text.splitlines() if line.startswith('fiber_port_context_cohort_')]
    token = '_g%d_' % bits
    need(len(names) == 1 and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', names[0])
         and len(re.findall(r'(?=_g[0-9]+_)', names[0])) == 1 and names[0].count(token) == 1,
         'one original private identity with admitted priority bits')
    return names[0], names[0].replace(token, '_g%d_' % (bits + 1), 1)


def terminal_success(commands):
    return (type(commands) is list and bool(commands) and all(type(row) is dict
        and row.get('State') == 'TERMINAL' and row.get('Status') in ('PASS', 'EXPECTED-NONZERO')
        and type(row.get('Exit')) is int and type(row.get('ExpectedExit')) is int
        and row['Exit'] == row['ExpectedExit'] == (1 if row['Status'] == 'EXPECTED-NONZERO' else 0)
        and row.get('TimedOut') is False and not row.get('JournalErrors') for row in commands))


def create_suite(native_bundle, *, profile, mode, inventory, helpers, watch, output_dir):
    """No imports or commands; reuse the caller's authenticated utility class."""
    return suite_type(helpers['cm0_controls'])(native_bundle, profile=profile, mode=mode,
        inventory=inventory, helpers=helpers, watch=watch, output_dir=output_dir)


def suite_type(utility):
    """Inherit only generic mechanics; never change the qualified module globals."""
    class Suite(utility.Suite):
        def __init__(self, native_bundle, *, profile, mode, inventory, helpers, watch, output_dir):
            need(not sys.flags.optimize, 'unoptimized Python required')
            need(type(profile) is str and profile in PROFILES and type(mode) is str and mode in MODES, 'one ordinary route')
            self.api, self.native, self.facade, self.process = (helpers[key] for key in ('api', 'native', 'facade', 'process'))
            self.watch, self.bundle = watch, native_bundle
            self.base = self.api.checked_path(native_bundle['Root'], directory=True)
            self.output = self.api.checked_path(output_dir, fresh=True)
            self.result = native_bundle['Result']
            helpers['profiles'].require_native(self.result, profile, mode)
            self.model = helpers['profiles'].profile(profile, mode)
            identity, directory, storage, port_sources = self.native.selection(profile, mode)
            group = 'CM0' if profile.startswith('CM0') else profile
            same([self.model[key] for key in ('Cohort', 'SourceGroup', 'StorageSymbol')],
                 [identity, group, 'fiber_port_storage_cohort_' + storage + '_v1_r0'], 'independent native/profile selection')
            artifact = self.model['CohortArtifact']
            same(self.result['CohortArtifact'], artifact, 'exact admitted artifact')
            same([self.result[key] for key in ('Verdict', 'Profile', 'Mode', 'Cohort', 'Linkage', 'LTO', 'Error', 'InputDrift')],
                 ['NATIVE-FINAL-TWIN-BUILD-PASS', profile, mode, identity, 'direct', False, None, []], 'positive build scope')
            fingerprint = inventory['SourceInventorySha256']
            need(type(fingerprint) is str and re.fullmatch(r'[0-9A-F]{64}', fingerprint), 'inventory fingerprint')
            same(self.result['SourceInventorySha256'], fingerprint, 'one inventory source identity')
            same(self.model['SourceInventorySha256'], fingerprint, 'independent inventory source identity')
            same(Path(self.result['SourceInventoryReceipt']).as_posix(), inventory['Bundle']['Root'].as_posix(), 'one inventory root')
            need(self.api.checked_path(native_bundle['Descriptor']['Build'], directory=True) == self.base, 'positive root/descriptor')
            names = (*self.native.COMMON_SOURCES, *port_sources, 'fiber/port/fiber_port_context_cohort_expectation.c',
                     FIXTURE + '/application.c', FIXTURE + '/startup.S')
            same(list(names), self.model['SourceOrder'], 'independent source roles')
            self.sources = copy.deepcopy(self.result['Sources'])
            same([row['Source'] for row in self.sources], [str(self.base / 'source' / name) for name in names], 'nine source roles')
            self.objects = tuple(self.base / 'objects' / ('%02d-' % i + Path(name).stem + '.o') for i, name in enumerate(names))
            same([row['Object'] for row in self.sources], [str(path) for path in self.objects], 'nine object roles')
            fixture, source_root = self.base / 'source' / FIXTURE, self.base / 'source'
            flags = helpers['recipe'].native_flags(artifact, mode, fixture, source_root / 'fiber/port' / directory,
                                                  source_root, self.base / 'cmsis')
            commands = self.result['Commands']
            need(len(commands) == 73 and all(type(row['Exit']) is int and row['Exit'] == 0
                 and row['Status'] == 'PASS' and row['TimedOut'] is False for row in commands), 'positive command closure')
            self.tools = {}
            for key, label in (('gcc', 'compiler version'), ('nm', 'inspect 03-fiber_port.o.nm'),
                               ('objdump', 'inspect 03-fiber_port.o.dis'), ('readelf', 'inspect 03-fiber_port.o.attributes')):
                rows = [row for row in commands if row['Label'] == label]
                need(len(rows) == 1, 'unique admitted tool role: ' + key)
                path = self.api.checked_path(rows[0]['Argv'][0])
                need(path in watch.hashes, 'tool must already be admitted')
                self.tools[key] = path
            for index, row in enumerate(self.sources):
                expected = self.native.startup_flags(artifact, mode) if index == 8 else [*flags, '-I' + str(Path(row['Source']).parent)]
                same(row['CompileFlags'], expected, 'exact recorded compile flags')
                argv = [str(self.tools['gcc']), *expected, '-MD', '-MF', row['CompileDependencyFile'],
                        '-MT', 'pilot-source-' + str(index), '-c', row['Source'], '-o', row['Object']]
                actual = [command['Argv'] for command in commands if command['Label'] == 'compile ' + Path(row['Source']).name]
                same(actual, [argv], 'exact actual positive compilation')
                need(row['CompileDependenciesVerified'] is True, 'positive compile dependencies')
                self.native.require_compile_dependencies(row['Dependencies'], row['ActualCompileDependencies'])
                for dependency in row['Dependencies']:
                    watch.read(dependency['Path'], dependency['Sha256'])
            indices = [i for i, row in enumerate(commands) if row['Label'] == 'resolve ld']
            need(len(indices) == 1, 'one actual linker resolution')
            linker = watch.read(self.base / ('command-%04d.stdout' % indices[0])).decode('utf-8').strip()
            self.tools['ld'] = self.api.checked_path(Path(os.path.abspath(linker)))
            need(self.tools['ld'] in watch.hashes, 'authenticated linker')
            same([row['Kind'] for row in self.result['Links']], ['ordinary', 'emit-relocs'], 'positive twins')
            self.link_argv = [str(self.tools['gcc']), *artifact['compile_flags'], '-' + mode, '-nostdlib',
                '-Wl,--gc-sections,--no-undefined,--fatal-warnings,--build-id=none,-z,noexecstack',
                '-T', str(fixture / 'link.ld'), *(str(path) for path in self.objects),
                '-Wl,-Map=' + str(self.base / 'ordinary.map'), '-o', str(self.base / 'ordinary.elf')]
            same([row['Argv'] for row in commands if row['Label'] == 'link ordinary'], [self.link_argv], 'exact direct positive link')
            same(self.result['Links'][0]['Path'], str(self.base / 'ordinary.elf'), 'positive ELF authority')
            self.environment = self.native.process_environment(os.environ)
            self.plan = control_plan(artifact, directory, storage)
            self.bits, self.storage = artifact['target']['nvic_priority_bits'], storage
            need(self.bits == (2 if group == 'CM0' else 4), 'profile priority bits')
            watch.read(Path(__file__).resolve())
            for helper in helpers.values():
                path = self.api.checked_path(helper.__file__)
                need(path in watch.hashes, 'helper must already be authenticated')
                watch.read(path, watch.hashes[path])
            denied = watch.denied | {path.parent for path in watch.hashes}
            need(all(not self.output.is_relative_to(path) and not path.is_relative_to(self.output) for path in denied), 'output/input overlap')
            watch.close()
            self.commands, self.expected, self.identities = [], {}, {}
            self._started = self._finished = self._controls_done = False
            self.report = dict(Status='FAIL', Scope=SCOPE, Base=copy.deepcopy(native_bundle['Descriptor']),
                Profile=profile, Mode=mode, Cohort=identity, SourceGroup=group, Linkage='direct', LTO=False,
                SourceInventorySha256=fingerprint, PositiveLinkRevalidated=False, Controls=[], Compilations=[],
                Error=None, PrimaryError=None, ClosingErrors=[], CellContractSatisfied=False, RequiredCellSatisfied=False,
                RequiredCellsSatisfied=0, FullABIProof=False, FullSemanticABIProof=False, PolicyEquivalence=False,
                CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False, OutputSealVerified=False)

        def run_link_controls(self):
            need(self._started and not self._finished and not getattr(self, '_controls_started', False), 'one batch only')
            self._controls_started = True
            _, positive, link_map = self._link('positive', self.objects)
            original = self.watch.read(self.result['Links'][0]['Path'], self.result['Links'][0]['Sha256'])
            reproduced = self.watch.read(positive, self.expected[positive.relative_to(self.output).as_posix()])
            need(original == reproduced, 'same-build positive ELF byte identity')
            self.report.update(PositiveLinkRevalidated=True, PositiveAuthority=dict(Original=self.result['Links'][0]['Path'],
                OriginalSha256=sha(original), Replayed=str(positive), ReplayedSha256=sha(reproduced), Map=str(link_map),
                ElfByteIdentical=True, Scope='SAME_OBJECTS_AND_LINK_FLAGS_RAW_ELF_REPRODUCTION_ONLY'))
            private, alternate = alternate_private(self.watch.read(self.objects[3].with_suffix('.nm')).decode('ascii'), self.bits)
            same(private, self.model['PrivateSymbol'], 'independent original private identity')
            anchor, anchor_import = self._imports(self.objects[4], 'unchanged-boot-v1', 'fiber_internal_runtime_port_abi_')
            need(anchor == ANCHOR, 'unchanged boot requires reverse-v1')
            wanted = (alternate, 'fiber_port_storage_cohort_' + self.storage + '_v999_r0', ANCHOR, 'SVC_Handler', 'PendSV_Handler')
            for spec, expected in zip(self.plan, wanted):
                name, index, added = spec['Name'], spec['Index'], spec['Added']
                record = dict(Name=name, Status='FAIL', Expected=expected, ProviderIndex=index if added is None else 9,
                              ReplacedIndex=index if added is None else None, RequiredCellsSatisfied=0, SemanticProof=False)
                self.report['Controls'].append(record)
                self._save('results.json', self.report)
                compiled = self.compile_tuple(index, name=name, mutations=spec['Mutations'], source_bytes=added)
                obj = Path(compiled['Object'])
                self.watch.read(obj, compiled['ObjectSha256'])
                selected = list(self.objects)
                if added is None:
                    selected[index] = obj
                else:
                    selected.append(obj)
                if name in CONTROLS[:2]:
                    prefix = 'fiber_port_context_cohort_' if index == 6 else 'fiber_port_storage_cohort_'
                    imported, evidence = self._imports(obj, name, prefix)
                    need(imported == expected, 'actual controlled import must match independent identity change')
                    record['ImportEvidence'] = evidence
                else:
                    definitions = self._definitions(obj, name)
                    if added is None:
                        changed = [row for row in definitions if row['Name'] == 'fiber_internal_runtime_port_abi_v2_anchor']
                        need(len(changed) == 1 and changed[0]['Kind'] == 'R' and changed[0]['Size'] == 1
                             and ANCHOR not in [row['Name'] for row in definitions], 'only changed state anchor')
                        imports, evidence = self._undefined(obj, name)
                        need(ANCHOR not in imports, 'missing v1 comes from unchanged consumers')
                        record.update(ChangedDefinitions=definitions, ChangedImports=evidence, ImportEvidence=anchor_import)
                    else:
                        matches = [row for row in definitions if row['Name'] == expected]
                        need(len(matches) == 1 and matches[0]['Kind'] == 'T' and matches[0]['Size'] > 0, 'strong added handler')
                        record['AddedDefinition'] = matches[0]
                first = len(self.commands)
                result, elf, partial_map = self._link(name, selected, expected_failure=True)
                if added is None:
                    text = SimpleNamespace(returncode=result.returncode, stdout=utility.diagnostic_text(result.stdout),
                                           stderr=utility.diagnostic_text(result.stderr))
                    need('lto-wrapper' not in text.stderr, 'ordinary diagnostics only')
                    missing = self.facade.classify_unresolved(text, expected, self.tools['ld'])
                    need(missing == expected, 'only intended missing symbol')
                    classification = dict(MissingSymbols=[missing], DiagnosticTextSha256=sha(text.stderr.encode('utf-8')),
                        DiagnosticNormalization='CRLF-TO-LF-ONLY', ClassifierSha256=self.watch.hashes[Path(self.facade.__file__)])
                else:
                    classification = utility.classify_duplicate(result, expected, self.tools['ld'], obj, self.objects[3], compiled['Source'])
                self.verify_objects()
                self.watch.close()
                record.update(Status='INTENDED-LINK-REJECTION-PASS', Compilation=compiled, Classification=classification,
                    LinkCommandIndex=first, FinalImageAbsent=not elf.exists(), PartialMap=str(partial_map) if partial_map.exists() else None,
                    ConsumedObjects=[dict(Index=i, Path=str(path), Sha256=sha(self.watch.read(path))) for i, path in enumerate(selected)])
                self._save('controls/' + name + '.json', record)
                self._save('results.json', self.report)
            self._controls_done = True
            return copy.deepcopy(self.report['Controls'])

        def finish(self, error=None):
            need(not self._finished, 'finish once')
            self._finished = True
            if error is None and not (self._controls_done and self.report['PositiveLinkRevalidated'] is True
                    and [row['Name'] for row in self.report['Controls']] == list(CONTROLS)
                    and all(row['Status'] == 'INTENDED-LINK-REJECTION-PASS' for row in self.report['Controls'])
                    and terminal_success(self.commands) and not self.report['ClosingErrors']):
                error = Rejected('incomplete or failed ordinary control suite')
            if error is not None:
                self._failure(error)
            if not self._started:
                return copy.deepcopy(self.report)
            try:
                self.verify_objects()
                self.watch.close()
                self._verify_outputs()
                self.report.update(Status=PASS if error is None else 'FAIL', OutputSealVerified=True, InputClosureVerified=error is None,
                    ClosingFilesVerified=len(self.watch.hashes), InputHashes={str(p): h for p, h in sorted(self.watch.hashes.items())},
                    InputPhysicalIdentities={str(p): list(v) for p, v in sorted(self.watch.identities.items())}, Commands=self.commands,
                    CommandsSha256=self.expected['commands.json'], IntendedLinkRejects=sum(
                        row['Status'] == 'INTENDED-LINK-REJECTION-PASS' for row in self.report['Controls']))
                self._save('results.json', self.report)
                manifest = {name: digest for name, digest in self.expected.items() if name != 'artifacts.json'}
                self._save('artifacts.json', dict(Artifacts=manifest))
                self.watch.close()
                self._verify_outputs()
                same(self.api.structured((self.output / 'artifacts.json').read_bytes()), dict(Artifacts=manifest), 'written manifest semantics')
            except BaseException as failure:
                self._failure(failure)
                try:
                    self._save('results.json', self.report)
                    actual = self.api.files_under(self.output)
                    self._write('artifacts.json', encoded(dict(Artifacts={name: sha(path.read_bytes())
                        for name, path in actual.items() if name != 'artifacts.json'})))
                except BaseException as closing:
                    self._failure(closing)
            return copy.deepcopy(self.report)

    return Suite
