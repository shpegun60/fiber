"""Independently replay the fixed CM3 LTO policy-cohort capture, offline."""
import argparse
import importlib.abc
import importlib.util
import math
from pathlib import Path
from types import SimpleNamespace
import sys
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
CONTROLS = HERE.with_name('cm3_lto_cohort_controls')
UTILITY = HERE.with_name('cm3_lto_transport') / 'probe.py'
UTILITY_SHA = 'F2D4CA9F1FC1F7FAE07F275913F7DFC688BFD8570AEE32DE2144EE1EA187F626'
PARENT = HERE.with_name('cm3_lto_link_contract') / 'witness.py'
PARENT_SHA = '599D384B53F45093F01949A4E95A9DF8A15BC4EABE9EA5E12A1C2E7138F3297E'
ENGINE = HERE.with_name('cm3_lto_link_controls') / 'probe.py'
PINS = {
    ENGINE: 'CE2C86F8FB1A391977ED385636108CC24307F495D22FAE495FBD2B449DA9F99F',
    CONTROLS / 'probe.py': 'E3FD2717BF7524EE433578E18903748932B8F602A79B7C6FD9B7E34105F9CC8F',
    CONTROLS / 'identity.py': '360485D634AC85AF37B78AAB45E622E568063CDE32F45250037F4C718F13732B',
    HERE.with_name('cm3_lto_link_contract') / 'audit.py': '9D6B4E1694A8C0A2D7F2E1C7B6D108B58B103131DD7C19D45CD08238E4CED759',
}
ROLES = ((3, 'runtime'), (4, 'boot'), (5, 'exception'), (6, 'expectation'))


def sha(data):
    import hashlib
    return hashlib.sha256(data).hexdigest().upper()


def need(ok, label):
    if not ok:
        raise ValueError('cm3-lto-cohort-witness: ' + label)


def load(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def admit(args):
    data = UTILITY.read_bytes()
    need(sha(data) == UTILITY_SHA, 'fixed capture utility')
    api = load('cm3_policy_capture_utility', UTILITY, data)
    watch = api.Closure()
    root = api.checked_path(args.controls_build)
    result = watch.structured(root / 'results.json', api.digest_text(args.controls_receipt_sha256))
    artifacts = watch.structured(root / 'artifacts.json', api.digest_text(args.controls_artifacts_sha256))['Artifacts']
    need(type(artifacts) is dict and artifacts.get('results.json') == args.controls_receipt_sha256,
         'caller-bound capture receipt/manifest')
    watch.tree(root, dict(artifacts, **{'artifacts.json': args.controls_artifacts_sha256}))
    api.same([result.get(key) for key in ('Status', 'Scope', 'Profile', 'Mode', 'Linkage', 'OriginalTranslationUnits',
        'OriginalSlimIRObjects', 'PositiveTranslationUnits', 'PositiveSlimIRObjects', 'PositiveStartupObjects',
        'RecompiledTranslationUnits', 'Thresholds')],
        ['CM3-LTO-COHORT-CONTROL-CAPTURE-PASS-NOT-QUALIFIED', 'CM3_O2_LTO_POLICY_COHORT_CONTROL_CAPTURE_ONLY',
         'CM3', 'O2-lto', 'direct', 9, 8, 9, 8, 1, 4, [16, 32]], 'exact capture cohort and scope')
    for key in ('CompleteLinkControlsQualified', 'PolicyCohortControlsQualified', 'StorageMismatchProven',
                'RuntimeABIVersionMismatchProven', 'FinalLinkContractValidated', 'FinalRootRelocationProof',
                'FinalReferenceParity', 'FullABIProof', 'SourceIRProof', 'SourceToMachineSemanticProof',
                'OriginalTranslationUnitOwnership', 'CanonicalProtocolValidated', 'InstructionEquivalence',
                'PolicyEquivalence', 'CompleteObjectProof', 'ArchiveExtraction', 'KernelRuntimeProof',
                'Qualification', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified', 'RequiredCellSatisfied'):
        need(result.get(key) is False, 'literal capture nonclaim: ' + key)
    need(type(result.get('RequiredCellsSatisfied')) is int and result['RequiredCellsSatisfied'] == 0,
         'zero capture credit')
    need(result.get('InputClosureVerified') is True and type(result.get('InputHashes')) is dict and result['InputHashes'],
         'complete capture input bindings')
    for path, value in result['InputHashes'].items():
        watch.read(path, api.digest_text(value))
    watch.close()
    return api, watch, root, result, artifacts


def witness_type():
    data = PARENT.read_bytes()
    need(sha(data) == PARENT_SHA, 'fixed native admission and sealing')
    parent = load('cm3_policy_parent_envelope', PARENT, data)

    class Witness(parent.Witness):
        def __init__(self, args, admitted):
            api, watch, root, result, artifacts = admitted
            super().__init__(SimpleNamespace(capture_build=result['CaptureBuild'],
                capture_receipt_sha256=result['CaptureReceiptSha256'],
                capture_artifacts_sha256=result['CaptureArtifactsSha256'], output_dir=args.output_dir))
            self.controls, self.capture, self.native = root, result, self.authority.result
            for path, value in watch.hashes.items():
                self.watch.read(path, value)
            self.watch.tree(root, dict(artifacts, **{'artifacts.json': args.controls_artifacts_sha256}))
            denied = {REPO, root, *(path.parent for path in self.watch.hashes)}
            need(all(not self.output.is_relative_to(path) and not path.is_relative_to(self.output) for path in denied),
                 'fresh output outside all newly admitted input roots')
            captured = dict(self.buffers)
            for path in (ENGINE, CONTROLS / 'probe.py', CONTROLS / 'identity.py'):
                captured[path] = self.watch.read(path, PINS[path])
            expected = []
            for index, (path, data) in enumerate(sorted(captured.items())):
                copied = root / ('input-sources/%04d-%s' % (index, path.name))
                need(self.watch.read(copied, sha(data)) == data, 'fresh captured source bytes')
                expected.append(dict(Original=str(path), Sha256=sha(data), Captured=str(copied)))
            api.same(result['CapturedSources'], expected, 'complete ordered captured source bindings')
            for path, expected in PINS.items():
                self.buffers[path] = self.watch.read(path, expected)
            for path in (Path(__file__).resolve(), HERE / 'audit.py', HERE / 'resolution.py'):
                self.buffers[path] = self.watch.read(path)
            self._validate_records()
            self.identities = {path: self.identity(path) for path in self.watch.hashes}
            self.report.update(Scope='NATIVE_CM3_O2_LTO_PRIVATE_POLICY_COHORT_LINK_COMPOSITION_ONLY',
                ControlsBuild=str(root), ControlsReceiptSha256=args.controls_receipt_sha256,
                ControlsArtifactsSha256=args.controls_artifacts_sha256, PolicyCohortMismatchLinkProof=False,
                StorageMismatchProven=False, RuntimeABIVersionMismatchProven=False,
                FinalLinkContractValidated=False, FinalRootRelocationProof=False, CanonicalProtocolValidated=False)
            self.close()

        def _inspections(self, obj):
            tools, plugin = Path(self.native['CapturedCompiler']).parent, self.native['LTOPlugin']['Path']
            return [('inspect ' + obj.name + suffix, [str(tools / ('arm-none-eabi-' + name + '.exe')), *flags, str(obj)],
                str(self.controls), False) for name, flags, suffix in (
                    ('readelf', ['-hSWsrA', '-lW'], '.readelf'), ('objdump', ['-drwC', '-Mreg-names-std'], '.dis'),
                    ('nm', ['--plugin', plugin, '-P', '-S', '--defined-only'], '.nm'))]

        def _validate_records(self):
            r, root, api = self.capture, self.controls, self.api
            base = [Path(row['Object']) for row in self.native['Sources']]
            self.variants = {16: list(base), 32: list(base)}
            gcc, seed = self.native['CapturedCompiler'], Path(self.native['SeedBuild'])
            script = seed / 'source/tools/fixtures/classic_final_image/link.ld'
            dependency_source = seed / 'source/tools/fixtures/classic_final_image/run.py'
            need(sha(self.buffers[dependency_source]) == 'FBCBA0C4FF480E139ADE401ECFA90822E9EA01A6AB554CEF157036EC9DE7F014',
                 'fixed actual dependency parser')
            parser = load('cm3_policy_dependency_grammar', dependency_source, self.buffers[dependency_source])
            identity = load('cm3_policy_identity_admission', CONTROLS / 'identity.py', self.buffers[CONTROLS / 'identity.py'])
            wanted = []
            need(type(r['AddedSources']) is list and len(r['AddedSources']) == 4, 'four recompiled providers')
            for row, (index, role) in zip(r['AddedSources'], ROLES):
                original = self.native['Sources'][index]
                source = Path(original['Source'])
                copied = root / ('recompiled-sources/%02d-%s' % (index, source.name))
                obj = root / ('objects32/%02d-%s.o' % (index, source.stem))
                dep = obj.with_suffix('.d')
                flags = list(original['CompileFlags'])
                need([f for f in flags if 'FIBER_SCHEDULER_BASEPRI' in f] == ['-DFIBER_SCHEDULER_BASEPRI=16']
                     and not any('FIBER_PORT_SCHEDULER_BASEPRI' in f for f in flags), 'one admitted policy definition')
                flags = ['-DFIBER_SCHEDULER_BASEPRI=32' if f == '-DFIBER_SCHEDULER_BASEPRI=16' else f for f in flags]
                api.same([row[key] for key in ('SourceIndex', 'Role', 'Source', 'Original', 'CapturedSource',
                    'SourceSha256', 'Object', 'CompileFlags', 'OriginalCompileFlags', 'OriginalBasepri', 'Basepri',
                    'SlimIR', 'CompileDependenciesVerified', 'DependencyFile')],
                    [index, role, str(source), str(source), str(copied), original['SourceSha256'], str(obj), flags,
                     original['CompileFlags'], 16, 32, True, True, str(dep)], 'exact source/recipe/role binding')
                need(self.watch.read(copied, original['SourceSha256']) == self.watch.read(source, original['SourceSha256']),
                     'recompiled original/copy source equality')
                self.api.require_elf32le(self.watch.read(obj, row['ObjectSha256']))
                sections = self.api.section_records(self.watch.read(Path(str(obj) + '.readelf')).decode('ascii'))
                self.api.same(row['Sections'], sections, 'actual recompiled IR section metadata')
                need(any(s['Name'].startswith('.gnu.lto_') for s in sections)
                     and not any(s['Size'] and 'X' in s['Flags'] for s in sections), 'actual slim IR without machine fallback')
                self.variants[32][index] = obj
                api.same(row['ActualCompileDependencies'], original['ActualCompileDependencies'], 'unchanged dependency facts')
                raw_dependency = self.watch.read(dep)
                def dependency_text(path, encoding=None, **kwargs):
                    need(Path(path) == dep and encoding == 'utf-8' and not kwargs, 'only immutable raw dependency input')
                    return raw_dependency.decode('utf-8')
                with patch.object(Path, 'read_text', dependency_text):
                    paths = parser.read_dependencies(dep)
                api.same([str(p) for p in paths], [p['Path'] for p in row['ActualCompileDependencies']], 'actual raw dependency membership')
                wanted.append(('compile policy32 ' + role, [gcc, *flags, '-MD', '-MF', str(dep), '-MT',
                    'pilot-source-' + str(index), '-c', str(source), '-o', str(obj)], str(root), False))
                wanted.extend(self._inspections(obj))
            pair = identity.cohort_pair(self.watch.read(Path(str(base[3]) + '.nm')).decode('ascii'),
                self.watch.read(Path(str(self.variants[32][3]) + '.nm')).decode('ascii'))
            api.same(r['CohortIdentities'], pair, 'actual complete IR cohort definitions')
            api.same(r['IdentityInputs'], [dict(Basepri=value, Path=str(path), Sha256=self.watch.hashes[path])
                for value, path in ((16, Path(str(base[3]) + '.nm')), (32, Path(str(self.variants[32][3]) + '.nm')))],
                'complete IR symbol input bindings')
            self.report['IRIdentityPair'] = pair
            api.same(r['Variants'], [dict(Basepri=value, Objects=[dict(SourceIndex=i, Path=str(path),
                Sha256=self.watch.hashes[path]) for i, path in enumerate(self.variants[value])]) for value in (16, 32)],
                'complete policy-specific ordered object identities')
            expected_pairs = [(value, kind) for value in (16, 32) for kind in ('ordinary', 'emit-relocs')]
            api.same([(row['Basepri'], row['Kind']) for row in r['Links']], expected_pairs, 'four ordered own-machine links')
            for link in r['Links']:
                value, kind = link['Basepri'], link['Kind']
                image = root / ('positive-%d' % value) / kind / 'image.elf'
                map_path, machine, resolution = image.with_suffix('.map'), Path(str(image) + '.ltrans0.ltrans.o'), Path(str(image) + '.res')
                flags = api.link_flags(dict(compile_flags=list(api.TARGET_FLAGS)), self.variants[value], script, image, map_path,
                    kind == 'emit-relocs')
                wanted.append(('link cohort%d %s' % (value, kind), [gcc, *flags], str(image.parent), False))
                api.same([link[key] for key in ('Path', 'Machine', 'Map', 'Resolution', 'Objects', 'VerboseTrace',
                    'TranslationUnits', 'SlimIRObjects', 'StartupObjects')], [str(image), str(machine), str(map_path),
                    str(resolution), [str(p) for p in self.variants[value]], True, 9, 8, 1], 'exact positive roles/providers')
                for path, key in ((image, 'Sha256'), (machine, 'MachineSha256'), (map_path, 'MapSha256'), (resolution, 'ResolutionSha256')):
                    self.watch.read(path, link[key])
                wanted.extend(self._inspections(machine))
                wanted.extend(self._inspections(image))
            need(type(r['NegativeControls']) is list and len(r['NegativeControls']) == 8, 'all eight isolated negatives')
            self.negative_proof = []
            for record, (value, index, role) in zip(r['NegativeControls'], [(v, i, n) for v in (16, 32) for i, n in ROLES]):
                foreign = 32 if value == 16 else 16
                name = 'base%d-swap-%s-to%d' % (value, role, foreign)
                objects = list(self.variants[value])
                objects[index] = self.variants[foreign][index]
                expected_symbol = pair['Private%d' % (value if index == 3 else foreign)]
                image = root / ('negative-' + name) / 'image.elf'
                full_flags = api.link_flags(dict(compile_flags=list(api.TARGET_FLAGS)), objects, script, image, image.with_suffix('.map'), False)
                flags = [f for f in full_flags if f != '-v']
                label = 'link intended cohort mismatch ' + name
                wanted.append((label, [gcc, *flags], str(image.parent), True))
                command_index = len(wanted) - 1
                api.same([record[key] for key in ('Name', 'Basepri', 'SwappedSourceIndex', 'SwappedRole', 'ForeignBasepri',
                    'ExpectedMissingSymbol', 'Status', 'CommandIndex', 'CommandStatus', 'Exit', 'Objects', 'TranslationUnits',
                    'SlimIRObjects', 'StartupObjects', 'VerboseTrace', 'RemovedLinkFlags', 'FullVerboseLinkFlags', 'LinkFlags',
                    'FinalImageAbsent')], [name, value, index, role, foreign, expected_symbol, 'PASS', command_index, 'FAIL', 1,
                    [str(p) for p in objects], 9, 8, 1, False, ['-v'], full_flags, flags, True], 'exact isolated missing-key control')
                stderr = root / ('command-%04d.stderr' % command_index)
                diagnostic = identity.require_mismatch(self.watch.read(stderr, record['DiagnosticSha256']).decode('ascii'), expected_symbol)
                api.same(record['Diagnostic'], diagnostic, 'complete raw intended diagnostic')
                need(not image.exists() and self.watch.read(stderr.with_suffix('.stdout')) == b'', 'no failed final or unexpected stdout')
                self.negative_proof.append(dict(Name=name, Basepri=value, SwappedSourceIndex=index, SwappedRole=role,
                    ForeignBasepri=foreign, ExpectedMissingSymbol=expected_symbol, CommandIndex=command_index,
                    DiagnosticSha256=self.watch.hashes[stderr], Diagnostic=diagnostic))
            commands = r['Commands']
            need(type(commands) is list and len(commands) == len(wanted) == 52, 'complete ordered command catalog')
            for index, (row, (label, argv, cwd, failed)) in enumerate(zip(commands, wanted)):
                api.same([row[key] for key in ('Label', 'Argv', 'Cwd', 'Status', 'Exit', 'TimedOut', 'Error')],
                    [label, argv, cwd, 'FAIL' if failed else 'PASS', 1 if failed else 0, False,
                     'ValueError: cm3-lto-probe: command failed/timeout: ' + label if failed else None], 'exact executed command')
                need(type(row.get('Seconds')) in (int, float) and math.isfinite(row['Seconds']) and row['Seconds'] >= 0,
                     'finite actual command duration')
                command = root / ('command-%04d.json' % index)
                api.same(self.watch.structured(command), row, 'raw command JSON binding')
                for suffix in ('.stdout', '.stderr'):
                    need(command.with_suffix(suffix) in self.watch.hashes, 'complete bound command streams')
                if label.startswith('inspect '):
                    suffixes = [s for s in ('.readelf', '.dis', '.nm') if label.endswith(s)]
                    need(len(suffixes) == 1 and self.watch.read(Path(str(argv[-1]) + suffixes[0]))
                         == self.watch.read(command.with_suffix('.stdout')), 'inspection sidecar/stdout equality')
            api.same(self.watch.structured(root / 'commands.json'), commands, 'complete catalog binding')
            environment = self.watch.structured(Path(r['CaptureBuild']) / 'environment.json')
            environment.update(TEMP=str(root / 'tmp'), TMP=str(root / 'tmp'))
            api.same(self.watch.structured(root / 'environment.json'), environment, 'actual sanitized environment')

        def audit(self):
            loader = load('cm3_policy_immutable_loader', self.base.LOADER, self.buffers[self.base.LOADER])
            graph = loader.FrozenSources(self.buffers)
            package = Path(self.native['SeedBuild']) / 'python/elftools'
            modules = {}
            for path in self.buffers:
                if path.is_relative_to(package):
                    parts = list(path.relative_to(package.parent).with_suffix('').parts)
                    is_package = parts[-1] == '__init__'
                    if is_package:
                        parts.pop()
                    modules['.'.join(parts)] = path, is_package
            need('elftools' in modules and not any(n == 'elftools' or n.startswith('elftools.') for n in sys.modules),
                 'closed initially unimported parser package')
            class Finder(importlib.abc.MetaPathFinder):
                def find_spec(inner, fullname, path=None, target=None):
                    if fullname != 'elftools' and not fullname.startswith('elftools.'):
                        return None
                    need(fullname in modules and target is None, 'unknown parser module')
                    source, is_package = modules[fullname]
                    spec = graph.spec(fullname, source)
                    if is_package:
                        spec.submodule_search_locations = [str(source.parent)]
                    return spec
            self.report['Sources'] = [dict(Original=str(path), Sha256=sha(data),
                Captured=str(self.copy('source-buffers/%04d-%s' % (i, path.name), data)))
                for i, (path, data) in enumerate(sorted(self.buffers.items()))]
            snapshots = {self.base.stable_path(path): data for path, data in self.buffers.items()}
            roles_by_key, self.report['BinaryInputs'] = {}, []
            startup = Path(self.native['Sources'][8]['Object'])
            physical = []
            for link in self.capture['Links']:
                key, final, machine = (link['Basepri'], link['Kind']), Path(link['Path']), Path(link['Machine'])
                roles = dict(Machine=machine, Final=final, Disassembly=Path(str(final) + '.dis'), LinkMap=Path(link['Map']),
                    Startup=startup, Attributes=Path(str(final) + '.readelf'), MachineAttributes=Path(str(machine) + '.readelf'),
                    Resolution=Path(link['Resolution']))
                for role, path in roles.items():
                    for previous_role, previous_path in physical:
                        need(path.samefile(previous_path) is (role == previous_role == 'Startup'), 'only startup may physically share across roles')
                    physical.append((role, path))
                    need(path in self.watch.hashes, 'authenticated binary role')
                    data = self.watch.read(path)
                    stable = self.base.stable_path(path)
                    need(stable not in snapshots or snapshots[stable] == data, 'shared binary role conflict')
                    snapshots[stable] = data
                    captured = self.copy('binary-inputs/%d-%s/%s%s' % (*key, role, path.suffix), data)
                    self.report['BinaryInputs'].append(dict(Basepri=key[0], Kind=key[1], Role=role, Original=str(path),
                        Captured=str(captured), Sha256=sha(data)))
                roles_by_key[key] = roles
            def read_bytes(path):
                stable = self.base.stable_path(path)
                need(stable in snapshots, 'unknown immutable reader input')
                return snapshots[stable]
            def read_text(path, encoding=None, errors=None, newline=None):
                need(newline is None and encoding in (None, 'ascii', 'utf-8') and errors in (None, 'strict'), 'exact text decoding')
                return read_bytes(path).decode(encoding or 'utf-8', errors or 'strict')
            previous_meta = list(sys.meta_path)
            try:
                sys.meta_path.insert(0, Finder())
                with graph.active(), patch.object(Path, 'read_bytes', read_bytes), patch.object(Path, 'read_text', read_text):
                    core = graph.load('cm3_policy_core', self.authority.core_path)
                    frozen = graph.load('cm3_policy_frozen_link_audit', HERE.with_name('cm3_lto_link_contract') / 'audit.py')
                    identity = graph.load('cm3_policy_identity', CONTROLS / 'identity.py')
                    audit = graph.load('cm3_policy_link_audit', HERE / 'audit.py')
                    resolution = graph.load('cm3_policy_resolution', HERE / 'resolution.py')
                    proofs = []
                    for (value, kind), roles in roles_by_key.items():
                        image = core.FinalImage(roles['Machine'], roles['Final'], roles['Disassembly'],
                            provider_objects={str(roles['Machine']): roles['Machine'], str(startup): startup},
                            link_map=roles['LinkMap'], float_abi='soft')
                        proof = audit.audit(image, read_text(roles['Attributes'], 'ascii'), basepri=value,
                            emit_relocs=kind == 'emit-relocs', machine_attributes_text=read_text(roles['MachineAttributes'], 'ascii'),
                            frozen_audit=frozen, identity=identity)
                        rows = resolution.parse(read_text(roles['Resolution'], 'ascii'), [str(p) for p in self.variants[value][:8]],
                            private=identity.PRIVATE16 if value == 16 else identity.PRIVATE32, storage=identity.STORAGE)
                        proofs.append(dict(Basepri=value, Kind=kind, LinkContract=proof, Resolution=rows))
                    twins = {str(value): core.compare_load_images(roles_by_key[value, 'ordinary']['Final'],
                        roles_by_key[value, 'emit-relocs']['Final']) for value in (16, 32)}
                self.report.update(Links=proofs, Twins=twins, ExecutedSourceBuffers=graph.executed,
                    NegativeControls=self.negative_proof, PolicyCohortMismatchLinkProof=True, FinalLinkContractValidated=True)
            finally:
                sys.meta_path[:] = previous_meta

        def run(self):
            self.output.mkdir(parents=True)
            try:
                self.audit()
                self.close()
                self.report.update(Status='CM3-LTO-POLICY-COHORT-LINK-PASS-NOT-FULL-ABI-QUALIFIED', InputClosureVerified=True,
                    ClosingFilesVerified=len(self.watch.hashes), InputHashes={str(p): h for p, h in sorted(self.watch.hashes.items())},
                    InputPhysicalIdentities={str(p): h for p, h in sorted(self.identities.items())})
                self.seal()
            except BaseException as error:
                self.report.update(Status='FAIL', Error=type(error).__name__ + ': ' + str(error), InputClosureVerified=False,
                    PolicyCohortMismatchLinkProof=False, FinalLinkContractValidated=False)
                try:
                    self.seal()
                except BaseException as closing:
                    self.report.update(OutputSealVerified=False, SealError=str(closing))
                    self.api.save(self.output / 'results.json', self.report)
                    self.api.save(self.output / 'artifacts.json', dict(Artifacts={name: sha(path.read_bytes())
                        for name, path in self.api.files_under(self.output).items() if name != 'artifacts.json'}))
            return self.report['Status'] != 'FAIL'
    return Witness


def main(argv=None):
    need(not sys.flags.optimize, 'unoptimized interpreter required')
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('controls-build', 'controls-receipt-sha256', 'controls-artifacts-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    admitted = admit(args)
    witness = witness_type()(args, admitted)
    passed = witness.run()
    print(witness.report['Status'], witness.report.get('Error') or '', str(witness.output))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
