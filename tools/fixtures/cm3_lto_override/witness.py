"""Recompose the fresh CM3 LTO override cohort; never execute a toolchain."""
import argparse
import hashlib
import importlib.abc
import importlib.util
import math
from pathlib import Path
import re
from types import SimpleNamespace
import sys
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
UTILITY = REPO / 'tools/fixtures/cm3_lto_transport/probe.py'
UTILITY_SHA = 'F2D4CA9F1FC1F7FAE07F275913F7DFC688BFD8570AEE32DE2144EE1EA187F626'
PARENT = HERE.with_name('cm3_lto_link_contract') / 'witness.py'
PARENT_SHA = '599D384B53F45093F01949A4E95A9DF8A15BC4EABE9EA5E12A1C2E7138F3297E'
CONTROLS = HERE.with_name('cm3_lto_link_controls')
FIXTURES = ('panic_override.c', 'duplicate_svc.c', 'duplicate_pendsv.c')
PINS = {
    CONTROLS / 'probe.py': 'CE2C86F8FB1A391977ED385636108CC24307F495D22FAE495FBD2B449DA9F99F',
    CONTROLS / 'resolution.py': '9EEFBB859BF703950FEF7CD1507CDE79942AE671648B5A5D73AB77C2016BD62A',
    CONTROLS / 'panic_override.c': '4A47E0E59115F70B283AAFB39E1286330D931C592C63DBEDB6B067946E73F0E5',
    CONTROLS / 'duplicate_svc.c': 'FD294BC5A7E458B7A463725AA2F00A2E2CD74C7C6ADF4B199412768326B87E14',
    CONTROLS / 'duplicate_pendsv.c': 'E0B70C157F5D52C132B98B6DF5BB76150BBF759B932B0A2AF0BABB52BFB466E0',
    HERE.with_name('cm3_lto_link_contract') / 'audit.py': '9D6B4E1694A8C0A2D7F2E1C7B6D108B58B103131DD7C19D45CD08238E4CED759',
    HERE.with_name('cm3_lto_roots') / 'native.py': 'D4BA0378FA50E11A570D40180149794B16EB0807E36DC902C19840E32D1AF05D',
    HERE.with_name('cm3_lto_protocol') / 'protocol.py': 'BA3B630BB1FEA67C81D2EE18C84F6D2A47DE9802E8763F52EE55DB34CD65F419',
}
DECODER_SHA = '394BA0549C2325BC5BB988EB1A6EBA89263CAF3E351189582931C59A64D5752D'
CHECKER_SHA = 'F0D9CD4F48912FB6E5455AA365BF73FFCF356BAFAD922B3A73ACA992A616A11A'


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def need(ok, label):
    if not ok:
        raise ValueError('cm3-lto-override-witness: ' + label)


def load(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def admit(args):
    data = UTILITY.read_bytes()
    need(sha(data) == UTILITY_SHA, 'fixed capture utility')
    api = load('cm3_override_capture_utility', UTILITY, data)
    watch = api.Closure()
    root = api.checked_path(args.controls_build)
    result = watch.structured(root / 'results.json', api.digest_text(args.controls_receipt_sha256))
    artifacts = watch.structured(root / 'artifacts.json', api.digest_text(args.controls_artifacts_sha256))['Artifacts']
    need(type(artifacts) is dict and artifacts.get('results.json') == args.controls_receipt_sha256, 'caller-bound capture seal')
    watch.tree(root, dict(artifacts, **{'artifacts.json': args.controls_artifacts_sha256}))
    api.same([result.get(key) for key in ('Status', 'Scope', 'Profile', 'Mode', 'Linkage', 'OriginalTranslationUnits',
        'OriginalSlimIRObjects', 'PositiveTranslationUnits', 'PositiveSlimIRObjects', 'PositiveStartupObjects')],
        ['CM3-LTO-FRESH-LINK-CAPTURE-PASS-NOT-QUALIFIED', 'CM3_O2_LTO_FRESH_LINK_CONTROL_CAPTURE_ONLY',
         'CM3', 'O2-lto', 'direct', 9, 8, 10, 9, 1], 'exact fresh-capture scope')
    need(result.get('InputClosureVerified') is True and type(result.get('InputHashes')) is dict and result['InputHashes'],
         'complete capture input bindings')
    for key in ('CompleteLinkControlsQualified', 'PanicOverrideQualified', 'DuplicateHandlerControlsQualified',
                'FinalLinkContractValidated', 'FinalRootRelocationProof', 'FinalReferenceParity', 'FullABIProof',
                'SourceToMachineSemanticProof', 'ArchiveExtraction', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified'):
        need(result.get(key) is False, 'literal capture nonclaim: ' + key)
    need(type(result.get('RequiredCellsSatisfied')) is int and result['RequiredCellsSatisfied'] == 0, 'zero capture credit')
    for path, value in result['InputHashes'].items():
        watch.read(path, api.digest_text(value))
    watch.close()
    return api, watch, root, result, artifacts


def witness_type():
    data = PARENT.read_bytes()
    need(sha(data) == PARENT_SHA, 'fixed full native admission and sealing implementation')
    parent = load('cm3_override_parent_envelope', PARENT, data)

    class Witness(parent.Witness):
        def __init__(self, args, admitted):
            api, controls_watch, root, result, artifacts = admitted
            native_args = SimpleNamespace(capture_build=result['CaptureBuild'],
                capture_receipt_sha256=result['CaptureReceiptSha256'],
                capture_artifacts_sha256=result['CaptureArtifactsSha256'], output_dir=args.output_dir)
            super().__init__(native_args)
            self.controls, self.capture, self.control_artifacts = root, result, artifacts
            self.native_capture = self.authority.result
            for path, value in controls_watch.hashes.items():
                self.watch.read(path, value)
            self.watch.tree(root, dict(artifacts, **{'artifacts.json': args.controls_artifacts_sha256}))
            denied = {REPO, root, *(path.parent for path in self.watch.hashes)}
            need(all(not self.output.is_relative_to(path) and not path.is_relative_to(self.output) for path in denied),
                 'fresh output outside all newly admitted input roots')
            captured_sources = dict(self.buffers)
            for path in (CONTROLS / 'probe.py', *(CONTROLS / name for name in FIXTURES)):
                captured_sources[path] = self.watch.read(path, PINS[path])
            expected_sources = []
            for i, (path, data) in enumerate(sorted(captured_sources.items())):
                copied = root / ('input-sources/%04d-%s' % (i, path.name))
                need(self.watch.read(copied, sha(data)) == data, 'exact fresh captured source bytes')
                expected_sources.append(dict(Original=str(path), Sha256=sha(data), Captured=str(copied)))
            self.api.same(result['CapturedSources'], expected_sources, 'complete ordered fresh captured source bindings')
            for path, expected in PINS.items():
                data = self.watch.read(path, expected)
                if path.suffix == '.py':
                    self.buffers[path] = data
            for path in (Path(__file__).resolve(), HERE / 'calls.py'):
                self.buffers[path] = self.watch.read(path)
            seed = Path(self.native_capture['SeedBuild'])
            self.decoder = seed / 'source/tools/fixtures/cm55_tfm_parity/elf.py'
            self.checker = seed / 'source/tools/fixtures/cm3_freeze_parity/check.py'
            need(sha(self.buffers[self.decoder]) == DECODER_SHA and sha(self.buffers[self.checker]) == CHECKER_SHA,
                 'unchanged captured decoder/checker')
            self._validate_records()
            self.identities = {path: self.identity(path) for path in self.watch.hashes}
            self.report.update(Scope='CM3_O2_LTO_STRONG_OVERRIDE_LINK_AND_NATIVE_ROOT_COMPOSITION_ONLY',
                ControlsBuild=str(root), ControlsReceiptSha256=args.controls_receipt_sha256,
                ControlsArtifactsSha256=args.controls_artifacts_sha256, PanicOverrideProof=False,
                DuplicateHandlerLinkProof=False, FullABIProof=False)
            self.close()

        def _validate_records(self):
            r, native = self.capture, self.native_capture
            api, root = self.api, self.controls
            added = r['AddedSources']
            need(type(added) is list and len(added) == 3, 'three fixed added source providers')
            base = [Path(row['Object']) for row in native['Sources']]
            gcc = native['CapturedCompiler']
            script = Path(native['SeedBuild']) / 'source/tools/fixtures/classic_final_image/link.ld'
            flags = native['Sources'][7]['CompileFlags']
            dependency_source = Path(native['SeedBuild']) / 'source/tools/fixtures/classic_final_image/run.py'
            need(sha(self.buffers[dependency_source]) == 'FBCBA0C4FF480E139ADE401ECFA90822E9EA01A6AB554CEF157036EC9DE7F014',
                 'fixed actual dependency grammar')
            dependency_parser = load('cm3_override_dependency_grammar', dependency_source, self.buffers[dependency_source])
            self.report['AdmissionSourceBuffers'] = [dict(Path=str(dependency_source), Sha256=sha(self.buffers[dependency_source]))]
            wanted = []
            for i, name in enumerate(FIXTURES):
                row = added[i]
                source, obj = root / 'added-sources' / name, root / 'objects' / (Path(name).stem + '.o')
                need(row['Original'] == str(CONTROLS / name) and row['Source'] == str(source)
                     and row['Object'] == str(obj) and row['SlimIR'] is True, 'fixed added source/object roles')
                need(row['SourceSha256'] == PINS[CONTROLS / name], 'fixed added source bytes')
                self.watch.read(source, row['SourceSha256'])
                self.watch.read(obj, row['ObjectSha256'])
                api.same(row['CompileFlags'], flags, 'exact inherited compile recipe')
                dep = obj.with_suffix('.d')
                need(row['DependencyFile'] == str(dep), 'fixed actual dependency record')
                wanted.append(('compile ' + name, [gcc, *flags, '-MD', '-MF', str(dep), '-MT',
                    'pilot-source-' + str(i), '-c', str(source), '-o', str(obj)], str(root), False))
                wanted.extend(self._inspection_commands(obj))
                dependencies = row['ActualCompileDependencies']
                need(type(dependencies) is list and dependencies and len({x['Path'] for x in dependencies}) == len(dependencies)
                     and str(source) in {x['Path'] for x in dependencies}, 'complete unique actual added dependencies')
                for dep_row in dependencies:
                    need(Path(dep_row['Path']) in self.watch.hashes and self.watch.hashes[Path(dep_row['Path'])] == dep_row['Sha256'],
                         'actual dependency/input authority binding')
                raw_dependency = self.watch.read(dep)
                def dependency_text(path, encoding=None, **kwargs):
                    need(Path(path) == dep and encoding == 'utf-8' and not kwargs, 'only immutable raw dependency input')
                    return raw_dependency.decode('utf-8')
                with patch.object(Path, 'read_text', dependency_text):
                    actual_dependencies = dependency_parser.read_dependencies(dep)
                api.same([x['Path'] for x in dependencies], [str(path) for path in actual_dependencies],
                         'raw actual dependency membership')
                nm = self.watch.read(Path(str(obj) + '.nm')).decode('ascii')
                wanted_nm = ([('cm3_lto_panic_override_code', 'B'), ('fiber_panic', 'T')] if i == 0
                             else [('SVC_Handler' if i == 1 else 'PendSV_Handler', 'T')])
                parsed_nm = []
                for line in nm.splitlines():
                    match = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*) ([A-Za-z]) 0\s*', line)
                    need(match is not None, 'fixed plugin-aware added-IR symbol metadata')
                    parsed_nm.append(match.groups())
                api.same(parsed_nm, wanted_nm, 'actual strong added-IR definitions')
            self.providers = [str(path) for path in base[:8]] + [added[0]['Object']]
            need(re.fullmatch(r'fiber_panic W 0\s*', self.watch.read(Path(str(base[2]) + '.nm')).decode('ascii')) is not None,
                 'bundled fallback remains actual weak IR definition')
            native_nm = self.watch.read(Path(str(base[3]) + '.nm')).decode('ascii')
            for symbol in ('SVC_Handler', 'PendSV_Handler'):
                need(len(re.findall(r'(?m)^' + re.escape(symbol) + r' T 0[ \t]*\r?$', native_nm)) == 1,
                     'original strong handler IR provider retained')
            objects = [*base[:8], Path(added[0]['Object']), base[8]]
            need([row['Kind'] for row in r['Links']] == ['ordinary', 'emit-relocs'], 'ordered genuine twins')
            for link in r['Links']:
                kind = link['Kind']
                image, map_path = root / kind / 'image.elf', root / kind / 'image.map'
                expected_flags = api.link_flags(dict(compile_flags=list(api.TARGET_FLAGS)), objects, script, image, map_path,
                                                kind == 'emit-relocs')
                wanted.append(('link override ' + kind, [gcc, *expected_flags], str(image.parent), False))
                machine = api.require_saved_machine_name(link['Machine'], image)
                need(machine == image.parent / 'image.elf.ltrans0.ltrans.o' and link['Path'] == str(image)
                     and link['Map'] == str(map_path) and link['Resolution'] == str(image) + '.res', 'fixed positive file roles')
                api.same(link['Objects'], [str(path) for path in objects], 'exact ten-provider link order')
                api.same([link[key] for key in ('TranslationUnits', 'SlimIRObjects', 'StartupObjects')], [10, 9, 1], 'new TU cohort')
                for path, key in ((image, 'Sha256'), (machine, 'MachineSha256'), (map_path, 'MapSha256'),
                                  (Path(str(image) + '.res'), 'ResolutionSha256')):
                    self.watch.read(path, link[key])
                wanted.extend(self._inspection_commands(machine))
                wanted.extend(self._inspection_commands(image))
            negatives = r['NegativeControls']
            need(type(negatives) is list and len(negatives) == 2, 'both isolated conflict records')
            self.negative_proof = []
            for i, (name, symbol) in enumerate(zip(FIXTURES[1:], ('SVC_Handler', 'PendSV_Handler'))):
                record = negatives[i]
                image = root / Path(name).stem / 'image.elf'
                negative_objects = [*base[:8], Path(added[i + 1]['Object']), base[8]]
                argv = [gcc, *api.link_flags(dict(compile_flags=list(api.TARGET_FLAGS)), negative_objects,
                    script, image, image.with_suffix('.map'), False)]
                wanted.append(('link intended conflict ' + symbol, argv, str(image.parent), True))
                index = len(wanted) - 1
                api.same([record[key] for key in ('Name', 'Symbol', 'Status', 'CommandIndex', 'CommandStatus', 'Exit',
                    'IntendedDiagnostic', 'FinalImageAbsent')], [name, symbol, 'PASS', index, 'FAIL', 1, True, True], 'exact conflict control')
                path = root / ('command-%04d.stderr' % index)
                data = self.watch.read(path, record['DiagnosticSha256'])
                text = data.decode('utf-8')
                marker = re.escape('`' + symbol + "'")
                pattern = (re.escape(str(negative_objects[-2])) + r' \(symbol from plugin\): in function ' + marker + r':\r?\n'
                    + r'\(\.text\+0x0\): multiple definition of ' + marker + '; ' + re.escape(str(base[3]))
                    + r' \(symbol from plugin\):\(\.text\+0x0\): first defined here')
                need(len(re.findall(pattern, text)) == 1 and not image.exists(), 'exact added/original duplicate collision and absent final')
                self.negative_proof.append(dict(Name=name, Symbol=symbol, CommandIndex=index,
                    OriginalProvider=str(base[3]), AddedProvider=str(negative_objects[-2]), DiagnosticSha256=sha(data)))
            commands = r['Commands']
            need(type(commands) is list and len(commands) == len(wanted) == 28, 'complete ordered command catalog')
            for i, (row, expected) in enumerate(zip(commands, wanted)):
                label, argv, cwd, failed = expected
                api.same([row[key] for key in ('Label', 'Argv', 'Cwd', 'Status', 'Exit', 'TimedOut')],
                    [label, argv, cwd, 'FAIL' if failed else 'PASS', 1 if failed else 0, False], 'exact actual command')
                need(type(row.get('Seconds')) in (int, float) and math.isfinite(row['Seconds']) and row['Seconds'] >= 0,
                     'finite actual command duration')
                need(row.get('Error') == ('ValueError: cm3-lto-probe: command failed/timeout: ' + label if failed else None),
                     'intended command error family')
                path = root / ('command-%04d.json' % i)
                api.same(self.watch.structured(path), row, 'raw command JSON binding')
                for suffix in ('.stdout', '.stderr'):
                    need(path.with_suffix(suffix) in self.watch.hashes, 'complete bound command streams')
                if label.startswith('inspect '):
                    suffixes = [suffix for suffix in ('.readelf', '.dis', '.nm') if label.endswith(suffix)]
                    need(len(suffixes) == 1, 'exact inspection sidecar role')
                    sidecar = Path(str(argv[-1]) + suffixes[0])
                    need(self.watch.read(sidecar) == self.watch.read(path.with_suffix('.stdout')),
                         'inspection sidecar must equal complete actual command stdout')
            api.same(self.watch.structured(root / 'commands.json'), commands, 'complete catalog binding')
            environment = self.watch.structured(root / 'environment.json')
            old_environment = self.watch.structured(Path(r['CaptureBuild']) / 'environment.json')
            old_environment.update(TEMP=str(root / 'tmp'), TMP=str(root / 'tmp'))
            api.same(environment, old_environment, 'same sanitized process environment with private TEMP')

        def _inspection_commands(self, obj):
            native = self.native_capture
            tools = Path(native['CapturedCompiler']).parent
            plugin = native['LTOPlugin']['Path']
            return [('inspect ' + obj.name + suffix,
                [str(tools / ('arm-none-eabi-' + name + '.exe')), *flags, str(obj)], str(self.controls), False)
                for name, flags, suffix in (('readelf', ['-hSWsrA', '-lW'], '.readelf'),
                    ('objdump', ['-drwC', '-Mreg-names-std'], '.dis'),
                    ('nm', ['--plugin', plugin, '-P', '-S', '--defined-only'], '.nm'))]

        def audit(self):
            loader = load('cm3_override_immutable_loader', self.base.LOADER, self.buffers[self.base.LOADER])
            graph = loader.FrozenSources(self.buffers)
            package = Path(self.native_capture['SeedBuild']) / 'python/elftools'
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
            self.report['BinaryInputs'] = []
            roles_by_kind = {}
            startup = Path(self.native_capture['Sources'][8]['Object'])
            for link in self.capture['Links']:
                kind, final, machine = link['Kind'], Path(link['Path']), Path(link['Machine'])
                roles = dict(Machine=machine, Final=final, Disassembly=Path(str(final) + '.dis'),
                    LinkMap=Path(link['Map']), Startup=startup, Attributes=Path(str(final) + '.readelf'),
                    MachineAttributes=Path(str(machine) + '.readelf'), MachineDisassembly=Path(str(machine) + '.dis'),
                    Resolution=Path(link['Resolution']))
                need(len(set(roles.values())) == 9 and all(not p.samefile(q) for i, p in enumerate(roles.values())
                    for q in list(roles.values())[:i]), 'distinct physical twin roles')
                for role, path in roles.items():
                    need(path in self.watch.hashes, 'already authenticated binary role')
                    data = self.watch.read(path)
                    key = self.base.stable_path(path)
                    need(key not in snapshots or snapshots[key] == data, 'shared binary role conflict')
                    snapshots[key] = data
                    copied = self.copy('binary-inputs/%s/%s%s' % (kind, role, path.suffix), data)
                    self.report['BinaryInputs'].append(dict(Kind=kind, Role=role, Original=str(path), Captured=str(copied), Sha256=sha(data)))
                roles_by_kind[kind] = roles
            ordinary, emitted = roles_by_kind['ordinary'], roles_by_kind['emit-relocs']
            for first_role, first_path in ordinary.items():
                for second_role, second_path in emitted.items():
                    shared_startup = first_role == second_role == 'Startup'
                    need(first_path.samefile(second_path) is shared_startup,
                         'only explicit startup may physically alias across twins')
            def read_bytes(path):
                key = self.base.stable_path(path)
                need(key in snapshots, 'unknown immutable reader input')
                return snapshots[key]
            def read_text(path, encoding=None, errors=None, newline=None):
                need(newline is None and encoding in (None, 'ascii', 'utf-8') and errors in (None, 'strict'), 'exact text decoding')
                return read_bytes(path).decode(encoding or 'utf-8', errors or 'strict')
            previous = list(sys.meta_path)
            try:
                sys.meta_path.insert(0, Finder())
                with graph.active(), patch.object(Path, 'read_bytes', read_bytes), patch.object(Path, 'read_text', read_text):
                    core = graph.load('cm3_override_core', self.authority.core_path)
                    adapter = graph.load('cm3_override_native_adapter', HERE.with_name('cm3_lto_roots') / 'native.py')
                    protocol = graph.load('cm3_override_protocol', HERE.with_name('cm3_lto_protocol') / 'protocol.py')
                    audit = graph.load('cm3_override_link_contract', HERE.with_name('cm3_lto_link_contract') / 'audit.py')
                    resolution = graph.load('cm3_override_resolution', CONTROLS / 'resolution.py')
                    calls = graph.load('cm3_override_calls', HERE / 'calls.py')
                    decoder = graph.load('cm3_override_decoder', self.decoder)
                    checker = graph.load('cm3_override_checker', self.checker)
                    proofs = []
                    for kind, roles in roles_by_kind.items():
                        image = core.FinalImage(roles['Machine'], roles['Final'], roles['Disassembly'],
                            provider_objects={str(roles['Machine']): roles['Machine'], str(startup): startup},
                            link_map=roles['LinkMap'], float_abi='soft')
                        contract = audit.audit(image, read_text(roles['Attributes'], 'ascii'),
                            emit_relocs=kind == 'emit-relocs', machine_attributes_text=read_text(roles['MachineAttributes'], 'ascii'))
                        rows = resolution.parse(read_text(roles['Resolution'], 'ascii'), self.providers)
                        expected = {self.providers[i]: 'RESOLVED_IR' for i in (0, 1, 3, 4, 5, 7)}
                        expected.update({self.providers[2]: 'PREEMPTED_IR', self.providers[8]: 'PREVAILING_DEF_IRONLY'})
                        actual = {r['Provider']: s['Resolution'] for r in rows for s in r['Symbols'] if s['Name'] == 'fiber_panic'}
                        need(actual == expected and sum(len(r['Symbols']) for r in rows) == 108, 'exact complete panic resolution roles')
                        call_proof = calls.audit_calls(image, contract, emit_relocs=kind == 'emit-relocs')
                        native = None
                        if kind == 'emit-relocs':
                            transport = adapter.NativeCM3LTOImage(core, roles['Machine'], roles['Final'], roles['Disassembly'],
                                provider_objects={str(roles['Machine']): roles['Machine'], str(startup): startup},
                                link_map=roles['LinkMap'])
                            native = protocol.check_native(decoder.Object(roles['Machine'], roles['MachineDisassembly']),
                                transport, checker)
                        proofs.append(dict(Kind=kind, LinkContract=contract, ResolutionRows=rows,
                            PanicResolutionRoles=actual, Calls=call_proof, NativeProtocols=native))
                    twins = core.compare_load_images(roles_by_kind['ordinary']['Final'], roles_by_kind['emit-relocs']['Final'])
                self.report.update(Links=proofs, Twins=twins, ExecutedSourceBuffers=graph.executed,
                    NegativeControls=self.negative_proof, PanicOverrideProof=True, DuplicateHandlerLinkProof=True,
                    CanonicalProtocolValidated=True, FinalRootRelocationProof=True)
            finally:
                sys.meta_path[:] = previous

        def run(self):
            self.output.mkdir(parents=True)
            try:
                self.audit()
                self.close()
                self.report.update(Status='CM3-LTO-OVERRIDE-LINK-PASS-NOT-FULL-ABI-QUALIFIED', InputClosureVerified=True,
                    ClosingFilesVerified=len(self.watch.hashes), InputHashes={str(p): h for p, h in sorted(self.watch.hashes.items())},
                    InputPhysicalIdentities={str(p): h for p, h in sorted(self.identities.items())})
                self.seal()
            except BaseException as error:
                self.report.update(Status='FAIL', Error=type(error).__name__ + ': ' + str(error), InputClosureVerified=False)
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
