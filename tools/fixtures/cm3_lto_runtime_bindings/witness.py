"""Audit current native CM3 O2-LTO providers and references; no target execution."""
import argparse
import copy
import hashlib
import importlib.abc
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PASS = 'CURRENT-CM3-LTO-RUNTIME-BINDINGS-PASS-NOT-QUALIFIED'
SCOPE = 'NATIVE_CURRENT_CM3_O2_LTO_RUNTIME_BINDINGS_ONLY'
FORWARD = ('fiber_port_context_init', 'fiber_port_runtime_memory_barrier', 'fiber_port_panic_wait',
    'fiber_port_require_scheduler_configuration_environment', 'fiber_port_runtime_prepare_start',
    'fiber_port_runtime_select_first', 'fiber_port_runtime_start_first', 'fiber_port_runtime_schedule')
REVERSE = ('fiber_internal_runtime_select_scheduler_candidate', 'fiber_internal_runtime_publish_current_context',
    'fiber_internal_runtime_require_current_context', 'fiber_internal_task_return')
PINS = {
    'capture': ('tools/fixtures/cm3_current_lto_capture/capture.py',
        '1191CDCDA9FC9312B09858D6439674DBCA19ABFCE5B0108F3575AEF3C65C0852'),
    'legacy': ('tools/fixtures/cm3_lto_link_contract/witness.py',
        '599D384B53F45093F01949A4E95A9DF8A15BC4EABE9EA5E12A1C2E7138F3297E'),
    'recipe': ('tools/fixtures/cm3_os_lto_join/witness.py',
        'BEC9C699F8C62A69CB2BF35B24CF51D8815329517F83A11517BF9657D294D7AB'),
    'recovery': ('tools/fixtures/cm3_current_lto_replay/witness.py',
        '7AFE40E8344E0E9329004BB4D9682606251C9FB05E7B17A3233BF16F1798AC4A'),
}
BUFFER_PINS = {
    'audit': ('tools/fixtures/cm3_lto_link_contract/audit.py',
        '9D6B4E1694A8C0A2D7F2E1C7B6D108B58B103131DD7C19D45CD08238E4CED759'),
    'bindings': ('tools/fixtures/cm3_lto_runtime_bindings/bindings.py',
        'A8C994427DDE61619AB789D62E198B24DEC0B05EF8D1EE8E1C28BE86536E4C3B'),
    'contract': ('tools/fixtures/cm3_lto_runtime_bindings/CONTRACT.md',
        'DAEB282DE77E2A258A66B87651CB5302BE358A7E3B3A1AF194D089D070BA2AFB'),
}


def need(value, message):
    if not value:
        raise ValueError('current-cm3-lto-bindings: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def module(name, path, raw):
    result = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = result
    exec(compile(raw, str(path), 'exec'), result.__dict__)
    return result


def descriptor(replay, root, receipt, artifacts):
    return dict(Build=str(replay.checked_path(root, directory=True)),
        ReceiptSha256=replay.digest(receipt), ArtifactsSha256=replay.digest(artifacts))


def declared_descriptor(replay, value):
    need(type(value) is dict and set(value) == {'Build', 'ReceiptSha256', 'ArtifactsSha256'},
         'exact declared evidence descriptor')
    return descriptor(replay, value['Build'], value['ReceiptSha256'], value['ArtifactsSha256'])


def command_view(result, seed_sources):
    """Supply only the absent O2 Seed flags expected by the frozen recipe API."""
    rows = result.get('Sources')
    need(type(rows) is list and type(seed_sources) is list and len(rows) == len(seed_sources) == 9,
         'nine independently bound source rows for command projection')
    view, projection = copy.deepcopy(result), []
    for index, (original, seed, selected) in enumerate(zip(rows, seed_sources, view['Sources'])):
        need(type(original) is dict and type(seed) is dict and 'SeedCompileFlags' not in original
             and type(original.get('Source')) is str and original.get('Source') == seed.get('Source')
             and type(original.get('SourceSha256')) is str
             and original['SourceSha256'] == seed.get('SourceSha256'), 'same raw/Seed source provider')
        flags = seed.get('CompileFlags')
        need(type(flags) is list and flags and all(type(flag) is str for flag in flags),
             'literal independently admitted Seed compile flags')
        selected['SeedCompileFlags'] = list(flags)
        projection.append(dict(SourceIndex=index, Source=original['Source'], SourceSha256=original['SourceSha256'],
            AddedField='SeedCompileFlags', Value=list(flags)))
    return view, dict(Authority='INDEPENDENTLY_ADMITTED_ORDINARY_CM3_O2_SEED',
        RawCaptureChanged=False, AddedFields=projection)


def require_bindings_result(proof, *, emit_relocs):
    need(type(emit_relocs) is bool and type(proof) is dict
         and proof.get('Status') == 'CM3-LTO-RUNTIME-BINDINGS-PASS-NOT-QUALIFIED'
         and proof.get('Scope') == 'NATIVE_CM3_O2_LTO_DIRECT_MERGED_MACHINE_RUNTIME_BINDINGS_ONLY'
         and proof.get('Profile') == 'CM3' and proof.get('Mode') == 'O2-lto'
         and proof.get('Linkage') == 'direct' and proof.get('EmitRelocs') is emit_relocs
         and proof.get('RuntimeProviderBindingsValidated') is True
         and proof.get('FinalLinkContractValidated') is True
         and proof.get('OriginalStartupVectorRelocationsAudited') is True, 'complete fixed bindings verdict')
    counts = dict(MandatoryDefinitionCount=30, AdditionalConsumerCount=3,
        ForwardProviderCount=8, ReverseProviderCount=4, ReverseReferenceCount=5,
        ReverseBLReferences=4, TaskReturnABS32References=1, ColdAnchorReadCount=2,
        StartupVectorReferenceCount=3, OriginalBindingRelocations=10,
        AppliedBindingRelocations=10 if emit_relocs else 0, RequiredCellsSatisfied=0)
    need(all(type(proof.get(name)) is int and proof[name] == value for name, value in counts.items()),
         'literal complete binding counts')
    for name, count in (('ForwardProviders', 8), ('ReverseProviders', 4), ('ReverseReferences', 5),
                        ('ColdAnchorReads', 2), ('StartupVectors', 3), ('AdditionalConsumerOrigins', 3)):
        rows = proof.get(name)
        need(type(rows) is list and len(rows) == count and all(type(row) is dict and row for row in rows),
             'complete binding evidence: ' + name)
    link = proof.get('LinkContract')
    need(type(link) is dict and link.get('Status') == 'CM3-LTO-DIRECT-LINK-CONTRACT-PASS-NOT-QUALIFIED'
         and link.get('Scope') == 'NATIVE_CM3_O2_LTO_DIRECT_FINAL_LINK_CONTRACT_ONLY'
         and link.get('Profile') == 'CM3' and link.get('Mode') == 'O2-lto' and link.get('Linkage') == 'direct'
         and link.get('EmitRelocs') is emit_relocs and link.get('FinalLinkContractValidated') is True
         and type(link.get('Symbols')) is dict and len(link['Symbols']) == 26,
         'retained complete fixed link contract')
    for field, names in (('ForwardProviders', FORWARD), ('ReverseProviders', REVERSE)):
        need(tuple(row.get('Name') for row in proof[field]) == names, 'exact named provider evidence: ' + field)
    mandatory = proof.get('MandatoryDefinitions')
    need(type(mandatory) is dict and len(mandatory) == 30 and not set(REVERSE).intersection(link['Symbols'])
         and set(mandatory) == set(link['Symbols']) | set(REVERSE), 'complete named mandatory definition surface')
    combined = dict(link['Symbols'], **{row['Name']: row for row in proof['ReverseProviders']})
    need(encoded(mandatory) == encoded(combined)
         and all(type(row) is dict and row.get('Name') == name and type(row.get('Original')) is dict
             and row['Original'] and type(row.get('Final')) is dict and row['Final']
             for name, row in mandatory.items()), 'complete raw original/final provider records')
    need(all(encoded(row) == encoded(mandatory[row['Name']]) for row in proof['ForwardProviders']),
         'forward provider records belong to the retained mandatory surface')
    consumers = proof['AdditionalConsumerOrigins']
    need(tuple(row.get('Name') for row in consumers) == (
        'fiber_port_scheduler_pick_first_from_start', 'fiber_port_scheduler_pick_next_from_pendsv',
        'fiber_port_init_context_frame') and all(type(row.get('Original')) is dict
            and row['Original'].get('name') == row['Name'] and type(row.get('Final')) is dict
            and row['Final'].get('name') == row['Name'] for row in consumers),
         'exact additional consumer names and raw origin records')
    need(proof.get('RequiredCellSatisfied') is False and all(proof.get(name) is False for name in (
        'Qualification', 'TypedABIProof', 'FullABIProof', 'FullSemanticABIProof', 'SourceIRProof',
        'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership', 'CanonicalProtocolValidated',
        'InstructionEquivalence', 'PolicyEquivalence', 'FinalReferenceParity', 'CompleteObjectProof',
        'KernelRuntimeProof', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified')),
         'non-promoting binding result')
    return proof


def revoke_failure(witness, recovery, error):
    def force():
        witness.report.update(Status='FAIL', RuntimeProviderBindingsValidated=False, FinalLinkContractValidated=False)
    def fail(message):
        try:
            witness._fail(message)
        finally:
            force()
    def seal():
        force()
        return witness._seal()
    force()
    facade = SimpleNamespace(report=witness.report, output=witness.output, replay_api=witness.replay_api,
        _fail=fail, _seal=seal)
    try:
        recovery.revoke_failure(facade, error)
    finally:
        force()


def witness_type(modules, sources):
    legacy, capture, recipe = (modules[name] for name in ('legacy', 'capture', 'recipe'))

    class Witness(legacy.Witness):
        def __init__(self, args):
            environment, outer = capture.load_environment()
            self.replay_api = replay = environment['replay']
            for path, raw in sources.items():
                need(outer.read(path, sha(raw)) == raw, 'same executed bootstrap bytes')
            admission = replay.Admission(outer)
            current_descriptor = descriptor(replay, args.inventory,
                args.inventory_receipt_sha256, args.inventory_artifacts_sha256)
            current = admission.snapshot(current_descriptor, current=True)
            need(current['SourceInventorySha256'] == capture.SOURCE_SHA
                 and type(current['Required']['RequiredCellCount']) is int
                 and current['Required']['RequiredCellCount'] == 2774, 'complete current E9 authority')
            capture_descriptor = descriptor(replay, args.capture_build,
                args.capture_receipt_sha256, args.capture_artifacts_sha256)
            bundle = admission.bundle(capture_descriptor)
            admission.require_inventory_binding(bundle, current, required=True)
            report = bundle['Result']
            capture.require_capture(report, capture.select('native', 'O2-lto'), sealed=True)
            expected_producer = dict(Path=str(ROOT / PINS['capture'][0]), Sha256=PINS['capture'][1])
            replay.same(report.get('CaptureProducer'), expected_producer, 'fixed current producer')
            replay.same(declared_descriptor(replay, report.get('CurrentInventory')), current_descriptor,
                        'independent inventory descriptor')
            need(replay.checked_path(report['SourceInventoryReceipt'], directory=True) == current['Bundle']['Root'],
                 'same independently admitted current inventory')
            selected_seed = descriptor(replay, report['SeedBuild'],
                report['SeedReceiptSha256'], report['SeedArtifactsSha256'])
            replay.same(declared_descriptor(replay, report.get('SeedAuthority')), selected_seed,
                        'independent ordinary Seed descriptor')
            prepared = capture.prepare(SimpleNamespace(side='native', mode='O2-lto',
                seed_build=selected_seed['Build'], seed_receipt_sha256=selected_seed['ReceiptSha256'],
                seed_artifacts_sha256=selected_seed['ArtifactsSha256'], inventory=current_descriptor['Build'],
                inventory_receipt_sha256=current_descriptor['ReceiptSha256'],
                inventory_artifacts_sha256=current_descriptor['ArtifactsSha256'], output_dir=args.output_dir))
            replay.same(prepared['Current']['Bundle']['Descriptor'], current_descriptor, 'same prepared inventory')
            replay.same(prepared['Group']['Descriptor'], selected_seed, 'same admitted ordinary Seed')
            replay.same(prepared['Producer'], expected_producer, 'same admitted producer buffer')
            seed = prepared['Seed']
            need(seed.result.get('Profile') == 'CM3' and seed.result.get('Mode') == 'O2'
                 and prepared['Model']['Side'] == 'native' and prepared['Model']['SeedMode'] == 'O2',
                 'independently admitted ordinary native CM3/O2 Seed')
            git = [path for path in seed.originals if path.name.casefold() == 'git.exe']
            need(len(git) <= 1, 'unambiguous nonexecuted Git provenance tool')
            self.provenance_git = git[0] if git else None
            self.created_output = False
            super().__init__(SimpleNamespace(capture_build=capture_descriptor['Build'],
                capture_receipt_sha256=capture_descriptor['ReceiptSha256'],
                capture_artifacts_sha256=capture_descriptor['ArtifactsSha256'], output_dir=args.output_dir))
            self.watch = capture.CombinedClosure(self.api, self.watch, outer)
            for guard in (prepared['Watch'], seed.closure):
                for path, value in tuple(guard.hashes.items()):
                    self.watch.read(path, value)
                for root, values in tuple(getattr(guard, 'trees', {}).items()):
                    self.watch.tree(root, values)
                for root, names in tuple(getattr(guard, 'memberships', {}).items()):
                    self.watch.tree(root, {name: guard.hashes[root / name] for name in names})
            for path, raw in {**seed.buffers, **outer.buffers, **sources}.items():
                need(self.watch.read(path, sha(raw)) == raw, 'admitted immutable helper/source bytes')
                need(path not in self.buffers or self.buffers[path] == raw, 'conflicting source buffer')
                self.buffers[path] = raw
            self.authority.watch = self.watch
            replay.same(self.authority.result, report, 'same independently admitted capture')
            projected, projection = command_view(report, seed.sources)
            group = dict(Root=self.root, Result=projected, Artifacts=bundle['Artifacts'], Seed=seed)
            o2_recipe = SimpleNamespace(mode_flags=self.api.mode_flags, startup_flags=lambda flags: list(flags),
                link_flags=lambda api, *values: api.link_flags(*values))
            recipe.Witness._commands(self, 'Native', group, o2_recipe)
            denied = {ROOT, *outer.denied, *prepared['Watch'].denied,
                      *(path.parent for path in self.watch.hashes)}
            need(not self.output.exists() and all(not self.output.is_relative_to(path)
                 and not path.is_relative_to(self.output) for path in denied), 'fresh disjoint output')
            self.identities = {path: self.identity(path) for path in self.watch.hashes}
            self.close()
            self.report.update(Status='FAIL', Error=None, Scope=SCOPE, Qualification=False,
                SourceInventoryReceipt=str(current['Bundle']['Root']), SourceInventorySha256=capture.SOURCE_SHA,
                CurrentInventory=current_descriptor, CurrentCaptureProducer=expected_producer,
                SeedAuthority=selected_seed, CommandsReconstructed=group['CommandsReconstructed'],
                CommandViewProjection=projection,
                BootstrapSources=[dict(Path=str(path), Sha256=sha(raw)) for path, raw in sorted(sources.items())],
                RuntimeProviderBindingsValidated=False, FinalLinkContractValidated=False,
                CanonicalProtocolValidated=False, FinalRootRelocationProof=False, FullSemanticABIProof=False,
                SourceIRProof=False, OriginalTranslationUnitOwnership=False, CompleteObjectProof=False,
                PolicyEquivalence=False, HostedCIQualified=False, RequiredCellSatisfied=False, RequiredCellCount=2774,
                ProducerCompilersReexecuted=False, ClosingErrors=[], PrimaryError=None)

        def identity(self, path):
            path = self.api.regular(path)
            value = super().identity(path)
            need(value['Links'] == 1 or path == self.provenance_git,
                 'single-linked semantic/tool file except authenticated Git provenance')
            return value

        def audit(self):
            authority = self.authority
            loader = legacy.load('runtime_bindings_immutable_loader', self.base.LOADER,
                self.buffers[self.base.LOADER])
            graph = loader.FrozenSources(self.buffers)
            package = Path(authority.result['SeedBuild']) / 'python/elftools'
            parser_modules = {}
            for path in self.buffers:
                if path.is_relative_to(package):
                    parts = list(path.relative_to(package.parent).with_suffix('').parts)
                    is_package = parts[-1] == '__init__'
                    if is_package:
                        parts.pop()
                    name = '.'.join(parts)
                    need(name not in parser_modules, 'unique parser source module')
                    parser_modules[name] = path, is_package
            need('elftools' in parser_modules and not any(name == 'elftools' or name.startswith('elftools.')
                 for name in sys.modules), 'closed initially unimported parser package')

            class Finder(importlib.abc.MetaPathFinder):
                def find_spec(inner, fullname, path=None, target=None):
                    if fullname != 'elftools' and not fullname.startswith('elftools.'):
                        return None
                    need(fullname in parser_modules and target is None, 'unknown parser source')
                    source, is_package = parser_modules[fullname]
                    spec = graph.spec(fullname, source)
                    if is_package:
                        spec.submodule_search_locations = [str(source.parent)]
                    return spec

            self.report['Sources'] = [dict(Original=str(path), Sha256=sha(raw),
                Captured=str(self.copy('source-buffers/%04d-%s' % (index, path.name), raw)))
                for index, (path, raw) in enumerate(sorted(self.buffers.items()))]
            snapshots = {self.base.stable_path(path): raw for path, raw in self.buffers.items()}
            startup = self.api.regular(authority.result['Sources'][-1]['Object'])
            by_kind, binaries = {}, []
            for link in authority.result['Links']:
                kind = link['Kind']
                machine, final = Path(link['Machine']), Path(link['Path'])
                roles = dict(Machine=machine, Final=final, Disassembly=Path(str(final) + '.dis'),
                    LinkMap=Path(link['Map']), Startup=startup, Attributes=Path(str(final) + '.readelf'),
                    MachineAttributes=Path(str(machine) + '.readelf'))
                need(len(set(roles.values())) == 7 and all(not path.samefile(other)
                     for index, path in enumerate(roles.values()) for other in list(roles.values())[:index]),
                     'seven distinct physical positive roles per twin')
                for role, path in roles.items():
                    need(path.is_relative_to(self.root), 'binary role outside admitted capture')
                    value = authority.artifacts[path.relative_to(self.root).as_posix()]
                    raw = self.watch.read(path, value)
                    key = self.base.stable_path(path)
                    need(key not in snapshots or snapshots[key] == raw, 'shared immutable binary role conflict')
                    snapshots[key] = raw
                    copied = self.copy('binary-inputs/%s/%s%s' % (kind, role, path.suffix), raw)
                    binaries.append(dict(Kind=kind, Role=role, Original=str(path), Captured=str(copied), Sha256=value))
                by_kind[kind] = roles
            need(list(by_kind) == ['ordinary', 'emit-relocs'], 'ordered actual machine twins')

            def read_bytes(path):
                key = self.base.stable_path(path)
                need(key in snapshots, 'unknown immutable reader input')
                return snapshots[key]

            def read_text(path, encoding=None, errors=None, newline=None):
                need(newline is None and encoding in (None, 'ascii', 'utf-8') and errors in (None, 'strict'),
                     'exact immutable text decoding')
                return read_bytes(path).decode(encoding or 'utf-8', errors or 'strict')

            previous = list(sys.meta_path)
            try:
                sys.meta_path.insert(0, Finder())
                with graph.active(), patch.object(Path, 'read_bytes', read_bytes), \
                        patch.object(Path, 'read_text', read_text):
                    core = graph.load('runtime_bindings_final_core', authority.core_path)
                    fixed_audit = graph.load('runtime_bindings_fixed_audit', ROOT / BUFFER_PINS['audit'][0])
                    bindings = graph.load('runtime_bindings_pure_extension', ROOT / BUFFER_PINS['bindings'][0])
                    proofs = []
                    for kind, roles in by_kind.items():
                        image = core.FinalImage(roles['Machine'], roles['Final'], roles['Disassembly'],
                            provider_objects={str(roles['Machine']): roles['Machine'], str(startup): startup},
                            link_map=roles['LinkMap'], float_abi='soft')
                        proof = bindings.inspect(image, core, fixed_audit,
                            read_text(roles['Attributes'], 'ascii'), emit_relocs=kind == 'emit-relocs',
                            machine_attributes_text=read_text(roles['MachineAttributes'], 'ascii'))
                        require_bindings_result(proof, emit_relocs=kind == 'emit-relocs')
                        proofs.append(dict(Kind=kind, Proof=proof))
                    twins = core.compare_load_images(by_kind['ordinary']['Final'], by_kind['emit-relocs']['Final'])
                    self.api.same(twins, authority.result['TwinLoadImages'], 'fresh actual load-image twins')
                self.report.update(Links=proofs, Twins=twins, BinaryInputs=binaries,
                    ExecutedSourceBuffers=graph.executed, ImmutableInputsConsumed=True,
                    FinalLinkContractValidated=True, RuntimeProviderBindingsValidated=True)
            finally:
                sys.meta_path[:] = previous

        def _fail(self, message):
            self.report.update(Status='FAIL', Error=self.report.get('Error') or message,
                InputClosureVerified=False, OutputSealVerified=False, FinalLinkContractValidated=False,
                RuntimeProviderBindingsValidated=False, ImmutableInputsConsumed=False)

        def _seal(self):
            success = self.report['Status'] == PASS
            actual = self.api.files_under(self.output)
            if success:
                need(set(actual) - {'results.json', 'artifacts.json'} == self.expected - {'results.json', 'artifacts.json'},
                     'predetermined complete output membership')
            self.report['OutputSealVerified'] = success
            receipt = encoded(self.report)
            (self.output / 'results.json').write_bytes(receipt)
            need((self.output / 'results.json').read_bytes() == receipt, 'intended receipt bytes')
            artifacts = {name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items()
                         if name not in ('results.json', 'artifacts.json')}
            artifacts['results.json'] = sha(receipt)
            manifest = encoded(dict(Artifacts=artifacts))
            (self.output / 'artifacts.json').write_bytes(manifest)
            need((self.output / 'artifacts.json').read_bytes() == manifest, 'intended manifest bytes')
            if success:
                need(set(artifacts) == self.expected - {'artifacts.json'}, 'exact planned artifact set')
                self.close()
                self.api.same({name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items()
                               if name != 'artifacts.json'}, artifacts, 'late complete output byte closure')
                need((self.output / 'artifacts.json').read_bytes() == manifest, 'late manifest drift')

        def run(self):
            self.output.mkdir(parents=True, exist_ok=False)
            self.created_output = True
            self.audit()
            self.close()
            self.report.update(Status=PASS, InputClosureVerified=True, ClosingFilesVerified=len(self.watch.hashes),
                InputHashes={str(path): value for path, value in sorted(self.watch.hashes.items())},
                InputPhysicalIdentities={str(path): value for path, value in sorted(self.identities.items())})
            self._seal()
            return True

    return Witness


def prepare(args):
    need(not sys.flags.optimize and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
         'fresh isolated unoptimized -I -S -B Python required')
    need(not any(name == 'elftools' or name.startswith('elftools.') for name in sys.modules),
         'no inherited parser state')
    sources = {}
    for relative, expected in (*PINS.values(), *BUFFER_PINS.values()):
        path = ROOT / relative
        raw = path.read_bytes()
        need(sha(raw) == expected, 'fixed authenticated helper buffer: ' + relative)
        sources[path] = raw
    sources[Path(__file__).resolve()] = Path(__file__).resolve().read_bytes()
    modules = {name: module('current_cm3_bindings_' + name, ROOT / row[0], sources[ROOT / row[0]])
               for name, row in PINS.items()}
    return witness_type(modules, sources)(args), modules


def succeeded(report):
    return (report.get('Status') == PASS and report.get('Scope') == SCOPE and report.get('Error') is None
        and report.get('Profile') == 'CM3' and report.get('Mode') == 'O2-lto' and report.get('Linkage') == 'direct'
        and report.get('SourceInventorySha256') == '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
        and report.get('PrimaryError') is None and report.get('ClosingErrors') == []
        and report.get('InputClosureVerified') is True and report.get('OutputSealVerified') is True
        and report.get('RuntimeProviderBindingsValidated') is True and report.get('FinalLinkContractValidated') is True
        and report.get('ImmutableInputsConsumed') is True and type(report.get('CommandsReconstructed')) is int
        and report['CommandsReconstructed'] == 57 and type(report.get('RequiredCellCount')) is int
        and report['RequiredCellCount'] == 2774
        and type(report.get('RequiredCellsSatisfied')) is int and report['RequiredCellsSatisfied'] == 0
        and report.get('RequiredCellSatisfied') is False
        and all(report.get(name) is False for name in ('Qualification', 'FullABIProof', 'FullSemanticABIProof',
            'SourceIRProof', 'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership', 'PolicyEquivalence',
            'CanonicalProtocolValidated', 'FinalRootRelocationProof', 'CompleteObjectProof', 'CpuExecution',
            'BoardExecution', 'GlobalFreezeQualified', 'HostedCIQualified', 'ProducerCompilersReexecuted')))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('capture-build', 'capture-receipt-sha256', 'capture-artifacts-sha256', 'inventory',
                 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    witness = None
    try:
        with patch('subprocess.Popen', side_effect=AssertionError('bindings replay cannot execute processes')), \
                patch('os.system', side_effect=AssertionError('bindings replay cannot execute shell commands')):
            witness, modules = prepare(args)
            need(witness.run() is True and succeeded(witness.report), 'complete bounded bindings replay required')
    except BaseException as error:
        if witness is not None and witness.created_output:
            try:
                revoke_failure(witness, modules['recovery'], error)
            except BaseException as secondary:
                print('Failure diagnostics: ' + str(secondary), file=sys.stderr)
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps({name: witness.report.get(name) for name in ('Status', 'Scope', 'CommandsReconstructed',
        'InputClosureVerified', 'OutputSealVerified', 'RequiredCellsSatisfied')}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
