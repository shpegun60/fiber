"""Audit retained CM3 O2-LTO link contracts without executing a toolchain."""
import argparse
import importlib.abc
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
BASE = HERE.with_name('cm3_lto_roots') / 'witness.py'
BASE_SHA = '5BFA66061B9BFAC9B7C6AF872AB831E69613DDDA03C0FA40E439E36273963713'


def need(condition, message):
    if not condition:
        raise ValueError('cm3-lto-link-witness: ' + message)


def load(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


class Witness:
    def __init__(self, args):
        import hashlib
        self.sha = lambda data: hashlib.sha256(data).hexdigest().upper()
        data = BASE.read_bytes()
        need(self.sha(data) == BASE_SHA, 'fixed capture-admission envelope required')
        self.base = load('cm3_link_contract_capture_envelope', BASE, data)
        self.authority = self.base.Witness(args)
        a = self.authority
        self.api, self.watch = a.api, a.watch
        self.root, self.output = a.root, a.output
        self.buffers = dict(a.buffers)
        for path in (BASE, Path(__file__).resolve(), HERE / 'audit.py'):
            self.buffers[path] = self.watch.read(path)
        need(self.sha(self.buffers[BASE]) == BASE_SHA, 'capture envelope changed')
        self._tree(Path(a.result['SeedBuild']), a.result['SeedArtifactsSha256'])
        inventory = Path(a.result['SourceInventoryReceipt'])
        need(inventory / 'artifacts.json' in self.watch.hashes, 'captured inventory manifest authority')
        self._tree(inventory, self.watch.hashes[inventory / 'artifacts.json'])
        self.report = dict(Status='FAIL', Scope='NATIVE_CM3_O2_LTO_DIRECT_FINAL_LINK_CONTRACT_ONLY', Error=None,
            Profile='CM3', Mode='O2-lto', Linkage='direct',
            CaptureBuild=str(self.root), CaptureReceiptSha256=args.capture_receipt_sha256,
            CaptureArtifactsSha256=args.capture_artifacts_sha256, Interpreter=a.report['Interpreter'],
            NativeCommandsExecuted=0, FreshLinksExecuted=0, CpuExecution=False, BoardExecution=False,
            SourceToMachineSemanticProof=False, FullABIProof=False, FinalReferenceParity=False,
            ArchiveExtraction=False, PanicOverrideProof=False, IdentityMismatchLinkProof=False,
            DuplicateHandlerLinkProof=False, RequiredCellsSatisfied=0, GlobalFreezeQualified=False)
        self.expected = {'results.json', 'artifacts.json'}
        self.identities = {path: self.identity(path) for path in self.watch.hashes}
        self.close()

    def identity(self, path):
        stat = self.api.regular(path).stat()
        return dict(Device=stat.st_dev, Inode=stat.st_ino, Links=stat.st_nlink, Size=stat.st_size)

    def close(self):
        self.watch.close()
        need(all(self.identity(path) == identity for path, identity in self.identities.items()),
             'input physical identity changed')

    def _tree(self, root, expected):
        manifest = self.watch.structured(root / 'artifacts.json', expected)
        need(type(manifest.get('Artifacts')) is dict and manifest['Artifacts'], 'complete nested tree')
        self.watch.tree(root, dict(manifest['Artifacts'], **{'artifacts.json': expected}))

    def copy(self, relative, data):
        need(relative not in self.expected and not Path(relative).is_absolute()
             and '..' not in Path(relative).parts, 'unique predetermined output')
        self.expected.add(relative)
        path = self.output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        self.watch.read(path, self.sha(data))
        self.identities[path] = self.identity(path)
        return path

    def audit(self):
        a = self.authority
        loader = load('cm3_link_contract_loader', self.base.LOADER, self.buffers[self.base.LOADER])
        graph = loader.FrozenSources(self.buffers)
        package = Path(a.result['SeedBuild']) / 'python/elftools'
        modules = {}
        for path in self.buffers:
            if path.is_relative_to(package):
                parts = list(path.relative_to(package.parent).with_suffix('').parts)
                is_package = parts[-1] == '__init__'
                if is_package:
                    parts.pop()
                name = '.'.join(parts)
                need(name not in modules, 'unique parser module')
                modules[name] = path, is_package
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

        self.report['Sources'] = [dict(Original=str(path), Sha256=self.sha(data),
            Captured=str(self.copy('source-buffers/%04d-%s' % (i, path.name), data)))
            for i, (path, data) in enumerate(sorted(self.buffers.items()))]
        snapshots = {self.base.stable_path(path): data for path, data in self.buffers.items()}
        binaries, roles_by_kind = [], {}
        startup = self.api.regular(a.result['Sources'][-1]['Object'])
        for link in a.result['Links']:
            kind = link['Kind']
            roles = dict(Machine=Path(link['Machine']), Final=Path(link['Path']),
                Disassembly=Path(link['Path'] + '.dis'), LinkMap=Path(link['Map']), Startup=startup,
                Attributes=Path(link['Path'] + '.readelf'), MachineAttributes=Path(link['Machine'] + '.readelf'))
            need(len(set(roles.values())) == 7 and all(not p.samefile(q) for i, p in enumerate(roles.values())
                 for q in list(roles.values())[:i]), 'distinct physical link roles')
            for role, path in roles.items():
                need(path.is_relative_to(self.root), 'binary role outside authenticated capture')
                expected = a.artifacts[path.relative_to(self.root).as_posix()]
                data = self.watch.read(path, expected)
                key = self.base.stable_path(path)
                need(key not in snapshots or snapshots[key] == data, 'shared binary role conflict')
                snapshots[key] = data
                captured = self.copy('binary-inputs/%s/%s%s' % (kind, role, path.suffix), data)
                binaries.append(dict(Kind=kind, Role=role, Original=str(path), Captured=str(captured), Sha256=expected))
            roles_by_kind[kind] = roles
        need(list(roles_by_kind) == ['ordinary', 'emit-relocs'], 'fixed twin order')

        def read_bytes(path):
            key = self.base.stable_path(path)
            need(key in snapshots, 'unknown immutable reader input')
            return snapshots[key]

        def read_text(path, encoding=None, errors=None, newline=None):
            need(newline is None and encoding in (None, 'ascii', 'utf-8') and errors in (None, 'strict'),
                 'exact text decoding')
            return read_bytes(path).decode(encoding or 'utf-8', errors or 'strict')

        previous_meta = list(sys.meta_path)
        try:
            sys.meta_path.insert(0, Finder())
            with graph.active(), patch.object(Path, 'read_bytes', read_bytes), patch.object(Path, 'read_text', read_text):
                core = graph.load('cm3_link_contract_elf', a.core_path)
                audit = graph.load('cm3_link_contract_audit', HERE / 'audit.py')
                proofs = []
                for kind, roles in roles_by_kind.items():
                    image = core.FinalImage(roles['Machine'], roles['Final'], roles['Disassembly'],
                        provider_objects={str(roles['Machine']): roles['Machine'], str(startup): startup},
                        link_map=roles['LinkMap'], float_abi='soft')
                    proof = audit.audit(image, read_text(roles['Attributes'], 'ascii'),
                        emit_relocs=kind == 'emit-relocs',
                        machine_attributes_text=read_text(roles['MachineAttributes'], 'ascii'))
                    proofs.append(dict(Kind=kind, Proof=proof))
                twins = core.compare_load_images(roles_by_kind['ordinary']['Final'], roles_by_kind['emit-relocs']['Final'])
            self.report.update(Links=proofs, Twins=twins, ExecutedSourceBuffers=graph.executed,
                BinaryInputs=binaries, ImmutableInputsConsumed=True)
        finally:
            sys.meta_path[:] = previous_meta

    def seal(self):
        success = self.report['Status'] != 'FAIL'
        members = set(self.api.files_under(self.output)) - {'results.json', 'artifacts.json'}
        if success:
            need(members == self.expected - {'results.json', 'artifacts.json'}, 'predetermined output membership')
        self.report['OutputSealVerified'] = True
        self.api.save(self.output / 'results.json', self.report)
        artifacts = {name: self.sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items()
                     if name != 'artifacts.json'}
        if success:
            need(set(artifacts) == self.expected - {'artifacts.json'}, 'exact receipt membership')
        manifest = dict(Artifacts=artifacts)
        self.api.save(self.output / 'artifacts.json', manifest)
        manifest_bytes = (self.output / 'artifacts.json').read_bytes()
        self.api.same(json.loads(manifest_bytes, object_pairs_hook=self.api.unique_object), manifest, 'manifest roundtrip')
        self.close()
        self.api.same({name: self.sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items()
                       if name != 'artifacts.json'}, artifacts, 'late output closure')
        need(self.sha((self.output / 'artifacts.json').read_bytes()) == self.sha(manifest_bytes), 'late manifest closure')

    def run(self):
        self.output.mkdir(parents=True)
        try:
            self.audit()
            self.close()
            self.report.update(Status='CM3-LTO-DIRECT-LINK-CONTRACT-PASS-NOT-QUALIFIED',
                InputClosureVerified=True, ClosingFilesVerified=len(self.watch.hashes),
                InputHashes={str(path): value for path, value in sorted(self.watch.hashes.items())},
                InputPhysicalIdentities={str(path): value for path, value in sorted(self.identities.items())})
            self.seal()
        except BaseException as error:
            self.report.update(Status='FAIL', Error=type(error).__name__ + ': ' + str(error), InputClosureVerified=False)
            try:
                self.seal()
            except BaseException as closing:
                self.report.update(OutputSealVerified=False, SealError=type(closing).__name__ + ': ' + str(closing))
                self.api.save(self.output / 'results.json', self.report)
                self.api.save(self.output / 'artifacts.json', dict(Artifacts={
                    name: self.sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items()
                    if name != 'artifacts.json'}))
        return self.report['Status'] != 'FAIL'


def main(argv=None):
    need(not sys.flags.optimize, 'unoptimized interpreter required')
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('capture-build', 'capture-receipt-sha256', 'capture-artifacts-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    witness = Witness(parser.parse_args(argv))
    passed = witness.run()
    print(witness.report['Status'], witness.report.get('Error') or '', str(witness.output))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
