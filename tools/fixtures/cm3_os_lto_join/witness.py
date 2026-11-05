"""Read-only Os-lto capture replay and six-root join; no compiler or target."""

import argparse
import ctypes
import hashlib
import importlib.abc
import importlib.util
import json
import math
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PASS = 'CM3-OS-LTO-JOIN-PASS-NOT-QUALIFIED'
PIN = 'a50edad08b29052631aa469d4df6e6ec7ff68878'
UTILITY = 'tools/fixtures/cm3_lto_transport/probe.py'
LOADER = 'tools/fixtures/cm3_final_roots/reference_witness.py'
PRODUCER = 'tools/fixtures/cm3_os_lto_transport/probe.py'
POLICY = 'tools/fixtures/cm3_final_join/POLICY_DIFFERENCES.md'
POLICY_SHA = '778B098F80EAE5EE641B323B4F8D60441C2F725921B506AEDA90B487D3EB5019'
FIXED = {
    UTILITY: 'F2D4CA9F1FC1F7FAE07F275913F7DFC688BFD8570AEE32DE2144EE1EA187F626',
    LOADER: 'AED0DBAC11EB8644EED71F9FAF36C67B2854DE19262A78CC7EA601FA7A3DD99C',
    PRODUCER: 'F5F75D7439B97049B5440695CB78862AA0815D7E1E69224BDBDC2B9AADE2AD01',
    'tools/fixtures/classic_final_image/elf.py': '3A8F4E42B42189CDDAE44DE6AFA4468F24781B6EDFD13F02491C96C1E0729809',
    'tools/fixtures/cm55_tfm_parity/elf.py': '394BA0549C2325BC5BB988EB1A6EBA89263CAF3E351189582931C59A64D5752D',
    'tools/fixtures/cm3_freeze_parity/check.py': 'F0D9CD4F48912FB6E5455AA365BF73FFCF356BAFAD922B3A73ACA992A616A11A',
    'tools/fixtures/cm3_lto_roots/native.py': 'D4BA0378FA50E11A570D40180149794B16EB0807E36DC902C19840E32D1AF05D',
    'tools/fixtures/cm3_reference_lto_roots/reference.py': '3E53C4C0C5030B973A599FBDD0CB0B7FDECC625DEFD8C204A8C9691C5F6A616D',
    'tools/fixtures/cm3_lto_protocol/protocol.py': 'BA3B630BB1FEA67C81D2EE18C84F6D2A47DE9802E8763F52EE55DB34CD65F419',
    'tools/fixtures/cm3_reference_lto_protocol/protocol.py': '200B277D03DF4236FE887907F732BC2A26898D8C15C1544D917B3DC3CF6BF798',
    'tools/fixtures/cm3_reference_lto_transport/probe.py': '1D1FDC0D644123FEF1E182107A8062A0BA9BCCB385DA0C2D13BDFD741290F2C3',
    'tools/fixtures/cm3_reference_lto_transport/admission.py': '27C192C12E30BD4F1A872D6A8586B85C303AF6D6873A85A26238BE7DD4962ECC',
    'tools/fixtures/cm3_lto_roots/mutations.py': '32BDE6CA67B12EEC9975D24D6628C5576EA29F33121CD60310F1F010CF272353',
    'tools/fixtures/cm3_reference_lto_roots/mutations.py': 'E20E55734138E5F9AE76019D3C3EF1260EE708FDF222DC72E5C8B5552E02029C',
    'tools/fixtures/cm3_lto_roots/witness.py': '5BFA66061B9BFAC9B7C6AF872AB831E69613DDDA03C0FA40E439E36273963713',
    'tools/fixtures/cm3_reference_lto_roots/witness.py': '3B9168D52F7AA63339264A8E7B655DF94FF1AC644FF08D20E4B617CED5699B54',
    'tools/fixtures/cm3_lto_protocol/witness.py': '39E1994A74DB225CD3BB2010AE07C49FD1DB2EE2006BCAD2FC59BD3092E6CF51',
    'tools/fixtures/cm3_reference_lto_protocol/witness.py': 'B3968C5C51BCB7DFF13425B6656715DB4FA9674C18503AA04FDE7EA0A0F89D5F',
    'tools/fixtures/cm3_lto_join/join.py': 'F4EF2402495FF90C6D781762EC2B85A458F7DA702F14B2C6A1581D9E09343CE3',
    'tools/fixtures/cm3_os_lto_join/compose.py': '359BB0E7463F4514F5964529702DDC07CCED773927970AC3C246A1B7E845367E',
}
ROLES = ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup', 'Plain', 'MachineDisassembly')


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def need(condition, message):
    if not condition:
        raise ValueError('cm3-os-lto-join: ' + message)


def stable(path):
    return Path(os.path.abspath(os.fspath(path)))


def load(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def interpreter_path():
    if os.name != 'nt':
        return stable(sys.executable)
    buffer = ctypes.create_unicode_buffer(32768)
    function = ctypes.WinDLL('kernel32', use_last_error=True).GetModuleFileNameW
    function.argtypes, function.restype = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32), ctypes.c_uint32
    size = function(None, buffer, len(buffer))
    need(0 < size < len(buffer), 'actual interpreter module path')
    return stable(buffer.value)


class Witness:
    def __init__(self, args):
        data = (ROOT / UTILITY).read_bytes()
        need(sha(data) == FIXED[UTILITY], 'fixed closure utilities')
        self.api = load('os_join_utility', ROOT / UTILITY, data)
        self.watch, self.buffers, self.groups, self.identities = self.api.Closure(), {}, {}, {}
        self.output = self.api.checked_path(args.output_dir, must_exist=False)
        for side in ('Native', 'Reference'):
            prefix = side.lower()
            root = self.api.checked_path(getattr(args, prefix + '_build'))
            receipt = self.api.digest_text(getattr(args, prefix + '_receipt_sha256'))
            manifest = self.api.digest_text(getattr(args, prefix + '_artifacts_sha256'))
            artifacts = self._tree(root, receipt, manifest)
            result = self.watch.structured(root / 'results.json', receipt)
            self._record(side, result)
            inputs = self.watch.structured(root / 'inputs.json', artifacts['inputs.json'])
            need(type(inputs.get('Files')) is list and inputs['Files']
                 and type(inputs.get('Watched')) is list and inputs['Watched'], 'nonempty capture input closure')
            for row in inputs['Files']:
                original, captured = self.api.regular(row['Original']), self.api.regular(row['Captured'])
                digest = self.api.digest_text(row['Sha256'])
                need(captured.is_relative_to(root) and artifacts[captured.relative_to(root).as_posix()] == digest,
                     'captured input/manifest binding')
                raw = self.watch.read(captured, digest)
                need(self.watch.read(original, digest) == raw, 'original/captured input bytes')
                if original.suffix == '.py':
                    self._buffer(original, raw)
                    self._buffer(captured, raw)
            for row in inputs['Watched']:
                self.watch.read(row['Path'], self.api.digest_text(row['Sha256']))
            need(type(result['ClosingFilesVerified']) is int
                 and result['ClosingFilesVerified'] == len(inputs['Watched']), 'literal full closing count')
            translated = SimpleNamespace(output_dir=str(self.output), **{
                prefix + '_build': result['SeedBuild'], prefix + '_receipt_sha256': result['SeedReceiptSha256'],
                prefix + '_artifacts_sha256': result['SeedArtifactsSha256']})
            for relative in (UTILITY, LOADER, 'tools/fixtures/cm3_reference_lto_transport/admission.py'):
                path = ROOT / relative
                self._buffer(path, self.watch.read(path, FIXED[relative]))
            raw_read = Path.read_bytes
            def seed_read(path):
                selected = stable(path)
                if selected.suffix == '.py':
                    need(selected in self.buffers, 'unknown Seed Python source outside authenticated buffers')
                    return self.buffers[selected]
                return raw_read(path)
            with patch.object(Path, 'read_bytes', seed_read):
                if side == 'Native':
                    seed = self.api.Seed(translated)
                else:
                    path = ROOT / 'tools/fixtures/cm3_reference_lto_transport/admission.py'
                    seed = load('os_join_reference_admission', path, self.buffers[path]).Seed(self.api, translated)
            for path, digest in seed.closure.hashes.items():
                self.watch.read(path, digest)
            for path, raw in seed.buffers.items():
                self._buffer(path, raw)
            ledger = seed.inventory / 'inputs/FREERTOS_ASM_PARITY.md'
            need(ledger in seed.originals, 'master ledger must be authenticated seed input')
            master = self.watch.read(ledger, seed.originals[ledger]['Sha256'])
            roles = self._roles(root, artifacts, result)
            self.groups[side] = dict(Root=root, Result=result, Artifacts=artifacts, Seed=seed,
                ReceiptSha256=receipt, ManifestSha256=manifest, Roles=roles,
                Inventory=seed.inventory, MasterLedger=ledger, MasterLedgerBytes=master,
                Package=seed.root / 'python/elftools')
        n, r = self.groups['Native'], self.groups['Reference']
        need(n['Root'] != r['Root'] and n['Inventory'] == r['Inventory']
             and n['MasterLedgerBytes'] == r['MasterLedgerBytes'], 'distinct captures and same captured master ledger')
        files = [row['Path'] for group in self.groups.values() for row in group['Roles'].values()]
        need(len(files) == 14 and all(not path.samefile(other) for i, path in enumerate(files) for other in files[:i]),
             'fourteen physically distinct positive binary roles')
        need(n['Roles']['Machine']['Bytes'] != r['Roles']['Machine']['Bytes'], 'distinct own actual machines')
        for name, digest in FIXED.items():
            path = ROOT / name
            self._buffer(path, self.watch.read(path, digest))
        producer = load('os_join_fixed_producer', ROOT / PRODUCER, self.buffers[ROOT / PRODUCER])
        for side, group in self.groups.items():
            self._commands(side, group, producer)
        self.policy = self.watch.read(ROOT / POLICY, POLICY_SHA)
        self._buffer(Path(__file__).resolve(), self.watch.read(Path(__file__).resolve()))
        denied = {ROOT, *(group['Root'] for group in self.groups.values()), *(path.parent for path in self.watch.hashes)}
        need(not self.output.exists() and all(not self.output.is_relative_to(path) and not path.is_relative_to(self.output)
             for path in denied), 'fresh output outside all authenticated inputs')
        interpreter = self.api.regular(interpreter_path())
        self.watch.read(interpreter)
        need(not self.output.is_relative_to(interpreter.parent) and not interpreter.parent.is_relative_to(self.output),
             'output/interpreter overlap')
        git_rows = [row for row in r['Seed'].commands if row['Label'] == 'reference git rev-parse']
        need(len(git_rows) == 2 and git_rows[0]['Argv'][0] == git_rows[1]['Argv'][0],
             'one seed-authenticated external Git provenance tool')
        self.provenance_git = self.api.regular(git_rows[0]['Argv'][0])
        need(self.provenance_git in r['Seed'].originals and self.provenance_git in self.watch.hashes
             and not self.provenance_git.is_relative_to(self.output)
             and not any(self.provenance_git.is_relative_to(group['Root']) for group in self.groups.values()),
             'Git provenance role must not alias a capture or output role')
        for path in self.watch.hashes:
            self.identities[path] = self._physical(path)
        self.watch.close()
        self.expected = {'results.json', 'artifacts.json'}
        self.report = dict(Status='FAIL', Error=None, Scope='CM3_OS_LTO_SIX_BODY_MECHANISM_JOIN_ONLY',
            Profile='CM3', Mode='Os-lto', Cohort=self.api.COHORT, ReferenceCommit=PIN,
            CanonicalProtocolValidated=False, FinalRootRelocationProof=False,
            Qualification=False, FinalReferenceParity=False, FullABIProof=False, SourceIRProof=False,
            PolicyEquivalence=False, SourceToMachineSemanticProof=False, OriginalTranslationUnitOwnership=False,
            CompleteObjectProof=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
            RequiredCellSatisfied=False, RequiredCellsSatisfied=0, NativeCommandsExecuted=0,
            ProducerCompilersReexecuted=False, MutantsReexecuted=False,
            NonexecutedGitProvenanceTool=dict(Path=str(self.provenance_git),
                Sha256=self.watch.hashes[self.provenance_git], PhysicalIdentity=self.identities[self.provenance_git]),
            Interpreter=dict(ModulePath=str(interpreter), Sha256=self.watch.hashes[interpreter], Version=sys.version))

    def _physical(self, path):
        info = self.api.regular(path).stat()
        # Packaged Git may share an installed inode. It is provenance data here,
        # never executed or used as an ELF provider; its identity still closes.
        need(info.st_nlink >= 1 and (info.st_nlink == 1 or path == self.provenance_git),
             'unexpected hard-linked input/output: ' + str(path))
        return info.st_dev, info.st_ino, info.st_nlink

    def _buffer(self, path, data):
        path = stable(path)
        need(path not in self.buffers or self.buffers[path] == data, 'conflicting immutable source buffer')
        self.buffers[path] = data

    def _tree(self, root, receipt, manifest):
        rows = self.watch.structured(root / 'artifacts.json', manifest)['Artifacts']
        need(type(rows) is dict and rows and rows.get('results.json') == receipt, 'caller receipt/manifest binding')
        for name, digest in rows.items():
            self.api.portable_name(name)
            self.api.digest_text(digest)
        self.watch.tree(root, dict(rows, **{'artifacts.json': manifest}))
        return rows

    def _record(self, side, row):
        count = 9 if side == 'Native' else 4
        self.api.same([row.get(key) for key in ('Status', 'Scope', 'Profile', 'Mode', 'SeedMode', 'SeedSide', 'Cohort',
            'Linkage', 'TranslationUnits', 'SlimIRObjects', 'FinalExecutableLinks', 'SavedMachineObjects')],
            ['PASS', ('NATIVE' if side == 'Native' else 'PINNED_REFERENCE') + '_CM3_OS_LTO_CAPTURE_FEASIBILITY_ONLY',
             'CM3', 'Os-lto', 'O2', side, self.api.COHORT, 'direct', count, count - 1, 2, 2], 'exact Os capture scope')
        need(row.get('Error') is None and row.get('LTO') is True, 'successful genuine LTO capture')
        for name in ('InputClosureVerified', 'OutputSealVerified', 'TwinLoadImageCompared',
                     'TwinLoadImageIdentical', 'TwinAllocatedSectionsIdentical'):
            need(row.get(name) is True, 'literal closed capture marker: ' + name)
        for name in ('Qualification', 'CanonicalProtocolValidated', 'FinalRootRelocationProof', 'FinalReferenceParity',
                     'FullABIProof', 'PolicyEquivalence', 'SourceIRProof', 'SourceToMachineSemanticProof',
                     'OriginalTranslationUnitOwnership', 'CompleteObjectProof', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified'):
            need(row.get(name) is False, 'literal capture nonclaim: ' + name)
        need(type(row.get('RequiredCellsSatisfied')) is int and row['RequiredCellsSatisfied'] == 0
             and row.get('RequiredCellSatisfied') is False, 'zero qualification credit')
        producer = row['CaptureProducer']
        need(self.api.regular(producer['Path']) == ROOT / PRODUCER and producer['Sha256'] == FIXED[PRODUCER],
             'fixed actual Os capture producer')
        self.api.same(row['OptimizationTransform'], dict(Original='-O2', Captured='-Os', OtherSeedFlagsUnchanged=True),
                      'exact capture optimization transform')
        if side == 'Reference':
            need(row.get('ReferenceCommit') == PIN and row.get('ReferenceBuilt') is True, 'pinned actual reference capture')

    def _roles(self, root, artifacts, result):
        self.api.same([row['Kind'] for row in result['Links']], ['ordinary', 'emit-relocs'], 'ordered actual twins')
        emit = root / 'emit-relocs'
        paths = dict(Machine=emit / 'image.elf.ltrans0.ltrans.o', Final=emit / 'image.elf',
            Disassembly=emit / 'image.elf.dis', LinkMap=emit / 'image.map',
            Startup=Path(result['Sources'][-1]['Object']), Plain=root / 'ordinary/image.elf',
            MachineDisassembly=emit / 'image.elf.ltrans0.ltrans.o.dis')
        rows = {}
        for role, path in paths.items():
            path = self.api.regular(path)
            need(path.is_relative_to(root), 'fixed binary role escaped capture')
            digest = artifacts[path.relative_to(root).as_posix()]
            rows[role] = dict(Path=path, Sha256=digest, Bytes=self.watch.read(path, digest))
        return rows

    def _commands(self, side, group, producer):
        root, result, seed = group['Root'], group['Result'], group['Seed']
        artifacts = group['Artifacts']
        records = result['Commands']
        need(type(records) is list and len(records) == (57 if side == 'Native' else 37), 'complete capture command count')
        self.api.same(self.watch.structured(root / 'commands.json', artifacts['commands.json']), records,
                      'recorded complete command catalog')
        tool_root = root / 'toolchain'
        expected_tools = {tool_root / path.relative_to(seed.tool_root): row['Sha256']
                          for path, row in seed.originals.items() if path.is_relative_to(seed.tool_root)}
        need(set(self.api.files_under(tool_root).values()) == set(expected_tools), 'exact cloned toolchain membership')
        for path, digest in expected_tools.items():
            self.watch.read(path, digest)
        gcc = tool_root / seed.gcc.relative_to(seed.tool_root)
        plugin = tool_root / seed.plugin.relative_to(seed.tool_root)
        workers = {name: tool_root / path.relative_to(seed.tool_root) for name, path in seed.workers.items()}
        self.api.same(result['CapturedCompiler'], str(gcc), 'actual cloned compiler identity')
        self.api.same(result['ResolvedWorkers'], {name: dict(Path=str(path), Sha256=expected_tools[path])
                      for name, path in workers.items()}, 'exact captured workers')
        self.api.same(result['LTOPlugin'], dict(Path=str(plugin), Sha256=expected_tools[plugin]), 'actual cloned plugin')
        environment = self.watch.structured(root / 'environment.json', artifacts['environment.json'])
        need(type(environment) is dict and all(type(k) is str and type(v) is str for k, v in environment.items()),
             'literal captured command environment')
        need(environment.get('TEMP') == environment.get('TMP') == str(root / 'tmp'), 'private captured temporary environment')
        self.api.same(seed.native.process_environment(environment), environment, 'frozen environment sanitation policy')
        search = [str(gcc.parent), *(str(path.parent) for path in workers.values())]
        system = next((value for key, value in environment.items() if key.upper() == 'SYSTEMROOT'), None)
        if system:
            search.append(str(Path(system) / 'System32'))
        need(environment.get('PATH') == os.pathsep.join(dict.fromkeys(search)), 'canonical captured compiler/worker/system PATH')
        expected, stdout_bindings = [], {}

        def command(label, argv, cwd=root, stdout=None):
            index = len(expected)
            expected.append((label, [str(value) for value in argv], str(cwd)))
            if stdout is not None:
                stdout_bindings[index] = stdout

        for name, path in workers.items():
            command('resolve ' + name, [gcc, '-print-prog-name=' + name])
        command('resolve LTO plugin', [gcc, '-print-file-name=' + plugin.name])

        def inspect(path):
            for tool, flags, suffix in (
                ('readelf', ['-hSWsrA', '-lW'], '.readelf'),
                ('objdump', ['-drwC', '-Mreg-names-std'], '.dis'),
                ('nm', ['--plugin', str(plugin), '-P', '-S', '--defined-only'], '.nm')):
                command('inspect ' + path.name + suffix,
                        [gcc.with_name('arm-none-eabi-' + tool + '.exe'), *flags, path],
                        stdout=Path(str(path) + suffix))

        count = 9 if side == 'Native' else 4
        need(type(result['Sources']) is list and len(result['Sources']) == count, 'exact capture source count')
        objects = []
        for index, (row, original) in enumerate(zip(result['Sources'], seed.sources)):
            source = self.api.regular(original['Source'])
            obj = root / 'objects' / ('%02d-' % index + source.stem + '.o')
            dependency = obj.with_suffix('.d')
            flags = producer.startup_flags(original['CompileFlags']) if index == count - 1 else producer.mode_flags(original['CompileFlags'])
            self.api.same([row['Source'], row['SourceSha256'], row['CompileFlags'], row['SeedCompileFlags'],
                row['Object'], row['DependencyFile'], row['SlimIR'], row['CompileDependenciesVerified']],
                [str(source), original['SourceSha256'], flags, original['CompileFlags'], str(obj), str(dependency),
                 index != count - 1, True], 'exact source/Os flags/startup binding')
            raw = self.watch.read(obj, row['ObjectSha256'])
            header = self.api.require_elf32le(raw)
            self.api.same(row['ELFHeader'], header, 'actual input ELF header metadata')
            sections = self.api.section_records(self.watch.read(Path(str(obj) + '.readelf')).decode('utf-8'))
            self.api.same(row['Sections'], sections, 'actual complete input section metadata')
            self.api.same([item['Index'] for item in sections], list(range(header['SectionCount'])), 'all source sections')
            if index != count - 1:
                need(any(item['Name'].startswith('.gnu.lto_') for item in sections)
                     and not any(item['Size'] and 'X' in item['Flags'] for item in sections), 'slim IR without fat fallback')
            else:
                need(not any(item['Name'].startswith('.gnu.lto_') for item in sections), 'non-LTO startup')
            dep_bytes = self.watch.read(dependency)
            def dependency_text(path, encoding=None, errors=None):
                need(stable(path) == dependency and encoding == 'utf-8' and errors is None, 'only authenticated dependency text')
                return dep_bytes.decode('utf-8')
            with patch.object(Path, 'read_text', dependency_text):
                actual = set(seed.native.read_dependencies(dependency))
            declared = {self.api.regular(item['Path']) for item in original['Dependencies']}
            declared = {tool_root / path.relative_to(seed.tool_root) if path.is_relative_to(seed.tool_root) else path for path in declared}
            need(actual == declared and all(path in self.watch.hashes for path in actual), 'same exact admitted actual dependencies')
            self.api.same(row['ActualCompileDependencies'], [dict(Path=str(path), Sha256=self.watch.hashes[path])
                          for path in sorted(actual)], 'actual dependency hashes')
            command('compile ' + source.name, [gcc, *flags, '-MD', '-MF', dependency,
                    '-MT', 'pilot-source-' + str(index), '-c', source, '-o', obj])
            inspect(obj)
            objects.append(obj)
        for kind, emit in (('ordinary', False), ('emit-relocs', True)):
            directory = root / kind
            image, link_map = directory / 'image.elf', directory / 'image.map'
            machine = directory / 'image.elf.ltrans0.ltrans.o'
            flags = producer.link_flags(self.api, seed.artifact, objects, seed.script, image, link_map, emit)
            command('link ' + kind, [gcc, *flags], directory)
            inspect(machine)
            inspect(image)
            row = result['Links'][0 if kind == 'ordinary' else 1]
            self.api.same([row['Path'], row['Machine'], row['Map']], [str(image), str(machine), str(link_map)], 'exact link outputs')
            self.watch.read(image, row['Sha256'])
            raw = self.watch.read(machine, row['MachineSha256'])
            self.watch.read(link_map, row['MapSha256'])
            self.api.same(row['MachineHeader'], self.api.require_elf32le(raw), 'actual saved machine ELF32LE')
            self.api.same(row['FinalHeader'], self.api.require_elf32le(self.watch.read(image), 'EXEC'), 'actual final ELF32LE')
            need({path for path in directory.iterdir() if path.name.startswith('image.elf.ltrans')
                  and path.name.endswith('.ltrans.o')} == {machine}, 'sole actual machine partition')
            self.api.same({name: sha(self.watch.read(path)) for name, path in self.api.files_under(directory).items()},
                          row['EntireDirectoryArtifacts'], 'complete raw link artifact membership')
        need(len(expected) == len(records), 'exact reconstructed command count')
        for index, (row, (label, argv, cwd)) in enumerate(zip(records, expected)):
            self.api.same([row['Label'], row['Argv'], row['Cwd']], [label, argv, cwd], 'ordered actual command binding')
            need(row['Status'] == 'PASS' and type(row['Exit']) is int and row['Exit'] == 0
                 and row['TimedOut'] is False and row.get('Error') is None, 'literal successful terminal command')
            need(type(row.get('Seconds')) in (int, float) and math.isfinite(row['Seconds']) and row['Seconds'] >= 0,
                 'finite nonnegative literal command duration')
            target = root / ('command-%04d.json' % index)
            self.api.same(self.watch.structured(target), row, 'actual terminal sidecar record')
            stdout = self.watch.read(target.with_suffix('.stdout'))
            self.watch.read(target.with_suffix('.stderr'))
            if index in stdout_bindings:
                need(stdout == self.watch.read(stdout_bindings[index]), 'inspector stdout/actual metadata artifact bytes')
            elif index < 7:
                path = list(workers.values())[index] if index < 6 else plugin
                need(self.api.regular(stdout.decode('utf-8').strip()) == path, 'recorded worker/plugin resolution bytes')
        self.api.same(result['ObjectChecks'], [dict(Stage=name, Status='PASS') for name in
            ('after-compile', 'before-link-ordinary', 'after-link-ordinary', 'before-link-emit-relocs',
             'after-link-emit-relocs', 'closing')], 'exact ordered object checkpoints')
        group['CommandsReconstructed'] = len(expected)

    def declare(self, path):
        path = stable(path)
        need(path.is_relative_to(self.output), 'declared output escaped witness')
        name = path.relative_to(self.output).as_posix()
        need(name not in self.expected, 'duplicate output declaration')
        self.expected.add(name)

    def close(self):
        self.watch.close()
        for group in self.groups.values():
            group['Seed'].closure.close()
        for path, identity in self.identities.items():
            need(self._physical(path) == identity, 'input physical identity drift: ' + str(path))

    def _bind_control_files(self, controls):
        for control in controls:
            for row in control['Files']:
                path = self.api.regular(row['Path'])
                need(path.is_relative_to(self.output / 'controls')
                     and path.relative_to(self.output).as_posix() in self.expected,
                     'control file must be a predetermined private output')
                self.watch.read(path, self.api.digest_text(row['Sha256']))
                identity = self._physical(path)
                recorded = row.get('PhysicalIdentity')
                if recorded is not None:
                    need(type(recorded) is dict and all(type(recorded.get(key)) is int
                         for key in ('Device', 'FileId', 'Links'))
                         and tuple(recorded[key] for key in ('Device', 'FileId', 'Links')) == identity,
                         'control-returned physical identity must match its actual file')
                need(path not in self.identities or self.identities[path] == identity,
                     'control physical identity changed before outer binding')
                self.identities[path] = identity

    def _read(self):
        loader = load('os_join_loader', ROOT / LOADER, self.buffers[ROOT / LOADER])
        graph = loader.FrozenSources(self.buffers)
        packages = []
        for group in self.groups.values():
            package = group['Package']
            members = {path.relative_to(package).as_posix(): sha(data) for path, data in self.buffers.items()
                       if path.is_relative_to(package)}
            need('__init__.py' in members, 'complete captured parser source package')
            packages.append((package, members))
        self.api.same(packages[0][1], packages[1][1], 'identical captured parser packages')
        modules = {}
        for path in self.buffers:
            if path.is_relative_to(packages[0][0]):
                parts = list(path.relative_to(packages[0][0].parent).with_suffix('').parts)
                is_package = parts[-1] == '__init__'
                if is_package:
                    parts.pop()
                name = '.'.join(parts)
                need(name not in modules, 'unique parser source module')
                modules[name] = path, is_package
        need(not any(name == 'elftools' or name.startswith('elftools.') for name in sys.modules),
             'initially unimported captured parser package')
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

        snapshots = {stable(path): data for path, data in self.buffers.items()}
        source_copies, binary_copies = [], []
        for index, (path, data) in enumerate(sorted(self.buffers.items())):
            target = self.output / 'source-buffers' / ('%04d-' % index + path.name)
            self.declare(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            self.watch.read(target, sha(data))
            source_copies.append(dict(Original=str(path), Captured=str(target), Sha256=sha(data)))
        for side, group in self.groups.items():
            for role, row in group['Roles'].items():
                path = row['Path']
                target = self.output / 'binary-inputs' / (side + '-' + role + path.suffix)
                self.declare(target)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(row['Bytes'])
                self.watch.read(target, row['Sha256'])
                snapshots[stable(path)] = row['Bytes']
                binary_copies.append(dict(Side=side, Role=role, Original=str(path), Captured=str(target), Sha256=row['Sha256']))
            twin_path = self.api.regular(group['Result']['TwinLoadImagesPath'])
            need(twin_path == group['Root'] / 'load-image.json', 'fixed structured twin evidence path')
            twin_sha = group['Artifacts']['load-image.json']
            need(twin_sha == group['Result']['TwinLoadImagesSha256'], 'twin evidence/manifest binding')
            snapshots[stable(twin_path)] = self.watch.read(twin_path, twin_sha)
        for name, data in (('MasterLedger.md', self.groups['Native']['MasterLedgerBytes']), ('PolicyLedger.md', self.policy)):
            target = self.output / 'ledgers' / name
            self.declare(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            self.watch.read(target, sha(data))

        raw_read = Path.read_bytes
        mutable = set()
        catalogs = {}
        # Every writable reader input is fixed before any private control runs.
        for side in ('Native', 'Reference'):
            relative = 'cm3_lto_roots' if side == 'Native' else 'cm3_reference_lto_roots'
            module = graph.load('os_join_catalog_' + side, ROOT / ('tools/fixtures/' + relative + '/mutations.py'))
            catalogs[side] = module
            need(type(module.CASES) is tuple and len(module.CASES) == 16, 'fixed sixteen-case catalog')
            group = self.groups[side]
            for name, expected in module.CASES:
                for role in ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup'):
                    path = self.output / 'controls' / side / 'mutants' / name / (role + group['Roles'][role]['Path'].suffix)
                    self.declare(path)
                    mutable.add(stable(path))
            for role in ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup', 'MachineDisassembly'):
                path = self.output / 'controls' / side / 'protocol-mutants/coherent-svc-immediate' / (role + group['Roles'][role]['Path'].suffix)
                self.declare(path)
                mutable.add(stable(path))

        def fixed_read(path):
            key = stable(path)
            if key in snapshots:
                return snapshots[key]
            need(key in mutable and Path(path).is_absolute() and Path(path) == key,
                 'unknown reader input outside immutable or predetermined private buffers')
            return raw_read(path)
        def fixed_text(path, encoding=None, errors=None, newline=None):
            need(newline is None and encoding in (None, 'ascii', 'utf-8') and errors in (None, 'strict'), 'exact reader text decoding')
            return fixed_read(path).decode(encoding or 'utf-8', errors or 'strict')
        previous = list(sys.meta_path)
        recomputed, views, controls = {}, {}, {}
        try:
            sys.meta_path.insert(0, Finder())
            with graph.active(), patch.object(Path, 'read_bytes', fixed_read), patch.object(Path, 'read_text', fixed_text), \
                    patch('subprocess.Popen', side_effect=AssertionError('witness cannot execute processes')), \
                    patch('os.system', side_effect=AssertionError('witness cannot execute shell commands')):
                core = graph.load('os_join_core', ROOT / 'tools/fixtures/classic_final_image/elf.py')
                decoder = graph.load('os_join_decoder', ROOT / 'tools/fixtures/cm55_tfm_parity/elf.py')
                checker = graph.load('os_join_checker', ROOT / 'tools/fixtures/cm3_freeze_parity/check.py')
                frozen_join = graph.load('os_join_frozen_predicates', ROOT / 'tools/fixtures/cm3_lto_join/join.py')
                compose = graph.load('os_join_composition', HERE / 'compose.py')
                for side, folder, protocol_folder in (
                    ('Native', 'cm3_lto_roots', 'cm3_lto_protocol'),
                    ('Reference', 'cm3_reference_lto_roots', 'cm3_reference_lto_protocol')):
                    group = self.groups[side]
                    roles = {role: row['Path'] for role, row in group['Roles'].items()}
                    adapter = graph.load('os_join_adapter_' + side,
                        ROOT / ('tools/fixtures/' + folder + ('/native.py' if side == 'Native' else '/reference.py')))
                    protocol = graph.load('os_join_protocol_' + side, ROOT / ('tools/fixtures/' + protocol_folder + '/protocol.py'))
                    factory = adapter.NativeCM3LTOImage if side == 'Native' else adapter.ReferenceCM3LTOImage
                    image = factory(core, roles['Machine'], roles['Final'], roles['Disassembly'],
                        provider_objects={str(roles['Machine']): roles['Machine'], str(roles['Startup']): roles['Startup']},
                        link_map=roles['LinkMap'])
                    roots = [image.function(name) for name in adapter.ROOTS]
                    need(len(roots) == 3 and all(row['GeneratedMachineBoundRootPreservation'] is True
                         and row['CanonicalProtocolValidated'] is False for row in roots), 'three complete emit-only transport roots')
                    decoded = decoder.Object(roles['Machine'], roles['MachineDisassembly'])
                    view = protocol.NativeProtocolView if side == 'Native' else protocol.ReferenceProtocolView
                    views[side] = view(decoded, image)
                    twins = core.compare_load_images(roles['Plain'], roles['Final'])
                    self.api.same(twins, group['Result']['TwinLoadImages'], 'fresh own-side structured load twins')
                    twin_path = self.api.regular(group['Result']['TwinLoadImagesPath'])
                    need(twin_path == group['Root'] / 'load-image.json', 'fixed structured twin evidence path')
                    need(sha(fixed_read(twin_path)) == group['Result']['TwinLoadImagesSha256'], 'captured twin evidence hash')
                    self.api.same(json.loads(fixed_read(twin_path), object_pairs_hook=self.api.unique_object), twins,
                                  'captured structured twin value')
                    recomputed[side] = dict(Roots=roots, Twins=twins, OrdinaryRootPreservationProven=False)
                    inputs = {role: roles[role] for role in ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup')}
                    cases = catalogs[side].run_cases(core, adapter, image, inputs, self.output / 'controls' / side)
                    self.api.same([(row['Name'], row['Expected']) for row in cases], list(catalogs[side].CASES), 'complete fixed control catalog')
                    need(all(row['Status'] == 'PASS' and row['ImmutableInputBuffersConsumed'] is True
                         and type(row['ClosingFilesVerified']) is int and row['ClosingFilesVerified'] == 5
                         and len(row['Files']) == 5 and row['Edits'] for row in cases), 'all sixteen actual private controls must reject')
                    self._bind_control_files(cases)
                    canonical_module = graph.load('os_join_canonical_control_' + side,
                        ROOT / ('tools/fixtures/' + protocol_folder + '/witness.py'))
                    control_type = canonical_module.witness_type()
                    def declared(path):
                        need(stable(path).relative_to(self.output).as_posix() in self.expected, 'predetermined canonical control output')
                    facade = SimpleNamespace(output=self.output / 'controls' / side, watch=self.watch,
                        report={}, declare=declared, declare_output=declared)
                    private_roles = {role: roles[role] for role in ('Machine', 'Final', 'Disassembly', 'LinkMap', 'Startup', 'MachineDisassembly')}
                    control_type._constant_control(facade, core, adapter, decoder, checker, protocol, private_roles, snapshots, image)
                    canonical = facade.report['ProtocolControls']
                    need(len(canonical) == 1 and canonical[0]['Status'] == 'PASS'
                         and canonical[0]['TransportPreservationAccepted'] is True
                         and canonical[0]['ImmutableInputBuffersConsumed'] is True
                         and type(canonical[0]['ClosingFilesVerified']) is int and canonical[0]['ClosingFilesVerified'] == 6,
                         'actual coherent SVC drift must preserve transport but fail canonical protocol')
                    self._bind_control_files(canonical)
                    controls[side] = dict(Transport=cases, Canonical=canonical)
                proof = compose.check_join(views['Native'], views['Reference'], checker,
                    self.groups['Native']['MasterLedgerBytes'].decode('ascii'), frozen_join)
                policy_rationales = frozen_join.require_ledger(self.policy.decode('ascii'), proof['ProtocolProof'])
            self.report.update(JoinProof=proof, RecomputedSides=recomputed, Controls=controls,
                PolicyDifferenceRationales=policy_rationales,
                MasterLedgerSha256=sha(self.groups['Native']['MasterLedgerBytes']), PolicyLedgerSha256=sha(self.policy),
                CapturedSourceBuffers=source_copies, BinaryInputs=binary_copies, ExecutedSourceBuffers=graph.executed,
                ImmutableInputsConsumed=True, TransportControlsExecuted=32, CanonicalControlsExecuted=2,
                MutantsReexecuted=True, ProducerBindings=[dict(Side=side, Build=str(group['Root']),
                    ReceiptSha256=group['ReceiptSha256'], ArtifactsSha256=group['ManifestSha256'],
                    CommandsReconstructed=group['CommandsReconstructed']) for side, group in self.groups.items()])
        finally:
            sys.meta_path[:] = previous
        for path in mutable:
            need(path.is_file(), 'all predetermined private artifacts must exist')
            self.watch.read(path)
        for path in self.watch.hashes:
            if path not in self.identities:
                self.identities[path] = self._physical(path)

    def _seal(self):
        success = self.report['Status'] == PASS
        if success:
            members = set(self.api.files_under(self.output)) - {'results.json', 'artifacts.json'}
            planned = self.expected - {'results.json', 'artifacts.json'}
            self.report.update(UnexpectedOutputMembers=sorted(members - planned), MissingDeclaredOutputMembers=sorted(planned - members))
            need(members == planned, 'predetermined output membership')
        self.report['OutputSealVerified'] = True
        # api.save uses ASCII write_text with the platform's newline translation.
        intended_receipt = (json.dumps(self.report, indent=2, sort_keys=True) + '\n').replace('\n', os.linesep).encode('ascii')
        self.api.save(self.output / 'results.json', self.report)
        need((self.output / 'results.json').read_bytes() == intended_receipt,
             'written receipt bytes differ from intended serialized report')
        self.sealed = {name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items()
                       if name not in ('artifacts.json', 'results.json')}
        self.sealed['results.json'] = sha(intended_receipt)
        if success:
            need(set(self.sealed) == self.expected - {'artifacts.json'}, 'exact planned artifact membership')
        manifest = dict(Artifacts=self.sealed)
        self.api.save(self.output / 'artifacts.json', manifest)
        raw = (self.output / 'artifacts.json').read_bytes()
        self.api.same(json.loads(raw, object_pairs_hook=self.api.unique_object), manifest, 'written artifact manifest value')
        self.manifest_sha = sha(raw)
        self.api.same({name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items()
                       if name != 'artifacts.json'}, self.sealed, 'post-manifest output closure')

    def _fail(self, error):
        self.report.update(Status='FAIL', Error=(self.report.get('Error') or '') + '; ' + str(error),
            InputClosureVerified=False, CanonicalProtocolValidated=False, FinalRootRelocationProof=False,
            ImmutableInputsConsumed=False, OutputSealVerified=False)

    def run(self):
        self.output.mkdir(parents=True)
        try:
            self._read()
            self.close()
            self.report.update(Status=PASS, InputClosureVerified=True, ClosingFilesVerified=len(self.watch.hashes),
                CanonicalProtocolValidated=True, FinalRootRelocationProof=True)
        except BaseException as error:
            self._fail(type(error).__name__ + ': ' + str(error))
        self.report['InputHashes'] = {str(path): value for path, value in sorted(self.watch.hashes.items())}
        try:
            self._seal()
            self.close()
            self.api.same({name: sha(path.read_bytes()) for name, path in self.api.files_under(self.output).items()
                           if name != 'artifacts.json'}, self.sealed, 'late complete output closure')
            need(sha((self.output / 'artifacts.json').read_bytes()) == self.manifest_sha, 'late artifact manifest drift')
        except BaseException as error:
            self._fail('closing: ' + str(error))
            try:
                self._seal()
            except BaseException as closing:
                self.report.update(OutputSealVerified=False, SealError=str(closing))
                self.api.save(self.output / 'results.json', self.report)
                self.api.save(self.output / 'artifacts.json', dict(Artifacts={name: sha(path.read_bytes())
                    for name, path in self.api.files_under(self.output).items() if name != 'artifacts.json'}))
        return self.report['Status'] == PASS


def main(argv=None):
    need(not sys.flags.optimize and __debug__, 'unoptimized interpreter required')
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('native-build', 'native-receipt-sha256', 'native-artifacts-sha256',
                 'reference-build', 'reference-receipt-sha256', 'reference-artifacts-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    witness = Witness(parser.parse_args(argv))
    passed = witness.run()
    print(witness.report['Status'], witness.report.get('Error') or '', str(witness.output))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
