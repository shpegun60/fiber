"""Compose native CM3 LTO protocols; no reference image, tools or targets."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import re
import sys
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE = HERE.with_name('cm3_lto_roots') / 'witness.py'
BASE_SHA = '5BFA66061B9BFAC9B7C6AF872AB831E69613DDDA03C0FA40E439E36273963713'
NATIVE_SHA = 'D4BA0378FA50E11A570D40180149794B16EB0807E36DC902C19840E32D1AF05D'
MUTATIONS_SHA = '32BDE6CA67B12EEC9975D24D6628C5576EA29F33121CD60310F1F010CF272353'
CHECKER_SHA = 'F0D9CD4F48912FB6E5455AA365BF73FFCF356BAFAD922B3A73ACA992A616A11A'
DECODER_SHA = '394BA0549C2325BC5BB988EB1A6EBA89263CAF3E351189582931C59A64D5752D'


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def need(condition, message):
    if not condition:
        raise ValueError('cm3-lto-protocol-witness: ' + message)


def load(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def witness_type():
    base_bytes = BASE.read_bytes()
    need(sha(base_bytes) == BASE_SHA, 'fixed complete machine-root envelope required')
    base = load('cm3_lto_protocol_frozen_root_witness', BASE, base_bytes)

    class Witness(base.Witness):
        def __init__(self, args):
            super().__init__(args)
            for path, expected in ((BASE, BASE_SHA), (BASE.parent / 'native.py', NATIVE_SHA),
                                   (BASE.parent / 'mutations.py', MUTATIONS_SHA)):
                need(sha(self.buffers[path]) == expected, 'fixed root implementation source cohort')
            for path in (Path(__file__).resolve(), HERE / 'protocol.py'):
                self.buffers[path] = self.watch.read(path)
            self.checker = Path(self.result['SeedBuild']) / 'source/tools/fixtures/cm3_freeze_parity/check.py'
            self.decoder = Path(self.result['SeedBuild']) / 'source/tools/fixtures/cm55_tfm_parity/elf.py'
            need(sha(self.buffers[self.checker]) == CHECKER_SHA and sha(self.buffers[self.decoder]) == DECODER_SHA,
                 'unchanged captured canonical checker and decoder required')
            self.report.update(Scope='NATIVE_CM3_O2_LTO_MACHINE_AND_CANONICAL_PROTOCOL_COMPOSITION_ONLY',
                               FinalReferenceParity=False, FullABIProof=False)

        def _read_roots(self):
            super()._read_roots()
            link = self.result['Links'][1]
            roles = {row['Role']: Path(row['Original']) for row in self.report['BinaryInputs'] if row['Role'] != 'Plain'}
            machine_dis = Path(str(roles['Machine']) + '.dis')
            need(machine_dis.is_relative_to(self.root), 'fixed saved-machine disassembly input')
            expected = self.artifacts[machine_dis.relative_to(self.root).as_posix()]
            machine_dis_bytes = self.watch.read(machine_dis, expected)
            target = self.output / 'protocol-inputs/MachineDisassembly.dis'
            self.declare_output(target)
            target.parent.mkdir(parents=True)
            target.write_bytes(machine_dis_bytes)
            self.watch.read(target, expected)
            self.report['MachineDisassemblyInput'] = dict(Original=str(machine_dis), Captured=str(target), Sha256=expected)
            roles['MachineDisassembly'] = machine_dis
            binaries = {base.stable_path(path): self.watch.read(path, self.artifacts[path.relative_to(self.root).as_posix()])
                        for path in roles.values()}
            loader = load('cm3_lto_protocol_immutable_loader', base.LOADER, self.buffers[base.LOADER])
            graph = loader.FrozenSources(self.buffers)
            snapshots = {base.stable_path(path): data for path, data in self.buffers.items()}
            snapshots.update(binaries)
            def fixed_read(path):
                key = base.stable_path(path)
                need(key in snapshots, 'unknown canonical reader input')
                return snapshots[key]
            def fixed_text(path, encoding=None, errors=None, newline=None):
                need(newline is None and encoding in (None, 'utf-8', 'ascii') and errors in (None, 'strict'),
                     'exact canonical text decoding required')
                return fixed_read(path).decode(encoding or 'utf-8', errors or 'strict')
            with graph.active(), patch.object(Path, 'read_bytes', fixed_read), patch.object(Path, 'read_text', fixed_text):
                core = graph.load('cm3_lto_protocol_core', self.core_path)
                adapter = graph.load('cm3_lto_protocol_machine_transport', BASE.parent / 'native.py')
                decoder = graph.load('cm3_lto_protocol_decoder', self.decoder)
                checker = graph.load('cm3_lto_protocol_checker', self.checker)
                protocol = graph.load('cm3_lto_protocol_projection', HERE / 'protocol.py')
                image = adapter.NativeCM3LTOImage(core, roles['Machine'], roles['Final'], roles['Disassembly'],
                    provider_objects={str(roles['Machine']): roles['Machine'], str(roles['Startup']): roles['Startup']},
                    link_map=roles['LinkMap'])
                decoded = decoder.Object(roles['Machine'], roles['MachineDisassembly'])
                proof = protocol.check_native(decoded, image, checker)
                self.api.same({row['Name']: row['TransportRecord'] for row in proof['Roots']},
                              {row['Name']: row for row in self.report['Roots']}, 'protocol/transport exact root binding')
            self.report.update(ProtocolProof=proof, CanonicalProtocolValidated=True,
                               ProtocolExecutedSourceBuffers=graph.executed)
            self._constant_control(core, adapter, decoder, checker, protocol, roles, binaries, image)

        def _constant_control(self, core, adapter, decoder, checker, protocol, roles, binaries, image):
            directory = self.output / 'protocol-mutants/coherent-svc-immediate'
            directory.mkdir(parents=True)
            paths, edits = {}, []
            for role, original in roles.items():
                path = directory / (role + original.suffix)
                self.declare_output(path)
                path.write_bytes(binaries[base.stable_path(original)])
                paths[role] = path
            addresses = {}
            for role, elf in (('Machine', image.machine), ('Final', image.final)):
                symbol = image._symbol(elf, 'fiber_port_start_first_context')
                address = (symbol['value'] & ~1) + 82
                section = elf.sections[symbol['section']].header
                offset = section.sh_offset + address - (section.sh_addr if elf.final else 0)
                data = paths[role].read_bytes()
                need(data[offset:offset + 2] == b'\x46\xdf', 'actual SVC70 field required')
                paths[role].write_bytes(data[:offset] + b'\x47\xdf' + data[offset + 2:])
                addresses[role] = address
                edits.append(dict(Role=role, FileOffset=offset, Before='46df', After='47df'))
            for role, binary in (('MachineDisassembly', 'Machine'), ('Disassembly', 'Final')):
                data = paths[role].read_bytes()
                pattern = (r'(?m)^(\s*' + format(addresses[binary], 'x') + r':\s+)df46(\s+svc\s+)70(\s*@\s*)0x46')
                changed, count = re.subn(pattern, r'\g<1>df47\g<2>71\g<3>0x47', data.decode('ascii'))
                need(count == 1, 'exact coherent disassembly SVC field')
                paths[role].write_bytes(changed.encode('ascii'))
                edits.append(dict(Role=role, BeforeSha256=sha(data), AfterSha256=sha(changed.encode('ascii'))))
            buffers = {base.stable_path(path): path.read_bytes() for path in paths.values()}
            record = dict(Name='coherent-svc-immediate', Status='FAIL', Edits=edits,
                Expected='CM3-CLOSED-ROOTS', TwinComparisonExecuted=False, SourceAuthorityPreserved=False,
                Files=[dict(Role=role, Path=str(path), Sha256=sha(buffers[base.stable_path(path)])) for role, path in paths.items()])
            self.report['ProtocolControls'] = [record]
            def fixed_read(path):
                key = base.stable_path(path)
                need(key in buffers, 'unknown private canonical reader input')
                return buffers[key]
            def fixed_text(path, encoding=None, errors=None, newline=None):
                need(newline is None and encoding in (None, 'utf-8', 'ascii') and errors in (None, 'strict'), 'private text decoding')
                return fixed_read(path).decode(encoding or 'utf-8', errors or 'strict')
            rejected = False
            with patch.object(Path, 'read_bytes', fixed_read), patch.object(Path, 'read_text', fixed_text):
                changed = adapter.NativeCM3LTOImage(core, paths['Machine'], paths['Final'], paths['Disassembly'],
                    provider_objects={str(roles['Machine']): paths['Machine'], str(roles['Startup']): paths['Startup']},
                    link_map=paths['LinkMap'])
                preserved = [changed.function(name) for name in adapter.ROOTS]
                record['TransportPreservationAccepted'] = len(preserved) == 3
                try:
                    protocol.check_native(decoder.Object(paths['Machine'], paths['MachineDisassembly']), changed, checker)
                except checker.Rejected as error:
                    record['Rejection'] = str(error)
                    rejected = str(error).startswith('REJECT:CM3-CLOSED-ROOTS:Native/fiber_port_start_first_context/')
            need(rejected and record['TransportPreservationAccepted'], 'preserved actual constant drift must fail canonical protocol')
            need(all(path.read_bytes() == data for path, data in buffers.items())
                 and {base.stable_path(path) for path in directory.iterdir()} == set(buffers), 'private canonical artifact closure')
            for row in record['Files']:
                self.watch.read(row['Path'], row['Sha256'])
            record.update(Status='PASS', ImmutableInputBuffersConsumed=True, ClosingFilesVerified=6)

    return Witness


def main(argv=None):
    need(not sys.flags.optimize, 'unoptimized interpreter required')
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('capture-build', 'capture-receipt-sha256', 'capture-artifacts-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    witness = witness_type()(parser.parse_args(argv))
    passed = witness.run()
    print(witness.report['Status'], witness.report.get('Error') or '', str(witness.output))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
