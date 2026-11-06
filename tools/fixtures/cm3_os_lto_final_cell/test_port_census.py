"""Synthetic Os census controls. No compiler, real parser or target execution."""

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PINS = {
    'policy': ('tools/fixtures/cm3_lto_port_policy/policy.py',
        '8FC3AD729BF8903D716E34579700FC22D417040156EFCF0B434D2C43D75F0CA0'),
    'fixture': ('tools/fixtures/cm3_lto_port_policy/test_policy.py',
        '34B4F6663E765D9D093789F9EFD441DEA657C64F718E3946BC8049097BDEC24D'),
}
METHODS = 17
c = f = p = None
DEFAULT_SURFACE = object()


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class CensusTests(unittest.TestCase):
    def scan(self, image=None, dis=None, *, whole=False, surface=DEFAULT_SURFACE):
        image = f.SyntheticELF() if image is None else image
        return c.inspect_lowered(image, f.CORE, image.dis() if dis is None else dis,
            p.inspect_ir_definitions(f.ir_rows()) if surface is DEFAULT_SURFACE else surface, p, whole_image=whole)

    def final_image(self):
        image = f.SyntheticELF(final=True)
        image.loads = [dict(Vaddr=section.header.sh_addr, FileSize=section.header.sh_size,
            MemorySize=section.header.sh_size, Flags=5 if index == 1 else 4, Offset=section.header.sh_offset)
            for index, section in enumerate(image.sections) if index]
        return image

    def rejected(self, callable_):
        with self.assertRaises((c.Rejected, f.p.Rejected)):
            callable_()

    def test_own_os_result_neutral_helpers_only_no_mutation(self):
        image = f.SyntheticELF(extra='ordinary_cmsis_helper')
        before = copy.deepcopy((image.data, image.symbols, image.relocations))
        result = self.scan(image)
        self.assertEqual(result['Scope'], 'CM3_OS_LTO_PORT_MACHINE_CENSUS_ONLY')
        self.assertEqual(result['Mode'], 'Os-lto')
        self.assertEqual(result['FunctionsAudited'], 50)
        self.assertEqual(result['ExecutableInstructionBytes'], 100)
        self.assertEqual(before, (image.data, image.symbols, image.relocations))
        for key in ('WorkerProvenanceValidated', 'CanonicalRootProtocolsValidated', 'FullInstructionSemantics',
                    'SourceIRSemantics', 'OriginalTranslationUnitOwnership', 'AttributeOnlyProtection',
                    'GeneralRegistersOnlyEffectProved', 'CPUExecution', 'BoardExecution', 'GlobalQualification'):
            self.assertIs(result[key], False)
        self.assertEqual(result['RequiredCellsSatisfied'], 0)

    def test_exact_ir_surface_revalidated_not_success_boolean(self):
        for value in ({'IRDefinitionsValidated': True, 'Definitions': []},
                      {'IRDefinitionsValidated': 1, 'Definitions': []},
                      {'IRDefinitionsValidated': True, 'Definitions': [dict(Role=[], Name='x')]}):
            self.rejected(lambda: self.scan(surface=value))

    def test_none_cannot_disable_public_provider_surface(self):
        image = f.SyntheticELF()
        image.symbols = [row for row in image.symbols if row['kind'] != 'STT_FUNC' or row['name'] == p.LOCAL[0]]
        self.rejected(lambda: self.scan(image, surface=None))
        image = self.final_image()
        image.symbols = [row for row in image.symbols if row['name'] not in p.FORWARD]
        self.rejected(lambda: c.inspect_final(image, f.CORE, image.dis(), None, p))

    def test_required_private_forward_and_strong_handlers(self):
        for name in (p.LOCAL[0], p.FORWARD[0], 'SVC_Handler', 'PendSV_Handler'):
            image = f.SyntheticELF()
            item = next(row for row in image.symbols if row['name'] == name)
            if name.endswith('_Handler'):
                item['binding'] = 'STB_WEAK'
            else:
                image.symbols.remove(item)
            with self.subTest(name=name):
                self.rejected(lambda: self.scan(image))

    def test_overlapping_or_bool_symbol_extent_rejected(self):
        image = f.SyntheticELF()
        image.symbols.append(dict(image.symbols[0], name='alias'))
        self.rejected(lambda: self.scan(image))
        image = f.SyntheticELF()
        image.symbols[0]['size'] = True
        self.rejected(lambda: self.scan(image))

    def test_unknown_and_forbidden_imports_defined_or_undefined(self):
        for name in ('__stack_chk_fail', '__gcov0.hidden', '__aeabi_i2f', '__aeabi_dadd', 'memmove'):
            image = f.SyntheticELF()
            target = f.sym(name, 'SHN_UNDEF', kind='STT_NOTYPE')
            image.symbols.append(target)
            image.relocations[2, 60] = 2, target
            with self.subTest(name=name):
                self.rejected(lambda: self.scan(image))
        self.rejected(lambda: self.scan(f.SyntheticELF(extra='__cyg_profile_func_enter')))

    def test_all_executable_bytes_must_match_disassembly(self):
        image = f.SyntheticELF()
        raw = image.dis()
        row = raw.splitlines()[1] + b'\n'
        for dis in (raw.replace(b'bf00', b'bf01', 1), raw.replace(row, b'', 1),
                    raw + row, raw + b' ffff: 00bf nop\n', raw.replace(b' 0:', b' 1:', 1)):
            self.rejected(lambda: self.scan(image, dis))

    def test_mapping_and_function_boundaries_are_authoritative(self):
        image = f.SyntheticELF()
        image.maps = [(0, 'a')]
        self.rejected(lambda: self.scan(image))
        image = f.SyntheticELF(transfers=True)
        image.symbols[0]['size'] = 2
        self.rejected(lambda: self.scan(image))

    def test_extended_register_encodings_and_operands_rejected(self):
        for raw, op, operands in ((struct.pack('<HH', 0xEC00, 0), 'ordinary', 'r0,r1'),
                                  (struct.pack('<HH', 0xFC00, 0), 'ordinary', 'r0,r1'),
                                  (b'\x00\xbf', 'vldr', 's0,[r0]'),
                                  (b'\x00\xbf', 'mov', 'r0,d8')):
            image = f.SyntheticELF()
            h = image.sections[1].header
            image.data = image.data[:h.sh_offset] + raw + image.data[h.sh_offset + len(raw):]
            image.instructions[1, 0] = op, operands, raw
            self.rejected(lambda: self.scan(image))

    def test_padding_and_literal_pools_are_not_discarded(self):
        result = self.scan(f.SyntheticELF(padding=bytes.fromhex('00bf00bf')))
        self.assertEqual(len(result['Padding']), 2)
        result = self.scan(f.SyntheticELF(pool=True))
        self.assertEqual(len(result['UnownedMappedPools']), 1)
        self.rejected(lambda: self.scan(f.SyntheticELF(padding=bytes.fromhex('7047'))))
        image = f.SyntheticELF(pool=True)
        h = image.sections[1].header
        image.data = image.data[:h.sh_offset] + bytes.fromhex('00bf') + image.data[h.sh_offset + 2:]
        image.instructions[1, 0] = 'nop', '', bytes.fromhex('00bf')
        self.rejected(lambda: self.scan(image))

    def test_rel_kinds_bounds_alignment_ownership_and_overlap(self):
        for change in ('kind', 'bounds', 'alignment', 'transfer-data', 'code-word', 'overlap'):
            image = f.SyntheticELF(transfers=True)
            kind, target = image.relocations.pop((2, 4))
            if change == 'kind':
                image.relocations[2, 4] = 255, target
            elif change == 'bounds':
                image.relocations[2, 63] = kind, target
            elif change == 'alignment':
                image.relocations[2, 5] = kind, target
            elif change == 'transfer-data':
                image.relocations[2, 4] = 10, target
            elif change == 'code-word':
                image.relocations[1, 0] = 2, target
            else:
                image.relocations[1, 2] = 10, target
            with self.subTest(change=change):
                self.rejected(lambda: self.scan(image))

    def test_actual_bl_and_bw_sites_and_interior_rejection(self):
        image = f.SyntheticELF(transfers=True)
        result = self.scan(image)
        self.assertEqual([row['SiteForm'] for row in result['References'][:2]], ['THM_CALL-BL', 'THM_JUMP24-B.W'])
        self.assertTrue(all(row['AddendSemanticsValidated'] is False
                            and row['AppliedDestinationValidated'] is False for row in result['References']))
        for offset, kind in ((0, 30), (1, 10), (2, 10)):
            image = f.SyntheticELF(transfers=True)
            _, target = image.relocations.pop((1, 0))
            image.relocations[1, offset] = kind, target
            self.rejected(lambda: self.scan(image))

    def test_whole_worker_role_uses_exact_linker_imports(self):
        result = self.scan(f.SyntheticELF(whole=True), whole=True)
        self.assertEqual(result['Undefined'], sorted(p.FINAL_WORKER_UNDEFINED))
        self.rejected(lambda: self.scan(f.SyntheticELF(), whole=True))
        self.rejected(lambda: self.scan(f.SyntheticELF(whole=True)))
        self.rejected(lambda: self.scan(f.SyntheticELF(), whole=1))

    def test_final_vector_slots_and_entry_bind_actual_symbols(self):
        def inspect(image):
            return c.inspect_final(image, f.CORE, image.dis(), p.inspect_ir_definitions(f.ir_rows()), p)
        result = inspect(self.final_image())
        self.assertEqual(result['FinalRootVectorBindings']['Words'], 256)
        for slot in (1, 11, 14):
            image = self.final_image()
            at = image.sections[3].header.sh_offset + slot * 4
            image.data = image.data[:at] + bytes(4) + image.data[at + 4:]
            self.rejected(lambda: inspect(image))
        image = self.final_image()
        image.elf.header.e_entry = 0
        self.rejected(lambda: inspect(image))

    def test_final_vector_requires_unique_allocated_file_load(self):
        for change in ('unallocated', 'nobits', 'missing', 'duplicate', 'short-file', 'offset', 'unreadable', 'bool-field'):
            image = self.final_image()
            h = image.sections[3].header
            if change == 'unallocated':
                h.sh_flags = 0
            elif change == 'nobits':
                h.sh_type = 'SHT_NOBITS'
            elif change == 'missing':
                image.loads.pop()
            elif change == 'duplicate':
                image.loads.append(dict(image.loads[-1]))
            elif change == 'short-file':
                image.loads[-1]['FileSize'] = 1000
            elif change == 'offset':
                image.loads[-1]['Offset'] += 1
            elif change == 'unreadable':
                image.loads[-1]['Flags'] = 1
            else:
                image.loads[-1]['Offset'] = True
            with self.subTest(change=change):
                self.rejected(lambda: c.inspect_final(image, f.CORE, image.dis(), p.inspect_ir_definitions(f.ir_rows()), p))

    def test_inline_relocation_printout_has_exact_address_and_grammar(self):
        image = f.SyntheticELF(transfers=True)
        original = image.dis()
        good = original.replace(b' bl 0\n', b' bl 0 <callee>\t0: R_ARM_THM_CALL\tcallee\n', 1)
        self.scan(image, good)
        for note in (b'2: R_ARM_THM_CALL\tcallee', b'0: R_ARM_THM_CALL\tcallee extra'):
            self.rejected(lambda: self.scan(image, original.replace(b' bl 0\n', b' bl 0 <callee>\t' + note + b'\n', 1)))

    def test_stress_uses_os_effects_and_clean_rejection_required(self):
        image = f.SyntheticELF(stress=True)
        calls = []
        class EffectRejected(ValueError):
            pass
        def inspect(image_, core_, helpers_, *, stress, mutation=None):
            calls.append(mutation)
            if mutation is None and len(calls) > 1:
                raise EffectRejected('actual raw effects')
            return dict(StressFamiliesActivated=True, StressCounterEvidence={'counter': 'synthetic'})
        effects = SimpleNamespace(inspect_lowered=inspect, Rejected=EffectRejected)
        helpers = SimpleNamespace(STRESS='ctxrt_attribute_stress')
        result = c.inspect_stress(image, f.CORE, image.dis(), p, effects, helpers, supported=True)
        self.assertTrue(result['SupportedPolicy'])
        calls.clear()
        result = c.inspect_stress(image, f.CORE, image.dis(), p, effects, helpers, supported=False)
        self.assertTrue(result['CleanPredicateRejected'])
        self.assertEqual(calls, ['ctxrt_attribute_stress', None])
        effects.inspect_lowered = lambda *args, **kw: dict(StressFamiliesActivated=False, StressCounterEvidence=None)
        self.rejected(lambda: c.inspect_stress(image, f.CORE, image.dis(), p, effects, helpers, supported=False))


def main():
    global c, f, p
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.absolute()
    if output.exists() or output == ROOT or ROOT in output.parents:
        raise SystemExit('fresh external output directory required')
    paths = [Path(__file__), HERE / 'port_census.py', *(ROOT / row[0] for row in PINS.values())]
    opening = {str(path): sha(path.read_bytes()) for path in paths}
    for relative, expected in PINS.values():
        if opening[str(ROOT / relative)] != expected:
            raise SystemExit('pinned helper mismatch before execution/' + relative)
    c = load(HERE / 'port_census.py', 'os_port_census_under_test')
    f = load(ROOT / PINS['fixture'][0], 'os_port_census_synthetic_fixture')
    names = ('ROLES', 'FORWARD', 'NAKED', 'LOCAL', 'UNDEFINED', 'FINAL_WORKER_UNDEFINED',
             'FORBIDDEN', 'FORBIDDEN_FORMS', '_header', '_symbols', '_forms', '_disassembly', 'inspect_ir_definitions')
    p = SimpleNamespace(**{name: getattr(f.p, name) for name in names})
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CensusTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    closing = {str(path): sha(path.read_bytes()) for path in paths}
    report = dict(Status='PASS' if result.wasSuccessful() and result.testsRun == METHODS and opening == closing else 'FAIL',
        Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
        SourceHashes=opening, SourceDrift=opening != closing, SyntheticControlsOnly=True,
        CompilerExecuted=False, ActualMachineBytesValidated=False, RequiredCellsSatisfied=0)
    output.mkdir(parents=True)
    (output / 'results.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n', encoding='ascii')
    print(json.dumps(report, sort_keys=True))
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
