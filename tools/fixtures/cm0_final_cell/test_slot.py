"""Pure controls for the bounded CM0 generated slot predicate; no tools run."""
import importlib.util
from pathlib import Path
import unittest


PATH = Path(__file__).with_name('slot.py')
SPEC = importlib.util.spec_from_file_location('cm0_cell_slot_controls', PATH)
slot = importlib.util.module_from_spec(SPEC)
exec(compile(PATH.read_bytes(), str(PATH), 'exec'), slot.__dict__)
SOURCE = ('void SVC_Handler(void) { __asm("ldr r0, =' + slot.SLOT + ' \\n"\n'
          '"ldr r0, [r0] \\n"); }\n'
          'void PendSV_Handler(void) { __asm("ldr r1, =' + slot.SLOT + ' \\n"\n'
          '"ldr r1, [r1] \\n"); }\n').encode('ascii')
ASSEMBLY = ('SVC_Handler:\n ldr r0, =' + slot.SLOT + '\n ldr r0, [r0]\n'
            ' .size SVC_Handler, .-SVC_Handler\n'
            'PendSV_Handler:\n ldr r1, =' + slot.SLOT + '\n ldr r1, [r1]\n'
            ' .size PendSV_Handler, .-PendSV_Handler\n').encode('ascii')
OBJECT = b'\x7fELF\x01\x01\x01' + b'pure placeholder, not an actual decoded object'


class SlotTests(unittest.TestCase):
    def check(self, source=SOURCE, assembly=ASSEMBLY, original=OBJECT, replay=OBJECT):
        return slot.check_generated(source, assembly, original, replay)

    def test_two_exact_owned_pairs_and_literal_nonclaims(self):
        result = self.check()
        self.assertEqual(result['GeneratedReferences'], 2)
        self.assertEqual([(row['Owner'], row['Register']) for row in result['Owners']],
                         [('SVC_Handler', 'r0'), ('PendSV_Handler', 'r1')])
        self.assertIs(result['WholeObjectByteIdentical'], True)
        for key in ('ArbitraryPointerAliasProof', 'FullSemanticABIProof', 'CpuExecution',
                    'BoardExecution', 'RequiredCellSatisfied'):
            self.assertIs(result[key], False)
        self.assertIs(type(result['RequiredCellsSatisfied']), int)
        self.assertEqual(result['RequiredCellsSatisfied'], 0)

    def test_extra_reference_redeclaration_and_address_escape_reject(self):
        for source in (SOURCE + ('extern void *' + slot.SLOT + ';').encode('ascii'),
                       SOURCE + ('void *p = &' + slot.SLOT + ';').encode('ascii')):
            with self.subTest(source=source[-80:]), self.assertRaises(slot.Rejected):
                self.check(source=source)
        with self.assertRaises(slot.Rejected):
            self.check(assembly=ASSEMBLY + (' .word ' + slot.SLOT + '\n').encode('ascii'))

    def test_store_delayed_load_and_register_escape_reject(self):
        for replacement in (b' str r0, [r0]', b' nop\n ldr r0, [r0]', b' ldr r1, [r0]',
                            b' mov r2, r0\n ldr r0, [r0]'):
            with self.subTest(replacement=replacement), self.assertRaises(slot.Rejected):
                self.check(assembly=ASSEMBLY.replace(b' ldr r0, [r0]', replacement))

    def test_wrong_or_incomplete_generated_owner_rejects(self):
        variants = (ASSEMBLY.replace(b'SVC_Handler:', b'wrong_owner:'),
                    ASSEMBLY.replace(b' .size SVC_Handler, .-SVC_Handler\n', b''),
                    ASSEMBLY.replace(b'r1', b'r0'),
                    ASSEMBLY + b'SVC_Handler:\n .size SVC_Handler, .-SVC_Handler\n')
        for assembly in variants:
            with self.subTest(assembly=assembly), self.assertRaises(slot.Rejected):
                self.check(assembly=assembly)

    def test_source_unclassified_access_and_non_ascii_reject(self):
        for source in (SOURCE.replace(b'ldr r0, [r0]', b'str r0, [r0]'), SOURCE + b'\xff'):
            with self.subTest(source=source[-70:]), self.assertRaises(slot.Rejected):
                self.check(source=source)
        with self.assertRaises(slot.Rejected):
            self.check(assembly=ASSEMBLY + b'\xff')

    def test_whole_object_identity_and_literal_byte_inputs_required(self):
        for original, replay in ((OBJECT, OBJECT + b'drift'), (b'not ELF', b'not ELF'),
                                 (bytearray(OBJECT), OBJECT)):
            with self.subTest(original=original[:20]), self.assertRaises(slot.Rejected):
                self.check(original=original, replay=replay)


if __name__ == '__main__':
    unittest.main(verbosity=2)
