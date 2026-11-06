"""Pure common-source controls over current canonical fixtures; no tools or ELF."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SUBJECT = HERE / 'ownership.py'
SUBJECT_SHA256 = 'F9971A707BC30FFA7AF0B816570ED476B2965F24369BC7A747C18784E5B0A552'
CORE = 'context/context_core.c'
STATE = 'context/context_runtime_state.c'
PANIC = 'context/context_panic.c'
MANIFEST = 'tools/runtime_sources.json'
REQUIRED = (CORE, STATE, PANIC, MANIFEST)
FUNCTIONS = (
    'fiber_internal_task_return', 'ctxrt_v1_init', 'ctxrt_v1_current', 'ctxrt_v1_start',
    'ctxrt_v1_set_dispatcher', 'ctxrt_v1_yield', 'fiber_internal_scheduler_store_pick_next',
    'fiber_internal_runtime_load_current_context', 'fiber_internal_runtime_select_scheduler_candidate',
    'fiber_internal_runtime_publish_current_context', 'fiber_internal_runtime_require_current_context',
    'fiber_internal_scheduler_is_configured', 'fiber_internal_runtime_close_context_configuration',
    'fiber_internal_runtime_context_configuration_is_open', 'fiber_panic',
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


class OwnershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        paths = (SUBJECT, Path(__file__).resolve(), *(REPO / name for name in REQUIRED))
        opening = {path: path.read_bytes() for path in paths}
        hashes = {path: sha(raw) for path, raw in opening.items()}

        def close_sources():
            closing = {path: sha(path.read_bytes()) for path in paths}
            if closing != hashes:
                raise AssertionError('ownership test/source/fixture hash drift')

        cls.addClassCleanup(close_sources)
        if hashes[SUBJECT] != SUBJECT_SHA256:
            raise AssertionError('ownership implementation differs from the frozen review input')
        spec = importlib.util.spec_from_file_location('cm0_common_ownership_controls', SUBJECT)
        cls.subject = importlib.util.module_from_spec(spec)
        exec(compile(opening[SUBJECT], str(SUBJECT), 'exec'), cls.subject.__dict__)
        cls.fixtures = {name: opening[REPO / name] for name in REQUIRED}

    def setUp(self):
        self.buffers = dict(self.fixtures)

    def replaced(self, path, before, after):
        self.assertEqual(self.buffers[path].count(before), 1, 'fixture mutation must isolate one actual fragment')
        result = dict(self.buffers)
        result[path] = result[path].replace(before, after, 1)
        return result

    def swapped(self, path, left, right):
        raw = self.buffers[path]
        self.assertEqual(raw.count(left), 1)
        self.assertEqual(raw.count(right), 1)
        marker = b'__ownership_test_swap_marker__'
        self.assertNotIn(marker, raw)
        result = dict(self.buffers)
        result[path] = raw.replace(left, marker, 1).replace(right, left, 1).replace(marker, right, 1)
        return result

    def rejects(self, buffers):
        with self.assertRaisesRegex(self.subject.Rejected, 'cm0-cell-ownership:'):
            self.subject.validate_common_sources(buffers)

    def test_actual_sources_pure_api_and_literal_nonclaims(self):
        self.assertEqual(self.subject.REQUIRED_SOURCES, REQUIRED)
        with patch('builtins.open', side_effect=AssertionError('validator opened a file')), \
                patch.object(Path, 'open', side_effect=AssertionError('validator opened a path')), \
                patch.object(Path, 'read_bytes', side_effect=AssertionError('validator read a path')), \
                patch.object(Path, 'write_bytes', side_effect=AssertionError('validator wrote a path')), \
                patch.object(importlib.util, 'spec_from_file_location', side_effect=AssertionError('validator loaded a helper')):
            result = self.subject.validate_common_sources(self.buffers)
        self.assertEqual(result['Status'], 'PASS')
        self.assertEqual(result['Scope'], 'CM0_COMMON_SOURCE_BOUNDARY_PREDICATES_ONLY')
        self.assertIs(result['SourceFactsOnly'], True)
        self.assertEqual(result['SourceHashes'], {path: sha(self.buffers[path]) for path in REQUIRED})
        self.assertEqual(result['SourceRoles'], dict(engine=CORE, state=STATE, panic=PANIC))
        self.assertEqual(tuple(row['Function'] for row in result['CheckedFunctions']), FUNCTIONS)
        self.assertEqual(len(result['CheckedFunctions']), 15)
        for key in ('InputAuthenticationProof', 'ActualProviderProof', 'DependencyProof', 'ElfProof',
                    'CompileProof', 'CompilerExecution', 'FullABIProof', 'FullSemanticABIProof',
                    'ArbitraryPointerAliasProof', 'CpuExecution', 'BoardExecution',
                    'RequiredCellSatisfied', 'GlobalFreezeQualified'):
            self.assertIs(result[key], False, key)
        self.assertIs(type(result['RequiredCellsSatisfied']), int)
        self.assertEqual(result['RequiredCellsSatisfied'], 0)

    def test_missing_extra_and_nonbyte_inputs_reject(self):
        for path in REQUIRED:
            with self.subTest(missing=path):
                self.rejects({key: value for key, value in self.buffers.items() if key != path})
        self.rejects(dict(self.buffers, **{'context/foreign.c': b''}))
        self.rejects(dict(self.buffers, **{CORE: bytearray(self.buffers[CORE])}))
        self.rejects(list(self.buffers.items()))

    def test_manifest_roles_schema_and_duplicate_keys_reject(self):
        baseline = json.loads(self.buffers[MANIFEST])
        variants = []
        wrong = copy.deepcopy(baseline)
        wrong['providers']['engine'], wrong['providers']['state'] = STATE, CORE
        variants.append(wrong)
        wrong = copy.deepcopy(baseline)
        wrong['providers']['panic'] = 'fiber/fiber_panic.c'
        variants.append(wrong)
        wrong = copy.deepcopy(baseline)
        wrong['compatibility']['facade_bridge'] = ['context/context_bridge.c']
        variants.append(wrong)
        wrong = copy.deepcopy(baseline)
        wrong['schema_version'] = True
        variants.append(wrong)
        for value in variants:
            with self.subTest(manifest=value):
                self.rejects(dict(self.buffers, **{MANIFEST: json.dumps(value).encode('ascii')}))
        for raw in (b'{"schema_version":1,"schema_version":1}',
                    b'{"schema_version":1,"SCHEMA_VERSION":1}', b'{invalid'):
            with self.subTest(raw=raw):
                self.rejects(dict(self.buffers, **{MANIFEST: raw}))

    def test_authored_cpu_intrinsics_assembly_and_matrix_terms_reject(self):
        variants = (
            (CORE, b'fiber_port_runtime_schedule();', b'__get_IPSR();'),
            (CORE, b'fiber_port_runtime_schedule();', b'__asm volatile("nop");'),
            (CORE, b'fiber_port_runtime_schedule();', b'SCB->ICSR = 1u;'),
            (STATE, b'fiber_internal_runtime_current_context_slot = next;', b'__set_BASEPRI(1u);'),
            (STATE, b'fiber_internal_runtime_current_context_slot = next;', b'FIBER_PORT_HAS_TEST;'),
            (PANIC, b'fiber_port_panic_wait();', b'__asm__("nop");'),
            (PANIC, b'fiber_port_panic_wait();', b'__get_PSP();'),
            (PANIC, b'fiber_port_panic_wait();', b'fiber_port_scheduler_critical_enter();'),
        )
        for path, anchor, injected in variants:
            with self.subTest(path=path, injected=injected):
                self.rejects(self.replaced(path, anchor, injected + b'\n    ' + anchor))

    def test_start_and_dispatcher_precedence_reject(self):
        variants = (
            (b'fiber_internal_runtime_close_context_configuration();', b'fiber_port_runtime_prepare_start();'),
            (b'fiber_port_runtime_prepare_start();',
             b'CtxrtContextV1 *const first = fiber_port_runtime_select_first();'),
            (b'fiber_internal_runtime_publish_current_context(first);', b'fiber_port_runtime_start_first(first);'),
            (b'fiber_port_require_scheduler_configuration_environment();',
             b'fiber_internal_scheduler_store_pick_next(dispatch, user);'),
        )
        for left, right in variants:
            with self.subTest(left=left, right=right):
                self.rejects(self.swapped(CORE, left, right))

    def test_common_private_owners_and_definitions_reject(self):
        for path, extra in (
            (CORE, b'\nstatic void *second_current = 0;\n'),
            (CORE, b'\nCtxrtContextV1 *volatile fiber_internal_runtime_current_context_slot = 0;\n'),
            (STATE, b'\nstatic void *second_dispatcher = 0;\n'),
            (PANIC, b'\nvoid fiber_panic(char code) { (void)code; }\n'),
        ):
            with self.subTest(path=path, extra=extra):
                self.rejects(dict(self.buffers, **{path: self.buffers[path] + extra}))
        self.rejects(self.replaced(CORE, b'fiber_port_runtime_schedule();',
            b'fiber_internal_runtime_current_context_slot = 0; fiber_port_runtime_schedule();'))
        self.rejects(self.replaced(STATE, b'static void *volatile fiber_internal_runtime_scheduler_user',
            b'void *volatile fiber_internal_runtime_scheduler_user'))

    def test_publication_and_lifecycle_reset_mutations_reject(self):
        raw = self.buffers[STATE]
        at = raw.index(b'void fiber_internal_runtime_publish_current_context(')
        prefix, publication = raw[:at], raw[at:]
        guard, store = b"FIBER_REQUIRE(next != 0, 'N');", b'fiber_internal_runtime_current_context_slot = next;'
        self.assertEqual(publication.count(guard), 1)
        self.assertEqual(publication.count(store), 1)
        marker = b'__ownership_publication_swap__'
        changed = publication.replace(guard, marker, 1).replace(store, guard, 1).replace(marker, store, 1)
        self.rejects(dict(self.buffers, **{STATE: prefix + changed}))
        self.rejects(self.replaced(STATE, store, b'fiber_internal_runtime_current_context_slot = 0;'))
        for name in (b'fiber_internal_runtime_scheduler_first_selection_started',
                     b'fiber_internal_runtime_context_configuration_closed'):
            with self.subTest(reset=name):
                assignment = name + b' = 1u;'
                self.rejects(self.replaced(STATE, assignment, assignment + b'\n    ' + name + b' = 0u;'))

    def test_comments_cannot_spoof_required_bodies_and_parser_closes(self):
        comment = b'\n/* __asm__("nop"); __get_IPSR(); ->sp { } */\n'
        result = self.subject.validate_common_sources(dict(self.buffers, **{CORE: comment + self.buffers[CORE]}))
        self.assertIs(result['SourceFactsOnly'], True)
        required = b'fiber_port_runtime_prepare_start();'
        self.rejects(self.replaced(CORE, required, b'/* ' + required + b' */'))
        self.rejects(dict(self.buffers, **{CORE: self.buffers[CORE] + b'/* unterminated'}))
        self.rejects(dict(self.buffers, **{CORE: self.buffers[CORE] + b'\nvoid ctxrt_v1_yield(void) {}\n'}))
        end = self.buffers[CORE].rindex(b'}')
        self.rejects(dict(self.buffers, **{CORE: self.buffers[CORE][:end] + self.buffers[CORE][end + 1:]}))


if __name__ == '__main__':
    unittest.main(verbosity=2)
