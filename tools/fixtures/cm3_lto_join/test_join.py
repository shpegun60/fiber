"""Pure synthetic controls for the fixed six-body CM3 LTO join contract.

FakeViews return copied checker expectations and fabricated transport records.
Their payloads are deliberately not ELF. The unchanged canonical checker runs,
but no qualified parser, protocol adapter, compiler, receipt or target is used.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
JOIN = HERE / "join.py"
CHECKER = HERE.parent / "cm3_freeze_parity/check.py"
JOIN_SHA256 = "F4EF2402495FF90C6D781762EC2B85A458F7DA702F14B2C6A1581D9E09343CE3"
CHECKER_SHA256 = "F0D9CD4F48912FB6E5455AA365BF73FFCF356BAFAD922B3A73ACA992A616A11A"
NATIVE = ("fiber_port_start_first_context", "SVC_Handler", "PendSV_Handler")
REFERENCE = ("prvPortStartFirstTask", "vPortSVCHandler", "xPortPendSVHandler")
COHORT = "cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default"
SLOT = "fiber_internal_runtime_current_context_slot"
SECTION = ".bss.fiber_runtime_current_context_slot"
DIFFERENCES = ("FAP-COMMON-START", "FAP-COMMON-PROVENANCE", "FAP-CM3-LOCAL-LITERAL-POOLS",
               "FAP-COMMON-MASK-RESTORE", "FAP-CM3-EXC-RETURN", "FAP-COMMON-SCHEDULER")
MECHANISMS = [
    dict(Name="first-start", NativeRoot=NATIVE[0], ReferenceRoot=REFERENCE[0],
         DifferenceIds=[DIFFERENCES[0], DIFFERENCES[1], DIFFERENCES[2]]),
    dict(Name="first-restore", NativeRoot=NATIVE[1], ReferenceRoot=REFERENCE[1],
         DifferenceIds=[DIFFERENCES[1], DIFFERENCES[3], DIFFERENCES[4], DIFFERENCES[2]]),
    dict(Name="PendSV", NativeRoot=NATIVE[2], ReferenceRoot=REFERENCE[2],
         DifferenceIds=[DIFFERENCES[5], DIFFERENCES[1], DIFFERENCES[4], DIFFERENCES[2]]),
]
LAYOUTS = {
    "Native": ((NATIVE[0], 0, 104, 34), (NATIVE[1], 128, 184, 64), (NATIVE[2], 384, 204, 72)),
    "Reference": ((REFERENCE[0], 0, 32, 10), (REFERENCE[1], 64, 36, 10), (REFERENCE[2], 128, 68, 19)),
}
CALLS = {
    NATIVE[0]: ((0x56, "fiber_panic"), (0x5E, "fiber_panic")),
    NATIVE[1]: ((0x72, "fiber_port_context_validate_restore"), (0x9E, "fiber_panic"),
                (0xA6, "fiber_panic"), (0xAE, "fiber_panic")),
    NATIVE[2]: ((0x34, "fiber_port_context_validate_save_current"), (0x82, "fiber_port_scheduler_pick_next_from_pendsv"),
                (0xB0, "fiber_panic"), (0xB8, "fiber_panic"), (0xC0, "fiber_panic")),
    REFERENCE[0]: (), REFERENCE[1]: (), REFERENCE[2]: ((28, "vTaskSwitchContext"),),
}
DOMAINS = dict(MachineRoot="SHA256-UNAPPLIED-MACHINE-FUNCTION-BYTES",
               FinalRoot="SHA256-APPLIED-FINAL-FUNCTION-BYTES", Canonical="SHA256-JSON-TOKENS")
EXPECTED_METHODS = 18
PREFIX_SIZE = 64
MISSING = object()
j = c = None


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def token_sha(tokens):
    return sha(json.dumps(tokens, separators=(",", ":"), ensure_ascii=True).encode("ascii"))


def module(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    exec(compile(data, str(path), "exec"), result.__dict__)
    return result


def set_path(value, keys, replacement):
    for key in keys[:-1]:
        value = value[key]
    if replacement is MISSING:
        del value[keys[-1]]
    else:
        value[keys[-1]] = copy.deepcopy(replacement)


def rationale_bodies():
    return {identity: "<!-- synthetic comment, not sufficient alone -->\nSynthetic rationale for " + identity + "."
            for identity in DIFFERENCES}


def ledger(bodies=None, newline="\n"):
    bodies = rationale_bodies() if bodies is None else bodies
    text = "# Synthetic CM3 difference ledger\n\n" + "\n\n".join(
        "### " + identity + "\n" + bodies[identity] for identity in DIFFERENCES) + "\n"
    return text.replace("\n", newline)


class FakeView:
    def __init__(self, side):
        self.side = side
        self.names = NATIVE if side == "Native" else REFERENCE
        self.canonical = copy.deepcopy(c._NATIVE if side == "Native" else c._REFERENCE)
        self.calls, self.on_first_call, self.evidence = [], None, {}
        marker = ("SYNTHETIC-" + side.upper() + "-NOT-ELF").encode("ascii").ljust(PREFIX_SIZE, b"\x7f")
        payload = bytes((index * 7 + (3 if side == "Native" else 19)) % 256 for index in range(768))
        self.decoded = SimpleNamespace(data=marker + payload)
        self.transport = SimpleNamespace(machine=SimpleNamespace(data=self.decoded.data), records={})
        self.offsets = {name: offset for name, offset, _, _ in LAYOUTS[side]}
        for name, offset, size, count in LAYOUTS[side]:
            instructions = [dict(Offset=index * 2, Bytes="00bf", Mnemonic=op, Operands=value, Synthetic=True)
                            for index, (op, value) in enumerate(self.canonical[name]) if op != "@literal-island"]
            if len(instructions) != count:
                raise ValueError("synthetic instruction count disagrees with frozen checker")
            islands = [json.loads(value) for op, value in self.canonical[name] if op == "@literal-island"]
            references = [dict(Offset=place, Kind=10, Symbol=symbol, Addend=-4) for place, symbol in CALLS[name]]
            references.extend(dict(Offset=island["Offset"] + row["Offset"], Kind=row["Kind"],
                                   Symbol=row["Target"], Addend=0)
                              for island in islands for row in island["Relocations"])
            record = dict(Name=name, Size=size, InstructionCount=count, Instructions=instructions,
                MappedData=[dict(Offset=row["Offset"], Bytes=row["Bytes"]) for row in islands], References=references,
                DefinitionOrigins=[dict(Name=symbol, GeneratedMachineOriginBound=True,
                    OriginalTranslationUnitOwnership=False, CalleeBodyProof=False, CalleeRelocationSemanticsChecked=False)
                    for symbol in dict.fromkeys(row["Symbol"] for row in references)],
                RootOrigin=dict(Name=name, Provider="C:/synthetic-" + side.lower() + "/machine.o",
                    InputSection=".text", InputSectionIndex=1, SymbolOffset=offset, Size=size,
                    GeneratedMachineOriginBound=True, OriginalTranslationUnitOwnership=False,
                    CalleeBodyProof=False, CalleeRelocationSemanticsChecked=False),
                GeneratedMachineBoundRootPreservation=True, CanonicalProtocolValidated=False,
                OriginalTranslationUnitOwnership=False, FinalReferenceParity=False, FullABIProof=False,
                CompleteObjectProof=False, InstructionEquivalence=False, SourceIRProof=False,
                SourceToMachineSemanticProof=False, SourceToIRSemanticProof=False, PolicyEquivalence=False,
                CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False, RequiredCellsSatisfied=0)
            self.transport.records[name] = record
            self.evidence[name] = dict(Name=name, TransportRecord=record, HashDomains=copy.deepcopy(DOMAINS))
            self.refresh_tokens(name)
        self.rebind_machine(self.decoded.data)

    def refresh_tokens(self, name):
        canonical = copy.deepcopy(self.canonical[name])
        raw, projections = copy.deepcopy(canonical), []
        if self.side == "Native" and name != self.names[0]:
            for index, (op, value) in enumerate(raw):
                if op == "ldr" and "=" + SLOT + "+0" in value:
                    raw[index] = (op, value.replace(SLOT, SECTION))
                elif op == "@literal-island":
                    island = json.loads(value)
                    for relocation in island["Relocations"]:
                        if relocation["Target"] == SLOT:
                            relocation["Target"] = SECTION
                    raw[index] = (op, json.dumps(island, sort_keys=True, separators=(",", ":")))
            projections = [dict(Kind="PROVED_SECTION_TO_LOGICAL_SLOT_ROLE_ONLY", Synthetic=True)]
        row = self.evidence[name]
        row.update(RawCanonicalTokens=raw, RawTokenSha256=token_sha(raw), ProjectionEvidence=projections)
        if self.side == "Native":
            row.update(ProjectedCanonicalTokens=canonical, ProjectedTokenSha256=token_sha(canonical))

    def rebind_machine(self, data):
        self.decoded.data = self.transport.machine.data = data
        self.machine_sha = sha(data)
        for name in self.names:
            record = self.transport.records[name]
            offset = PREFIX_SIZE + self.offsets[name]
            body = data[offset:offset + record["Size"]]
            record.update(MachineBodySha256=sha(body), BodySha256=sha(b"synthetic applied final:" + body))
            record["RootOrigin"]["ProviderSha256"] = self.machine_sha
            self.evidence[name].update(MachineProviderSha256=self.machine_sha,
                MachineBodySha256=record["MachineBodySha256"], FinalBodySha256=record["BodySha256"])

    def append_tail(self, name):
        self.canonical[name].append(("nop", ""))
        record = self.transport.records[name]
        end = PREFIX_SIZE + self.offsets[name] + record["Size"]
        data = bytearray(self.decoded.data)
        data[end:end + 2] = b"\x00\xbf"
        record["Size"] += 2
        record["RootOrigin"]["Size"] += 2
        record["InstructionCount"] += 1
        record["Instructions"].append(dict(Mnemonic="nop", Operands="", Bytes="00bf", Synthetic=True))
        self.refresh_tokens(name)
        self.rebind_machine(bytes(data))

    def function(self, name, *, literal_islands=False):
        if literal_islands is not True or name not in self.canonical:
            raise c.Rejected("REJECT:CM3-CLOSED-ROOTS:synthetic wrong-side or incomplete root")
        self.calls.append(name)
        callback, self.on_first_call = self.on_first_call, None
        if callback is not None:
            callback()
        return self.canonical[name]


class ProofChecker:
    """Tamper only after the real unchanged six-body matcher has completed."""
    def __init__(self, change):
        self._NATIVE, self._REFERENCE = c._NATIVE, c._REFERENCE
        self.change = change

    def check_pair(self, native, reference):
        proof = c.check_pair(native, reference)
        self.change(proof)
        return proof


class Fixture:
    def __init__(self):
        self.native, self.reference = FakeView("Native"), FakeView("Reference")
        self.ledger = ledger()

    def check(self, checker=None):
        return j.check_join(self.native, self.reference, c if checker is None else checker, self.ledger)

    def sides(self):
        return (("Native", self.native), ("Reference", self.reference))


class JoinTests(unittest.TestCase):
    def rejects(self, fixture, checker=None):
        with self.assertRaises((j.Rejected, c.Rejected)):
            fixture.check(checker)

    def test_six_complete_bodies_scope_frames_and_all_nonclaims(self):
        fixture = Fixture()
        result = fixture.check()
        self.assertEqual(result["Status"], "CM3-LTO-SIX-BODY-JOIN-PASS-NOT-QUALIFIED")
        self.assertEqual(result["Scope"], "CM3_O2_LTO_P4_B16_DIRECT_SIX_CLOSED_ROOT_JOIN_ONLY")
        self.assertEqual((result["Profile"], result["Mode"], result["Cohort"], result["Linkage"]),
                         ("CM3", "O2-lto", COHORT, "direct"))
        self.assertIs(result["LTO"], True)
        self.assertIs(result["CanonicalProtocolValidated"], True)
        self.assertIs(result["OriginalTransportRecordsUnmodified"], True)
        self.assertIs(type(result["ClosedBodies"]), int)
        self.assertEqual(result["ClosedBodies"], 6)
        self.assertEqual(result["FrameContract"], dict(NativeCoreSlots=9, NativeExcReturn="PER-CONTEXT-SAVED-LR",
            ReferenceCoreSlots=8, ReferenceFirstRestoreExcReturn="ORR-LR-13", EquivalenceProven=False))
        for key in ("Qualification", "FinalReferenceParity", "FullABIProof", "FinalElfProof", "SourceIRProof",
                    "SourceToIRSemanticProof", "SourceToMachineSemanticProof", "OriginalTranslationUnitOwnership",
                    "InstructionEquivalence", "PolicyEquivalence", "CompleteObjectProof", "KernelRuntimeProof",
                    "HandlerRoutingProven", "ProducerCompilersReexecuted", "MutantsReexecuted", "CpuExecution",
                    "BoardExecution", "GlobalFreezeQualified", "RequiredCellSatisfied"):
            self.assertIs(result[key], False)
        for key in ("NativeCommandsExecuted", "RequiredCellsSatisfied"):
            self.assertIs(type(result[key]), int)
            self.assertEqual(result[key], 0)
        self.assertEqual(fixture.native.calls, list(NATIVE))
        self.assertEqual(fixture.reference.calls, list(REFERENCE))
        for side, view in fixture.sides():
            self.assertEqual([row["Name"] for row in result["Roots"][side]], list(view.names))
            self.assertEqual(result["MachineSha256"][side], sha(view.decoded.data))
            for row, record in zip(result["Roots"][side], result["RawTransportRoots"][side]):
                self.assertEqual(row["TransportRecord"], record)
                self.assertIs(record["CanonicalProtocolValidated"], False)
                self.assertIs(record["OriginalTranslationUnitOwnership"], False)

    def test_exact_mechanisms_and_six_difference_ids_are_independent_expectations(self):
        result = Fixture().check()
        self.assertEqual(result["Mechanisms"], MECHANISMS)
        self.assertEqual(result["DifferenceIds"], list(DIFFERENCES))
        self.assertEqual(j.expected_mechanisms(), MECHANISMS)
        changed = j.expected_mechanisms()
        changed[0]["DifferenceIds"].clear()
        self.assertEqual(j.expected_mechanisms(), MECHANISMS)

    def test_ledger_lf_crlf_comments_and_raw_text_hashes_are_retained(self):
        for newline in ("\n", "\r\n"):
            fixture = Fixture()
            fixture.ledger = ledger(newline=newline)
            result = fixture.check()
            self.assertEqual(result["LedgerSha256"], sha(fixture.ledger.encode("ascii")))
            self.assertEqual(tuple(result["DifferenceRationales"]), DIFFERENCES)
            for identity, body in rationale_bodies().items():
                expected = body.replace("\n", newline)
                self.assertEqual(result["DifferenceRationales"][identity]["Text"], expected)
                self.assertEqual(result["DifferenceRationales"][identity]["TextSha256"], sha(expected.encode("ascii")))

    def test_required_ledger_headings_are_unique_exact_and_not_comment_only(self):
        for identity in DIFFERENCES:
            for change in ("missing", "duplicate", "level", "empty", "comment", "punctuation"):
                fixture = Fixture()
                if change == "missing":
                    fixture.ledger = fixture.ledger.replace("### " + identity + "\n", "### ABSENT-" + identity + "\n", 1)
                elif change == "duplicate":
                    fixture.ledger += "\n### " + identity + "\nAnother synthetic rationale.\n"
                elif change == "level":
                    fixture.ledger = fixture.ledger.replace("### " + identity + "\n", "#### " + identity + "\n", 1)
                else:
                    bodies = rationale_bodies()
                    bodies[identity] = {"empty": " \t", "comment": "<!-- words only in a comment -->", "punctuation": "--- !!!"}[change]
                    fixture.ledger = ledger(bodies)
                with self.subTest(identity=identity, change=change):
                    self.rejects(fixture)

    def test_distinct_views_bytes_and_own_transport_machine_bindings_are_required(self):
        fixture = Fixture()
        with self.assertRaises(j.Rejected):
            j.check_join(fixture.native, fixture.native, c, fixture.ledger)
        for change in ("same-content", "shared-machine", "preserved-drift", "nonbytes", "empty", "hash"):
            fixture = Fixture()
            if change == "same-content":
                fixture.reference.rebind_machine(bytes(bytearray(fixture.native.decoded.data)))
            elif change == "shared-machine":
                fixture.reference.transport.machine = fixture.native.transport.machine
            elif change == "preserved-drift":
                fixture.native.transport.machine.data += b"different"
            elif change == "nonbytes":
                fixture.native.decoded.data = bytearray(fixture.native.decoded.data)
            elif change == "empty":
                fixture.native.rebind_machine(b"")
            else:
                fixture.native.machine_sha = "0" * 64
            with self.subTest(change=change):
                self.rejects(fixture)

    def test_matching_cannot_change_a_bound_whole_machine_between_checks(self):
        for side in ("Native", "Reference"):
            fixture = Fixture()
            view = fixture.native if side == "Native" else fixture.reference
            view.on_first_call = lambda view=view: view.rebind_machine(view.decoded.data + b":late-change")
            with self.subTest(side=side), self.assertRaisesRegex(j.Rejected, "changed while matching"):
                fixture.check()

    def test_checker_root_contracts_must_be_literal_complete_ordered_dicts(self):
        for side in ("Native", "Reference"):
            names, table = (NATIVE, c._NATIVE) if side == "Native" else (REFERENCE, c._REFERENCE)
            for roots in ({}, {name: table[name] for name in reversed(names)}, dict(table, foreign=[]), tuple(names)):
                paired = Mock(side_effect=c.check_pair)
                checker = SimpleNamespace(_NATIVE=c._NATIVE, _REFERENCE=c._REFERENCE, check_pair=paired)
                setattr(checker, "_NATIVE" if side == "Native" else "_REFERENCE", roots)
                with self.subTest(side=side, roots=list(roots)), self.assertRaises(j.Rejected):
                    Fixture().check(checker)
                paired.assert_not_called()

    def test_each_opposite_side_root_must_match_without_partial_pass(self):
        for side, names in (("Native", NATIVE), ("Reference", REFERENCE)):
            for name in names:
                fixture = Fixture()
                view = fixture.native if side == "Native" else fixture.reference
                view.canonical[name][0] = ("synthetic-wrong-opcode", "")
                view.refresh_tokens(name)
                with self.subTest(side=side, name=name), self.assertRaises(c.Rejected):
                    fixture.check()
        fixture = Fixture()
        with self.assertRaises(c.Rejected):
            j.check_join(fixture.reference, fixture.native, c, fixture.ledger)

    def test_view_evidence_requires_exact_three_root_membership_and_order(self):
        for side in ("Native", "Reference"):
            for change in ("missing", "unexpected", "order", "wrong-name"):
                fixture = Fixture()
                view = fixture.native if side == "Native" else fixture.reference
                if change == "missing":
                    del view.evidence[view.names[1]]
                elif change == "unexpected":
                    view.evidence["foreign"] = copy.deepcopy(view.evidence[view.names[1]])
                elif change == "order":
                    view.evidence = {name: view.evidence[name] for name in reversed(view.names)}
                else:
                    view.evidence[view.names[1]]["Name"] = view.names[2]
                with self.subTest(side=side, change=change):
                    self.rejects(fixture)

    def test_mixed_and_consistent_nonzero_tail_nops_never_get_o2_lto_credit(self):
        fixture = Fixture()
        fixture.native.append_tail(NATIVE[0])
        with self.assertRaisesRegex(c.Rejected, "mixed root tail-NOP"):
            fixture.check()
        fixture = Fixture()
        for _, view in fixture.sides():
            for name in view.names:
                view.append_tail(name)
        proof = c.check_pair(fixture.native, fixture.reference)
        self.assertEqual([row["TailNops"] for row in proof["RootEvidence"]], [1] * 6)
        with self.assertRaisesRegex(j.Rejected, "zero tail NOPs"):
            fixture.check()

    def test_complete_proof_root_names_scope_and_record_membership_are_required(self):
        changes = ((('Verdict',), "PARTIAL"), (('ProofScope',), "foreign"), (('ClosedBodies',), 3),
                   (('Roots',), list(reversed(NATIVE))), (('Roots',), list(NATIVE) + ["foreign"]),
                   (('RootEvidence',), []), (('RootEvidence', 0, 'Side'), "Reference"),
                   (('RootEvidence', 3, 'Name'), NATIVE[0]), (('RootEvidence', 0, 'Ignored'), True),
                   (('DifferenceSource', 'Spec'), "foreign"), (('ReferenceSvcObligation', 'HandlerRoutingProven'), True))
        for keys, value in changes:
            checker = ProofChecker(lambda proof, keys=keys, value=value: set_path(proof, keys, value))
            with self.subTest(keys=keys, value=value):
                self.rejects(Fixture(), checker)

    def test_mechanism_roots_names_and_difference_assignments_cannot_drift(self):
        changes = ((('Mechanisms',), []), (('Mechanisms', 0, 'Name'), "first-restore"),
                   (('Mechanisms', 1, 'NativeRoot'), NATIVE[2]), (('Mechanisms', 2, 'ReferenceRoot'), REFERENCE[0]),
                   (('Mechanisms', 0, 'DifferenceIds'), []),
                   (('Mechanisms', 1, 'DifferenceIds'), [DIFFERENCES[1], DIFFERENCES[3], DIFFERENCES[2]]),
                   (('Mechanisms', 2, 'DifferenceIds'), ["FAP-FOREIGN"]),
                   (('DifferenceIds',), list(reversed(DIFFERENCES))), (('DifferenceIds',), list(DIFFERENCES) + ["FAP-FOREIGN"]))
        for keys, value in changes:
            checker = ProofChecker(lambda proof, keys=keys, value=value: set_path(proof, keys, value))
            with self.subTest(keys=keys, value=value):
                self.rejects(Fixture(), checker)

    def test_child_proof_nonclaims_are_literal_false_and_cells_literal_integer_zero(self):
        keys = ("RequiredCellSatisfied", "CompleteObjectProof", "InstructionEquivalence", "CpuExecution",
                "FinalElfProof", "GlobalFreezeQualified", "BoardExecution", "FinalReferenceParity", "FullABIProof",
                "PolicyEquivalence", "SourceToMachineSemanticProof", "SourceToIRSemanticProof", "SourceIRProof")
        for key in keys:
            for value in (True, 0):
                checker = ProofChecker(lambda proof, key=key, value=value: set_path(proof, (key,), value))
                with self.subTest(key=key, value=value):
                    self.rejects(Fixture(), checker)
        for value in (True, False, 1, 0.0):
            checker = ProofChecker(lambda proof, value=value: set_path(proof, ("RequiredCellsSatisfied",), value))
            with self.subTest(cells=value):
                self.rejects(Fixture(), checker)

    def test_proof_numeric_boolean_aliases_and_raw_token_hash_substitutes_reject(self):
        changes = ((('ClosedBodies',), True), (('ClosedBodies',), 6.0),
                   (('RootEvidence', 0, 'Tokens'), True), (('RootEvidence', 0, 'Tokens'), 999),
                   (('RootEvidence', 0, 'LiteralIslands'), True), (('RootEvidence', 0, 'LiteralIslands'), 1.0),
                   (('RootEvidence', 0, 'TailNops'), False), (('RootEvidence', 0, 'TailNops'), 0.0),
                   (('RootEvidence', 0, 'BodySha256'), "not-a-hash"), (('RootEvidence', 0, 'BodySha256'), "0" * 64))
        for keys, value in changes:
            checker = ProofChecker(lambda proof, keys=keys, value=value: set_path(proof, keys, value))
            with self.subTest(keys=keys, value=value):
                self.rejects(Fixture(), checker)

    def test_raw_transport_completeness_typed_counts_and_nonclaims_are_preserved(self):
        changes = ((('Name',), "foreign"), (('GeneratedMachineBoundRootPreservation',), 1),
                   (('RequiredCellsSatisfied',), False), (('RequiredCellsSatisfied',), 0.0),
                   (('Size',), True), (('Size',), 0), (('InstructionCount',), True), (('InstructionCount',), 0),
                   (('Instructions',), []), (('MappedData',), []), (('References',), None),
                   (('DefinitionOrigins',), None), (('RootOrigin',), None),
                   (('RootOrigin', 'Name'), "foreign"), (('RootOrigin', 'ProviderSha256'), "0" * 64),
                   (('RootOrigin', 'GeneratedMachineOriginBound'), 1))
        flags = ("CanonicalProtocolValidated", "OriginalTranslationUnitOwnership", "FinalReferenceParity",
                 "PolicyEquivalence", "CpuExecution", "BoardExecution", "GlobalFreezeQualified", "FullABIProof",
                 "CompleteObjectProof", "InstructionEquivalence", "SourceIRProof", "SourceToMachineSemanticProof",
                 "SourceToIRSemanticProof")
        changes += tuple(((flag,), value) for flag in flags for value in (True, 0))
        changes += tuple((("RootOrigin", flag), value) for flag in
                         ("OriginalTranslationUnitOwnership", "CalleeBodyProof", "CalleeRelocationSemanticsChecked")
                         for value in (True, 0))
        for side in ("Native", "Reference"):
            for keys, value in changes:
                fixture = Fixture()
                view = fixture.native if side == "Native" else fixture.reference
                set_path(view.transport.records[view.names[1]], keys, value)
                with self.subTest(side=side, keys=keys, value=value):
                    self.rejects(fixture)

    def test_evidence_hash_domains_tokens_and_projection_membership_are_exact(self):
        common = ((('MachineProviderSha256',), "0" * 64), (('MachineBodySha256',), "0" * 64),
                  (('FinalBodySha256',), "0" * 64), (('HashDomains', 'MachineRoot'), "canonical tokens"),
                  (('RawCanonicalTokens',), []), (('RawCanonicalTokens',), [("nop", False)]),
                  (('RawTokenSha256',), "0" * 64), (('TransportRecord', 'MachineBodySha256'), "lowercase"),
                  (('TransportRecord', 'BodySha256'), "0" * 64))
        for side in ("Native", "Reference"):
            for keys, value in common:
                fixture = Fixture()
                view = fixture.native if side == "Native" else fixture.reference
                set_path(view.evidence[view.names[1]], keys, value)
                with self.subTest(side=side, keys=keys):
                    self.rejects(fixture)
        for side, keys, value in (("Native", ("ProjectionEvidence",), []),
                                  ("Native", ("ProjectedCanonicalTokens",), []),
                                  ("Native", ("ProjectedTokenSha256",), "0" * 64),
                                  ("Reference", ("ProjectionEvidence",), [{}]),
                                  ("Reference", ("ProjectedCanonicalTokens",), []),
                                  ("Reference", ("ProjectedTokenSha256",), "0" * 64)):
            fixture = Fixture()
            view = fixture.native if side == "Native" else fixture.reference
            set_path(view.evidence[view.names[1]], keys, value)
            with self.subTest(side=side, keys=keys):
                self.rejects(fixture)
        fixture = Fixture()
        fixture.native.evidence[NATIVE[0]]["ProjectionEvidence"] = [{}]
        self.rejects(fixture)

    def test_pure_join_does_not_mutate_inputs_and_returns_detached_evidence(self):
        fixture = Fixture()
        before = copy.deepcopy((fixture.native.canonical, fixture.native.evidence, fixture.native.transport.records,
                                fixture.reference.canonical, fixture.reference.evidence, fixture.reference.transport.records,
                                c._NATIVE, c._REFERENCE))
        with patch("builtins.open", side_effect=AssertionError("pure join cannot open files")), \
                patch.object(Path, "open", side_effect=AssertionError("pure join cannot open files")), \
                patch.object(Path, "read_bytes", side_effect=AssertionError("pure join cannot read files")), \
                patch.object(Path, "read_text", side_effect=AssertionError("pure join cannot read files")), \
                patch.object(Path, "write_bytes", side_effect=AssertionError("pure join cannot write files")), \
                patch.object(Path, "write_text", side_effect=AssertionError("pure join cannot write files")), \
                patch("subprocess.Popen", side_effect=AssertionError("pure join cannot run processes")):
            result = fixture.check()
        result["Roots"]["Native"][0]["TransportRecord"]["RootOrigin"]["Name"] = "changed-output"
        result["Roots"]["Reference"][0]["RawCanonicalTokens"][0] = ("changed-output", "")
        result["RawTransportRoots"]["Reference"][0]["CanonicalProtocolValidated"] = True
        result["ProtocolProof"]["Mechanisms"][0]["DifferenceIds"].clear()
        result["Mechanisms"][0]["DifferenceIds"].clear()
        after = (fixture.native.canonical, fixture.native.evidence, fixture.native.transport.records,
                 fixture.reference.canonical, fixture.reference.evidence, fixture.reference.transport.records,
                 c._NATIVE, c._REFERENCE)
        self.assertEqual(after, before)
        self.assertEqual(fixture.check()["Mechanisms"], MECHANISMS)

    def test_ledger_requires_ascii_text_and_exact_ordered_difference_proof(self):
        proof = c.check_pair(FakeView("Native"), FakeView("Reference"))
        for value in (None, b"ledger", "non-ASCII \u00e9"):
            with self.subTest(ledger=value), self.assertRaises(j.Rejected):
                j.require_ledger(value, proof)
        for identities in ([], tuple(DIFFERENCES), list(reversed(DIFFERENCES)), list(DIFFERENCES) + [DIFFERENCES[0]]):
            changed = dict(proof, DifferenceIds=identities)
            with self.subTest(identities=identities), self.assertRaises(j.Rejected):
                j.require_ledger(ledger(), changed)
        for malformed in (None, [], {}, {"DifferenceIds": True}):
            with self.subTest(proof=malformed), self.assertRaises(j.Rejected):
                j.require_ledger(ledger(), malformed)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    output, temporary = args.output_dir.resolve(), Path(tempfile.gettempdir()).resolve()
    if (output.exists() or args.output_dir.is_symlink() or output.is_relative_to(REPO)
            or REPO.is_relative_to(output) or not output.is_relative_to(temporary)):
        parser.error("fresh external TEMP output directory required")
    report = dict(Status="FAIL", Tests=0, ExpectedTestMethods=EXPECTED_METHODS, Failures=0, Errors=0, Skipped=0,
        SourceHashes={}, SourceDrift=[], SourceClosureVerified=False, ClosingFilesVerified=0,
        Scope="PURE_SYNTHETIC_CM3_LTO_SIX_BODY_JOIN_CONTROLS_ONLY", SyntheticInputs=True, FrozenCheckerUsed=False,
        ActualELFTested=False, ActualMachineDecoderTested=False, ActualTransportPreservationTested=False,
        ActualProtocolViewsTested=False, Qualification=False, NativeCommandsExecuted=0, ToolInvocations=0,
        FinalReferenceParity=False, FullABIProof=False, FinalElfProof=False, SourceIRProof=False,
        SourceToIRSemanticProof=False, SourceToMachineSemanticProof=False, CompleteObjectProof=False,
        OriginalTranslationUnitOwnership=False, InstructionEquivalence=False, PolicyEquivalence=False,
        KernelRuntimeProof=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
    paths = (Path(__file__).resolve(), JOIN, CHECKER)
    try:
        if sys.flags.optimize or not __debug__:
            raise ValueError("optimized interpreter unsupported")
        buffers = {path: path.read_bytes() for path in paths}
        report["SourceHashes"] = {str(path): sha(data) for path, data in buffers.items()}
        if sha(buffers[JOIN]) != JOIN_SHA256 or sha(buffers[CHECKER]) != CHECKER_SHA256:
            raise ValueError("exact frozen join and unchanged checker source cohort required")
        global j, c
        with patch("subprocess.Popen", side_effect=AssertionError("pure controls cannot execute processes")), \
                patch("os.system", side_effect=AssertionError("pure controls cannot execute processes")):
            j = module("pure_cm3_lto_join", JOIN, buffers[JOIN])
            c = module("pure_cm3_lto_join_frozen_checker", CHECKER, buffers[CHECKER])
            report["FrozenCheckerUsed"] = True
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(JoinTests)
            count = suite.countTestCases()
            if count != EXPECTED_METHODS:
                raise ValueError("exact 18 synthetic join control methods required")
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        report.update(Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
            FailureDetails=[dict(Test=str(case), Detail=detail) for case, detail in result.failures + result.errors])
        if result.wasSuccessful() and result.testsRun == count and not result.skipped:
            report["Status"] = "PASS"
    except Exception:
        report.update(Status="FAIL", Error=traceback.format_exc(), Errors=report["Errors"] + 1)
    finally:
        for path, value in report["SourceHashes"].items():
            try:
                if sha(Path(path).read_bytes()) != value:
                    report["SourceDrift"].append(path)
                else:
                    report["ClosingFilesVerified"] += 1
            except OSError:
                report["SourceDrift"].append(path)
        report["SourceClosureVerified"] = len(report["SourceHashes"]) == 3 and not report["SourceDrift"]
        if not report["SourceClosureVerified"]:
            report["Status"] = "FAIL"
    output.mkdir(parents=True, exist_ok=False)
    target = output / "results.json"
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="ascii")
    print("Receipt:", target, sha(target.read_bytes()))
    return 0 if report["Status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
