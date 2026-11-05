"""Explicit Os-LTO six-body composition of unchanged CM3 predicates.

The caller admits both actual Os captures and the frozen helpers. This module
does no I/O and does not relabel an O2 witness or mutate its expected protocols.
"""
import copy


NATIVE_ROOTS = ('fiber_port_start_first_context', 'SVC_Handler', 'PendSV_Handler')
REFERENCE_ROOTS = ('prvPortStartFirstTask', 'vPortSVCHandler', 'xPortPendSVHandler')
COHORT = 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default'


def check_join(native_view, reference_view, checker, ledger_text, frozen_join):
    """Recompute complete protocol/evidence predicates; construct an Os result.

    Frozen helpers validate full bodies, origins, hashes and rationale roles.
    Their zero-tail rule applies here too. No successful O2 result is consumed.
    """
    f = frozen_join
    f.need(tuple(f.NATIVE_ROOTS) == NATIVE_ROOTS and tuple(f.REFERENCE_ROOTS) == REFERENCE_ROOTS
           and f.COHORT == COHORT, 'exact frozen CM3 helper identity contract')
    f.need(native_view is not reference_view, 'distinct native and reference views required')
    native_machine = f._machine(native_view, 'Native')
    reference_machine = f._machine(reference_view, 'Reference')
    f.need(native_machine != reference_machine, 'two distinct actual machine byte inputs required')
    f.need(type(getattr(checker, '_NATIVE', None)) is dict and tuple(checker._NATIVE) == NATIVE_ROOTS
           and type(getattr(checker, '_REFERENCE', None)) is dict and tuple(checker._REFERENCE) == REFERENCE_ROOTS
           and callable(getattr(checker, 'check_pair', None)), 'unchanged complete six-root checker contract')
    f.need(type(ledger_text) is str and ledger_text.isascii(), 'captured ASCII difference ledger required')
    proof = checker.check_pair(native_view, reference_view)
    f._proof(proof)
    f.need(f._machine(native_view, 'Native') == native_machine
           and f._machine(reference_view, 'Reference') == reference_machine,
           'machine bytes changed while checking complete Os protocols')
    roots, transports = {}, {}
    roots['Native'], transports['Native'] = f._evidence(
        native_view, 'Native', NATIVE_ROOTS, proof['RootEvidence'][:3])
    roots['Reference'], transports['Reference'] = f._evidence(
        reference_view, 'Reference', REFERENCE_ROOTS, proof['RootEvidence'][3:])
    rationales = f.require_ledger(ledger_text, proof)
    return dict(Status='CM3-OS-LTO-SIX-BODY-JOIN-PASS-NOT-QUALIFIED',
        Scope='CM3_OS_LTO_P4_B16_DIRECT_SIX_CLOSED_ROOT_JOIN_ONLY',
        Profile='CM3', Mode='Os-lto', Cohort=COHORT, Linkage='direct', LTO=True,
        Qualification=False, ClosedBodies=6, Mechanisms=copy.deepcopy(proof['Mechanisms']),
        DifferenceIds=copy.deepcopy(proof['DifferenceIds']), ProtocolProof=copy.deepcopy(proof),
        Roots=roots, RawTransportRoots=transports, OriginalTransportRecordsUnmodified=True,
        DifferenceRationales=rationales, LedgerSha256=f._sha(ledger_text.encode('ascii')),
        MachineSha256=dict(Native=f._sha(native_machine), Reference=f._sha(reference_machine)),
        FrameContract=dict(NativeCoreSlots=9, NativeExcReturn='PER-CONTEXT-SAVED-LR',
            ReferenceCoreSlots=8, ReferenceFirstRestoreExcReturn='ORR-LR-13', EquivalenceProven=False),
        CanonicalProtocolValidated=True, FinalReferenceParity=False, FullABIProof=False, FinalElfProof=False,
        SourceIRProof=False, SourceToIRSemanticProof=False, SourceToMachineSemanticProof=False,
        OriginalTranslationUnitOwnership=False, InstructionEquivalence=False, PolicyEquivalence=False,
        CompleteObjectProof=False, KernelRuntimeProof=False, HandlerRoutingProven=False,
        ProducerCompilersReexecuted=False, MutantsReexecuted=False, NativeCommandsExecuted=0,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False, RequiredCellSatisfied=False,
        RequiredCellsSatisfied=0)
