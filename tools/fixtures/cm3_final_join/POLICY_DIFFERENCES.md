# CM3 Final-Join Policy Differences

This document specializes six existing ledger IDs for the one CM3 p4/b16,
soft/no-FPU/no-MPU cohort. The normative assignments are the fixed
`cm3_freeze_parity/check.py:_MECHANISMS` and the table in `CONTRACT.md`.
All six rationales must also exist in the admitted inventory's immutable
captured `FREERTOS_ASM_PARITY.md` ledger. This text neither replaces that ledger
nor adds IDs, broadens an assignment, filters instructions or waives a failed
protocol. It describes different contracts, not equivalence or target results.

### FAP-COMMON-START

Assigned to first-start. The reference starts the task already held in its
private `pxCurrentTCB`; first-start obtains MSP through VTOR at `0xE000ED08`,
enables interrupts and enters SVC 0. Native selects through the user scheduler
and common runtime state, validates its start plan, establishes the privileged
control plane with the architecture's checks, clears stale PendSV and enters
the dedicated SVC 70 path. These are separate preparation/activation contracts.
Matching the complete transfer roots does not close the preceding general C
selection/setup chain or prove that either SVC handler actually executes.

### FAP-COMMON-PROVENANCE

Assigned to all three mechanisms. Native handlers retain exception identity,
EXC_RETURN, stack origin/alignment/bounds, stacked xPSR/PC/SVC and selected
context validation, including their exact failure edges and call order.
Reference assembly relies on trusted kernel/TCB ownership and is shorter.
Those additional native checks cannot be ignored, moved past the corresponding
transfer, or replaced by the transfer itself. A map-bound definition, matched
instruction protocol or stored context seal is not a proof of live stack
contents, actual exception provenance or successful hardware execution.

### FAP-COMMON-SCHEDULER

Assigned to PendSV. Native calls
`fiber_port_scheduler_pick_next_from_pendsv` through its fixed bridge and
common-state contract. Reference calls `vTaskSwitchContext` while preserving
r3/LR on MSP. The link-only reference provider is a typed fail-stop boundary,
not a kernel scheduler, simulated task switch or fabricated TCB.
Each call must retain its own exact target entry, original provider identity,
map placement, mask envelope and ordering. Callee origin binding does not prove
the C callback/bridge/kernel algorithm or recursively close its call graph.

### FAP-COMMON-MASK-RESTORE

The fixed assignment is first-restore. Native SVC retains its explicit
PRIMASK/barrier envelope around validated restoration and clearing BASEPRI.
Reference SVC clears BASEPRI before ORR/BX without the native validation and
global-mask sequence. Do not summarize this as first-SVC restoration of a
previous BASEPRI value: its actual protocol clears BASEPRI.

The complete PendSV protocols also retain a mask-policy difference: native
saves incoming BASEPRI, raises it to 16 and restores the saved value after its
scheduler bridge; reference sets 16 and subsequently clears it to zero under
its kernel mask-state assumption. This difference remains visible in PendSV's
complete scheduler/provenance protocols. It does not add this ID to PendSV's
frozen assignment. No interrupt-window, prior-mask or MMIO equivalence is
inferred by relabeling or normalizing those instructions.

### FAP-CM3-EXC-RETURN

Assigned to first-restore and PendSV. Native stores nine software-frame words:
r4-r11 and exact EXC_RETURN in LR, which is validated and restored as part of
the frame. Reference CM3 stores/restores eight core-register words only.
Reference first restore uses the actual handler LR and the exact
`orr lr,lr,#13` instruction to construct the Thread/PSP return; it does not
load a ninth EXC_RETURN word. Reference PendSV preserves LR across its C call,
rather than placing it in each task's software frame.

The join must retain both frame protocols, register lists and LR operations.
There is no synthetic LR slot, erased ORR, frame-size normalization or implicit
comparison of initial r4-r11 values. The matched protocols do not establish
dynamic EXC_RETURN values, architectural exception completion or live frame
safety. CM0's staged high-register restore/C SVC dispatcher is not applicable.

### FAP-CM3-LOCAL-LITERAL-POOLS

Assigned to all three mechanisms. Native CM3 uses bounded port-local CPU/NVIC
helpers and local `.ltorg` placement following its terminal failure branches.
Reference retains its own inline-assembly `.ltorg` sites. These are real binary
layout differences: pool/padding boundaries and distances are not discarded
to obtain a common token stream. Canonical protocol tokens, symbol extents,
full original owning-section records and raw final bytes remain distinct.

The reference root relocations are the two `pxCurrentTCB` ABS32 words with
original addend zero and one `vTaskSwitchContext` THM_CALL with original addend
-4. Native retains its separate current-context slot, validation/panic calls
and scheduler bridge. Every applied address must bind its own unapplied
original REL authority and actual map/provider placement. Ordinary direct
twins do not establish native-LTO reach, archive behavior, hostile-helper
closure or whole-function instruction equivalence between implementations.
