# C3FS Paired Initializer Execution

`tools/test_cm33f_secure_initialize.ps1` requires existing ARM GCC14, CMSIS,
the clean pinned FreeRTOS kernel, Python/pyelftools0.33 and an explicit existing
WSL QEMU root. It installs nothing, programs no board and runs no full matrix.
`-Smoke` is development-only and cannot qualify this suite.

## Actual Images And Ownership

Two independently linked Cortex-M33 images execute on QEMU AN505. The Secure
image contains the unchanged three production C3FS gateway/pool objects and
exactly nine generated NSC veneers/imports. No allocator, load/save shortcut,
runtime bundle, public context provider or dummy lifecycle operation is added.
Fixture SVC/PendSV/SysTick handlers are not production handlers or activation.
RuntimeSelectable remains0, with the same C3FS public identity/layout/storage.

Secure boot establishes full Secure CPACR before any query. The production
initializer, not boot or an NSC wrapper, performs its PRIS/stack/pool/CONTROL2/
NSACR/LSPENS/TS sequence. The NS fixture queries before initialization from
Thread, and after initialization only from Handler: a zero Secure PSP after
CONTROL2 is not a usable Thread-mode Secure stack. The final NS fixture grants
NS CPACR explicitly, then probes real S0/S31 access. Output GPRs are cleared
before the FP reads so NOPs cannot accidentally preserve expected constants.
This is an access-permission probe, not FP context preservation.

Each qualified hard/softfp O2/Os normal/LTO tuple has normal and raw-hostile
production builds. Normal builds cover all declared cases; hostile builds
replay an explicitly listed critical subset. Complete generated production
text is decoded using ELF `$t/$d` mapping symbols, with no omitted instruction
bytes, no FP instructions and only the exact admitted APSR flags cleanup.
Initializer/helper intervals and instruction hashes are retained. All nine
public veneers must decode as real SG plus a direct branch to the real body.
These are the supported GCC14 envelopes, not a general no-V rule for CMSE.

## Entry And Failure Cases

Every nonterminal run independently executes a direct Secure SVC rejection,
NS Thread/PendSV/SysTick rejections, then actual NS SVC first/repeated calls.
False admission covers startup-marker states, BFHFNMINS, shared FPCA, SFPA,
both banked LSPACT flags and defensive CONTROL_NS read corruption. Each of the
eight queries has its own missing-CPACR and nPRIV terminal case, with partial
CP10/11 grants additionally tested on the first query and initializer.

FPCA is shared, not an independently banked NS bit. Real NS-view writes first
establish test-owned NSACR permission and necessarily affect the Secure view.
The otherwise redundant CONTROL_NS check is exercised separately by injecting
its destination after an actual MRS; that is a named corruption test, not a
coherent alternate CPU state. Actual CPU MRS is used because QEMU's raw GDB
CONTROL_NS storage does not include shared FPCA. Every real SG instruction is
stepped and its entry SFPA0 is observed. Nonzero SFPA admission is exercised by
an actual CPU MSR after SG, not by pretending the NS view can write SFPA.
The suite does not claim a nonzero pre-SG SFPA seed through QEMU's restricted
banked GDB setter; that development attempt is not qualifying evidence.

Post-commit cases inject failed AIRCR/PSP/PSPLIM/CONTROL/NSACR/FPCCR readbacks
after their actual instructions. Pool return0/2 is injected after the actual
whole-pool operation returns1. The real one-way INITIALIZING marker must stay
closed and repeated calls must not change backend state. Marker-write loss,
first/last-byte RAM corruption after the real scrub, pool-state corruption,
and private pool entry-state corruption exercise actual terminal paths.

The private AF_UNIX RSP transport is reused read-only from A26. Policy changes
execute explicit fixture Secure CPU STR/MSR helpers, avoiding attribution-
dependent debugger MMIO writes. RAM corruption and destination-register
readback injections are separately logged. They do not replace SG, exception
entry, banked-state execution, production instructions, pool code or FP hardware.

Terminal acceptance requires the actual production UDF PC, the actual Secure
UsageFault entry, exact stacked PC/xPSR/frame, expected EXC_RETURN basic frame,
CFSR UNDEFINSTR without NOCP, no HFSR, one matching CPU-produced report and
exit42. Unrelated faults, timeouts, missing reports and exit codes alone cannot
pass. Classifier mutations of the actual captured record are separate negative
controls, not extra CPU executions. Each case additionally requires its declared
outcome (success, false admission, sticky failure or exact terminal fault) and
its named injection. A terminal case returning0 cannot pass as false admission.

## Compiled Controls And Reference

Test-local mutations compile actual current source with one query preflight,
CONTROL_NS predicate, exact pool-return check or exact CONTROL check removed
or weakened. The CPU oracle must reject the first return or stop before the
forbidden commit/next backend effect. Removing GRO must fail complete production
text inspection. `FIXTURE_FP_NOP_CONTROL` changes only the fixture's FP probe
to NOPs and must fail its exact data check after a successful initializer.
No committed precompiled control or compiler-executable hash is required.

Actual pinned `portable/GCC/ARM_CM33` at
`a50edad08b29052631aa469d4df6e6ec7ff68878` is compiled for MPU0/FPU1/TZ1,
hard/softfp O2/Os: both NS source units and all four Secure units. Complete
preprocessed/generated/object bodies and exact source/tool/artifact hashes are
retained. Reference CMSE FP cleanup is not passed through the production
integer-only oracle. The earlier paired-reference suite remains separate;
this gate does not execute a FreeRTOS scheduler or claim whole-port equivalence.

## Receipts And Limits

Receipts include commands, text snapshots, before/after input hashes, actual
QEMU/interpreter/resolved-library hashes, final ELFs/maps/imports/disassemblies,
per-case CPU events and exact classifier/control results. Unique output roots
are never reused or recursively deleted. Production positives use actual
unmodified source; compiled controls have original/mutant hashes and exact
single-change descriptions. Counters and hashes belong to the final receipt.

The fixture reserves Secure MSP RAM0x30001000..0x30004000 and separate mapped NS
stacks. These trusted integration-owned stacks support the exercised C/CMSE/
exception paths, not arbitrary physical-MSP corruption containment or arbitrary
nesting. No Secure stack allocation, lazy FP trigger, high-FP save/load,
Secure-origin running EXC_RETURN admission, complete Fiber runtime, physical
board support or exhaustive feature/geometry combinations are qualified here.
Required integration counterflags remain normative; raw hostile closure is
additional evidence for the named six flag classes, not a -pg/stack-check claim.
