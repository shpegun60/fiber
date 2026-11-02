# C3FP First-Start Code Generation

Run `tools/test_cm33f_mpu_first_start_codegen.ps1 -ArmGcc <gcc.exe>
-CmsisCore <CMSIS/Include> [-FreeRtosRoot <pinned-kernel>] [-BuildRoot <output>]
[-ExpectedSvcSha256 <freeze-hash>]`. Python 3 standard library only is required;
there is no package installation, emulator, board, or network operation.

The maintained cross-product is O2/Os, hard/softfp, 8/16 MPU regions, and normal/
LTO: 16 configurations. Each links an unmodified pinned FreeRTOS comparator and
normal plus countered-hostile production ELFs, all with section GC. The source
pin is `a50edad08b29052631aa469d4df6e6ec7ff68878`; tracked and untracked reference
changes reject qualification. Production/fixture/reference/header/compiler-tool
inputs are hashed before/after. Commands, preprocessed sources, generated
assembly, objects, dependency files, maps, disassembly, ELF attributes/symbols,
oracle observations, failed attempts, and artifact hashes remain in a unique
build directory. Any input drift fails rather than issuing PASS.

## What Is Checked

The production SVC object exports exactly seventeen functions and three return-site
labels: its prior seven functions, seven generic forward operations, the bundle,
and two shared PRIMASK helpers. The separately compiled real PendSV object exports
exactly eight functions, including the cold component-v1 anchor and first-pick helper.
The final ELF has unique strong SVC/PendSV handlers in vector slots 11/14 and
exact owned SVC70/71/72 opcodes. The actual eight-operation forward surface is
present (constructor plus seven adapters), and `FIBER_PORT_RUNTIME_SELECTABLE == 1`
reflects the separate complete-group qualification. This fixture does not supply
a common five-call runtime. Linking the
running components is required for compatibility; it does not qualify their
execution or turn this first-start gate into a running-runtime gate.
Cold preparation must call the actual PendSV component anchor before initial
context validation. Both cold functions must perform a resolved volatile byte
read of the readonly one-byte reverse-v1 marker. The provider object's exact
strong external definition is checked before link; legitimate LTO internalization
to a final local object does not invalidate its retained volatile loads. Final
size, value and nonwritable section flags are checked separately. No fixture component
anchor or replacement PendSV helper is supplied. This is a mandatory separate
component link contract. The real SVC owns exactly one context/storage provider
pair; both must remain strong, readonly, one-byte value 1 objects resolving the
fixture's exact manifest expectations. The fixture may not define providers,
forward adapters or the bundle. The bundle must call the real PendSV component;
runtime preparation must call the bundle, and first selection must call the
actual first-pick helper with its preserved capture/callback/validation envelope.
New definitions' preprocessed headers must carry the canonical sensitive bundle
and general-register target attributes. Final placement is checked independently:
privileged mandatory operations/bundle, unprivileged barrier and public-name
terminal fixtures, and syscall-region runtime schedule. Schedule must be a
single tail branch to the unchanged real SVC71 veneer.

The three first-start/handler naked functions and the two real service veneers
are compared against complete independent normalized
instruction lists, including rejection branches and terminal panic sinks, not
just a set of regex matches. Only Thumb width suffixes, register aliases,
literal-pool addresses, and assembler spelling aliases are normalized. Literal
values come from actual ELF bytes; function ranges come from ELF symbols.
Every function byte is accounted for using ARM `$t`/`$d` mapping symbols.
Executable bytes require a decoded two/four-byte instruction matching the ELF
bytes, without gaps or overlaps. Naked-function data must be a trailing,
actually referenced literal pool or its zero alignment padding. Unknown live
`.word`/`.inst` bytes cannot disappear from the comparison. Repeated mapping
names are valid; ambiguous function-symbol lookups fail rather than selecting
the last dictionary entry. All local function records are audited separately.
Same-named private helpers in separate translation units are resolved through
the actual direct call address, not an ambiguous name lookup. Only GCC's exact
`.lto_priv.N` local-name disambiguation is normalized; global handler ambiguity
still rejects and has its own maintained compiled control.
The expanded SVC handler must route exact B8 to MSP and BC/AC to PSP before
tail-dispatch, with explicit branch targets and unchanged terminal rejection
sinks. The first-start trampoline and basic restore retain their prior complete
sequence expectations. Each of the three global return sites is proved to be
exactly two bytes after its owner's SVC opcode.

The restore proves MPU disable, MAIR0, RNR 4[/8/12] four-pair alias blocks,
exact MPU_CTRL=5 enable, active-image validation before transfer, saved PSP and
PSPLIM write/readbacks, saved CONTROL write plus readback of bits 0..2 equal to
3, and exact final EXC_RETURN=0xFFFFFFBC. Incoming origin is 0xFFFFFFB8. The
4+8+8 descending loads consume the 20-word basic image and reset its cursor;
the separate statically asserted backing capacity is 54 words, not 54 first-
restore words. Hardware r0-r3/r12/LR/PC/xPSR are copied to PSP and r4-r11 are
restored in the pinned reference order. BASEPRI clearing, PRIMASK enable, and
barriers are included in the sequence checks.

Generated C envelopes are checked for required ordered calls and the resolved
RNR write/read, RBAR read, and RLAR read MMIO sites. These are structural
code-generation checks, not branch-condition execution, fault handling, live
PSP/mask behavior, real exception return, or MPU enforcement proof. Actual
execution is a separate parent-owned fixture.

Every production function in the linked boot/SVC/PendSV/provider graph is scanned
for ordinary FP/MVE instructions, indirect BLX, compiler instrumentation symbols,
and writable instrumentation counters; unresolved final symbols fail. Hostile
`-finstrument-functions -fstack-protector-all -fprofile-arcs -ftest-coverage
-fsanitize=undefined -fsanitize-coverage=trace-pc` must genuinely affect an
unprotected compiler control. Production's countered-hostile builds then append
the documented selected-port counter-options, including disabling trace-pc
coverage and `-mgeneral-regs-only`. CMSIS inline helpers do not inherit the
caller's attributes; this is not an attribute-only effective-hostile whole-
graph qualification. No CMSE security V-form exception is applicable to this
non-CMSE component. Only the real `PendSV_Handler` may contain FP transfers:
the exact ordered six VSTMIA/VLDMIA/VLDMDB forms for s16-s31 and s0-s16. All
other V-forms reject, including ordinary FP operations in helpers. The real
PendSV also has byte-complete decoding, but its complete branch/control-flow
parity and running FP behavior are outside this first-start gate.

Twelve real separately compiled mutants per hard/O2 region/LTO combination test
wrong PSP source, CONTROL readback, final EXC_RETURN, MPU transfer set, cursor
publication, incoming origin, an ordinary FP instruction, and removal of the
instrumentation protection, and live-path `.inst.w 0xED810000` / `0xFFFFFFFF`.
The two additional mutants change the actual yield/return veneer service numbers.
The two raw instruction controls must specifically hit DECODE. Each mutant
must link and hit its named oracle rejection;
a crash, traceback, compiler failure, or unrelated rejection is not success.
The instrumentation mutant alone links named forbidden compiler providers so
the oracle, not a missing library, rejects it. Duplicate strong SVC and PendSV providers
must also fail specifically with a multiple-definition diagnostic. A separately
assembled local duplicate SVC symbol must link but fail SYMBOL ambiguity.
All mutant links retain the real unaffected boot/PendSV objects; dropping the
new dependency is not an acceptable way to make a negative pass. The complete
grid requires 32 production ELF checks and 60 compiled/link negatives.

## Actual FreeRTOS Comparator And Differences

Both original `portable/GCC/ARM_CM33_NTZ/non_secure/portasm.c` and `port.c`
are compiled directly from the pinned tree. There is no handwritten replacement
restore or copied assembly extraction. LTO builds contain the actual LTO-compiled
reference, not a normal-object substitute. Complete shared privileged sections
also retain unrelated reference runtime code, including PendSV; none executes.
Comparison is limited to the named first-start functions. No whole-object or
whole-runtime equality is claimed.

| Area | Pinned reference | Deliberate Fiber difference |
| --- | --- | --- |
| Context source | Load pxCurrentTCB twice | Dispatcher passes validated selected context; MSP spill preserves it across the active-image validator |
| Origin/frame | Generic MSP/PSP SVC routing, wrappers-v2 syscall paths | First start requires exact NS Thread/MSP basic 0xFFFFFFB8, IPSR 11, owned SVC #70 site, frame and vector/map validation; BC/AC running routing is retained separately |
| SVC immediate | Start scheduler 102 | First-start 70; real selected-port 71/72 veneers are checked for exact surface, not execution here |
| MSP/start | VTOR load, MSP rewind, enable masks, SVC, NOP | Validated vector and full vector-storage range, explicit MSP readback, stale PendSV clear, barriers and terminal unexpected-return sink |
| FPU/start policy | prvSetupFPU inside C SVC dispatch, reference lazy policy | Production boot/FPU validation precedes SVC; Fiber default eager policy is not asserted equal to FreeRTOS lazy policy |
| Global MPU policy | Scheduler startup installs FreeRTOS global map | Dispatcher installs linker-derived Fiber global image and checks each region; current-pointer aperture is a separate RO/XN range |
| Per-context MPU | Same MAIR0 and RNR alias-block transfer order; preserve CTRL and OR enable | Additional serialization, require disabled geometry, exact CTRL=5 and active-image readbacks |
| Basic register transfer | LDMDB4, PSP/PSPLIM/CONTROL, LDMDB8/STMIA8/LDMDB8, cursor store | Same register groups/order; explicit PSP/PSPLIM and CONTROL=3 readbacks, exact final 0xFFFFFFBC guard, terminal failures |
| Exit | Clear BASEPRI and BX LR | Additional BASEPRI readback, PRIMASK enable and barriers before BX LR |
| Storage/construction | 54-word backing, 20-word basic restore, reference debug seeds and wrapper metadata | Same relevant frame shape; sealed Fiber metadata/live r9/zero seeds/default MPU map follow the separate constructor proof |

This is M33 ARMv8.0-M: no M55 ARMv8.1-M RLAR.PXN or MVE policy is imported.
The actual unmodified reference start/restore sequences and 54-word backing
facts are checked independently; Fiber's stronger guards are not mistaken for
an exact assembly equality claim. Generated C surrounding code may differ in
register allocation, branch layout, prologues, constant addressing and LTO
layout; only the explicitly stated structural facts are compared there.

## Test-Only Providers

Production fixture `providers.c` supplies the exact readonly reverse-v1 marker, current-pointer storage,
terminal `fiber_panic`, task/context/stack roots, and a synthetic 512-word vector table.
They are linkage providers only. The runner never calls them or any ARM code;
their presence does not constitute a production runtime/provider or prove
reachability, startup zeroing, or successful first exception return. The real
production task-return veneer is never shadowed. The fixture supplies the
reverse `fiber_internal_task_return` policy as `fiber_panic('R')`, matching
`fiber_core.c`. The only scheduler reverse providers are candidate selection
(terminal `'K'`, because no scheduler is configured here) and checked,
barrier-bracketed current publication, plus the faithful checked current-context
guard. Placement-only dependencies use visibly named C functions
`fixture_unexecuted_fiber_current`/`fixture_unexecuted_fiber_schedule` with public
assembler spellings and terminal UDF73/UDF74 loops; the ELF oracle checks those
exact traps. They are never executed and cannot supply a fake usable common
runtime. No fixture implements any of the eight forward operations. The providers satisfy the real retained PendSV's
exact dependencies, not an arbitrary unresolved-symbol prefix.

Reference providers supply pxCurrentTCB storage, a zero syscall implementation
table, terminal vTaskSwitchContext/xTaskIncrementTick/xTaskGetMPUSettings and a
synthetic task-return address. They satisfy retained reference sections only,
not a real kernel or syscall service. The reference config changes only the
task-return address to this named test-only provider; production reference
port.c/portasm.c source is unmodified. No SecureContext, complete NS runtime,
hardware isolation, physical no-FP silicon, or hardware-support claim follows.
