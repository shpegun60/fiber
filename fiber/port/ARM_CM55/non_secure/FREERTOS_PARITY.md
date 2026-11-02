# ARM_CM55 Non-secure SecureContext FreeRTOS Parity Ledger

## Staged Status

This staged selected-port profile freezes the exact scalar Cortex-M55
TrustZone Non-secure context dictionary used by the pinned FreeRTOS
`GCC/ARM_CM55/non_secure` port. Slice 1 provided no constructor, attachment,
runtime, handlers, or global selector route. Slice 2 adds the
paired immutable identity gateway, and Slice 3 adds a Secure-only static
capacity reservation plus immutable capacity queries in `ARM_CM55/secure`.
Slice 4 adds Secure-private pool initialization/allocation/lookup, not NSC
lifecycle operations. Slice 5 adds the paired one-shot NSC CPU/pool initializer
and its Non-secure declaration. Slice 6 adds allocation/load/save imports and
guarded Secure implementations, still without a Non-secure caller runtime.
Slice 7 adds an internal exact Secure-object cohort and build-owned generation
link assertion, not a new import or application expectation API. Slice 8 adds
Non-secure sealed construction and pre-start attachment only. Slice 9 adds
Non-secure sealed construction, pre-start attachment, and staged first start.
It supplies one owned first-start SVC, a private MSP plan and live Secure
handle. Slice 10 adds the private scalar running save/select/load component
and strong PendSV, not a complete forward runtime ABI or global selector route.
Slice 11 adds all eight forward operations and the real common-runtime
integration candidate, with qualification pending. Runtime selection remains
zero and no new complete-runtime claim is made before that gate passes.

### Standalone Private Include Closure

The private header now includes its own `fiber_portmacro.h` before boot types
and private declarations. The standard build-owned exact-context expectation
source includes only that private header, so it must receive the complete
selected-port trait/cohort contract without a hidden forced include. Every
production runtime C unit already includes the dictionary first; this repair
does not edit a naked transfer or context identity. The complete runtime gate
must qualify the ordinary include path, not promote the earlier explicitly
incomplete `DevelopmentExpectationInclude` execution receipt.

The focused parent compile proves eight ordinary expectation-object builds
(O2/Os and all four hash/map policies), each with exactly one expected private
cohort undefined symbol, without a forced port include. Receipt:
`%TEMP%/fiber-c55s-private-include-409255edf760493ebdd5c9c958dc450e`.
This compile-only result removes the include blocker; it does not promote the
staged profile or substitute for the full common/two-image runtime gate.

The future profile is one privileged, no-MPU, no-FPU, no-MVE Non-secure
scheduler image paired with one matching `ARM_CM55/secure` SecureContext
companion. FPU, MVE, MPU, PAC, BTI, TF-M, and Secure-only scheduling remain
separate exact profiles.

## Pinned Reference

```text
FreeRTOS commit: a50edad08b29052631aa469d4df6e6ec7ff68878
CPU runtime:     portable/GCC/ARM_CM55/non_secure/
Secure companion: portable/GCC/ARM_CM55/secure/
```

| Reference file | SHA-256 | Slice-1 disposition |
| --- | --- | --- |
| `non_secure/portmacro.h` | `B7F94C8C21A4B583837C10F00ED93A1EA8C5801DEA8A3AD6C6DB13A49F947420` | M55 identity and explicit MVE configuration requirement are mapped to exact compiler/trait gates. |
| `non_secure/portmacrocommon.h` | `324ACBC8D95D75FCFBDA0703E7891B35948BC21D1526BD32780EA8B935B724A2` | The shared ARMv8-M frame dictionary is the reference for the future runtime. |
| `non_secure/port.c` | `BEE0956FE5384827D28E63BC0F20D5837A09A87DC8B348B60E124B1B51EDBB9A` | Slice 8 maps the no-MPU `pxPortInitialiseStack` dictionary; Slice 9 maps first-start SVC initialization, not scheduler/runtime activation. |
| `non_secure/portasm.c` | `6F39F5CB7A24766DF3FA025E41E0E502301550136151B5E2EABDFA9AC4E42D60` | Slice 9 adapts `vStartFirstTask` and no-MPU `vRestoreContextOfFirstTask`; Slice 10 maps lines 441-542, no-MPU/FPU0/MVE0/PAC0 TrustZone PendSV, with differences below. |
| `non_secure/portasm.h` | `185477BF5A84B9B61927E4A0894427A4F471C448840DBF521F312B6F52D03B6C` | Slice 9 maps VTOR/MSP, basic EXC_RETURN and special-register first-restore vocabulary into private naked assembly. |
| `non_secure/mpu_wrappers_v2_asm.c` | `0DC69DD4372646D176CDF98429C8BC9A056E6B0200CB558C51DF4E1F10378D4F` | Explicitly outside no-MPU C55S. Its unprivileged syscall wrappers belong to the separately audited C55M/C55P/C55W MPU cohorts. |
| `secure/secure_context.h` | `8209F4BAF60741E8ED5516AF9706FC4B5B2EE3CF16452EDB0C034B7DDDE443B4` | Future paired opaque-handle contract. |
| `secure/secure_context.c` | `E25244584CE048F44AAD7C89E9FEA80B811141760F948FD775E0E9EB2964ED72` | Paired static pool and ordered initialization are implemented; Slice 9 calls initialize/optional allocate/load for first start only. |
| `secure/secure_context_port.c` | `B3ED96A95CB008F157082C4437D2846D740851865AD2E4DC893AED895823AF8E` | Slice 6 maps scalar PSPLIM-before-PSP load and stored-PSP-before-clear save; Slice 9 uses load only, with running switch integration deferred. |
| `secure/secure_heap.h` | `E58805B998EE73A9EB84627EBD2955787CDFD0CD968D1BC7D93423441BAB6C87` | Opaque allocation vocabulary is adapted to the implemented static Secure pool, not imported heap interfaces. |
| `secure/secure_heap.c` | `CE5D5F7FC774E7EC51157F5078361F3CB0A20CE9C94593396F543E5046E53F42` | Dynamic reference allocation is intentionally replaced by the static-lifetime pool; no FreeRTOS heap enters Fiber. |
| `secure/secure_init.h` | `7704E518DFAAE39170274B7DD924B1A214FFFB12DC37C050E7D3457B5AA0E149` | Paired one-shot initialization vocabulary; the NS header declares the C55S-versioned initializer only. |
| `secure/secure_init.c` | `1B8444698089651C6415D48A2B6716BA6C6DC32F71C51B679F5A8A9A3968DE55` | Keyed PRIS setup precedes Secure stack/pool/CONTROL initialization; the scalar cohort does not adopt NSFPUAccess. |
| `secure/secure_port_macros.h` | `5F2DF28DF3D445F08727CAF41F83ED6C67E0494E40AF5572B5E18F6416B2838D` | Future Secure compiler/architecture helper vocabulary; it stays in the paired Secure artifact. |

The pinned M55 `port.c`, `portasm.c`, `portasm.h`, `portmacrocommon.h`, and all
listed Secure companion sources are byte-identical to the pinned CM33
counterparts. Only
`portmacro.h` differs: FreeRTOS names Cortex-M55, reports ARMv8.1-M minor
version one, and requires an explicit `configENABLE_MVE` setting. Fiber does
not import a FreeRTOS config macro; its selected compiler manifest instead
requires scalar `-march=armv8.1-m.main` and rejects compiler MVE state.

## Frozen Non-secure Layout

The Non-secure software frame is exactly eleven words:

```text
low address -> high address
  word 0  opaque SecureContext handle
  word 1  PSPLIM
  word 2  EXC_RETURN
  words 3..10  r4..r11
```

The initial synthetic frame therefore consumes 76 bytes with the hardware
exception frame. The maximum no-FPU saved representation is 80 bytes including
the exception-alignment word. `FiberPortBoot.secure_stack_bytes` is frozen at
offset 28; construction defaults it to zero and attachment seals a nonzero
request without allocating Secure state. `FiberContext`
is 80 bytes and has exact cohort identity `C55S` / `0x43353553` with feature
mask `0x8A`.

## Manifest And Boundary

```text
FIBER_PORT_BUILD_SELECTED=1
FIBER_PORT_ARMV81M_MAINLINE=1
include path: fiber/port/ARM_CM55/non_secure
compiler: -march=armv8.1-m.main -mthumb -mfloat-abi=soft
CMSIS: __CORTEX_M=55, __VTOR_PRESENT=1, __FPU_USED=0
Non-secure compiler: __ARM_FEATURE_CMSE=1
```

Secure `-mcmse` compilation reports CMSE level 3 and is rejected by the
Non-secure profile. The eventual Secure image is a separate artifact, not a
second fiber runtime. Its Slice-2 identity and Slice-3 capacity veneers,
Slice-4 private pool, Slice-5 initializer, and Slice-6 stack-transfer entries
are qualified separately.

Slice 5 retains those eight immutable query names and adds exactly
`fiber_secure_context_gateway_c55s_v1_initialize` as the ninth NSC import.
The declaration has no Secure-entry attribute or CMSIS dependency. It is a
selected-backend boot operation, not an application initialization requirement.
Slice 9 calls it from the owned Non-secure first-start SVC only after
validating its exact call site. The Secure entry checks the
immediate Non-secure caller and IPSR=11 independently, rejects BFHFNMINS=1
before commitment, and performs PRIS -> PSPLIM=0 -> PSP=0 -> private pool
initialization returning exactly one -> CONTROL=2 with exact full readback ->
READY. It neither writes interrupt masks nor changes the Non-secure register
bank. See the Secure ledger for sticky failure and BSS-startup requirements.
Slice 6 retains all nine names and adds exactly:

```text
fiber_secure_context_gateway_c55s_v1_allocate(uint32_t bytes, uintptr_t owner)
fiber_secure_context_gateway_c55s_v1_load(uint32_t handle, uintptr_t owner)
fiber_secure_context_gateway_c55s_v1_save(uint32_t handle, uintptr_t owner)
```

All require immediate NS origin, READY, and exact Secure CONTROL=2. Allocate/
load permit only SVC11 or PendSV14; save is PendSV14-only. Allocate/load require
PSP=PSPLIM=0. A zero load/save handle succeeds only for a nonzero owner with both
stack registers zero. Nonzero handles are resolved only by Secure-private owned
lookup; no record pointer crosses the ABI. Load writes/verifies PSPLIM before
PSP. Save checks live geometry, stores PSP, barriers, verifies owned relookup
and the actual stored PSP, then clears/verifies PSPLIM before PSP. There is no
CONTROL write or explicit FP/MVE stacking trigger in these entries. No changes
to the initializer, pool geometry, C55S identity/layout/feature values, or ABI
version are required for the additive twelve-entry import set.

The Non-secure caller must validate its exact NS call site independently and treat
any partial-update failure as terminal: no retry, context selection, or Thread
resume. There is no rollback/recovery API. Twelve-entry CMSE linkage is not
evidence of a working Non-secure scheduler; runtime selection remains zero
until the future source group provides all eight mandatory forward operations
and strong vector handlers. No Non-secure Fiber runtime is claimed here.

CMSE housekeeping is not FP datapath support or a no-`V*` instruction promise.
The exact `FAP-CMSE-M55` classification remains mandatory; physical no-FPU/
no-MVE QEMU execution is unqualified even with a `__FPU_PRESENT=0` fixture.

The Slice-7 private guard binds the two Secure gateway objects and pool to the
same evaluated configuration/layout tuple. Ordinary queries extract the pool
through a strong non-NSC C helper, then retain their exact key read; initializer
does so after its preflight and before commitment. Allocation/load/save have
no new hot-path checks. The Secure integration separately includes
`secure/fiber_secure_context_cohort_contract.ld` to reject wholly pre-guard
archives. It is an assertion, not an archive extractor. See the Secure ledger
for the twelve-fact/24-halfword key and clean-rebuild boundary.

No external expected-capacity object is added. A coherent guarded Secure
archive's queries report its own configuration even when NS/application build
defines differ; callers must still validate the returned capacity facts. This
mechanism changes neither the twelve imports nor any NS context/public ABI.

## Slice 8: Sealed Construction And Attachment

`fiber_port_boot.c/.h` implement the CM33 construction prefix, not its later
MSP/start/restore runtime tail. The constructor `fiber_port_context_init` uses
a static local frame builder. It checks context/stack disjointness, alignment,
overflow, exact usable geometry, and integration-owned Non-secure RAM/code
hooks. Permissive weak hooks exist only with the explicit bring-up setting.
Hook declarations and all reachable private definitions carry canonical
sensitive/general-register-only attributes; the four new forced-inline helpers
use the inline-sensitive bundle instead of noinline/noipa attributes.
As in the CM33 prefix, GCC can lower boot-record initialization/copying to
freestanding `memset`/`memcpy` calls. Their linked implementations remain an
integration-owned sensitive/general-register-only call-chain obligation; a
fixture implementation is not evidence for an arbitrary platform C library.

The record retains magic/version 3, guards, exact C55S tuple, hash and seal.
It starts with `secure_stack_bytes=0`. The nineteen-word initial frame has
handle zero, PSPLIM equal to the aligned NS stack base, exact EXC_RETURN
`0xFFFFFFBC`, r4-r11, then a basic hardware frame. Its size is 76 bytes; the
minimum usable stack still covers the 80-byte maximum saved representation.
The constructor captures incoming r9 before integration calls, preserves it
at frame word 8, and checks it after construction. All other unused registers
are zero, R0 is the argument, LR is the terminal task-return service, PC is
the normalized Thumb entry, and xPSR is exactly the initial T-bit value.
The initial-frame checker deliberately does not require r9 to be zero.

The exact EXC_RETURN selects S=0, DCRS=1, basic Thread/PSP, ES=0. Altering
security, DCRS, FP-frame or stack-selection bits is not another accepted
initial image. The separate `0xFFFFFFB8` first-SVC-origin dictionary is used by
Slice 9. No Secure stack seal is placed in NS
storage: the two-word Secure seal remains the paired pool's responsibility.
Neither constructor nor attachment performs an s0/d0 lazy-state probe, writes
CONTROL/PSP/PSPLIM/masks, enables FP/MVE, or changes security attribution.

The Slice-8 attachment operation in `fiber_port_secure_context.c` is
`fiber_port_secure_context_attach(ctx, bytes)`, declared by the selected-port
`fiber_port_secure_context_abi.h`. Handler-mode rejection precedes the existing
optional common context-configuration lifecycle guard. Attachment validates
the sealed boot record and initial frame, rejects a duplicate request, and
checks all eight immutable C55S identity/capacity queries before resealing.
Each query result is checked after fresh NS IPSR, PRIMASK, BASEPRI, FAULTMASK,
CONTROL and PSPLIM readback. Local general-register MRS asm avoids acquiring
instrumentation through CMSIS register helpers. The request must be nonzero,
eight-byte aligned, and within the returned configured capacity. The frame,
including handle zero, stays unchanged. This is serialized pre-start mutation,
not a concurrent publication or rollback API.

Both objects retain their exact selected-context cohort expectation. They do
not define a context/storage provider; staged integration must supply an
explicit fixture provider, not mistake these sources for a complete runtime.
Attachment also retains the unchanged optional lifecycle-v1 anchor. That
operation calls only the eight query symbols, never initialize/allocate/load/save, and adds no
NSC, common operation, registration API, or persistent state. It cannot make
`fiber_start` available while `FIBER_PORT_RUNTIME_SELECTABLE` remains zero.

The FreeRTOS no-preload branch leaves unused registers uninitialized, while
Fiber deliberately zeros them and preserves its existing r9 platform-register
policy. Fiber additionally validates/seals metadata and turns the reference's
Thread-to-SVC allocation request into a pre-start size-only request. Actual
allocation/load was deferred by Slice 8; Slice 9 adds first-start use only.
These are explicit construction/attachment policies, not wholesale scheduler
equivalence. Optional lifecycle-service dependency inversion introduces no
Fiber/Task knowledge into the CPU interface.

The historical Slice-8 focused GCC 14.3.1 smoke covered ordinary C/C++ archive links at O0/O2/Os
and optimized LTO, missing/foreign selected-cohort, query and lifecycle links,
type-only consumption without CMSIS, and hostile O0/O2/Os builds including
explicit permissive weak hooks. That source snapshot had no persistent data,
stateful gateway imports, CPU-policy writes or FP datapath instructions in
those non-LTO checks. The query and memory-helper fixtures are test doubles;
these compile/link measurements do not execute construction or SG attachment.

Maintained Slice-8 qualification passed separately at
`%TEMP%/fiber-m55-secure-attachment-5d4be79794ac4bb6815bd0292bebc07f/results.json`:
892 execution cases, 1175 checks, seven O0/O2/Os/LTO/hostile modes, 133 inputs,
zero drift, complete suite. Its receipt SHA-256 is
`CE7592C97520E04E0A1FB2FD5F20CFFD73E57CE8474711F8D4EBFE6A10F19B86`.
It covers actual-reference construction, complete initial bytes/r9, malformed
ranges and records, request/lifecycle/query/CPU-state failures, archive/GC
negatives, hostile codegen, and real two-image Thread-to-SG attachment. It is
not a first-start receipt or qualification of the later Slice-9 source state;
the attachment runner snapshots all local NS C/headers and must be rerun after
the new source freeze. No hardware result or physical-no-FPU qualification is
implied; `FAP-CMSE-M55` remains in force.

## Slice 9: Staged First Start

The only new production files are `fiber_port_private.h`,
`fiber_port_runtime.c`, `fiber_port_svc.c`, and
`fiber_port_first_start_contract.ld`. Despite its conventional filename, the
runtime source supplies no generic eight-operation runtime provider. Existing
boot, dictionary, and attachment sources supply only the needed private cold
checks and first-start helper. No Secure source, twelve-entry gateway ABI,
context/storage tuple, public operation, selector route, PendSV or yield is
changed. `FIBER_PORT_RUNTIME_SELECTABLE` remains zero. Explicit staged
integration supplies the matching context/storage provider and the ordinary
reverse-v1 services/data; production staged sources define neither provider.

The integration publishes its first context before calling the private
`fiber_port_first_start(first)` entry in privileged NS Thread/MSP, with CONTROL,
PRIMASK, BASEPRI and FAULTMASK zero. Preparation checks immutable linker-owned
vector/code maps and reserved MSP bounds, VTOR, the exact strong SVC vector,
vector MSP top, context/raw-stack disjointness from reserved MSP, the sealed
cold frame and unchanged CPU state around integration hooks. Its real C call
to `fiber_port_arm_cm55_secure_context_first_start_component_v1_anchor` roots
the separate handler object and retained exact context/reverse identities
under ordinary archive extraction; it does not depend on an asm-only archive
reference or provide an always-linked fake runtime. A zeroed twelve-byte
private plan publishes first/top and a one-way prepared marker. The attachment
object additionally owns one zeroed four-byte live-handle marker. Failure does
not reset these markers or retry a partial Secure commit.

The naked start bridge rechecks entry CPU state and active vectors, optionally
rewinds MSP from the approved vector (`FIBER_REWIND_MSP=1`), clears stale pending
PendSV, enables masks and executes only the owned SVC70. With rewind disabled,
the trusted active MSP is preserved; its actual hardware-frame top must still
leave the full baseline reservation below it. The strong SVC accepts only
IPSR11, exact NS basic Thread/MSP EXC_RETURN `0xFFFFFFB8`, CONTROL0 and clear
masks, captures raw MSP and the assembly-only common current-slot value, then
sets PRIMASK1 and branches to C. The current-slot spelling appears in production
only inside naked assembly, never as a C declaration/lvalue.

The dispatcher requires prepared state and the exact prepared/current pointer.
Before explicitly reading stacked PC/xPSR it proves the complete aligned
32-byte hardware-frame extent in reserved MSP. It requires Thread xPSR T set,
no alignment pad, and the exact even owned
`fiber_port_c55s_first_start_svc_return` PC. It proves the preceding two-byte
instruction extent in approved code before fetching exact opcode `0xDF46`.
After repeated vector/context/CPU validation it consumes the one-way plan,
before the first Secure lifecycle effect. The first-start helper rechecks
SVC11/PRIMASK1/BASEPRI0/FAULTMASK0/CONTROL0 and context/cold-frame validity.
All eight identity/capacity queries and each lifecycle result are followed by
fresh NS IPSR, masks, CONTROL and PSPLIM validation before acceptance.

Initialize must return exactly one, exactly once. With no attached request,
allocation is skipped and `load(0, owner=ctx)` must return one, exactly once.
With an attached request, allocation occurs once and must return a nonzero
handle no greater than the queried maximum context count, not necessarily one.
The handle is published to frame word zero through a volatile store, barriers
and exact volatile readback. Load receives exactly that handle/owner and must
return one. The original cold checker still requires zero; the separate
`fiber_port_context_first_start_frame_check(ctx, expected_handle)` requires
the exact expected handle and request/zero-handle relation. Boot hash, saved
frame pointer and constructor-captured r9 are checked across these operations;
r9 is not compared with a later live platform register. The live handle is
published/read back only after success. Every failure is terminal; there is no
rollback, selection, or Thread resume. Final VTOR/SVC/vector-top readback and
CPU-state validation run after Secure preparation, immediately before restore.

The naked restore loads handle/PSPLIM/EXC_RETURN first, requires exact
`0xFFFFFFBC`, writes/verifies PSPLIM, writes CONTROL2 with ISB and exact full
readback2, and writes/verifies the hardware PSP. Armv8-M Handler uses MSP but
permits SPSEL writes/readback; exception-entry CONTROL0 is not a post-write
readback policy. Masks/IPSR are checked before the final r4-r11 load. Only
barriers, interrupt enable and exception return follow that load; there is no
C call or failure branch after GPR/r9 restoration. No NS FP/MVE/PAC probe,
s0/d0 read, or data-path operation is added. The unchanged Secure compiler's
CMSE FPCXTNS/VSCCLRM mechanics remain covered by `FAP-CMSE-M55`, not a blanket
no-V-instruction claim.

### Reference Mapping And Intentional Differences

The comparison is the actual pinned `ARM_CM55/non_secure` no-MPU/no-FPU/no-MVE
branch, not an assumption based on CM33 names. `portasm.c` first restore loads
handle/PSPLIM/EXC_RETURN and then `adds r0, #32`, discarding r4-r11 slots. Fiber
deliberately restores all those slots, including its captured r9, as stronger
deterministic initial-register policy; the whole first restore is not claimed
instruction-identical. The reference first handle is zero and task allocation
service runs later. Fiber's attached pre-start request deliberately moves the
first allocation/load into this validated first-start SVC; unattached first
start preserves the zero-handle policy. Reference task/heap/scheduler/syscall
dispatch, PAC/FPU/MPU branches and future PendSV are not copied. The mapping is
`vStartFirstTask` -> private naked bridge, start-SVC initialization -> validated
dispatcher plus paired initialize, and `vRestoreContextOfFirstTask` -> private
basic restore. Shared special-word order/PSPLIM/PSP and exact security token
are retained; additional metadata, provenance and readback checks are Fiber
policy, not proof of exhaustive FreeRTOS equivalence.

### Integration And Evidence Boundary

The board includes `fiber_port_first_start_contract.ld` after its memory
sections (or supplies it as a second `-T`) and defines six half-open bounds:
`__fiber_c55s_ns_vector_start__/end__`,
`__fiber_c55s_ns_start_code_start__/end__`, and
`__fiber_c55s_ns_msp_stack_start__/end__`. No addresses are selected by the port.
Vectors and code must be immutable approved NS mappings; the complete core
vector extent and relevant start code must be covered. Reserved MSP is aligned,
disjoint from code/vectors/first context/raw task stack, and at least 2048 bytes.
Integration owns a trusted physical exception/C stack, qualified maximum
C/CMSE depth and any added address/memory hooks, nesting and interrupts. The
baseline reservation is not merely a hardware-frame allowance, nor a proof
that an arbitrary corrupted physical MSP can reach panic: exception stacking
or the C prologue can already fault. Raw-frame validation precedes explicit
frame decode, not every possible hardware/compiler memory access.

Focused GCC 14.3.1 evidence is retained at
`%TEMP%/fiber-c55s-first-start-smoke-2612d0cd15b44d089d52c93208395e2e/receipt.json`:
eight O0/O2/Os, optimized-LTO and hostile modes; 169 checks; zero input drift.
It links actual three-object Secure production and its twelve-entry CMSE
import artifact, ordinary staged NS archives/direct objects, strong owned SVC,
no full-runtime symbols, and missing exact context/reverse guards. It includes
stack-usage files and generated assembly showing special-register/readback
ordering, no post-GPR C call and no hostile instrumentation imports in the
four NS objects. Fixture memory helpers/terminal sinks and explicit staged
providers are not a full runtime or arbitrary integration-library proof.
This smoke is compile/link/codegen evidence only; it is distinct from the later
maintained execution receipt below and the historical Slice-8 receipt.

Maintained Slice-9 real two-image first-start qualification subsequently passed
at `%TEMP%/fiber-m55-secure-first-start-653753cfc13c43c783c83adaf5a9ae54`:
ten modes, 568 launches, 5740 checks, 30 compiled mutants, 154 inputs, zero
input drift. The actual reference uses first SVC102 and skips the initial GPR
slots; Fiber's owned SVC70 restores them. The suite qualifies that explicit
difference, not instruction identity. Receipt SHA-256 (`results.json`):
`682896D43CD282CC3567C21DC9F881910F21CD790E0E6837A221C5BB3A53BC4D`.
Artifact manifest SHA-256 (`sha256.csv`):
`C4A7C0ED20B35C847BC2C32D3AFD20CE45A6F334F548A33634DF79866A644ADD`.
Before Slice-10 source edits, the parent independently rehashed all 154 inputs
and 12385 artifacts with zero mismatches. This is historical qualification of
the frozen first-start source state, not the later running slice, full runtime
or hardware. Slice-8 attachment's separate 892-case receipt remains separate;
both source-sensitive runners require replay after the next source freeze.

## Slice 10: Staged Scalar Running Component

The only new source is `fiber_port_pendsv.c`. Scoped additions in private/boot
headers and sources and `fiber_port_secure_context.c` supply running validation
and Secure callers; `fiber_port_runtime.c` adds only a cold call retaining
`fiber_port_arm_cm55_secure_context_pendsv_component_v1_anchor`. The six
existing first-start transfer bodies and `fiber_port_svc.c` are unchanged
except that approved preparation call. The separate cold component retains
exact reverse-v1 and selected-context dependencies under archive extraction,
GC and LTO. It adds no hot reverse-anchor read. Staged integration still owns
the context/storage providers, common current slot and reverse implementations.
No forward adapter, runtime provider, global route, SVC71/72, FP/MVE/MPU/PAC/BTI
policy or Secure source/ABI/layout change is made. Selection remains zero.

### Architecture And Frame Admission

The exact pinned M55 `PendSV_Handler`, lines 441-542, calls Secure save before
NS stores, conditionally saves/restores r4-r11 for EXC_RETURN.S=0, always stores
the three special words, selects under BASEPRI, restores NS PSPLIM before
Secure load, then restores NS PSP and returns through EXC_RETURN. The S=1
branch is implemented, not silently rejected or treated as a basic NS frame.

Only `0xFFFFFFBC` (NS origin) and `0xFFFFFFFC` (Secure origin) are accepted:
basic Thread return, NS PSP selected, ES=0, DCRS=1, with S bit 6 selecting the
shape. In an NS handler SPSEL refers to the NS bank, not permission to read
the Secure hardware frame. DC/DCRS0 is not a valid alternative for NS return:
Arm DDI0553B.y B3.22 RNCQN rejects ES=0/DCRS=0 with INVER. See the
[Arm architecture manual](https://community.arm.com/cfs-file/__key/communityserver-discussions-components-files/471/DDI0553B_5F00_y_5F00_armv8m_5F00_arm.pdf),
also B3.22's background-stack selection rules. A real M55 two-image Secure
Thread interruption must capture FC/DCRS1 and exercise return before this
branch is qualified. It is source-implemented but architecture execution is
pending; NS-only tests or a synthetic LR fixture cannot close that gate.

S=0 saves `[handle, PSPLIM_NS, EXC_RETURN, r4-r11]` below the live eight-word
NS hardware frame: eleven software words plus eight hardware words, 76 bytes,
or 80 with the validated optional alignment word. S=1 saves only
`[handle, PSPLIM_NS, EXC_RETURN]`: twelve bytes. Its hardware/additional callee
state stays on the Secure stack, owned by hardware and the Secure companion.
The live/saved checkers prove the three-word header extent before reading it;
only the admitted S=0 branch proves/reads a complete NS hardware frame and
checks T, Thread IPSR, even code PC and optional padding. S=1 requires an
attached nonzero owned handle, checks NS stack bounds but never reads its NS
GPR/hardware area. Both save shapes leave saved SP at offset four modulo eight.
No context/storage/frame dictionary or layout revision changes.

### Private State And Ordering

The attachment object adds a four-byte ordinary NS BSS start marker: zero ->
INITIALIZING before the first Secure initialize -> READY only after successful
first load/live-handle publication. It is never reset or retried. Existing
one-shot first-plan consumption remains before lifecycle effects. Running
helpers require READY independently of whether the live handle is zero.
The new PendSV object owns a separate 32-byte ordinary NS BSS transaction plan,
not common scheduler storage: idle -> source validated/save started -> saved
-> next selected -> next prepared -> idle only after successful load and
publication. A panic after any partial Secure or NS commit is terminal; no
rollback path resets either marker to make the transaction retryable.

Admission requires IPSR14, exact CONTROL_NS=0 as observed after architectural
exception entry, clear PRIMASK/BASEPRI/FAULTMASK and aligned live PSP_NS.
Integration supplies trusted reserved MSP, immutable approved NS vector/code
bounds, active VTOR and the exact strong PendSV vector, and lowest implemented
PendSV priority. The component validates these conditions, not configures them.
It never repairs CONTROL or writes interrupt configuration. Hooks, reverse
selector/publication and every SG boundary are guarded by fresh snapshots of
NS IPSR/CONTROL/PRIMASK/BASEPRI/FAULTMASK/PSPLIM/PSP. The selector alone runs
under the configured BASEPRI threshold; save/allocation/load use BASEPRI0.
Interrupts must obey the serialized single-core Secure caller contract and
preserve the private transfer state. No physical-MSP-corruption containment or
unqualified interrupt-nesting/C-stack-depth claim is implied.

Before any NS image store, live validation proves context extent before its
fields, complete sealed metadata/raw stack maps and canary prefix before its
read, reserved-MSP/context/stack disjointness, software space and conditional
hardware extent. Secure save, including explicit handle-zero empty-state
validation, succeeds and unloads Secure PSP/PSPLIM before assembly stores the
NS frame. The private live handle is cleared only after confirmed save.
The selector sees an exact validated saved image and unchanged NS CPU state;
distinct current/next context and raw-stack ranges must be pairwise disjoint.

A never-run attached next context may allocate lazily only after an exact cold
image check, all gateway identity/capacity queries and bounded nonzero allocation.
The frame's handle publication is volatile and read back; its initial registers
including r9 and sealed geometry are rechecked. A zero handle in an arbitrary
previously running image is not sufficient. Nonzero frames rely on Secure owned
lookup during load; unattached frames require zero. NS PSPLIM is restored and
read back before loading Secure state. Load zero is also called explicitly to
prove the Secure bank remains empty. Only confirmed load publishes the private
live handle, then reverse `fiber_internal_runtime_publish_current_context`
publishes common current. Common slot access is one naked-assembly load pair,
never a C declaration/lvalue. NS PSP is restored/read back before the final
conditional GPR load, unlike the reference's unchecked PSP-after-GPR tail;
successful resume has no subsequent C call. S=1 skips that GPR load entirely.

### Function Mapping And Qualification Gate

| Local function(s) | Actual reference / deliberate local policy |
| --- | --- |
| `PendSV_Handler` | M55 `portasm.c:441-542`, no-MPU/FPU0/MVE0/PAC0 TrustZone branch; preserve S-bit conditional NS stores/loads and three special-word order, add strict admission, C guards and readbacks. |
| `fiber_port_pendsv_prepare_save` | Pre-save hardening before reference `SecureContext_SaveContext`; one-way transaction latch and predicted saved-SP/EXC_RETURN checks. |
| `fiber_port_secure_context_save_current_from_pendsv` | Reference handle/TCB -> Secure save; explicit zero save, NS preservation and live-handle clear only after confirmed unload. |
| `fiber_port_scheduler_pick_next_from_pendsv` | Reference `vTaskSwitchContext` under BASEPRI; use frozen reverse selector without common-storage C access and validate candidate/disjointness. |
| `fiber_port_pendsv_prepare_next`, `fiber_port_secure_context_prepare_next_from_pendsv` | Fiber pre-start size-only attachment policy, exact cold-image lazy allocation after current unload, before Secure load; not a copied FreeRTOS task allocation SVC. |
| `fiber_port_pendsv_load_next`, `fiber_port_secure_context_load_next_from_pendsv` | Reference Secure load after NS PSPLIM restore; strengthen zero-handle/owned lookup outcome and publish only after confirmed load, via private live-handle store and common reverse publication. |
| `fiber_port_context_live_frame_check`, `fiber_port_context_saved_frame_check` | Local branch-sensitive 12-byte vs 76/80-byte frame validation; never decode Secure hardware data from NS memory. |
| `fiber_port_running_context_check`, `fiber_port_running_hardware_frame_check`, `fiber_port_running_exc_return_check` | Local sealed metadata/maps/canary validation and exact BC/FC/DCRS1 scalar admission. |
| `fiber_port_running_cpu_capture`, `fiber_port_running_cpu_check`, `fiber_port_pendsv_cpu_capture`, `fiber_port_secure_context_running_cpu_capture` | Local seven-field NS preservation and phase-specific mask/Handler/start-ready guards; no CPU repair. |
| `fiber_port_pendsv_environment_check` | Integration-owned immutable vector/code, active VTOR and lowest PendSV-priority precondition, no startup writes. |
| `fiber_port_pendsv_current_image_check`, `fiber_port_secure_context_saved_snapshot_check`, `fiber_port_pendsv_contexts_disjoint_check` | Local exact source/next image snapshots and disjointness against trusted hook/reverse/SG boundaries. |
| `fiber_port_arm_cm55_secure_context_pendsv_component_v1_anchor` | Cold independently retained component/reverse/context contract; no hot-path ABI read or full-runtime provider. |

Production running sources require independent maintained Rawls two-image
qualification, actual Secure interruption observation, unchanged-source
first-start/attachment replay, codegen/parity and negative controls. No running
execution PASS or full-runtime claim is inferred from the earlier 568 first
launches, 892 attachment cases or any focused compile-only result.

Focused GCC14.3.1 running-source smoke at
`%TEMP%/fiber-c55s-running-smoke-87b020e3f08a4a6c8416ae6acecdc46f` passed:
forty actual ARM objects (five NS objects in O0/O2/Os, O2-LTO/Os-LTO and hostile
O0/O2/Os), thirty non-LTO disassemblies without FP/MVE or instrumentation
dependencies, and four C11/C++17 private-header syntax checks. The hostile
commands retain instrumentation/coverage/stack-protector/branch-count options;
no negative exclusion flags mask the canonical attribute checks. Strong
PendSV, reverse select/publication and the independent cold reverse-v1 import
are present. Codegen spot checks find both the conditional eight-GPR block and
three-word special block, PSPLIM/PSP writes, and no C call between final GPR
load and successful BX. The whole SVC source is byte-identical, and the runtime
source differs only by the approved cold anchor call. `receipt.json` records
commands, hashes and exact seven-file write set; `before/` preserves prior NS
inputs. This is not an execution, final LTO link, complete instruction-parity,
archive/GC-retention proof or arbitrary integration call-chain qualification.

## Slice 11: Forward Runtime Candidate

`fiber_port.c` now defines the seven remaining frozen forward operations and
the exact cohort provider; construction remains in `fiber_port_boot.c`.
Unique first-start and PendSV component references root the two strong handler
archive members independently of startup weak aliases. The common runtime
still owns scheduler state, first-selection lifecycle and current publication.
The port exposes no C lvalue for the common current slot.

Before selecting the first context, preparation validates the active NS vector
source, linked code/MSP bounds and physical MSP reserve, then configures SVC
priority zero, lowest PendSV priority, STKALIGN and stale PendSV clearing, with
implemented-priority-bit and PRIGROUP readback. It records the MSP plan before
calling the scheduler. First selection executes under BASEPRI with all seven
NS CPU-state fields guarded; the selected initial image is checked before
common publishes it. The existing private SVC component commits the matching
MSP/context plan and transfers through its unchanged naked bodies.

Public schedule checks only Thread/current, privileged PSP and clear masks,
then requests PendSV. It does not duplicate the full running-frame validator.
The running validators now treat hash and address-map settings independently:
fast structural/ABI checks, frame bounds, canary, exact BC/FC, xPSR and PC form
remain mandatory; the record hash is recomputed only with the hash setting.
Context/stack/redzone/stacked-PC hooks execute only with the map setting.
Cold init, first start and a never-run attached context's lazy allocation keep
their one-shot full validation. Secure gateway and scheduler CPU-state guards
remain mandatory regardless of those optional validation settings.

The candidate passes 32 strict O2/Os compilation objects across the four
hash/map settings. This is not complete-common-runtime execution, final ELF
or a profile promotion. Runtime-selectable remains zero. No global selector
route has been added and no naked SVC/PendSV transfer body was changed.

Before these production edits, the independent running-component suite passed
1,000 launches and 3,964 checks: 70 positive executions, 810 exact panic cases,
40 Secure-corruption fault cases and 80 compiled controls across ten modes.
It includes actual Secure-origin interruption and separately executed pinned
FreeRTOS reference behavior. Parent rehashes 318 input entries and 13,162
artifacts with zero mismatches, preserving 89 exact repository inputs.

```text
Component receipt:
  %TEMP%/fiber-m55-secure-running-30e68a6a3b86400db670fb16320a4e7f
results.json SHA-256:
  62B27BA06E6A15AA2E41BFCA676FA87F152C21C268FB748EB022A7EB1257C977
Source archive:
  %TEMP%/fiber-qualified-repo-inputs-6e3ef16a03b64642814b30ccfb3f1fe3
ZIP SHA-256:
  ED168B1790CCF58D7FDD261268138A4FC5074EB899324B8D1445B9A7D3DD8739
```

That receipt qualifies its preserved component bytes, not the later Slice-11
adapter and conditional-validation edits. Full real-common/two-image runtime,
default and all-four-policy execution, fresh whole-body/reference parity and
archive/cohort/GC/LTO negative proofs are now in progress. Hardware TrustZone
validation remains a separate pending obligation.
