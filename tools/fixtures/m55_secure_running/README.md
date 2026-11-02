# C55S Staged Running Transfer

`tools/test_m55_secure_running.ps1` builds and executes actual production source
in two images on the existing QEMU AN547 Cortex-M55. It does not install tools,
modify production source, program hardware, or provide a complete generic port.
The reference must be clean FreeRTOS-Kernel
`a50edad08b29052631aa469d4df6e6ec7ff68878`.

## Invocation

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test_m55_secure_running.ps1 `
  -ArmGcc C:/path/to/arm-none-eabi-gcc.exe `
  -CmsisCore C:/path/to/CMSIS/Include `
  -QemuRoot /home/ruslan/.cache/fiber-qemu-control-owner-20261101 `
  -WslDistro Ubuntu-24.04
```

`-BuildRoot` and `-FreeRtosRoot` are optional. The explicit existing Linux tool
root supplies `qemu-system-arm`, its isolated `LD_LIBRARY_PATH`, and `-L` data.
`-DevelopmentModes`, `-DevelopmentCases`, and `-DevelopmentReferenceOnly` always
make `CompleteSuite` false. Failure, missing reports, unknown stops/instructions,
timeout, unexpected exit, missing symbols, and input drift throw; nothing skips.

## Complete Inventory

The default run has **1000 QEMU launches**. Actual pinned reference source runs
five positive scenarios in O2/Os with and without LTO (20 launches). Fiber runs
90 cases and eight compiled rejection controls in each of ten modes (980):
O2/Os, optimized LTO, static archives plus GC, archive plus optimized LTO, and
hostile instrumentation. Hostile production objects receive all enabled
instrumentation/coverage/sanitizer/stack flags, without subtractive flags.
Their exact undefined sets equal same-run normal objects; counters and runtime
instrumentation symbols are forbidden. Two successfully compiled annotation-
removal controls must expose instrumentation and coverage escapes.

| Cases | Oracle |
| --- | --- |
| 0-4 | zero/zero, attached/attached Secure windows, both mixed directions, attached/attached NS windows |
| 100-193 | exact EXC_RETURN/CPU/current pointer/live PSP/hardware frame/hash/canary/next image/callback/map-hook failure diagnostics |
| 210-216 | real Save/Load admission, owned handle, Secure bank and pool owner rejection |
| 220-223 | both seal words, stored PSP and limit corruption: actual pool UDF and exact Secure UsageFault |
| 230-232 | zero result injected after actual successful Save/Allocate/Load effects; exact sticky terminal phase, no repair or publication |
| 240-247 | each actual running cold-query result independently changed to zero |
| 250-263 | each query's NS PRIMASK disturbance and last-query CONTROL/BASEPRI/FAULTMASK/PSPLIM disturbances |

There are 81 exact panic cases and four exact corruption-fault cases. Numeric
ranges contain deliberate gaps. Runtime receipts record every actual stop,
gateway arguments, registers, memory transitions, injected state and terminal
diagnostic. The eight compiled controls remove NS GPR restore, alter allocation
size/owner, omit real Secure Save, decode an NS hardware frame for Secure origin,
store NS GPRs for Secure origin, select PSP for a Handler fault, and counterfeit
a Thread-return fault record. Each must compile and link, then fail its named
execution oracle; incidental build failure is not accepted.

## Independent Observations

Actual task assembly seeds all r0-r12/LR, then writes ICSR through a CPU STR.
The task switch interrupts actual NS Thread or actual Secure Thread inside SG,
not a C model or fabricated EXC_RETURN. Secure-origin NS PendSV observes FC:
S=1, DCRS=1, no NS hardware push, and a real 72-byte Secure hardware image.
The observed image is integrity signature FEFA125B, one reserved/alignment word
(not assumed), r4-r11, then the basic eight hardware words. NS origin observes
BC, a 32-byte NS hardware push, and a complete 19-word saved image. Secure
origin saves only the three-word NS header. All live registers including r9,
PSP/PSPLIM, owner, bank state, masks, NS stack bytes and resume state are checked.
The next never-run attached task is allocated once by actual PendSV before
its first Thread entry. Initial complete 19-word images are checked before
entry; historical images are not treated as current live frames afterward.

The actual Secure bounded pool is three contexts with maximum stack1024,
request512. Independent numeric geometry checks all 3168 bytes after every
primitive, exact raw arguments, first-free handles, owners, all stack seals,
zeroing, and limit-before-pointer outcomes. No expected owner/limit is copied
from a production record. All eight actual SG queries are paired through their
real BXNS returns. Secure Save occurs before any NS software store; Load occurs
before restore. Result-fault controls change R0 only after proving actual Secure
effects; they do not claim physical MSR readback failure injection.

Seal/record corruption reaches the production UDF FFDE. The fault oracle
correlates the pre-UDF actual PendSV Handler registers with actual Secure
UsageFault IPSR6, EXC_RETURN F5, exact basic frame on Secure MSP (MODE Handler
overrides SPSEL), CFSR UNDEFINSTR only, HFSR/SFSR zero, exact terminal report and
exit91. The plan remains in Save phase1, with no SG/Thread return or publication.
A generic fault is never success. Compiled wrong-stack and counterfeit-Thread
controls prove the fault record is not self-confirming.

GDB special-bank writes can acknowledge without changing QEMU state. Therefore
CPU disturbances execute actual MSR instructions in a fixture trampoline; the
oracle checks effective readback and preservation of all other banks, GPRs,
flags, and physical Handler MSP. This is not generalized into a RAZ claim.

## Reference And Deliberate Deltas

The runner compiles actual pinned M55 non_secure port.c/portasm.c and Secure
secure_init.c/secure_context.c/secure_context_port.c. Reference Task/heap hooks
are explicitly fixture policy: two minimal TCBs, a two-task scheduler, and a
bounded three-slot allocator for the reference's real request512 plus seal8.
The real assembly and SG primitives execute, not reference-shaped doubles.

Both paths use the reference's PendSV S-bit branch (portasm.c lines441-542):
Secure Save before NS save, no NS r4-r11 transfer for Secure origin, Load before
restore. Deliberate differences are explicit: reference first restore discards
initial r4-r11; Fiber restores them all including inherited r9. Reference starts
with handle0 then allocates/loads in task SVC100; Fiber request policy allocates
first in owned SVC70 and allocates the next cold task in PendSV. Fiber calls
Save/Load even for handle0, unlike the reference's skip. Reference fixture
selector BASEPRI is128; Fiber uses its actual default32 with NVIC bits3. All
masks are zero at resume. Fiber's sealed context checks and bounded opaque pool
are additional policy, not identical assembly or identical allocation policy.

Exact final imports are twelve production C55S SG entries plus fixture work SG.
Missing and actual foreign CM33 providers must fail with precisely the twelve
C55S dependencies. The fixture work-only absolute import comes from this
build's real CMSE import at the identical veneer address, never synthetic
production adapters. Generated successful PendSV tail must be GPR load,
DSB/ISB, BX LR with no C afterward.

## Evidence And Limits

Each run creates a unique temp root with actual objects, archives, ELFs, CMSE
imports, saved compiler intermediates/dependencies, maps, disassembly, symbols,
exact commands, QEMU inventory and per-launch JSON receipts. `results.json`
includes the complete inventory and assertions; `inputs-before.json` and
`inputs-after.json` must agree; `fixture-inputs.json` lists this runner/fixture
set; `sha256.csv` hashes every artifact except itself. No global matrix runs.

This qualifies only the staged first/PendSV transfer primitives with real
common candidate selection/publication, not all eight port operations or a
public runtime/provider. Fixture task-return is terminal; execution stops
before task return, and no service72 is invented. No full FreeRTOS scheduler,
general Secure Thread application, asynchronous stress, hardware timing,
silicon, board, performance, or global whole-program LTO claim is made.

The current staged running validator unconditionally checks hashes/maps/
canaries and hardware-PC maps. Global HASH/MAP_ONSWITCH defaults0 do not yet
select four-setting running policy. This suite does not claim production0/0
hot-path semantics; activation policy remains a separate parent-owned task.
