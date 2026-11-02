# C33F TF-M Staged Consumer Gate

Run `tools/test_cm33f_tfm.ps1 -ArmGcc <gcc> -CmsisCore <CMSIS Include>`.
Optional `-HostGcc`, `-BuildRoot`, `-FreeRtosRoot`, `-Python`, and
`-ExpectedRuntimeSelectable` (default 0, required to remain 0 for this stage).
Host GCC is mandatory; the existing MSYS2 UCRT64 GCC is a fallback. No downloads,
emulator provisioning or hardware programming are performed. Actual modeled CPU
execution additionally requires an explicit existing absolute WSL `-QemuRoot`,
with optional `-WslDistro` (default `Ubuntu-24.04`). Without that argument the
receipt explicitly records execution `NOT_RUN`, not an activation qualification.

The new group derives CPU/boot mechanics from M33F_NTZ and TF-M adapter logic
from C3TF; `provenance.json` records the exact consumed progenitor snapshots.
The maintained fixtures/runner derive consumer/role/host test machinery from the
separately frozen C5TF gate but do not modify or rerun that gate. Reference inputs
are the pinned FreeRTOS M33_NTZ FPU=1/MVE=0/MPU=0/TRUSTZONE=0 branch and actual
TF-M v2 wrapper source. Compiling them is not exact assembly equality or real
TF-M execution proof; independent parity is a separate gate.

Target cases use actual Cortex-M33 scalar FP code generation, hard and softfp,
O2/Os with and without LTO, allocating C/C++ consumers and direct/static archive
links. Public/common compilation has no CMSIS include dependency. Exact identity,
76/72-byte context/boot layout, 72-byte initial/212-byte maximum saved image,
strong handlers/vectors, five public calls and eight forward operations are
checked. Stale allocating consumers cannot borrow this storage cohort.
Each stale-consumer include trace must consume exactly its sibling profile's
two public storage headers, with no private/runtime macro or CMSIS header.
Only those consumed sibling headers are inputs; unrelated sibling runtime
edits do not invalidate this public storage-identity test.

The shared `tools/fixtures/portable_application.c` is compiled without source
changes as C11 and C++17, then linked directly and through the complete static
archive in every target tuple. The C-only fixture uses `static _Alignas(8)`;
C++ compilation has a fixture-only `_Alignas(n)` to GCC `aligned(n)` spelling
bridge, not a required library-user macro. Both final 2048-byte stacks must
remain 8-byte aligned. Include traces reject CMSIS, device, private runtime and
optional TF-M headers, and the allocating application's exact undefined set is
the public five operations plus its derived storage identity. The unchanged
application has no artificial API root table; LTO may inline ordinary public
functions. The separate rooted consumer still checks all five named providers.

A public `fiber_init`-only C/C++ consumer also links two actual common/port
archives with GC in every O2/Os native/LTO tuple. The pre-v1 common model removes
only the reverse-v1 marker definition from the real common state source; this
is explicitly not a full historical source checkout. Its negative must report
only the missing reverse-v1 marker. A matching current-common positive must
contain the constructor's cold volatile marker read and the readonly one-byte
value 1, without retaining startup, handlers, scheduling or TF-M entry points.
The constructor fixtures provide only address predicates, not runtime stubs or
TF-M provider/root tables.
The final LTO driver repeats `-ffunction-sections -fdata-sections`; otherwise
GCC may coalesce unrelated functions and invalidate a constructor-only GC test.

Default-policy objects and final portable/execution ELFs record exact settings:
eager FP, MSP rewind, boot hash checking, disabled switch-time address mapping
and permissive hooks, enabled canary, 32-byte redzone, derived BASEPRI and staged
metadata 0. Static assertions and an actual compiled explicit-lazy control
check the policy observer. The control rejects a non-default test tuple; it
does not claim that an explicit lazy policy is invalid in production.

CPU+boot, initializer, wrapper and combined groups have separate exact undefined
sets. LTO IR observations are supplemented by native lowering. No port object
may define common-owned reverse services/storage; weak common-anchor and CPU
public-call leak controls are actual source-derived compiled objects.

Host execution substitutes only CPU observations and the two PRIMASK primitive
bodies in the actual initialization/mutex sources. It checks lifecycle, exact
eight-field preservation, FPCA-set running admission, error/sticky/reentry,
owner/contention/finite-timeout semantics, source-derived mutants and strict
report classifiers. Host state is not actual ARM register behavior. No native
pointer/layout result substitutes for target ELF geometry.

The raw hostile audit applies effective instrumentation, stack-protection,
profiling, sanitizer and coverage flags without counter-options. It checks
complete new-port raw objects and sensitive common functions in raw/lowered LTO
groups, including conditional validation and opt-in permissive-hook helper
definitions. Ordinary common `fiber_init`, scheduler configuration and its
storage helper are not declared sensitive; their compiler references/counters
are recorded separately and may not occur in other functions. Only the two explicit high-FP
context transfers in PendSV may use VFP instructions. Compiled unprotected
function/helper controls must expose compiler instrumentation. This is a bounded
attribute/dependency/FP-op audit, not byte-complete CPU parity.
All hostile flags are applied to every audited source. LTO lowering repeats
the sanitizer/instrumentation flags but does not repeat the driver-only
`-fprofile-arcs` library-selection trigger; per-TU profiling remains, and the
lowered unprotected control must still expose every compiler-dependency family.

All external TF-M providers are typed fixtures. Actual TF-Mv2.0.0 NS sources,
headers, Secure veneers, NS FP grant and matching hard/softfp ABI are integration
requirements, not tested facilities. The initializer preserves entry CPACR,
FPCCR and full CONTROL before the later CPU FP preparation; it does not hide
provider corruption by repairing registers. No fiber SecureContext is involved.

## Actual Common And FP Execution

With `-QemuRoot`, the maintained gate runs real common C and all four C3FT source
objects on QEMU `mps2-an505` (Cortex-M33 with FP). The separate Secure bootstrap
only grants NS memory and FP access, delegates lazy/eager selection, and branches
to the NS image. It is not TF-M. `tfm_ns_interface_init` is a protected, typed NS
fixture provider: there is no Secure TF-M image or Secure service execution.

The hard/softfp, O2/Os, normal/LTO grid runs both explicit lazy/eager FP policy,
plus a separate no-policy-override default build, and
ordinary/reserved-R9 modes. Three owners exercise basic and extended frames,
R4-R11, S0-S31, FPSCR, current-context publication, PSP/PSPLIM, masks, initializer
order and all four cooperative mutex operations. Finite contention must not
schedule; WAIT_FOREVER must actually yield until its owner releases. Reserved
cases compile the entire common/port/provider/hook chain with `-ffixed-r9`, and
handwritten NS assembly does not borrow R9. Ordinary cases check caller R9
preservation and valid frames without imposing an incoming initial-frame seed.

Actual admission cases cover provider errors/CPU leaks, early idempotent init,
FPCA-set init preservation, Thread/PSP, nPRIV, genuine SysTick, runtime masks,
PendSV callback corruption and the real common task-return path. Pure
`fiber_init` is environment-neutral: prestart Handler/unprivileged construction
are positive controls, not newly invented privilege restrictions. A prearmed
SysTick reports an unprivileged panic or constructor result from Handler mode;
the originating Thread never resumes. Callback-failure reports also terminate
inside the originating PendSV before exception return.

Compiled mutations must fail at specific data checks for lost high-FP transfers,
lost R4, missing auto initialization, ordinary caller R9 corruption and reserved
wrong seeding. High-FP copy mutants use eager policy to isolate payload copying
from lazy materialization. Missing initializer CONTROL/CPACR/FPCCR guards must
be rejected for forbidden later activation, not an unrelated crash. Additional
compiled controls cover counterfeit Thread-origin Handler panic, unrelated
fault, missing observation report and timeout. New fixture callbacks/helpers
also undergo effective raw hostile/LTO compilation, separate from normal
execution. These checks are not the independent complete reference-parity gate.
Every execution image retains and checks all eight strong forward definitions.
The fault control must report its exact UDF instruction, UsageFault/UNDEFINSTR,
basic NS Thread/MSP return and stacked Thread/Thumb origin; a timeout or unrelated
fault cannot substitute. The timeout control must reach bounded exit 124.

Commands, separate images, maps, disassembly, exception logs, strict reports and
QEMU binary/runtime dependency hashes are retained. QEMU and its actual loaded
libraries are rehashed before/after execution. This proves only the tested M33
model with FP present, not physical silicon or an absent-FP configuration.

Each invocation preserves commands, generated sources, object/ELF symbols and
disassemblies, maps, exact negative reports, before/after source/tool/include
hashes and consumed Markdown snapshots. Digests are uppercase SHA256. The local
FreeRTOS reference must match `a50edad08b29052631aa469d4df6e6ec7ff68878` and be
tracked/untracked clean before and after. Any drift fails qualification.
