# C33F TF-M Staged Consumer Gate

Run `tools/test_cm33f_tfm.ps1 -ArmGcc <gcc> -CmsisCore <CMSIS Include>`.
Optional `-HostGcc`, `-BuildRoot`, `-FreeRtosRoot`, `-Python`, and
`-ExpectedRuntimeSelectable` (default 0, required to remain 0 for this stage).
Host GCC is mandatory; the existing MSYS2 UCRT64 GCC is a fallback. No downloads,
emulator provisioning, target execution, or hardware programming are performed.

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

Each invocation preserves commands, generated sources, object/ELF symbols and
disassemblies, maps, exact negative reports, before/after source/tool/include
hashes and consumed Markdown snapshots. Digests are uppercase SHA256. The local
FreeRTOS reference must match `a50edad08b29052631aa469d4df6e6ec7ff68878` and be
tracked/untracked clean before and after. Any drift fails qualification.
