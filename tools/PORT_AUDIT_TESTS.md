# Port Audit Regression Gate

These maintained regressions address `PORT_ARCHITECTURE_AUDIT.md` (A01-A34)
and the staged C55S private-pool lifecycle.
`compile_matrix.ps1` invokes them in addition to the pinned FreeRTOS comparison
and the existing compile, ELF, archive, ABI, cohort, GC, and LTO checks.

## Running The Gate

The current runner is qualified on Windows PowerShell with STM32CubeIDE GNU
Arm GCC 14.3.1, the corresponding binutils, CMSIS Core, a clean pinned local
FreeRTOS checkout, host GCC, and Python 3.10 or later. The host-state fixtures
currently use the MinGW executable/link model. These tools are test dependencies,
not library dependencies or additional application API requirements.

Install the two pinned audit-only Python packages in an isolated environment or
the directory below, then run the matrix from the repository root:

```powershell
$modules = Join-Path $env:TEMP 'fiber-classic-audit-python'
python -m pip install --target $modules -r tools/fixtures/classic_audit/requirements.txt
powershell -NoProfile -ExecutionPolicy Bypass -File tools/compile_matrix.ps1 `
  -ArmGcc $env:ARM_NONE_EABI_GCC -CmsisCore $env:CMSIS_CORE_INCLUDE -KeepBuild
```

Host GCC must be discoverable as `gcc` or installed in the fixture's documented
MinGW location. Individual host runners also accept `-HostGcc`. See
`fixtures/classic_audit/README.md` for interpreter/module overrides. The runners
do not install packages, program boards, modify the reference, or silently skip
missing prerequisites. A future CI job must install these same prerequisites
and run the same gate; the presence of scripts is not a claim of a CI run.

`compile_matrix.ps1 -BuildRoot <absent-output-path>` selects an exact output
directory for automation. Existing directories/files are rejected instead of
reused. Explicit outputs and failed automatic runs are always retained;
`-KeepBuild` also retains successful automatic runs. The cleanup path cannot
remove arbitrary user directories or traverse reparse points.

Acceptance automation must additionally use `-RequireArchitectureExecution`
with an existing `-ControlQemuRoot`. Missing/blank prefixes and `-SettingsOnly`
are then rejected before tool discovery or output creation. This switch never
provisions QEMU; individual execution runners still qualify their dependencies.

## Evidence By Runner

| Runner | Proof |
| --- | --- |
| `test_matrix_artifacts.ps1` | Filesystem-only admission, stale-output rejection, failure/explicit retention policy and exact temporary cleanup bounds, including root/nested/junction rejection. This is infrastructure proof, not CPU or hosted-CI coverage. |
| `test_matrix_execution_policy.ps1` | Executes the actual matrix configuration guard: required execution cannot silently become `NOT_RUN` or use the settings-only subset. Checks unique full staged dispatch, explicit QEMU forwarding, no development-only switches and C3FT argument binding. C55S receipt controls reject incomplete/malformed/multiple results and boolean/string count coercion; exact full inventory is mandatory. Configuration proof only, not QEMU or hosted-CI execution. |
| `test_classic_audit.ps1` | Real ARM boot/guard paths executed by Unicorn at `-O2`/`-Os`, normal/LTO links, address-zero reads, r9, full CM0 vector extent, canary address order, and strong fallback overrides. |
| `test_thumb1_vector_constraints.ps1` | Actual CM0/CM0 MPU vector-load helpers: eighty O0/Og/O2/Os/O3, ordinary/reserved-r9, normal/native-LTO ELFs; VTOR-present/absent and zero/nonzero sources, callee-register/SP preservation, four compiled old-constraint controls. Focused instruction proof, not whole-port or exception execution. |
| `test_consumer_cohort.ps1` | Public no-CMSIS C/C++ usage, matching storage, stale allocating consumers and archives, both 8/16-region directions, old storage revisions, GC and LTO rejection. |
| `test_owner_guards.ps1` | Adversarial complete Secure-companion builds with mandatory counterflags, final LTO code audits, call-relocation qualification, reference-drift negatives, and effective optimization selection. |
| `test_mpu_constructor_attributes.ps1` | Four existing v8-M MPU constructors: exact normal/hostile dependencies, unchanged normal instructions/relocations, actual caller compiles and compiled annotation-removal mutants at applicable O2/Os, 8/16-region and ABI configurations. |
| `test_mpu_start_policy.ps1` | All seven active protected MPU dictionaries plus staged C3FP reject unsupported `FIBER_REWIND_MSP=0`; 54 O2/Os/core/FP/VTOR/region configurations compare default and explicit-1 object bytes and require the exact zero-policy diagnostic. Header compile proof, not first-SVC execution. |
| `test_reverse_abi_constructor.ps1` | Actual CM7 public init and constructor: 32 direct/archive, O2/Os, normal/LTO, v1/v2-only constructor-only and start-retained links; exact missing-anchor oracle and discarded-start proof. Eight compiled constructor-guard-removal controls reproduce the pre-fix gap. Source audit covers all 27 currently enumerated constructors, including staged C3SO, C5SO, C3FS and C3FT; the central matrix separately requires a v1 reference from each active constructor object. No exception execution or hardware claim. |
| `test_cm33_secure_origin.ps1` | Actual common plus real scalar CM33 NS/Secure groups on AN505: BC/FC mixed transfers, exact 12-byte Secure-origin NS header, bounded poison/watchpoint controls, compiled S-branch removals and paired layout-generation-one rejection. O0/O2/Os and O2/Os LTO. Runtime/reference source evidence is separate from Tesla's whole-body parity; no board claim. |
| `test_inline_cpu_helpers.ps1` | Focused shared EXC_RETURN and local r9/BASEPRI/vector helper protections for the four existing v8-M MPU dictionaries and staged C3FP; generated hostile probes and compiled negative controls. Qualification is recorded separately from source implementation. |
| `test_v8_scalar_ntz_security.ps1` | Source-derived scalar/NTZ architectural-state guards, actual ARM generated assembly, and split CM33 handler cohort/reverse-ABI negative archive links. |
| `test_m55_fp_mpu_state.ps1` | Source-derived FP/MVE MPU startup, core-frame decoding, live/saved CONTROL, active union view, lazy policy, bounds-before-read, MPU disjointness, yield/resume, and ARM component assembly. |
| `test_arm_control.ps1` | Executed QEMU instruction/exception transitions separating exception-entry CONTROL, post-MSR readback, physical Handler MSP, exception return, and M33 Secure/Non-secure SG banks. This separate architecture gate requires an existing isolated QEMU prefix. |
| `test_cm33_secure_guards.ps1` | Actual two-image CM33 gateway/pool execution with generated CMSE veneers, caller-origin and strict-aliasing proofs, plus BFHFNMINS rejection before commitment. Private Unix RSP tracing stops guard-removal mutants before the forbidden AIRCR store; arbitrary faults are not accepted. Requires the explicit QEMU gate. |
| `test_cm33f_secure_initialize.ps1` | Staged C3FS two-image M33 initializer through real SG: hard/softfp O2/Os normal/LTO and named raw-hostile cases, exact terminal fault/frame/status classification, caller/quiescence and sticky-failure controls, actual pinned reference objects. FP access only, not preservation, allocation/load/save or full runtime. Requires explicit QEMU; `-Smoke` is incomplete development evidence. |
| `test_m55_secure_pool.ps1` | Private C55S pool lifetime, geometry, C++ linkage, register preservation, metadata/seal corruption and interrupted init. Default M55 ELFs get codegen proof; Unicorn executes separately labeled `-fno-branch-count-reg` variants on its scalar model. |
| `test_m55_secure_pool_qemu.ps1` | Actual default M55 production-pool execution at O2/Os and both LTO modes, including low-overhead loops. Exact UDF/status/stacked-PC checks distinguish deliberate fail-closed cases from unrelated faults, missing reports, and timeouts. Requires the explicit QEMU gate. |
| `test_m55_secure_cohort.ps1` | Independent Secure-private exact object agreement, archive/LTO extraction, equal-size stale objects, expression normalization, pre-guard/missing-data/duplicate controls, and isolated per-query retention/removal mutants. 496-check link-only evidence; no external capacity expectation or NS runtime provider. |
| `test_cm33_secure_cohort.ps1` | Independent 496-check C33S private companion binding using its actual objects, geometry and key, including 32 compiled single-query retention mutants. Qualification is separate from C55S and the CM33 NS runtime. |
| `test_cm33_secure_isa.ps1` | Real M33 companion input-object AND final-ELF ISA admission, whole-pool source ceiling, wrong-M55 inputs, mixed/native/LTO higher-ISA controls, compatible lower-subset helper, and strict attribute parser negatives. 300 checks; final observed `dls`/`le` veto is not an exhaustive opcode scanner. |
| `test_m55_secure_initialize.ps1` | Separate staged C55S initializer proof using actual M55 Secure/Non-secure images and SG, exact current twelve-entry imports/old-eight initializer negatives, ordered CPU/pool effects, preflight rejection, postcommit fault injection and classifier controls. The later twelve-entry replay preserves the initializer cases; it does not qualify the other three lifecycle entries. Requires the explicit QEMU gate; no Non-secure Fiber runtime is implied. |
| `test_m55_secure_lifecycle.ps1` | Separate staged C55S allocation/load/save proof: actual M55 Secure/Non-secure SG calls, exact twelve-entry imports/old-nine negatives, owner/pool geometry, ordered PSP/PSPLIM transfers, rejection and partial-update controls. The four-mode 148-scenario run, independent oracle review and later combined matrix pass; exact receipts are in `PORT_ARCHITECTURE_AUDIT.md`. Requires the explicit QEMU gate; no Non-secure Fiber runtime is implied. |
| `test_m55_secure_attachment.ps1` | Staged NS constructor/pre-start attachment: actual pinned reference constructor, complete frame/metadata/untouched-stack oracle including r9, real NS-Thread-to-SG query trace, explicitly labelled query/CPU-state doubles, lifecycle/cohort link negatives and compiled oracle mutants. Seven O0/O2/Os, optimized-LTO and hostile modes produce 892 launches; no full runtime/provider/switching or hardware claim. Requires the explicit QEMU prefix. |
| `test_cm33f_mpu_manifest.ps1` | Staged CM33 scalar-FP MPU public C/C++ types without CMSIS, strict real-CMSIS manifests, 8/16-region hard/softfp layouts, numeric RBAR.SH oracle, and actual pinned M33 MPU/FP reference geometry at O2/Os. No Fiber constructor or handler parity is claimed by this type-only proof. |
| `test_cm33f_mpu_constructor.ps1` | Separate staged C3FP constructor/linker proof against the actual pinned M33 MPU/FP constructor: 8 O2/Os hard/softfp and 8/16-region configurations, numeric images/maps/seals/bounds, linker negatives, hostile instrumentation and optimized-Python rejection. No handlers or complete runtime. |
| `test_cm33f_mpu_first_start_codegen.ps1` | Staged strong SVC-70 and basic restore: 16 O2/Os hard/softfp, 8/16-region, normal/LTO configurations compile actual pinned reference and normal/hostile production ELFs. Complete normalized naked sequences, mapping-symbol byte coverage, ordered C-envelope/MMIO evidence and exact compiled negative controls. No executed exception transfer or complete runtime. |
| `test_cm33f_mpu_first_start_execution.ps1` | Actual Secure-bootstrap/NS first basic SVC-70 restore on QEMU AN505: O2/Os hard/softfp, real model geometry, complete initial integer state, PSP/PSPLIM/CONTROL and eight-region image, exact rejection and MPU access-fault cases. Sixteen-region variants are compile/link only. No PendSV, FP-context stress or full runtime; reference assembly comparison is a separate gate. Requires the explicit QEMU prefix. |
| `test_cm33f_mpu_running_execution.ps1` | Actual strong SVC-71/SVC-72 and PendSV components on QEMU AN505: all four basic/extended save-restore combinations, PSP/PSPLIM/CONTROL, complete FP and integer state, eight-region replacement, scheduler CPU/MPU preservation and exact rejection cases. Sixteen-region variants are compile/link only. The staged harness calls the private start bridge, not the public common lifecycle. Separate generated-assembly parity compiles the pinned reference. |
| `test_cm33f_mpu_runtime.ps1` | Actual five-operation common lifecycle and eight-operation C3FP provider, direct/archive, GC/LTO, hostile, exact vector/cohort/reverse and negative links. The current staged-source receipt has 161 AN505 executions; 16-region and default-panic images are compile/link-only. Requires explicit QEMU. Reference identity is checked, but assembly parity and actual reference execution are separate gates. |
| `test_m55_secure_first_start.ps1` | Separate staged C55S first-start gate using two actual M55 images, CMSE veneers and the production initializer/allocation/load gateways. Its complete run must exercise both zero-handle and attached first restore, normal/LTO/archive/hostile builds and exact preflight/partial-update failures. Development case selection is recorded as an incomplete suite. No ordinary PendSV, full eight-operation runtime or board qualification is implied. |
| `test_m55_secure_runtime.ps1` | Complete staged C55S two-image common lifecycle/eight-operation provider and twelve production gateways on AN547, direct/archive/GC/LTO, NS/common dual-r9, four hash/map policies, NS/S-origin switching and exact negative links/faults. No forced includes; `Development*` selections cannot qualify the full suite. Raw stack-check cases budget 8 KiB stacks, not probe elimination. Requires explicit QEMU; no activation or board claim. |
| `test_m55_secure_runtime_admission.ps1` | Composes the unchanged complete C55S runtime suite with exact C/C++ public-consumer, constructor-only reverse-v1 archive and unoverridden-default admission. Requires the exact full runtime inventory plus 80 default executions, recorded immutable inputs/QEMU dependencies and actual driver-selected LTO plugin. Missing-v1 negatives reject mixed linker errors, including a compiled RAM-overflow control. Development subsets retain CompleteSuite=false; no activation, physical-no-FP or board claim. |
| `fixtures/source_export_identity/identity.ps1 -RunProof` | Canonical source-byte manifests and optional exact-root Git attribution for C3SO/C5SO exports. Actual no-Git AdmissionOnly runs, mutation/removal controls, LTO plugin/wrapper provenance and causal drift-guard removal; installed tools are never modified. Does not replace the full runtime suites. |
| `test_cm33_secure_only.ps1` | Staged Secure-only scalar scheduler: actual pinned Secure-only reference tuple, C/C++ public storage without CMSIS, numeric role/frame layout, exact forward/reverse symbols, ordered transfer subsets and 29 manifest negatives at O2/Os. Not closed whole-body parity, final ELF/LTO or exception execution. |
| `test_cm33_secure_only_runtime.ps1` | Actual common lifecycle and full C3SO provider in a Secure M33 image; normal/archive/GC/LTO/vector/cohort/reverse checks, dual-r9, mask/lifecycle/corruption and raw compiler cases. Adds unchanged public portable/default links and constructor-only mismatched-common archive negatives with executable retain-removal controls. The complete 297-execution receipt is distinct from closed-body parity; focused phases cannot claim completeness. No hardware claim. |
| `test_cm55_tfm.ps1` | Actual M55 CPU/runtime target links and typed source-derived TF-M adapter/mutex tests, plus explicitly supplied AN547 dual-r9 construction/first-SVC/PendSV execution. Both ordinary AAPCS and consistently reserved-r9 ABI are checked. No actual Secure TF-M image or board qualification. |
| `test_cm33f_tfm.ps1` | Staged M33 FP consumer/typed-adapter links and host tests; explicit QEMU additionally executes real common and all port objects, hard/softfp, lazy/eager and dual-r9 FP transfers with compiled controls. Uses a test Secure bootstrap and typed NS provider, not actual Secure TF-M. Missing QEMU records `NOT_RUN`; independent reference parity and activation remain separate gates. |
| `test_cm55_secure_only.ps1` | Staged scalar Secure-only M55: actual pinned M55_NTZ Secure-only reference compilation, exact independent C5SO geometry/storage/symbol surface, ordered generated transfer subsets and 36 manifest negatives. Not a relabeled M33 runtime receipt, closed-body equivalence or execution. |
| `test_cm55_secure_only_runtime.ps1` | Independent C5SO common/runtime proof on AN547 with normal/archive/GC/LTO/vector/cohort/reverse, dual-r9 and raw compiler cases. Complete suites include unchanged public/default-policy links and constructor-only exact archive ABI rejection/causal controls. Not a relabeled M33 receipt, reference-parity or hardware claim; focused phases are incomplete. |

The source-derived host tests compile the actual selected function bodies and
constants with explicit hardware/integration stubs. They do not execute the
exception machinery or substitute a model for the generated-assembly checks.
The Unicorn harness executes real Thumb guard code, not hardware MPU or lazy-FP
behavior. The paired FreeRTOS checks still compile the actual pinned reference.

For the QEMU gate, first prepare the isolated prefix explicitly as described in
[`fixtures/arm_control/README.md`](fixtures/arm_control/README.md), then pass its
WSL path to the matrix with `-ControlQemuRoot` (or `FIBER_CONTROL_QEMU_ROOT`).
`-ControlWslDistro` selects the WSL distribution. The matrix never provisions
tools. When no prefix is supplied it prints `NOT_RUN`; that result must not be
reported as an executed architectural proof. Missing tools or failed cases with
an explicitly supplied prefix fail the run. CI qualification must supply this
dependency separately from the source-derived host tests.

The two M55 pool runners provide complementary evidence. Unicorn's scalar
model requires the explicitly labeled low-overhead-loop counterflag for its
executed variants; those results do not establish default M55 execution. The
separate QEMU `mps3-an547` runner executes the unmodified production source with
normal M55 code generation and no such flag. Neither runner exercises the later
Non-secure runtime, NSC activation, or Secure PSP/PSPLIM save/load lifecycle.
The initializer runner qualifies only guarded initialization through the NSC
entry; it does not extend the two memory-only pool receipts to allocation,
attachment or context transfer. The separate lifecycle runner addresses the
three allocation/load/save entries. Its results must distinguish ordinary
rejection, deliberate fail-closed faults, and terminal partial-update failures.
A partial-update failure must stop in the originating Non-secure Handler before
exception return, not report success after Thread execution has resumed.
Neither runner supplies the still-pending Non-secure Fiber runtime or attachment
implementation. The later constructor/attachment runner supplies its own staged
source and evidence; it does not supply the pending Fiber runtime.
Actual-reference transfer parity and these execution proofs
remain separate evidence classes.

The staged C55S hostile audit covers every byte of the pure cohort provider's
sized ELF symbol. One compiled pure helper must pass; six nonexecuted compiled
controls must reject undefined instructions, UDF, data, missing byte coverage and
a store. The lifecycle store classifier preserves actual M55 decoder output;
its separate generic-Thumb STC decoder control is static only and establishes
no M55 coprocessor execution capability.

Exception entry and Handler execution must not be modeled as a permanent SPSEL
read-as-zero rule on Armv8-M. Entry clears the targeted bank, but privileged
Handler writes can set the stored bit while Handler code still uses MSP.
Post-write readback therefore compares the written value. SG is not exception
entry. The maintained QEMU tests exercise these distinctions independently of
the host stubs and selected-port source checks; they are not Fiber runtime or
hardware qualification.

Keep commands, generated sources, disassembly, ELF/maps, negative-link output,
and results from a failing or qualifying run. Do not describe these results as
board qualification or exhaustive semantic equivalence of every instruction.
The separately planned global `-O0/-Og/-O3` and final-LTO parity expansion remains
a later gate; host `-O0` cases do not establish that global ARM coverage.

The classic and C3FP Python runners reject optimized interpreters explicitly
before assertion-based checks, extraction or classifier imports can run. Their
dependency-version checks use explicit failures rather than assertions. Maintained
negative controls verify the intended optimization/version diagnostic; arbitrary
import failures cannot satisfy these controls. Do not enable `PYTHONOPTIMIZE` or
invoke these proofs with `-O`/`-OO`.

## Integration Requirements

Additional maintained compiler proofs are independent from the default matrix:

| Runner | Scope |
| --- | --- |
| `test_h7s_snapshot_build.ps1` | Separate offline real H7S Boot Debug/Release gate: exact pinned production export and separately hashed outer project, private CubeIDE configuration/workspace/home, fresh generated 35-object recipes and exact source/object/dependency/ABI owners. Final ELF vectors, weak startup Reset, strong port SVC/PendSV and three read-only cohort pointers have maintained admission and changed actual-ELF rejection controls. No live build, CubeMX regeneration, provisioning, debugger, QEMU or board execution. Not selected by the default matrix. |
| `test_classic_context_runtime.ps1` | Actual CM0 microbit execution through pure Context and real Fiber v1: public start/yield plus an assembly-owned direct-PendSV GPR supplement, O2/Os ordinary/final-LTO, direct/archive and hash/map policies. Exact panic/terminal controls, actual compiled restore/publication mutants, strong vectors, prelink common-private ownership, final ELF cohorts and paired pinned FreeRTOS mechanisms are required. This is not M0+, FP, MPU, TrustZone, STM32 peripheral or board qualification. The main matrix selects it only with an explicit QEMU root. |
| `test_classic_fp_context_runtime.ps1` | Actual CM4F AN386 Context/Fiber FP-state execution: 64 positive and 224 compiled register/frame/publication controls, O2/Os ordinary/final-LTO, direct/archive, eager/lazy and primary/validation policies. Three workers include a GRO/FP-inactive path. Public-call callee-saved checks and direct-PendSV all-FP checks are distinct. Exact observer write/return/entry bounds have 32 assembled controls; eight actual pinned CM4F reference final ELFs remain link-only and bounded-mechanism comparisons, not whole-kernel equivalence. Conditional explicit-QEMU dispatch; no G4 peripheral/NVIC-width, CM7, softfp, arithmetic, complete panic-suite or board claim. |
| `test_classic_cm7_fp_context_runtime.ps1` | Separate AN500 M7 r1p2 hard-FP Context/Fiber suite: 64 positives and 224 compiled causal controls, O2/Os ordinary/final-LTO direct/archive eager/lazy and primary/validation policies. Uses the same unchanged bounded ELF/observer checker, exact M7 CPUID/MVFR, capability/cohort/terminal discriminators and distinct M7 BASEPRI envelopes. Eight actual pinned CM7/r0p1 final ELFs are link-only references. Fresh CM4 replay and 296 native executable-image comparisons guard the shared test refactor. Conditional explicit-QEMU dispatch; not H7/H7S board/cache/TCM, erratum effectiveness, DP arithmetic, complete panic-suite or global parity evidence. |
| `test_cm0_freeze_parity.ps1` | Separate non-MPU M0/VTOR=0 and M0+/VTOR=1 seven-mode codegen/link gate: 20 ordinary paired objects, 30 mechanism comparisons, 28 final pairs/56 positive ELFs, 84 actual-source compiled mechanism controls. Uses actual pinned CM0 `port.c`/`portasm.c`, real Context providers, natural archive extraction and actual final LTO plugin provenance. Old `-Cm0Only` O2/Os inventories remain unchanged. Not CPU/G0 execution, CM0+ VTOR=0, MPU, constructor interpretation, closed-function equivalence or global parity. Not dispatched by the current default matrix. |
| `test_sensitive_port_closure.ps1` | Exact selected/common native source groups, raw instrumentation/SSP/coverage/sanitizer/profile flags without exclusion counterflags, normal/slim-native-LTO and sectioned/unsectioned text. Function reachability separates sensitive common roots from cold public construction/configuration. Unknown initializers, hooks, build failures and drift fail. The recorded global 336-cell receipt is FAIL; it is not a replacement for the documented supported-build counterflags. |
| `test_constructor_r9.ps1` | Actual public constructors and bounded linked GPR restore slices under ordinary AAPCS and consistently reserved-r9 ABIs. `-ImmutableInputs` freezes actual sources before execution; development subsets cannot qualify the full inventory. Ordinary borrowed frame R9 is an observation, not an invented static-base failure. See the fixture README for the exact boundary and historical unqualified builds. |
| `freertos_asm_parity.ps1 -Cm33fTfmOnly` | Focused actual pinned C3FT O2/Os hard/softfp object closure, 77 complete streams, bounded numeric oracles and compiled causal controls. The default parity dispatch includes it. It does not execute real FP exceptions, qualify native LTO or activate the staged profile. |
| `test_parity_helper_imports.ps1` | Strict-mode imports of compile/disassembly/ordered-parity helpers with absent, false and true optional focused-recording state. Three real ARM probe objects, missing-instruction negatives, and an old-caller-dependency reproduction protect helper reuse without relaxing any production parity assertion. |
| `test_cm4_raw_compiler.ps1` | Scoped CM4 no-FPU/soft/hard/softfp eager/lazy raw compiler closure, five optimizations and native-LTO layouts, literal-pool reach and compiled naked-body controls, pinned O2/Os reference mechanisms and constructor r9 checks. A scoped PASS does not qualify global raw flags or hardware. |
| `test_cm33_tfm_raw_compiler.ps1` | Scalar C3TF CPU/boot/initializer/mutex transitive closure across five optimizations, normal/native LTO and three hash/map/rewind profiles. Compiled old/new naked-body equality, pinned CPU/wrapper reference builds, inline-only removal controls and a scoped constructor-r9 subset remain separate from real TF-M/PSA execution and global raw qualification. |
| `test_cm33_paired_raw_compiler.ps1` | Scalar paired CM33 NS/secure CPU-helper raw closure, five optimizations, ordinary/native-LTO text layouts, compiled helper-removal controls and unchanged naked-body/dictionary checks. Closed reference analysis, secure cohort binding and actual dual-origin execution retain separate receipts; no hardware or global raw qualification is inferred. |
| `test_v8_mpu_raw_compiler.ps1` | Four scalar/FP/MVE CM33/CM55 MPU source groups, 8/16 regions, applicable hard/softfp ABIs, five optimizations and native-LTO layouts; exact captured compiler closure and CPU-inline removal controls. Separate ordered-reference and state-model receipts do not imply exception execution or hardware isolation. |
| `test_cm33f_tfm.ps1` | Staged C3FT target/host proof plus explicit QEMU execution; unchanged portable C/C++ consumers, exact default-policy observer and constructor-only archive admission. Real common runtime is used; the typed NS provider and Secure bootstrap are fixtures, not a Secure TF-M image. RuntimeSelectable remains separately gated. |
| `test_sensitive_data_reachability.ps1` | Actual native ELF callback fields at object start/interior, protected/unprotected direct and indirect roots, O2/Os normal/native-LTO layouts and six containment-removal causal controls. Proves the bounded ABS32 object-extent resolver case, not arbitrary indirect-call provenance or global raw closure. |
| `fixtures/c55s_raw_admission/run.py` | Actual complete staged C55S source group and standard expectation TU; twelve O2/Os normal/native-LTO positives and twelve compiled missing-forward-operation mutants. Exact old-exemption false PASS and repaired rejection are causal controls, not profile activation or Secure execution. |

- Public `fiber_core.h` usage automatically emits a caller-storage expectation.
  Direct concrete-type allocators must include the expectation header described
  in `CONSUMER_COHORT_TEST.md`; bare inspection/type-only compilation stays free
  of runtime dependencies.
- The existing linker `KEEP(*(.fiber_port_context_cohort_expectation))` must keep
  all input contributions. The output is a multiple of the target pointer size,
  not a fixed one-pointer section. Rebuild all pre-guard application objects.
- CM33 MPU and the three M55 MPU profiles use context generation 2
  (`0x00020008u` or `0x00020010u`). Clean-rebuild every component and expectation.
- Armv8-M current-slot and privileged-RW mappings must be disjoint. Startup must
  zero the separate slot section. The slot remains RO/XN at both privilege levels
  while MPU is enabled; publication remains inside the protected MPU-off interval.
- CM0 MPU no-VTOR aliases require the explicit immutable-map integration proof
  documented by the classic runner. An unproved alias fails closed.
- Raw stack/canary storage must be accepted by the embedding RAM hook before
  access. Do not weaken a board memory map merely to satisfy a negative test.
