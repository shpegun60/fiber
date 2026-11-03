# CM4 MPU FP-Active Grid

This separate opt-in suite reuses the frozen basic-grid and FP-pilot fixtures
without changing their sources or replacing their receipts. The bounded target
is Cortex-M4 on QEMU AN386, eight MPU regions, hard fpv4-sp-d16, and the real
Context/FiberV1 common providers and ARM_CM4_MPU handlers. All C is GRO; explicit
FP state is exercised by the pilot's user-stack assembly oracle.

## Literal Inventory

- 32 positive images: Context/FiberV1 x eager/lazy x O2/Os x ordinary/final-LTO
  x direct/archive provider linkage.
- 20 actual backend controls: the five pilot payload mutations under both FP
  policies for Context O2 ordinary/direct, and FiberV1 Os final-LTO/archive.
- Eight actual pinned FreeRTOS reference ELFs keyed by optimization, LTO and
  archive linkage. The pin is `a50edad08b29052631aa469d4df6e6ec7ff68878` and the
  same 26 selected reference source hashes are required before use.
- 32 hash-bound positive/reference associations. Context/FiberV1 and eager/lazy
  variants share the reference matching their optimization/LTO/archive tuple.
- One model probe: 61 distinct final ELFs total, with exactly 53 requested
  target observations when execution is explicitly selected. References are
  link-only and are never counted as execution observations.

The five compiled controls omit high-FP save, high-FP restore, low-FP save,
low-FP restore, or corrupt the saved FPSCR. Cursor geometry is preserved.
Expected resumed payload reasons are respectively 131, 131, 134, 134 and 132,
always worker0, with phase1 for high-FP omissions and phase2 for the other
controls. Exact exit66 and the two-line reason/failure terminal are required;
an arbitrary panic, fault, timeout or different reason is not a causal PASS.

## Mechanisms And Limits

The reused fixture keeps context metadata and reporting privileged, current
publication in the isolated read-only aperture, and all worker writes within
their own stacks. Two workers use distinct FP payloads; the third stays
FP-inactive. Genuine public yield checks ABI-preserved high FP. The assembly
envelope through the real naked SVC71 scheduling primitive checks full
S0-S31/FPSCR. Constructor-seeded return reaches the production SVC72 path.

The privileged dispatcher observes the saved basic/extended images and raw
serialized CONTROL, then poisons only the outgoing user frame's low16/FPSCR
words. Correct restoration must reconstruct them from the private copy rather
than succeed because the old user frame happened to remain intact. Core words
and the reserved FP word are not poisoned.

This does not prove strict low-FP/FPSCR self-selection: the self-selection is
in the public-yield phase, whose oracle intentionally checks high FP only.
Post-save LSPACT=0 also does not establish pre-save LSPACT=1 or the exact point
of lazy materialization. `PreSaveLspactObserved` remains false; no RSP probe or
production observer hook is added here.

Decoded reference associations are bounded mechanism evidence, not byte
identity, whole-kernel equivalence or reference execution. Upstream enables
lazy preservation; Fiber's eager policy is an intentional difference. This
grid does not extend qualification to MPU16, O0/Og/O3, softfp, arbitrary MPU
regions, all features, STM32 NVIC-width manifests, hardware or CI.

## Invocation And Evidence

Use `tools/test_classic_cm4_mpu_fp_grid.ps1` with explicit `ArmGcc`, `CmsisCore`,
`FreeRtosRoot`, actual `Python`, existing `PythonModules` with pyelftools 0.33,
and a fresh external `BuildRoot`. The Python entry point accepts `--repo`,
`--gcc`, `--cmsis`, `--freertos`, `--build-root`, optional `--wsl-distro`, and
optional `--qemu-root`.

The default, or explicit `--compile-only`, only builds, links and inspects.
It must not invoke WSL/QEMU. A closed compile receipt has
`Verdict=COMPILE-PREFLIGHT-PASS`, `Execution=NOT_RUN`, with no target rows
executed. `--execute-grid` (PowerShell `-ExecuteGrid`) additionally requires an
explicit existing Linux QEMU prefix. Only the complete, exact 53-observation
request may close as `Verdict=FP-GRID-PASS`, `Execution=BOUNDED_FP_GRID`.
`CompleteSuite` remains false in both modes: this is a bounded FP grid, not a
full ARM_CM4_MPU or all-feature qualification. No development subset is offered.

Before importing local helpers, `run.py` captures the basic, pilot and grid
directories, the grid and pilot wrappers, current selected Context/runtime and
port sources, source-role readers, reference/parity helpers, the two maintained
QEMU scripts, CMSIS headers and pinned reference inputs. It also captures the
existing pyelftools package before its first import. Only captured helper bytes
are loaded; missing inputs fail rather than fall back to the live repository.
The suites capture tool identities, actual dependencies, native ELF/owner/
vector/cohort evidence, associations, commands and opening/closing identities.

Capture attribution is fresh selected bytes, not an implicit clean-Git claim.
FAIL-first closing requires typed inventory contracts, artifact verification
and zero input/QEMU drift before accepting the requested mode. Every attempt
uses a new evidence directory; earlier failures and pilot receipts are neither
overwritten nor relabeled. No historical TEMP receipt is a required input,
and neither mode installs tools, provisions WSL, changes production or flashes
a board.
