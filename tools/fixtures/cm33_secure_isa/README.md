# CM33 Secure Companion ISA Regression

Run `tools/test_cm33_secure_isa.ps1 -ArmGcc <arm-none-eabi-gcc.exe>` with optional
`-CmsisCore <CMSIS Include>` / `-BuildRoot <evidence parent>`.
There is no network action or skip mode. An unexpected compilation failure
fails the run rather than qualifying a negative control.

The runner builds the actual CM33 Secure identity gateway, context gateway and
pool at `-O2` and `-Os`, with and without LTO. The pool is compiled without a
CMSIS include path; its dependency output must remain CMSIS-free. Matching
images must link with the private cohort generation fragment, retain the real
pool provider and one strong private cohort byte, expose exactly the current twelve NSC
imports and have no unresolved symbols. The same production pool compiled for
Cortex-M55 may compile successfully under the approved scoped GCC function
target policy. Its whole linked pool must have no observed `dls`/`le`; its input
object still advertises `v8.1-M.mainline` and must be rejected in all four modes.
The runner preserves actual macro dumps under the normal M33/M55 soft/GRO flags:
both expose Armv8-M Mainline/CMSE, without a distinguishing FP/MVE/v8.1/LOB macro.
It does not manufacture a target macro to make a rejection appear possible.

## Final ELF Rule

The attribute detector consumes actual `readelf -hW` and `readelf -AW` output. It requires
one ELF32 class, little-endian data, ARM machine, Microcontroller architecture
profile, and exactly one known `Tag_CPU_arch` from this explicit ceiling list:
`v6-M`, `v6S-M`, `v7`, `v7E-M`, `v8-M.baseline`, `v8-M.mainline`.
An ARM-state-use tag must be absent or exactly `No`. Missing, duplicate,
unknown, suffixed or higher architecture values fail closed; CPU names never
override the architecture. Actual complete positive companions must merge to
exactly `v8-M.mainline`. The final-image decision also vetoes addressed, encoded
`dls`/`le` instructions from actual final `objdump` output, for the mixed-LTO
reason below. This is deliberately not an exhaustive unsupported-opcode scanner.
Parser negative controls are synthetic and identified separately from compiled
examples.

Admission requires **both every inspected input object and the final ELF** to
pass. Correct production pool inputs must be exactly `v8-M.mainline`. Wrong-M55
production pool inputs must be `v8.1-M.mainline` and rejected even if a scoped
function target emits compatible instructions. Native wrong-pool final ELFs
also retain the higher attribute and are rejected. In the measured LTO case the
final attributes fall to `v8-M.mainline`; the original input rejection remains
mandatory and prevents that compatible-looking output from being admitted.

An independent memory-only C helper is compiled for Cortex-M3 and linked into
each correct CM33 image through an ordinary call. This compatible lower-ISA
object must leave the final architecture at `v8-M.mainline`. That does not
declare a lower-target production pool to be a supported build manifest.

The same helper compiled for Cortex-M55 must actually retain encoded `dls` and
`le` instructions in its final named function, and the final ELF must merge to
`v8.1-M.mainline` and be rejected by the detector. The helper stays native when
the rest of the image uses LTO, making this a mixed-object final-link check.
No production guard is bypassed to manufacture this counterexample. Failure to
generate the instructions is a test failure, not a skipped negative control.

## Isolated Guard Mechanism Probes

These are fixture-only experiments, not alternative production guards. With the
local GCC 14.3.1 / binutils 2.44.0.20250616 toolchain:

- A top-level `.arch armv8-m.main` rejects native M55 `dls`/`le` assembly while
  the same source compiled for M33 succeeds.
- A GCC function `target("arch=armv8-m.main")` removes the observed low-overhead
  loop, but the native object still advertises `v8.1-M.mainline`; final attribute
  rejection remains meaningful even when that helper has no `dls`/`le`.
- A genuinely LTO-compiled M55 helper, linked with the M33 driver into the
  actual M33 companion, retains `dls`/`le` while the final ELF attributes report
  `v8-M.mainline`. This occurs both with and without the top-level `.arch`
  directive at `-O2` and `-Os`. Attribute-only rejection is insufficient here;
  the separate final-disassembly veto must reject each compiled counterexample.

Each mechanism is checked in maintained code, not just described from a prior
receipt. The runner makes no assertion that preprocessing alone can distinguish
all M33 and M55 scalar soft/GRO builds. A future compiler changing a measured
counterexample must trigger review, not quietly remove the negative control.

Arm DDI0553B.y C2.4.492 (printed page 1437) assigns DLS T2 to the Armv8.1-M
Low Overhead Branch extension and decodes it as UNDEFINED without that
extension. See the [Arm architecture manual](https://community.arm.com/cfs-file/__key/communityserver-discussions-components-files/471/DDI0553B_5F00_y_5F00_armv8m_5F00_arm.pdf).
These integer instructions are not prohibited by `-mgeneral-regs-only`.
CPU-state-free source does not guarantee portable generated instructions.

## Evidence And Limits

Each invocation creates a unique evidence directory, preserves command argument
arrays and exit codes, compiler/readelf identities, preprocessed sources,
assembly, objects and dependencies, final ELF/map/import/disassembly/attributes,
checks, a receipt, input before/after SHA256 manifests, and artifact hashes.
LTO final-link intermediate assembly and objects are retained too.
Source drift fails the run. Only a complete run prints final `PASS`.

The image is link-only. Its calls are not a valid lifecycle sequence. No image
is executed or programmed. This checks attributed ISA compatibility with a real
generated counterexamples, including observed compiler LTO attribute loss, not arbitrary dishonest/missing object metadata,
every possible unsupported opcode, complete TrustZone behavior, hardware, or
an application-owned geometry expectation. It neither changes the public API
nor widens the supported production manifest.
