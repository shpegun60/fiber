# Pinned Classic-FP Reference Final-Image Pilot

This is an opt-in link-only companion to the native pilot. It builds the
actual `portable/GCC/ARM_CM4F/port.c` or
`portable/GCC/ARM_CM7/r0p1/port.c` from the locally pinned FreeRTOS
`a50edad08b29052631aa469d4df6e6ec7ff68878`. It compiles an unchanged,
hash-checked captured copy, without reimplementing or modifying the upstream
port. Exactly the CM4 and CM7/r0p1 hard-FP, VTOR1, no-MPU, p4/b16,
ordinary-AAPCS cohorts and O0/Og/O2/Os/O3 direct linkage are admitted.
Default selection remains CM4/O2. Profile-bound attributes and header facts
distinguish CM4 SP from CM7 `fpv5-d16` SP+DP; ELF hard-float flags alone
are not a profile admission proof.

The native inventory's eager cohort identifies the target/ABI, not an
upstream FP policy claim. The reference retains its upstream ASPEN+LSPEN
lazy setup. The recorded eager/lazy difference is not erased or declared
equivalent by this final-image witness.

## Build And Ownership

Four fresh translation units are required: the pinned port, typed boundary
providers, typed consumer and fixture startup. Both ordinary and
`--emit-relocs` links consume exactly the same frozen objects, target flags
and script, with `--build-id=none`. Direct input-section placements are
retained in the emitted map. Source/tool/dependency hashes, original REL
addends, commands, terminal outcomes and object checkpoints are retained.
Actual compiler dependencies must match precompile discovery. Port source,
portmacro, config provider, CPU/FPU flags and protocols must select the
same profile. No archive, LTO or additional optimization is admitted.

CM7's captured inventory also requires the exact
`configENABLE_ERRATA_837070_WORKAROUND=1` definition; CM4 does not. The
builder must preserve this profile-specific define set without admitting
extra definitions. The pinned CM7/r0p1 source already contains its erratum
sequence unconditionally: preserving the manifest define is not a claim
that this macro switches that source sequence on or off.

The providers define `pxCurrentTCB`, `vTaskSwitchContext` and
`xTaskIncrementTick` with their real upstream C types. The current TCB is
NULL. Scheduler/tick/assert calls enter explicit fail-stop boundaries.
No actual TCB, stack, ready list or scheduler model is invented. Fixture
reset cannot start the reference scheduler. No target instruction runs.
Vectors retain the actual SVC, PendSV and SysTick symbols; this only proves
link-time placement, not active VTOR, exception execution or board routing.

Two explicitly kept unowned Thumb NOPs outside function extents provide
the coherent-callee-retarget negative control. They are deliberately not
a valid function origin. The synthetic memory map and all fixture code
are test artifacts, not production integration changes.

## Fixed Reader Surface

`ReferenceCM4FinalImage` and `ReferenceCM7FinalImage` are fixed profile
readers, separate from the native reader. Their only mode parameter admits
the five ordinary modes above. No caller can provide a different protocol,
root/callee/slot allowlist or arbitrary target recipe. These are the base
complete prelink roots, shared by Og/O2/Os/O3:

| Profile | Root | Binding | Bytes | Original References |
| --- | --- | --- | ---: | --- |
| Both | `prvPortStartFirstTask` | local | 40 | none |
| Both | `vPortSVCHandler` | global | 32 | `pxCurrentTCB` ABS32+0 |
| CM4 | `xPortPendSVHandler` | global | 92 | BL at 46, ABS32 at 88 |
| CM7/r0p1 | `xPortPendSVHandler` | global | 96 | BL at 50, ABS32 at 92 |

O0 alone appends exactly one `00bf` NOP per root, after the literal island
with its own Thumb mapping. Neither the instruction nor its mapping is
discarded. CM4 totals are 164 bytes/48 instructions, or 170/51 at O0;
CM7 totals are 168/50, or 174/53 at O0. Each profile/mode retains exactly
one BL-4 to `vTaskSwitchContext` and two ABS32+0 words for `pxCurrentTCB`.
CM7's literal LDR displacement is 80, not CM4's 76. Its upstream
CPSID/BASEPRI/barrier/CPSIE sequence remains distinct from the native
PRIMASK-preserving policy. Alternate `WORKAROUND_PMU_CM001=1` code is not
admitted by these fixed protocols.

The independent reviewed prelink protocol is checked before final-image
replay. The final reader retains all code, literal islands, alignment
padding, local branches, mapping symbols and extents. Only the exact
observed IT-EQ/high-FP-save/restore forms are added, with raw bytes and
operands bound. The local first root is not permission for other local,
weak, ambiguous or caller-selected definitions.

The first root has two exact adjacent data mappings: padding `[34,36)`
and literal pool `[36,40)`. Both prelink and final must retain them.
Conflating or shifting their boundary rejects, even when bytes still match.
`DataMappings` records both; the logical literal island remains `[34,40)`.

Original REL addends come only from ET_REL bytes. Applied ET_EXEC fields
are decoded without fabricating an ET_REL view of final bytes. Function
and current-TCB entry origins bind actual provider symbols/sections/offsets
to independently retained input-section map placements. Final symbol-table
self-consistency alone is insufficient. ELF32LE ARM, load/section ownership,
permissions, NOBITS boundaries and complete twin load equality remain strict.

## Replay And Negative Controls

`reference_witness.py` consumes existing objects/final ELFs/disassembly/map.
It executes no tool. Each input is copied and hashed before use; exact
original provider path identities remain map keys. It replays all three
positive roots. The five witness roles and four providers must represent
eight distinct physical files, with only the intentional prelink/provider
overlap. Same-path twins, cross-role aliases and hard links reject before
capture; pure input-identity controls exercise those cases. The witness
then retains thirteen actual bounded mutation classes:

- ordinary instruction byte change;
- applied BL destination plus two;
- applied current-TCB ABS32 plus four;
- applied REL kind and symbol substitutions;
- original BL and ABS32 addend changes;
- local first-root binding changed to global;
- root extent and data-mapping boundary changes;
- coherent callee symbol plus BL retarget to unowned Thumb NOP padding;
- NOBITS current-TCB storage overlapping file-backed text;
- writable current-TCB owner without writable load permission.

Each control requires a real changed field, the intended rejection stage
and matching rejection reason. Failure to construct a control is FAIL,
not a successful rejection. Eleven controls must preserve identical twin
load images; the two structural storage controls reject at twin validation.
Closing source/input/captured-input/mutant hashes must not drift.

## Non-Claims

This is reference prelink-bound final-root preservation and entry-origin
evidence. It is not native/reference semantic equivalence, C-callee/internal
relocation or constructor closure, successful MMIO, actual scheduler/TCB
semantics, archive/LTO coverage, CPU/board execution or global qualification.
It satisfies zero required global parity cells on its own. Existing native
pilot admission and tests are not replaced by the reference companion.

## Commands

The build uses the installed/captured pyelftools 0.33 package, like the
native pilot. Output directories must be fresh and external to the repo.
The standalone witness rejects repository descendants/ancestors and existing
outputs before directory creation, input capture or ELF-reader loading.

```text
python -B tools/fixtures/classic_final_image/reference_run.py \
  --gcc <existing-arm-gcc-14.3.1> --git <existing-git> \
  --freertos <clean-pinned-local-FreeRTOS> \
  --inventory <retained-source-inventory> --profile CM7 --mode Og \
  --output-dir <fresh-build>
```

With an existing successful build, in PowerShell:

```powershell
$b = '<successful-build>'
$receipt = Get-Content "$b/results.json" -Raw | ConvertFrom-Json
$providerArgs = @()
foreach ($row in $receipt.Sources) {
    $providerArgs += '--provider-object'
    $providerArgs += $row.Object
}
$env:PYTHONPATH = "$b/python"
python -B tools/fixtures/classic_final_image/reference_witness.py `
    --profile $receipt.Profile --mode $receipt.Mode `
    --prelink-object "$b/objects/00-port.o" `
    --final-elf "$b/emit-relocs.elf" --plain-elf "$b/ordinary.elf" `
    --disassembly "$b/emit-relocs.dis" --link-map "$b/emit-relocs.map" `
    @providerArgs --output-dir '<fresh-reader-output>'
```

Separate pure suites are `test_reference_run.py --report <fresh-TEMP-json>`
and `test_reference_elf.py --output-dir <fresh-directory>`, plus
`test_reference_witness.py --report <fresh-json>` (input identity and exact
profile/mode totals). They execute no native tool or target image. Invoke
builder/reader once per Cartesian pair for a ten-pair sweep, using fresh
directories; partial attempts do not qualify a complete sweep.
