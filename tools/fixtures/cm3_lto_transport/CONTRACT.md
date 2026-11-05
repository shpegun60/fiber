# Native CM3 LTO Transport Feasibility

## Fixed Scope

This contract specifies an opt-in capture/build feasibility probe for
`cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default`, at O2-lto with
direct linkage only. The target is Cortex-M3/ARMv7-M, ordinary AAPCS, soft ABI,
no FPU or FP stacking, VTOR1, no MPU, classic security, four declared priority
bits and raw BASEPRI threshold 16. It adds no port backend or runtime feature.

The input authority is a separately qualified native CM3 ordinary-O2 producer
receipt and its complete artifact manifest. The probe builds new slim-IR inputs
and two genuine LTO executables from the seed's captured source/configuration
bytes. An ordinary object, fat-object fallback, saved assembly or an earlier
executable cannot substitute for a new LTO link.

This is a transport and build contract, not a final-root preservation checker.
It does not assert that any implementation or qualification run has passed.

## Seed Admission

The caller supplies independent SHA-256 values for native `results.json` and
`artifacts.json`. Authenticate both complete buffers before loading captured
parser/helper code, creating build outputs or executing tools. Require the
manifest's receipt binding, exact artifact membership and every declared hash;
authenticate manifest-bound input records from the same buffers. Duplicate JSON
keys, missing/foreign artifacts, conflicting bindings and unsafe paths reject.

Admission requires the exact CM3 cohort, ordinary O2 mode, native producer scope,
successful producer closure and the fixed nine-source group. The seed's
captured inventory, source-provider identities, target flags, literal defines,
configuration recipes, dependencies and compiler baseline remain authority.
Hashes or target attributes alone are not source or CPU proof.

Use captured source/configuration bytes, not an unbound current checkout.
Historical seed originals are provenance records; do not silently replace
captured bytes with newer originals or claim qualification of a later tree.
Any live tools used by the new build must match their admitted captured hashes.
Close all admitted seed files and newly used inputs at completion.

Fresh external output must not overlap the repository, seed, captures,
inventory, tool/configuration inputs or their protected source trees. Reject
physical aliases, reparse/symlink escapes and hard-link self-comparison.
Pre-output admission failures create no output; later failures retain a
non-promoting failure receipt and available diagnostic artifacts.

## Exact Source Group

Preserve the native producer's fixed order and source identities:

1. `context/context_core.c`.
2. `context/context_runtime_state.c`.
3. `context/context_panic.c`.
4. `fiber/port/ARM_CM3/fiber_port.c`.
5. `fiber/port/ARM_CM3/fiber_port_boot.c`.
6. `fiber/port/ARM_CM3/fiber_port_exception.c`.
7. `fiber/port/fiber_port_context_cohort_expectation.c`.
8. `tools/fixtures/classic_final_image/application.c`.
9. `tools/fixtures/classic_final_image/startup.S`.

Compile the same eight C TUs as slim LTO IR and the one startup assembly TU as
native code. Preserve the admitted target/configuration flags and include
providers; only the explicit LTO transport recipe may change code-generation
options. Dependency discovery and actual compile dependencies must agree.
Each C output must contain LTO IR and no nonempty executable fallback body.
The assembly output is the sole declared non-IR source object.

## Genuine Links And Retention

Both final links use the same frozen, ordered eight IR objects and one assembly
object. Run them in distinct fresh link directories with distinct output/map/
temporary names. One link is ordinary; the other adds `-Wl,--emit-relocs`.
Both must independently invoke LTO, not relink retained machine output in place
of the original IR inputs. Do not use an archive or whole-archive extraction.

The fixed link recipe includes the admitted CM3 target flags and:

```text
-O2 -flto -flto-partition=one -save-temps=obj -v -nostdlib
-Wl,-plugin-opt=-save-temps
-Wl,--gc-sections,--no-undefined,--fatal-warnings,--build-id=none,-z,noexecstack
-T <captured-link-script> -Wl,-Map=<this-link-map>
<eight-frozen-IR-objects> <one-frozen-startup-object> -o <this-final-ELF>
```

Preserve the seed's actual object order rather than regrouping by file suffix.
The single-partition option is an explicit pilot recipe fact, not default LTO
coverage or preservation of the original TU partitioning. C compilation must
enable LTO at O2; reject counterflags, fat/native fallback and target overrides.

Driver `-save-temps=obj` alone is not a guarantee that the linker plugin retains
its machine outputs. Both links must also use exactly
`-Wl,-plugin-opt=-save-temps`. This sets the plugin's own retention state;
the wrapper's handling of driver `-save-temps=obj` is separate. In GCC 14.3,
the plugin's environment check recognizes plain driver `-save-temps`, not the
`=obj` spelling, while its explicit plugin option enables retention during
cleanup. Do not reconstruct a deleted object by assembling saved `.s`, replaying
LTRANS, rewriting ELF bytes or substituting an ordinary O2 object. Missing
machine output is a feasibility failure.

GCC's plugin and wrapper implement separate temporary-file handling:

- https://github.com/gcc-mirror/gcc/blob/releases/gcc-14.3.0/lto-plugin/lto-plugin.c
- https://github.com/gcc-mirror/gcc/blob/releases/gcc-14.3.0/gcc/lto-wrapper.cc

The plugin option, retention cleanup and driver-option check are at lines 1327,
863 and 1517 respectively in the GCC 14.3.0 plugin source above.

Those sources explain retention mechanics, not qualification of the admitted
ST compiler binary. Capture the queried plugin/wrapper paths and hashes, the
actual verbose link command/output and all response files. A `-###` prediction
is supplementary evidence, not an executed link. Reject plugin bypass through
`-nop`, `-ltrans-objects=`, disabled LTO/plugin use or a foreign plugin/worker.
The fixed generated argv excludes these bypass options; no caller-provided
worker options are accepted. The verbose trace check authenticates observed
tool-path membership. Worker/response argument bytes are retained, not parsed
as a complete semantic plugin-execution graph in this capture-only probe.

## Unqualified Layout Sketch

The parent-reported native two-link sketch on 2026-11-05 distinguishes these
attempts; neither is a qualified producer receipt:

- E1 used driver `-save-temps=obj` without the explicit plugin-retention option.
  The plugin deleted `*.ltrans0.ltrans.o`. E1 does not satisfy the retained
  machine-owner requirement and must not be promoted to qualification.
- E2 added exactly `-Wl,-plugin-opt=-save-temps` and retained an actual
  post-LTO machine object of 13752 bytes, distinct from the 90230-byte WPA IR
  partition `*.ltrans0.o`. E2 is layout/retention evidence only, not a qualified
  producer or root/protocol/provenance closure result.

In the parent-reported E2 machine symbol inventory, all three native transfer
roots retain global `T` entries, the current-context slot has a local `b` entry,
and the source's weak default `fiber_panic` has become global `T`. These are
post-LTO observations, not unchanged source/IR binding facts, ordinary-reader
admission rules or full post-LTO ABI qualification. Capture both stages without
widening the ordinary reader or changing production attributes to fit the sketch.

These sizes describe the reported sketch, not fixed acceptance constants or a
substitute for structural classification and complete authenticated evidence.
Retain the original attempts and their available diagnostics without relabeling
E1 or treating E2 as satisfaction of this contract.

## Closure And Machine Owners

Retain raw IR inputs, startup object, plugin resolution file, wrapper/WPA/LTRANS
arguments and response files, partition lists, generated assembly, true post-LTO
machine objects, final ELFs, maps and inspection outputs. Capture their exact
membership and hashes, including every file in the private temporary trees.
Windows wrapper-argument filenames may be flattened: capture the actual names,
raw bytes and invocation references rather than guessing, renaming or requiring
a conventional POSIX filename pattern. Include such files in the exact seal.
No guessed suffix, first glob match or map pathname alone authenticates a
machine owner. Parse records as bounded data; do not execute saved commands.

The transport evidence must capture and bind:

1. Captured source/configuration bytes to actual compile commands, dependencies
   and the eight IR-object hashes plus startup-object hash.
2. Those exact IR inputs to the actual plugin/wrapper invocation, resolution
   data, WPA inputs and emitted LTRANS partitions.
3. Each partition to its actual code-generation invocation and retained
   native ELF32 little-endian ARM ET_REL machine object, distinct from IR.
4. Symbol facts for the declared three native roots and declared callee/current
   slot, together with the raw full map and complete post-LTO machine objects,
   separately for both links. This is a capture obligation, not validation of
   machine-to-final definition placement.

The probe does not validate every final definition or establish individual TU
source origin. Unique machine-section/offset/size placement through the map,
original REL addend checks and applied-reference semantics belong to the future
adapter, not this capture/build feasibility result.

Keep GIMPLE/IR source facts separate from post-LTO machine binding. The eight C
inputs retain their compile/source provenance and IR hashes; the startup object
retains its distinct native compile provenance. Plugin resolutions describe
linker-visible IR definitions, not a complete private-function provenance map
or a certificate that source weak/global/local bindings survive code generation.
Independently proving eight slim-IR inputs plus one native startup object, with
no fat fallback, is a separate obligation from inspecting machine symbols.

Record native root, callee and current-slot symbols with actual machine binding,
type, section, value, size and the identity of the artifact each record was read
from. Capturing these facts does not prove their final origin mapping. A local
machine slot or globalized weak source function must be reported as such, not
relabeled to match the seed or silently treated as a qualified ABI adaptation.
Single-partition code generation does not preserve nine-TU ownership: original
source/IR providers and generated machine providers are distinct evidence sets, not a
one-to-one mapping. Merging into one machine object does not prove per-TU
preservation, C-callee semantics or whole-object correctness. Missing, renamed,
coalesced or ambiguous definitions must be disclosed as adapter limitations,
not repaired by permissive alias selection.

The post-LTO objects retain unapplied machine-code relocations for a future
adapter. Applied final relocation metadata cannot recover original REL addends.
This probe captures those authorities but does not validate complete root bodies,
relocation semantics or native/reference mechanisms. Structural comparison of
the two finals' loadable bytes/layout, entry and allocated/vector bytes must
retain raw evidence; equality is not a final-root or execution proof.

Capture the interpreter, compiler, resolved workers, linker/plugin, relevant
DLLs, helpers/parser package, specs and sanitized environment actually used.
Use the maintained contained process runner and await complete process cleanup.
Close source, tool, seed, object and private-temp memberships/hashes after both
links and at final sealing. Scoped input capture is not a transitive host trust
claim. A late change, missing artifact, failure or incomplete child cannot leave
a promoting success receipt; retain failed attempts without relabeling them.
The saved twin-comparison file has its own fixed path, raw hash and receipt
value binding in closing checks before the initial output seal. Changing or
deleting it cannot be legitimized by hashing the modified output into a new
manifest. Late checks repeat that binding after sealing.

## Invocation

The probe's CLI accepts only the fixed native seed and fresh output:

```text
<probe-cli> --native-build <qualified-native-CM3-O2-build>
  --native-receipt-sha256 <independently-qualified-results-sha256>
  --native-artifacts-sha256 <independently-qualified-artifacts-sha256>
  --output-dir <fresh-external-directory>
```

This is an argument contract, not a claim that a named executable or successful
receipt already exists. The producer supplies the admitted compiler and source
inputs; no caller-selected CPU, mode, source list or symbol allowlist is added.

## Nonclaims

A successful transport feasibility receipt establishes captured build/provenance
evidence only. Required-cell/global counters remain typed integer zero, and
global-freeze, final-root/final-parity, complete-object, CPU/board, reference
comparison and archive-qualification claims remain false. It does not qualify
full ABI obligations, general C/kernel semantics, mechanisms, exception routing,
MMIO, Os-lto, other cohorts, default-partition LTO or hosted exact-SHA CI.

The ordinary `classic_final_image/elf.py` and existing ordinary readers remain
unchanged. Any future LTO evidence adapter is separate and requires independent
root/protocol, original-addend, applied-reference and ownership controls. No
production runtime/assembly, public/port ABI, feature admission or default matrix
change follows from this probe. Protected unrelated WIP is outside its scope.
