# A32 Data Reachability Regression

## Preserved Diagnostic

This fixture records a confirmed classifier gap, not a production-port defect or
a new global qualification receipt. No shared runner, source or selector is
changed. It has no runtime/exception/MPU execution claim.

Compile `interior_callback.c` for Cortex-M33 soft-float with `-O2`,
`-ffreestanding -ffunction-sections -fdata-sections -finstrument-functions`,
including the repository's `fiber` directory. No counterflags are required.
The canonical sensitive roots themselves remain uninstrumented; the deliberately
ordinary helper has real entry/exit hooks.

Feed the actual native object and `objdump -drwC` output to the maintained
`inspect()` with `common=True`, root `readiness_indirect_root`, and a fixture-only
cold set containing `readiness_ordinary_helper`. That cold set models an exact
ordinary common API which must become protected when reached from a hot root;
it is not a proposed production exemption.

- Padding zero: the callback literal addresses the initialized object's start.
  The helper is reached and instrumentation is rejected.
- Padding 1024 words: the callback literal contains the section-relative addend
  `0x1000`, addressing the pointer field inside the initialized 4100-byte object.
  GCC emits a genuine `R_ARM_ABS32` section relocation. The diagnostic resolver
  returns no object target because it only matches exact symbol starts. The
  helper is omitted from reachability and `defects=[]` is a false negative.
- The direct root rejects the same helper at either padding value, independently
  showing that the helper's instrumentation and hook classifier are active.

The boundary is `Elf.targets()` in
`tools/fixtures/sensitive_port_closure/run.py`: ABS32 section-symbol data targets
need containing-object extent handling, or a fail-closed unresolved-data result.
Function targets must retain their distinct Thumb/address semantics. Preserve
the existing exact cold API/counter policy rather than widening its allowlist.
After a repair, both indirect variants must reject the ordinary helper; keeping
only the current zero-offset callback control is insufficient.

The actual selected-port source groups are all-root protected. This gap concerns
the common sensitive-to-cold transitive proof; no current production interior
callback path has been demonstrated. Existing bounded profile receipts are not
relabelled, but they do not establish this missing case.

## Diagnostic Evidence

`%TEMP%/fiber-closure-readiness-interior-ehe16b_5/results.json` remains **FAIL**:
six interior-offset false negatives at O2/Os, each in normal, genuinely lowered
sectioned LTO and unsectioned LTO. All six zero-offset variants reject, as do
the twelve direct-call activity controls. Source/inspector/tool hashes are
recorded before/after with no drift; the diagnostic is not a PASS gate.
Receipt SHA256:
`ACC34F5FAE75D55F4F260AC9EAAAC1C2C87E40FA58298D28B30D8A3E61B97599`.

The diagnostic records the original C fixture hash but did not contemporaneously
archive its bytes; the current fixture is the maintained extended version below.
The original classifier bytes do survive in the earlier immutable capture
`%TEMP%/fiber-sensitive-port-closure-c119d2f8e42441af96ec4d16ca3ba1cf/immutable-inputs/repo/tools/fixtures/sensitive_port_closure/run.py`,
SHA256 `C4E1B1210B68D5F1C25560AC023014E336AC90746E6F4F538773962818B06562`.
Do not infer a complete original source archive from the diagnostic receipt.
The maintained repair has its own captured inputs and same-object causal controls.

At the diagnostic checkpoint the fixture was the only new C source; production
and shared proof scripts were unchanged. The diagnostic used instrumentation only, to
isolate the missing graph edge; the maintained combined raw families still
need replay after an approved resolver/control repair.

## Maintained Repair

`test_sensitive_data_reachability.ps1` compiles this fixture with both ordinary
and canonically protected helper bodies. At O2/Os, normal and genuinely lowered
native LTO (sectioned/unsectioned text), both zero-offset and 4096-byte interior
callback fields must reach the actual helper. Protected bodies produce no
defects; ordinary bodies must expose that helper's instrumentation. Twenty-four
native objects therefore supply 48 exact root checks. Six classifier mutations
remove only containing-object resolution and must reproduce the old missing
indirect edge on the same actual objects. Function entries retain exact
Thumb-normalized matching; data extents are not Thumb-normalized.

The final focused receipt passes with zero input drift:
`%TEMP%/sensitive-data-reachability-41cc515fe95e45d58e53145fb0de6b19`.
`results.json` SHA256:
`40E35DCB84267F9DAB6F356765561B1BE30B5BE3074689EC215BF3B683C92C04`.
Parent independently verifies 199 entries across the three recorded manifests.
The central matrix invokes this regression before full reference parity.

A separate immutable current-resolver C5TF/CM7 replay passes 24 baseline/raw
cells and 120 controls at O2/Os with both native-LTO text layouts. Parent verifies
72 consumed inputs and 3,186 artifacts without mismatch. Its receipt is
`%TEMP%/fiber-data-resolver-closure-9358a0d892dc4a299a613870aa6a2de8`,
SHA256 `8B6EB9667BB0C2443C715C552107A110950DAD5C0FDE154E264DFB6CA4160674`.

This closes the demonstrated ABS32 containing-object case, not every relocation
form, dynamic function-pointer origin, whole-program equivalence, production
path execution or the global A32 inventory. The original FAIL remains FAIL.
