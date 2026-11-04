# Classic-FP Final Mechanism Join

## Scope

This opt-in, read-only gate joins completed native and pinned-reference
final-image builds for exactly CM4 or CM7/r0p1, hard FP, eager native FP,
VTOR1, no MPU, p4/b16, ordinary AAPCS and O0/Og/O2/Os/O3. Both build
receipts must select the same exact cohort and mode. Reference FP setup
retains upstream lazy ASPEN+LSPEN policy; an eager native inventory label
does not change that source behavior.

The join executes no compiler, linker or target image. It does not build
a scheduler, synthesize successful kernel callbacks or select replacement
objects from older mechanism-only receipts. Inputs are the actual final
build groups and their expected receipt and artifact-manifest hashes, with
fresh external output. Both receipts/manifests are authenticated before
any captured parser code is imported. Parser bytes bind the authenticated
native manifest; a self-resealed manifest alone is not authority.

## Admission And Closure

Native and reference producers must have their exact successful verdicts,
source selections and target facts. Native has nine actual TUs; reference
has four. Each has two identical-object ordinary/emit-relocs final links,
seven ordered object checkpoints, actual verified compile dependencies
and complete artifact/input/generated-input closure. All required counters
remain typed integer zero and all execution/global/policy promotion flags
remain false. Missing or empty closure records are not proof.

The reference pin is
`a50edad08b29052631aa469d4df6e6ec7ff68878`. Port, portmacro, config,
upstream defines, compiler target/FPU facts and captured source inventory
must agree. CM7 includes the exact errata metadata definition while CM4
does not. This metadata does not make the pinned r0p1 CPSID/CPSIE sequence
conditional. Same-path or physical aliases between distinct ELF roles
are forbidden; the intentional prelink/provider overlap is retained.

Original and captured inputs, objects, maps, readers and retained helper
bytes are bound before use and checked again at close. Complete artifact
membership must still agree; late additions, modifications or deletions
fail. The immutable captured inventory ledger supplies transfer difference
rationales. `POLICY_DIFFERENCES.md` supplies the explicit FP setup policy
rationale added after that inventory; its captured hash is separate.
Mutable current global documentation is not substituted for either.

## Mechanism Composition

The existing independent six-body `check_pair()` operates on the final
builds' own native index-3 and reference index-0 prelink objects and their
disassembly. Exactly one post-island tail NOP per root is required for O0;
the other four modes require zero. Mode labels alone cannot prove this,
and identical Og/O2 instruction bytes cannot prove their compiler flags.

Both final readers independently replay all three complete transfer roots
with original REL addends, applied fields, provider/map origins, data
mappings and exact instruction protocols. Each build's ordinary and
emit-relocs loader images must agree. Native and reference load images
are deliberately not required to agree with one another.

| Mechanism | Native Root | Reference Root | Difference IDs |
| --- | --- | --- | --- |
| first-start | `fiber_port_start_first_context` | `prvPortStartFirstTask` | `FAP-COMMON-START`, `FAP-COMMON-PROVENANCE` |
| first-restore | `SVC_Handler` | `vPortSVCHandler` | `FAP-COMMON-PROVENANCE`, `FAP-COMMON-MASK-RESTORE`, `FAP-FP-VALIDATION` |
| PendSV-FP | `PendSV_Handler` | `xPortPendSVHandler` | `FAP-COMMON-SCHEDULER`, `FAP-COMMON-PROVENANCE`, `FAP-COMMON-MASK-RESTORE`, `FAP-FP-VALIDATION` |

CM7 adds `FAP-CM7-ERRATA-PRIMASK` to first-restore and PendSV-FP. The
exact IDs and assignments are required, not a caller-defined allowlist.
`FAP-FP-SETUP-POLICY` remains explicit and unresolved by these roots.

Checker body hashes describe canonical instruction-token JSON; final-reader
body hashes describe raw final bytes. They must remain separate. Their
different values are not a mismatch to normalize away.

## Non-Claims

Success means six complete emitted bodies joined into three documented
mechanisms, with final-image preservation on each side. It is not semantic
equivalence of different algorithms, successful MMIO or exception routing,
constructor/C-callee/kernel closure, complete-object parity, other cohorts,
archive/final-LTO, CPU/board or global freeze qualification. This bounded
gate alone satisfies zero required global parity keys. No production
runtime, ABI, default build settings or hardware state is changed.

Recorded PASS counts and exact receipts belong in the audit only after an
actual complete run; pure synthetic controls do not qualify real images.

## Invocation

Use a fresh unoptimized Python interpreter. The parser is selected from the
authenticated native build's captured `python/elftools` package, not an
ambient installation with a matching version string.

```text
python -B tools/fixtures/classic_final_join/join.py \
  --native-build <completed-native-build> \
  --native-receipt-sha256 <native-results-sha256> \
  --native-artifacts-sha256 <native-artifacts-sha256> \
  --reference-build <completed-pinned-reference-build> \
  --reference-receipt-sha256 <reference-results-sha256> \
  --reference-artifacts-sha256 <reference-artifacts-sha256> \
  --profile CM4 --mode O2 --output-dir <fresh-external-output>
```

Expected hashes must come from separately qualified producer evidence, not
be recalculated from a suspect build merely to bypass admission. Import
authentication does not make arbitrary Python already running in a reused
interpreter trustworthy. The command above starts a separate interpreter.

The output records protocol-token hashes and raw final-root hashes in
separate structures. Its retained input copies, report and artifact manifest
are closed as an exact path/hash set. A late write/closure error returns
failure and replaces a tentative PASS with FAIL where storage is writable.
The parent still must check the exit code and intended failure reason.
