# CM0-Family Final Mechanism Join

## Fixed Scope

This opt-in gate composes the actual native and pinned-reference final
images for CM0, CM0PLUS and CM0PLUSVTOR at O0/Og/O2/Os/O3. Only p2/b0,
ordinary AAPCS, soft/no-FPU, no-MPU cohorts are admitted. BASEPRI is not
applicable; zero does not mean a masked-interrupt threshold equivalent to
the classic-FP ports. CPU/VTOR identity binds the producer recipes even
where several profiles or modes have identical transfer instructions.

No compiler, linker, objdump, emulator or target is executed. Both producer
receipt and artifact-manifest hashes must come from separately qualified
evidence. All four are authenticated before parser import. Computing new
expected hashes from a suspect archive is not an admission proof.

## Inputs And Ownership

Native has nine actual TUs and one transfer prelink at source index 3.
Reference has five TUs, with its C dispatcher in index 0 (`port.c`) and
four assembly functions in index 1 (`portasm.c`). They remain separate
objects throughout. The fixed `ReferenceOwners` adapter routes only these
five known roots; it neither merges object symbol tables nor changes
their origins. Each same owning object feeds both the complete prelink
protocol checker and the relocation-aware final reader.

All source/dependency, generated-input, resolved worker, tool/DLL, parser
and inventory bindings must be present, not merely individually correct
if supplied. Exact ordered compile/link commands bind CPU/mode, source,
objects, script, map, ordinary/emit-relocs selection and output. Pinned
FreeRTOS source/header bytes and Git blobs allow exact bytes or uniform
whole-file LF-to-CRLF conversion, not mixed-newline normalization.

The native and reference producers must select the same captured source
inventory, cohort and mode. The reference pin is
`a50edad08b29052631aa469d4df6e6ec7ff68878`. Its VTOR0 fixture explicitly
disables the dormant upstream VTOR installation check; VTOR1 retains one.
The inline infinite-loop assertion and fail-stop kernel providers remain
unchanged. A null opaque current-TCB pointer is not a fabricated runtime
kernel. This gate does not execute that provider or its scheduler.

The parser comes from the authenticated native build's captured package.
Shared Watch, input-identity and output-seal helpers remain unchanged;
the exact byte buffer executed for the shared helper is also authenticated
when registered for closure. Original/captured inputs, source memberships
and output artifacts close after replay. Separate output directories,
physical file identities and final ordinary/emit-relocs twins prevent
self-comparison through same-path or hard-link aliases.

## Exact Mechanisms

| Mechanism | Native | Reference | Difference IDs |
| --- | --- | --- | --- |
| first-start | `fiber_port_start_first_context` | `vStartFirstTask` | `FAP-COMMON-START`, `FAP-COMMON-PROVENANCE` |
| first-restore | `SVC_Handler` | `SVC_Handler`, `vPortSVCHandler_C`, `vRestoreContextOfFirstTask` | `FAP-COMMON-PROVENANCE`, `FAP-CM0-STAGED-FRAME` |
| PendSV | `PendSV_Handler` | `PendSV_Handler` | `FAP-COMMON-SCHEDULER`, `FAP-COMMON-PROVENANCE`, `FAP-COMMON-MASK-RESTORE`, `FAP-CM0-STAGED-FRAME` |

The immutable captured ledger must contain every exact assigned rationale.
The native SVC validates/restores the complete staged nine-word software
frame. Reference SVC passes through its real C dispatcher, loads the
initial EXC_RETURN into r2, writes CONTROL=2 and skips initial r4-r11 slots
in its separate first-restore function. Those are different algorithms;
initial register-value equivalence and dynamic exception targets are not
claimed. Native cooperative policy versus upstream kernel/tick machinery
also remains an explicit difference.

The eight complete source-derived prelink protocols retain every branch,
literal descriptor and mode-specific NOP. Both final readers independently
preserve whole owning sections, original REL addends, applied destinations,
provider/map origins, mapping boundaries and out-of-function pools/padding.
Each implementation's two loader images must match; native and reference
images are not required to match each other. Canonical protocol-token hashes
and raw final-byte hashes remain separate evidence.

## Invocation

```text
python -B tools/fixtures/cm0_final_join/join.py \
  --native-build <qualified-native-build> \
  --native-receipt-sha256 <qualified-native-results-sha256> \
  --native-artifacts-sha256 <qualified-native-artifacts-sha256> \
  --reference-build <qualified-reference-build> \
  --reference-receipt-sha256 <qualified-reference-results-sha256> \
  --reference-artifacts-sha256 <qualified-reference-artifacts-sha256> \
  --profile CM0 --mode O2 --output-dir <fresh-external-directory>
```

Use a fresh unoptimized interpreter, not an ambient already-imported parser.
Pure admission, contract and closure controls use their respective
`test_*.py --report <fresh-TEMP-json>` entry points. Their doubles and
in-memory metadata variants do not count as real ELF mutations or cells.
Actual measured counts and failed attempts are recorded separately in the
architecture audit after execution, not predicted here as successful runs.

## Limits

Success is bounded eight-body/three-mechanism final-image composition with
documented differences. It is not semantic equivalence, initial register
equivalence, general C/callee/kernel closure, successful handler/MMIO
execution, routing, stack-value/EXC_RETURN proof, complete objects, other
cohorts, FP/MPU/security, archive/final LTO, CPU/board or global freeze.
Required global counters remain integer zero. Production C/assembly, ABI,
feature/default build settings and hardware state are unchanged. Local
receipts are not hosted exact-commit CI.
