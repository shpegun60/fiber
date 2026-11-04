# Captured CM3 Mechanism Comparison

This fixture compares three complete naked-function roots from two closed
compile preflights. It does not compile firmware, execute a CPU or qualify the
full Context/Fiber runtime. A matching subsequence is not a passing body.

```text
python tools/freeze_cm3_mechanisms.py --inventory INVENTORY_RECEIPT --native NATIVE_RECEIPT --reference REFERENCE_RECEIPT --output-dir FRESH_EXTERNAL
```

The deliberately bounded cohort is
`cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default`, runtime role only.
All five ordinary modes O0/Og/O2/Os/O3 are required. Other NVIC thresholds,
fixed-R9, MPU, final executables, direct/archive extraction and LTO are separate
obligations; they cannot be inferred from this cohort's mechanism checks.

| Mechanism | Fiber | Pinned FreeRTOS |
| --- | --- | --- |
| First request | `fiber_port_start_first_context` | `prvPortStartFirstTask` |
| First restore | `SVC_Handler` | `vPortSVCHandler` |
| Save/schedule/restore | `PendSV_Handler` | `xPortPendSVHandler` |

The driver requires closed artifact membership and hashes, the same captured
inventory fingerprint and exact context identity, complete cell inventories,
and native ET_REL object/disassembly bindings. Compiler input captures are
fingerprinted and source bytes are tied back to the inventory. It executes
captured checker/decoder bytes and rejects closing reader, input or output
drift. Receipts describe captured inputs, not the current working tree or an
authenticated third-party build attestation.

The opt-in literal-island representation records data bytes, offsets,
references and relocation identities in the complete body and retains every
NOP. It makes no claim that a decoder can prove SVC never returns. That
startup obligation belongs to the paired first-restore protocol and later
runtime/ELF tests. Existing decoder callers keep the original strict behavior.

The retained adaptations use the existing rationale ledger in
`FREERTOS_ASM_PARITY.md`: explicit MSP/CONTROL preparation and SVC 70 versus
the upstream VTOR reload/SVC 0; stronger exception/frame provenance; exact
per-context EXC_RETURN rather than reconstructed/handler-held LR; preserved
scheduler mask state; common-owned scheduler selection/publication rather than
`pxCurrentTCB`; and explicit local literal pools. These are reviewed differences,
not byte equivalence or an implicit claim that the whole FreeRTOS kernel ran.

Every result keeps `RequiredCellSatisfied=false`, `FinalElfProof=false` and
`GlobalFreezeQualified=false`. Constructor semantics, C validation/helper
closure, forward/reverse ABI, final vectors/cohort negative links, CPU execution
and hardware remain independent gates. A partial checker or a compile-only
receipt cannot satisfy the global inventory accountant.

## Controls

```text
python -B tools/fixtures/cm3_freeze_parity/test_contract.py
python -B tools/fixtures/cm3_freeze_parity/test_protocols.py
python -B tools/fixtures/cm3_freeze_parity/test_check.py --temp-root FRESH_TEMP_DIRECTORY --native-root NATIVE_RECEIPT --reference-root REFERENCE_RECEIPT
```

`test_contract.py` exercises synthetic receipt/join/scope guards. The exhaustive
token mutations and synthetic decoder states in `test_protocols.py` are pure
controls, not real-ELF or CPU evidence. `test_check.py` separately reads the
five recorded CM3 object pairs, verifies consumed file hashes and mutates only
private TEMP copies of the O0 native ELF/disassembly. No compiler, objdump or
CPU is invoked. Changed reference literals, branches, tail instructions,
relocations, call addends and inconsistent disassembly must reject with their
specific diagnostic. The fresh test output directory must be inside TEMP.
Keep the input receipts immutable; failed controls never qualify the backend.
