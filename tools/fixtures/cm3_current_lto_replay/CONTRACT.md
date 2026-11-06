# Current CM3 Os-LTO Replay

## Scope

This additive frontend admits current-E9 native and pinned-reference Os-lto
direct captures for the fixed CM3 p4/b16 soft-float cohort. It reuses unchanged
machine-to-final readers, canonical protocol predicates, actual mutation
catalogs and six-body mechanism composition. It does not rebuild a producer,
execute a target or turn capture PASS into root proof by relabeling a receipt.
This contract reports no measured successful replay.

O2-lto uses the existing parameterized root/protocol witnesses separately; this
adapter accepts Os-lto only. No mode, symbol, instruction or recipe allowlist is
caller-configurable.

## API And Inputs

The runner calls:

```python
Witness = witness_type(legacy, capture, extra_sources=authenticated_sources)
witness = Witness(args)
passed = witness.run()
```

`legacy` is the pinned `cm3_os_lto_join/witness.py` module. The returned class
inherits `legacy.Witness` and replaces only its constructor. `capture` is the
runner-authenticated current capture module. `extra_sources` is a copied mapping
of canonical paths to immutable, independently authenticated bytes, including
the runner, this adapter and contract, current capture module and legacy
witness. The constructor rechecks those bytes in its real physical closure;
the caller remains responsible for binding executed bootstrap buffers to pins.
The adapter does not inspect `__main__`, patch helper globals or rewrite sources.

Exactly ten named CLI arguments supply evidence descriptors and fresh output:

```text
--native-build PATH
--native-receipt-sha256 SHA256
--native-artifacts-sha256 SHA256
--reference-build PATH
--reference-receipt-sha256 SHA256
--reference-artifacts-sha256 SHA256
--inventory PATH
--inventory-receipt-sha256 SHA256
--inventory-artifacts-sha256 SHA256
--output-dir FRESH_PATH
```

The runner uses fresh unoptimized `python -I -S -B`, without inherited
`elftools`. Construction performs no output creation or process execution.
`witness.replay_api` exposes the pinned `freeze_replay.py` module for independent
structured-result checks by the runner.

## Admission

Before parser import or output creation, modern replay admission authenticates
the independently caller-bound inventory and both complete capture trees.
`Admission.snapshot(current=True)` recomputes the full current manifest/registry
plan. Source fingerprint is fixed to:

```text
69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313
```

All 2,774 keys and the inventory backlog remain inventory authority, not replay
credit. Reachable Seed/capture inventory facts must agree with this independent
snapshot. Both records must pass current `require_capture(..., sealed=True)`
for their exact side and Os route, plus literal SeedMode O2, exact SeedSide and
the sole O2-to-Os optimization transform. CaptureProducer must bind the same
current module bytes authenticated by the runner and enrolled in the closure.
There is no fixed historical reference Seed path or E8 authority substitution.

Each captured ordinary Seed descriptor is re-admitted through current
`capture.prepare()`, preserving all inherited native/reference validators and
pin/blob checks. The constructor does not call the old Os constructor.
CurrentInventory and SeedAuthority metadata must agree with these independent
descriptors. Captured Files require unique Original providers; no input catalog
deduplication or historical receipt repair occurs in replay.

The instance combines the native Seed closure with modern outer admission,
merges the reference closure, both full capture catalogs and all Seed source
buffers, and retains legacy membership plus modern hash/physical/tree closing.
Both groups retain the legacy keys used by unchanged methods, including their
own Seed, parser package, actual roles, capture hashes and captured master
ledger. Master ledger bytes and inventory must agree across sides.

## Unchanged Replay Authority

The inherited `_buffer`, `_tree`, `_roles`, `_commands`, `_physical`, `_read`,
`_seal`, `close` and `run` are not replaced. Fixed helpers use the old Os
`FIXED` pins. Its authenticated Os recipe helper remains the authority for full
57/37-command reconstruction, actual dependencies, slim IR and link records;
it is not confused with the current capture producer identity.

Seven actual binary roles per side are physically distinct across all fourteen
roles. Each root uses its own actual saved machine, startup, final ELF,
disassembly and map, with full REL/addend/origin and byte preservation checks.
Canonical views use each actual machine and machine disassembly. Ordinary
twins receive structural load comparison, not an independent emitted-REL root
proof. Raw transport records keep their own canonical-proof false markers.

The unchanged composition checks six complete roots and three mechanisms,
zero tail NOPs, captured master-ledger rationales and the separately pinned
policy supplement. Its fixed catalogs execute 16 transport controls and one
coherent SVC canonical control per side. No prior control count substitutes for
fresh private controls. Complete copies, immutable reads, expected membership,
intended-byte receipt sealing and late closing remain inherited requirements.

Only the exact Seed-authenticated external nonexecuted Git provenance binary
may retain its recorded multiple-link identity. Semantic roles and output
files keep the inherited single-link guard. Real physical closing runs outside
the reader's immutable-buffer scope. Output is fresh and disjoint in both
directions from the repository and all admitted inputs, tools and evidence.

## Reporting Boundary

The old Os Scope, Mode and pass-status vocabulary remain unchanged. Current
inventory, producer and bootstrap-source metadata are additive. ProducerBindings
are generated by the inherited replay using the selected captures. Root and
canonical flags may become true only after complete fresh replay and closing;
failure clears those flags through the inherited failure path.

Full ABI, full semantic ABI, source-to-IR/machine semantics, whole-object proof,
policy equivalence, whole-cell/reference qualification, archive, hosted CI,
CPU/board and global qualification remain unproved. RequiredCellSatisfied is
false and RequiredCellsSatisfied is literal integer zero. This gate does not
credit any of the 2,774 inventory cells.
