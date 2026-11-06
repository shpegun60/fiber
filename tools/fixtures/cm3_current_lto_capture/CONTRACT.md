# Current CM3 LTO Capture

## Scope And Status

This is a maintained capture frontend, not a final-root or whole-cell gate.
Its four closed routes are native/reference crossed with O2-lto/Os-lto,
direct linkage only. The target is the fixed CM3 p4/b16, soft-float, no-FPU,
MPU-disabled cohort. Both sides start from independently authenticated ordinary
CM3/O2 seeds; no historical result is relabeled as current evidence.
The reference remains pinned to
`a50edad08b29052631aa469d4df6e6ec7ff68878`.

The parameterized reference constructor and local command implementation are
reviewed and source-pinned. This contract does not report a measured successful
capture; reviewed source and matching pins alone do not qualify an actual run.

## CLI And Admission

Run `capture.py` in a fresh unoptimized `python -I -S -B` process, without an
inherited `elftools` module. Exactly nine named arguments are required:

```text
--side native|reference
--mode O2-lto|Os-lto
--seed-build PATH
--seed-receipt-sha256 SHA256
--seed-artifacts-sha256 SHA256
--inventory PATH
--inventory-receipt-sha256 SHA256
--inventory-artifacts-sha256 SHA256
--output-dir FRESH_PATH
```

The hash-bound `freeze_replay.py` admission authenticates the inventory receipt,
manifest and complete captured tree before constructing a seed. Its unchanged
`Admission.snapshot(current=True)` recomputes the canonical plan and compares
current manifest and registry facts. The admitted inventory must be current E9,
with source fingerprint:

```text
69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313
```

All 2,774 canonical keys and 26 backlog records remain inventory authority;
the capture count is not a coverage projection or satisfied-cell count.
Canonical fingerprints are not interchangeable with raw artifact hashes.

The seed receipt and artifact manifest are independently caller-bound. Its
reachable inventory facts, embedded inventory receipt/manifest hashes and
exact cohort must agree with the separately admitted E9 snapshot. Original,
Captured and generated input bindings, complete membership and source/tool
checks remain mandatory. Historical E8 input or current Original-byte drift
must reject; there is no virtual source overlay.

Output creation follows all admission and closing checks. Output must be fresh
and disjoint in both directions from admitted evidence, repository, checkout,
source, generated-input, helper, inventory, compiler and interpreter roots.

## Reused Admission And Plumbing

Native admission reuses the pinned F2D4 native `Seed`. Reference admission is a
local subclass of the pinned 27C192 legacy `Seed`: only its constructor is
copied to replace fixed historical path/hash authority with caller descriptors.
All inherited validators and their defining globals remain unchanged:
scope, inventory, commands, reference pin/blobs, recipe, sources, links and
prelink evidence. Typed fail-stop providers do not become a kernel runtime.

Pinned modules execute the exact authenticated source buffers. No outer frozen
spec-loader remains active around seed construction. The existing inner source
loaders and captured parser retain their authority; no helper globals, source
text or fixed protocol models are patched.

Bootstrap helpers require fixed buffer pins before their first use:

| Helper Under `tools/fixtures/` | SHA-256 |
| --- | --- |
| `cm3_final_roots/reference_witness.py` | `AED0DBAC11EB8644EED71F9FAF36C67B2854DE19262A78CC7EA601FA7A3DD99C` |
| `classic_final_join/join.py` | `2785F72E5F86257A403141EB856BB8D49F0A9A6CF4D005CC858D8D2B60EBF013` |

The native constructor's exact bootstrap-loader path may read its already
authenticated buffer through a temporary `Path.read_bytes` hook. This is not
another spec-loader or permission to substitute unrelated reads. Restore the
hook before real physical closing and output creation. Later twin-helper loads
must match the already watched pin before code execution, not learn a hash from
the then-live helper. The local command helper also requires pinned same-buffer
loading and inclusion in captured source/input closure before use.

An instance-only combined closure preserves legacy hash/membership checks and
modern hash/physical-identity/tree checks. Structured reads parse the checked
buffer. Both authorities receive the admitted paths before `Probe.prepare()`,
so initial input copies include the frontend, helpers and independent inventory.
Both closing checks remain active for subsequently enrolled paths. A real
combined close outside the bootstrap read hook is required before output exists;
buffer-backed reads alone are not filesystem identity or closing evidence.

The inherited preparation clones the admitted toolchain into the fresh output.
A local `verify_tools()` retains the inherited exact tool membership/hash check
and enrolls/rechecks every cloned tool in the combined closure before command
execution. Admission denial roots are fixed before output creation; later
watched output paths do not make the output reject itself. Do not baseline the
entire still-growing output tree as an immutable input tree.

## Actual Capture Requirements

O2-lto uses the unchanged native/reference probe factory. Os-lto uses the pinned
Os factory: the sole O2 optimization flag becomes Os for every TU and link,
including startup. Other admitted compile/link flags and provider order remain
fixed. There are no caller-supplied executables, flags or recipes.

- Native: nine TUs, eight genuine slim C IR inputs and one native startup object.
- Reference: four TUs, three genuine slim C IR inputs and one native startup.
- Each side: two direct links from the same fresh inputs, ordinary and emitted
  relocations, in separate directories, with one actual saved LTRANS machine
  per link. WPA IR or fat-object code is not machine authority.
- Retain actual dependencies, frozen object checks, full link temporary trees,
  maps, resolutions, machine facts, command streams and worker/plugin identities.
- Reuse captured tools, sanitized process environment and hardened process runner.
  A local primary-preserving command wrapper journals ATTEMPT before launch and
  retains terminal state, exit/timeout details and raw stdout/stderr. Failure to
  persist the prelaunch journal must prevent launch. Compiler/process failure
  remains primary if tool closing, cleanup or terminal-journal writes also fail;
  retain those as secondary failures instead of replacing the original cause.
  A secondary fault after exit zero still fails the capture. Never retry the
  process to repair a journal or manufacture a successful command record.
- A complete native run has 57 successful driver commands; reference has 37.
  These include host tool queries and inspections, not target execution.
- Structural twin comparison must succeed with the unchanged, captured parser
  and reader. Retain the comparison bytes and close their hash and contents.

## Closing And Nonclaims

The local seal serializes intended receipt and manifest bytes before writing.
The receipt hash is derived from those intended bytes, not learned from its
written file. Verify exact output membership/content and intended manifest
bytes after writing and again through inherited late closing. Mutable receipt
and manifest files are not enrolled as immutable inputs. Closing/sealing faults
must leave FAIL and zero credit; a sealed FAIL is not capture success.

`Probe.persist_failure_evidence()` makes a best-effort FAIL receipt and matching
manifest when normal finishing or sealing fails. Preserve the primary failure
and retain secondary persistence errors separately. The fallback must keep
`InputClosureVerified` and `OutputSealVerified` false, even if both files can be
written with matching hashes. That consistency is diagnostic evidence, not a
verified input/output seal or permission to promote the failed capture.
Only a fixed finite diagnostic repair may retry FAIL receipt/manifest writes;
it must preserve the primary error and both false verification flags. It must
never retry a process, compile, link or capture stage, or use unbounded recovery.

Legacy `Scope`, compile/link mechanics and finish behavior remain unchanged;
local command recording preserves failure authority without changing recipes.
Additional current-route, inventory and helper metadata identify this frontend
without rewriting a historical scope or receipt. Genuine LTO, built-reference
and twin comparison facts may be true only for their actual bounded observations.

Capture PASS grants no final-root, canonical-protocol, ordinary-owner, source/IR
semantic, full-ABI, native/reference parity, policy-equivalence, archive, CI,
CPU/board or global qualification. `RequiredCellSatisfied` remains false and
`RequiredCellsSatisfied` is literal integer zero. Independent current-source
root/REL/origin and canonical protocol replay, followed by the remaining static
cell obligations, are separate gates; frozen predicates are not relaxed here.
