# Executing Freeze Replay Dispatcher

## Interface

The implementation belongs to `tools/freeze_replay.py`. This contract fixes its
first interface; it records no implementation, execution or measured PASS.
Existing proof gates remain authoritative. The dispatcher executes them against
retained inputs, checks their receipts and closes evidence; it does not implement
ELF decoding, transport, canonical protocols or a new equivalence checker.

```text
python tools/freeze_replay.py --inventory CURRENT --inventory-receipt-sha256 HASH --inventory-artifacts-sha256 HASH --catalog CATALOG.json --catalog-sha256 HASH --output-dir FRESH
```

All six options are required. There is no caller-selected Python, executable,
module, command, argv, source pin or gate path. Archive support is limited to
the single frozen route below. No compiler, linker, emulator or target is run.

The catalog is ASCII JSON with exactly this shape and case-sensitive keys:

```json
{
  "SchemaVersion": 1,
  "Selections": [
    {
      "Route": "CM3/O2-lto/archive",
      "Inventory": {"Build": "C:/historical-inventory", "ReceiptSha256": "HASH", "ArtifactsSha256": "HASH"},
      "Native": {"Build": "C:/native-capture", "ReceiptSha256": "HASH", "ArtifactsSha256": "HASH"},
      "Reference": {"Build": "C:/reference-capture", "ReceiptSha256": "HASH", "ArtifactsSha256": "HASH"},
      "PriorJoin": {"Build": "C:/retained-join", "ReceiptSha256": "HASH", "ArtifactsSha256": "HASH"}
    }
  ]
}
```

`HASH` denotes exactly 64 uppercase hexadecimal characters, not a literal
accepted value. `Build` is an absolute directory path. Every descriptor has
exactly those three keys. Selections are nonempty, ordered and unique by Route.
Unknown fields, duplicate/case-aliased JSON keys and unknown routes reject.
Inventory identifies the selected evidence's historical source snapshot;
the CLI inventory identifies the current canonical plan. Neither overwrites
the other. PriorJoin is an authenticated baseline, never sufficient proof.

## Closed Routes

Ordinary modes are exactly `O0`, `Og`, `O2`, `Os`, `O3`. The following expansions
are all 33 routes; spelling and case are exact.

| Route IDs | Existing gate | Fixed cohort facts |
|---|---|---|
| `CM0/<ordinary-mode>/direct` | `tools/fixtures/cm0_final_join/join.py` | cortex-m0, soft/no-FP, VTOR0, MPU0, p2/b0 |
| `CM0PLUS/<ordinary-mode>/direct` | same CM0 gate | cortex-m0plus, soft/no-FP, VTOR0, MPU0, p2/b0 |
| `CM0PLUSVTOR/<ordinary-mode>/direct` | same CM0 gate | cortex-m0plus, soft/no-FP, VTOR1, MPU0, p2/b0 |
| `CM4/<ordinary-mode>/direct` | `tools/fixtures/classic_final_join/join.py` | cortex-m4, hard/eager, MPU0, p4/b16 |
| `CM7/<ordinary-mode>/direct` | same classic gate | cortex-m7/r0p1, hard/eager, MPU0, p4/b16 |
| `CM3/<ordinary-mode>/direct` | `tools/fixtures/cm3_final_join/join.py` | cortex-m3, soft/no-FP, MPU0, p4/b16 |
| `CM3/O2-lto/direct` | `tools/fixtures/cm3_lto_join/witness.py` | same fixed CM3 cohort |
| `CM3/Os-lto/direct` | `tools/fixtures/cm3_os_lto_join/witness.py` | same fixed CM3 cohort |
| `CM3/O2-lto/archive` | `tools/fixtures/cm3_lto_archive_join/witness.py` | same fixed CM3 cohort |

Exact cohort IDs are the six `PROFILES` identities in the frozen
`classic_final_image/run.py`, not inferred from CPU labels or a default p4 row.
The archive gate pin is
`FFD12847C2362F4145F5F1693A7AAFD9FEAC0D30FAA2CC1AF8FF35F179753C4E`.
All other gate/helper pins are fixed implementation constants, not catalog data.

Each child receives the existing flags `--native-build`,
`--native-receipt-sha256`, `--native-artifacts-sha256`, `--reference-build`,
`--reference-receipt-sha256`, `--reference-artifacts-sha256`, `--output-dir`.
Only ordinary routes additionally receive `--profile` and `--mode`. For O2-lto
direct, Native/Reference identify the prior independent protocol envelopes;
for Os-lto direct and O2-lto archive they identify actual producer captures.

## Public Python API For Pure Controls

- `Rejected(ValueError)`: admission failure.
- `routes()`: fresh dictionary keyed by the 33 Route strings; values contain
  `Profile`, `Mode`, `Linkage`, `Cohort`, `SourceGroup`, `ArtifactRole`, `Gate`.
- `route_for(route_id)`: fresh route dictionary, or Rejected; no I/O.
- `validate_catalog(value)`: validate the exact structure above and return a
  fresh ordered selection list; no filesystem reads, imports or execution.
- `gate_arguments(route_id, selection, output)`: return only the fixed gate CLI
  argument list, excluding interpreter/bootstrap/entry point; no execution.
- `scope_report()`: fresh FAIL-default report with all broader claims false,
  required/global credit literal integer zero and no verified components.
- `process_environment(environ)`: return an explicit sanitized allowlist;
  reject injection variables and case-aliased environment keys.
- `prepare(args)`: authenticate inputs and admit output without creating it;
  return a Dispatcher. `Dispatcher.run()` creates output and executes gates.
- `Dispatcher.command(argv, label, timeout=1200)`: record ATTEMPT before the
  managed runner and terminal streams/status afterward, including exceptions.
- `Dispatcher.finish(error=None)`: close and seal; an uncompleted/empty runner
  cannot PASS. `main(argv=None)` implements the CLI above.

Tests may stub the managed runner. Importing the dispatcher must not launch a
process, create output, import catalog-selected code or execute a gate.

## Admission, Evidence And Credit

Before mkdir, authenticate the catalog/current inventory and every selected
historical inventory, producer/protocol pair and prior join receipt/manifest
from the exact buffers parsed. Close complete artifact memberships and input
bindings, reject physical role aliases, and deny output overlap with repository,
evidence, original source and tool roots. Preserve old receipts unchanged.

Execute fixed authenticated source buffers using the existing frozen loader,
actual Windows GetModuleFileNameW interpreter, isolated Python, sanitized
environment and unchanged `freeze_cohorts/process_runner.py`. Record command
ATTEMPT first; retain terminal stdout/stderr, timeout and cleanup diagnostics.
Require fresh structured evidence, exact route/source/input bindings, complete
artifact/input closure and successful gates, not exit zero or PASS text alone.

Emit the authenticated current `plan()` with all 2774 canonical keys retained,
the complete backlog, verified component references and an explicit missing-work
queue. Historical snapshot IDs remain separate even when cohort IDs coincide.
An E8 replay is not current E9 proof. CM0 has eight closed bodies, not six.
O2-lto direct authenticates prior controls without rerunning them; Os-lto and
archive run their existing fresh 32 transport plus two canonical controls.

Root transport, canonical mechanisms, twin equality and negative-control
components retain their individual scopes and execution provenance. None alone
satisfies a required cell or proves full API/ABI, source/IR semantics, runtime,
CPU/hardware, CI or global freeze. RequiredCellSatisfied, FullABIProof,
APIProof and GlobalFreezeQualified remain false; RequiredCellsSatisfied is the
literal integer zero. Missing and unsupported work is never relabeled PASS.

Seal against intended receipt bytes and exact output membership through late
closing checks. Any execution/closing/sealing failure remains FAIL, preserving
available command/evidence files and a consistent readable failure manifest.
