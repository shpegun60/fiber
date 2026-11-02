# Exported Source Identity

The C3SO and C5SO runtime wrappers accept source exports without `.git`.
`identity.ps1` is their shared identity helper and a bounded maintained proof.
It is itself included in each wrapper's input hashes and source manifest.

## Authoritative Bytes

The existing `inputs-before.json`, verified input copies, actual compiler
dependency admission, `inputs-after.json`, and drift failure remain authoritative.
Nothing substitutes a revision string for those checks. The source-only
`source-manifest-before/after.sha256` files select repository-contained rows
from those same input snapshots; external tool, CMSIS and FreeRTOS inputs remain
in the complete input manifests.

Canonical source-manifest bytes are UTF-8 without BOM, with LF line endings:

```text
fiber-source-byte-manifest-v1
<lowercase SHA256><two spaces><case-preserving relative path>
```

Every row ends in LF. Paths use `/`, exclude the absolute export root and are
sorted using ordinal comparison. Duplicate case-insensitive paths, CR/LF in a
path, malformed hashes and empty source sets are rejected. The SHA256 of the
complete canonical bytes is `SourceManifestSHA256Before/After`; it is **not a
Git commit ID**. The companion JSON records the schema, digest and source rows.
`SourceManifestStable` supplements, but does not replace, complete input drift
rejection. This is the declared gate-input census, not every file in an archive.

## Optional Attribution

`RepositoryHEADBefore/After` are optional metadata only. Without a `.git` entry
at the exact source root they are null and Git is not queried for source
attribution. If present, `git rev-parse --show-toplevel` must match that exact
root before `rev-parse --verify HEAD^{commit}` is accepted. An enclosing or
foreign repository, missing/broken metadata, malformed result or unavailable
Git command leaves HEAD null with an explicit metadata status. An accepted HEAD
does not assert a clean checkout or that the compiled bytes equal that commit.
Linked-worktree `.git` files remain supported through Git's exact-root check.

FreeRTOS is a separate external reference repository. Its existing required
exact commit, consumed-file diff and final commit checks are unchanged.

## Bounded Proof

Run with existing tools and emulator; no installation or board access occurs:

```powershell
& tools/fixtures/source_export_identity/identity.ps1 -RunProof `
    -ProofArmGcc <arm-none-eabi-gcc.exe> -ProofCmsisCore <CMSIS-Include> `
    -ProofFreeRtosRoot <pinned-FreeRTOS-repository> `
    -ProofQemuRoot <absolute-WSL-QEMU-root> -ProofBuildRoot <evidence-root>
```

The proof copies the required source/fixture files, verifies their SHA256,
marks snapshot files read-only, and runs both actual wrappers with
`-AdmissionOnly` from that no-`.git` snapshot. Original source is not rewritten;
snapshot hashes are rechecked after execution. Both profiles use actual QEMU
CPU execution, O2/Os and normal/LTO, including their existing lifecycle and
archive/link controls. `CompleteSuite=false` remains mandatory: this does not
run either full runtime/raw-compiler suite or qualify hardware/profile support.

Isolated mutable control files exercise each actual wrapper's AST-extracted
`HashInputs`, drift assignment and both final drift-failure guards: a changed
byte produces the actual FAIL verdict and terminal diagnostic, while a removed
input fails hashing. A test-local guard-removal script must accept that same
changed-byte input, proving oracle sensitivity. These controls do not mutate a running script or the
immutable execution snapshot. Separate controls check canonical ordering,
export-root independence, changed source digests, no-root-metadata behavior,
foreign-root rejection, malformed HEAD, failed/unavailable Git and actual
broken Git metadata. Metadata-result controls use an explicit injected Git
runner; the actual source-root attribution probe and broken-metadata control
use real Git. Source HEAD is never a prerequisite even for this proof.

The evidence retains source-copy mappings, full child receipts, commands,
checks, source manifests and artifact SHA256 hashes, including failures.
