# Software Checkpoint d005a36 Evidence Archive

## Scope

The checkpoint is `d005a3604248b34e577417cda0acfb83ecb47ff8` on `v2`.
This is preservation of existing evidence, not a qualification rerun. Runtime
C/ASM, context layout, public5/port8 and unrelated untracked WIP are unchanged.
No compiler, admission, producer, board operation or hosted CI run is added.

Historical results are bounded: final-cut tests 33/33, raw input audit
7999/7999, and the CM3/runtime/final/Os-lto/direct cell. The actual cell receipt
credits one of 2774 required cells. This is not a whole-library freeze claim.
Hash and CRC verification prove byte preservation, not the correctness of the
historical assertions or unobserved process history.

## Package

`tools/archive_checkpoint.py` copies the pinned existing cell and test receipts,
their hash-bound inputs, nine manifest trees, source buffers, command journals,
captured tool binaries and available test fixtures. The checkpoint's tracked
source snapshot is generated separately using `git archive`; untracked WIP is
not included. The archive is outside the Git repository and outside `%TEMP%`.
That convenience tar follows Git export/EOL conversion; it is not a substitute
for exact historical source bytes. In particular, its qualifier/test exports use
CRLF while the independently hash-bound D950/DEC6 source payloads preserve LF
exactly. Historical hashes always refer to those raw payloads, not the tar.

Every ZIP member except `MANIFEST.json` has a relative name, byte size and SHA-256
in that manifest. Identical payloads are deduplicated by SHA-256. `provenance.json`
maps each historical path/hash pair to its payload. Raw receipts, their hashes,
and historical physical identity tuples are not rewritten.

An exact alternate copy is explicitly distinguished from a file still present
at its original path. In particular, the old D76 test cut is preserved from its
previously reconstructed, byte-verified historical copy, not silently replaced
by the newer DEC6 source. Copied bytes do not recreate historical file identities.
Missing or mismatched expectations are listed in `missing.json`; verification
must not report a complete archive when any remain unresolved.
Missing or mismatched discovery receipts/manifests stop the builder before ZIP
creation because their dependency closure cannot be inferred safely.

Standalone qualification-time Git status and compiler `--version` output were
not separately recorded. The archive must not invent them. Archive-time Git
status is labeled separately; the qualification source checkpoint predates the
final d005a36 documentation/test commit. Captured tool hashes, actual argv/flags,
and compiler layout identification remain available in the raw receipts. The
seed captures do preserve raw `-dumpfullversion` stdout `14.3.1`; this is included
without executing the tool again. `toolchain.json` also indexes exact embedded
GCC/cc1/ld identification strings and offsets in the archived binaries, explicitly
as archive-time byte observations rather than historical `--version` output.

## Offline Verification

The ZIP has an adjacent `.zip.sha256` sidecar. The verifier requires it by default:

```powershell
python -I -S -B verify_checkpoint_archive.py software-checkpoint-d005a36.zip
```

`tools/verify_checkpoint_archive.py` uses the Python standard library only. It
checks the archive SHA-256, CRC, exact manifest membership, every member's size
and hash, and provenance-to-payload bindings. It rejects unsafe or duplicate ZIP
names and incomplete evidence. It does not extract or execute payloads, rerun
tests, or access the old absolute paths. The verifier is both inside the archive
and supplied beside it for direct use.

An unsigned archive with a co-located checksum is not an authenticity signature.
Store the final digest independently for protection against deliberate replacement.

## Retention And Cleanup

A second byte-verified copy is required before cleanup. Two locations on the same
disk are useful local redundancy, not an independent-device disaster backup.
Never recursively clear all `%TEMP%`. Cleanup is restricted to explicitly named
owned receipt directories/files, with exact resolved-path, membership, reparse
point and hash checks against the verified archive immediately before removal.
Shared parser, retained-source and other evidence trees are not cleanup targets.

## Archival Result, 2026-11-09

Primary: `C:/Users/admin/Documents/my_workspace/stm32/experiments/_artifacts/fiber/software-checkpoint-d005a36.zip`.
Second local copy: `C:/Users/admin/Documents/fiber-checkpoint-backups/d005a36/software-checkpoint-d005a36.zip`.
Both locations also contain the standalone verifier and SHA-256 sidecar. They
are on the same C: volume, not independent-device backup storage.

- ZIP bytes: `60087341`.
- ZIP SHA-256: `6C7C035896E2702D819C82D3C70D50890FDEA551529CF8054045CEDA0619C35C`.
- Exact ZIP members: 1681; manifest-bound members: 1680.
- Provenance expectations: 10705; content-addressed payloads: 1670.
- Captured at original paths: 10704; explicitly disclosed alternate: one D76 cut.
- Unresolved missing/mismatched expectations: zero.
- Primary and relocated-copy offline SHA/CRC/manifest/payload checks: PASS.
- Historical paths accessed by offline verifier: false.
- Independent ZIP-only review of pinned receipts, all 7999 bindings and the nine
  manifest trees: PASS; no protected-WIP payload paths found.
- Verifier synthetic tests: 22/22, owner and parent, identical receipt SHA-256
  `5B55458822B61599AE67BC1ECB46564E9D670CC9F4705F155A30E515A15AAD79`.

The existing 33/33, 7999/7999 and bounded-cell receipts have been preserved, not
rerun. Qualification-time Git status is still not separately recorded. New
archival synthetic tests are not additional runtime/port qualification credit.

Cleanup is **not performed**: the execution environment rejected the deletion
command before process launch. All ten planned targets remain present. The two
archive locations retain `cleanup-plan.json` (six exact receipt directories and
four scripts, 43 files / 44579721 bytes) and `cleanup-result.json` recording the
blocked operation. No TEMP, shared-source, parser, external capture or WIP file
was deleted. Evidence archival is complete; targeted cleanup remains separate.
