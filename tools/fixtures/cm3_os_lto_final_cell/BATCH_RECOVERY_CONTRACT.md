# Os Batch Recovery And Catalog Integrity

The build-only disposition remains `BUILT-PENDING-READER`, never whole-cell PASS.
Two additional driver obligations apply before accepting a hardened checkpoint.

## Complete Pending Catalog

The pending reader catalog must equal the exact ordered projection of the
original ABI, isolation, common-attribute and selected-port component records.
Each component copy must equal its original top-level fields. Role count and
uniqueness alone are insufficient: dropping a required role and decrementing
the count must fail, as must path/hash substitution or changing the copied
component independently. Hashes not explicitly stored in a component must come
from that same attempt's closed input-hash record, not an unbound caller value.

This record check does not replace reading and validating actual declared bytes
in the enclosing immutable reader. Build-only output never grants semantic credit.

## Owned Recovery Output

Recovery may write only after the session has successfully claimed its output
directory and recorded its physical identity. A failed `start()` does not grant
permission to create or overwrite files in an existing or otherwise unowned
directory. Before each recovery write, check that the original non-symlink,
non-reparse output directory still exists with the same device/inode identity.
An absent or replaced root must produce a bounded closing error, not writes to
the replacement. Preserve the original failure and never retry compilation.

These checks do not claim race-free protection against a hostile concurrent
filesystem actor. They close the defined failure/replacement fixtures and retain
the caller-owned trusted-workspace assumption.

## Live Attempts

Do not edit admitted driver or helper sources while commands from that attempt
are running. Retain a completed pre-hardening attempt and its captured source
buffers as historical evidence. A hardened producer execution must use the fixed
driver in a fresh output directory; do not relabel an earlier run as that producer.
Machine replays, synthetic tests, executed tool commands and board evidence are
separate levels of proof. No target CPU or board is executed by these tools.
