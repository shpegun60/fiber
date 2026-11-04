# Final-Join Policy Supplement

This supplement preserves a rationale added after the retained source
inventory ledger. Transfer mechanism IDs still bind that inventory's
immutable ledger, not this file. This is not an instruction-equivalence
or hardware qualification claim.

### FAP-FP-SETUP-POLICY

The exact selected native hard-FP/eager CM4/CM7 setup enables CP10/CP11 in
CPACR at `0xE000ED88` with mask `0x00F00000`. Its FPCCR policy at
`0xE000EF34` sets ASPEN and clears LSPEN, masked value `0x80000000`.
The pinned FreeRTOS setup enables the same CPACR fields, but sets both
ASPEN and LSPEN, masked value `0xC0000000`. These emitted setup contracts
are intentionally different. The final transfer-root join does not prove
their policy equivalence, pending-lazy-state/LSPACT handling, successful
MMIO readback or whole-startup execution.
