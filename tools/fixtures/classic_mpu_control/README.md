# Classic MPU CONTROL Regression

Run from the library root with explicit installed tools:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test_classic_mpu_control.ps1 `
  -ArmGcc '<arm-none-eabi-gcc.exe>' -CmsisCore '<CMSIS/Include>' `
  -HostGcc '<gcc.exe>' -BuildRoot '<fresh-directory>'
```

Only Python's standard library is required. Optimized Python invocations are
rejected, including imports. This is host execution and actual ARM compilation,
not ARM execution, exception emulation, QEMU, or hardware qualification.

## Authoritative Inputs

The runner captures the actual CM0 MPU, CM3 MPU and CM4/M7 MPU source groups,
public/Context headers, CMSIS headers, and its two maintained classifier modules
before compiling. Both original and immutable copied bytes are enrolled before
import/use and checked again at closing. Compiler dependency scans enroll generated projections and
actual installed system headers before use. Closing hashes cover live originals,
captured dependencies, installed compiler images, native ARM binutils and the
ARM driver's queried delegates. The actual `-###` plugin must equal the queried
plugin path; native `nm`/`ar` receive that explicit plugin for slim LTO inputs.
This is a bounded tool inventory, not a claim of complete transitive host-tool
or operating-system identity. No unrelated source tree or protected WIP is
enumerated. All commands, failed attempts, preprocessed guard projections,
native objects/disassembly, link diagnostics and manifests are retained.

## Cases

- Seven profiles: CM0+ VTOR0/1; CM3; CM4 and CM7 hard-float with 8/16 MPU regions.
- Actual scalar `FIBER_REQUIRE` conditions are extracted by named function role
  and preprocessed through each selected real port header. Cursor-address
  identity assertions are not scalar CONTROL guards. Only the selected scalar
  is varied; sealed initial metadata uses the actual header constants.
- 35 host executables cover five optimizations and 238680 truth-table calls:
  all low-byte values, every higher bit with low values 0..7, and explicit
  wrong-origin/basic/extended EXC_RETURN values. Fresh images require 3; saved
  basic images allow exactly 1/3; saved extended images require exactly 1;
  pre-save live Handler state requires 1; FP post-VSTM state allows exactly 1/5.
  EXC_RETURN and PendSV IPSR guards have independent numeric oracles.
- 61 compiled projection mutations must fail with their exact named diagnostic.
  They restore old exact-3/7 rules or admit reserved bits/invalid initial state.
  These are source-derived scalar guard tests, not full validator execution,
  metadata-corruption execution, or validation-order proof.
- 63 actual ARM object cells cover O0/Og/O2/Os/O3 ordinary, O2/Os slim native
  LTO, and O2/Os native LTO without function sections. Raw instrumentation, SSP,
  coverage, UBSan, trace-pc and profiling flags are not countermanded. Coverage
  flags are omitted only from relocatable driver lowering to avoid driver-added
  libgcov; their IR was generated in the TUs and active controls verify output.
- The maintained whole-object hook classifier must report zero actual port
  defects. Each cell has an unannotated compiled control proving all six raw
  families remain active. There is no public-common cold-function exemption:
  these cells compile the two actual port C files, not common providers.
- Direct executable pre-MRS roots come from transfers in the actual handler
  prefix, not a fixed root-name list. Relocations and exact entry addresses
  identify calls; compared function addresses are not call edges. Indirect,
  interior-entry or unknown external transfers fail closed. A jump out of the
  prefix must be its exact local terminal `fiber_panic` stub. Function identity
  retains section, entry and extent, so duplicate local names cannot overwrite
  one another. Every reachable actual C body must be free of VFP instructions.
  A bounded byte-address CFG starts at each actual entry and follows both sides
  of conditional transfers, including IT-predicated returns. Ordinary calls
  retain fallthrough; only proven unconditional returns/tail branches and the
  known noreturn `fiber_panic` call suppress it. Every reached address must have
  a complete decoded instruction matching the ELF bytes within its function
  extent. Fallthrough into `.word`/`.hword` or other undecoded bytes is rejected;
  literal pools are admitted only off that overapproximated CFG. Unsupported
  indirect transfers fail closed. Per-function reachable byte counts and proven
  unreachable spans are retained with the section/entry/extent evidence.
  The capture/store window must match the exact bounded instruction sequence:
  CM0/CM3 capture r2; CM4/M7 capture r3 before the three conditional FP transfers
  and protected store. Added instructions or a wrong register are rejected,
  rather than relying on an incomplete r3-clobber denylist. CM0 post-MSR
  readbacks must compare exactly 1. Per-cell root/body extents are retained.
- At O2 ordinary/native LTO: 14 actual annotation-removal controls must expose
  pre-MRS instrumentation, 4 actual CM0 assembly mutations must fail readback
  classification, and 16 actual VFP insertions before MRS/in a transitive helper
  must be rejected for the intended exact reason.
- 129 additional scanner/provenance assurance records are kept separately from
  the original five Counts/seven ControlCounts contract: 24 actual compiled
  EOR/MOV/wrong-capture controls, 32 new-prefix helper controls (clean, FP,
  indirect, interior target), 32 duplicate-local helper controls (clean/poison,
  both object orders, ordinary/native LTO), and one paired copied-classifier
  closing control; and 40 byte-coverage records across ordinary/native LTO.
  These last records reproduce the same-ELF disassembly-row hiding case, execute
  the compiler on the actual NOP/`.hword 0xeeb0,0x0a40`/NOP helper, reject data
  on conditional-branch/conditional-return false edges, and accept the same FP
  encoding behind a proven unconditional branch. The closing pair invokes the actual finalizer with unchanged
  and intentionally drifted copies; its explicitly closing-only subreceipts
  reuse the genuine parent observations and are not separate compile suites.
- 56 matching final-ELF cohort links and 56 strict mismatch failures cover
  O2 ordinary/slim LTO, direct/archive, both v1->v2 and v2->v1. The v1 provider
  is an explicitly labeled identity-only mutation of current source, not a
  historical behavioral baseline. Expected missing names come from actual
  consumer objects. Each mismatch also has a mixed-error counterfeit control.

The receipt requires the exact complete inventory, zero input drift and verified
artifact hashes before PASS. Native outputs must contain no surviving LTO IR;
LTO inputs must have IR and no executable fallback. These checks do not replace
the pinned FreeRTOS O2/Os mechanism comparison or fresh CPU qualification, and
do not claim general all-optimization equivalence, full common runtime linking,
or reverse-provider/duplicate-handler qualification.

The PowerShell launcher independently requires real booleans, empty error/drift
arrays, verified artifacts, exact typed five-field Counts and seven-field
ControlCounts objects, and the complete unique case/control identity sets. It
does not coerce strings to booleans or accept skip rows. The maintained
`test_closing.ps1` AST-extracts this actual checker, accepts the authentic complete
receipt, and rejects 162 malformed variants for exact diagnostics (including the
original coerced/incomplete reproduction). It runs automatically after each
successful Python suite and writes a separate `<BuildRoot>-closing` receipt, so
the Python artifact inventory is not extended after its closing verification.
It can also run alone with `-ReceiptPath <existing-results.json> -BuildRoot
<fresh-directory>`; that checks orchestration only and does not upgrade the
source identity or historical acceptance of the seed receipt.

## Preserved Development Attempts

The following complete FAIL receipts remain distinct and are not upgraded by a
later replay:

- `C:\cmctrl-dev-b5729369`: Store Python alias is not directly hash-readable.
- `C:\cmctrl-dev-c21e9357`: assumed LTO plugin basename did not exist.
- `C:\cmctrl-dev-a9c40385`: CM0 constructor delegates its initial-image guard.
- `C:\cmctrl-dev-47a1596c`: guard extraction missed the local CPU reader spelling.
- `C:\cmctrl-dev-670d2584`: data-address reachability was unsuitable for the
  separate direct-executable-edge pre-MRS proof.
- `C:\cmctrl-dev-7bf5963c`: native `nm` lacked the explicit slim-LTO plugin.
- `C:\cmctrl-dev-e129fb09`: CM3 cursor-address assertion was misclassified as a
  scalar CONTROL guard; both CM0 variants had completed before this failure.
- `C:\cmctrl-q2-45ffb9c7`: the strengthened graph rejected an interior transfer
  in the deliberately instrumented annotation-removal mutant. The negative now
  requires an actual direct instrumentation call in the handler's real validator
  entry instead of attempting to qualify that mutant's entire call graph.

The initial direct PowerShell invocation was blocked by execution policy before
the runner started; maintained commands explicitly use `-ExecutionPolicy Bypass`.

The original `C:\cmctrl-q-d1a78f56\results.json` (SHA256 starting `56C9ACBD`)
and `C:\cmctrl-review-a7df52b4\handoff.json` (starting `259D933A`) are retained
unchanged. Their pre-MRS scanner and copied-classifier closing assurances were
subsequently found incomplete, and their PowerShell acceptance check allowed
coercion. Their measured historical results are not relabeled as qualification
of the strengthened checker/scanner above.
The intermediate `C:\cmctrl-q3-534e902a` replay qualified the new scanner/control
work but predates the final literal-string/ordinal receipt-identity checks and
their 162-negative closing suite. It remains a distinct historical receipt.
The v2 `C:\cmctrl-q4-2188ddaf\results.json` (starting `407D18EB`) and
`C:\cmctrl-review-v2-5f4319d7\handoff.json` (starting `8C239C8D`) also remain
unchanged. Review found that their scanner could drop reachable undecoded/data
rows. Those bytes are not relabeled as qualification of the byte-coverage CFG.
