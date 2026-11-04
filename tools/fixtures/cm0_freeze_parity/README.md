# CM0 / CM0+ Bounded Freeze Parity

The separate captured-object, five-mode complete-root gate is documented in
`CLOSED_ROOTS.md`. It does not replace or qualify this final-ELF fixture.

This is a software code-generation and link gate, not global parity, G0 CPU
execution, peripheral/board qualification or full FreeRTOS equivalence. No
firmware is executed. Nothing provisions packages or programs a board.

The two literal profiles are Cortex-M0/core_cm0.h/VTOR=0 and
Cortex-M0+/core_cm0plus.h/VTOR=1, both non-MPU and soft ABI. CM0+ VTOR=0 and
CM0 MPU are not silently included. Existing `-Cm0Only` parity remains separate.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools/test_cm0_freeze_parity.ps1 `
  -ArmGcc $env:ARM_NONE_EABI_GCC -CmsisCore $env:CMSIS_CORE_INCLUDE `
  -FreeRtosKernel $env:FREERTOS_KERNEL_REFERENCE -BuildRoot C:/q/absent-cm0-parity
```

The exact output directory must not exist. All attempts and failure artifacts
remain available. Use immutable exported repository inputs for qualification;
the runner hashes and copies source bytes, records actual dependencies/tools,
and rejects input or repository-inventory drift. Source byte capture does not
turn later live edits into qualification of that later tree.

Python must be unoptimized with the already-installed `pyelftools==0.33` from
the maintained classic-audit requirements. `-Python` and `-PythonModules` select
existing installations. The default module discovery also checks the existing
temporary `fiber-classic-audit-python` directory. Missing prerequisites fail;
no package is installed and no maintained cell is skipped.

Five existing paired-object invocations use the explicit `-Cm0NonMpuOnly`
selector at O0/Og/O2/Os/O3. Each must report two configurations, four objects
and six ordered mechanism checks with zero input drift. The normal parity
driver remains limited to O2/Os outside this new focused selector.
Nine actual-driver controls reject O0/Og/O3 under the default, old CM0-only
and CM3-only modes before compiler discovery or output creation. Separate old
`-Cm0Only` O2/Os replays retain their three configurations, six objects and
18 mechanisms, including the unchanged MPU row. These compatibility checks do
not claim a fresh full-catalog default invocation.

The final-ELF grid is two profiles x seven modes x direct/archive: 28 pairs,
56 positive executable ELFs. The seven modes are ordinary O0/Og/O2/Os/O3 and
native final-linked O2/Os LTO. They are not five modes of CPU execution.
Pure Context links use the actual engine/state/panic providers and all three
actual ARM_CM0 backend C units, without legacy compatibility, Fiber lifecycle
or optional configuration. Real public typed roots retain all five Context
operations. All eight actual forward providers are checked before linking.

Each upstream image compiles the unchanged pinned
`portable/GCC/ARM_CM0/port.c` and `portasm.c` with real upstream headers.
Typed constructor/scheduler roots, strong SVC/PendSV/SysTick vectors and
prelink ownership are checked. Reset and missing-kernel boundaries fail-stop
through UDF #90; they never emulate successful scheduling/ticks or run the
kernel. The current-TCB boundary is explicitly null BSS. There are no copied
handlers, manufactured successful kernel returns, or whole-archive extraction.
Reference dependencies cannot import project/CMSIS declarations.

Final disassembly checks ordered start/restore/PendSV mechanisms and records
the retained adaptations: SVC 70 versus upstream 100, validated first restore
versus upstream GPR skip, common versus TCB publication, and saved PRIMASK
restoration versus upstream unconditional enable. These are bounded ordered
checks, not closed whole-function equivalence or a proof of C constructor
semantics. Actual constructor bodies are retained, not interpreted here.

For each pair, three actual-source PendSV mutations must compile and link:
wrong save stride, missing high-R9 restore, and omitted mask-restoration macro.
Each must reject with its own exact mechanism identity, not an unrelated build,
ELF or classifier failure. The literal inventory is 84 compiled controls.
Strict optimized direct/import invocation and counterfeit-diagnostic controls
also run. Ordinary and final-ELF coverage is reported independently.

LTO C inputs must be slim IR; the final image must contain native function
bodies with no IR sections. The actual link driver's `-###` plugin path must
match the queried and hashed DLL. Commands, dependency/source-object maps,
source-byte mirror, full disassembly, ELF/map/symbol inventories, before/after
hashes and receipts are retained. A failed or incomplete attempt cannot emit
a PASS receipt. Existing raw-compiler and exception-runtime suites remain
independent requirements and are not replaced by this gate.
