# Four-Group V8 MPU Raw Compiler Closure

Run `tools/test_v8_mpu_raw_compiler.ps1 -ArmGcc <gcc.exe> -CmsisCore <CMSIS Include>`.
No QEMU, network provisioning or board operation is performed.

The default complete grid has 360 cells: CM33_MPU/CM55_MPU scalar soft ABI,
CM55F_MPU/CM55_MVEF_MPU hard and softfp ABI, each with 8 and 16 regions,
O0/Og/O2/Os/O3, baseline/raw flags, ordinary native objects and genuinely
lowered slim LTO with sectioned/unsectioned output. A smaller explicit
`-Optimizations` selection is marked `CompleteSuite=false`.

The wrapper snapshots its own runner, all selected source groups, shared
headers/common C, the maintained sensitive-port classifier/fixtures and CMSIS.
It re-executes the copied runner. The maintained raw flags, dependency capture,
ELF relocation classifier, active/counterfeit controls and ordinary-cold common
exception remain unchanged. Protected common current/start/schedule chains are
not confused with ordinary cold init/registration functions.

At O2/Os a further 72 compiled controls remove only the sensitive bundle from
the nine new CPU inlines. General-register constraints, every non-inline bundle
and the existing geometry/r9 inlines are retained. An actual instrumentation
relocation must appear; a failed build is not an accepted negative result.

Every command, dependency file, native ELF/disassembly, CPU attributes,
classification, source snapshot and before/after input hash is retained.
`sha256.csv` is generated at completion after the final receipt, covering every
retained file except itself. Failed builds/controls remain in their unique root.

This is compiler-closure evidence, not architecture, scheduler, FP-state, MPU
isolation or hardware execution proof. Pinned FreeRTOS ordered-mechanism gates
remain separate. Normal external `memcpy`/`memset` implementations and application
callbacks are not supplied or qualified here; their imports are classified,
not a license to ignore compiler hooks or unresolved private helpers.
