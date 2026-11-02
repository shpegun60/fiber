# Inline CPU Helper Proof

Run from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/test_inline_cpu_helpers.ps1 -ArmGcc <arm-none-eabi-gcc.exe> -CmsisCore <CMSIS/Include>
```

`-HostGcc` and `-BuildRoot` are optional. The runner discovers host GCC on PATH
or the existing MSYS2 UCRT64 location. No Python or emulator packages are needed.
Missing compilers, binutils or headers fail the test rather than skipping it.

The actual five MPU dictionaries and shared EXC_RETURN predicate are compiled
at O2/Os, with 8/16 MPU regions and every applicable soft/hard/softfp ABI.
Each helper is called from both a general-register-only sensitive wrapper and
an otherwise identical ordinary-target sensitive wrapper. A second C++ compile
checks the same target compatibility and unmangled fixture wrapper declarations.

Hostile flags enable function instrumentation, stack protection, coverage,
profiling and UBSan. No instrumentation-exclusion flags or global
general-register-only target hide missing per-function attributes. Ordinary
and hostile objects must have the exact empty external dependency set, the
exact wrapper function inventory, no writable storage, runtime counters or hooks, no FP/MVE
instructions, and identical per-function instruction bytes.

One sensitive inline bundle is removed at a time from the actual preprocessed
compiler input. Its general-register-only target and body remain unchanged.
All eight mutants in every configuration must compile and be rejected for
instrumentation, including enter/exit calls in that helper's sensitive wrapper.
The same checker is also exercised with focused classifier counterexamples.

Host C/C++ fixtures consume compiler-expanded, source-derived traits and include
the shared header without CMSIS, fiber_compiler.h or a prior attributes include.
Their independent numeric EXC_RETURN oracle checks 131104 values per run.

Artifacts include exact argv, compiler versions, input hashes, preprocessed
sources, assembly, object symbols/sections/relocations, and mutant diagnostics.
This is compiler/object evidence, not an exception, QEMU or hardware execution
claim. Other port dictionaries, CMSIS helpers, and non-inline runtime callees
remain coverage-pending.
