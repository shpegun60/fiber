# MPU Constructor Attributes

`tools/test_mpu_constructor_attributes.ps1` compiles actual constructors and
their callers for four selected MPU profiles, 8/16 regions, O2/Os, and the
supported scalar or hard/softfp ABIs: 24 configurations, 48 compiled hostile
annotation-removal mutants, and 40 real caller compilations.

The explicit hashed header inventory includes top-level canonical `context/*.h`
as well as root, legacy `fiber`, shared port, and selected-profile headers. The
private annotation-removal tree preserves these relative include paths. It
does not compile the Context engine or discover and accept arbitrary headers.

A separate preprocessing control admits the real legacy public type forwarder
from the complete copied tree, then deliberately omits its canonical
`context/context_api_types.h` dependency in an isolated tree. Only the exact
missing-header diagnostic is accepted. This input-failure control does not
count as an annotation-removal mutant; compile failures in those mutants remain
fatal.

The attribute oracle remains independent: exact imports and coverage symbols,
hostile instrumentation inside the actual carrier, identical normal
instructions/relocations after annotation removal, and the fixed r9 leaf bytes.
No import allowance, counterflag, assembly baseline, runtime profile, or hardware
claim is added. Commands, dependency files, generated code, source hashes, and
the canonical-input control receipt are retained in the fresh build directory.
