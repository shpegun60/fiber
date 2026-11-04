# TF-M v2.0.0 Compile-only Interface Fixture

This is a source fixture, not a provisioned tool or a runtime feature. It
provides unchanged official TF-M interface headers for compile-only use by the
pinned FreeRTOS `portable/ThirdParty/GCC/ARM_TFM/os_wrapper_freertos.c`.
It does not provide a Secure TF-M implementation, veneers, an RTOS mutex
implementation, PSA services, or evidence of runtime integration.

## Provenance

- Upstream: https://git.trustedfirmware.org/TF-M/trusted-firmware-m.git/
- Official read-only mirror: https://github.com/TrustedFirmware-M/trusted-firmware-m
- Tag: `TF-Mv2.0.0`
- Annotated tag object: `83ed551cb8341d45e1db2dcafd614f13589dbf44`
- Peeled commit: `9ca8a5eb3c85eecee1303dffa262800ea0385584`
- Tag metadata: https://api.github.com/repos/TrustedFirmware-M/trusted-firmware-m/git/ref/tags/TF-Mv2.0.0
- Tag object: https://api.github.com/repos/TrustedFirmware-M/trusted-firmware-m/git/tags/83ed551cb8341d45e1db2dcafd614f13589dbf44

The three upstream files below are byte-for-byte copies of commit-addressed
raw responses. Their bytes were also cross-checked against the official
mirror's contents API and Git blob SHA-1 values at that commit. They retain
the original notices and BSD-3-Clause license. No comments, declarations or
license text were rewritten.

All three files use their original ASCII/LF bytes: no BOM, no CR bytes, and
exactly one final LF. Hashes below describe raw bytes, not newline-normalized
text. Do not silently convert them to CRLF or apply other normalization.
No Git attributes are supplied by this fixture.

## Source Files

### interface/include/os_wrapper/mutex.h

- Fetch: https://raw.githubusercontent.com/TrustedFirmware-M/trusted-firmware-m/9ca8a5eb3c85eecee1303dffa262800ea0385584/interface/include/os_wrapper/mutex.h
- Bytes: `1975`
- Raw SHA-256: `321A599838EE95A3FAF75BAFF57D2DB1BD3770824BE467DDC24870744831D705`
- Git blob SHA-1: `ffdf92c36d23dcf732c251a1bb834bc57e5cedc2`
- SPDX license: `BSD-3-Clause`

### interface/include/os_wrapper/common.h

- Fetch: https://raw.githubusercontent.com/TrustedFirmware-M/trusted-firmware-m/9ca8a5eb3c85eecee1303dffa262800ea0385584/interface/include/os_wrapper/common.h
- Bytes: `501`
- Raw SHA-256: `AD83089404AADC15A130378EE69AB096436A60F6AADC45D899ECBEAA77D7C048`
- Git blob SHA-1: `6494723030df24419a785d91a1f6a5f2eb60e51b`
- SPDX license: `BSD-3-Clause`

### license.rst

- Fetch: https://raw.githubusercontent.com/TrustedFirmware-M/trusted-firmware-m/9ca8a5eb3c85eecee1303dffa262800ea0385584/license.rst
- Bytes: `1765`
- Raw SHA-256: `C16DF600171BFDAE60D22A01F046D742F89BA1046E2E5ED135BBF091B21BE34F`
- Git blob SHA-1: `2f703d5e468cd69370332c1b1af94ac27ad25e10`
- License text for the headers' `BSD-3-Clause` identifiers.

## Include Closure and Scope

The exact TF-M include closure is:

```text
interface/include/os_wrapper/mutex.h
  -> os_wrapper/common.h
       -> <stdint.h>
```

Use this fixture's `interface/include` directory as the include root. The
toolchain supplies `<stdint.h>`; it is not a TF-M file. FreeRTOS declarations
and the mutex implementation remain separate pinned-source obligations.
Consumers must bind the actual dependency paths to these headers and verify
the raw hashes rather than permit shadowing by synthetic fixture headers.

This header provider does not admit any processor, activate a port, satisfy
assembly/final-ELF parity, or establish TF-M runtime, CPU, board or global
freeze qualification.
