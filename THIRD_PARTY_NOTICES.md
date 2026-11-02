# Third-Party Notices

This file retains notices for the FreeRTOS-referenced and adapted portions
identified below. It does not assign or change the license of independently
authored Fiber code, and does not claim that every file or line in a listed
directory was copied. Staged artifacts are included without implying runtime
support. Per-port `FREERTOS_PARITY.md` records and
[FREERTOS_ASM_PARITY.md](FREERTOS_ASM_PARITY.md) describe adopted, adapted,
replaced, comparison-only, and excluded mechanisms.

## FreeRTOS Kernel

- Upstream: <https://github.com/FreeRTOS/FreeRTOS-Kernel>
- Pinned commit: `a50edad08b29052631aa469d4df6e6ec7ff68878`
- Local reference: `_reference/FreeRTOS-Kernel`, outside this repository.
- Upstream notice file: `LICENSE.md`.
- SHA-256 of that local upstream file:
  `9EB6F69D48A1DD764E8A33F14A584F460D3CEC653477C136A95DD6DF9C249211`.

### Source Group Mapping

Local groups below are relative to `fiber/port/`; upstream groups are relative
to `portable/GCC/` at the pinned commit. The mappings cover port dictionaries,
frame construction, context transfer, MPU images, and Secure companion portions
as classified in their individual ledgers, not the FreeRTOS kernel API.

| Local source group | Upstream source group |
| --- | --- |
| `ARM_CM0`, `ARM_CM0_MPU` | `ARM_CM0` |
| `ARM_CM3` | `ARM_CM3` |
| `ARM_CM3_MPU` | `ARM_CM3_MPU` |
| `ARM_CM4` | `ARM_CM4F` |
| `ARM_CM4_MPU` | `ARM_CM4_MPU` |
| `ARM_CM7/r0p1` | `ARM_CM7/r0p1`, `ARM_CM4F` |
| `ARM_CM23_NTZ/non_secure` | `ARM_CM23_NTZ/non_secure` |
| `ARM_CM33_NTZ`, `ARM_CM33F_NTZ`, `ARM_CM33_MPU`, `ARM_CM33F_MPU`, and the CPU-port portion of `ARM_CM33_TFM` (each `non_secure`) | `ARM_CM33_NTZ/non_secure` |
| Staged `ARM_CM33_SECURE_ONLY/secure` | The same `ARM_CM33_NTZ/non_secure` source group with `configRUN_FREERTOS_SECURE_ONLY=1`, TrustZone/MPU/FP disabled; not the `ARM_CM33/secure` companion |
| `ARM_CM55_NTZ`, `ARM_CM55F_NTZ`, `ARM_CM55_MVEF_NTZ`, `ARM_CM55_MPU`, `ARM_CM55F_MPU`, `ARM_CM55_MVEF_MPU`, and the CPU-port portion of `ARM_CM55_TFM` (each `non_secure`) | `ARM_CM55_NTZ/non_secure` |
| Staged `ARM_CM55_SECURE_ONLY/secure` | The same `ARM_CM55_NTZ/non_secure` source group with `configRUN_FREERTOS_SECURE_ONLY=1`, TrustZone/MPU/FP/MVE disabled; not the `ARM_CM55/secure` companion |
| `ARM_CM33/non_secure`, `ARM_CM33/secure` | `ARM_CM33/non_secure`, `ARM_CM33/secure` |
| Staged `ARM_CM33F/non_secure`, `ARM_CM33F/secure` | The same `ARM_CM33` source pair with FPU enabled, MPU/MVE disabled; distinct Fiber paired identity and staged feature implementation |
| `ARM_CM55/non_secure`, `ARM_CM55/secure` | `ARM_CM55/non_secure`, `ARM_CM55/secure` |

### Retained File-Level Notices

The following text is retained verbatim from upstream headers, with C comment
delimiters removed. Identical notices shared by multiple files are listed once.
The upstream files identify their license as `SPDX-License-Identifier: MIT`.

All GCC source groups listed above:

```text
Copyright (C) 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
```

`ARM_CM0/port.c`, `ARM_CM3_MPU/port.c`, and `ARM_CM4_MPU/port.c` additionally:

```text
Copyright 2025 Arm Limited and/or its affiliates
<open-source-office@arm.com>
```

`ARM_CM33/non_secure/portasm.c` and `ARM_CM55/non_secure/portasm.c` additionally:

```text
Copyright 2024 Arm Limited and/or its affiliates
<open-source-office@arm.com>
```

For the following notices, the v8-M source groups are `ARM_CM23_NTZ`,
`ARM_CM33_NTZ`, `ARM_CM55_NTZ`, `ARM_CM33`, and `ARM_CM55`, each `non_secure`.

Their `portmacrocommon.h` files, and the `ARM_CM33_NTZ` and `ARM_CM55_NTZ`
`portasm.c` files, additionally:

```text
Copyright 2024, 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
```

Their `port.c` files additionally:

```text
Copyright 2024-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
```

Their `portmacro.h` files additionally:

```text
Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
```

### ARM_TFM Wrapper Reference

`fiber/port/ARM_CM33_TFM/non_secure/fiber_port_tfm_os_wrapper.c`,
`fiber/port/ARM_CM55_TFM/non_secure/fiber_port_tfm_os_wrapper.c`, and their
headers provide Fiber's cooperative replacement for the mutex interface mapped
in each port's ledger. The reference is
`portable/ThirdParty/GCC/ARM_TFM/os_wrapper_freertos.c` at the same pin, with
SHA-256 `9A6242DB2128A3220495C6739078959CF56D56649F1FFB2634C6430603938901`.
The reference file is also MIT licensed, not a different license. Its distinct
notice is retained here; this does not claim that its FreeRTOS semaphore/queue
implementation is copied into Fiber's cooperative wrapper:

```text
Copyright (c) 2019-2024, Arm Limited. All rights reserved.
```

### MIT License Text

The following is the complete text of the pinned upstream `LICENSE.md`:

```text
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Comparison-Only And External Dependencies

- Other FreeRTOS mechanisms that the ledgers mark comparison-only, excluded,
  or deferred are not claimed as incorporated source by this notice. Some
  qualification tests compile the external pinned originals as comparison
  objects; that does not make the complete kernel part of Fiber.
- TF-M v2.0.0 Secure services and `tfm_ns_interface_init()` are external
  integration dependencies, not bundled TF-M implementations. The local mutex
  wrapper and its reference notice are identified separately above.
- CMSIS/device headers are external build dependencies. Python, Unicorn,
  pyelftools, QEMU, and compiler tools are external validation/build tools.
  This FreeRTOS notice does not describe those projects as FreeRTOS-derived
  code or replace their own notices when their material is distributed.
