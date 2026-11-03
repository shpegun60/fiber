"""Bind two observer stops to actual O2/native/direct FP-pilot ELF bytes.

The caller supplies the maintained Image instance and a positive pilot row.
This module neither constructs replacement handlers nor executes the target.
"""
from __future__ import annotations

from copy import copy, deepcopy
import hashlib
import json
from pathlib import Path
import re
import struct

import cm4_mpu_fp_checks as checks


SLOT = "fiber_internal_runtime_current_context_slot"
REVERSE = "fiber_internal_runtime_port_abi_v1_anchor"
CONFIG = "fiber_internal_runtime_context_configuration_abi_v1_anchor"
STORAGE = "fiber_port_storage_cohort_arm_cm4_mpu_v1_r8"
COHORT = ("fiber_port_context_cohort_armv7em_p0x434D344Du_l0x00020008u_f1_e1_h1_j1_v1_"
          "d0_r0_z8u_y1_w2_g8_u10000000_i0_o0xFFFFFFFDu_c1_s0_x0_m0_a0_b0_t0_n0_k0_q0")
PUBLIC = ("ctxrt_v1_init", "ctxrt_v1_current", "ctxrt_v1_set_dispatcher",
          "ctxrt_v1_start", "ctxrt_v1_yield")
FIBER = ("fiber_v1_init", "fiber_v1_current", "fiber_v1_set_scheduler",
         "fiber_v1_start", "fiber_v1_yield")
FORWARD = ("fiber_port_context_init", "fiber_port_runtime_prepare_start",
           "fiber_port_runtime_select_first", "fiber_port_runtime_start_first",
           "fiber_port_runtime_schedule", "fiber_port_require_scheduler_configuration_environment",
           "fiber_port_runtime_memory_barrier", "fiber_port_panic_wait")
LEGACY = ("fiber_init", "fiber_current", "fiber_scheduler_set_pick_next", "fiber_start", "fiber_schedule")
FACTS = ("RawControlBeforeVstm", "PspLowFrameOffset", "ExtendedSaveGate", "HighFpSave16",
         "LowFpRawSave17", "BasicSaveAndCursor", "BasicRestoreInverse", "ControlRestore",
         "ExtendedRestoreGate", "LowFpRawRestore17", "HighFpRestore16", "CursorResetAndReturn",
         "PostCopyLspactGuard")


def _need(value, reason):
    if not value:
        raise RuntimeError("LAZY_PLAN_" + reason)


def _sha(data):
    _need(type(data) is bytes, "BYTES")
    return hashlib.sha256(data).hexdigest().upper()


def _word(value):
    return type(value) is int and 0 <= value <= 0xffffffff


def _section(image, name, address=None, size=None, writable=False, executable=False):
    value = image.sections.get(name)
    _need(type(value) is dict and _word(value.get("Address")) and _word(value.get("Size")) and
          type(value.get("Flags")) is int and type(value.get("Data")) is bytes, "SECTION:" + name)
    _need(value["Flags"] & 2 and bool(value["Flags"] & 1) is writable and
          bool(value["Flags"] & 4) is executable, "SECTION_FLAGS:" + name)
    _need(address is None or value["Address"] == address, "SECTION_ADDRESS:" + name)
    _need(size is None or value["Size"] == size, "SECTION_SIZE:" + name)
    return value


def _symbol(image, name, kind=None, local=False):
    symbol = image.symbol(name, kind, local=local)
    _need(symbol.get("Name") == name and _word(symbol.get("Address")) and
          _word(symbol.get("Size")), "SYMBOL:" + name)
    return symbol


def _symbol_proof(image, symbol):
    raw = image.bytes(symbol)
    _need(len(raw) == symbol["Size"], "SYMBOL_BYTES:" + symbol["Name"])
    return dict(Address=symbol["Address"], Size=symbol["Size"], Kind=symbol["Kind"],
                Binding=symbol["Binding"], Section=symbol["Section"], BytesSha256=_sha(raw))


def _function(image, name, proof):
    symbol = _symbol(image, name, "STT_FUNC")
    section = image.sections[symbol["Section"]]
    _need(symbol["Binding"] == "STB_GLOBAL" and symbol["Address"] & 1 and
          section["Flags"] & 7 == 6, "STRONG_THUMB_FUNCTION:" + name)
    proof[name] = _symbol_proof(image, symbol)
    return symbol


def _mnemonic(instruction):
    value = instruction.get("Mnemonic")
    _need(type(value) is str, "MNEMONIC")
    return re.sub(r"\.(?:w|n)$", "", value.lower())


def _operands(instruction):
    value = instruction.get("Operands")
    _need(type(value) is str, "OPERANDS")
    return re.sub(r"\s+", "", value.split("@", 1)[0].lower())


def _immediate(instruction, mnemonic, register, number):
    operands = _operands(instruction)
    aliases = "(?:lr|r14)" if register == "lr" else re.escape(register)
    match = re.fullmatch(aliases + r",#(0x[0-9a-f]+|[0-9]+)", operands)
    return (_mnemonic(instruction) == mnemonic and match is not None and
            int(match[1], 16 if match[1].startswith("0x") else 10) == number)


def _body(image, name):
    raw = list(image.body(name))
    symbol = _symbol(image, name, "STT_FUNC")
    cursor = symbol["Address"] & ~1
    code, decoded, outside = [], [], set()
    remaining = 0
    for instruction in raw:
        address, data = instruction.get("Address"), instruction.get("Bytes")
        _need(_word(address) and address == cursor and type(data) is bytes and data,
              "DECODE_BOUNDARY:" + name)
        mapped_data = image.is_data(instruction, name)
        _need(type(mapped_data) is bool, "MAPPING:" + name)
        if mapped_data:
            _need(remaining == 0, "IT_CROSSES_DATA:" + name)
        else:
            _need(len(data) in (2, 4) and address % 2 == 0, "THUMB_WIDTH:" + name)
            halfword = int.from_bytes(data[:2], "little")
            width = 4 if halfword >> 11 in (0b11101, 0b11110, 0b11111) else 2
            _need(len(data) == width, "THUMB_WIDTH:" + name)
            if remaining == 0:
                outside.add(address)
            mnemonic = _mnemonic(instruction)
            if re.fullmatch(r"it[te]{0,3}", mnemonic):
                _need(remaining == 0, "NESTED_IT:" + name)
                remaining = len(mnemonic) - 1
            elif remaining:
                remaining -= 1
            code.append(instruction)
        decoded.append(dict(Address=address, Bytes=data.hex().upper(), Width=len(data),
                            Mnemonic=instruction["Mnemonic"], Operands=instruction["Operands"],
                            MappedData=mapped_data))
        cursor += len(data)
    _need(code and remaining == 0 and cursor == (symbol["Address"] & ~1) + symbol["Size"],
          "DECODE_EXTENT:" + name)
    _need(len({i["Address"] for i in raw}) == len(raw), "DUPLICATE_BOUNDARY:" + name)
    return code, decoded, outside


def _point(code, outside, address):
    _need(_word(address), "SITE_ADDRESS")
    matches = [i for i in code if i["Address"] == address]
    _need(len(matches) == 1 and address in outside, "SITE_NOT_UNCONDITIONAL_BOUNDARY")
    instruction = matches[0]
    return dict(Address=address, Bytes=instruction["Bytes"].hex().upper(), Width=len(instruction["Bytes"]))


def _target(instruction):
    text = instruction["Operands"].split("@", 1)[0].strip().lower()
    match = re.fullmatch(r"(?:0x)?([0-9a-f]+)(?:\s+<[^>]+>)?", text)
    _need(match is not None, "CALL_TARGET")
    return int(match[1], 16)


def plan(image, row):
    """Return a JSON-compatible static plan, not an execution/PASS receipt."""
    _need(type(row) is dict and row.get("Consumer") in ("context", "fiber") and
          type(row.get("Consumer")) is str and type(row.get("Lazy")) is bool and
          type(row.get("Model")) is bool and row["Model"] is False and
          "Mutation" in row and row["Mutation"] is None and
          type(row.get("Case")) is int and row["Case"] == 0 and
          type(row.get("Optimization")) is str and row["Optimization"] == "O2" and
          type(row.get("LTO")) is bool and row["LTO"] is False and
          type(row.get("Archive")) is bool and row["Archive"] is False, "POSITIVE_PILOT_ROW")
    _need(type(row.get("Elf")) is str and row["Elf"].strip() and
          type(row.get("ElfSha256")) is str and re.fullmatch(r"[0-9A-F]{64}", row["ElfSha256"]),
          "ELF_IDENTITY")
    path = Path(image.path).resolve(strict=True)
    _need(Path(row["Elf"]).is_absolute() and Path(row["Elf"]).resolve(strict=True) == path,
          "ELF_PATH")
    original = path.read_bytes()
    _need(original == image.data and _sha(original) == row["ElfSha256"], "ELF_DRIFT")
    disassembly_path = path.with_suffix(".dis")
    disassembly = disassembly_path.read_bytes()
    symbols = {}
    for name in ("Reset_Handler", "SVC_Handler", "PendSV_Handler", *PUBLIC, *FORWARD,
                 "fiber_port_unprivileged_task_return", "fiber_port_scheduler_pick_next_from_pendsv"):
        _function(image, name, symbols)
    if row["Consumer"] == "fiber":
        for name in FIBER:
            _function(image, name, symbols)
    else:
        _need(not any(n.startswith("fiber_v1_") for n in image.symbols), "CONTEXT_ISOLATION")
    _need(not set(LEGACY) & set(image.symbols), "LEGACY_SUBSTITUTION")

    boot = _section(image, ".boot_vectors", 0, 8)
    vectors = _section(image, ".isr_vector", 0x400, 1024)
    _need(len(boot["Data"]) == 8 and len(vectors["Data"]) == 1024, "VECTOR_BYTES")
    words = struct.unpack("<256I", vectors["Data"])
    _need(struct.unpack("<2I", boot["Data"]) == words[:2] and words[0] == 0x20010000 and
          words[1] == symbols["Reset_Handler"]["Address"] and
          words[11] == symbols["SVC_Handler"]["Address"] and
          words[14] == symbols["PendSV_Handler"]["Address"], "STRONG_VECTORS")
    privileged = _section(image, ".privileged_code", 0x800, executable=True)
    user = _section(image, ".user_code", 0x10000, executable=True)
    _need(privileged["Address"] + privileged["Size"] <= 0x10000 and
          user["Address"] + user["Size"] <= 0x20000, "CODE_RANGES")
    for name in ("SVC_Handler", "PendSV_Handler", "fiber_port_scheduler_pick_next_from_pendsv"):
        value = symbols[name]
        _need(value["Section"] == ".privileged_code" and
              0x800 <= (value["Address"] & ~1) < (value["Address"] & ~1) + value["Size"] <= 0x10000,
              "PRIVILEGED_HANDLER:" + name)

    _need([n for n in image.symbols if n.startswith("fiber_port_context_cohort_arm")] == [COHORT] and
          [n for n in image.symbols if n.startswith("fiber_port_storage_cohort_arm")] == [STORAGE], "EXACT_COHORTS")
    for name in (COHORT, STORAGE, SLOT, REVERSE):
        symbols[name] = _symbol_proof(image, _symbol(image, name, "STT_OBJECT"))
    if row["Consumer"] == "fiber":
        symbols[CONFIG] = _symbol_proof(image, _symbol(image, CONFIG, "STT_OBJECT"))
    else:
        _need(CONFIG not in image.symbols, "CONTEXT_CONFIGURATION")
    expectation = _section(image, ".fiber_port_context_cohort_expectation")
    count = 3 if row["Consumer"] == "fiber" else 2
    _need(expectation["Size"] == len(expectation["Data"]) == count * 4 and
          sorted(struct.unpack("<" + str(count) + "I", expectation["Data"])) ==
          sorted([symbols[COHORT]["Address"]] + [symbols[STORAGE]["Address"]] * (count - 1)),
          "READONLY_COHORT_POINTERS")
    roots = _symbol(image, "fixture_public_api_roots", "STT_OBJECT")
    _need(roots["Size"] == 20 and image.sections[roots["Section"]]["Flags"] & 3 == 2 and
          struct.unpack("<5I", image.bytes(roots)) ==
          tuple(symbols[n]["Address"] for n in (FIBER if row["Consumer"] == "fiber" else PUBLIC)), "PUBLIC_ROOTS")
    symbols[roots["Name"]] = _symbol_proof(image, roots)

    aperture = _section(image, ".current_slot", 0x20000000, 32, writable=True)
    _need(aperture["Type"] == "SHT_NOBITS" and symbols[SLOT]["Address"] == 0x20000000 and
          symbols[SLOT]["Size"] == 4 and symbols[SLOT]["Section"] == ".current_slot" and
          _symbol(image, "__slot_start__")["Address"] == 0x20000000 and
          _symbol(image, "__slot_end__")["Address"] == 0x20000020, "CURRENT_SLOT_APERTURE")
    occupants = [name for name, values in image.symbols.items() for value in values
                 if value["Section"] == ".current_slot" and value["Kind"] == "STT_OBJECT" and value["Size"]]
    _need(occupants == [SLOT], "APERTURE_OCCUPANTS")
    workers = _symbol(image, "workers", "STT_OBJECT", local=True)
    _need(workers["Binding"] == "STB_LOCAL" and workers["Size"] % 3 == 0 and
          workers["Address"] % 8 == 0 and (workers["Size"] // 3) % 8 == 0 and
          0x20008000 <= workers["Address"] < workers["Address"] + workers["Size"] <= 0x2000e000 and
          image.sections[workers["Section"]]["Flags"] & 7 == 3, "THREE_PRIVILEGED_WORKERS")
    symbols["workers"] = _symbol_proof(image, workers)
    stride = workers["Size"] // 3
    worker_addresses = [workers["Address"] + stride * index for index in range(3)]
    stacks = []
    for index, address in enumerate((0x20002000, 0x20004000, 0x20006000)):
        section = _section(image, ".stack" + str(index), address, 4096, writable=True)
        _need(section["Type"] == "SHT_NOBITS" and
              _symbol(image, "__stack" + str(index) + "_start")["Address"] == address and
              _symbol(image, "__stack" + str(index) + "_end")["Address"] == address + 4096,
              "STACK_SYMBOLS")
        stacks.append(dict(Begin=address, End=address + 4096))

    facts = checks.check_subject(image)
    _need(facts.get("Role") == "subject" and facts.get("Symbol") == "PendSV_Handler" and
          type(facts.get("Count")) is int and facts["Count"] == 13 and
          set(facts.get("Facts", {})) == set(FACTS), "THIRTEEN_FP_FACTS")
    details = facts["Facts"]
    code, decoded, outside = _body(image, "PendSV_Handler")
    gate, guard = details["ExtendedSaveGate"], details["PostCopyLspactGuard"]
    pre = _point(code, outside, gate["Address"])
    post = _point(code, outside, guard["Address"])
    by_address = {instruction["Address"]: index for index, instruction in enumerate(code)}
    before, after = by_address[pre["Address"]], by_address[post["Address"]]
    _need(_immediate(code[before], "tst", "lr", 16) and before + 2 < len(code) and
          _mnemonic(code[before + 1]) == "ittt" and _operands(code[before + 1]) == "eq" and
          code[before + 2]["Address"] == details["HighFpSave16"]["Address"] and
          gate["ExcReturnMask"] == 16 and gate["Condition"] == "EQ" and gate["ItSlots"] == 3,
          "PRE_SAVE_GATE")
    _need(_immediate(code[after], "tst", "r3", 1) and guard["Fpccr"] == 0xe000ef34 and guard["Mask"] == 1 and
          details["LowFpRawSave17"]["Store"] < details["BasicSaveAndCursor"]["Store"] < post["Address"] and
          post["Address"] < details["BasicRestoreInverse"]["Address"], "POST_COPY_GUARD")
    calls = [i for i in code[after + 1:] if _mnemonic(i) == "bl"]
    _need(calls and _target(calls[0]) ==
          symbols["fiber_port_scheduler_pick_next_from_pendsv"]["Address"] & ~1, "POST_BEFORE_SCHEDULER")

    returned, return_decoded, return_outside = _body(image, "fiber_port_unprivileged_task_return")
    return_symbol = _symbol(image, "fiber_port_svc_return_return_site")
    return_pc = return_symbol["Address"]
    point = _point(returned, return_outside, return_pc)
    resume = next(index for index, instruction in enumerate(returned) if instruction["Address"] == return_pc)
    _need(0x10000 <= return_pc < 0x20000 and resume > 0 and
          _mnemonic(returned[resume - 1]) == "svc" and
          re.fullmatch(r"#?(?:72|0x0*48)", _operands(returned[resume - 1])) is not None and
          returned[resume - 1]["Address"] + len(returned[resume - 1]["Bytes"]) == return_pc,
          "ACTUAL_SVC72_RETURN_SITE")
    encoded = json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode("ascii")
    _need(path.read_bytes() == original and disassembly_path.read_bytes() == disassembly, "LATE_ARTIFACT_DRIFT")
    return dict(Elf=str(path), ElfSha256=_sha(original), Consumer=row["Consumer"], Lazy=row["Lazy"],
                Pre=pre, Post=post, CurrentSlot=symbols[SLOT]["Address"], Workers=worker_addresses,
                Stacks=stacks, ReturnPC=return_pc,
                Proof=dict(Symbols=symbols, WorkerStride=stride, FpMechanisms=facts,
                    Vectors=dict(BootSha256=_sha(boot["Data"]), ActiveSha256=_sha(vectors["Data"]),
                                 InitialMSP=words[0], Reset=words[1], SVC=words[11], PendSV=words[14]),
                    DecodedPendSV=decoded, DecodedPendSVSha256=_sha(encoded),
                    Disassembly=dict(Path=str(disassembly_path), Sha256=_sha(disassembly)),
                    ReturnLabel=dict(Address=return_pc, Size=return_symbol["Size"],
                                     Kind=return_symbol["Kind"], Binding=return_symbol["Binding"]),
                    ReturnInstruction=point, DecodedReturn=return_decoded,
                    PreOutsideIT=True, PostOutsideIT=True,
                    Scope="Static ELF/site plan only; not CPU observations, whole-handler parity or source ownership proof"))


def control_tests(image, row):
    """Nine in-memory admission controls per actual ELF; no target execution."""
    state, original_row = deepcopy(image.__dict__), deepcopy(row)
    path = Path(image.path).resolve(strict=True)
    disassembly_path = path.with_suffix(".dis")
    original_elf, original_disassembly = path.read_bytes(), disassembly_path.read_bytes()
    records = []

    def test(name, layer, action, expected_accepted, expected_reason=None):
        accepted, reason, result = True, None, None
        try:
            result = action()
        except RuntimeError as failure:
            accepted, reason = False, str(failure)
        _need(accepted is expected_accepted and reason == expected_reason,
              "CONTROL:" + name + ":" + repr((accepted, reason)))
        records.append(dict(Name=name, Layer=layer, ExpectedAccepted=expected_accepted,
                            ExpectedReason=expected_reason, Accepted=accepted, Reason=reason))
        return result

    def counterfeit():
        result = copy(image)
        _need(result is not image and type(result) is type(image), "CONTROL_CLONE")
        result.__dict__ = deepcopy(state)
        return result

    try:
        baseline = test("actual-image", "end-to-end-planner", lambda: plan(image, row), True)
        for site, operands, reason in (("Pre", "lr,#8", "FP_SAVE_CONDITION"),
                                       ("Post", "r3,#2", "FP_LSPACT_GUARD")):
            changed = counterfeit()
            matches = [i for i in changed.dis if i["Address"] == baseline[site]["Address"]]
            _need(len(matches) == 1, "CONTROL_ANCHOR")
            # Deliberately counterfeit only the decoder's operand text, keeping
            # its byte claim and all ELF/source files unchanged. This exercises
            # the maintained checker through plan(), not a compiled negative.
            matches[0]["Operands"] = operands
            test("wrong-" + site.lower() + "-mask", "checker-through-plan",
                 lambda: plan(changed, row), False, reason)

        code, _, outside = _body(image, "PendSV_Handler")
        for site in ("Pre", "Post"):
            _need(baseline[site]["Width"] == 4, "CONTROL_REQUIRES_WIDE_SITE:" + site)
            interior = baseline[site]["Address"] + 2
            test(site.lower() + "-wide-interior", "point-helper",
                 lambda: _point(code, outside, interior), False,
                 "LAZY_PLAN_SITE_NOT_UNCONDITIONAL_BOUNDARY")

        for name in ("SVC_Handler", "PendSV_Handler", SLOT, "workers"):
            changed = counterfeit()
            _need(len(changed.symbols.get(name, [])) == 1, "CONTROL_SYMBOL:" + name)
            changed.symbols[name].append(deepcopy(changed.symbols[name][0]))
            test("duplicate-" + name, "end-to-end-planner", lambda: plan(changed, row), False,
                 "Missing/duplicate final symbol: " + name)
        _need(len(records) == 9, "CONTROL_COUNT")
    finally:
        _need(image.__dict__ == state and row == original_row, "CONTROL_ORIGINAL_MUTATED")
        _need(path.read_bytes() == original_elf and disassembly_path.read_bytes() == original_disassembly,
              "CONTROL_ARTIFACT_DRIFT")
    return dict(ElfSha256=baseline["ElfSha256"], Controls=records, Count=9, TargetExecutions=0,
                Scope="In-memory actual-Image planner/decoded controls; not compiled or CPU negatives")
