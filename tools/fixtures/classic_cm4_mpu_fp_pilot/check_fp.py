"""Bounded decoded CM4 MPU FP-copy mechanisms, not whole-handler equivalence.

The literal controls follow ARM_CM4_MPU/fiber_port.c and pinned FreeRTOS
a50edad08b29052631aa469d4df6e6ec7ff68878, portable/GCC/ARM_CM4_MPU/port.c.
They are decoded instruction excerpts, not assembled code or CPU executions.

Required image API: body(name), is_data(instruction, name), symbol(name).
Instructions provide Address, Mnemonic and Operands; symbols provide Address.
The real Image.body performs the ELF-byte/disassembly consistency check. The
subject's FPCCR literal must be decoded as in-body data by that same Image.
No files, packages, shell tools or target execution are accessed here.
"""
import re


MUTATION_REASONS = {
    "omit-high-save": "FP_HIGH_SAVE",
    "omit-high-restore": "FP_HIGH_RESTORE",
    "omit-low-save": "FP_LOW_SAVE",
    "omit-low-restore": "FP_LOW_RESTORE",
}

_ALIASES = {"sb": "r9", "sl": "r10", "fp": "r11", "ip": "r12",
            "r13": "sp", "r14": "lr", "r15": "pc"}
_SOFTWARE = "{r3-r11,lr}"
_HARDWARE = "{r4-r11}"
_PSP_HARDWARE = "{r0,r4-r11}"


def _need(value, reason):
    if not value:
        raise RuntimeError(reason)


def _operands(value):
    _need(type(value) is str, "FP_DECODE")
    value = value.split("@", 1)[0].strip().lower()
    value = re.sub(r"\b(?:sb|sl|fp|ip|r13|r14|r15)\b",
                   lambda m: _ALIASES[m[0]], value)
    value = re.sub(r"\s+", "", value)
    value = re.sub(r"#(-?(?:0x[0-9a-f]+|[0-9]+))",
                   lambda m: "#" + str(int(m[1], 16 if "x" in m[1] else 10)), value)

    def registers(match):
        result = []
        for part in match[1].split(","):
            span = re.fullmatch(r"([rs])(\d+)-\1(\d+)", part)
            if span:
                begin, end = int(span[2]), int(span[3])
                _need(begin <= end <= 31, "FP_DECODE")
                result.extend(span[1] + str(n) for n in range(begin, end + 1))
            else:
                _need(re.fullmatch(r"(?:[rs]\d+|sp|lr|pc)", part), "FP_DECODE")
                result.append(part)
        return "{" + ",".join(result) + "}"

    value = re.sub(r"\{([^{}]+)\}", registers, value)
    return re.sub(r"\[(r\d+|sp|lr|pc)\]", r"[\1,#0]", value)


def _key(instruction):
    _need(type(instruction.get("Mnemonic")) is str, "FP_DECODE")
    mnemonic = re.sub(r"\.(?:w|n)$", "", instruction["Mnemonic"].lower())
    mnemonic = {"stm": "stmia", "ldm": "ldmia"}.get(mnemonic, mnemonic)
    operands = _operands(instruction.get("Operands"))
    if mnemonic == "ldmia" and operands.startswith("sp!,"):
        mnemonic, operands = "pop", operands[4:]
    elif mnemonic == "stmdb" and operands.startswith("sp!,"):
        mnemonic, operands = "push", operands[4:]
    if mnemonic in ("add", "sub", "addeq", "subeq"):
        short = re.fullmatch(r"(r\d+|sp),(#-?\d+)", operands)
        if short:
            operands = short[1] + "," + operands
    return mnemonic, operands


def _is(instruction, mnemonic, operands):
    return _key(instruction) == _key({"Mnemonic": mnemonic, "Operands": operands})


def _expect(code, index, mnemonic, operands, reason):
    _need(0 <= index < len(code) and _is(code[index], mnemonic, operands), reason)


def _only(code, mnemonic, operands, reason, after=-1):
    found = [i for i, instruction in enumerate(code)
             if i > after and _is(instruction, mnemonic, operands)]
    _need(len(found) == 1, reason)
    return found[0]


def _target(instruction, reason):
    text = instruction["Operands"].split("@", 1)[0].strip().lower()
    match = re.match(r"(?:0x)?([0-9a-f]+)(?:\s|<|$)", text)
    _need(match is not None, reason)
    return int(match[1], 16)


def _image_body(image, name):
    try:
        raw = list(image.body(name))
        entry = image.symbol(name)["Address"] & ~1
        code = [i for i in raw if not image.is_data(i, name)]
        data = {i["Address"]: i for i in raw if image.is_data(i, name)}
        addresses = [i["Address"] for i in raw]
        _need(code and code[0]["Address"] == entry and
              all(type(a) is int for a in addresses) and
              addresses == sorted(set(addresses)), "FP_BODY")
        for instruction in raw:
            _key(instruction)
        return code, data
    except Exception as error:
        if isinstance(error, RuntimeError) and str(error).startswith("FP_"):
            raise
        raise RuntimeError("FP_BODY") from None


def _subject_psp(code, raw):
    # The C preflight temporarily reuses r0. Its actual bounded assembly
    # snapshot must restore the entry PSP before the FP-address calculation.
    reason = "FP_PSP_SOURCE"
    _need(raw == 15, reason)
    expected = {
        0: ("mrs", "r0,psp"), 1: ("isb", "sy"),
        3: ("ldr", "r1,[r1]"), 4: ("cmp", "r1,#0"),
        6: ("push", "{r0,r1,r2,lr}"), 7: ("mov", "r2,lr"),
        8: ("mov", "r3,r0"), 9: ("mov", "r0,r1"),
        10: ("mov", "r1,r3"), 12: ("pop", "{r0,r1,r2,lr}"),
        13: ("mov", "r2,r1"), 14: ("ldr", "r1,[r2]"),
    }
    for index, (mnemonic, operands) in expected.items():
        _expect(code, index, mnemonic, operands, reason)
    _need(_key(code[2])[0] == "ldr" and
          re.fullmatch(r"r1,\[pc,#-?\d+\]", _key(code[2])[1]) and
          _key(code[5])[0] == "beq" and _key(code[11])[0] == "bl", reason)


def _lspact(image, code, data, saved, restored):
    reason = "FP_LSPACT_GUARD"
    test = _only(code, "tst", "r3,#1", reason)
    _need(saved < test - 2 and test + 1 < restored, reason)
    _expect(code, test - 1, "ldr", "r3,[r3]", reason)
    literal = code[test - 2]
    mnemonic, operands = _key(literal)
    match = re.fullmatch(r"r3,\[pc,#(-?\d+)\]", operands)
    _need(mnemonic == "ldr" and match is not None, "FP_LSPACT_ADDRESS")
    address = ((literal["Address"] + 4) & ~3) + int(match[1])
    word = data.get(address)
    _need(word is not None and _key(word) == (".word", "0xe000ef34"),
          "FP_LSPACT_ADDRESS")
    _need(_key(code[test + 1])[0] == "bne", reason)
    calls = [i for i in range(saved + 1, restored) if _key(code[i])[0] == "bl"]
    _need(calls and test + 1 < calls[0], reason)
    target = _target(code[test + 1], reason)
    found = [i for i, instruction in enumerate(code) if instruction["Address"] == target]
    _need(len(found) == 1, "FP_LSPACT_PANIC")
    panic = found[0]
    _expect(code, panic, "movs", "r0,#69", "FP_LSPACT_PANIC")
    _need(panic + 2 < len(code) and _key(code[panic + 1])[0] == "bl" and
          _key(code[panic + 2])[0] == "b", "FP_LSPACT_PANIC")
    try:
        panic_entry = image.symbol("fiber_panic")["Address"] & ~1
    except Exception:
        raise RuntimeError("FP_LSPACT_PANIC") from None
    _need(_target(code[panic + 1], "FP_LSPACT_PANIC") == panic_entry and
          _target(code[panic + 2], "FP_LSPACT_PANIC") == target, "FP_LSPACT_PANIC")
    return {"Address": code[test]["Address"], "Fpccr": 0xE000EF34,
            "Mask": 1, "Reject": "nonzero -> fiber_panic('E') before scheduler call"}


def _check(image, subject):
    name = "PendSV_Handler" if subject else "xPortPendSVHandler"
    code, data = _image_body(image, name)
    raw = _only(code, "mrs", "r3,control", "FP_RAW_CONTROL_ORDER")
    stores = [i for i, instruction in enumerate(code)
              if _key(instruction)[0].startswith("vstm")]
    _need(stores and raw < stores[0], "FP_RAW_CONTROL_ORDER")
    psp = _only(code, "mrs", "r0,psp", "FP_PSP_SOURCE")
    if subject:
        _need(psp == 0 and psp < raw, "FP_PSP_SOURCE")
        _subject_psp(code, raw)
        add = raw + 1
    else:
        _need(psp == raw + 1, "FP_PSP_SOURCE")
        _expect(code, psp + 1, "isb", "sy", "FP_PSP_SOURCE")
        add = raw + 3
    _expect(code, add, "add", "r0,r0,#32", "FP_PSP_OFFSET")
    _expect(code, add + 1, "tst", "lr,#16", "FP_SAVE_CONDITION")
    _expect(code, add + 2, "ittt", "eq", "FP_SAVE_CONDITION")
    high, low_load, low = add + 3, add + 4, add + 5
    _expect(code, high, "vstmiaeq", "r1!,{s16-s31}", "FP_HIGH_SAVE")
    _expect(code, low_load, "vldmiaeq", "r0,{s0-s16}", "FP_LOW_LOAD")
    _expect(code, low, "vstmiaeq", "r1!,{s0-s16}", "FP_LOW_SAVE")

    # Deliberately not a whole-path whitelist: an extra FPSCR overwrite after
    # the legitimate triplet retains these mechanisms and needs a payload oracle.
    back = _only(code, "sub", "r0,r0,#32", "FP_PSP_OFFSET", after=low)
    _expect(code, back + 1, "stmia", "r1!," + _SOFTWARE, "FP_BASIC_SAVE")
    _expect(code, back + 2, "ldmia", "r0," + _HARDWARE, "FP_BASIC_SAVE")
    _expect(code, back + 3, "stmia", "r1!," + _PSP_HARDWARE, "FP_BASIC_SAVE")
    saved = back + 4
    _expect(code, saved, "str", "r1,[r2]", "FP_SAVE_CURSOR")

    restore = _only(code, "ldmdb", "r1!," + _PSP_HARDWARE,
                    "FP_BASIC_RESTORE", after=saved)
    _expect(code, restore - 1, "ldr", "r1,[r2]", "FP_RESTORE_CURSOR")
    _expect(code, restore + 1, "msr", "psp,r0", "FP_BASIC_RESTORE")
    _expect(code, restore + 2, "stmia", "r0!," + _HARDWARE, "FP_BASIC_RESTORE")
    _expect(code, restore + 3, "ldmdb", "r1!," + _SOFTWARE, "FP_CONTROL_RESTORE")
    _expect(code, restore + 4, "msr", "control,r3", "FP_CONTROL_RESTORE")
    gate = restore + 5
    if subject:
        _expect(code, gate, "isb", "sy", "FP_CONTROL_RESTORE")
        gate += 1
    _expect(code, gate, "tst", "lr,#16", "FP_RESTORE_CONDITION")
    _expect(code, gate + 1, "ittt", "eq", "FP_RESTORE_CONDITION")
    _expect(code, gate + 2, "vldmdbeq", "r1!,{s0-s16}", "FP_LOW_RESTORE_LOAD")
    _expect(code, gate + 3, "vstmiaeq", "r0!,{s0-s16}", "FP_LOW_RESTORE")
    _expect(code, gate + 4, "vldmdbeq", "r1!,{s16-s31}", "FP_HIGH_RESTORE")
    _expect(code, gate + 5, "str", "r1,[r2]", "FP_RESTORE_CURSOR")
    tail = gate + 6
    if subject:
        for offset, (mnemonic, operands) in enumerate(
                (("cpsie", "i"), ("dsb", "sy"), ("isb", "sy"))):
            _expect(code, tail + offset, mnemonic, operands, "FP_RETURN")
        tail += 3
    _expect(code, tail, "bx", "lr", "FP_RETURN")

    facts = {
        "RawControlBeforeVstm": {"Address": code[raw]["Address"], "Register": "r3"},
        "PspLowFrameOffset": {"PspCapture": code[psp]["Address"],
                              "Add": code[add]["Address"], "Bytes": 32,
                              "Subtract": code[back]["Address"]},
        "ExtendedSaveGate": {"Address": code[add + 1]["Address"],
                             "ExcReturnMask": 16, "Condition": "EQ", "ItSlots": 3},
        "HighFpSave16": {"Address": code[high]["Address"], "Words": 16,
                         "Destination": "r1!"},
        "LowFpRawSave17": {"Load": code[low_load]["Address"],
                           "Store": code[low]["Address"], "Words": 17,
                           "Includes": "s0-s15 and raw FPSCR via s16"},
        "BasicSaveAndCursor": {"Address": code[back + 1]["Address"],
                               "SoftwareWords": 10, "HardwareWords": 8, "PspWords": 1,
                               "BasicCursorWord": 19, "ExtendedCursorWord": 52,
                               "Store": code[saved]["Address"]},
        "BasicRestoreInverse": {"Address": code[restore]["Address"],
                                "HardwareDestination": "r0!", "PspWrittenBeforeCopy": True},
        "ControlRestore": {"Address": code[restore + 4]["Address"], "Register": "r3"},
        "ExtendedRestoreGate": {"Address": code[gate]["Address"],
                                "ExcReturnMask": 16, "Condition": "EQ", "ItSlots": 3},
        "LowFpRawRestore17": {"Load": code[gate + 2]["Address"],
                              "Store": code[gate + 3]["Address"], "Words": 17,
                              "Destination": "r0! after eight basic-frame words"},
        "HighFpRestore16": {"Address": code[gate + 4]["Address"], "Words": 16},
        "CursorResetAndReturn": {"Store": code[gate + 5]["Address"],
                                 "Return": code[tail]["Address"], "CursorWord": 0},
    }
    if subject:
        facts["PostCopyLspactGuard"] = _lspact(image, code, data, saved, restore)
    return {
        "Role": "subject" if subject else "reference", "Symbol": name,
        "Count": len(facts), "Facts": facts,
        "Scope": "Ordered emitted FP-copy mechanisms only; not whole-handler semantic or byte equivalence",
        "PolicyDifference": "Pinned reference configures always-lazy outside this checker; subject policy is observed separately",
        "Limits": ["No CPU execution, payload-integrity or whole-path control-flow proof",
                   "Backing allocation, helper closure and MPU policy are checked elsewhere",
                   "Additional writes after the legitimate FP copy require the runtime payload oracle"],
    }


def check_subject(image):
    return _check(image, True)


def check_reference(image):
    return _check(image, False)


def _fixture_rows(subject):
    # Literal excerpts from the two cited handler bodies. Address assignment
    # below is synthetic and does not encode Thumb instructions.
    if subject:
        rows = [("mrs", "r0,psp"), ("isb", "sy"), ("ldr", "r1,[pc,#0]"),
                ("ldr", "r1,[r1]"), ("cmp", "r1,#0"), ("beq", "@panicJ"),
                ("push", "{r0,r1,r2,lr}"), ("mov", "r2,lr"), ("mov", "r3,r0"),
                ("mov", "r0,r1"), ("mov", "r1,r3"), ("bl", "2800 <preflight>"),
                ("pop", "{r0,r1,r2,lr}"), ("mov", "r2,r1"), ("ldr", "r1,[r2]"),
                ("mrs", "r3,control")]
    else:
        rows = [("ldr", "r3,[pc,#0]"), ("ldr", "r2,[r3]"), ("ldr", "r1,[r2]"),
                ("mrs", "r3,control"), ("mrs", "r0,psp"), ("isb", "sy")]
    rows += [("add", "r0,r0,#32"), ("tst", "lr,#16"), ("ittt", "eq"),
             ("vstmiaeq", "r1!,{s16-s31}"), ("vldmiaeq", "r0,{s0-s16}"),
             ("vstmiaeq", "r1!,{s0-s16}"), ("sub", "r0,r0,#32"),
             ("stmia", "r1!," + _SOFTWARE), ("ldmia", "r0," + _HARDWARE),
             ("stmia", "r1!," + _PSP_HARDWARE), ("str", "r1,[r2]")]
    if subject:
        rows += [("ldr", "r3,@fpccr"), ("ldr", "r3,[r3]"), ("tst", "r3,#1"),
                 ("bne", "@panicE")]
    rows += [("mov", "r0,#128"), ("msr", "basepri,r0"), ("bl", "3000 <scheduler>"),
             ("mov", "r0,#0"), ("msr", "basepri,r0"),
             ("ldr", "r1,[r2]"), ("ldmdb", "r1!," + _PSP_HARDWARE),
             ("msr", "psp,r0"), ("stmia", "r0!," + _HARDWARE),
             ("ldmdb", "r1!," + _SOFTWARE), ("msr", "control,r3")]
    if subject:
        rows += [("isb", "sy")]
    rows += [("tst", "lr,#16"), ("ittt", "eq"), ("vldmdbeq", "r1!,{s0-s16}"),
             ("vstmiaeq", "r0!,{s0-s16}"), ("vldmdbeq", "r1!,{s16-s31}"),
             ("str", "r1,[r2]")]
    if subject:
        rows += [("cpsie", "i"), ("dsb", "sy"), ("isb", "sy")]
    rows += [("bx", "lr")]
    if subject:
        rows += ["panicJ:", ("movs", "r0,#106"), ("bl", "2000 <fiber_panic>"),
                 ("b", "@panicJ"), "panicE:", ("movs", "r0,#69"), ("bl", "2000 <fiber_panic>"),
                 ("b", "@panicE")]
    return rows


class _Fixture:
    def __init__(self, subject, rows, fpccr=0xE000EF34):
        name = "PendSV_Handler" if subject else "xPortPendSVHandler"
        self.name, self.code, self.data = name, [], set()
        labels, address = {}, 0x1000
        for row in rows:
            if isinstance(row, str):
                labels[row[:-1]] = address
            else:
                address += 4
        literal = (address + 15) & ~15
        address = 0x1000
        for row in rows:
            if isinstance(row, str):
                continue
            mnemonic, operands = row
            if operands == "r3,@fpccr":
                operands = "r3,[pc,#" + str(literal - ((address + 4) & ~3)) + "]"
            elif operands.startswith("@"):
                operands = format(labels[operands[1:]], "x") + " <local>"
            self.code.append(dict(Address=address, Mnemonic=mnemonic, Operands=operands))
            address += 4
        if subject:
            self.code.append(dict(Address=literal, Mnemonic=".word", Operands=hex(fpccr)))
            self.data.add(literal)

    def body(self, name):
        _need(name == self.name, "FP_SELF_CONTROL_FIXTURE")
        return self.code

    def is_data(self, instruction, name):
        _need(name == self.name, "FP_SELF_CONTROL_FIXTURE")
        return instruction["Address"] in self.data

    def symbol(self, name):
        _need(name in (self.name, "fiber_panic"), "FP_SELF_CONTROL_FIXTURE")
        return {"Address": 0x2001 if name == "fiber_panic" else 0x1001}


def _edit(rows, before, after, occurrence=0):
    positions = [i for i, row in enumerate(rows) if row == before]
    _need(len(positions) > occurrence, "FP_SELF_CONTROL_FIXTURE")
    rows[positions[occurrence]] = after


def self_controls():
    """Pure literal decoded controls; never an ELF, build or execution claim."""
    controls = []

    def test(name, subject, rows, expected=None, fpccr=0xE000EF34):
        actual = None
        try:
            result = _check(_Fixture(subject, rows, fpccr), subject)
            _need(result["Count"] == (13 if subject else 12), "FP_SELF_CONTROL_COUNT")
        except RuntimeError as error:
            actual = str(error)
        _need(actual == expected, "FP_SELF_CONTROL:" + name + ":" + str(actual))
        controls.append(dict(Name=name, Role="subject" if subject else "reference",
                             Accepted=actual is None, ExpectedReason=expected, ActualReason=actual))

    mutations = [
        ("omit-high-save", ("vstmiaeq", "r1!,{s16-s31}"), ("addeq", "r1,r1,#64"), "FP_HIGH_SAVE", 0),
        ("omit-high-restore", ("vldmdbeq", "r1!,{s16-s31}"), ("subeq", "r1,r1,#64"), "FP_HIGH_RESTORE", 0),
        ("omit-low-save", ("vstmiaeq", "r1!,{s0-s16}"), ("addeq", "r1,r1,#68"), "FP_LOW_SAVE", 0),
        ("omit-low-restore", ("vstmiaeq", "r0!,{s0-s16}"), ("addeq", "r0,r0,#68"), "FP_LOW_RESTORE", 0),
        ("low-load-count", ("vldmiaeq", "r0,{s0-s16}"), ("vldmiaeq", "r0,{s0-s15}"), "FP_LOW_LOAD", 0),
        ("high-save-count", ("vstmiaeq", "r1!,{s16-s31}"), ("vstmiaeq", "r1!,{s16-s30}"), "FP_HIGH_SAVE", 0),
        ("high-save-condition", ("vstmiaeq", "r1!,{s16-s31}"), ("vstmia", "r1!,{s16-s31}"), "FP_HIGH_SAVE", 0),
        ("save-bit4", ("tst", "lr,#16"), ("tst", "lr,#8"), "FP_SAVE_CONDITION", 0),
        ("save-it-count", ("ittt", "eq"), ("itt", "eq"), "FP_SAVE_CONDITION", 0),
        ("low-address", ("add", "r0,r0,#32"), ("add", "r0,r0,#28"), "FP_PSP_OFFSET", 0),
        ("basic-return-address", ("sub", "r0,r0,#32"), ("sub", "r0,r0,#28"), "FP_PSP_OFFSET", 0),
        ("basic-save-writeback", ("ldmia", "r0," + _HARDWARE), ("ldmia", "r0!," + _HARDWARE), "FP_BASIC_SAVE", 0),
        ("software-save-count", ("stmia", "r1!," + _SOFTWARE), ("stmia", "r1!,{r3,r5-r11,lr}"), "FP_BASIC_SAVE", 0),
        ("save-cursor", ("str", "r1,[r2]"), ("str", "r1,[r2,#4]"), "FP_SAVE_CURSOR", 0),
        ("restore-psp", ("msr", "psp,r0"), ("msr", "psp,r4"), "FP_BASIC_RESTORE", 0),
        ("basic-restore-writeback", ("stmia", "r0!," + _HARDWARE), ("stmia", "r0," + _HARDWARE), "FP_BASIC_RESTORE", 0),
        ("control-restore", ("msr", "control,r3"), ("msr", "control,r4"), "FP_CONTROL_RESTORE", 0),
        ("restore-bit4", ("tst", "lr,#16"), ("tst", "lr,#8"), "FP_RESTORE_CONDITION", 1),
        ("restore-cursor", ("str", "r1,[r2]"), ("str", "r1,[r2,#4]"), "FP_RESTORE_CURSOR", 1),
    ]
    for subject in (True, False):
        prefix = "subject-" if subject else "reference-"
        test(prefix + "positive", subject, _fixture_rows(subject))
        for name, before, after, reason, occurrence in mutations:
            rows = _fixture_rows(subject)
            _edit(rows, before, after, occurrence)
            test(prefix + name, subject, rows, reason)
        rows = _fixture_rows(subject)
        raw = rows.index(("mrs", "r3,control"))
        high = rows.index(("vstmiaeq", "r1!,{s16-s31}"))
        rows[raw], rows[high] = rows[high], rows[raw]
        test(prefix + "raw-control-after-vstm", subject, rows, "FP_RAW_CONTROL_ORDER")
        rows = _fixture_rows(subject)
        low = rows.index(("vldmdbeq", "r1!,{s0-s16}"))
        high = rows.index(("vldmdbeq", "r1!,{s16-s31}"))
        rows[low], rows[high] = rows[high], rows[low]
        test(prefix + "reverse-low-high-order", subject, rows, "FP_LOW_RESTORE_LOAD")
        rows = _fixture_rows(subject)
        at = rows.index(("vstmiaeq", "r1!,{s0-s16}")) + 1
        rows[at:at] = [("itt", "eq"), ("movweq", "r12,#0"), ("streq", "r12,[r1,#-4]")]
        test(prefix + "extra-fpscr-write-mechanisms-only", subject, rows)

    for name, before, after, reason in [
            ("psp-snapshot-pop", ("pop", "{r0,r1,r2,lr}"), ("nop", ""), "FP_PSP_SOURCE"),
            ("lspact-bit", ("tst", "r3,#1"), ("tst", "r3,#2"), "FP_LSPACT_GUARD"),
            ("lspact-reject", ("bne", "@panicE"), ("beq", "@panicE"), "FP_LSPACT_GUARD"),
            ("lspact-read", ("ldr", "r3,[r3]"), ("nop", ""), "FP_LSPACT_GUARD"),
            ("lspact-panic", ("movs", "r0,#69"), ("movs", "r0,#70"), "FP_LSPACT_PANIC")]:
        rows = _fixture_rows(True)
        _edit(rows, before, after)
        test(name, True, rows, reason)
    test("lspact-address", True, _fixture_rows(True), "FP_LSPACT_ADDRESS", 0xE000EF38)
    for push, pop in ((False, True), (True, False), (True, True)):
        rows = _fixture_rows(True)
        if push:
            _edit(rows, ("push", "{r0,r1,r2,lr}"), ("stmdb.w", "sp!,{r0,r1,r2,lr}"))
        if pop:
            _edit(rows, ("pop", "{r0,r1,r2,lr}"), ("ldmia.w", "sp!,{r0,r1,r2,lr}"))
        test("sp-alias-" + str(push) + str(pop), True, rows)
    for name, mnemonic, operands in (("no-writeback", "ldmia.w", "sp,{r0,r1,r2,lr}"),
            ("wrong-base", "ldmia.w", "r3!,{r0,r1,r2,lr}"),
            ("wrong-mode", "ldmdb.w", "sp!,{r0,r1,r2,lr}"),
            ("missing-register", "ldmia.w", "sp!,{r0,r1,lr}"),
            ("pc-not-lr", "ldmia.w", "sp!,{r0,r1,r2,pc}")):
        rows = _fixture_rows(True)
        _edit(rows, ("pop", "{r0,r1,r2,lr}"), (mnemonic, operands))
        test("sp-alias-" + name, True, rows, "FP_PSP_SOURCE")
    return {"Controls": controls,
            "Scope": "Synthetic source-derived decoded excerpts only; no actual ELF, CPU execution or payload-integrity proof. Extra FPSCR writes deliberately retain mechanism PASS."}
