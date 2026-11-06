"""Pure fixed-CM3 supported port-policy checks; no I/O or dynamic imports.

Caller authentication and compiler-command provenance are separate obligations.
The instruction census binds disassembly bytes, rejects explicitly enumerated
forms, and uses the supplied frozen reader's Thumb width/mapping primitives.
It is not an independent decoder or complete instruction-semantics proof.
"""

import hashlib
import re
import struct


class Rejected(ValueError):
    pass


def need(condition, detail):
    if not condition:
        raise Rejected("REJECT:CM3-LTO-PORT-POLICY:" + detail)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


RAW_FLAGS = ("-finstrument-functions", "-fstack-protector-all", "-fprofile-arcs",
             "-ftest-coverage", "-fsanitize=undefined", "-fsanitize-coverage=trace-pc")
COUNTER_FLAGS = ("-fno-instrument-functions", "-fno-stack-protector", "-fno-profile-arcs",
                 "-fno-test-coverage", "-fno-sanitize=all", "-fno-sanitize-coverage=trace-pc",
                 "-mgeneral-regs-only")
ROLES = ("runtime", "boot", "exception")
PRIVATE = ("fiber_port_context_cohort_armv7m_p0x434D3033u_l0x00010001u_"
           "f0_e0_h1_j1_v1_d0_r0_z8u_y0_w2_g4_u00010000_i0_"
           "o0xFFFFFFFDu_c0_s0_x0_m0_a0_b0_t0_n0_k0_q0")
STORAGE = "fiber_port_storage_cohort_arm_cm3_v1_r0"
FORWARD = ("fiber_port_context_init", "fiber_port_runtime_memory_barrier", "fiber_port_panic_wait",
           "fiber_port_require_scheduler_configuration_environment", "fiber_port_runtime_prepare_start",
           "fiber_port_runtime_select_first", "fiber_port_runtime_start_first", "fiber_port_runtime_schedule")
NAKED = ("fiber_port_start_first_context", "SVC_Handler", "PendSV_Handler")
RUNTIME = ("fiber_port_init_context_frame", "fiber_port_panic_wait",
           "fiber_port_require_scheduler_configuration_environment", "fiber_port_runtime_memory_barrier",
           "fiber_port_runtime_prepare_start", "fiber_port_runtime_schedule", "fiber_port_runtime_select_first",
           "fiber_port_runtime_start_first", "fiber_port_scheduler_pick_first_from_start",
           "fiber_port_scheduler_pick_next_from_pendsv", *NAKED)
BOOT = ("fiber_fallback_initial_msp", "fiber_port_runtime_prepare", "fiber_port_boot_prepare_msp_for_start",
        "fiber_port_boot_record_compute_hash", "fiber_port_boot_record_fast_check", "fiber_port_boot_record_check",
        "fiber_port_boot_create", "fiber_port_boot_check", "fiber_port_require_start_environment",
        "fiber_port_context_init", "fiber_port_context_validate_save_current", "fiber_port_context_validate_restore",
        "fiber_port_context_prepare_first_start", "fiber_port_require_start_interrupt_state")
EXCEPTION = ("fiber_exception_runtime_check", "fiber_pendsv_init_lowest_priority")
LOCAL = ("fiber_port_capture_scheduler_cpu_state", "fiber_port_validate_scheduler_cpu_state",
         "fiber_port_boot_simple_check", "fiber_port_prepare_start_msp_plan", "fiber_port_validate_start_msp_for_boot",
         "fiber_port_validate_context_pointer", "fiber_boot_hash32_accum", "fiber_port_validate_stack_canary",
         "fiber_port_capture_validation_cpu_state", "fiber_port_validate_validation_cpu_state",
         "fiber_port_fallback_initial_msp_checked", "fiber_require_privileged_thread_msp",
         "fiber_validate_vector_entry", "fiber_validate_pendsv_priority", "fiber_validate_svc_priority",
         "fiber_probe_implemented_priority_mask", "fiber_count_implemented_priority_bits",
         "fiber_validate_basepri_priority_mask", "fiber_validate_priority_grouping", "fiber_validate_feature_policy")
UNDEFINED = ("fiber_addr_plausible_code", "fiber_addr_plausible_ram", "fiber_panic",
             "fiber_internal_runtime_current_context_slot", "fiber_internal_runtime_port_abi_v1_anchor",
             "fiber_internal_runtime_select_scheduler_candidate", "fiber_internal_runtime_publish_current_context",
             "fiber_internal_runtime_require_current_context", "fiber_internal_task_return", "memcpy", "memset")
FINAL_WORKER_UNDEFINED = ("__pilot_ram_begin", "__pilot_ram_end", "__pilot_text_begin", "__pilot_text_end")
FORBIDDEN = re.compile(r"^(?:__cyg_profile|__stack_chk|__gcov|__ubsan|__asan|__tsan|__sanitizer|"
                       r"__gnu_mcount|mcount$|_mcount$|__aeabi_|__(?:add|sub|mul|div|neg|cmp|eq|ne|lt|le|gt|ge|"
                       r"unord|extend|trunc|float|fix).*(?:sf|df|tf))")
FORBIDDEN_FORMS = (
    "32-bit first halfword EC00..EFFF or FC00..FFFF (conservative coprocessor/FP/MVE domains)",
    "v-prefixed mnemonic; cdp/mrc/mcr/mrrc/mcrr/ldc/stc mnemonic families",
    "MVE tail-predication dlstp/wlstp/letp/lctp mnemonics",
    "explicit S0..S31/D0..D31/Q0..Q15 register operands",
)


def supported_flags(original):
    need(type(original) is list and all(type(x) is str for x in original), "original argv flags")
    need(all(original.count(x) == 1 for x in ("-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft",
                                             "-O2", "-flto", "-fno-fat-lto-objects")), "fixed slim CM3/O2 target")
    need(not any(x in original for x in RAW_FLAGS + COUNTER_FLAGS), "new policy appended once")
    result = list(original) + list(RAW_FLAGS) + list(COUNTER_FLAGS)
    require_effective_options(result, supported=True)
    return result


def require_effective_options(argv, *, supported):
    need(type(supported) is bool and type(argv) is list and argv
         and all(type(x) is str and x and "\x00" not in x for x in argv), "effective argv schema")
    need(all(x in argv for x in ("-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft", "-O2")), "effective target")
    for arg in argv:
        need(not arg.startswith("-O") or arg == "-O2", "foreign optimization")
        need(not arg.startswith("-mcpu=") or arg == "-mcpu=cortex-m3", "foreign CPU")
        need(not arg.startswith("-mfloat-abi=") or arg == "-mfloat-abi=soft", "foreign float ABI")
        need(not arg.startswith("-mfpu="), "foreign FPU")
        need(not arg.startswith("-mno-general-regs-only"), "general-register policy disabled")
        need(not arg.startswith(("-finstrument-functions-exclude-", "-fno-lto", "-ffat-lto-objects")),
             "unsupported compiler override")
        if arg.startswith(("-finstrument-functions", "-fstack-protector", "-fprofile-arcs", "-ftest-coverage",
                           "-fsanitize", "-fno-instrument", "-fno-stack-protector", "-fno-profile",
                           "-fno-test-coverage", "-fno-sanitize")):
            need(arg in RAW_FLAGS + COUNTER_FLAGS, "unclassified stress/policy option")
    if supported:
        need(all(x in argv for x in COUNTER_FLAGS), "all seven supported counters")
        # GCC groups target options ahead of -f options in actual lto1 argv.
        # Only the six counter-options have ordering relationships here.
        positions = [max(i for i, x in enumerate(argv) if x == flag) for flag in COUNTER_FLAGS[:-1]]
        need(positions == sorted(positions), "supported counter order")
        for positive, negative in zip(RAW_FLAGS, COUNTER_FLAGS):
            last = positions[COUNTER_FLAGS.index(negative)]
            need(all(i < last for i, x in enumerate(argv) if x == positive), "positive option overrides policy")
    else:
        need(all(x in argv for x in RAW_FLAGS), "six uncancelled raw flags")
        need(not any(x in argv for x in COUNTER_FLAGS[:-1]), "raw stress has policy cancellation")
    return dict(SupportedPolicy=supported, EffectiveOptionsVerified=True,
                RawPresent=[x for x in RAW_FLAGS if x in argv],
                CanonicalizedRawAbsent=[x for x in RAW_FLAGS if x not in argv],
                Counters=list(COUNTER_FLAGS) if supported else [], AttributeEffectsValidated=False)


def inspect_ir_definitions(rows_by_role):
    """Rows are complete plugin-NM records: Name, Kind, Value=0, Size=None."""
    need(type(rows_by_role) is dict and set(rows_by_role) == set(ROLES), "three ordered provider roles")
    expected = {"runtime": {name: "T" for name in RUNTIME}, "boot": {name: "T" for name in BOOT},
                "exception": {name: "T" for name in EXCEPTION}}
    expected["runtime"].update({PRIVATE: "D", STORAGE: "D"})
    expected["boot"]["fiber_fallback_initial_msp"] = "W"
    rows, seen = [], set()
    for role in ROLES:
        records = rows_by_role[role]
        need(type(records) is list, "IR definition rows")
        actual = {}
        for row in records:
            need(type(row) is dict and set(row) == {"Name", "Kind", "Value", "Size"}
                 and type(row["Name"]) is str and type(row["Kind"]) is str
                 and type(row["Value"]) is int and row["Value"] == 0 and row["Size"] is None,
                 "raw plugin definition schema")
            need(row["Name"] not in actual and row["Name"] not in seen, "unique IR provider definition")
            actual[row["Name"]] = row["Kind"]
            seen.add(row["Name"])
            rows.append(dict(Role=role, **row))
        need(actual == expected[role], "source-derived IR definition surface: " + role)
    return dict(IRDefinitionsValidated=True, Definitions=rows, PublicFunctions=29, CohortObjects=2,
                OriginalTranslationUnitMachineOwnership=False)


def stress_source(attributes):
    pair = attributes.stress_sources()
    need(type(pair) is dict and type(pair.get("Unprotected")) is bytes
         and pair.get("Function") == "ctxrt_attribute_stress", "fixed ordinary stress source")
    return dict(Source=pair["Unprotected"], Function=pair["Function"], SourceSha256=sha(pair["Unprotected"]),
                RequiredFamilies=pair["RequiredFamilies"], SourceAnnotationDifference=False)


def _disassembly(raw, image):
    need(type(raw) is bytes and raw, "actual disassembly bytes")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise Rejected("REJECT:CM3-LTO-PORT-POLICY:disassembly encoding") from error
    result, section = {}, None
    for line in lines:
        heading = re.fullmatch(r"Disassembly of section (.+):", line)
        if heading:
            need(image.names.count(heading[1]) == 1, "disassembly section identity")
            section = image.names.index(heading[1])
            continue
        address = re.match(r"^\s*([0-9a-fA-F]+):\s+(.*)$", line)
        if address is None or section is None:
            continue
        if re.fullmatch(r"R_ARM_[A-Z0-9_]+\s+.+", address[2]):
            continue  # Actual REL authority below is the ELF, not this printout.
        row = re.fullmatch(r"([0-9a-fA-F]{8}|[0-9a-fA-F]{4}(?:\s+[0-9a-fA-F]{4})?)\s+"
                           r"([.]?[a-zA-Z][a-zA-Z0-9_.]*)(?:\s+(.*))?", address[2])
        need(row is not None, "unclassified disassembly address row")
        words = row[1].split()
        data = (struct.pack("<I", int(words[0], 16)) if len(words) == 1 and len(words[0]) == 8 else
                b"".join(struct.pack("<H", int(word, 16)) for word in words))
        op = re.sub(r"\.[nw]$", "", row[2].lower())
        operand_text = row[3] or ""
        # Wide objdump places a relocation after the instruction operands.
        # Its printed address must agree; the ELF remains REL authority below.
        note = re.search(r"\t([0-9a-fA-F]+):\s+R_ARM_", operand_text)
        if note is not None:
            printed = re.fullmatch(r"([0-9a-fA-F]+):\s+R_ARM_[A-Z0-9_]+\s+\S+",
                                   operand_text[note.start() + 1:])
            need(printed is not None and int(printed[1], 16) == int(address[1], 16),
                 "inline relocation printout address/grammar")
            operand_text = operand_text[:note.start()]
        operands = re.split(r"[;@]", operand_text)[0].strip()
        key = section, int(address[1], 16)
        need(key not in result, "duplicate disassembly address")
        result[key] = op, operands, data
    return result


def _header(image, core, final):
    need(type(image) is core._ELF and type(image.data) is bytes and image.final is final, "genuine supplied core ELF")
    need(len(image.data) >= 52 and image.data[:7] == b"\x7fELF\x01\x01\x01", "ARM ELF32LE bytes")
    kind, machine, version = struct.unpack_from("<HHI", image.data, 16)
    need((kind, machine, version) == (2 if final else 1, 40, 1)
         and not struct.unpack_from("<I", image.data, 36)[0] & 0x400, "soft ARM ELF kind")
    need(len(image.names) == len(set(image.names)) and not any(name.startswith(".gnu.lto_") for name in image.names),
         "unique machine sections, no IR/fat substitute")


def _symbols(image):
    definitions, functions, undefined = {}, {}, []
    for item in image.symbols:
        need(type(item) is dict and all(type(item.get(x)) is int and item[x] >= 0 for x in ("value", "size", "index"))
             and all(type(item.get(x)) is str for x in ("name", "kind", "binding", "visibility"))
             and type(item.get("section")) in (str, int), "literal symbol metadata")
        name = item["name"]
        need(not FORBIDDEN.search(name), "forbidden runtime/counter symbol: " + name)
        if not name:
            continue
        if item["section"] == "SHN_UNDEF":
            need(item["binding"] == "STB_GLOBAL", "strong undefined dependency")
            undefined.append(name)
            continue
        if item["kind"] in ("STT_FUNC", "STT_OBJECT"):
            need(name not in definitions, "ambiguous definition: " + name)
            definitions[name] = item
        if item["kind"] != "STT_FUNC":
            continue
        section, start, size = item["section"], item["value"] & ~1, item["size"]
        need(type(section) is int and 0 < section < len(image.sections) and size > 0 and size % 2 == 0
             and item["value"] & 1, "positive Thumb function: " + name)
        h = image.sections[section].header
        origin = h.sh_addr if image.final else 0
        need(h.sh_type == "SHT_PROGBITS" and h.sh_flags & 6 == 6 and origin <= start
             and start + size <= origin + h.sh_size and image.mapping(section, start)[0] == "t",
             "function mapping/bounds: " + name)
        for other in functions.values():
            other_start = other["value"] & ~1
            need(section != other["section"] or start + size <= other_start or other_start + other["size"] <= start,
                 "overlapping function/alias: " + name)
        functions[name] = item
    need(len(undefined) == len(set(undefined)), "unique undefined imports")
    need(functions, "nonempty machine function census")
    return definitions, functions, sorted(undefined)


def _forms(op, operands, raw):
    if len(raw) == 4:
        first = struct.unpack_from("<H", raw)[0]
        need(not (0xEC00 <= first <= 0xEFFF or 0xFC00 <= first <= 0xFFFF),
             "forbidden conservative extended-register encoding domain")
    need(not op.startswith("v") and not re.fullmatch(r"(?:cdp|mrc|mcr|mrrc|mcrr|ldc|stc)[a-z0-9.]*", op)
         and op not in ("dlstp", "wlstp", "letp", "lctp"), "forbidden extended-register mnemonic")
    bare = re.sub(r"<[^>]*>", "", operands).lower()
    # Objdump prints direct branch addresses in hexadecimal without 0x.
    # An address such as d0 is not a D-register operand in these forms.
    numeric = r"(?:0x)?[0-9a-f]+"
    if op in ("b", "bl", "beq", "bne", "bcs", "bhs", "bcc", "blo", "bmi", "bpl",
              "bvs", "bvc", "bhi", "bls", "bge", "blt", "bgt", "ble"):
        need(re.fullmatch(r"\s*" + numeric + r"\s*", bare) is not None, "direct branch numeric target")
        bare = ""
    elif op in ("cbz", "cbnz"):
        branch = re.fullmatch(r"\s*(r[0-7])\s*,\s*" + numeric + r"\s*", bare)
        need(branch is not None, "CBZ/CBNZ low register and numeric target")
        bare = branch[1]
    need(not re.search(r"(?<![a-z0-9_])(?:[sd](?:[0-9]|[12][0-9]|3[01])|q(?:[0-9]|1[0-5]))(?![a-z0-9_])", bare),
         "forbidden extended register operand")


def _scan(image, core, disassembly, *, expected_undefined, surface=None, mandatory_locals=False):
    _header(image, core, image.final)
    definitions, functions, undefined = _symbols(image)
    need(undefined == sorted(expected_undefined), "exact generated undefined dependency surface")
    required = ()
    if surface is not None:
        need(type(surface) is dict and surface.get("IRDefinitionsValidated") is True, "validated IR surface required")
        # Revalidate, rather than trust a caller-created success boolean.
        grouped = {role: [] for role in ROLES}
        for row in surface.get("Definitions", []):
            need(type(row) is dict and row.get("Role") in grouped, "IR surface projection row")
            grouped[row["Role"]].append({key: row[key] for key in ("Name", "Kind", "Value", "Size")})
        surface = inspect_ir_definitions(grouped)
        required = tuple(row["Name"] for row in surface["Definitions"])
        for row in surface["Definitions"]:
            name = row["Name"]
            need(name in definitions and definitions[name]["kind"] == ("STT_OBJECT" if row["Kind"] == "D" else "STT_FUNC"),
                 "IR provider retained with kind: " + name)
        for name in FORWARD + NAKED:
            need(functions[name]["binding"] == "STB_GLOBAL", "strong mandatory ABI/handler: " + name)
        if mandatory_locals:
            need(set(LOCAL) <= set(functions), "source-derived private helper extents")
    records = _disassembly(disassembly, image)
    consumed, pool_targets, loose_data, padding = set(), set(), [], []
    evidence = {name: dict(Name=name, Symbol=dict(item), Instructions=0, DataBytes=0, References=[],
                          BodySha256=sha(image.section_read(item["section"],
                              (item["value"] & ~1) - (image.sections[item["section"]].header.sh_addr if image.final else 0),
                              item["size"]))) for name, item in functions.items()}
    code_bytes = data_bytes = 0
    for section, segment in enumerate(image.sections):
        h = segment.header
        if not h.sh_flags & 4 or not h.sh_flags & 2 or not h.sh_size:
            continue
        need(h.sh_type == "SHT_PROGBITS", "file-backed executable section")
        origin = h.sh_addr if image.final else 0
        position, end = origin, origin + h.sh_size
        while position < end:
            mapping, limit = image.mapping(section, position)
            need(mapping in ("t", "d") and type(limit) is int and position < limit, "closed Thumb/data mappings")
            key = section, position
            need(key in records, "missing byte-bound disassembly row")
            op, operands, raw = records[key]
            owners = [name for name, item in functions.items() if item["section"] == section
                      and (item["value"] & ~1) <= position < (item["value"] & ~1) + item["size"]]
            need(len(owners) <= 1, "unique complete-body owner")
            if mapping == "t":
                first = struct.unpack("<H", image.section_read(section, position - origin, 2))[0]
                width = core._width(first)
                need(type(width) is int and width in (2, 4) and len(raw) == width and not op.startswith("."),
                     "actual Thumb instruction width")
                _forms(op, operands, raw)
                if first & 0xF800 == 0x4800:
                    form = core._address_form(raw, position)
                    need(form is not None and form[0] == "ldr", "frozen literal form")
                    pool_targets.add((section, form[1]))
                if not owners:
                    need(raw in (bytes.fromhex("00bf"), bytes.fromhex("aff30080")), "unowned executable non-NOP bytes")
                    padding.append(dict(Section=section, Address=position, Bytes=raw.hex()))
                else:
                    evidence[owners[0]]["Instructions"] += 1
                code_bytes += width
            else:
                width = len(raw)
                need((op, width) in ((".word", 4), (".short", 2)), "mapped literal descriptor")
                if owners:
                    evidence[owners[0]]["DataBytes"] += width
                else:
                    loose_data.append(dict(Section=section, Address=position, Size=width, Bytes=raw.hex()))
                data_bytes += width
            need(position + width <= min(limit, end) and raw == image.section_read(section, position - origin, width),
                 "disassembly/mapping/raw-byte agreement")
            if owners:
                need(position + width <= (functions[owners[0]]["value"] & ~1) + functions[owners[0]]["size"],
                     "instruction/data crosses function extent")
            consumed.add(key)
            position += width
    need(set(records) == consumed, "extra/unconsumed disassembly rows")
    for row in loose_data:
        need(row["Size"] == 4 and (row["Section"], row["Address"]) in pool_targets,
             "unowned mapped pool word has actual frozen LDR reference")
    refs, fields = [], {}
    used_imports = set()
    for (section, offset), (kind, target) in sorted(image.relocations.items()):
        need(all(type(x) is int for x in (section, offset, kind)) and 0 < section < len(image.sections)
             and kind in (2, 10, 30) and offset >= 0 and target in image.symbols,
             "closed original/applied REL kinds ABS32/THM_CALL/THM_JUMP24")
        need(not FORBIDDEN.search(target["name"]), "forbidden runtime REL target")
        h = image.sections[section].header
        need(h.sh_type == "SHT_PROGBITS" and offset + 4 <= h.sh_size,
             "complete file-backed four-byte REL field")
        need(all(other_section != section or offset + 4 <= other or other + 4 <= offset
                 for other_section, other in fields), "nonoverlapping REL fields")
        fields[section, offset] = kind
        address = offset + (h.sh_addr if image.final else 0)
        owners = [name for name, item in functions.items() if item["section"] == section
                  and (item["value"] & ~1) <= address < (item["value"] & ~1) + item["size"]]
        raw = image.section_read(section, offset, 4)
        key = section, address
        if kind == 2:
            need(address % 4 == 0, "word-aligned ABS32 field")
            if h.sh_flags & 4:
                mapping, limit = image.mapping(section, address)
                need(mapping == "d" and address + 4 <= limit and key in consumed
                     and records[key][0] == ".word" and records[key][2] == raw,
                     "ABS32 executable-section site is a complete mapped literal word")
            site = "ABS32-DATA"
        else:
            need(address % 2 == 0 and h.sh_flags & 6 == 6 and len(owners) == 1,
                 "Thumb transfer has an aligned unique executable function owner")
            mapping, limit = image.mapping(section, address)
            expected_op = "bl" if kind == 10 else "b"
            need(mapping == "t" and address + 4 <= limit and key in consumed
                 and records[key][0] == expected_op and records[key][2] == raw
                 and address + 4 <= (functions[owners[0]]["value"] & ~1) + functions[owners[0]]["size"],
                 "REL transfer is one complete byte-bound Thumb instruction")
            first, second = struct.unpack("<HH", raw)
            need(first & 0xF800 == 0xF000 and second & 0xD000 == (0xD000 if kind == 10 else 0x9000),
                 "REL kind matches BL/B.W encoding")
            site = "THM_CALL-BL" if kind == 10 else "THM_JUMP24-B.W"
        row = dict(Section=section, Offset=offset, Kind=kind, Target=dict(target), Owner=owners[0] if owners else None,
                   SiteForm=site, SiteBytes=raw.hex(), FieldBytes=4,
                   AddendSemanticsValidated=False, AppliedDestinationValidated=False)
        refs.append(row)
        if owners:
            evidence[owners[0]]["References"].append(row)
        if target["section"] == "SHN_UNDEF":
            used_imports.add(target["name"])
    need(set(undefined) <= used_imports, "every allowed external import has actual REL use")
    need(all(row["Instructions"] > 0 for row in evidence.values()), "every positive function has covered instructions")
    return dict(Status="CM3-LTO-PORT-POLICY-MACHINE-PASS", Scope="CM3_O2_LTO_SUPPORTED_PORT_POLICY_COMPONENT_ONLY",
                ObjectSha256=sha(image.data), DisassemblySha256=sha(disassembly), FinalELF=image.final,
                FunctionsAudited=len(functions), FunctionEvidence=list(evidence.values()),
                DefinitionsFromIR=[dict(definitions[name]) for name in required],
                DefinitionSurface=surface, Undefined=undefined, AllowedMemoryHelpers=["memcpy", "memset"],
                References=refs, Padding=padding, UnownedMappedPools=loose_data,
                ExecutableInstructionBytes=code_bytes, ExecutableMappedDataBytes=data_bytes,
                CompleteExecutableCensus=True, ForbiddenDependenciesAbsent=True,
                RecognizedForbiddenFormsAbsent=True, RecognizedForbiddenForms=list(FORBIDDEN_FORMS),
                FullInstructionSemantics=False, SourceIRSemantics=False, OriginalTranslationUnitOwnership=False,
                AttributeOnlyProtection=False, GeneralRegistersOnlyEffectProved=False,
                CPUExecution=False, BoardExecution=False, GlobalQualification=False, RequiredCellsSatisfied=0)


def inspect_lowered(image, core, disassembly, ir_definitions, *, whole_image=False):
    need(type(whole_image) is bool and image.final is False, "lowered role")
    return _scan(image, core, disassembly, expected_undefined=FINAL_WORKER_UNDEFINED if whole_image else UNDEFINED,
                 surface=ir_definitions, mandatory_locals=not whole_image)


def inspect_final(image, core, disassembly, ir_definitions):
    need(image.final is True, "final executable role")
    result = _scan(image, core, disassembly, expected_undefined=(), surface=ir_definitions)
    definitions, functions, _ = _symbols(image)
    need("pilot_vectors" in definitions and "Reset_Handler" in functions, "fixed vector/startup providers")
    vector = definitions["pilot_vectors"]
    need(vector["kind"] == "STT_OBJECT" and vector["size"] == 1024 and vector["binding"] == "STB_GLOBAL"
         and type(vector["section"]) is int and 0 < vector["section"] < len(image.sections), "256-word strong vector table")
    h = image.sections[vector["section"]].header
    need(image.names[vector["section"]] == ".isr_vector" and not h.sh_flags & 4, "vector section")
    raw = image.section_read(vector["section"], vector["value"] - h.sh_addr, 1024)
    words = struct.unpack("<256I", raw)
    for index, name in ((1, "Reset_Handler"), (11, "SVC_Handler"), (14, "PendSV_Handler")):
        need(words[index] == functions[name]["value"], "strong vector pointer binding: " + name)
    need(image.elf.header.e_entry == functions["Reset_Handler"]["value"], "entry binding")
    result["FinalRootVectorBindings"] = dict(VectorSha256=sha(raw), Words=256,
        Entry=words[1], SVC=words[11], PendSV=words[14], CanonicalRootProtocolsValidated=False)
    return result


def inspect_stress(image, core, disassembly, attributes, *, supported):
    need(type(supported) is bool, "literal stress disposition")
    proof = attributes.inspect_lowered(image, core, stress=True,
                                      mutation=None if supported else attributes.STRESS)
    if supported:
        clean = _scan(image, core, disassembly, expected_undefined=())
        need(set(row["Name"] for row in clean["FunctionEvidence"]) == {attributes.STRESS}, "ordinary supported stress carrier")
        return dict(Status="CM3-LTO-PORT-POLICY-STRESS-CLEAN", CleanMachine=clean, Effects=proof,
                    SupportedPolicy=True, RequiredCellsSatisfied=0)
    need(proof["StressFamiliesActivated"] is True and proof["StressCounterEvidence"] is not None,
         "actual raw stress families and carrier counter")
    rejected = False
    try:
        attributes.inspect_lowered(image, core, stress=True)
    except attributes.Rejected:
        rejected = True
    need(rejected, "unchanged clean predicate rejects actual raw stress")
    return dict(Status="CM3-LTO-PORT-POLICY-STRESS-EFFECTS-DETECTED", Effects=proof,
                SupportedPolicy=False, CleanPredicateRejected=True, RequiredCellsSatisfied=0)
