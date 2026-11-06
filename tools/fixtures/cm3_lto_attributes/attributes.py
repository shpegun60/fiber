"""Pure Context hostile-LTO source plans and lowered-machine evidence.

The caller authenticates sources, compiler recipes, the supplied frozen reader,
and genuine disassembly. No path in this module is opened or executed. Cold
inline attribution is not inferred from the mere presence of a counter/address.
"""

import hashlib
import re
import struct


class Rejected(ValueError):
    pass


def need(condition, detail):
    if not condition:
        raise Rejected("REJECT:CM3-LTO-ATTRIBUTES:" + detail)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


HOSTILE_FLAGS = (
    "-finstrument-functions", "-fstack-protector-all", "-fprofile-arcs",
    "-ftest-coverage", "-fsanitize=undefined", "-fsanitize-coverage=trace-pc",
)
FORWARD = (
    "fiber_port_context_init", "fiber_port_runtime_memory_barrier",
    "fiber_port_panic_wait", "fiber_port_require_scheduler_configuration_environment",
    "fiber_port_runtime_prepare_start", "fiber_port_runtime_select_first",
    "fiber_port_runtime_start_first", "fiber_port_runtime_schedule",
)
ENGINE = (
    "fiber_internal_task_return", "ctxrt_v1_init", "ctxrt_v1_current",
    "ctxrt_v1_start", "ctxrt_v1_set_dispatcher", "ctxrt_v1_yield",
)
STATE = (
    "fiber_internal_runtime_load_current_context",
    "fiber_internal_runtime_select_scheduler_candidate",
    "fiber_internal_runtime_publish_current_context",
    "fiber_internal_runtime_require_current_context",
    "fiber_internal_scheduler_is_configured",
    "fiber_internal_runtime_close_context_configuration",
    "fiber_internal_runtime_context_configuration_is_open",
)
COLD = "fiber_internal_scheduler_store_pick_next"
SETTER = "ctxrt_v1_set_dispatcher"
PANIC = "fiber_panic"
STRESS = "ctxrt_attribute_stress"
PROTECTED = ENGINE + STATE + (PANIC,)
THREAD = ("ctxrt_v1_current", "ctxrt_v1_yield", STATE[0])
THREAD_SECTION = ".text.fiber_runtime_thread_functions"
SOURCES = {
    "engine": "context/context_core.c",
    "state": "context/context_runtime_state.c",
    "panic": "context/context_panic.c",
}
MUTATIONS = {
    "engine": ("ctxrt_v1_current", "context/context_api_decl.h",
               rb"CtxrtContextV1 \*ctxrt_v1_current\(void\)"),
    "state": (STATE[0], "context/context_runtime_state.h",
              rb"CtxrtContextV1 \*fiber_internal_runtime_load_current_context\(void\)"),
    "panic": (PANIC, "context/context_panic.h", rb"void fiber_panic\(char code\)"),
}
HOOKS = frozenset((
    "__cyg_profile_func_enter", "__cyg_profile_func_exit",
    "__stack_chk_fail", "__stack_chk_guard", "__gcov_init", "__gcov_exit",
    "__gcov_merge_add", "__sanitizer_cov_trace_pc",
    "__ubsan_handle_type_mismatch_v1", "__ubsan_handle_pointer_overflow",
    "__ubsan_handle_shift_out_of_bounds", "__ubsan_handle_add_overflow",
    "__ubsan_handle_sub_overflow", "__ubsan_handle_mul_overflow",
    "__ubsan_handle_out_of_bounds",
))
GCOV_IMPORTS = frozenset(("__gcov_init", "__gcov_exit", "__gcov_merge_add"))
COLD_IMPORTS = GCOV_IMPORTS | frozenset((
    "__cyg_profile_func_enter", "__cyg_profile_func_exit",
    "__stack_chk_guard", "__stack_chk_fail", "__sanitizer_cov_trace_pc",
))
STRESS_FAMILIES = {
    "FunctionInstrumentation": ("__cyg_profile_func_enter", "__cyg_profile_func_exit"),
    "StackProtector": ("__stack_chk_guard", "__stack_chk_fail"),
    "Profiling": ("__gcov_init", "__gcov_exit", "__gcov_merge_add"),
    "UndefinedBehavior": ("__ubsan_handle_add_overflow", "__ubsan_handle_out_of_bounds"),
    "SanitizerCoverage": ("__sanitizer_cov_trace_pc",),
}


def catalog():
    """Return fresh JSON records; the fixed model does not come from an ELF."""
    return dict(
        Sources=dict(SOURCES), ProtectedFunctions=list(PROTECTED),
        OrdinaryFunctions=[COLD], ThreadFunctions=list(THREAD),
        AggregateExpectedUndefined=list(FORWARD), RawFlags=list(HOSTILE_FLAGS),
        MutationFunctions={role: spec[0] for role, spec in MUTATIONS.items()},
        TransitiveProtection=False, RequiredCellCount=0,
    )


def inspect_ir_undefined(names, role, *, mutation=False):
    """Check plugin-NM undefined names, before hostile code is generated."""
    engine = set(FORWARD) - {FORWARD[1], FORWARD[2]}
    engine.update((PANIC, STATE[0], STATE[2], STATE[4], STATE[5], COLD))
    expected = {"engine": engine, "state": {PANIC, FORWARD[1]},
                "panic": {FORWARD[1], FORWARD[2]}}
    need(type(role) is str and role in expected, "IR role")
    need(type(mutation) is bool, "IR mutation selector")
    need(type(names) in (list, tuple) and all(type(x) is str for x in names)
         and len(names) == len(set(names)), "IR undefined names")
    # GCC14 retains gcov metadata imports in slim IR for the ordinary cold
    # helper; this is not machine instrumentation or LTRANS flag evidence.
    compiler = GCOV_IMPORTS if role == "state" or mutation else frozenset()
    if mutation:
        need(expected[role] | compiler <= set(names) <= expected[role] | HOOKS,
             "mutant IR source surface plus bounded early imports: " + role)
    else:
        need(set(names) == expected[role] | compiler, "exact original IR surface: " + role)
    return dict(Role=role, ExpectedUndefined=sorted(expected[role]),
                CompilerImports=sorted(set(names) - expected[role]),
                UndefinedValidated=True, MachineCodeValidated=False, RawFlagActivationValidated=False)


def adapt_specs(raw):
    """Delete only the driver's auto-libgcov insertion, not instrumentation."""
    need(type(raw) is bytes and raw and b"\x00" not in raw, "dumpspecs bytes")
    original = b"%{fprofile-arcs|fcondition-coverage|fprofile-generate*|coverage:-lgcov}"
    replacement = b"%{fprofile-arcs|fcondition-coverage|fprofile-generate*|coverage:}"
    need(raw.count(original) == 1, "one exact GCC14 auto-libgcov spec")
    offset = raw.index(original)
    result = raw[:offset] + replacement + raw[offset + len(original):]
    return dict(Specs=result, OriginalSha256=sha(raw), AdaptedSha256=sha(result),
                Offset=offset, Original=original.decode("ascii"), Replacement=replacement.decode("ascii"),
                OnlyRemovedBytes="-lgcov", InstrumentationCounterFlagsAdded=False)


def require_hostile_options(wpa, ltrans):
    """Check both actual saved argv streams, not just wrapper/WPA intent.

    Inputs are GCC's one-argument-per-line saved .ltrans_args files. The parent
    separately binds their exact paths, memberships and lower invocation.
    """
    evidence = []
    for stage, raw, marker in (("WPA", wpa, "-fwpa"), ("LTRANS", ltrans, "-fltrans")):
        need(type(raw) is bytes and raw and b"\x00" not in raw, stage + " arguments bytes")
        try:
            args = raw.decode("utf-8").splitlines()
        except UnicodeError as error:
            raise Rejected("REJECT:CM3-LTO-ATTRIBUTES:argument encoding") from error
        need(all(arg and arg == arg.strip() for arg in args), stage + " argument lines")
        need(marker in args and all(flag in args for flag in HOSTILE_FLAGS), stage + " six raw flags")
        need(all(flag in args for flag in ("-mcpu=cortex-m3", "-mthumb", "-mfloat-abi=soft", "-O2",
                                          "-flto-partition=one", "-nostdlib", "-r", "-flinker-output=nolto-rel")),
             stage + " exact target/lower mode")
        forbidden = ("-fno-instrument-functions", "-finstrument-functions-exclude-", "-fno-stack-protector",
                     "-fno-profile", "-fno-test-coverage", "-fno-sanitize", "-fno-lto")
        for arg in args:
            need(not arg.startswith(forbidden), stage + " hostile counterflag")
            need(not arg.startswith("-O") or arg == "-O2", stage + " optimization")
            need(not arg.startswith("-mcpu=") or arg == "-mcpu=cortex-m3", stage + " CPU")
            need(not arg.startswith("-mfloat-abi=") or arg == "-mfloat-abi=soft", stage + " float ABI")
            need(not arg.startswith("-mfpu="), stage + " foreign FPU")
            need(not arg.startswith("-flto-partition=") or arg == "-flto-partition=one", stage + " partition")
            need(arg != "-ffat-lto-objects", stage + " fat fallback")
            need(not arg.startswith(("-fsanitize", "-fstack-protector", "-finstrument-functions", "-fprofile-arcs"))
                 or arg in HOSTILE_FLAGS, stage + " contradictory stress option")
            need(arg != "-lgcov", stage + " forbidden runtime archive")
        evidence.append(dict(Stage=stage, ArgumentsSha256=sha(raw), RawFlags=list(HOSTILE_FLAGS),
                             ActualStageFlagVerified=marker))
    return dict(ActualHostileOptionsVerified=True, Stages=evidence, RuntimeLibraryProvided=False,
                AttributeEffectsValidated=False, RequiredCellCount=0)


def inspect_sources(sources):
    """Bind all 14 protected definitions and declarations to canonical tokens."""
    need(type(sources) is dict and all(type(k) is str and type(v) is bytes for k, v in sources.items()),
         "source buffers")
    declarations = {name: "context/context_api_decl.h" for name in ENGINE[1:]}
    declarations[ENGINE[0]] = "context/context_runtime_port_abi.h"
    declarations.update({name: "context/context_runtime_port_abi.h" for name in STATE[1:4]})
    declarations.update({name: "context/context_runtime_state.h" for name in (STATE[0],) + STATE[4:]})
    declarations[PANIC] = "context/context_panic.h"
    definitions = {name: SOURCES["engine"] for name in ENGINE}
    definitions.update({name: SOURCES["state"] for name in STATE})
    definitions[PANIC] = SOURCES["panic"]
    rows = []
    for name in PROTECTED:
        for site, path, end in (("Declaration", declarations[name], rb";"),
                                ("Definition", definitions[name], rb"\{")):
            need(path in sources, "source catalog input: " + path)
            attrs = rb"(?P<attrs>(?:[A-Z][A-Z0-9_]*(?:[ \t]+[A-Z][A-Z0-9_]*)*[ \t]*\r?\n)+)"
            signature = rb"[A-Za-z_][A-Za-z0-9_* \t]*\b" + name.encode("ascii") + rb"\([^;{}]*\)"
            matches = list(re.finditer(rb"(?m)^" + attrs + signature + rb"[ \t\r\n]*" + end, sources[path]))
            need(len(matches) == 1, "source catalog unique anchor: " + name + ":" + site)
            tokens = matches[0].group("attrs").split()
            need(tokens.count(b"CTXRT_API_ATTR_SENSITIVE") == 1
                 and tokens.count(b"CTXRT_GENERAL_REGS_ONLY") == 1, "protected source tokens: " + name)
            need((b"CTXRT_API_THREAD_FUNCTION" in tokens) == (name in THREAD), "source Thread placement: " + name)
            need((b"CTXRT_API_NORETURN" in tokens) == (name in (PANIC, ENGINE[0], "ctxrt_v1_start")),
                 "source noreturn contract: " + name)
            rows.append(dict(Name=name, Site=site, Path=path, SourceSha256=sha(sources[path]),
                             AnchorSha256=sha(matches[0][0])))
    return dict(ProtectedDefinitions=14, ProtectedDeclarations=14, Records=rows,
                GeneratedEffectsValidated=False, RequiredCellCount=0)


def annotation_mutant(role, sources):
    """Remove one bundle at exactly its actual declaration and definition.

    Sources is the caller's complete private-copy input map, relative path to
    bytes. Unmodified consumed headers are retained, not reconstructed here.
    """
    need(type(role) is str and role in MUTATIONS, "mutation role")
    need(type(sources) is dict and sources, "source map")
    for path, data in sources.items():
        need(type(path) is str and re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", path)
             and all(part not in (".", "..") for part in path.split("/"))
             and type(data) is bytes, "relative source bytes")
    function, header, signature = MUTATIONS[role]
    paths = (header, SOURCES[role])
    result, edits = dict(sources), []
    attributes = rb"(?:[A-Z][A-Z0-9_]*(?:[ \t]+[A-Z][A-Z0-9_]*)*[ \t]*\r?\n)+"
    for path, ending in zip(paths, (rb";", rb"\{")):
        need(path in sources, "missing mutation input: " + path)
        pattern = re.compile(rb"(?m)^(?P<attrs>" + attributes + rb")" + signature
                             + rb"[ \t\r\n]*" + ending)
        matches = list(pattern.finditer(sources[path]))
        need(len(matches) == 1, "unique mutation anchor: " + path)
        match = matches[0]
        group = match.group("attrs")
        token = rb"\bCTXRT_API_ATTR_SENSITIVE\b"
        need(len(re.findall(token, group)) == 1, "one canonical bundle: " + path)
        start, end = match.span("attrs")
        changed = re.sub(token, b"", group)
        result[path] = sources[path][:start] + changed + sources[path][end:]
        edits.append(dict(Path=path, BeforeSha256=sha(sources[path]),
                          AfterSha256=sha(result[path]), RemovedTokens=1,
                          Function=function, Site="Declaration" if path == header else "Definition"))
    return dict(Role=role, Function=function, Sources=result, Edits=edits,
                ReplacedIRRole=role, CompiledMutantRejected=False,
                RuntimeExecuted=False, RequiredCellCount=0)


def stress_sources():
    """Identical never-executed bodies, differing only in the dispatch bundle."""
    before = b'''#include "context/context_api_types.h"
#include "context/context_api_attributes.h"
'''
    body = b'''CtxrtContextV1 *ctxrt_attribute_stress(CtxrtContextV1 *current, void *user)
{
    volatile char scratch[32];
    volatile int *input = (volatile int *)user;
    volatile int index = input[0];
    volatile int sum = input[1] + input[2];
    scratch[index] = (char)sum;
    if (scratch[index] != 0) {
        return current;
    }
    return (CtxrtContextV1 *)user;
}
'''
    protected = before + b"CTXRT_DISPATCH_ATTR\n" + body
    ordinary = before + body
    return dict(Protected=protected, Unprotected=ordinary, Function=STRESS,
                RequiredFamilies={key: list(value) for key, value in STRESS_FAMILIES.items()},
                OnlyDifference="one CTXRT_DISPATCH_ATTR definition token",
                RuntimeExecuted=False, RequiredCellCount=0)


def _header(image, core):
    need(type(image) is core._ELF and type(image.data) is bytes, "supplied core._ELF")
    data = image.data
    need(len(data) >= 52 and data[:7] == b"\x7fELF\x01\x01\x01", "ELF32LE bytes")
    kind, machine, version = struct.unpack_from("<HHI", data, 16)
    flags = struct.unpack_from("<I", data, 36)[0]
    need((kind, machine, version) == (1, 40, 1) and not image.final
         and not flags & 0x400, "ARM soft ET_REL, no hard-float")
    need(not any(name.startswith(".gnu.lto_") for name in image.names), "IR/fat fallback")
    need(len(image.names) == len(set(image.names)), "unique section names")


def _functions(image):
    result = {}
    for item in image.symbols:
        if item["section"] == "SHN_UNDEF" or item["kind"] != "STT_FUNC":
            continue
        name = item["name"]
        need(type(name) is str and name and name not in result, "unique function name")
        section, value, size = item["section"], item["value"], item["size"]
        need(all(type(x) is int for x in (section, value, size)) and 0 < section < len(image.sections)
             and value & 1 and size > 0 and size % 2 == 0,
             "positive Thumb function extent: " + name)
        h = image.sections[section].header
        start = value & ~1
        need(h.sh_type == "SHT_PROGBITS" and h.sh_flags & 6 == 6
             and start + size <= h.sh_size and image.mapping(section, start)[0] == "t",
             "mapped executable function: " + name)
        for other in result.values():
            need(section != other["section"] or start + size <= (other["value"] & ~1)
                 or (other["value"] & ~1) + other["size"] <= start,
                 "function aliases/overlap: " + name)
        result[name] = item
    return result


def _symbol_fields(item):
    need(type(item) is dict and set(item) == {
        "name", "value", "size", "kind", "binding", "section", "visibility", "index",
    }, "raw core symbol fields")
    need(all(type(item[key]) is str for key in ("name", "kind", "binding", "visibility"))
         and all(type(item[key]) is int and item[key] >= 0 for key in ("value", "size", "index"))
         and (type(item["section"]) is int or type(item["section"]) is str), "raw core symbol types")


def _walk(image, core, item):
    section, start = item["section"], item["value"] & ~1
    end, position = start + item["size"], start
    instructions, data = {}, []
    while position < end:
        mapping, limit = image.mapping(section, position)
        need(type(limit) is int and position < limit, "mapping boundary")
        if mapping == "d":
            stop = min(limit, end)
            data.append(dict(Offset=position, Size=stop - position,
                             BytesSha256=sha(image.section_read(section, position, stop - position))))
            position = stop
            continue
        need(mapping == "t" and position % 2 == 0 and position + 2 <= min(limit, end),
             "Thumb mapping coverage")
        first = struct.unpack("<H", image.section_read(section, position, 2))[0]
        width = core._width(first)
        need(type(width) is int and width in (2, 4) and position + width <= min(limit, end),
             "instruction/mapping extent")
        instructions[position] = image.section_read(section, position, width)
        position += width
    return instructions, data


def _resolved(image, kind, target, section, offset):
    """Only an original ABS32 supplies a complete unencoded data addend here."""
    if kind != 2 or type(target["section"]) is not int:
        return None
    addend = struct.unpack("<I", image.section_read(section, offset, 4))[0]
    value = target["value"] + addend
    matches = []
    for symbol in image.symbols:
        if symbol["section"] != target["section"] or symbol["kind"] not in ("STT_FUNC", "STT_OBJECT"):
            continue
        start = symbol["value"] & ~1 if symbol["kind"] == "STT_FUNC" else symbol["value"]
        address = value & ~1 if symbol["kind"] == "STT_FUNC" else value
        if symbol["size"] > 0 and start <= address < start + symbol["size"]:
            matches.append(symbol["name"])
    need(len(matches) <= 1, "ambiguous ABS32 target identity")
    return dict(Addend=addend, TargetOffset=value, Symbol=matches[0] if matches else None)


def inspect_lowered(image, core, *, mutation=None, stress=False):
    """Inspect a genuine aggregate three-IR lower, or a paired stress lower.

    Hook/counter references inside the dispatcher setter are returned PENDING,
    not accepted merely because a cold-helper counter/address also exists.
    The parent experiment can therefore expose cross-TU inline effects without
    silently asserting clean protected bodies or transitive attribute semantics.
    """
    need(type(stress) is bool and (mutation is None or type(mutation) is str), "inspection arguments")
    need(mutation in ((None, STRESS) if stress else (None,) + tuple(x[0] for x in MUTATIONS.values())),
         "fixed annotation mutant")
    _header(image, core)
    for item in image.symbols:
        _symbol_fields(item)
    functions = _functions(image)
    protected = (STRESS,) if stress else PROTECTED
    allowed = set(protected) | (set() if stress else {COLD})
    constructors = {name for name in functions if re.fullmatch(
        r"_sub_[ID]_[0-9]{5}_[0-9]+(?:\.lto_priv\.[0-9]+|\.[0-9]+)?", name)}
    need(set(functions) == allowed | constructors, "exact lowered function catalog")
    for name in protected:
        need(functions[name]["binding"] in (("STB_WEAK", "STB_GLOBAL") if name == PANIC else ("STB_GLOBAL",)),
             "protected binding: " + name)
        if name in THREAD:
            need(image.names[functions[name]["section"]] == THREAD_SECTION,
                 "Thread section: " + name)
    undefined = []
    for item in image.symbols:
        if item["section"] != "SHN_UNDEF" or not item["name"]:
            continue
        need(item["binding"] == "STB_GLOBAL" and item["kind"] in ("STT_NOTYPE", "STT_FUNC", "STT_OBJECT"),
             "strong undefined record")
        undefined.append(item["name"])
    need(len(undefined) == len(set(undefined)), "unique undefined names")
    base = set() if stress else set(FORWARD)
    need(base <= set(undefined) and set(undefined) <= base | HOOKS, "exact external surface plus bounded compiler imports")
    walks = {name: _walk(image, core, item) for name, item in functions.items()}
    rows = {name: [] for name in functions}
    outside, references = [], []
    for key, pair in sorted(image.relocations.items()):
        need(type(key) is tuple and len(key) == 2 and all(type(x) is int for x in key)
             and type(pair) is tuple and len(pair) == 2, "relocation record shape")
        section, offset = key
        kind, target = pair
        _symbol_fields(target)
        need(target in image.symbols, "REL target belongs to supplied symbol table")
        need(type(kind) is int and kind > 0 and 0 < section < len(image.sections)
             and type(offset) is int and offset >= 0, "relocation fields")
        owners = [name for name, item in functions.items() if item["section"] == section
                  and (item["value"] & ~1) <= offset < (item["value"] & ~1) + item["size"]]
        need(len(owners) <= 1, "unique reference owner")
        resolved = _resolved(image, kind, target, section, offset)
        semantic = (resolved or {}).get("Symbol") or target["name"]
        hook = target["name"] in HOOKS
        counter = bool(re.match(r"^__gcov[0-9_]*[.]", semantic))
        row = dict(Section=section, Offset=offset, Kind=kind, Target=dict(target),
                   ResolvedABS32=resolved, SemanticTarget=semantic,
                   Owner=owners[0] if owners else None, CompilerHook=hook, CompilerCounter=counter,
                   OriginalHookTransferValidated=False)
        if hook and kind in (10, 30):
            need(owners and offset in walks[owners[0]][0], "hook call instruction boundary")
            raw = walks[owners[0]][0][offset]
            if kind == 10:
                form = core._address_form(raw, offset)
                need(form is not None and form[0] == "bl" and form[3] == -4,
                     "original THM_CALL hook addend")
            else:
                # Fixed original R_ARM_THM_JUMP24 REL template: B.W -4.
                # No general B.W decoder or final destination claim is added.
                need(raw == bytes.fromhex("fff7febf"), "original THM_JUMP24 -4 template")
            row["OriginalHookTransferValidated"] = True
        elif hook:
            need(kind == 2, "only original literal addresses or supported hook transfers")
            need(not image.sections[section].header.sh_flags & 4
                 or image.mapping(section, offset)[0] == "d",
                 "hook ABS32 is mapped data, not an instruction")
            need(offset + 4 <= image.sections[section].header.sh_size
                 and image.section_read(section, offset, 4) == bytes(4), "hook ABS32 zero addend")
        if hook or counter:
            need(owners or image.names[section].startswith((".data", ".rodata", ".init_array", ".fini_array")),
                 "classified compiler metadata location")
        if owners:
            rows[owners[0]].append(row)
        else:
            outside.append(row)
        references.append(row)
    imported = set(undefined) & HOOKS
    used_names = {row["Target"]["name"] for row in references}
    need(set(undefined) <= used_names, "external import has an actual REL use")
    if not stress:
        need(COLD_IMPORTS <= imported, "all ordinary cold compiler families active")
        if mutation is None:
            need(imported == COLD_IMPORTS, "exact original aggregate compiler imports")
    if stress and mutation is None:
        need(not undefined and not constructors, "protected stress has no compiler dependencies/constructors")
    counters = [item for item in image.symbols if item["name"].startswith("__gcov")
                and item["section"] != "SHN_UNDEF"]
    counter_owners = {COLD} if not stress else set()
    if mutation:
        counter_owners.add(mutation)
    for item in counters:
        need(item["kind"] == "STT_OBJECT" and item["size"] > 0
             and any(item["name"] in ("__gcov0." + name, "__gcov_." + name)
                     for name in counter_owners), "counter definition owner")
    if not stress:
        ordinary_hooks = {row["Target"]["name"] for row in rows[COLD]
                          if row["OriginalHookTransferValidated"]}
        need({"__cyg_profile_func_enter", "__cyg_profile_func_exit"} <= ordinary_hooks,
             "ordinary cold body proves active instrumentation")
        need(any(item["name"] == "__gcov0." + COLD for item in counters),
             "ordinary cold counter identity")
        need({"__stack_chk_fail", "__sanitizer_cov_trace_pc"} <= ordinary_hooks
             and any(row["Target"]["name"] == "__stack_chk_guard" for row in rows[COLD]),
             "ordinary cold SSP and trace-pc body activity")
    for row in outside:
        need(not row["CompilerHook"] or row["Target"]["name"] == "__gcov_merge_add",
             "only gcov merge-pointer compiler metadata outside bodies")
    pending, evidence = [], []
    for name in protected:
        effects = [row for row in rows[name] if row["CompilerHook"] or row["CompilerCounter"]]
        if name == mutation:
            actual = {row["Target"]["name"] for row in effects if row["OriginalHookTransferValidated"]}
            required = {"__cyg_profile_func_enter"}
            if name != PANIC:
                required.add("__cyg_profile_func_exit")
            need(required <= actual, "mutant has actual carrier instrumentation: " + name)
        elif effects:
            need(not stress and name == SETTER, "protected body compiler effect: " + name)
            pending.append(dict(Function=name, Effects=effects,
                                ColdCounterReferences=[row for row in rows[name]
                                                       if row["SemanticTarget"] in ("__gcov0." + COLD, "__gcov_." + COLD)],
                                ColdAddressReferences=[row for row in rows[name] if row["SemanticTarget"] == COLD],
                                AttributionValidated=False))
        item = functions[name]
        instructions, data = walks[name]
        evidence.append(dict(Name=name, Symbol=dict(item), Section=image.names[item["section"]],
                             BodySha256=sha(image.section_read(item["section"], item["value"] & ~1, item["size"])),
                             InstructionCount=len(instructions), MappedData=data, References=rows[name],
                             DirectCompilerEffects=len(effects), AnnotationMutant=name == mutation))
    stress_counter = None
    if stress and mutation:
        counter_name = "__gcov0." + STRESS
        definitions = [item for item in counters if item["name"] == counter_name]
        need(len(definitions) == 1, "stress profiling carrier counter definition")
        definition = definitions[0]
        section = definition["section"]
        need(type(section) is int and 0 < section < len(image.sections),
             "stress profiling carrier counter section")
        header = image.sections[section].header
        need(header.sh_type in ("SHT_NOBITS", "SHT_PROGBITS") and header.sh_flags & 3 == 3
             and not header.sh_flags & 4 and definition["value"] + definition["size"] <= header.sh_size,
             "stress profiling carrier counter storage bounds")
        carrier_refs = [row for row in rows[STRESS] if row["CompilerCounter"] and row["Kind"] == 2
                        and row["ResolvedABS32"] is not None
                        and row["ResolvedABS32"]["Symbol"] == counter_name]
        need(carrier_refs, "stress profiling carrier resolved counter reference")
        for row in carrier_refs:
            mapping, limit = image.mapping(row["Section"], row["Offset"])
            need(mapping == "d" and row["Offset"] % 4 == 0
                 and row["Offset"] + 4 <= min(limit, (functions[STRESS]["value"] & ~1) + functions[STRESS]["size"]),
                 "stress profiling carrier mapped counter literal")
        stress_counter = dict(Definition=dict(definition), References=carrier_refs)
        seen = {row["Target"]["name"] for row in rows[STRESS]}
        for family, required in STRESS_FAMILIES.items():
            # Gcov init/exit live in compiler-generated constructors, not the
            # stress body. They remain actual RELs, not an nm substring oracle.
            available = {row["Target"]["name"] for row in references} if family == "Profiling" else seen
            need(set(required) <= available, "stress family not activated: " + family)
    for name in constructors:
        need(all(not row["CompilerHook"] or row["Target"]["name"] in {
            "__gcov_init", "__gcov_exit", "__stack_chk_guard", "__stack_chk_fail", "__sanitizer_cov_trace_pc",
        }
                 for row in rows[name]), "compiler constructor hook family")
    return dict(
        Status=("CONTEXT-LTO-ATTRIBUTES-ATTRIBUTION-PENDING" if pending else
                "CONTEXT-LTO-ANNOTATION-MUTANT-DETECTED" if mutation else
                "CONTEXT-LTO-DIRECT-ATTRIBUTE-CHECKS-PASS"),
        Scope="CM3_O2_LTO_CONTEXT_ATTRIBUTE_EFFECT_COMPONENT_ONLY", ObjectSha256=sha(image.data),
        ProtectedFunctions=len(protected), RootEvidence=evidence, Undefined=sorted(undefined),
        CompilerImports=sorted(imported), OrdinaryEvidence=[] if stress else rows[COLD],
        CounterDefinitions=[dict(item) for item in counters],
        CompilerConstructors=[dict(Name=name, Symbol=dict(functions[name]), References=rows[name],
                                   BodySha256=sha(image.section_read(functions[name]["section"],
                                                                   functions[name]["value"] & ~1,
                                                                   functions[name]["size"])))
                              for name in sorted(constructors)],
        MetadataReferences=outside, UnresolvedAttribution=pending,
        AllProtectedBodiesClean=not pending and mutation is None,
        CompiledAnnotationMutantDetected=mutation is not None,
        StressFamiliesActivated=bool(stress and mutation), ThreadSectionValidated=not stress,
        StressCounterEvidence=stress_counter,
        OrdinaryColdActivityValidated=not stress, ColdInlineAttributionValidated=not pending,
        TransitiveProtection=False, FullABI=False, FullIRSemantics=False,
        FullInstructionSemantics=False, FullAttributeEquivalence=False,
        CPUExecution=False, BoardExecution=False, GlobalQualification=False, RequiredCellCount=0,
    )
