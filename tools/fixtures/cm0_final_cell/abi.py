"""Pure source-byte inspection and C probe emission for one CM0/O2 cell.

Callers authenticate inputs before calling these functions. This module performs
no filesystem access, imports no project helpers, and executes no compiler.
Source pins identify the retained snapshot; they are not a C semantic oracle.
Expected C signatures below are independently spelled, not inferred from the
headers' typedefs. Provider ELF definitions, final origins, actual compiler
dependencies, attribute effects and the cold anchor read remain outer duties.

API:
    emit_probes() -> dict[filename, probe_record]
    inspect_sources(dict[relative_posix_path, bytes]) -> inspection_record
    inspect_provider_dependencies(sources, receipt_bytes, *, source_root)
        -> dependency_record
    inspect_preprocessed_attributes(preprocessed_bytes) -> declaration_record

Each probe record has Source (ASCII str), SourceSha256, ExpectedCompile (bool),
DiagnosticIdentifier (str or None), RequiredCFlags (list[str]), CompileOnly and
CompilerExecuted. All returned containers are fresh. There is no PASS status.
"""

import hashlib
import json
import ntpath
import posixpath
import re


class Rejected(ValueError):
    """Malformed facts or a mismatch with the fixed source cell."""


COHORT = "cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default"
INVENTORY_SHA256 = "69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313"
SLOT = "fiber_internal_runtime_current_context_slot"
SOURCE_ORDER = (
    "context/context_core.c",
    "context/context_runtime_state.c",
    "context/context_panic.c",
    "fiber/port/ARM_CM0/fiber_port.c",
    "fiber/port/ARM_CM0/fiber_port_boot.c",
    "fiber/port/ARM_CM0/fiber_port_exception.c",
    "fiber/port/fiber_port_context_cohort_expectation.c",
    "tools/fixtures/classic_final_image/application.c",
    "tools/fixtures/classic_final_image/startup.S",
)

# name, independent pointer type, expected object index, noreturn declaration
FORWARD = (
    ("fiber_port_context_init", "cm0_expected_init", 4, False),
    ("fiber_port_runtime_memory_barrier", "cm0_expected_void", 3, False),
    ("fiber_port_panic_wait", "cm0_expected_noreturn_void", 3, True),
    ("fiber_port_require_scheduler_configuration_environment", "cm0_expected_void", 3, False),
    ("fiber_port_runtime_prepare_start", "cm0_expected_void", 3, False),
    ("fiber_port_runtime_select_first", "cm0_expected_first", 3, False),
    ("fiber_port_runtime_start_first", "cm0_expected_noreturn_start", 3, True),
    ("fiber_port_runtime_schedule", "cm0_expected_void", 3, False),
)
REVERSE = (
    ("fiber_internal_runtime_select_scheduler_candidate", "cm0_expected_select", 1, False),
    ("fiber_internal_runtime_publish_current_context", "cm0_expected_publish", 1, False),
    ("fiber_internal_runtime_require_current_context", "cm0_expected_void", 1, False),
    ("fiber_internal_task_return", "cm0_expected_noreturn_void", 0, True),
)

# Raw source identities, not compiled-body fingerprints or learned type tables.
SOURCE_HASHES = (
    ("context/context_port_abi.h", "9031B8BCC35ADD6D36387FB1F146611A59A223A2093BD794ED84DFF6A7CF90FD"),
    ("context/context_runtime_port_abi.h", "58D670DC6B9FD209153A88545D8297489BEAA1B7686B20035C05CDAA658402DB"),
    ("context/context_api_attributes.h", "0CB8664CBDD00972B8AE50631719357C0D877D2835F78BA2D46D88CDE59FCF1C"),
    ("context/context_api_types.h", "84710D42FCBD8CEE07667750064A43F59AE7B23B5ED4CEC7530F7385F6CEF296"),
    ("context/context_panic.h", "7C06DDDBE12EB25439B85611C79200E6C674435F1A12F83C389D36DADB84E1A3"),
    ("context/context_runtime_state.h", "C32BD52DEEF64A5F9D87F8B95CAE17BED3657FC92DC69734BA33526294BD920E"),
    ("fiber/fiber_api_attributes.h", "B774862C7F63C3DFED52510C2B7F302AF83441234E8E39CA9AC2CC05390FC480"),
    ("fiber/fiber_runtime_port_abi.h", "82AD870115DE36ADB38A20392022FB9044013B18109AB74D3148C0CC605A71A4"),
    ("fiber/port/fiber_port_runtime_abi.h", "B4237594F2ABA42773ABA0711107F45CD14520FBBF410933D65A3917CFC0D3AB"),
    (SOURCE_ORDER[0], "98B4415D23252196C6CFC9A795889193BB807D8FC875CD3B3965812EE4CDCA3A"),
    (SOURCE_ORDER[1], "5DA79F90B8115C12ABF49DBCDDF83E036303C253C1A6BBD76CFB406FDCC95427"),
    (SOURCE_ORDER[2], "5EE9CE0D62D9C32DDAC660841A447170FCC4B0B3945B075FA357722ECCD22AD6"),
    (SOURCE_ORDER[3], "DEEFD31BB1A26A3BB94D8B36B47AC983BD52168B630885E89A01E2821E287FB3"),
    (SOURCE_ORDER[4], "22275EFF60D0C2D424EF4648132EDD1EC996CCD079181C566F579C1BF86E9C42"),
    (SOURCE_ORDER[5], "4A4443A36151988EA2DC0EF0E19BAE5B9F360054C41FEBF5A2A1C9EEB11EEBCC"),
    (SOURCE_ORDER[6], "87E4654D151CE3C5BDCD43E3D1444ACD70A18C4890EB9E96E1E6D45F9EC1A89D"),
    (SOURCE_ORDER[7], "590A18D64ED2466C9BE3E3E1D37CC98A3B34F3EEC9B053540672A7B1BF77F1D3"),
    (SOURCE_ORDER[8], "3448DA14A4D86033C9F8DA0C2FD82C4DA0D6DC5D9CA299C189B53E815B7A4D98"),
)

ATTRIBUTE_QUERIES = (
    "noinline", "noipa", "noclone", "no_icf", "used",
    "no_instrument_function", "no_stack_protector",
    "no_profile_instrument_function", "no_sanitize_coverage",
    'target("general-regs-only")',
)
UNPROVEN_ATTRIBUTES = (
    ('no_sanitize("address", "undefined", "thread")',
     "GCC 14.3.1 query ICE; declaration requires inspect_preprocessed_attributes plus the accepted compile; effects unproved"),
)

# A deliberately small declaration dialect, transcribed from the two canonical
# headers. The independent C type oracle in emit_probes remains authoritative
# for C compatibility; this table only bounds the preprocessed declaration scan.
_CPP_SIGNATURES = (
    "void fiber_port_context_init(CtxrtContextV1 *context, void *stack_begin, void *stack_end, CtxrtEntryFnV1 entry, void *arg)",
    "void fiber_port_runtime_memory_barrier(void)",
    "void fiber_port_panic_wait(void)",
    "void fiber_port_require_scheduler_configuration_environment(void)",
    "void fiber_port_runtime_prepare_start(void)",
    "CtxrtContextV1 *fiber_port_runtime_select_first(void)",
    "void fiber_port_runtime_start_first(CtxrtContextV1 *first)",
    "void fiber_port_runtime_schedule(void)",
    "CtxrtContextV1 *fiber_internal_runtime_select_scheduler_candidate(CtxrtContextV1 *current)",
    "void fiber_internal_runtime_publish_current_context(CtxrtContextV1 *next)",
    "void fiber_internal_runtime_require_current_context(void)",
    "void fiber_internal_task_return(void)",
)
_CPP_TOKEN = re.compile(r'''\s+|"(?:\\[^\r\n]|[^"\\\r\n])*"|'(?:\\[^\r\n]|[^'\\\r\n])*'|[A-Za-z_][A-Za-z_0-9]*|[0-9][A-Za-z_0-9.]*|[^\w\s]''')
_CPP_MARKER = re.compile(r'^\s*#\s*([0-9]+)\s+("(?:\\.|[^"\\])*")(?:\s+([1-4](?:\s+[1-4])*))?\s*$')
_CPP_DIAGNOSTIC = re.compile(r'^\s*#\s*pragma\s+GCC\s+diagnostic\s+(?:push|pop|(?:ignored|warning|error)\s+"-W[A-Za-z0-9_=+\-]+")\s*$')
_NO_SANITIZE_TOKENS = (
    "no_sanitize", "(", '"address"', ",", '"undefined"', ",", '"thread"', ")",
)

_HEADERS = '''#include "context/context_port_abi.h"
#include "context/context_runtime_port_abi.h"
'''
_TARGET = '''#if !defined(__GNUC__) || defined(__clang__) || __GNUC__ != 14
#error CM0_ABI_requires_GCC_14
#endif
#if !defined(__ARM_ARCH_6M__) || !defined(__thumb__) || defined(__ARM_PCS_VFP) || defined(__ARM_FP)
#error CM0_ABI_requires_ARMv6M_Thumb_soft_no_FP
#endif
_Static_assert(sizeof(void *) == 4, "CM0_ABI_pointer_width");
_Static_assert(FIBER_RUNTIME_PORT_ABI_VERSION == 1u, "CM0_ABI_reverse_version");
'''


def _need(condition, message):
    if not condition:
        raise Rejected("cm0-cell-abi: " + message)


def _sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def _scope():
    result = {key: False for key in (
        "CompilerExecuted", "DeclarationTypesProven", "DeclarationAttributesProven",
        "PublishedAttributeBundleProven",
        "ProviderObjectIdentityProven", "ActualDependencyClosureProven",
        "SourceBodyIsolationProven", "GeneratedSlotIsolationProven",
        "ColdAnchorReadProven", "FullABIProof", "FullSemanticABIProof",
        "WholeProviderEquivalence", "InstructionEquivalence", "PolicyEquivalence",
        "SourceIRProof", "SourceToMachineSemanticProof", "KernelRuntimeProof",
        "HandlerRoutingProven", "CpuExecution", "BoardExecution",
        "HostedCIQualified", "ArchiveQualification", "GlobalFreezeQualified",
        "CellContractSatisfied", "RequiredCellSatisfied",
    )}
    result["RequiredCellsSatisfied"] = 0
    return result


def _owners():
    return [{"Name": name, "Direction": direction, "ObjectIndex": index,
             "Source": SOURCE_ORDER[index], "NoReturn": noreturn}
            for direction, rows in (("forward", FORWARD), ("reverse", REVERSE))
            for name, _, index, noreturn in rows]


def emit_probes():
    """Return five ASCII C sources; no compilation or diagnostic classification.

    Attribute queries are declaration queries, not function-pointer type tests.
    GCC describes their support/argument semantics in Other-Builtins.html:
    https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
    Unsupported or unobservable attributes must remain incomplete, not be
    silently removed by the caller. No probe proves transitive attribute effects.
    Slot negatives require a specific undeclared-identifier diagnostic; any
    unrelated compile failure is not successful slot-isolation evidence.
    """
    types = _HEADERS + _TARGET + '''
struct FiberContext;
typedef void (*cm0_expected_entry)(void *);
typedef struct FiberContext *(*cm0_expected_dispatch)(struct FiberContext *, void *);
typedef void (*cm0_expected_init)(struct FiberContext *, void *, void *, cm0_expected_entry, void *);
typedef void (*cm0_expected_void)(void);
typedef struct FiberContext *(*cm0_expected_first)(void);
typedef void (*cm0_expected_start)(struct FiberContext *);
/* GCC's noreturn pointer qualification is independently part of this oracle. */
typedef void (*cm0_expected_noreturn_void)(void) __attribute__((noreturn));
typedef void (*cm0_expected_noreturn_start)(struct FiberContext *) __attribute__((noreturn));
typedef struct FiberContext *(*cm0_expected_select)(struct FiberContext *);
typedef void (*cm0_expected_publish)(struct FiberContext *);
_Static_assert(!__builtin_types_compatible_p(cm0_expected_noreturn_void, cm0_expected_void), "CM0_ABI_noreturn_void_distinct");
_Static_assert(!__builtin_types_compatible_p(cm0_expected_noreturn_start, cm0_expected_start), "CM0_ABI_noreturn_start_distinct");
_Static_assert(__builtin_types_compatible_p(CtxrtContextV1 *, struct FiberContext *), "CM0_ABI_context_type");
_Static_assert(__builtin_types_compatible_p(CtxrtEntryFnV1, cm0_expected_entry), "CM0_ABI_entry_type");
_Static_assert(__builtin_types_compatible_p(CtxrtDispatchFnV1, cm0_expected_dispatch), "CM0_ABI_dispatch_type");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fiber_internal_runtime_port_abi_v1_anchor), const unsigned char *), "CM0_ABI_anchor_type");
'''
    for number, (name, expected, _, _) in enumerate(FORWARD + REVERSE):
        types += ('_Static_assert(__builtin_types_compatible_p(__typeof__(&' + name
                  + '), ' + expected + '), "CM0_ABI_type_' + name + '");\n')
        types += ("static " + expected + " const cm0_abi_reference_" + str(number)
                  + " __attribute__((used)) = &" + name + ";\n")
    types += '''static void __attribute__((used, noinline)) cm0_abi_anchor_read(void)
{
    FIBER_RUNTIME_PORT_ABI_RETAIN_V1();
}
'''
    attributes = _HEADERS + _TARGET
    attributes += '''#if !defined(__has_builtin)
#error CM0_ABI_attribute_query_unavailable
#elif !__has_builtin(__builtin_has_attribute)
#error CM0_ABI_attribute_query_unavailable
#endif
'''
    for name, _, _, noreturn in FORWARD + REVERSE:
        for number, attribute in enumerate(ATTRIBUTE_QUERIES):
            attributes += ('_Static_assert(__builtin_has_attribute(' + name + ', '
                           + attribute + '), "CM0_ABI_attr_' + name + '_'
                           + str(number) + '");\n')
        if noreturn:
            attributes += ('_Static_assert(__builtin_has_attribute(' + name
                           + ', noreturn), "CM0_ABI_noreturn_' + name + '");\n')
    sources = {"types.c": types, "attributes.c": attributes}
    sources["slot_read.c"] = _HEADERS + (
        "void cm0_abi_slot_read(void)\n{\n    (void)" + SLOT + ";\n}\n")
    sources["slot_write.c"] = _HEADERS + (
        "void cm0_abi_slot_write(struct FiberContext *value)\n{\n    "
        + SLOT + " = value;\n}\n")
    sources["slot_address.c"] = _HEADERS + (
        "void cm0_abi_slot_address(void)\n{\n    (void)&" + SLOT + ";\n}\n")
    return {name: {
        "Source": source, "SourceSha256": _sha(source.encode("ascii")),
        "ExpectedCompile": not name.startswith("slot_"),
        "DiagnosticIdentifier": SLOT if name.startswith("slot_") else None,
        "RequiredCFlags": ["-std=gnu11", "-Werror=incompatible-pointer-types", "-Werror=attributes"],
        "CompileOnly": True, "CompilerExecuted": False,
        "UnprovenAttributes": [{"Attribute": attribute, "Reason": reason}
                               for attribute, reason in UNPROVEN_ATTRIBUTES]
                              if name == "attributes.c" else [],
    } for name, source in sources.items()}


def _sources(sources):
    _need(type(sources) is dict, "sources must be a dict of relative paths to bytes")
    seen = set()
    for path, data in sources.items():
        _need(type(path) is str and bool(path) and "\\" not in path
              and ":" not in path and "\x00" not in path
              and all(part not in ("", ".", "..") for part in path.split("/")),
              "noncanonical relative source path")
        _need(path.casefold() not in seen, "case-aliased source path: " + path)
        seen.add(path.casefold())
        _need(type(data) is bytes, "source is not bytes: " + path)
    return sources


def inspect_sources(sources):
    """Check all 18 raw identities of this snapshot, allowing extra captured files.

    No newline normalization, C parsing, declaration proof or provider proof.
    The caller must authenticate and close the supplied buffers and their paths.
    """
    sources = _sources(sources)
    rows = []
    for path, expected in SOURCE_HASHES:
        _need(path in sources, "missing source: " + path)
        actual = _sha(sources[path])
        _need(actual == expected, "raw source identity mismatch: " + path)
        rows.append({"Path": path, "Sha256": actual})
    return {"Cohort": COHORT, "Mode": "O2", "Linkage": "direct",
            "RawSourceIdentitiesChecked": True, "Sources": rows,
            "ExpectedOwners": _owners(), "Scope": _scope()}


def _cpp_marker_path(filename):
    """Lexical path identity only: no cwd, filesystem, case folding or resolve."""
    _need(bool(filename) and not any(ord(char) < 32 for char in filename),
          "empty/control character in marker path")
    if filename.startswith("<") and filename.endswith(">"):
        return filename
    drive, _ = ntpath.splitdrive(filename)
    if drive or "\\" in filename:
        _need(not filename.startswith(("\\\\?\\", "\\\\.\\")), "device namespace in marker path")
        _need(not drive or ntpath.isabs(filename), "drive-relative marker path")
        _need(drive or not filename.startswith("\\"), "current-drive-rooted marker path")
        normalized = ntpath.normpath(filename).replace("\\", "/")
    else:
        normalized = posixpath.normpath(filename)
    _need(normalized not in (".", "..") and not normalized.startswith("../"),
          "unbound relative root escape in marker path")
    return normalized


def _cpp_tokens(data):
    """Tokenize ordinary GCC .i text, retaining each token's line-marker origin."""
    _need(type(data) is bytes and bool(data), "preprocessed input must be nonempty bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeError as error:
        raise Rejected("cm0-cell-abi: preprocessed input is not UTF-8") from error
    _need("\x00" not in text, "NUL in preprocessed input")
    filename, line_number, comment = None, 0, False
    result = []
    for line in text.splitlines():
        if not comment and line.lstrip().startswith("#"):
            if _CPP_DIAGNOSTIC.fullmatch(line):
                _need(filename is not None, "diagnostic pragma precedes the first marker")
                _need(not any(filename == name or filename.endswith("/" + name) for name in (
                    "context/context_port_abi.h", "context/context_runtime_port_abi.h")),
                    "diagnostic pragma inside canonical ABI header")
                line_number += 1
                continue
            marker = _CPP_MARKER.fullmatch(line)
            _need(marker is not None, "unsupported/malformed preprocessor directive")
            try:
                filename = json.loads(marker[2])
            except (ValueError, UnicodeError) as error:
                raise Rejected("cm0-cell-abi: unsupported line-marker filename") from error
            filename = _cpp_marker_path(filename)
            line_number = int(marker[1])
            continue
        cursor = 0
        while cursor < len(line):
            if comment:
                end = line.find("*/", cursor)
                if end < 0:
                    break
                comment, cursor = False, end + 2
                continue
            if line.startswith("//", cursor):
                break
            if line.startswith("/*", cursor):
                comment, cursor = True, cursor + 2
                continue
            token = _CPP_TOKEN.match(line, cursor)
            _need(token is not None, "unsupported C token in preprocessed input")
            value = token[0]
            _need(value not in ('"', "'"), "unterminated C literal")
            if not value.isspace():
                _need(filename is not None, "C tokens precede the first GCC line marker")
                result.append((value, filename, line_number))
            cursor = token.end()
        line_number += 1
    _need(not comment, "unterminated C comment")
    return result


def _cpp_statements(tokens):
    """Yield file-scope declarations; reject selected functions used as bodies."""
    names = {row[0] for row in FORWARD + REVERSE}
    statement, parens, brackets, braces = [], 0, 0, 0
    for token in tokens:
        value = token[0]
        if braces:
            _need(value not in names, "ABI identifier inside a definition/initializer")
            braces += (value == "{") - (value == "}")
            continue
        if value == "{" and parens == brackets == 0:
            _need(not any(row[0] in names for row in statement), "ABI function definition is not a header declaration")
            statement, braces = [], 1
            continue
        _need(value != "}", "unbalanced C braces")
        statement.append(token)
        parens += (value == "(") - (value == ")")
        brackets += (value == "[") - (value == "]")
        _need(parens >= 0 and brackets >= 0, "unbalanced C declaration")
        if value == ";" and parens == brackets == 0:
            yield statement[:-1]
            statement = []
    _need(parens == brackets == braces == 0 and not statement, "incomplete preprocessed declaration")


def _cpp_attribute_groups(values):
    """Separate leading GNU attribute groups from one fixed function declarator."""
    attributes = []
    cursor = 0
    while cursor < len(values) and values[cursor] == "__attribute__":
        _need(values[cursor + 1:cursor + 3] == ("(", "("), "malformed GNU attribute group")
        cursor += 3
        depth, start = 0, cursor
        while cursor < len(values):
            value = values[cursor]
            if value == ")" and depth == 0:
                attributes.append(values[start:cursor])
                _need(values[cursor:cursor + 2] == (")", ")"), "malformed GNU attribute closing")
                cursor += 2
                break
            if value == "," and depth == 0:
                attributes.append(values[start:cursor])
                start = cursor + 1
            depth += (value == "(") - (value == ")")
            _need(depth >= 0, "unbalanced attribute arguments")
            cursor += 1
        else:
            raise Rejected("cm0-cell-abi: unterminated GNU attribute group")
    _need(all(attribute and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", attribute[0])
              for attribute in attributes), "malformed/empty GNU attribute")
    return attributes, values[cursor:]


def inspect_preprocessed_attributes(preprocessed_bytes):
    """Inspect no_sanitize declarations in an authenticated GCC typed-probe .i.

    Accept only the fixed canonical prototypes and their leading GNU attributes.
    GCC line markers are lexically normalized with ntpath/posixpath, preserving
    full origins (including an altered/escaped root), not rebased by basename.
    They must place all declaration tokens in the canonical header, with a
    common header-root prefix. Observed GCC diagnostic pragmas outside those
    headers are non-C metadata; other directives reject. Markers are *claims*:
    the caller must bind those paths, original header bytes, dependencies, raw
    .i bytes, accepted -Werror=attributes compile and reflection assertions to
    the SAME attempt. This pure inspection cannot authenticate that relationship.
    No GCC query skip by itself proves the complete published declaration bundle.
    This is not a general C parser, provider/body proof or attribute-effect proof.
    """
    tokens = _cpp_tokens(preprocessed_bytes)
    rows = FORWARD + REVERSE
    expected = {row[0]: tuple(_CPP_TOKEN.findall(signature))
                for row, signature in zip(rows, _CPP_SIGNATURES)}
    expected = {name: tuple(value for value in values if not value.isspace())
                for name, values in expected.items()}
    declarations, headers = {}, {}
    for statement in _cpp_statements(tokens):
        values = tuple(row[0] for row in statement)
        depth, candidates = 0, []
        for index, value in enumerate(values):
            if depth == 0 and value in expected and values[index + 1:index + 2] == ("(",):
                candidates.append(value)
            depth += (value == "(") - (value == ")")
        if not candidates:
            continue
        _need(len(candidates) == 1, "ambiguous ABI declaration")
        name = candidates[0]
        _need(name not in declarations, "duplicate ABI declaration: " + name)
        attributes, signature = _cpp_attribute_groups(values)
        _need(signature == expected[name], "noncanonical ABI prototype: " + name)
        direction = "forward" if name in {row[0] for row in FORWARD} else "reverse"
        relative = ("context/context_port_abi.h" if direction == "forward"
                    else "context/context_runtime_port_abi.h")
        origins = {row[1] for row in statement}
        _need(len(origins) == 1, "split declaration/header provenance: " + name)
        origin = next(iter(origins))
        _need(origin == relative or origin.endswith("/" + relative), "wrong canonical header: " + name)
        _need(direction not in headers or headers[direction] == origin, "multiple canonical header roots")
        headers[direction] = origin
        sanitizers = [attribute for attribute in attributes if attribute[0] == "no_sanitize"]
        _need(sanitizers == [_NO_SANITIZE_TOKENS], "exact single no_sanitize argument list required: " + name)
        declarations[name] = {"Name": name, "Direction": direction,
                              "Header": origin, "Line": statement[0][2],
                              "NoSanitizeArguments": ["address", "undefined", "thread"]}
    _need(set(declarations) == set(expected), "missing fixed ABI declarations")
    forward_root = headers["forward"][:-len("context/context_port_abi.h")]
    reverse_root = headers["reverse"][:-len("context/context_runtime_port_abi.h")]
    _need(forward_root == reverse_root, "canonical headers have different roots")
    return {"Cohort": COHORT, "Mode": "O2", "Linkage": "direct",
            "PreprocessedSha256": _sha(preprocessed_bytes),
            "PreprocessedNoSanitizeDeclarationsChecked": True,
            "ForwardDeclarations": 8, "ReverseDeclarations": 4,
            "Declarations": [declarations[row[0]] for row in rows],
            "CanonicalHeaders": headers, "LineMarkerProvenanceOnly": True,
            "AcceptedCompileRequired": True, "SameAttemptReflectionRequired": True,
            "AuthenticatedHeaderBindingRequired": True, "Scope": _scope()}


def _object(pairs):
    result = {}
    seen = set()
    for key, value in pairs:
        _need(key.casefold() not in seen, "duplicate/case-aliased JSON key: " + key)
        seen.add(key.casefold())
        result[key] = value
    return result


def _path(value):
    _need(type(value) is str and "\x00" not in value, "path must be a string")
    # Retained producer records use doubled Windows separators. Collapse only
    # separators, not dot components, drive-relative paths or filesystem aliases.
    value = re.sub(r"/+", "/", value.replace("\\", "/"))
    _need(re.match(r"^[A-Za-z]:/", value) is not None
          and all(part not in ("", ".", "..") and ":" not in part
                  for part in value[3:].rstrip("/").split("/")), "invalid absolute path")
    return value.rstrip("/")


def _hash(value):
    _need(type(value) is str and re.fullmatch(r"[0-9A-Fa-f]{64}", value) is not None,
          "invalid SHA256")
    return value.upper()


def _dependencies(value):
    _need(type(value) is list and bool(value), "missing dependency records")
    rows = {}
    aliases = set()
    for row in value:
        _need(type(row) is dict and set(row) == {"Path", "Sha256"}, "dependency schema")
        path = _path(row["Path"])
        _need(path.casefold() not in aliases, "duplicate/aliased dependency")
        aliases.add(path.casefold())
        rows[path] = _hash(row["Sha256"])
    return rows


def inspect_provider_dependencies(sources, receipt_bytes, *, source_root):
    """Bind declared dependency records to supplied source bytes, without I/O.

    Receipt status is not authority. This does not re-run GCC, inspect object
    bytes, prove actual definitions, authenticate external dependency bytes or
    verify the command/ELF/closing seals. Those remain mandatory outer evidence.
    """
    inspection = inspect_sources(sources)
    _need(type(receipt_bytes) is bytes, "receipt must be authenticated bytes")
    try:
        receipt = json.loads(receipt_bytes.decode("utf-8"), object_pairs_hook=_object,
                             parse_constant=lambda value: _need(False, "nonfinite JSON: " + value))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Rejected("cm0-cell-abi: invalid receipt JSON") from error
    _need(type(receipt) is dict, "receipt must be an object")
    for key, expected in (("Profile", "CM0"), ("Mode", "O2"), ("Cohort", COHORT),
                          ("Linkage", "direct"), ("SourceInventorySha256", INVENTORY_SHA256)):
        _need(type(receipt.get(key)) is str and receipt[key] == expected, "wrong " + key)
    _need(receipt.get("LTO") is False, "LTO must be false")
    _need(type(receipt.get("TranslationUnits")) is int and receipt["TranslationUnits"] == 9,
          "translation unit count must be integer nine")
    records = receipt.get("Sources")
    _need(type(records) is list and len(records) == 9, "exact ordered nine sources required")
    root = _path(source_root)
    _need(root.endswith("/source"), "source_root must end in /source")
    native_root = root[:-7]
    bound = []
    external = {}
    for index, (relative, row) in enumerate(zip(SOURCE_ORDER, records)):
        _need(type(row) is dict, "source record must be an object")
        source = root + "/" + relative
        _need(_path(row.get("Source")) == source, "source order/path mismatch")
        _need(_hash(row.get("SourceSha256")) == _sha(sources[relative]), "source hash mismatch")
        stem = relative.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        obj = native_root + "/objects/" + format(index, "02d") + "-" + stem + ".o"
        _need(_path(row.get("Object")) == obj, "object index/path mismatch")
        object_hash = _hash(row.get("ObjectSha256"))
        _need(row.get("CompileDependenciesVerified") is True, "dependencies not declared verified")
        declared = _dependencies(row.get("Dependencies"))
        actual = _dependencies(row.get("ActualCompileDependencies"))
        _need(declared == actual, "declared/actual dependency records differ")
        _need(actual.get(source) == _sha(sources[relative]), "own source dependency missing")
        captured = []
        for path, digest in actual.items():
            if path.casefold().startswith(root.casefold() + "/"):
                _need(path.startswith(root + "/"), "case-aliased dependency root")
                name = path[len(root) + 1:]
                _need(name in sources and _sha(sources[name]) == digest,
                      "captured dependency bytes missing/different: " + name)
                captured.append(name)
            else:
                _need(path not in external or external[path] == digest, "external hash conflict")
                external[path] = digest
        mandatory = {relative}
        if index in (0, 1, 2, 3, 4):
            mandatory.update(("context/context_port_abi.h", "context/context_api_attributes.h",
                              "context/context_api_types.h", "fiber/fiber_api_attributes.h"))
        if index in (0, 1, 3, 4):
            mandatory.add("context/context_runtime_port_abi.h")
        _need(mandatory <= set(captured), "canonical provider header dependency missing")
        bound.append({"ObjectIndex": index, "Source": relative, "Object": obj,
                      "DeclaredObjectSha256": object_hash, "Dependencies": sorted(captured)})
    return {"Cohort": COHORT, "Mode": "O2", "Linkage": "direct",
            "ReceiptSha256": _sha(receipt_bytes), "SourceInspection": inspection,
            "DeclaredProviderDependenciesBound": True, "Providers": bound,
            "UnverifiedExternalDependencies": [{"Path": path, "Sha256": digest}
                                               for path, digest in sorted(external.items())],
            "Scope": _scope()}
