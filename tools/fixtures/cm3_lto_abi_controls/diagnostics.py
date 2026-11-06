"""Pure closed GNU GCC14 LTO link-diagnostic grammar, not link provenance.

The caller authenticates commands, tool/object/source bytes and absent output.
Negative links must omit -v; verbose traces are not stripped or blacklisted.
"""

import hashlib
import ntpath
from pathlib import PurePath
import posixpath
import re


TRAILER = 'collect2.exe: error: ld returned 1 exit status'
IDENTIFIER = r'[A-Za-z_][A-Za-z0-9_]*'
ABSOLUTE = r'(?:[A-Za-z]:[\\/]|/)[^:\r\n]+'
PATH = r'(?:"(?:[A-Za-z]:[\\/]|/)[^":\r\n]+"|\'(?:[A-Za-z]:[\\/]|/)[^\':\r\n]+\'|' + ABSOLUTE + r')'
LOCATION = r'\((?P<section>\.[A-Za-z0-9_.]+)\+0x(?P<offset>[0-9a-fA-F]+)\)'
FUNCTIONS = {
    'private': frozenset(('fiber_exception_runtime_check', 'fiber_port_context_init')),
    'storage': frozenset(),
    'anchor': frozenset(('fiber_port_context_init', 'fiber_port_runtime_prepare_start')),
}
TABLE = '.fiber_port_context_cohort_expectation'


class Rejected(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected('cm3-lto-diagnostics: ' + message)


def _path(value):
    need(type(value) is str or isinstance(value, PurePath), 'literal absolute path')
    text = str(value)
    if text.startswith(('"', "'")):
        need(len(text) > 2 and text[-1] == text[0], 'balanced path quoting')
        text = text[1:-1]
    need(text and not any(ord(c) < 32 or c in '\x7f"<>|?*`' for c in text), 'closed diagnostic path characters')
    if re.match(r'^[A-Za-z]:[\\/]', text):
        need(':' not in text[2:], 'only the drive colon is permitted')
        return ('windows', ntpath.normcase(ntpath.normpath(text.replace('/', '\\'))))
    need(text.startswith('/') and not text.startswith('//') and ':' not in text,
         'absolute drive or POSIX path, not drive-relative/UNC')
    return ('posix', posixpath.normpath(text))


def _match_path(actual, expected, label):
    need(_path(actual) == _path(expected), 'exact ' + label + ' path')


def _text(result):
    need(type(getattr(result, 'returncode', None)) is int and result.returncode == 1
         and type(getattr(result, 'stdout', None)) is bytes and result.stdout == b''
         and type(getattr(result, 'stderr', None)) is bytes and result.stderr
         and getattr(result, 'timed_out', None) is False, 'terminal exit-1, empty-byte stdout and no timeout required')
    for name in ('State', 'state'):
        if hasattr(result, name):
            need(type(getattr(result, name)) is str and getattr(result, name) == 'TERMINAL', 'terminal command state')
    for name in ('Status', 'status'):
        if hasattr(result, name):
            need(type(getattr(result, name)) is str and getattr(result, name) == 'FAIL', 'failed command status')
    for name in ('Error', 'error'):
        need(getattr(result, name, None) is None, 'no runner/infrastructure error')
    try:
        text = result.stderr.decode('utf-8', errors='strict').replace('\r\n', '\n')
    except UnicodeError as error:
        raise Rejected('cm3-lto-diagnostics: strict UTF-8 diagnostic bytes') from error
    need(text.endswith('\n') and not any((ord(c) < 32 and c not in '\n\t') or ord(c) == 127 for c in text),
         'terminated diagnostic without lone CR, NUL or control characters')
    lines = text[:-1].split('\n')
    need(len(lines) >= 2 and lines[-1] == TRAILER and all(lines), 'one terminal closed collect2 trailer and no blank lines')
    return text, lines[:-1]


def _family(expected):
    need(type(expected) is str and re.fullmatch(IDENTIFIER, expected) is not None, 'one literal expected symbol')
    if re.fullmatch(r'fiber_port_context_cohort_armv7m_[A-Za-z0-9_]+', expected):
        return 'private'
    if re.fullmatch(r'fiber_port_storage_cohort_arm_cm3_v[1-9][0-9]*_r0', expected):
        return 'storage'
    need(expected == 'fiber_internal_runtime_port_abi_v1_anchor', 'only CM3 private/storage or reverse-v1 anchor')
    return 'anchor'


def _evidence(result, text):
    return dict(DiagnosticSha256=hashlib.sha256(result.stderr).hexdigest().upper(),
        DiagnosticTextSha256=hashlib.sha256(text.encode('utf-8')).hexdigest().upper(),
        DiagnosticNormalization='CRLF-TO-LF-ONLY', ClosedGrammarValidated=True,
        CommandProvenanceVerified=False, PhysicalIdentityChecked=False, FullABIProof=False,
        Qualification=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0)


def classify_undefined(result, expected, ld, *, machine=None, sources=()):
    """Accept only expected-symbol LTRANS headers/references and one trailer.

    An omitted machine is inferred consistently from the diagnostic and is NOT
    caller-bound. Optional sources are exact admitted paths, not new grammars.
    """
    family = _family(expected)
    _path(ld)
    need(type(sources) in (tuple, list), 'explicit source-path sequence')
    source_ids = [_path(path) for path in sources]
    need(len(source_ids) == len(set(source_ids)), 'unique optional source paths')
    selected = _path(machine) if machine is not None else None
    text, lines = _text(result)
    active, pending, headers, references, observed = None, False, [], [], None

    def bind_machine(path):
        nonlocal selected, observed
        identity = _path(path)
        need(identity[1].endswith('.ltrans0.ltrans.o'), 'actual partition-zero machine, not GIMPLE IR')
        if selected is None:
            selected = identity
        need(identity == selected, 'one exact diagnostic LTRANS machine')
        observed = path if observed is None else observed

    ending = r": undefined reference to `(?P<symbol>" + IDENTIFIER + r")'"
    for line in lines:
        prefix = re.fullmatch(r'(?P<ld>' + PATH + r'): (?P<body>.+)', line)
        if prefix is not None:
            _match_path(prefix['ld'], ld, 'linker')
            body = prefix['body']
            heading = re.fullmatch(r'(?P<machine>' + PATH + r"): in function `(?P<function>" + IDENTIFIER + r")':", body)
            if heading is not None:
                need(not pending and heading['function'] in FUNCTIONS[family], 'complete approved LTO function group')
                bind_machine(heading['machine'])
                active, pending = heading['function'], True
                headers.append(dict(Machine=heading['machine'], Function=active))
                continue
            direct = re.fullmatch(r'(?P<machine>' + PATH + r'):' + LOCATION + ending, body)
            need(direct is not None and not pending and family in ('private', 'storage')
                 and direct['section'] == TABLE and direct['symbol'] == expected, 'only intended direct expectation-table reference')
            bind_machine(direct['machine'])
            references.append(dict(Machine=direct['machine'], Function=None, Source=None,
                Section=direct['section'], Offset=int(direct['offset'], 16), Symbol=expected))
            active = None
            continue
        detail = re.fullmatch(r'(?P<source><artificial>|' + PATH + r'):' + LOCATION + ending, line)
        need(detail is not None and active is not None and detail['section'] == '.text'
             and detail['symbol'] == expected, 'approved function-bound expected undefined reference')
        if detail['source'] != '<artificial>':
            need(_path(detail['source']) in source_ids, 'exact optional source path')
        references.append(dict(Machine=observed, Function=active, Source=detail['source'],
            Section=detail['section'], Offset=int(detail['offset'], 16), Symbol=expected))
        pending = False
    need(references and not pending, 'nonempty references and no dangling function heading')
    identities = [(row['Function'], row['Section'], row['Offset']) for row in references]
    need(len(identities) == len(set(identities)), 'no repeated diagnostic reference site')
    return dict(_evidence(result, text), Classification='INTENDED-LTO-UNDEFINED', MissingSymbols=[expected],
        Family=family, ReferenceCount=len(references), References=references, FunctionHeaders=headers,
        Linker=str(ld), Machine=observed, MachinePathCallerBound=machine is not None, LinkerExitRecords=1)


def classify_duplicate(result, symbol, ld, added, original, source):
    """Accept the observed three-line GNU LTO-plugin duplicate-function form.

    Plugin diagnostics name IR objects, not source files. Source is a declared
    caller input only; authenticated compile argv must establish that binding.
    """
    need(type(symbol) is str and symbol in ('SVC_Handler', 'PendSV_Handler'), 'one fixed strong handler')
    _path(ld)
    need(_path(added) != _path(original), 'distinct added and original provider paths')
    need(_path(added)[1].endswith('.o') and _path(original)[1].endswith('.o')
         and _path(source)[1].endswith('.c'), 'declared IR objects and C source paths')
    text, lines = _text(result)
    need(len(lines) == 2, 'exactly one duplicate header and definition record')
    heading = re.fullmatch(r'(?P<ld>' + PATH + r'): (?P<added>' + PATH
        + r") \(symbol from plugin\): in function `" + re.escape(symbol) + r"':", lines[0])
    need(heading is not None, 'exact plugin duplicate heading')
    _match_path(heading['ld'], ld, 'linker')
    _match_path(heading['added'], added, 'added object')
    definition = re.fullmatch(r"\(\.text\+0x0\): multiple definition of `" + re.escape(symbol)
        + r"'; (?P<original>" + PATH + r') \(symbol from plugin\):\(\.text\+0x0\): first defined here', lines[1])
    need(definition is not None, 'exact one plugin multiple-definition cause')
    _match_path(definition['original'], original, 'original object')
    return dict(_evidence(result, text), Classification='INTENDED-LTO-DUPLICATE', DuplicateSymbols=[symbol],
        Linker=str(ld), AddedObject=str(added), OriginalObject=str(original), DeclaredAddedSource=str(source),
        PluginObjectDiagnostic=True, SourcePathPresent=False, SourceOwnershipProven=False, LinkerExitRecords=1)
