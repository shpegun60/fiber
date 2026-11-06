"""Pure fixed-source ownership predicates; no provider, ELF or compile proof."""
import hashlib
import json
import re


ROLE_SOURCES = {
    'engine': 'context/context_core.c',
    'state': 'context/context_runtime_state.c',
    'panic': 'context/context_panic.c',
}
MANIFEST = 'tools/runtime_sources.json'
REQUIRED_SOURCES = (*ROLE_SOURCES.values(), MANIFEST)
_MANIFEST = dict(schema_version=1, providers=dict(ROLE_SOURCES,
    optional_configuration='context/context_configuration.c'),
    compatibility=dict(legacy_compat=['fiber/fiber_core.c'], facade_bridge=[]))
_INCLUDES = {
    'engine': ('context_api_decl.h', 'context_panic.h', 'context_runtime_port_abi.h',
               'context_runtime_state.h', 'context_port_abi.h'),
    'state': ('context_runtime_state.h', 'context_panic.h', 'context_runtime_port_abi.h'),
    'panic': ('context_panic.h', 'context_port_abi.h'),
}
_SIGNATURES = {
    'engine': (
        'void fiber_internal_task_return(void)',
        'void ctxrt_v1_init(CtxrtContextV1 *context, void *stack_begin, void *stack_end, CtxrtEntryFnV1 entry, void *arg)',
        'CtxrtContextV1 *ctxrt_v1_current(void)',
        'void ctxrt_v1_start(void)',
        'void ctxrt_v1_set_dispatcher(CtxrtDispatchFnV1 dispatch, void *user)',
        'void ctxrt_v1_yield(void)',
    ),
    'state': (
        'void fiber_internal_scheduler_store_pick_next(CtxrtDispatchFnV1 pick_next, void *user)',
        'CtxrtContextV1 *fiber_internal_runtime_load_current_context(void)',
        'CtxrtContextV1 *fiber_internal_runtime_select_scheduler_candidate(CtxrtContextV1 *current)',
        'void fiber_internal_runtime_publish_current_context(CtxrtContextV1 *next)',
        'void fiber_internal_runtime_require_current_context(void)',
        'uint32_t fiber_internal_scheduler_is_configured(void)',
        'void fiber_internal_runtime_close_context_configuration(void)',
        'uint32_t fiber_internal_runtime_context_configuration_is_open(void)',
    ),
    'panic': ('void fiber_panic(char code)',),
}
_GLOBALS = {
    'engine': '',
    'state': '''
const unsigned char fiber_internal_runtime_port_abi_v1_anchor = (unsigned char)FIBER_RUNTIME_PORT_ABI_VERSION;
CtxrtContextV1 *volatile fiber_internal_runtime_current_context_slot
    __attribute__((section(".bss.fiber_runtime_current_context_slot"))) = 0;
static CtxrtDispatchFnV1 volatile fiber_internal_runtime_scheduler_pick_next = 0;
static void *volatile fiber_internal_runtime_scheduler_user = 0;
static volatile uint32_t fiber_internal_runtime_scheduler_first_selection_started = 0;
static volatile uint32_t fiber_internal_runtime_context_configuration_closed = 0;
''',
    'panic': 'static volatile char fiber_internal_fallback_panic_code = 0;',
}
_LAYOUT = ('->boot', '->sp', 'FiberPortBoot', 'offsetof(FiberContext',
    'sizeof(FiberContext', '_Alignof(FiberContext', 'offsetof(CtxrtContextV1',
    'sizeof(CtxrtContextV1', '_Alignof(CtxrtContextV1')
_CPU = ('__get_IPSR', '__get_PRIMASK', '__get_CONTROL', '__get_BASEPRI', '__get_FAULTMASK',
    'fiber_port_basepri_read', 'fiber_port_scheduler_critical_', 'FIBER_PORT_HAS_',
    'SCB->ICSR', 'fiber_port_pend_switch')
_TRANSITIONAL = ('fiber_port_require_start_environment(', 'fiber_port_require_start_interrupt_state(',
    'fiber_pendsv_init_lowest_priority(', 'fiber_port_runtime_prepare(',
    'fiber_port_context_prepare_first_start(', 'fiber_port_scheduler_pick_first_from_start(',
    'fiber_port_scheduler_set_pick_next(', 'fiber_port_require_schedule_environment(',
    'fiber_port_request_schedule(', 'fiber_port_start_first_context(')
_ATTRIBUTES = ('CTXRT_API_NORETURN', 'CTXRT_API_ATTR_SENSITIVE', 'CTXRT_GENERAL_REGS_ONLY',
               'CTXRT_API_THREAD_FUNCTION', 'FIBER_API_WEAK')
_STATE_PRIVATE = ('fiber_internal_runtime_current_context_slot',
    'fiber_internal_runtime_port_abi_v1_anchor', 'fiber_internal_runtime_scheduler_pick_next',
    'fiber_internal_runtime_scheduler_user', 'fiber_internal_runtime_scheduler_first_selection_started',
    'fiber_internal_runtime_context_configuration_closed')
_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_][A-Za-z0-9_]*|'
                    r'0[xX][0-9A-Fa-f]+[uUlL]*|[0-9]+[uUlL]*|[^\s]')


class Rejected(ValueError):
    pass


def _need(condition, message):
    if not condition:
        raise Rejected('cm0-cell-ownership: ' + message)


def _sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def _tokens(text):
    return tuple(_TOKEN.findall(text))


def _code(raw, path):
    _need(type(raw) is bytes and raw.isascii() and b'\0' not in raw, 'ASCII source bytes: ' + path)
    text = raw.decode('ascii')
    code, structure = list(text), list(text)
    index = 0
    while index < len(text):
        start = index
        if text.startswith('//', index):
            end = text.find('\n', index)
            index = len(text) if end < 0 else end
            for at in range(start, index):
                code[at] = structure[at] = ' ' if text[at] not in '\r\n' else text[at]
        elif text.startswith('/*', index):
            end = text.find('*/', index + 2)
            _need(end >= 0, 'unterminated comment: ' + path)
            index = end + 2
            for at in range(start, index):
                code[at] = structure[at] = ' ' if text[at] not in '\r\n' else text[at]
        elif text[index] in '\"\'':
            quote = text[index]
            index += 1
            while index < len(text) and text[index] != quote:
                _need(text[index] not in '\r\n', 'unterminated literal: ' + path)
                index += 2 if text[index] == '\\' else 1
            _need(index < len(text), 'unterminated literal: ' + path)
            index += 1
            for at in range(start, index):
                structure[at] = ' ' if text[at] not in '\r\n' else text[at]
        else:
            index += 1
    return ''.join(code), ''.join(structure)


def _positions(text, fragment):
    actual, wanted = _tokens(text), _tokens(fragment)
    return [index for index in range(len(actual) - len(wanted) + 1)
            if actual[index:index + len(wanted)] == wanted]


def _ordered(text, fragments, label):
    last, used = -1, {}
    for fragment in fragments:
        positions = _positions(text, fragment)
        occurrence = used.get(fragment, 0)
        _need(len(positions) > occurrence and positions[occurrence] > last, 'ordered ' + label + ': ' + fragment)
        last, used[fragment] = positions[occurrence], occurrence + 1


def _body(code, structure, signature):
    pattern = r'\s*'.join(r'\b' + re.escape(token) + r'\b' if re.fullmatch(r'[A-Za-z_]\w*', token)
                         else re.escape(token) for token in _tokens(signature)) + r'\s*\{'
    matches = list(re.finditer(pattern, structure))
    _need(len(matches) == 1, 'one fixed function definition: ' + signature)
    match = matches[0]
    start, depth = match.end() - 1, 1
    end = start + 1
    while end < len(structure) and depth:
        depth += (structure[end] == '{') - (structure[end] == '}')
        end += 1
    _need(depth == 0, 'unterminated function: ' + signature)
    return code[start:end], (match.start(), end)


def _manifest(raw):
    _need(type(raw) is bytes and raw.isascii(), 'ASCII runtime source manifest')

    def pairs(rows):
        result, seen = {}, set()
        for key, value in rows:
            _need(type(key) is str and key.casefold() not in seen, 'duplicate/case-aliased manifest key')
            seen.add(key.casefold())
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError) as error:
        raise Rejected('cm0-cell-ownership: malformed runtime source manifest') from error
    _need(type(value) is dict and type(value.get('schema_version')) is int,
          'literal manifest schema version')
    _need(value == _MANIFEST, 'exact independently specified canonical source roles')


def validate_common_sources(buffers: dict[str, bytes]) -> dict:
    """Validate exactly REQUIRED_SOURCES, without opening paths or running tools.

    These are fixed textual source/body predicates, not C control-flow/alias
    semantics. The composer must separately authenticate buffers and validate
    actual provider definitions, consumed dependencies and compiler evidence.
    """
    _need(type(buffers) is dict and all(type(key) is str for key in buffers)
          and set(buffers) == set(REQUIRED_SOURCES), 'exact canonical source buffers')
    _need(all(type(value) is bytes for value in buffers.values()), 'literal source buffers')
    _manifest(buffers[MANIFEST])
    bodies, facts = {}, []
    include_pattern = re.compile(r'(?m)^[ \t]*#[ \t]*include[ \t]+"([^"\r\n]+)"[ \t]*\r?$')
    attribute_pattern = re.compile(r'(?m)^[ \t]*(?:' + '|'.join(_ATTRIBUTES)
        + r')(?:[ \t]+(?:' + '|'.join(_ATTRIBUTES) + r'))*[ \t]*\r?$')
    for role, path in ROLE_SOURCES.items():
        code, structure = _code(buffers[path], path)
        includes = list(include_pattern.finditer(code))
        _need(tuple(row[1] for row in includes) == _INCLUDES[role], 'canonical authored includes: ' + path)
        _need('fiber_port_selected.h' not in code and not re.search(
            r'\bfiber_(?:init|current|start|scheduler_set_pick_next|schedule)\s*\(', structure),
            'no selected complete facade or legacy calls: ' + path)
        for forbidden in _LAYOUT:
            _need(forbidden not in code and not _positions(code, forbidden),
                  'opaque context layout: ' + path + ': ' + forbidden)
        for forbidden in _CPU:
            # The matrix includes identifier prefixes as well as exact expressions.
            denied = forbidden in code if forbidden.endswith('_') else bool(_positions(code, forbidden))
            _need(not denied, 'no authored CPU access: ' + path + ': ' + forbidden)
        _need(not re.search(r'\b(?:asm|__asm|__asm__|__(?:get|set)_[A-Za-z0-9_]*)\b', structure),
              'no authored assembly or CMSIS register intrinsic: ' + path)
        if role != 'state':
            _need(not any(re.search(r'\b' + name + r'\b', structure) for name in _STATE_PRIVATE),
                  'common-private state is accessed only by its source owner: ' + path)
        if role != 'panic':
            _need(not re.search(r'\bfiber_internal_fallback_panic_code\b', structure),
                  'fallback panic storage has its sole source owner: ' + path)
        residue = list(code)
        for signature in _SIGNATURES[role]:
            body, (start, end) = _body(code, structure, signature)
            name = re.search(r'([A-Za-z_]\w*)\s*\(', signature)[1]
            bodies[name] = body
            facts.append(dict(Source=path, Function=name, Signature=signature,
                              CheckedBodyTextSha256=_sha(body.encode('ascii'))))
            residue[start:end] = ' ' * (end - start)
        for row in includes:
            residue[row.start():row.end()] = ' ' * (row.end() - row.start())
        residue = attribute_pattern.sub('', ''.join(residue))
        _need(_tokens(residue) == _tokens(_GLOBALS[role]), 'only canonical private storage/definitions: ' + path)

    core = '\n'.join(bodies[name] for name in ('ctxrt_v1_init', 'ctxrt_v1_current', 'ctxrt_v1_start',
        'ctxrt_v1_set_dispatcher', 'ctxrt_v1_yield', 'fiber_internal_task_return'))
    for forbidden in _TRANSITIONAL:
        _need(not _positions(core, forbidden), 'no displaced port call: ' + forbidden)
    _ordered(bodies['ctxrt_v1_start'], (
        "FIBER_REQUIRE(fiber_internal_scheduler_is_configured() != 0u, 'K');",
        "FIBER_REQUIRE(ctxrt_v1_current() == 0, 'k');",
        'fiber_internal_runtime_close_context_configuration();', 'fiber_port_runtime_prepare_start();',
        'CtxrtContextV1 *const first = fiber_port_runtime_select_first();',
        'fiber_internal_runtime_publish_current_context(first);', 'fiber_port_runtime_start_first(first);'), 'start')
    _ordered(bodies['ctxrt_v1_set_dispatcher'], ('fiber_port_require_scheduler_configuration_environment();',
        'fiber_internal_scheduler_store_pick_next(dispatch, user);'), 'dispatcher registration')
    for name, call in (('ctxrt_v1_init', 'fiber_port_context_init(context, stack_begin, stack_end, entry, arg);'),
                       ('ctxrt_v1_current', 'return fiber_internal_runtime_load_current_context();'),
                       ('ctxrt_v1_yield', 'fiber_port_runtime_schedule();'),
                       ('fiber_internal_task_return', "fiber_panic('R');")):
        _need(bool(_positions(bodies[name], call)), 'canonical delegation: ' + name)
    candidate = bodies['fiber_internal_runtime_select_scheduler_candidate']
    _ordered(candidate, ('fiber_internal_runtime_scheduler_first_selection_started = 1u;',
        'CtxrtContextV1 *const next = pick_next(current, user);', "FIBER_REQUIRE(next != 0, 'N');",
        'return next;'), 'candidate selection')
    _need(not re.search(r'\bfiber_internal_runtime_scheduler_first_selection_started\s*=\s*0', candidate),
          'candidate must not reopen first selection')
    _ordered(bodies['fiber_internal_runtime_close_context_configuration'], ('fiber_port_runtime_memory_barrier();',
        "FIBER_REQUIRE(fiber_internal_runtime_context_configuration_closed == 0u,",
        'fiber_internal_runtime_context_configuration_closed = 1u;', 'fiber_port_runtime_memory_barrier();'), 'configuration close')
    state = _code(buffers[ROLE_SOURCES['state']], ROLE_SOURCES['state'])[0]
    _need(len(re.findall(r'\bfiber_internal_runtime_context_configuration_closed\s*=\s*0', state)) == 1,
          'configuration closes without reset after initialization')
    for fragment in ('fiber_internal_runtime_context_configuration_closed == 0u',
                     'fiber_internal_runtime_current_context_slot == 0',
                     'fiber_internal_runtime_scheduler_first_selection_started == 0u'):
        _need(bool(_positions(bodies['fiber_internal_runtime_context_configuration_is_open'], fragment)),
              'configuration-open state: ' + fragment)
    _ordered(bodies['fiber_internal_runtime_publish_current_context'], ("FIBER_REQUIRE(next != 0, 'N');",
        'fiber_internal_runtime_current_context_slot = next;'), 'current publication')
    _ordered(bodies['fiber_panic'], ('fiber_internal_fallback_panic_code = code;',
        'fiber_port_runtime_memory_barrier();', 'fiber_port_panic_wait();', 'FIBER_API_UNREACHABLE();'), 'fallback panic')
    return dict(Status='PASS', Scope='CM0_COMMON_SOURCE_BOUNDARY_PREDICATES_ONLY', SourceFactsOnly=True,
        SourceRoles=dict(ROLE_SOURCES), SourceHashes={path: _sha(buffers[path]) for path in REQUIRED_SOURCES},
        AuthoredIncludes={role: list(names) for role, names in _INCLUDES.items()}, CheckedFunctions=facts,
        CanonicalPrivateStorageDeclarations=True, RuntimeSourceManifestMatched=True,
        InputAuthenticationProof=False, ActualProviderProof=False, DependencyProof=False, ElfProof=False,
        CompileProof=False, CompilerExecution=False, FullABIProof=False, FullSemanticABIProof=False,
        ArbitraryPointerAliasProof=False, CpuExecution=False, BoardExecution=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0, GlobalFreezeQualified=False)
