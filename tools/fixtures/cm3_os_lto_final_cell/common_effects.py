"""Os-owned common hostile-LTO effect predicates, with no I/O or loading.

The caller authenticates the neutral helper/reader modules, genuine machine
bytes and actual Os/raw-six worker argv. ELF bytes do not establish optimization
mode. No old inspect_lowered result is consumed or relabelled. This checks
original ET_REL effects, not final-link, C/IR semantics or transitive protection.
"""

import copy
import hashlib
import re
import struct


HELPER_SHA256 = '93275A5903A67CB2DAEABB76BEF1431B052878BB478455E54343DB20881E83C0'
SCOPE = 'NATIVE_CM3_OS_LTO_COMMON_ATTRIBUTE_EFFECT_COMPONENT_ONLY'
PASS = 'CM3-OS-LTO-COMMON-EFFECTS-PASS-NOT-QUALIFIED'
MUTANT = 'CM3-OS-LTO-COMMON-ANNOTATION-MUTANT-DETECTED'
PENDING = 'CM3-OS-LTO-COMMON-ATTRIBUTION-PENDING'
PROTECTED = ('fiber_internal_task_return', 'ctxrt_v1_init', 'ctxrt_v1_current',
    'ctxrt_v1_start', 'ctxrt_v1_set_dispatcher', 'ctxrt_v1_yield',
    'fiber_internal_runtime_load_current_context', 'fiber_internal_runtime_select_scheduler_candidate',
    'fiber_internal_runtime_publish_current_context', 'fiber_internal_runtime_require_current_context',
    'fiber_internal_scheduler_is_configured', 'fiber_internal_runtime_close_context_configuration',
    'fiber_internal_runtime_context_configuration_is_open', 'fiber_panic')
FORWARD = ('fiber_port_context_init', 'fiber_port_runtime_memory_barrier', 'fiber_port_panic_wait',
    'fiber_port_require_scheduler_configuration_environment', 'fiber_port_runtime_prepare_start',
    'fiber_port_runtime_select_first', 'fiber_port_runtime_start_first', 'fiber_port_runtime_schedule')
THREAD = ('ctxrt_v1_current', 'ctxrt_v1_yield', 'fiber_internal_runtime_load_current_context')
THREAD_SECTION = '.text.fiber_runtime_thread_functions'
COLD = 'fiber_internal_scheduler_store_pick_next'
SETTER = 'ctxrt_v1_set_dispatcher'
PANIC = 'fiber_panic'
STRESS = 'ctxrt_attribute_stress'
MUTATIONS = ('ctxrt_v1_current', 'fiber_internal_runtime_load_current_context', PANIC)
CONSTRUCTOR = r'_sub_[ID]_[0-9]{5}_[0-9]+(?:\.lto_priv\.[0-9]+|\.[0-9]+)?'
FALSE_FIELDS = ('TransitiveProtection', 'FullABI', 'FullSemanticABIProof', 'FullIRSemantics',
    'FullInstructionSemantics', 'FullAttributeEquivalence', 'CPUExecution', 'BoardExecution',
    'GlobalQualification', 'Qualification', 'CellContractSatisfied', 'RequiredCellSatisfied',
    'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership', 'OsCompilerOptionsValidated',
    'FinalLinkValidated', 'AllRelocationDestinationSemanticsValidated')


class Rejected(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected('REJECT:CM3-OS-LTO-COMMON-EFFECTS:' + message)


def sha(raw):
    need(type(raw) is bytes, 'immutable byte hash input')
    return hashlib.sha256(raw).hexdigest().upper()


def _helpers(h):
    need(all(callable(getattr(h, name, None)) for name in
         ('_header', '_functions', '_symbol_fields', '_walk', '_resolved')), 'explicit neutral primitives')
    need(tuple(h.PROTECTED) == PROTECTED and tuple(h.FORWARD) == FORWARD and tuple(h.THREAD) == THREAD
         and h.THREAD_SECTION == THREAD_SECTION and h.COLD == COLD and h.SETTER == SETTER
         and h.PANIC == PANIC and h.STRESS == STRESS
         and tuple(spec[0] for spec in h.MUTATIONS.values()) == MUTATIONS, 'fixed source-derived helper catalogs')


def _reference(image, core, h, functions, walks, key, pair, fields):
    need(type(key) is tuple and len(key) == 2 and all(type(value) is int for value in key)
         and type(pair) is tuple and len(pair) == 2, 'literal REL record')
    section, offset = key
    kind, target = pair
    h._symbol_fields(target)
    need(type(kind) is int and kind in (2, 10, 30) and target in image.symbols
         and 0 < section < len(image.sections) and offset >= 0, 'closed REL kind/symbol/section')
    header = image.sections[section].header
    need(header.sh_type == 'SHT_PROGBITS' and offset + 4 <= header.sh_size, 'complete file-backed REL field')
    need(all(other_section != section or offset + 4 <= other_offset or other_offset + 4 <= offset
             for other_section, other_offset in fields), 'nonoverlapping four-byte REL fields')
    fields.add(key)
    owners = [name for name, item in functions.items() if item['section'] == section
              and (item['value'] & ~1) <= offset < (item['value'] & ~1) + item['size']]
    need(len(owners) <= 1, 'unique REL owner')
    owner = owners[0] if owners else None
    if owner:
        item = functions[owner]
        need(offset + 4 <= (item['value'] & ~1) + item['size'], 'REL field crosses function extent')
    raw = image.section_read(section, offset, 4)
    resolved, addend = None, None
    if kind == 2:
        need(offset % 4 == 0, 'word-aligned ABS32 field')
        if header.sh_flags & 4:
            mapping, limit = image.mapping(section, offset)
            need(owner is not None and mapping == 'd' and offset + 4 <= limit,
                 'ABS32 inside complete owned mapped literal')
        addend = struct.unpack('<I', raw)[0]
        resolved = h._resolved(image, kind, target, section, offset)
        if target['section'] == 'SHN_UNDEF':
            need(addend == 0, 'original external ABS32 zero addend')
    else:
        need(owner is not None and header.sh_flags & 6 == 6 and offset % 2 == 0
             and offset in walks[owner][0] and walks[owner][0][offset] == raw,
             'REL transfer is a complete owned instruction')
        if kind == 10:
            form = core._address_form(raw, offset)
            need(form is not None and form[0] == 'bl' and type(form[3]) is int, 'original THM_CALL encoding')
            addend = form[3]
        else:
            # The admitted original tail-transfer template, not a B.W decoder.
            need(raw == bytes.fromhex('fff7febf'), 'original THM_JUMP24 -4 template')
            addend = -4
    semantic = (resolved or {}).get('Symbol') or target['name']
    hook = target['name'] in h.HOOKS
    counter = bool(re.match(r'^__gcov[0-9_]*[.]', semantic))
    if hook and kind in (10, 30):
        need(addend == -4, 'original hook transfer -4 addend')
    if hook or counter:
        need(owner is not None or image.names[section].startswith(('.data', '.rodata', '.init_array', '.fini_array')),
             'classified compiler metadata location')
    return dict(Section=section, Offset=offset, Kind=kind, Target=dict(target), Owner=owner,
        SiteBytes=raw.hex(), FieldBytes=4, OriginalAddend=addend, ResolvedABS32=resolved,
        SemanticTarget=semantic, CompilerHook=hook, CompilerCounter=counter,
        OriginalHookTransferValidated=hook and kind in (10, 30), AppliedDestinationValidated=False)


def _inspect(image, core, h, *, mutation, stress):
    _helpers(h)
    h._header(image, core)
    for item in image.symbols:
        h._symbol_fields(item)
    functions = h._functions(image)
    protected = (STRESS,) if stress else PROTECTED
    allowed = set(protected) | (set() if stress else {COLD})
    constructors = {name for name in functions if re.fullmatch(CONSTRUCTOR, name)}
    need(set(functions) == allowed | constructors, 'exact lowered function catalog')
    for name in protected:
        need(functions[name]['binding'] in (('STB_WEAK', 'STB_GLOBAL') if name == PANIC else ('STB_GLOBAL',)),
             'protected binding: ' + name)
        if name in THREAD:
            need(image.names[functions[name]['section']] == THREAD_SECTION, 'Thread section: ' + name)
    undefined = []
    for item in image.symbols:
        if item['section'] != 'SHN_UNDEF' or not item['name']:
            continue
        need(item['binding'] == 'STB_GLOBAL' and item['kind'] in ('STT_NOTYPE', 'STT_FUNC', 'STT_OBJECT'),
             'strong undefined dependency')
        undefined.append(item['name'])
    need(len(undefined) == len(set(undefined)), 'unique undefined imports')
    base = set() if stress else set(FORWARD)
    need(base <= set(undefined) <= base | h.HOOKS, 'exact source imports plus classified compiler imports')
    walks = {name: h._walk(image, core, item) for name, item in functions.items()}
    rows = {name: [] for name in functions}
    references, outside, fields = [], [], set()
    for key, pair in sorted(image.relocations.items()):
        row = _reference(image, core, h, functions, walks, key, pair, fields)
        (rows[row['Owner']] if row['Owner'] is not None else outside).append(row)
        references.append(row)
    imported = set(undefined) & h.HOOKS
    need(set(undefined) <= {row['Target']['name'] for row in references}, 'every import has actual original REL use')
    if not stress:
        need(h.COLD_IMPORTS <= imported, 'ordinary cold families active')
        if mutation is None:
            need(imported == h.COLD_IMPORTS, 'exact positive aggregate compiler imports')
    elif mutation is None:
        need(not undefined and not constructors, 'protected stress has no imports or constructors')
    counters = [item for item in image.symbols if item['name'].startswith('__gcov') and item['section'] != 'SHN_UNDEF']
    counter_owners = ({COLD} if not stress else set()) | ({mutation} if mutation else set())
    for item in counters:
        need(item['kind'] == 'STT_OBJECT' and item['size'] > 0 and type(item['section']) is int
             and 0 < item['section'] < len(image.sections)
             and any(item['name'] in ('__gcov0.' + name, '__gcov_.' + name) for name in counter_owners),
             'counter definition owner/kind')
        header = image.sections[item['section']].header
        need(header.sh_type in ('SHT_NOBITS', 'SHT_PROGBITS') and header.sh_flags & 3 == 3
             and not header.sh_flags & 4 and item['value'] + item['size'] <= header.sh_size,
             'counter storage mapping/bounds')
    if not stress:
        activity = {row['Target']['name'] for row in rows[COLD] if row['OriginalHookTransferValidated']}
        need({'__cyg_profile_func_enter', '__cyg_profile_func_exit', '__stack_chk_fail',
              '__sanitizer_cov_trace_pc'} <= activity
             and any(row['Target']['name'] == '__stack_chk_guard' for row in rows[COLD]),
             'ordinary cold actual function/SSP/trace-pc activity')
        need(any(item['name'] == '__gcov0.' + COLD for item in counters)
             and any(row['CompilerCounter'] and row['Kind'] == 2 and row['ResolvedABS32'] is not None
                     and row['ResolvedABS32']['Symbol'] == '__gcov0.' + COLD for row in rows[COLD]),
             'ordinary cold resolved carrier counter reference')
    for row in outside:
        need(not row['CompilerHook'] or row['Target']['name'] == '__gcov_merge_add',
             'only gcov merge metadata hook outside bodies')
    pending, evidence = [], []
    for name in protected:
        effects = [row for row in rows[name] if row['CompilerHook'] or row['CompilerCounter']]
        if name == mutation:
            actual = {row['Target']['name'] for row in effects if row['OriginalHookTransferValidated']}
            expected = {'__cyg_profile_func_enter'} | (set() if name == PANIC else {'__cyg_profile_func_exit'})
            need(expected <= actual, 'mutant actual carrier instrumentation: ' + name)
        elif effects:
            need(not stress and name == SETTER, 'protected body compiler effect: ' + name)
            pending.append(dict(Function=name, Effects=copy.deepcopy(effects),
                ColdCounterReferences=[copy.deepcopy(row) for row in rows[name]
                    if row['SemanticTarget'] in ('__gcov0.' + COLD, '__gcov_.' + COLD)],
                ColdAddressReferences=[copy.deepcopy(row) for row in rows[name] if row['SemanticTarget'] == COLD],
                AttributionValidated=False))
        item = functions[name]
        instructions, data = walks[name]
        need(instructions, 'nonempty complete protected body')
        evidence.append(dict(Name=name, Symbol=dict(item), Section=image.names[item['section']],
            BodySha256=sha(image.section_read(item['section'], item['value'] & ~1, item['size'])),
            InstructionCount=len(instructions), MappedData=data, References=copy.deepcopy(rows[name]),
            DirectCompilerEffects=len(effects), AnnotationMutant=name == mutation, CompleteBodyCovered=True))
    stress_counter = None
    if stress and mutation:
        name = '__gcov0.' + STRESS
        definitions = [item for item in counters if item['name'] == name]
        carrier = [row for row in rows[STRESS] if row['CompilerCounter'] and row['Kind'] == 2
                   and row['ResolvedABS32'] is not None and row['ResolvedABS32']['Symbol'] == name]
        need(len(definitions) == 1 and carrier, 'raw stress actual carrier counter definition/reference')
        stress_counter = dict(Definition=dict(definitions[0]), References=copy.deepcopy(carrier))
        seen = {row['Target']['name'] for row in rows[STRESS]}
        for family, required in h.STRESS_FAMILIES.items():
            available = {row['Target']['name'] for row in references} if family == 'Profiling' else seen
            need(set(required) <= available, 'stress family not activated: ' + family)
    for name in constructors:
        need(all(not row['CompilerHook'] or row['Target']['name'] in {
            '__gcov_init', '__gcov_exit', '__stack_chk_guard', '__stack_chk_fail', '__sanitizer_cov_trace_pc'}
            for row in rows[name]), 'compiler constructor hook family')
    result = dict(Status=PENDING if pending else MUTANT if mutation else PASS, Scope=SCOPE,
        Profile='CM3', Mode='Os-lto', Linkage='direct', Stress=stress, Mutation=mutation,
        ModeAuthority='CALLER_AUTHENTICATED_OS_WORKER_FLAGS', HelperAuthenticationCallerOwned=True,
        ObjectSha256=sha(image.data), ProtectedFunctions=len(protected), RootEvidence=evidence,
        Undefined=sorted(undefined), CompilerImports=sorted(imported),
        OrdinaryEvidence=[] if stress else copy.deepcopy(rows[COLD]),
        CounterDefinitions=copy.deepcopy(counters), References=references,
        CompilerConstructors=[dict(Name=name, Symbol=dict(functions[name]), References=copy.deepcopy(rows[name]),
            BodySha256=sha(image.section_read(functions[name]['section'], functions[name]['value'] & ~1,
                                            functions[name]['size']))) for name in sorted(constructors)],
        MetadataReferences=copy.deepcopy(outside), UnresolvedAttribution=pending,
        AllProtectedBodiesClean=not pending and mutation is None, CompiledAnnotationMutantDetected=mutation is not None,
        StressFamiliesActivated=stress and mutation is not None, StressCounterEvidence=stress_counter,
        ThreadSectionValidated=not stress, OrdinaryColdActivityValidated=not stress,
        ColdInlineAttributionValidated=not pending, OriginalRELFieldsCensused=True,
        RelocationFields=len(references), RequiredCellCount=0, RequiredCellsSatisfied=0,
        **dict.fromkeys(FALSE_FIELDS, False))
    return require_result(result, mutation=mutation, stress=stress)


def inspect_lowered(image, core, helpers, *, mutation=None, stress=False):
    """Inspect one actual original ET_REL, never infer its Os flag authority."""
    need(type(stress) is bool and (mutation is None or type(mutation) is str), 'literal inspection selectors')
    need(mutation in ((None, STRESS) if stress else (None,) + MUTATIONS), 'fixed source annotation mutant')
    try:
        return _inspect(image, core, helpers, mutation=mutation, stress=stress)
    except helpers.Rejected as error:
        raise Rejected('REJECT:CM3-OS-LTO-COMMON-EFFECTS:neutral primitive: ' + str(error)) from error


def _hash(value, message):
    need(type(value) is str and re.fullmatch('[0-9A-F]{64}', value) is not None, message)


def _returned_reference(row):
    need(type(row) is dict and type(row.get('Kind')) is int and row['Kind'] in (2, 10, 30), 'returned REL kind')
    need(all(type(row.get(key)) is int and row[key] >= (1 if key == 'Section' else 0)
             for key in ('Section', 'Offset')) and type(row.get('FieldBytes')) is int and row['FieldBytes'] == 4
         and type(row.get('OriginalAddend')) is int and (row['Owner'] is None or type(row['Owner']) is str),
         'returned literal REL fields')
    need(type(row.get('SiteBytes')) is str and re.fullmatch('[0-9a-f]{8}', row['SiteBytes']) is not None
         and type(row.get('Target')) is dict and row['Target']
         and type(row.get('SemanticTarget')) is str, 'returned raw REL bytes/target')
    for key in ('CompilerHook', 'CompilerCounter', 'OriginalHookTransferValidated'):
        need(type(row.get(key)) is bool, 'returned REL boolean/' + key)
    need(row.get('AppliedDestinationValidated') is False, 'no applied destination claim')
    if row['Kind'] == 2:
        need(row['Offset'] % 4 == 0 and row['OriginalAddend'] == struct.unpack('<I', bytes.fromhex(row['SiteBytes']))[0],
             'returned ABS32 raw addend')
    else:
        need(row['Offset'] % 2 == 0, 'returned Thumb field alignment')
    if row['OriginalHookTransferValidated']:
        need(row['CompilerHook'] and row['Kind'] in (10, 30) and row['OriginalAddend'] == -4,
             'returned validated original hook transfer')


def require_result(proof, *, mutation=None, stress=False):
    """Strict returned-leaf shape; never replaces inspecting authenticated bytes."""
    need(type(proof) is dict and type(stress) is bool and (mutation is None or type(mutation) is str)
         and mutation in ((None, STRESS) if stress else (None,) + MUTATIONS), 'literal result/selectors')
    for key, expected in (('Scope', SCOPE), ('Profile', 'CM3'), ('Mode', 'Os-lto'), ('Linkage', 'direct'),
            ('ModeAuthority', 'CALLER_AUTHENTICATED_OS_WORKER_FLAGS')):
        need(type(proof.get(key)) is str and proof[key] == expected, 'fixed returned scope/' + key)
    need(proof.get('Stress') is stress and proof.get('Mutation') == mutation, 'returned selectors')
    for key in FALSE_FIELDS:
        need(proof.get(key) is False, 'nonclaim/' + key)
    need(proof.get('HelperAuthenticationCallerOwned') is True and proof.get('OriginalRELFieldsCensused') is True,
         'caller authority and original field census')
    for key in ('RequiredCellCount', 'RequiredCellsSatisfied'):
        need(type(proof.get(key)) is int and proof[key] == 0, 'zero typed credit/' + key)
    _hash(proof.get('ObjectSha256'), 'object byte hash')
    names = (STRESS,) if stress else PROTECTED
    need(type(proof.get('ProtectedFunctions')) is int and proof['ProtectedFunctions'] == len(names),
         'complete protected count')
    roots = proof.get('RootEvidence')
    need(type(roots) is list and len(roots) == len(names) and all(type(row) is dict for row in roots)
         and [row.get('Name') for row in roots] == list(names), 'complete ordered protected roots')
    refs = proof.get('References')
    need(type(refs) is list and type(proof.get('RelocationFields')) is int
         and proof['RelocationFields'] == len(refs), 'literal complete REL census')
    sites = set()
    for row in refs:
        _returned_reference(row)
        site = row['Section'], row['Offset']
        need(site not in sites and all(section != site[0] or site[1] + 4 <= offset or offset + 4 <= site[1]
                                      for section, offset in sites), 'returned overlapping REL sites')
        sites.add(site)
    for root in roots:
        need(type(root.get('Symbol')) is dict and root['Symbol'].get('name') == root['Name']
             and type(root.get('Section')) is str and root.get('CompleteBodyCovered') is True
             and type(root.get('InstructionCount')) is int and root['InstructionCount'] > 0,
             'complete returned root metadata')
        _hash(root.get('BodySha256'), 'root raw body hash')
        need(type(root.get('References')) is list
             and root['References'] == [row for row in refs if row['Owner'] == root['Name']], 'complete root REL projection')
        effects = [row for row in root['References'] if row['CompilerHook'] or row['CompilerCounter']]
        need(type(root.get('DirectCompilerEffects')) is int and root['DirectCompilerEffects'] == len(effects)
             and root.get('AnnotationMutant') is (root['Name'] == mutation), 'typed root effects')
        need(type(root.get('MappedData')) is list, 'complete mapped data records')
    for field in ('Undefined', 'CompilerImports'):
        values = proof.get(field)
        need(type(values) is list and all(type(value) is str and value for value in values)
             and values == sorted(set(values)), 'unique literal import list/' + field)
    need(type(proof.get('OrdinaryEvidence')) is list and type(proof.get('MetadataReferences')) is list
         and proof['OrdinaryEvidence'] == ([] if stress else [row for row in refs if row['Owner'] == COLD])
         and proof['MetadataReferences'] == [row for row in refs if row['Owner'] is None], 'returned ordinary/metadata projections')
    for field in ('CounterDefinitions', 'CompilerConstructors', 'UnresolvedAttribution'):
        need(type(proof.get(field)) is list and all(type(row) is dict for row in proof[field]), 'returned list/' + field)
    pending = proof['UnresolvedAttribution']
    need(len(pending) <= 1 and all(row.get('Function') == SETTER and row.get('AttributionValidated') is False
         and type(row.get('Effects')) is list and row['Effects'] for row in pending), 'only unresolved setter attribution')
    if pending:
        need(not stress and pending[0]['Effects'] == [row for row in refs if row['Owner'] == SETTER
             and (row['CompilerHook'] or row['CompilerCounter'])], 'complete pending setter effects')
    need(proof.get('Status') == (PENDING if pending else MUTANT if mutation else PASS)
         and proof.get('AllProtectedBodiesClean') is (not pending and mutation is None)
         and proof.get('ColdInlineAttributionValidated') is (not pending)
         and proof.get('CompiledAnnotationMutantDetected') is (mutation is not None)
         and proof.get('StressFamiliesActivated') is (stress and mutation is not None)
         and proof.get('ThreadSectionValidated') is (not stress)
         and proof.get('OrdinaryColdActivityValidated') is (not stress), 'consistent typed returned disposition')
    if stress and mutation:
        counter = proof.get('StressCounterEvidence')
        need(type(counter) is dict and type(counter.get('Definition')) is dict
             and counter['Definition'].get('name') == '__gcov0.' + STRESS
             and type(counter.get('References')) is list and counter['References']
             and all(row in refs and row['Owner'] == STRESS and row['Kind'] == 2
                     and row['CompilerCounter'] for row in counter['References']), 'raw stress counter evidence')
    else:
        need(proof.get('StressCounterEvidence') is None, 'no invented stress counter evidence')
    return proof
