"""Pure six-body CM3 O2-lto mechanism join, not final/reference qualification.

The caller authenticates receipts, helper identities and each real protocol view.
Each view must decode its own independently preserved generated machine. This
module performs no I/O, imports no selected helper and supplies no opposite-side
substitute. Raw transport evidence stays separate from canonical token hashes.
"""
import copy
import hashlib
import json
import re


NATIVE_ROOTS = ('fiber_port_start_first_context', 'SVC_Handler', 'PendSV_Handler')
REFERENCE_ROOTS = ('prvPortStartFirstTask', 'vPortSVCHandler', 'xPortPendSVHandler')
COHORT = 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default'
SCOPE = 'CM3_O2_LTO_P4_B16_DIRECT_SIX_CLOSED_ROOT_JOIN_ONLY'
PASS = 'CM3-LTO-SIX-BODY-JOIN-PASS-NOT-QUALIFIED'
HASH_DOMAINS = dict(MachineRoot='SHA256-UNAPPLIED-MACHINE-FUNCTION-BYTES',
                    FinalRoot='SHA256-APPLIED-FINAL-FUNCTION-BYTES', Canonical='SHA256-JSON-TOKENS')


class Rejected(RuntimeError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected('REJECT:CM3-LTO-JOIN:' + message)


def _sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def _digest(value, label):
    need(type(value) is str and re.fullmatch(r'[A-F0-9]{64}', value) is not None,
         'exact uppercase SHA256 required: ' + label)
    return value


def _json(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise Rejected('REJECT:CM3-LTO-JOIN:JSON evidence required') from error


def _same(actual, expected, label):
    need(_json(actual) == _json(expected), label)


def expected_mechanisms():
    return [dict(Name='first-start', NativeRoot=NATIVE_ROOTS[0], ReferenceRoot=REFERENCE_ROOTS[0],
                 DifferenceIds=['FAP-COMMON-START', 'FAP-COMMON-PROVENANCE', 'FAP-CM3-LOCAL-LITERAL-POOLS']),
        dict(Name='first-restore', NativeRoot=NATIVE_ROOTS[1], ReferenceRoot=REFERENCE_ROOTS[1],
             DifferenceIds=['FAP-COMMON-PROVENANCE', 'FAP-COMMON-MASK-RESTORE', 'FAP-CM3-EXC-RETURN', 'FAP-CM3-LOCAL-LITERAL-POOLS']),
        dict(Name='PendSV', NativeRoot=NATIVE_ROOTS[2], ReferenceRoot=REFERENCE_ROOTS[2],
             DifferenceIds=['FAP-COMMON-SCHEDULER', 'FAP-COMMON-PROVENANCE', 'FAP-CM3-EXC-RETURN', 'FAP-CM3-LOCAL-LITERAL-POOLS'])]


def _difference_ids():
    return list(dict.fromkeys(identity for row in expected_mechanisms() for identity in row['DifferenceIds']))


def require_ledger(ledger, proof):
    need(type(ledger) is str and ledger.isascii(), 'captured ASCII difference ledger required')
    need(type(proof) is dict and type(proof.get('DifferenceIds')) is list, 'difference identity proof required')
    identities = proof['DifferenceIds']
    _same(identities, _difference_ids(), 'exact six ordered captured rationale identities required')
    rationales = {}
    for identity in identities:
        matches = list(re.finditer(r'^### ' + re.escape(identity) + r'[^\S\r\n]*\r?$', ledger, re.MULTILINE))
        need(len(matches) == 1, 'one captured rationale heading required: ' + identity)
        start = matches[0].end()
        following = re.search(r'^#{1,6}\s+', ledger[start:], re.MULTILINE)
        body = ledger[start:start + following.start()] if following else ledger[start:]
        need(re.search(r'[A-Za-z0-9]', re.sub(r'<!--.*?-->', '', body, flags=re.DOTALL)) is not None,
             'nonempty captured difference rationale required: ' + identity)
        rationales[identity] = dict(Text=body.strip(), TextSha256=_sha(body.strip().encode('ascii')))
    return rationales


def _machine(view, side):
    decoded, transport = getattr(view, 'decoded', None), getattr(view, 'transport', None)
    data = getattr(decoded, 'data', None)
    preserved = getattr(getattr(transport, 'machine', None), 'data', None)
    need(type(data) is bytes and data and type(preserved) is bytes and data == preserved,
         side + ' decoder/preserved whole machine bytes must match')
    need(getattr(view, 'machine_sha', None) == _sha(data), side + ' whole machine hash mismatch')
    need(callable(getattr(view, 'function', None)) and type(getattr(view, 'evidence', None)) is dict,
         side + ' real protocol view interface required')
    return data


def _proof(proof):
    need(type(proof) is dict and proof.get('Verdict') == 'CM3-CLOSED-ROOTS-PASS'
         and proof.get('ProofScope') == 'CM3_P4_B16_SIX_CLOSED_ROOT_PROTOCOLS_ONLY'
         and type(proof.get('ClosedBodies')) is int and proof['ClosedBodies'] == 6,
         'complete unchanged six-body protocol proof required')
    need(type(proof.get('Roots')) is list and all(type(name) is str for name in proof['Roots']),
         'literal ordered root name list required')
    mechanisms = proof.get('Mechanisms')
    need(type(mechanisms) is list and len(mechanisms) == 3 and all(type(row) is dict
         and type(row.get('DifferenceIds')) is list and all(type(identity) is str for identity in row['DifferenceIds'])
         for row in mechanisms), 'three literal mechanism rows and difference lists required')
    need(type(proof.get('DifferenceIds')) is list and all(type(identity) is str for identity in proof['DifferenceIds']),
         'literal ordered difference identity list required')
    _same(proof.get('Roots'), list(NATIVE_ROOTS), 'exact native root names/order required')
    _same(proof.get('Mechanisms'), expected_mechanisms(), 'exact three mechanism/difference assignments required')
    _same(proof.get('DifferenceIds'), _difference_ids(), 'exact six ordered difference identities required')
    for key in ('RequiredCellSatisfied', 'CompleteObjectProof', 'InstructionEquivalence', 'CpuExecution',
                'FinalElfProof', 'GlobalFreezeQualified'):
        need(proof.get(key) is False, 'protocol proof promotion forbidden: ' + key)
    for key in ('BoardExecution', 'FinalReferenceParity', 'FullABIProof', 'PolicyEquivalence',
                'SourceToMachineSemanticProof', 'SourceToIRSemanticProof', 'SourceIRProof'):
        if key in proof:
            need(proof[key] is False, 'protocol proof promotion forbidden: ' + key)
    if 'RequiredCellsSatisfied' in proof:
        need(type(proof['RequiredCellsSatisfied']) is int and proof['RequiredCellsSatisfied'] == 0,
             'protocol proof cannot earn required cells')
    _same(proof.get('DifferenceSource'),
          dict(Spec='tools/freertos_asm_parity.ps1:Assert-Cm3Mechanisms', Ledger='FREERTOS_ASM_PARITY.md'),
          'fixed difference provenance required')
    _same(proof.get('ReferenceSvcObligation'), dict(StartRoot=REFERENCE_ROOTS[0], RestoreRoot=REFERENCE_ROOTS[1],
          FirstContextExcReturnProtocolMatched=True, HandlerRoutingProven=False, UnreachabilityProven=False),
          'reference first-context obligation is a matched protocol, not routing/unreachability proof')
    rows = proof.get('RootEvidence')
    need(type(rows) is list and len(rows) == 6, 'six complete ordered root records required')
    identities = [('Native', name) for name in NATIVE_ROOTS] + [('Reference', name) for name in REFERENCE_ROOTS]
    for row, (side, name) in zip(rows, identities):
        need(type(row) is dict and set(row) == {'Side', 'Name', 'Tokens', 'LiteralIslands', 'TailNops', 'BodySha256'}
             and row['Side'] == side and row['Name'] == name, 'complete ordered root evidence identity required')
        need(type(row['Tokens']) is int and row['Tokens'] > 0 and type(row['LiteralIslands']) is int
             and row['LiteralIslands'] == 1 and type(row['TailNops']) is int and row['TailNops'] == 0,
             'O2-lto requires one complete island and literal integer zero tail NOPs on every root')
        _digest(row['BodySha256'], side + '/' + name + '/canonical tokens')


def _tokens(value, label):
    need(type(value) is list and value and all(type(row) is tuple and len(row) == 2
         and all(type(item) is str for item in row) for row in value), 'complete canonical token list: ' + label)
    return _sha(json.dumps(value, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii'))


def _evidence(view, side, names, matched):
    need(tuple(view.evidence) == names, side + ' exact evidence root membership/order required')
    roots, transports = [], []
    machine_sha = _sha(view.decoded.data)
    for name, match in zip(names, matched):
        row = view.evidence[name]
        need(type(row) is dict and row.get('Name') == name and row.get('MachineProviderSha256') == machine_sha,
             side + '/' + name + ' evidence must bind its own whole machine')
        record = row.get('TransportRecord')
        need(type(record) is dict and record.get('Name') == name and record.get('GeneratedMachineBoundRootPreservation') is True,
             side + '/' + name + ' unchanged preserved transport record required')
        for key in ('CanonicalProtocolValidated', 'OriginalTranslationUnitOwnership', 'FinalReferenceParity',
                    'PolicyEquivalence', 'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified'):
            need(record.get(key) is False, 'raw transport evidence promotion forbidden: ' + key)
        for key in ('FullABIProof', 'CompleteObjectProof', 'InstructionEquivalence', 'SourceIRProof',
                    'SourceToMachineSemanticProof', 'SourceToIRSemanticProof'):
            if key in record:
                need(record[key] is False, 'raw transport evidence promotion forbidden: ' + key)
        need(type(record.get('RequiredCellsSatisfied')) is int and record['RequiredCellsSatisfied'] == 0,
             'raw transport cannot earn required cells')
        for key in ('Size', 'InstructionCount'):
            need(type(record.get(key)) is int and record[key] > 0, 'positive typed complete transport extent/count: ' + key)
        need(type(record.get('Instructions')) is list and len(record['Instructions']) == record['InstructionCount']
             and type(record.get('MappedData')) is list and record['MappedData']
             and type(record.get('References')) is list and type(record.get('DefinitionOrigins')) is list,
             'complete raw transport instruction/data/reference evidence required')
        origin = record.get('RootOrigin')
        need(type(origin) is dict and origin.get('Name') == name and origin.get('GeneratedMachineOriginBound') is True
             and origin.get('ProviderSha256') == machine_sha, 'root origin must bind its own generated machine')
        for key in ('OriginalTranslationUnitOwnership', 'CalleeBodyProof', 'CalleeRelocationSemanticsChecked'):
            need(origin.get(key) is False, 'generated origin cannot promote original ownership or callee proof: ' + key)
        machine_body = _digest(record.get('MachineBodySha256'), side + '/' + name + '/machine body')
        final_body = _digest(record.get('BodySha256'), side + '/' + name + '/applied final body')
        need(row.get('MachineBodySha256') == machine_body and row.get('FinalBodySha256') == final_body,
             'transport body hashes must remain in their separate raw byte domains')
        _same(row.get('HashDomains'), HASH_DOMAINS, 'explicit raw machine/final/canonical hash domains required')
        raw = row.get('RawCanonicalTokens')
        raw_hash = _tokens(raw, side + '/' + name + '/raw')
        need(row.get('RawTokenSha256') == raw_hash, 'raw canonical token hash mismatch')
        projections = row.get('ProjectionEvidence')
        need(type(projections) is list, 'explicit semantic projection evidence required')
        if side == 'Native':
            projected = row.get('ProjectedCanonicalTokens')
            canonical_hash = _tokens(projected, side + '/' + name + '/projected')
            need(row.get('ProjectedTokenSha256') == canonical_hash and len(projected) == len(raw)
                 and len(projections) == (0 if name == names[0] else 1),
                 'native evidence must retain exactly the two origin-proved slot projections')
            canonical = projected
        else:
            need(not projections and 'ProjectedCanonicalTokens' not in row and 'ProjectedTokenSha256' not in row,
                 'reference named-symbol tokens must remain unprojected')
            canonical, canonical_hash = raw, raw_hash
        need(match['BodySha256'] == canonical_hash and match['Tokens'] == len(canonical)
             and len(canonical) == record['InstructionCount'] + 1,
             'checker root must bind the same complete view tokens, not a raw byte hash')
        roots.append(copy.deepcopy(row))
        transports.append(copy.deepcopy(record))
    return roots, transports


def check_join(native_view, reference_view, checker, ledger_text):
    """Join the real two views; caller separately authenticates all outer inputs.

    Checker rejection propagates. Join-contract failures raise this module's
    Rejected. The returned evidence is detached from both input view dictionaries.
    """
    need(native_view is not reference_view, 'distinct native and reference views required')
    native_machine, reference_machine = _machine(native_view, 'Native'), _machine(reference_view, 'Reference')
    need(native_machine != reference_machine, 'two distinct whole generated machine byte inputs required')
    need(type(getattr(checker, '_NATIVE', None)) is dict and tuple(checker._NATIVE) == NATIVE_ROOTS
         and type(getattr(checker, '_REFERENCE', None)) is dict and tuple(checker._REFERENCE) == REFERENCE_ROOTS
         and callable(getattr(checker, 'check_pair', None)), 'unchanged native/reference checker root contracts required')
    need(type(ledger_text) is str and ledger_text.isascii(), 'captured ASCII difference ledger required')
    proof = checker.check_pair(native_view, reference_view)
    _proof(proof)
    need(_machine(native_view, 'Native') == native_machine and _machine(reference_view, 'Reference') == reference_machine,
         'machine byte inputs changed while matching complete protocols')
    roots, transport_roots = {}, {}
    roots['Native'], transport_roots['Native'] = _evidence(native_view, 'Native', NATIVE_ROOTS, proof['RootEvidence'][:3])
    roots['Reference'], transport_roots['Reference'] = _evidence(reference_view, 'Reference', REFERENCE_ROOTS, proof['RootEvidence'][3:])
    rationales = require_ledger(ledger_text, proof)
    return dict(Status=PASS, Scope=SCOPE, Profile='CM3', Mode='O2-lto', Cohort=COHORT, Linkage='direct', LTO=True,
        Qualification=False, ClosedBodies=6, Mechanisms=copy.deepcopy(proof['Mechanisms']),
        DifferenceIds=copy.deepcopy(proof['DifferenceIds']), ProtocolProof=copy.deepcopy(proof),
        Roots=roots, RawTransportRoots=transport_roots, OriginalTransportRecordsUnmodified=True,
        DifferenceRationales=rationales, LedgerSha256=_sha(ledger_text.encode('ascii')),
        MachineSha256=dict(Native=_sha(native_machine), Reference=_sha(reference_machine)),
        FrameContract=dict(NativeCoreSlots=9, NativeExcReturn='PER-CONTEXT-SAVED-LR', ReferenceCoreSlots=8,
                           ReferenceFirstRestoreExcReturn='ORR-LR-13', EquivalenceProven=False),
        CanonicalProtocolValidated=True, FinalReferenceParity=False, FullABIProof=False, FinalElfProof=False,
        SourceIRProof=False, SourceToIRSemanticProof=False, SourceToMachineSemanticProof=False,
        OriginalTranslationUnitOwnership=False, InstructionEquivalence=False, PolicyEquivalence=False,
        CompleteObjectProof=False, KernelRuntimeProof=False, HandlerRoutingProven=False,
        ProducerCompilersReexecuted=False, MutantsReexecuted=False, NativeCommandsExecuted=0,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False, RequiredCellSatisfied=False,
        RequiredCellsSatisfied=0)
