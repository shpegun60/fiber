"""Read-only ordinary direct root replay through the unchanged family gates."""
import copy
from contextlib import nullcontext
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[3]
PROFILES = 'tools/fixtures/ordinary_final_cell/profiles.py'
PROFILES_SHA = 'BDD5C9A1F490FF3156CB4DC752F0C411F6FA07852BA5024124E91CC05601CFCD'
POLICY = 'tools/fixtures/classic_final_join/POLICY_DIFFERENCES.md'
POLICY_SHA = 'D5744662AF124C41709AF73E3DA3819B0C9797EEE0F597B27D572FFACDB509EB'
POLICY_ID = 'FAP-FP-SETUP-POLICY'
FAMILIES = dict(CM0='cm0', CM0PLUS='cm0', CM0PLUSVTOR='cm0', CM3='cm3', CM4='classic', CM7='classic')
MODES = ('O0', 'Og', 'O2', 'Os', 'O3')


def need(condition, message):
    if not condition:
        raise ValueError('ordinary-cell-recompute: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return json.dumps(value, sort_keys=True, allow_nan=False, separators=(',', ':')).encode('ascii')


def module(name, path, raw):
    """Execute only the single source buffer authenticated by the caller's watch."""
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[name] = loaded
    exec(compile(raw, str(path), 'exec'), loaded.__dict__)
    return loaded


def rationale_facts(raw, identifiers):
    need(type(raw) is bytes and type(identifiers) is list and identifiers
         and all(type(item) is str and item for item in identifiers)
         and len(set(identifiers)) == len(identifiers), 'nonempty unique declared differences')
    text = raw.decode('ascii')
    headings = list(re.finditer(r'^#{1,6}[ \t]+([^\r\n]+?)[ \t]*\r?$', text, re.MULTILINE))
    facts = []
    for identifier in identifiers:
        matches = [i for i, heading in enumerate(headings) if heading[1] == identifier]
        need(len(matches) == 1 and headings[matches[0]][0].startswith('### '),
             'one exact captured rationale heading: ' + identifier)
        index = matches[0]
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        body = text[headings[index].end():end].strip()
        visible = re.sub(r'<!--.*?-->', '', body, flags=re.DOTALL)
        need(re.search(r'[A-Za-z0-9]', visible) is not None, 'nonempty captured rationale: ' + identifier)
        facts.append(dict(Id=identifier, RationaleSha256=sha(body.encode('ascii'))))
    return facts


def recheck_pilot(native, native_api, final_api, attributes, manifest, profile, mode):
    """Replay every native prelink and final predicate, without invoking a build."""
    result, root = native['Result'], native['Root']
    pilot = native_api.Pilot.__new__(native_api.Pilot)
    pilot.root, pilot.profile, pilot.mode = root / 'source', profile, mode
    pilot.sources = [Path(row['Source']) for row in result['Sources']]
    pilot.objects = [Path(row['Object']) for row in result['Sources']]
    pilot.object_hashes = tuple((row['Object'], row['ObjectSha256']) for row in result['Sources'])
    pilot.fixture_copy = root / 'source/tools/fixtures/classic_final_image'
    pilot.admission, pilot.final_reader = attributes, final_api
    pilot.storage = native_api.selection(profile, mode)[2]
    pilot.artifact = native_api.require_manifest_selection(manifest, profile, mode, attributes)
    pilot.report = dict(Sources=copy.deepcopy(result['Sources']))
    pilot.prelink()
    for name, value in pilot.report.items():
        need(encoded(value) == encoded(result[name]), 'recomputed complete native prelink: ' + name)
    for link in result['Links']:
        pilot.audit_final(Path(link['Path']))
    return pilot.report


def _producer_bindings(prepared, family):
    result = []
    for side in ('Native', 'Reference'):
        group = prepared[side]
        row = dict(Side=side, Build=str(group['Root']), ReceiptSha256=group['ReceiptSha256'],
                   UniqueImageInputs=group['UniqueImageInputs'])
        if family == 'cm0':
            row['Prelinks'] = group['Prelinks']
        else:
            row['PrelinkSha256'] = group['PrelinkSha256']
        if family == 'cm3':
            row.update(ArtifactsSha256=group['ManifestSha256'], Prelink=group['Prelink'],
                       OwnerEvidence=group['ReplayedOwnerEvidence'])
        result.append(row)
    return result


def _protocol(join, helpers, prepared, profile, mode, family):
    native, reference = (prepared[side]['MechanismObject'] for side in ('Native', 'Reference'))
    if family == 'cm3':
        join.require_cross_side_inputs(prepared['Native'], prepared['Reference'])
        proof = helpers['checker'].check_pair(native, reference)
        helpers['inventory'].require_proof(proof, mode)
        join.require_mechanisms(proof)
        expected = list(dict.fromkeys(item for row in join.expected_mechanisms() for item in row['DifferenceIds']))
        need(encoded(proof['DifferenceIds']) == encoded(expected), 'ordered CM3 difference identities')
        roots = [*prepared['Native']['Result']['PrelinkNativeRoots'],
                 *prepared['Reference']['Result']['PrelinkReferenceRoots']]
        need(encoded(proof['RootEvidence']) == encoded(roots), 'CM3 same-object complete protocol evidence')
    else:
        proof = helpers['checker'].check_pair(native, reference, mode if family == 'cm0' else profile)
        if family == 'cm0':
            helpers['attributes'].require_proof(proof, mode)
        else:
            helpers['attributes'].require_proof(proof, profile, mode)
        join.require_pairings(proof, profile)
    return proof


def _compare(api, previous, prepared, proof, family, selection, fingerprint, pin, ledger):
    replayed = dict(ProtocolProof=proof, ClosedBodies=8 if family == 'cm0' else 6,
        Mechanisms=proof['Mechanisms'], ProducerBindings=_producer_bindings(prepared, family),
        SourceInventorySha256=fingerprint, ReferenceCommit=pin, LedgerSha256=sha(ledger),
        NativeArtifactsSha256=selection['Native']['ArtifactsSha256'],
        ReferenceArtifactsSha256=selection['Reference']['ArtifactsSha256'])
    for side in ('Native', 'Reference'):
        replayed[side + 'FinalRoots'] = prepared[side]['Roots']
        replayed[side + 'Twins'] = prepared[side]['Twins']
    if family == 'cm3':
        replayed.update(HashDomains=dict(PrelinkProtocol='SHA256-JSON-TOKENS',
            FinalRoot='SHA256-APPLIED-ELF-FUNCTION-BYTES', Ledger='SHA256-CAPTURED-LEDGER-BYTES'),
            FrameContract=dict(NativeCoreSlots=9, NativeExcReturn='PER-CONTEXT-SAVED-LR',
                ReferenceCoreSlots=8, ReferenceFirstRestoreExcReturn='ORR-LR-13', EquivalenceProven=False))
    for name, value in replayed.items():
        api.same(value, previous[name], 'recomputed complete join: ' + name)
    return replayed


def _replay(api, watch, join, joined_watch, helpers, output, selection, groups, current, contract, bindings, family):
    profile, mode = contract['Profile'], contract['Mode']
    if family == 'cm3':
        prepared = {side: join.prepare_group(joined_watch, groups[side], side, profile, mode, helpers)
                    for side in ('Native', 'Reference')}
    else:
        prepared = {side: join.prepare_group(joined_watch, groups[side]['Root'], selection[side]['ReceiptSha256'],
                    side, profile, mode, helpers) for side in ('Native', 'Reference')}
    for side, group in prepared.items():
        api.same(group['Result'], groups[side]['Result'], 'same authenticated producer: ' + side)
        need(group['Inventory'] == current['Bundle']['Root'], 'same current captured inventory: ' + side)
        api.same(group['Result']['SourceInventorySha256'], current['SourceInventorySha256'], 'inventory fingerprint')
    proof = _protocol(join, helpers, prepared, profile, mode, family)
    identifiers = proof['DifferenceIds']
    ledger = watch.read(current['Bundle']['Root'] / 'inputs/FREERTOS_ASM_PARITY.md')
    rationales = rationale_facts(ledger, identifiers)
    expected_ids = contract['DifferenceIds']
    need(len(expected_ids) == len(set(expected_ids)) and
         set(identifiers) == set(expected_ids) - ({POLICY_ID} if family == 'classic' else set()),
         'exact independent profile difference inventory')
    previous = groups['PriorJoin']['Result']
    compared = _compare(api, previous, prepared, proof, family, selection,
                        current['SourceInventorySha256'], contract['ReferenceCommit'], ledger)
    facts = dict(Profile=profile, Mode=mode, Scope='ORDINARY_DIRECT_COMPLETE_FAMILY_ROOT_RECOMPUTATION_ONLY',
        MechanismParityWithDeclaredDifferences=True, Protocol=proof, Rationales=rationales,
        LedgerSha256=sha(ledger), ProducerBindings=compared['ProducerBindings'],
        HashDomains=dict(PrelinkProtocol='SHA256-JSON-TOKENS', FinalRoot='SHA256-APPLIED-ELF-FUNCTION-BYTES',
                         Ledger='SHA256-CAPTURED-LEDGER-BYTES'),
        SourceInventorySha256=current['SourceInventorySha256'],
        RequiredCellsSatisfied=0, FullABIProof=False, FullSemanticABIProof=False, InstructionEquivalence=False,
        PolicyEquivalence=False, SourceIRProof=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False)
    for name in ('ClosedBodies', 'Mechanisms', 'NativeFinalRoots', 'ReferenceFinalRoots', 'NativeTwins', 'ReferenceTwins'):
        facts[name] = compared[name]
    if family == 'cm3':
        declared = join.require_ledger(ledger.decode('ascii'), proof)
        api.same(declared, previous['DifferenceRationales'], 'complete CM3 captured rationales')
        executed_sources = copy.deepcopy(list(helpers['ExecutedSourceBuffers']))
        api.same(executed_sources, previous['ExecutedSourceBuffers'],
                 'complete CM3 executed immutable source evidence')
        facts['ExecutedSourceBuffers'] = executed_sources
        facts['NativePredicates'] = dict(Sources=copy.deepcopy(prepared['Native']['Result']['Sources']),
                                        **prepared['Native']['ReplayedOwnerEvidence'])
        facts['FrameContract'] = compared['FrameContract']
    else:
        facts['NativePredicates'] = recheck_pilot(prepared['Native'], helpers['native'], helpers['final'],
            helpers['attributes'], current['Manifest'], profile, mode)
    if family == 'classic':
        policy = watch.read(ROOT / POLICY, POLICY_SHA)
        supplement = rationale_facts(policy, [POLICY_ID])
        api.same(POLICY_ID, previous['FPSetupDifferenceId'], 'separate unresolved FP setup difference')
        api.same(sha(policy), previous['PolicySupplementSha256'], 'same captured FP policy supplement')
        facts['FPPolicySupplement'] = dict(Sha256=sha(policy), Rationales=supplement,
            NativePolicy=contract['NativeFPPolicy'], ReferencePolicy=contract['ReferenceFPPolicy'],
            PolicyEquivalence=False, HardwareEffectsProven=False)
    facts['Bindings'] = bindings.inspect(contract, prepared['Native']['Result'], prepared['Native']['Root'], helpers['final'])
    need(facts['Bindings'].get('Status') == 'PASS', 'all independent native thin bindings')
    api.same(facts['NativePredicates']['Sources'], prepared['Native']['Result']['Sources'], 'full native source authority')
    return facts


def recompute(api, watch, output, selection, groups, current, contract, bindings):
    """Replay one admitted ordinary route inside the caller's immutable-read scope.

    Return facts, the family's closing watch, and exact-byte output-copy hashes.
    The caller must reclose both watches against physical files after that scope.
    """
    need(not sys.flags.optimize, 'unoptimized Python required by frozen predicates')
    profile, mode = contract['Profile'], contract['Mode']
    need(type(profile) is str and profile in FAMILIES and type(mode) is str and mode in MODES,
         'one closed ordinary profile and mode')
    profiles = module('_ordinary_cell_profiles_recompute', ROOT / PROFILES, watch.read(ROOT / PROFILES, PROFILES_SHA))
    api.same(contract, profiles.profile(profile, mode), 'independent complete profile contract')
    api.same(selection['Route'], contract['Route'], 'exact selected route')
    api.same(current['SourceInventorySha256'], contract['SourceInventorySha256'], 'independent current inventory')
    profiles.require_native(groups['Native']['Result'], profile, mode)
    profiles.require_reference(groups['Reference']['Result'], profile, mode)
    family = FAMILIES[profile]
    relative = 'tools/fixtures/' + family + '_final_join/join.py'
    api.same(contract['Gate'], relative, 'closed family gate')
    join = module('_ordinary_cell_family_join', ROOT / relative, watch.read(ROOT / relative, api.SOURCE_PINS[relative]))
    joined_watch = join.Watch(output / 'recomputed')
    if family == 'cm3':
        prepared_inputs = {}
        for side in ('Native', 'Reference'):
            row = selection[side]
            group = join._authenticate(joined_watch, groups[side]['Root'], row['ReceiptSha256'], row['ArtifactsSha256'])
            api.same(group['Result'], groups[side]['Result'], 'same CM3 authenticated result')
            api.same(group['Artifacts'], groups[side]['Artifacts'], 'same CM3 authenticated artifact membership')
            prepared_inputs[side] = group
        prepared_inputs['PriorJoin'] = groups['PriorJoin']
        context = join.load_api(joined_watch, prepared_inputs['Native'], prepared_inputs['Reference'])
    else:
        prepared_inputs = groups
        context = nullcontext(join.load_api(joined_watch, groups['Native']['Root']))
    with context as helpers:
        facts = _replay(api, watch, join, joined_watch, helpers, output, selection, prepared_inputs,
                        current, contract, bindings, family)
    joined_watch.close()
    for path, digest in tuple(joined_watch.hashes.items()):
        watch.read(path, digest)
    copies = {}
    for original, path in joined_watch.copies.items():
        digest = joined_watch.hashes[original]
        watch.read(path, digest)
        copies[path.relative_to(output).as_posix()] = digest
    return facts, joined_watch, copies
