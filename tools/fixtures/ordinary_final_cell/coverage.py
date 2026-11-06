"""Pure ordinary-cell accounting over an externally authenticated E9 plan.

Contracts are caller-authenticated canonical profiles.profile dictionaries, not
receipts. Only their credit-relevant projection is checked here; this is not a
second profile oracle, input authenticator, or proof executor. verified_keys is
the caller's final, revocable set of completely verified cells, expressed as a
list of literal five-tuples. No receipt label or previous coverage grants credit.
"""
from copy import deepcopy


COMMON = ('cpu-neutral-engine', 'reverse-v1-ownership', 'source-provider-identity')
RUNTIME = ('forward-eight', 'reverse-v1', 'current-slot-isolation', 'strong-handlers',
           'exact-profile-context-cohort', 'generated-assembly-reference-parity',
           'final-elf-vectors', 'negative-link-controls')
COMPANION = ('companion-gateway-abi', 'paired-image-contract',
             'generated-assembly-reference-parity', 'negative-link-controls')
MODES = ('O0', 'Og', 'O2', 'Os', 'O3')
KEY_FIELDS = ('Cohort', 'ArtifactRole', 'Representation', 'Mode', 'Linkage')
REQUIRED_CELL_COUNT = 2774
BACKLOG_COUNT = 26
SOURCE_INVENTORY_SHA256 = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
_SELECTORS = (
    ('CM0', 'cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default', 'CM0'),
    ('CM0PLUS', 'cm0-cortex-m0plus-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default', 'CM0'),
    ('CM0PLUSVTOR', 'cm0-cortex-m0plus-soft-nofpu-none-v1-mpu0-p2-b0-aapcs-default', 'CM0'),
    ('CM3', 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default', 'CM3'),
    ('CM4', 'cm4-cortex-m4-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default', 'CM4'),
    ('CM7', 'cm7-cortex-m7-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default', 'CM7'),
)


class Rejected(ValueError):
    pass


def _need(condition, message):
    if not condition:
        raise Rejected('ordinary-cell-coverage: ' + message)


def _same(actual, expected):
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return actual.keys() == expected.keys() and all(_same(actual[k], v) for k, v in expected.items())
    if type(expected) in (list, tuple):
        return len(actual) == len(expected) and all(_same(a, b) for a, b in zip(actual, expected))
    return actual == expected


def _text(value):
    return type(value) is str and bool(value) and value.strip() == value and '\x00' not in value


def _hash(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789ABCDEF' for c in value)


def _json(value):
    if type(value) is dict:
        _need(all(type(k) is str for k in value), 'literal string dictionary keys')
        for item in value.values():
            _json(item)
    elif type(value) is list:
        for item in value:
            _json(item)
    else:
        _need(value is None or type(value) in (str, int, bool), 'literal JSON data without floats')


def _key(row):
    _need(type(row) is dict and all(_text(row.get(field)) for field in KEY_FIELDS), 'five literal key fields')
    return tuple(row[field] for field in KEY_FIELDS)


def _plan(required, backlog):
    _need(type(required) is dict, 'required plan dictionary')
    _json(required)
    _need(type(required.get('SchemaVersion')) is int and required['SchemaVersion'] == 1,
          'literal plan schema version one')
    _need(required.get('ExpectedOnly') is True and required.get('Execution') == 'NOT_RUN'
          and required.get('GlobalFreezeQualified') is False, 'unpromoted expected plan')
    _need(type(required.get('RequiredCellCount')) is int
          and required['RequiredCellCount'] == REQUIRED_CELL_COUNT, 'complete 2774-cell plan')
    _need(_hash(required.get('InventoryManifestSha256')), 'canonical manifest fingerprint')
    _need(_same(required.get('ObjectModes'), list(MODES))
          and _same(required.get('FinalModes'), [*MODES, 'O2-lto', 'Os-lto']), 'canonical mode axes')
    obligations = {'common': list(COMMON), 'runtime': list(RUNTIME), 'secure_companion': list(COMPANION)}
    _need(_same(required.get('PlannedProofRequirements'), obligations), 'canonical common-three/runtime-eight/companion obligations')
    cells = required.get('RequiredCells')
    _need(type(cells) is list and len(cells) == REQUIRED_CELL_COUNT, 'all required rows')
    index = {}
    for row in cells:
        key = _key(row)
        _need(key not in index, 'duplicate required key')
        _need(_text(row.get('SourceGroup')) and _hash(row.get('CohortSha256')), 'required source group/cohort identity')
        _need(key[1] in obligations, 'unknown artifact role')
        if key[2] == 'object':
            _need(key[3] in MODES and key[4] == 'none', 'object mode/linkage')
        else:
            _need(key[2] == 'final' and key[3] in (*MODES, 'O2-lto', 'Os-lto')
                  and key[4] in ('direct', 'archive'), 'final representation/mode/linkage')
        index[key] = row
    _need(type(backlog) is list and len(backlog) == BACKLOG_COUNT, 'all 26 backlog records')
    _json(backlog)
    ids = []
    for row in backlog:
        _need(type(row) is dict and _text(row.get('id'))
              and row.get('status') in ('Pending', 'ReferenceOnly'), 'backlog identity/status')
        ids.append(row['id'])
    _need(len(set(ids)) == BACKLOG_COUNT, 'duplicate backlog identity')
    _need(sum(row['status'] == 'Pending' for row in backlog) == 23, '23 pending and three reference-only records')
    return cells, index, obligations


def _contract_keys(contracts, index):
    _need(type(contracts) is list, 'literal selected contract list')
    selected = {}
    for contract in contracts:
        _need(type(contract) is dict, 'profile contract dictionary')
        _json(contract)
        profile, mode = contract.get('Profile'), contract.get('Mode')
        _need(type(profile) is str and type(mode) is str and mode in MODES, 'closed profile/mode')
        matches = [row for row in _SELECTORS if row[0] == profile]
        _need(len(matches) == 1, 'unknown ordinary profile')
        _, cohort, group = matches[0]
        expected = dict(Profile=profile, Mode=mode, Route=profile + '/' + mode + '/direct',
            Cohort=cohort, SourceGroup=group, ArtifactRole='runtime', Representation='final',
            Linkage='direct', LTO=False, SourceInventorySha256=SOURCE_INVENTORY_SHA256,
            CommonRequirements=list(COMMON), RuntimeRequirements=list(RUNTIME), MetadataOnly=True,
            RequiredCellSatisfied=False, RequiredCellsSatisfied=0, FullABIProof=False,
            FullSemanticABIProof=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False)
        _need(all(k in contract and _same(contract[k], v) for k, v in expected.items()), 'canonical contract credit projection')
        key = _key(contract)
        _need(key not in selected, 'duplicate selected contract')
        _need(key in index and index[key]['SourceGroup'] == group, 'selected key/source group absent or different')
        artifact = contract.get('CohortArtifact')
        _need(type(artifact) is dict and artifact.get('role') == 'runtime'
              and artifact.get('source_group_id') == group and artifact.get('abi_contract') == 'forward8',
              'runtime artifact source group/ABI')
        selected[key] = contract
    return selected


def coverage(required, backlog, contracts, verified_keys):
    """Return (full coverage, missing work); inputs and prior outputs are untouched.

    verified_keys must be a list of unique literal (cohort, role, representation,
    mode, linkage) tuples, each present in contracts and the admitted plan. An
    empty list is the failure/revocation path, regardless of any receipt labels.
    Authentication of the entire plan, contracts and completed proof obligations
    is the enclosing composer's duty; this function does not execute those proofs.
    """
    cells, index, obligations = _plan(required, backlog)
    selected = _contract_keys(contracts, index)
    _need(type(verified_keys) is list, 'literal verified-key list')
    verified = set()
    for key in verified_keys:
        _need(type(key) is tuple and len(key) == 5 and all(_text(value) for value in key), 'literal canonical five-tuple')
        _need(key not in verified, 'duplicate verified key')
        _need(key in selected, 'unknown or unselected verified key')
        verified.add(key)
    rows, missing = [], []
    for cell in cells:
        key = _key(cell)
        passed = key in verified
        remaining = [] if passed else list(obligations[cell['ArtifactRole']])
        item = deepcopy(cell)
        item.update(Status='BOUNDED_STATIC_CELL_VERIFIED' if passed else 'PENDING',
                    RequiredCellSatisfied=passed, MissingWholeCellRequirements=remaining)
        rows.append(item)
        if not passed:
            missing.append(dict(Key=list(key), MissingWholeCellRequirements=list(remaining)))
    count = len(verified)
    shared = dict(RequiredCellCount=REQUIRED_CELL_COUNT, RequiredCellsSatisfied=count,
                  GlobalFreezeQualified=False, FullABIProof=False, FullSemanticABIProof=False,
                  CpuExecution=False, BoardExecution=False, HostedCIQualified=False)
    return (dict(deepcopy(shared), Cells=rows, PlannedProofRequirements=deepcopy(obligations)),
            dict(deepcopy(shared), Cells=missing, Backlog=deepcopy(backlog)))
