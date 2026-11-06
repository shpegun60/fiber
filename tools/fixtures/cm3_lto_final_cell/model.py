"""Fixed CM3/O2-LTO metadata and accounting, not admission or proof execution.

The caller authenticates the catalog, complete E9 plan and passed coverage
module. Only a final, revocable verified-key list grants accounting credit.
This module performs no file access, helper loading or process execution.
"""
from copy import deepcopy


ROUTE = 'CM3/O2-lto/direct'
COHORT = 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default'
COHORT_SHA256 = 'C7C37950A2C7391B8E9C719A828CE9A288A5634FBEB6C3934A41F5AF6177C700'
SOURCE_INVENTORY_SHA256 = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
KEY_FIELDS = ('Cohort', 'ArtifactRole', 'Representation', 'Mode', 'Linkage')
KEY = (COHORT, 'runtime', 'final', 'O2-lto', 'direct')
ROLES = ('Inventory', 'Native', 'Reference', 'Join', 'Bindings', 'ABIControls',
         'Isolation', 'CommonAttributes', 'PortPolicy')
COMMON = ('cpu-neutral-engine', 'reverse-v1-ownership', 'source-provider-identity')
RUNTIME = ('forward-eight', 'reverse-v1', 'current-slot-isolation', 'strong-handlers',
           'exact-profile-context-cohort', 'generated-assembly-reference-parity',
           'final-elf-vectors', 'negative-link-controls')
REQUIRED_CELL_COUNT = 2774


class Rejected(ValueError):
    pass


def need(condition, detail):
    if not condition:
        raise Rejected('cm3-lto-cell-model: ' + detail)


def _text(value):
    return (type(value) is str and bool(value) and value.strip() == value
            and all(ord(char) >= 32 and ord(char) != 127 for char in value))


def _hash(value):
    return type(value) is str and len(value) == 64 and all(char in '0123456789ABCDEF' for char in value)


def contract():
    """Return fresh JSON metadata; no receipt, path or execution is admitted."""
    return dict(SchemaVersion=1, Route=ROUTE, Profile='CM3', Mode='O2-lto',
        Cohort=COHORT, CohortSha256=COHORT_SHA256, SourceGroup='CM3',
        ArtifactRole='runtime', Representation='final', Linkage='direct', LTO=True,
        SourceInventorySha256=SOURCE_INVENTORY_SHA256,
        CommonRequirements=list(COMMON), RuntimeRequirements=list(RUNTIME),
        MetadataOnly=True, ProofExecutor=False, InputAuthenticationProof=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0, FullABIProof=False,
        FullSemanticABIProof=False, SourceIRProof=False, PolicyEquivalence=False,
        InstructionEquivalence=False, CpuExecution=False, BoardExecution=False,
        HostedCIQualified=False, GlobalFreezeQualified=False)


def validate_catalog(value):
    """Validate closed textual descriptors, not canonical/physical path identity."""
    need(type(value) is dict and set(value) == {'SchemaVersion', 'Route', 'Bundles'},
         'exact catalog fields')
    need(type(value['SchemaVersion']) is int and value['SchemaVersion'] == 1,
         'literal schema version one')
    need(type(value['Route']) is str and value['Route'] == ROUTE, 'fixed explicit route')
    bundles = value['Bundles']
    need(type(bundles) is dict and set(bundles) == set(ROLES), 'exact nine bundle roles')
    for role in ROLES:
        row = bundles[role]
        need(type(row) is dict and set(row) == {'Build', 'ReceiptSha256', 'ArtifactsSha256'},
             'exact descriptor fields: ' + role)
        need(_text(row['Build']), 'literal control-free Build text: ' + role)
        need(_hash(row['ReceiptSha256']) and _hash(row['ArtifactsSha256']),
             'uppercase SHA256 descriptor digests: ' + role)
    return deepcopy(value)


def coverage(required, backlog, verified_keys, *, coverage_module):
    """Return full coverage/missing rows without changing inputs or helper globals.

    [] revokes all credit; [KEY] accounts for the sole caller-verified cell.
    Passing KEY does not execute or authenticate any prerequisite. The frozen
    ordinary helper validates the complete plan, not its ordinary-only selector.
    """
    try:
        cells, index, obligations = coverage_module._plan(required, backlog)
    except ValueError as error:
        raise Rejected('cm3-lto-cell-model: invalid complete required plan: ' + str(error)) from error
    need(KEY in index, 'selected LTO key absent from required plan')
    selected = index[KEY]
    need(type(selected.get('SourceGroup')) is str and selected['SourceGroup'] == 'CM3'
         and type(selected.get('CohortSha256')) is str and selected['CohortSha256'] == COHORT_SHA256,
         'selected CM3 source group and exact cohort fingerprint')
    need(type(verified_keys) is list and len(verified_keys) <= 1, 'only [] or [exact KEY tuple]')
    if verified_keys:
        key = verified_keys[0]
        need(type(key) is tuple and len(key) == 5 and all(type(item) is str for item in key)
             and key == KEY, 'only the fixed literal LTO key can receive credit')
    rows, missing = [], []
    for cell in cells:
        key = tuple(cell[field] for field in KEY_FIELDS)
        passed = bool(verified_keys) and key == KEY
        remaining = [] if passed else list(obligations[cell['ArtifactRole']])
        row = deepcopy(cell)
        row.update(Status='BOUNDED_STATIC_CELL_VERIFIED' if passed else 'PENDING',
                   RequiredCellSatisfied=passed, MissingWholeCellRequirements=remaining)
        rows.append(row)
        if not passed:
            missing.append(dict(Key=list(key), MissingWholeCellRequirements=list(remaining)))
    shared = dict(RequiredCellCount=REQUIRED_CELL_COUNT, RequiredCellsSatisfied=len(verified_keys),
        MetadataOnly=True, ProofExecutor=False, GlobalFreezeQualified=False,
        FullABIProof=False, FullSemanticABIProof=False, CpuExecution=False,
        BoardExecution=False, HostedCIQualified=False)
    return (dict(deepcopy(shared), Cells=rows, PlannedProofRequirements=deepcopy(obligations)),
            dict(deepcopy(shared), Cells=missing, Backlog=deepcopy(backlog)))
