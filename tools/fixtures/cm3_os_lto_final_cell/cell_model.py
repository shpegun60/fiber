"""Fixed CM3/Os-LTO metadata and accounting, not admission or proof execution.

The caller authenticates the exact complete E9 plan bytes and the supplied
coverage helper. The helper validates plan shape, not inventory authority.
Only the caller's final, revocable verified-key metadata grants accounting
credit after detailed proof obligations, actual closing and sealing pass.
This module performs no I/O, helper loading, inspection or process execution.
"""
from copy import deepcopy


ROUTE = 'CM3/Os-lto/direct'
COHORT = 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default'
COHORT_SHA256 = 'C7C37950A2C7391B8E9C719A828CE9A288A5634FBEB6C3934A41F5AF6177C700'
SOURCE_INVENTORY_SHA256 = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
KEY_FIELDS = ('Cohort', 'ArtifactRole', 'Representation', 'Mode', 'Linkage')
KEY = (COHORT, 'runtime', 'final', 'Os-lto', 'direct')
COMMON = ('cpu-neutral-engine', 'reverse-v1-ownership', 'source-provider-identity')
RUNTIME = ('forward-eight', 'reverse-v1', 'current-slot-isolation', 'strong-handlers',
           'exact-profile-context-cohort', 'generated-assembly-reference-parity',
           'final-elf-vectors', 'negative-link-controls')
REQUIRED_CELL_COUNT = 2774


class Rejected(ValueError):
    pass


def need(condition, detail):
    if not condition:
        raise Rejected('cm3-os-lto-cell-model: ' + detail)


def contract():
    """Return fresh JSON metadata; no input or proof execution is authenticated."""
    return dict(SchemaVersion=1, Route=ROUTE, Profile='CM3', Mode='Os-lto',
        Cohort=COHORT, CohortSha256=COHORT_SHA256, SourceGroup='CM3',
        ArtifactRole='runtime', Representation='final', Linkage='direct', LTO=True,
        SourceInventorySha256=SOURCE_INVENTORY_SHA256,
        CommonRequirements=list(COMMON), RuntimeRequirements=list(RUNTIME),
        MetadataOnly=True, ProofExecutor=False, InputAuthenticationProof=False, Qualification=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0, FullABIProof=False,
        FullSemanticABIProof=False, SourceIRProof=False, PolicyEquivalence=False,
        InstructionEquivalence=False, CpuExecution=False, BoardExecution=False,
        HostedCIQualified=False, GlobalFreezeQualified=False)


def coverage(required, backlog, verified_keys, *, coverage_module):
    """Return fresh full coverage/missing work without altering inputs or helpers.

    [] revokes all credit; [KEY] accounts for the sole caller-verified Os cell.
    Neither list authenticates inputs or executes proof obligations. The caller
    authenticates the entire E9 plan; _plan checks its 2774-row/26-backlog shape
    and obligations, not canonical inventory identity. Other well-formed rows
    are retained, not reconstructed or selected through an O2/ordinary verdict.
    """
    planner = getattr(coverage_module, '_plan', None)
    need(callable(planner), 'coverage helper must provide callable _plan')
    try:
        cells, index, obligations = planner(required, backlog)
    except ValueError as error:
        raise Rejected('cm3-os-lto-cell-model: invalid complete plan shape: ' + str(error)) from error
    need(KEY in index, 'selected Os-LTO key absent from required plan')
    selected = index[KEY]
    need(type(selected.get('SourceGroup')) is str and selected['SourceGroup'] == 'CM3'
         and type(selected.get('CohortSha256')) is str and selected['CohortSha256'] == COHORT_SHA256,
         'selected CM3 source group and exact cohort fingerprint')
    need(type(verified_keys) is list and len(verified_keys) <= 1, 'only [] or [exact KEY tuple]')
    if verified_keys:
        key = verified_keys[0]
        need(type(key) is tuple and len(key) == 5 and all(type(item) is str for item in key)
             and key == KEY, 'only the fixed literal Os-LTO key can receive credit')
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
        MetadataOnly=True, ProofExecutor=False, InputAuthenticationProof=False, Qualification=False,
        GlobalFreezeQualified=False,
        FullABIProof=False, FullSemanticABIProof=False, CpuExecution=False,
        BoardExecution=False, HostedCIQualified=False)
    return (dict(deepcopy(shared), Cells=rows, PlannedProofRequirements=deepcopy(obligations)),
            dict(deepcopy(shared), Cells=missing, Backlog=deepcopy(backlog)))
