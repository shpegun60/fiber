"""Compose Os-owned machine predicates inside the caller's immutable reader.

The caller authenticates the sealed 134-command batch and all helpers, supplies
read_role(component, role) -> (Path, bytes), and owns worker/flag provenance,
physical closure and output sealing. No compiler or complete cell verdict here.
"""

import hashlib
from pathlib import Path


COMMON = ('positive', 'mutant-engine', 'mutant-state', 'mutant-panic',
          'stress-protected', 'stress-unprotected')
MUTATIONS = (None, 'ctxrt_v1_current', 'fiber_internal_runtime_load_current_context',
             'fiber_panic', None, 'ctxrt_attribute_stress')
PORT = ('selected', 'stress-supported', 'stress-raw')


class Rejected(ValueError):
    pass


def need(condition, detail):
    if not condition:
        raise Rejected('REJECT:CM3-OS-LTO-MACHINE-REPLAY:' + detail)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def inspect(batch, core, helpers, read_role):
    """Return component evidence, retaining unresolved attribution as pending."""
    need(type(batch) is dict and batch.get('Status') == 'BUILT-PENDING-READER'
         and batch.get('Profile') == 'CM3' and batch.get('Mode') == 'Os-lto'
         and batch.get('Linkage') == 'direct' and batch.get('LTO') is True,
         'caller-bound current Os build')
    need(type(helpers) is dict and set(helpers) == {'effects', 'census', 'attributes', 'policy'}
         and callable(read_role), 'explicit pure helpers and immutable role reader')
    pending = batch.get('PendingFinalReader')
    need(type(pending) is dict and pending.get('Status') == 'PENDING'
         and pending.get('OneImmutableReaderScopeRequired') is True
         and type(pending.get('Inputs')) is list, 'explicit final-reader input catalog')
    catalog = {}
    for row in pending['Inputs']:
        need(type(row) is dict and set(row) == {'Component', 'Role', 'Path', 'Sha256'}
             and all(type(row[key]) is str and row[key] for key in row), 'typed reader input binding')
        key = row['Component'], row['Role']
        need(key not in catalog, 'unique reader input role')
        catalog[key] = row
    consumed = {}

    def read(component, role):
        key = component, role
        need(key in catalog, 'required machine role/' + component + '/' + role)
        path, raw = read_role(component, role)
        need(isinstance(path, Path) and path.is_absolute() and type(raw) is bytes,
             'immutable path/raw role pair')
        claimed = catalog[key]
        need(str(path) == claimed['Path'] and sha(raw) == claimed['Sha256'], 'bound role bytes/' + role)
        consumed[key] = dict(claimed)
        return path, raw

    def image(component, role, final=False):
        path, raw = read(component, role)
        value = core._ELF(path, 'ET_EXEC' if final else 'ET_REL')
        need(value.data == raw and value.final is final, 'parser consumes exact bound role bytes/' + role)
        return value

    effects, census, attrs, policy = (helpers[name] for name in ('effects', 'census', 'attributes', 'policy'))
    common_record = batch.get('CommonAttributesDeferredReader')
    need(type(common_record) is dict and type(common_record.get('Lowerings')) is list
         and len(common_record['Lowerings']) == 6, 'six common lowerings')
    common, unresolved = [], []
    for index, row in enumerate(common_record['Lowerings']):
        group, mutation, stress = COMMON[index], MUTATIONS[index], index >= 4
        need(type(row) is dict and row.get('Group') == group and row.get('Mutation') == mutation
             and row.get('Stress') is stress, 'exact ordered common selectors/' + group)
        pair = []
        for role in ('Object', 'Machine'):
            value = image('CommonAttributes', group + '/' + role)
            proof = effects.inspect_lowered(value, core, attrs, mutation=mutation, stress=stress)
            effects.require_result(proof, mutation=mutation, stress=stress)
            rejected = False
            if mutation is not None:
                try:
                    effects.inspect_lowered(value, core, attrs, stress=stress)
                except effects.Rejected:
                    rejected = True
                need(rejected, 'unchanged clean predicate rejects actual common control/' + group + '/' + role)
            need(type(proof.get('UnresolvedAttribution')) is list, 'explicit common attribution disposition')
            if proof['UnresolvedAttribution']:
                unresolved.append(dict(Group=group, Role=role, Evidence=proof['UnresolvedAttribution']))
            pair.append(dict(Role=role, Proof=proof, OriginalProtectedPredicateRejected=rejected))
        need(pair[0]['Proof']['Status'] == pair[1]['Proof']['Status']
             and pair[0]['Proof']['Undefined'] == pair[1]['Proof']['Undefined'],
             'aggregate/worker common disposition/' + group)
        common.append(dict(Group=group, Machines=pair))

    port_rows = batch.get('PortPolicyLowerings')
    need(type(port_rows) is list and len(port_rows) == 3
         and [row.get('Group') for row in port_rows if type(row) is dict] == list(PORT),
         'three ordered port lowerings')
    surface = batch.get('PortPolicyIRDefinitionSurface')
    need(type(surface) is dict and surface.get('IRDefinitionsValidated') is True, 'mandatory selected IR surface')
    port = []
    for group in PORT:
        for role, dis_role in (('Aggregate', 'AggregateDisassembly'), ('Machine', 'MachineDisassembly')):
            value = image('PortPolicy', group + '/' + role)
            _, disassembly = read('PortPolicy', group + '/' + dis_role)
            if group == 'selected':
                proof = census.inspect_lowered(value, core, disassembly, surface, policy)
            else:
                proof = census.inspect_stress(value, core, disassembly, policy, effects, attrs,
                                               supported=group == 'stress-supported')
            port.append(dict(Group=group, Role=role, Proof=proof))
    for role, dis_role, final in (('ELF', 'Disassembly', True), ('Machine', 'MachineDisassembly', False)):
        value = image('PortPolicy', 'Final/' + role, final=final)
        _, disassembly = read('PortPolicy', 'Final/' + dis_role)
        proof = (census.inspect_final(value, core, disassembly, surface, policy) if final else
                 census.inspect_lowered(value, core, disassembly, surface, policy, whole_image=True))
        port.append(dict(Group='Final', Role=role, Proof=proof))
    need(len(common) == 6 and sum(len(row['Machines']) for row in common) == 12 and len(port) == 8,
         'exact twenty machine roles')
    return dict(Status='MACHINE-REPLAY-PENDING-ATTRIBUTION' if unresolved else 'MACHINE-COMPONENTS-REPLAYED',
        Scope='CM3_OS_LTO_COMMON_AND_PORT_MACHINE_COMPONENTS_ONLY', Profile='CM3', Mode='Os-lto',
        CommonMachines=common, PortMachines=port, UnresolvedAttribution=unresolved,
        MachineRoles=20, CommonMachineRoles=12, PortMachineRoles=8,
        ReadRoles=[consumed[key] for key in sorted(consumed)],
        CommonAttributionClosed=not unresolved, CallerOwnsAdmissionAndImmutableScope=True,
        WorkerOptionsValidated=False, WorkerExecutionProvenanceValidated=False,
        IRDefinitionProvenanceValidated=False, FinalRootTransferProtocolsValidated=False,
        ABIControlsReplayed=False, IsolationReplayed=False, FinalReferenceParity=False,
        CompleteCellProof=False, RequiredCellsSatisfied=0, Qualification=False,
        GlobalFreezeQualified=False, HostedCIQualified=False, CPUExecution=False, BoardExecution=False)
