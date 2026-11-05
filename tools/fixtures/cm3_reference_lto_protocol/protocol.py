"""Reference CM3 LTO canonical composition over preserved named-symbol roots.

No filesystem, helper loading, token projection, native substitute or execution.
"""
import copy
import hashlib
import json

ROOTS = ('prvPortStartFirstTask', 'vPortSVCHandler', 'xPortPendSVHandler')


class Rejected(RuntimeError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected('REJECT:CM3-REFERENCE-LTO-PROTOCOL:' + message)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def integers(row, keys):
    return type(row) is dict and all(type(row.get(key)) is int for key in keys)


class ReferenceProtocolView:
    def __init__(self, decoded_machine, transport_image):
        need(type(decoded_machine.data) is bytes and decoded_machine.data == transport_image.machine.data,
             'canonical decoder must consume exact preserved machine bytes')
        self.decoded, self.transport = decoded_machine, transport_image
        self.machine_sha = sha(decoded_machine.data)
        self.evidence = {}

    def function(self, name, *, literal_islands=False):
        need(name in ROOTS and literal_islands is True, 'three exact complete reference roots required')
        record = self.transport.function(name)
        need(record['Name'] == name and record['GeneratedMachineBoundRootPreservation'] is True
             and record['CanonicalProtocolValidated'] is False, 'unchanged complete transport record required')
        definitions = [row for row in self.decoded.symbols if row['name'] == name and row['section'] != 0]
        need(len(definitions) == 1, 'unique decoded root definition')
        symbol = definitions[0]
        expected_info = 0x02 if name == ROOTS[0] else 0x12
        need(integers(symbol, ('section', 'info', 'size', 'value'))
             and integers(record, ('Size', 'InstructionCount')) and symbol['section'] > 0
             and symbol['info'] == expected_info and symbol['size'] == record['Size'] and symbol['value'] & 1,
             'exact local/global decoded reference function metadata required')
        origin = record['RootOrigin']
        need(integers(origin, ('InputSectionIndex', 'SymbolOffset', 'Size'))
             and origin['GeneratedMachineOriginBound'] is True and origin['Name'] == name
             and origin['ProviderSha256'] == self.machine_sha and origin['InputSectionIndex'] == symbol['section']
             and origin['SymbolOffset'] == symbol['value'] & ~1 and origin['Size'] == symbol['size'],
             'decoded root differs from independently preserved machine origin')
        body = self.decoded.read(symbol['section'], symbol['value'] & ~1, symbol['size'])
        need(type(body) is bytes and len(body) == symbol['size'] and sha(body) == record['MachineBodySha256'],
             'exact complete machine root bytes required')
        tokens = self.decoded.function(name, literal_islands=True)
        need(type(tokens) is list and tokens and all(type(row) is tuple and len(row) == 2
             and all(type(item) is str for item in row) for row in tokens), 'complete raw canonical tokens required')
        token_hash = sha(json.dumps(tokens, separators=(',', ':'), ensure_ascii=True).encode('ascii'))
        self.evidence[name] = dict(Name=name, MachineBodySha256=record['MachineBodySha256'],
            FinalBodySha256=record['BodySha256'], MachineProviderSha256=self.machine_sha,
            RawCanonicalTokens=copy.deepcopy(tokens), RawTokenSha256=token_hash, ProjectionEvidence=[],
            HashDomains=dict(MachineRoot='SHA256-UNAPPLIED-MACHINE-FUNCTION-BYTES',
                            FinalRoot='SHA256-APPLIED-FINAL-FUNCTION-BYTES', Canonical='SHA256-JSON-TOKENS'),
            TransportRecord=copy.deepcopy(record))
        return tokens


def check_reference(decoded_machine, transport_image, checker):
    need(tuple(checker._REFERENCE) == ROOTS, 'exact frozen three-reference-root checker required')
    view = ReferenceProtocolView(decoded_machine, transport_image)
    matched = [checker._match(view, 'Reference', name, checker._REFERENCE[name]) for name in ROOTS]
    need(len(matched) == 3 and all(type(row['TailNops']) is int and row['TailNops'] == 0 for row in matched),
         'O2-lto requires zero post-island tail NOPs on every reference root')
    return dict(Status='REFERENCE-CANONICAL-PASS-NOT-PAIRED-QUALIFIED',
        Scope='REFERENCE_CM3_O2_LTO_THREE_CANONICAL_PROTOCOLS_ONLY', CanonicalProtocolValidated=True,
        ClosedBodies=3, MatchEvidence=matched, Roots=[view.evidence[name] for name in ROOTS],
        OriginalTransportRecordsUnmodified=True, SemanticProjections=0, SourceToMachineSemanticProof=False,
        FinalReferenceParity=False, FullABIProof=False, PolicyEquivalence=False, CompleteObjectProof=False,
        CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False, RequiredCellsSatisfied=0)
