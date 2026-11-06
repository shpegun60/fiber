"""Ordinary direct-cell thin ELF bindings, with explicit profile authority.

The caller authenticates source/profile contracts, files, reader and closing
identities. Offsets are measured, not learned expected answers: the independent
contract fixes every tracked owner/section/type/target and its multiplicity.
Applied references are checked in both twins using the qualified ELF reader.
No tools, dynamic imports or target instructions execute here.
"""
from collections import Counter
import hashlib
from pathlib import Path
import struct


SELECT = 'fiber_internal_runtime_select_scheduler_candidate'
PUBLISH = 'fiber_internal_runtime_publish_current_context'
CURRENT = 'fiber_internal_runtime_require_current_context'
RETURN = 'fiber_internal_task_return'
ANCHOR = 'fiber_internal_runtime_port_abi_v1_anchor'
SLOT = 'fiber_internal_runtime_current_context_slot'
EXPECTATION = '.fiber_port_context_cohort_expectation'
FORWARD = {'fiber_port_context_init': 4, 'fiber_port_runtime_memory_barrier': 3,
           'fiber_port_panic_wait': 3, 'fiber_port_require_scheduler_configuration_environment': 3,
           'fiber_port_runtime_prepare_start': 3, 'fiber_port_runtime_select_first': 3,
           'fiber_port_runtime_start_first': 3, 'fiber_port_runtime_schedule': 3}
REVERSE = ((3, '.text.fiber_port_runtime_schedule', 10, CURRENT),
           (3, '.text.fiber_port_scheduler_pick_first_from_start', 10, SELECT),
           (3, '.text.fiber_port_scheduler_pick_next_from_pendsv', 10, SELECT),
           (3, '.text.fiber_port_scheduler_pick_next_from_pendsv', 10, PUBLISH),
           (3, '.text.fiber_port_init_context_frame', 2, RETURN))
COLD = ((3, 'fiber_port_runtime_prepare_start'), (4, 'fiber_port_context_init'))
SLOTS = ((3, '.text.SVC_Handler', 2, SLOT), (3, '.text.PendSV_Handler', 2, SLOT))
VECTORS = ((8, '.isr_vector', 4, 2, 'Reset_Handler'),
           (8, '.isr_vector', 44, 2, 'SVC_Handler'),
           (8, '.isr_vector', 56, 2, 'PendSV_Handler'))


class Rejected(ValueError):
    pass


def need(value, message):
    if not value:
        raise Rejected('ordinary-cell-bindings: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def section(elf, name):
    need(elf.names.count(name) == 1, 'unique section: ' + name)
    return elf.names.index(name)


def mapped(elf, index, address, size, kind):
    actual, boundary = elf.mapping(index, address)
    need(actual == kind and address + size <= boundary, 'complete ' + kind + ' mapping')


def reference_membership(objects, private, storage):
    """Select exact independent reference classes, retaining measured offsets."""
    cohorts = ((4, '.text.fiber_port_context_init', 2, private),
               (5, '.text.fiber_exception_runtime_check', 2, private),
               (6, EXPECTATION, 2, private), (7, EXPECTATION, 2, storage))
    cold = tuple((i, '.text.' + function, 2, ANCHOR) for i, function in COLD)
    expected = Counter((*REVERSE, *cold, *cohorts, *SLOTS))
    tracked = {SELECT, PUBLISH, CURRENT, RETURN, ANCHOR, SLOT, private, storage}
    found = []
    for owner, obj in enumerate(objects):
        if owner < 3:
            continue
        for (index, offset), (kind, symbol) in obj.relocations.items():
            if symbol['name'] in tracked:
                found.append((owner, obj.sections[index].name, offset, kind, symbol['name']))
    need(Counter((i, name, kind, target) for i, name, _, kind, target in found) == expected,
         'complete consumer owner/section/type/target/multiplicity membership')
    return dict(Reverse=[row for spec in REVERSE for row in found if (row[0], row[1], row[3], row[4]) == spec],
                Cold=[row for spec in cold for row in found if (row[0], row[1], row[3], row[4]) == spec],
                Cohort=[row for spec in cohorts for row in found if (row[0], row[1], row[3], row[4]) == spec],
                Slot=[row for spec in SLOTS for row in found if (row[0], row[1], row[3], row[4]) == spec])


class Bindings:
    def __init__(self, contract, result, root, core):
        need(type(contract) is dict and type(result) is dict, 'explicit contract and receipt')
        need(all(result.get(name) == contract[name] for name in ('Profile', 'Mode', 'Cohort'))
             and result.get('SourceInventorySha256') == contract['SourceInventorySha256']
             and result.get('Linkage') == 'direct' and result.get('LTO') is False,
             'exact ordinary profile/mode/positive recipe')
        self.contract, self.root, self.core = contract, Path(root).resolve(strict=True), core
        self.private, self.storage = contract['PrivateSymbol'], contract['StorageSymbol']
        self.owners = {SELECT: 1, PUBLISH: 1, CURRENT: 1, RETURN: 0, ANCHOR: 1,
            SLOT: 1, self.private: 3, self.storage: 3, 'Reset_Handler': 8,
            'SVC_Handler': 3, 'PendSV_Handler': 3, **FORWARD}
        self.functions = {SELECT, PUBLISH, CURRENT, RETURN, 'Reset_Handler',
                          'SVC_Handler', 'PendSV_Handler', *FORWARD}
        rows, names = result.get('Sources'), contract['SourceOrder']
        need(type(rows) is list and len(rows) == len(names) == 9, 'nine ordered sources')
        self.paths, self.objects, self.sources = [], [], []
        for index, (name, row) in enumerate(zip(names, rows)):
            source = self.root / 'source' / name
            obj = self.root / 'objects' / ('%02d-%s.o' % (index, Path(name).stem))
            need(Path(row['Source']).resolve(strict=True) == source.resolve(strict=True)
                 and Path(row['Object']).resolve(strict=True) == obj.resolve(strict=True),
                 'source/object order: ' + name)
            parsed, source_hash = core._ELF(obj, 'ET_REL'), sha(source.read_bytes())
            need(source_hash == row['SourceSha256'] and sha(parsed.data) == row['ObjectSha256'],
                 'source/object receipt bytes: ' + name)
            self.paths.append(obj)
            self.objects.append(parsed)
            self.sources.append(dict(Source=name, SourceSha256=source_hash,
                                     Object=str(obj), ObjectSha256=sha(parsed.data)))
        self.definitions = {}
        for name, owner in self.owners.items():
            found = [(i, s) for i, obj in enumerate(self.objects) for s in obj.symbols
                     if s['name'] == name and s['section'] != 'SHN_UNDEF']
            need(len(found) == 1 and found[0][0] == owner, 'unique original provider: ' + name)
            self.definitions[name] = found[0][1]
        self.identities(self.objects)
        self.references = reference_membership(self.objects, self.private, self.storage)

    def identities(self, objects):
        prefixes = ('fiber_port_context_cohort_arm', 'fiber_port_storage_cohort_')
        names = {s['name'] for obj in objects for s in obj.symbols
                 if s['name'].startswith(prefixes)
                 and s['name'] != 'fiber_port_storage_cohort_consumer_expectation'}
        need(names == {self.private, self.storage}, 'foreign private/storage identity')

    def placement(self, image, owner, index):
        obj = self.objects[owner]
        sec = obj.sections[index]
        need(obj.names.count(sec.name) == 1, 'unique original section name')
        identity = self.core._object_identity(self.paths[owner])
        need(identity in image.providers and image.providers[identity].data == obj.data, 'map provider bytes')
        placed = image.placements.get((identity, sec.name))
        need(placed is not None, 'kept map placement: ' + sec.name)
        address, size = placed
        h = sec.header
        matches = [(i, s) for i, s in enumerate(image.final.sections)
                   if s.header.sh_flags & 2 and s.header.sh_addr <= address
                   and address + size <= s.header.sh_addr + s.header.sh_size]
        need(size == h.sh_size and size > 0 and len(matches) == 1
             and address % max(1, h.sh_addralign) == 0, 'complete input-section placement')
        final_index, final_sec = matches[0]
        need(final_sec.header.sh_type == h.sh_type and final_sec.header.sh_flags & 7 == h.sh_flags & 7,
             'input/final storage: ' + sec.name)
        return dict(Provider=str(self.paths[owner]), ProviderSha256=sha(obj.data), InputSection=sec.name,
                    InputSectionIndex=index, SectionAddress=address, SectionSize=size,
                    FinalSectionIndex=final_index, LinkMapSha256=image.link_map_hash)

    def definition(self, image, name):
        owner, original = self.owners[name], self.definitions[name]
        kind = 'STT_FUNC' if name in self.functions else 'STT_OBJECT'
        need(original['kind'] == kind and original['binding'] == 'STB_GLOBAL'
             and type(original['section']) is int and original['size'] > 0, 'original definition: ' + name)
        final = [s for s in image.final.symbols if s['name'] == name and s['section'] != 'SHN_UNDEF']
        need(len(final) == 1, 'unique final definition: ' + name)
        final = final[0]
        need(final['kind'] == kind and final['binding'] == 'STB_GLOBAL'
             and type(final['section']) is int and original['size'] == final['size'], 'final definition: ' + name)
        origin = self.placement(image, owner, original['section'])
        offset = original['value'] & ~1 if kind == 'STT_FUNC' else original['value']
        value = final['value'] & ~1 if kind == 'STT_FUNC' else final['value']
        need(0 <= offset and offset + original['size'] <= origin['SectionSize']
             and origin['SectionAddress'] + offset == value
             and origin['FinalSectionIndex'] == final['section'], 'definition placement: ' + name)
        if kind == 'STT_FUNC' or name == SLOT:
            self.objects[owner].symbol(name, kind, root=True)
            image.final.symbol(name, kind, root=True)
            image._origin(name, final)
        else:
            original_section = self.objects[owner].sections[original['section']]
            h = original_section.header
            need(original_section.name == '.rodata.' + name and original['size'] == 1
                 and h.sh_type == 'SHT_PROGBITS' and h.sh_flags & 7 == 2
                 and self.objects[owner].section_read(original['section'], offset, 1) == b'\x01'
                 and image.read(value, 1) == b'\x01', 'read-only byte definition: ' + name)
        if name == SLOT:
            h = self.objects[owner].sections[original['section']].header
            need(self.objects[owner].names[original['section']] == '.bss.fiber_runtime_current_context_slot'
                 and h.sh_type == 'SHT_NOBITS' and h.sh_size == 4 and h.sh_addralign >= 4
                 and h.sh_flags & 7 == 3 and offset == 0 and final['size'] == 4 and value % 4 == 0,
                 'four-byte aligned zero-fill slot')
            need(any(load['Flags'] & 3 == 2 and load['Vaddr'] <= value
                     and value + 4 <= load['Vaddr'] + load['MemorySize'] for load in image.final.loads),
                 'slot writable/non-executable load')
        if kind == 'STT_OBJECT':
            for elf, symbol in ((self.objects[owner], original), (image.final, final)):
                need(not any(s is not symbol and s['kind'] == 'STT_OBJECT'
                             and s['section'] == symbol['section'] and s['size'] > 0
                             and s['value'] < symbol['value'] + symbol['size']
                             and symbol['value'] < s['value'] + s['size'] for s in elf.symbols),
                     'overlapping object definition: ' + name)
        return final, dict(origin, Name=name, ObjectIndex=owner, SymbolOffset=offset,
                           Size=original['size'], Value=final['value'], Binding=final['binding'])

    def reference(self, image, spec, emitted):
        owner, name, offset, kind, target = spec
        obj = self.objects[owner]
        index = section(obj, name)
        need(obj.relocations.get((index, offset), (None, {}))[0] == kind
             and obj.relocations[(index, offset)][1]['name'] == target, 'original relocation')
        before_target = obj.relocations[(index, offset)][1]
        if target == 'Reset_Handler':
            need(before_target == self.definitions[target], 'original startup target')
        else:
            need(before_target['section'] == 'SHN_UNDEF' and before_target['binding'] == 'STB_GLOBAL'
                 and before_target['kind'] == 'STT_NOTYPE' and before_target['value'] == before_target['size'] == 0,
                 'original external target: ' + target)
        origin = self.placement(image, owner, index)
        address = origin['SectionAddress'] + offset
        need(0 <= offset and offset + 4 <= origin['SectionSize'], 'reference extent')
        before, after = obj.section_read(index, offset, 4), image.read(address, 4)
        definition, target_origin = self.definition(image, target)
        if kind == 10:
            old = self.core._address_form(before, offset)
            new = self.core._address_form(after, address)
            need(old is not None and old[0] == 'bl' and old[3] == -4
                 and new is not None and new[0] == 'bl' and new[1] == definition['value'] & ~1,
                 'BL original addend/applied destination')
            mapped(obj, index, offset, 4, 't')
            mapped(image.final, origin['FinalSectionIndex'], address, 4, 't')
            addend, resolved = -4, definition['value'] & ~1
        else:
            need(kind == 2 and offset % 4 == 0 and address % 4 == 0
                 and struct.unpack('<I', before)[0] == 0, 'ABS32 original zero addend/alignment')
            mapped(obj, index, offset, 4, 'd')
            mapped(image.final, origin['FinalSectionIndex'], address, 4, 'd')
            addend, resolved = 0, definition['value']
            need(struct.unpack('<I', after)[0] == resolved, 'ABS32 applied destination')
        key = (origin['FinalSectionIndex'], address - image.final.sections[origin['FinalSectionIndex']].header.sh_addr)
        need(image.final.relocations.get(key) == (kind, definition) if emitted else key not in image.final.relocations,
             'exact final relocation metadata disposition')
        return dict(ObjectIndex=owner, Section=name, Offset=offset, Kind=kind, Symbol=target,
                    Addend=addend, Place=address, ResolvedValue=resolved, OriginalBytes=before.hex(),
                    Bytes=after.hex(), InputPlacement=origin, TargetOrigin=target_origin,
                    AppliedRelocationMetadataChecked=emitted)

    def cold_read(self, image, spec, emitted):
        owner, name, pool, _, _ = spec
        function = name.removeprefix('.text.')
        obj, index = self.objects[owner], section(self.objects[owner], name)
        original = obj.symbol(function, 'STT_FUNC', root=True)
        final = image.final.symbol(function, 'STT_FUNC', root=True)
        need(original['value'] & ~1 == 0, 'cold function starts at original section origin')
        ref = self.reference(image, spec, emitted)
        candidates, offset = [], 0
        while offset < original['size']:
            kind, boundary = obj.mapping(index, offset)
            if kind != 't':
                offset = boundary
                continue
            raw = obj.section_read(index, offset, 2)
            half = struct.unpack('<H', raw)[0]
            width = self.core._width(half)
            need(offset + width <= min(boundary, original['size']), 'complete original instruction width')
            if width == 2 and half & 0xf800 == 0x4800:
                form = self.core._address_form(raw, offset)
                if form[:3] == ('ldr', pool, 3):
                    need(offset + 4 <= min(boundary, original['size'])
                         and obj.section_read(index, offset + 2, 2) == bytes.fromhex('1b78'),
                         'immediate retained LDRB r3,[r3]')
                    candidates.append(offset)
            offset += width
        need(len(candidates) == 1, 'exactly one literal/byte-read sequence for cold anchor')
        load = candidates[0]
        base = final['value'] & ~1
        after = image.read(base + load, 4)
        need(after == obj.section_read(index, load, 4)
             and self.core._address_form(after[:2], base + load)[:3] == ('ldr', ref['Place'], 3),
             'preserved cold load/read target')
        mapped(image.final, final['section'], base + load, 4, 't')
        return dict(Function=function, ObjectIndex=owner, LoadOffset=load, ReadOffset=load + 2,
                    Bytes=after.hex(), AnchorReference=ref, RetainedByteRead=True)

    def image(self, emitted):
        stem = 'emit-relocs' if emitted else 'ordinary'
        image = self.core.FinalImage(self.paths[3], self.root / (stem + '.elf'), self.root / (stem + '.dis'),
            provider_objects={str(p): p for p in self.paths}, link_map=self.root / (stem + '.map'),
            float_abi=self.contract['FloatABI'])
        self.identities((image.final,))
        forward = [self.definition(image, name)[1] for name in FORWARD]
        reverse = [self.definition(image, name)[1] for name in (SELECT, PUBLISH, CURRENT, RETURN)]
        refs = {key: [self.reference(image, row, emitted) for row in self.references[key]]
                for key in ('Reverse', 'Cohort', 'Slot')}
        cold = [self.cold_read(image, row, emitted) for row in self.references['Cold']]
        vectors = [self.reference(image, row, emitted) for row in VECTORS]
        vector = image.final.sections[section(image.final, '.isr_vector')]
        need(vector.header.sh_addr == 0 and vector.header.sh_size == 1024
             and vector.header.sh_flags & 7 == 2 and vector.header.sh_type == 'SHT_PROGBITS'
             and struct.unpack('<I', image.read(0, 4))[0] == 0x20010000
             and image.final.elf.header.e_entry == vectors[0]['ResolvedValue'], 'vector geometry/MSP/entry')
        need(self.objects[8].sections[section(self.objects[8], '.isr_vector')].header.sh_size == 1024,
             'original vector extent')
        expectation = image.final.sections[section(image.final, EXPECTATION)]
        need(expectation.header.sh_size == 8 and expectation.header.sh_flags & 7 == 2
             and {r['Place'] for r in refs['Cohort'][2:]} == {expectation.header.sh_addr, expectation.header.sh_addr + 4},
             'two exact expectation pointer placements')
        return dict(FinalSha256=sha(image.final.data), LinkMapSha256=image.link_map_hash,
                    ForwardProviders=forward, ReverseProviders=reverse, ReverseReferences=refs['Reverse'],
                    ColdAnchorReads=cold, CohortReferences=refs['Cohort'], SlotReferences=refs['Slot'],
                    SlotOrigin=self.definition(image, SLOT)[1], StartupVectors=vectors,
                    InitialMSP=0x20010000, Entry=image.final.elf.header.e_entry)


def inspect(contract, native_result, native_root, final_api):
    bindings = Bindings(contract, native_result, native_root, final_api)
    return dict(Status='PASS', Scope='ORDINARY_DIRECT_THIN_ELF_BINDINGS_ONLY',
                Profile=contract['Profile'], Mode=contract['Mode'], Sources=bindings.sources,
                Ordinary=bindings.image(False), EmitRelocs=bindings.image(True),
                TypedABIProof=False, InputAuthenticationProof=False, ClosingProof=False,
                CanonicalProtocolValidated=False, GeneratedSlotIsolationProven=False,
                CalleeBodySemanticsProven=False, FullABIProof=False, FullSemanticABIProof=False,
                SourceIRProof=False, SourceToMachineSemanticProof=False, KernelRuntimeProof=False,
                CellContractSatisfied=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0,
                CompilerExecution=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False)
