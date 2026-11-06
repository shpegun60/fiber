"""CM0/O2/direct source-provider and applied-reference facts, not cell admission.

The caller authenticates the result, all files, parser/helpers and their closing
identities/memberships. No tools are launched and no source modules are loaded.
"""
import hashlib
from pathlib import Path
import struct


COHORT = 'cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default'
INVENTORY = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
SOURCES = (
    'context/context_core.c', 'context/context_runtime_state.c', 'context/context_panic.c',
    'fiber/port/ARM_CM0/fiber_port.c', 'fiber/port/ARM_CM0/fiber_port_boot.c',
    'fiber/port/ARM_CM0/fiber_port_exception.c',
    'fiber/port/fiber_port_context_cohort_expectation.c',
    'tools/fixtures/classic_final_image/application.c',
    'tools/fixtures/classic_final_image/startup.S',
)
SELECT = 'fiber_internal_runtime_select_scheduler_candidate'
PUBLISH = 'fiber_internal_runtime_publish_current_context'
CURRENT = 'fiber_internal_runtime_require_current_context'
RETURN = 'fiber_internal_task_return'
ANCHOR = 'fiber_internal_runtime_port_abi_v1_anchor'
SLOT = 'fiber_internal_runtime_current_context_slot'
PRIVATE = ('fiber_port_context_cohort_armv6m_p0x434D3030u_l0x00010001u_f0_e0_h0_j0_v0_d0_r0_'
           'z8u_y0_w1_g2_u00000000_i0_o0xFFFFFFFDu_c0_s0_x0_m0_a0_b0_t0_n0_k0_q0')
STORAGE = 'fiber_port_storage_cohort_arm_cm0_v1_r0'
EXPECTATION = '.fiber_port_context_cohort_expectation'
FORWARD_OWNERS = {'fiber_port_context_init': 4, 'fiber_port_runtime_memory_barrier': 3,
                  'fiber_port_panic_wait': 3, 'fiber_port_require_scheduler_configuration_environment': 3,
                  'fiber_port_runtime_prepare_start': 3, 'fiber_port_runtime_select_first': 3,
                  'fiber_port_runtime_start_first': 3, 'fiber_port_runtime_schedule': 3}
OWNERS = {SELECT: 1, PUBLISH: 1, CURRENT: 1, RETURN: 0, ANCHOR: 1,
          SLOT: 1, PRIVATE: 3, STORAGE: 3, 'Reset_Handler': 8,
          'SVC_Handler': 3, 'PendSV_Handler': 3, **FORWARD_OWNERS}
FUNCTIONS = frozenset((SELECT, PUBLISH, CURRENT, RETURN, 'Reset_Handler',
                       'SVC_Handler', 'PendSV_Handler', *FORWARD_OWNERS))
# Owner, original input section, section-relative relocation offset, kind, name.
REVERSE = (
    (3, '.text.fiber_port_runtime_schedule', 0x0a, 10, CURRENT),
    (3, '.text.fiber_port_scheduler_pick_first_from_start', 0x1a, 10, SELECT),
    (3, '.text.fiber_port_scheduler_pick_next_from_pendsv', 0x12, 10, SELECT),
    (3, '.text.fiber_port_scheduler_pick_next_from_pendsv', 0x26, 10, PUBLISH),
    (3, '.text.fiber_port_init_context_frame', 0x88, 2, RETURN),
)
COLD = (
    (3, 'fiber_port_runtime_prepare_start', 0x18, 0x02, 0x04),
    (4, 'fiber_port_context_init', 0x13c, 0xae, 0xb0),
)
COHORT_REFS = (
    (4, '.text.fiber_port_context_init', 0x134, 2, PRIVATE),
    (5, '.text.fiber_exception_runtime_check', 0x2c, 2, PRIVATE),
    (6, EXPECTATION, 0, 2, PRIVATE), (7, EXPECTATION, 0, 2, STORAGE),
)
SLOT_REFS = ((3, '.text.SVC_Handler', 0xb4, 2, SLOT),
             (3, '.text.PendSV_Handler', 0xe0, 2, SLOT))
VECTORS = ((8, '.isr_vector', 4, 2, 'Reset_Handler'),
           (8, '.isr_vector', 44, 2, 'SVC_Handler'),
           (8, '.isr_vector', 56, 2, 'PendSV_Handler'))


class Rejected(ValueError):
    pass


def need(condition, detail):
    if not condition:
        raise Rejected('cm0-cell-bindings: ' + detail)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def section(elf, name):
    need(elf.names.count(name) == 1, 'unique section: ' + name)
    return elf.names.index(name)


def mapped(elf, index, address, size, kind):
    actual, boundary = elf.mapping(index, address)
    need(actual == kind and address + size <= boundary, 'complete ' + kind + ' mapping')


class _Bindings:
    def __init__(self, result, root, core):
        need(type(result) is dict and result.get('Profile') == 'CM0'
             and result.get('Mode') == 'O2' and result.get('Cohort') == COHORT
             and result.get('SourceInventorySha256') == INVENTORY, 'fixed CM0/O2/E9 selection')
        self.root, self.core = Path(root).resolve(strict=True), core
        rows = result.get('Sources')
        need(type(rows) is list and len(rows) == 9, 'nine ordered sources')
        self.paths, self.objects, self.sources = [], [], []
        for index, (name, row) in enumerate(zip(SOURCES, rows)):
            need(type(row) is dict, 'source record')
            source = self.root / 'source' / name
            obj = self.root / 'objects' / ('%02d-%s.o' % (index, Path(name).stem))
            need(Path(row['Source']).resolve(strict=True) == source.resolve(strict=True)
                 and Path(row['Object']).resolve(strict=True) == obj.resolve(strict=True),
                 'source/object order: ' + name)
            source_hash = sha(source.read_bytes())
            parsed = core._ELF(obj, 'ET_REL')
            need(source_hash == row.get('SourceSha256') and sha(parsed.data) == row.get('ObjectSha256'),
                 'source/object receipt hash: ' + name)
            self.paths.append(obj)
            self.objects.append(parsed)
            self.sources.append(dict(Source=name, SourceSha256=source_hash, Object=str(obj),
                                     ObjectSha256=sha(parsed.data)))
        self.definitions = {}
        for name, owner in OWNERS.items():
            found = [(index, symbol) for index, obj in enumerate(self.objects) for symbol in obj.symbols
                     if symbol['name'] == name and symbol['section'] != 'SHN_UNDEF']
            need(len(found) == 1 and found[0][0] == owner, 'unique provider: ' + name)
            self.definitions[name] = found[0][1]
        prefixes = ('fiber_port_context_cohort_arm', 'fiber_port_storage_cohort_')
        names = {s['name'] for obj in self.objects for s in obj.symbols
                 if s['name'].startswith(prefixes)
                 and s['name'] != 'fiber_port_storage_cohort_consumer_expectation'}
        need(names == {PRIVATE, STORAGE}, 'foreign private/storage identity')
        expected = (*REVERSE, *((i, '.text.' + name, pool, 2, ANCHOR)
                               for i, name, pool, _, _ in COLD), *COHORT_REFS, *SLOT_REFS)
        tracked = {SELECT, PUBLISH, CURRENT, RETURN, ANCHOR, SLOT, PRIVATE, STORAGE}
        actual = {(i, obj.sections[sec].name, off, kind, target['name'])
                  for i, obj in enumerate(self.objects) if i >= 3
                  for (sec, off), (kind, target) in obj.relocations.items()
                  if target['name'] in tracked}
        need(actual == set(expected), 'complete selected-consumer relocation membership')

    def placement(self, image, owner, index):
        obj = self.objects[owner]
        sec = obj.sections[index]
        need(obj.names.count(sec.name) == 1, 'unique original section name')
        identity = self.core._object_identity(self.paths[owner])
        need(identity in image.providers and image.providers[identity].data == obj.data,
             'map provider bytes')
        placed = image.placements.get((identity, sec.name))
        need(placed is not None, 'kept map placement: ' + sec.name)
        address, size = placed
        h = sec.header
        matches = [(i, s) for i, s in enumerate(image.final.sections)
                   if s.header.sh_flags & 2 and s.header.sh_addr <= address
                   and address + size <= s.header.sh_addr + s.header.sh_size]
        need(size == h.sh_size and size > 0 and len(matches) == 1
             and address % max(1, h.sh_addralign) == 0, 'full input-section placement: ' + sec.name)
        final_index, final_sec = matches[0]
        need(final_sec.header.sh_type == h.sh_type and final_sec.header.sh_flags & 7 == h.sh_flags & 7,
             'input/final storage: ' + sec.name)
        return dict(Provider=str(self.paths[owner]), ProviderSha256=sha(obj.data),
                    InputSection=sec.name, InputSectionIndex=index, SectionAddress=address,
                    SectionSize=size, FinalSectionIndex=final_index,
                    LinkMapSha256=image.link_map_hash)

    def definition(self, image, name):
        owner = OWNERS[name]
        original = self.definitions[name]
        kind = 'STT_FUNC' if name in FUNCTIONS else 'STT_OBJECT'
        need(original['kind'] == kind and original['binding'] == 'STB_GLOBAL'
             and type(original['section']) is int and original['size'] > 0,
             'original definition: ' + name)
        final = [s for s in image.final.symbols if s['name'] == name and s['section'] != 'SHN_UNDEF']
        need(len(final) == 1, 'unique final definition: ' + name)
        final = final[0]
        need(final['kind'] == kind and final['binding'] == 'STB_GLOBAL'
             and type(final['section']) is int and original['size'] == final['size'],
             'final definition: ' + name)
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
            original_section = self.objects[owner].sections[original['section']]
            h = original_section.header
            need(original_section.name == '.bss.fiber_runtime_current_context_slot'
                 and h.sh_type == 'SHT_NOBITS' and h.sh_size == 4 and h.sh_addralign >= 4
                 and h.sh_flags & 7 == 3 and offset == 0 and final['size'] == 4 and value % 4 == 0,
                 'four-byte zero-fill slot')
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
             and obj.relocations[(index, offset)][1]['name'] == target, 'original relocation: ' + name)
        original_target = obj.relocations[(index, offset)][1]
        if target == 'Reset_Handler':
            need(original_target == self.definitions[target], 'original startup target')
        else:
            need(original_target['section'] == 'SHN_UNDEF' and original_target['binding'] == 'STB_GLOBAL'
                 and original_target['kind'] == 'STT_NOTYPE' and original_target['value'] == 0
                 and original_target['size'] == 0, 'original external target: ' + target)
        origin = self.placement(image, owner, index)
        address = origin['SectionAddress'] + offset
        need(0 <= offset and offset + 4 <= origin['SectionSize'], 'reference extent')
        before, after = obj.section_read(index, offset, 4), image.read(address, 4)
        definition, target_origin = self.definition(image, target)
        if kind == 10:
            original_form = self.core._address_form(before, offset)
            final_form = self.core._address_form(after, address)
            need(original_form is not None and original_form[0] == 'bl' and original_form[3] == -4
                 and final_form is not None and final_form[0] == 'bl'
                 and final_form[1] == definition['value'] & ~1, 'BL addend/applied destination')
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
        if emitted:
            need(image.final.relocations.get(key) == (kind, definition), 'exact final relocation definition')
        else:
            need(key not in image.final.relocations, 'ordinary image has applied relocation metadata')
        return dict(ObjectIndex=owner, Section=name, Offset=offset, Kind=kind, Symbol=target,
                    Addend=addend, Place=address, ResolvedValue=resolved, OriginalBytes=before.hex(),
                    Bytes=after.hex(), InputPlacement=origin, TargetOrigin=target_origin,
                    AppliedRelocationMetadataChecked=emitted)

    def cold_read(self, image, spec, emitted):
        owner, function, pool, load, read = spec
        obj = self.objects[owner]
        index = section(obj, '.text.' + function)
        original = obj.symbol(function, 'STT_FUNC', root=True)
        final = image.final.symbol(function, 'STT_FUNC', root=True)
        origin = image._origin(function, final)
        need(original['value'] & ~1 == 0 and read == load + 2 and read + 2 <= original['size'],
             'cold-read function extent')
        ref = self.reference(image, (owner, '.text.' + function, pool, 2, ANCHOR), emitted)
        base = final['value'] & ~1
        before = obj.section_read(index, load, 4)
        after = image.read(base + load, 4)
        need(before == after and before[2:] == bytes.fromhex('1b78'), 'retained LDRB r3,[r3] cold read')
        old_form = self.core._address_form(before[:2], load)
        new_form = self.core._address_form(after[:2], base + load)
        need(old_form is not None and old_form[:3] == ('ldr', pool, 3)
             and new_form is not None and new_form[:3] == ('ldr', ref['Place'], 3),
             'cold literal load target/register')
        for offset in (load, read):
            mapped(obj, index, offset, 2, 't')
            mapped(image.final, final['section'], base + offset, 2, 't')
        return dict(Function=function, ObjectIndex=owner, FunctionOrigin=origin, LoadOffset=load,
                    ReadOffset=read, LoadAddress=base + load, ReadAddress=base + read,
                    Bytes=after.hex(), AnchorReference=ref, RetainedByteRead=True)

    def image(self, emitted):
        stem = 'emit-relocs' if emitted else 'ordinary'
        image = self.core.FinalImage(self.paths[3], self.root / (stem + '.elf'),
            self.root / (stem + '.dis'), provider_objects={str(p): p for p in self.paths},
            link_map=self.root / (stem + '.map'), float_abi='soft')
        identities = {s['name'] for s in image.final.symbols
                      if s['name'].startswith(('fiber_port_context_cohort_arm', 'fiber_port_storage_cohort_'))
                      and s['name'] != 'fiber_port_storage_cohort_consumer_expectation'}
        need(identities == {PRIVATE, STORAGE}, 'foreign final private/storage identity')
        forward = [self.definition(image, name)[1] for name in FORWARD_OWNERS]
        reverse = [self.definition(image, n)[1] for n in (SELECT, PUBLISH, CURRENT, RETURN)]
        refs = [self.reference(image, spec, emitted) for spec in REVERSE]
        cold = [self.cold_read(image, spec, emitted) for spec in COLD]
        cohorts = [self.reference(image, spec, emitted) for spec in COHORT_REFS]
        slots = [self.reference(image, spec, emitted) for spec in SLOT_REFS]
        vectors = [self.reference(image, spec, emitted) for spec in VECTORS]
        vector = image.final.sections[section(image.final, '.isr_vector')]
        need(vector.header.sh_addr == 0 and vector.header.sh_size == 1024
             and vector.header.sh_flags & 7 == 2 and vector.header.sh_type == 'SHT_PROGBITS'
             and struct.unpack('<I', image.read(0, 4))[0] == 0x20010000
             and image.final.elf.header.e_entry == vectors[0]['ResolvedValue'], 'vector geometry/MSP/entry')
        need(self.objects[8].sections[section(self.objects[8], '.isr_vector')].header.sh_size == 1024,
             'original vector extent')
        expectation = image.final.sections[section(image.final, EXPECTATION)]
        need(expectation.header.sh_size == 8 and expectation.header.sh_flags & 7 == 2
             and {r['Place'] for r in cohorts[2:]} == {expectation.header.sh_addr, expectation.header.sh_addr + 4},
             'two exact expectation pointer placements')
        return dict(FinalSha256=sha(image.final.data), LinkMapSha256=image.link_map_hash,
                    ForwardProviders=forward, ReverseProviders=reverse, ReverseReferences=refs, ColdAnchorReads=cold,
                    CohortReferences=cohorts, SlotOrigin=self.definition(image, SLOT)[1],
                    SlotReferences=slots, StartupVectors=vectors, InitialMSP=0x20010000,
                    Entry=image.final.elf.header.e_entry)


def inspect(native_result, native_root, final_api):
    """Inspect already-admitted immutable files with the caller's frozen reader.

    Applied REL authority comes from emit-relocs; ordinary checks use the same
    original addends, map placements and actual bytes, not independent REL proof.
    Full protocol, generated-slot policy, typed ABI and input authentication are
    separate composer obligations; this helper neither imports nor runs them.
    """
    bindings = _Bindings(native_result, native_root, final_api)
    ordinary, emitted = bindings.image(False), bindings.image(True)
    return dict(Status='PASS', Scope='CM0_O2_DIRECT_THIN_ELF_BINDINGS_ONLY',
                Sources=bindings.sources, Ordinary=ordinary, EmitRelocs=emitted,
                InputAuthenticationProof=False, ClosingProof=False, TwinLoadImageCompared=False,
                CanonicalProtocolValidated=False, GeneratedSlotIsolationProven=False,
                CalleeBodySemanticsProven=False, TypedABIProof=False, SourceIRProof=False,
                SourceToMachineSemanticProof=False, KernelRuntimeProof=False,
                FullABIProof=False, FullSemanticABIProof=False,
                CellContractSatisfied=False, RequiredCellSatisfied=False, RequiredCellsSatisfied=0,
                CompilerExecution=False, CpuExecution=False, BoardExecution=False,
                GlobalFreezeQualified=False)
