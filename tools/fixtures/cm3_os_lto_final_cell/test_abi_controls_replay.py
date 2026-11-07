"""Synthetic full-41 ABI replay controls with closed helper/source buffers."""

import argparse
import copy
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
METHODS = 32
HEADERS = ('context/context_port_abi.h', 'context/context_runtime_port_abi.h',
    'context/context_api_attributes.h', 'context/context_api_types.h', 'context/context_panic.h',
    'context/context_runtime_state.h', 'fiber/fiber_api_attributes.h', 'fiber/fiber_runtime_port_abi.h',
    'fiber/port/fiber_port_runtime_abi.h')
ORDER = ('context/context_core.c', 'context/context_runtime_state.c', 'context/context_panic.c',
    'fiber/port/ARM_CM3/fiber_port.c', 'fiber/port/ARM_CM3/fiber_port_boot.c',
    'fiber/port/ARM_CM3/fiber_port_exception.c', 'fiber/port/fiber_port_context_cohort_expectation.c',
    'tools/fixtures/classic_final_image/application.c', 'tools/fixtures/classic_final_image/startup.S')
EXTRA = ('fiber/port/ARM_CM3/fiber_port_types.h', 'tools/fixtures/classic_final_image/link.ld')
PROTOTYPES = (
    'void fiber_port_context_init(CtxrtContextV1 *context, void *stack_begin, void *stack_end, CtxrtEntryFnV1 entry, void *arg);',
    'void fiber_port_runtime_memory_barrier(void);', 'void fiber_port_panic_wait(void);',
    'void fiber_port_require_scheduler_configuration_environment(void);', 'void fiber_port_runtime_prepare_start(void);',
    'CtxrtContextV1 *fiber_port_runtime_select_first(void);', 'void fiber_port_runtime_start_first(CtxrtContextV1 *first);',
    'void fiber_port_runtime_schedule(void);',
    'CtxrtContextV1 *fiber_internal_runtime_select_scheduler_candidate(CtxrtContextV1 *current);',
    'void fiber_internal_runtime_publish_current_context(CtxrtContextV1 *next);',
    'void fiber_internal_runtime_require_current_context(void);', 'void fiber_internal_task_return(void);')
BUFFERS, H, m = {}, {}, None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def elf(tag, executable=False):
    names = b'\0.text\0.gnu.lto_test\0.shstrtab\0'
    payload = tag.encode('ascii')
    text = b'\x00\xbf' if executable else b''
    data = text + payload + names
    offset = (52 + len(data) + 3) & ~3
    ident = b'\x7fELF\x01\x01\x01' + bytes(9)
    header = struct.pack('<16sHHIIIIIHHHHHH', ident, 1, 40, 1, 0, 0, offset, 0, 52, 0, 0, 40, 4, 3)
    sections = [(0,) * 10, (1, 1, 6, 0, 52, len(text), 0, 0, 2, 0),
                (7, 1, 0x80000000, 0, 52 + len(text), len(payload), 0, 0, 1, 0),
                (21, 3, 0, 0, 52 + len(text) + len(payload), len(names), 0, 0, 1, 0)]
    return header + data + bytes(offset - 52 - len(data)) + b''.join(struct.pack('<10I', *row) for row in sections)


def readelf_text(raw):
    header = H['transport'].require_elf32le(raw)
    offset = header['SectionOffset'];rows = [struct.unpack_from('<10I', raw, offset + i * 40) for i in range(4)]
    strings = rows[3];names = raw[strings[4]:strings[4] + strings[5]]
    lines = ['ELF Header:', '  Class:                             ELF32',
             '  Number of section headers:         4', 'Section Headers:',
             '  [Nr] Name Type Addr Off Size ES Flg Lk Inf Al',
             '  [ 0] NULL 00000000 000000 000000 00 0 0 0']
    for index, row in enumerate(rows[1:], 1):
        name = names[row[0]:names.index(0, row[0])].decode('ascii')
        kind = 'STRTAB' if row[1] == 3 else 'PROGBITS';flags = 'AX' if row[2] == 6 else 'E' if row[2] else ''
        lines.append('  [ %d] %s %s %08x %06x %06x %02x %s %d %d %d' %
                     (index, name, kind, row[3], row[4], row[5], row[9], flags, row[6], row[7], row[8]))
    lines.append('Key to Flags:')
    return ('\n'.join(lines) + '\n').encode('ascii')


class Model:
    """Invented artifacts and journals, real neutral helpers, synthetic core."""
    def __init__(self):
        self.root = Path('C:/synthetic-full-abi/batch');self.seed = self.root.parent / 'seed'
        self.sr = self.seed / 'source';self.capture = self.root.parent / 'native-Os-lto'
        self.files, self.reads, self.calls = {}, [], []
        self.sources = {name: BUFFERS[ROOT / name] for name in HEADERS + ORDER + EXTRA}
        self.sources['tools/fixtures/classic_final_image/main.h'] = b'#define __NVIC_PRIO_BITS 4U\n'
        for name, raw in self.sources.items():self.files[self.sr / name] = raw
        self.external = self.capture / 'toolchain/include/stdint.h';self.files[self.external] = b'synthetic external dependency'
        self.tools = dict(Gcc=self.capture / 'toolchain/bin/arm-none-eabi-gcc.exe', Nm=self.capture / 'toolchain/bin/arm-none-eabi-nm.exe',
            Readelf=self.capture / 'toolchain/bin/arm-none-eabi-readelf.exe', Ld=self.capture / 'toolchain/arm-none-eabi/bin/ld.exe',
            Plugin=self.capture / 'toolchain/lib/gcc/arm-none-eabi/14.3.1/liblto_plugin.dll')
        for name, path in self.tools.items():self.files[path] = ('synthetic admitted tool/' + name).encode('ascii')
        meta = dict(Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True, Cohort=m.COHORT, SourceInventorySha256=m.SOURCE)
        self.native = dict(meta, Status='PASS', Scope='NATIVE_CM3_OS_LTO_CAPTURE_FEASIBILITY_ONLY', SeedMode='O2', SeedBuild=str(self.seed),
            CapturedCompiler=str(self.tools['Gcc']), TranslationUnits=9, SlimIRObjects=8, Qualification=False,
            RequiredCellSatisfied=False, RequiredCellsSatisfied=0, Error=None, PrimaryError=None, ClosingErrors=[],
            InputClosureVerified=True, OutputSealVerified=True, Sources=[], Commands=[], Links=[], InputHashes={},
            LTOPlugin=dict(Path=str(self.tools['Plugin']), Sha256=sha(self.files[self.tools['Plugin']])))
        self.objects = []
        for index, name in enumerate(ORDER):
            source = self.sr / name;obj = self.capture / 'objects' / ('%02d-' % index + Path(name).stem + '.o')
            self.files[obj] = elf('native-' + str(index));self.objects.append(obj)
            deps = self.provider_dependencies(index)
            seed_flags = self.seed_flags(index);flags = ['-Os' if x == '-O2' else x for x in seed_flags]
            if index != 8:flags += ['-flto', '-fno-fat-lto-objects']
            row = dict(Source=str(source), SourceSha256=sha(self.files[source]), Object=str(obj), ObjectSha256=sha(self.files[obj]),
                DependencyFile=str(obj.with_suffix('.d')), SlimIR=index != 8, SeedCompileFlags=seed_flags, CompileFlags=flags,
                CompileDependenciesVerified=True, ActualCompileDependencies=deps)
            self.native['Sources'].append(row)
            self.native['InputHashes'].update({r['Path']:r['Sha256'] for r in deps})
            self.native['Commands'].append(dict(Label='compile ' + Path(name).name,
                Argv=[str(self.tools['Gcc']), *flags, '-MD', '-MF', row['DependencyFile'], '-MT', 'pilot-source-' + str(index),
                      '-c', str(source), '-o', str(obj)], State='TERMINAL', Status='PASS', Exit=0, TimedOut=False, Seconds=0.125))
        self.original = b'synthetic positive ELF'
        for kind in ('ordinary', 'emit-relocs'):
            path = self.capture / kind / 'image.elf';link_map = path.with_suffix('.map');self.files[path] = self.original
            self.native['Links'].append(dict(Kind=kind, Path=str(path), Map=str(link_map), Machine=str(path) + '.ltrans0.ltrans.o', Sha256=sha(self.original)))
            argv = [str(self.tools['Gcc']), '-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-Os', '-flto',
                '-flto-partition=one', '-save-temps=obj', '-v', '-nostdlib', '-Wl,-plugin-opt=-save-temps',
                '-Wl,--gc-sections,--no-undefined,--fatal-warnings,--build-id=none,-z,noexecstack', '-T',
                str(self.sr / 'tools/fixtures/classic_final_image/link.ld'), *map(str, self.objects)]
            if kind == 'emit-relocs':argv.append('-Wl,--emit-relocs')
            argv += ['-Wl,-Map=' + str(link_map), '-o', str(path)]
            self.native['Commands'].append(dict(Label='link ' + kind, Argv=argv, State='TERMINAL', Status='PASS', Exit=0, TimedOut=False, Seconds=0.25))
        vector = struct.pack('<256I', *([0x20001000, 0x101] + [0] * 254))
        self.comparison = dict(Identical=True, Entry=0x101, VectorAddress=0, VectorBytes=vector.hex(),
            Segments=[dict(Vaddr=0, Paddr=0, FileSize=1024, MemorySize=1152, Flags=5, Align=4096, BytesSha256=sha(vector))])
        self.core = types.SimpleNamespace(_ELF=self.parse_image, compare_load_images=self.compare)
        self.batch = dict(meta, Status='BUILT-PENDING-READER', SourceSeed=str(self.seed), NativeCapture=dict(Build=str(self.capture)),
                          Commands=[], Controls=[], Compilations=[], ABIProbes={})
        self.streams = {};self.labels = H['recipes'].batch_plan()['Commands']
        self.private = 'fiber_port_context_cohort_armv7m_synthetic_g4_v1';self.alternate = self.private.replace('_g4_', '_g5_')
        self.anchor = 'fiber_internal_runtime_port_abi_v1_anchor'
        self.link(0, 'positive', self.objects)
        positive = self.root / 'links/positive/image.elf';link_map = positive.with_suffix('.map')
        readers = [dict(Role=role, Path=str(path), Sha256=sha(self.files[path])) for role,path in
                   (('OriginalELF', self.capture / 'ordinary/image.elf'), ('ReproducedELF', positive))]
        self.batch['PositiveAuthority'] = dict(Original=readers[0]['Path'], OriginalSha256=readers[0]['Sha256'],
            Replayed=str(positive), ReplayedSha256=sha(self.files[positive]), Map=str(link_map), MapSha256=sha(self.files[link_map]),
            RawElfByteIdentical=True, Scope='SAME_OS_SLIM_INPUTS_RECIPE_LOAD_IMAGE_REPRODUCTION_PENDING',
            LoadImageComparison=None, LoadImageValidated=False, ValidationDeferred=True, LinkCommandIndex=0, ReaderInputs=readers)
        self.batch['ABIControlsDeferredReader'] = dict(Kind='OS_POSITIVE_LOAD_IMAGE_REPRODUCTION', Status='PENDING',
            ValidationDeferred=True, Inputs=copy.deepcopy(readers), Map=dict(Role='ReproducedMap',Path=str(link_map),Sha256=sha(self.files[link_map])),
            PositiveLinkRevalidated=False, RequiredCellsSatisfied=0)
        self.definitions(1, self.objects[3], [(self.private, 'D')])
        anchor_import = self.imports(2, self.objects[4], [self.anchor], self.anchor)
        plan = H['plan'].control_plan(dict(target=dict(nvic_priority_bits=4)), 'ARM_CM3', 'arm_cm3')
        expected = (self.alternate, 'fiber_port_storage_cohort_arm_cm3_v999_r0', self.anchor, 'SVC_Handler', 'PendSV_Handler')
        for position,(spec,first,link_index,wanted) in enumerate(zip(plan,(3,8,13,19,24),(7,12,18,23,28),expected)):
            name,index,added = spec['Name'],spec['Index'],spec['Added'];directory = self.root/'compilations'/name
            flags = list(self.native['Sources'][index]['CompileFlags']);deltas=[]
            if added is None:
                project = directory/'source'
                for relative,raw in self.sources.items():
                    changed=raw
                    for mutation,before,after in spec['Mutations']:
                        if relative==mutation:
                            changed=raw.replace(before,after,1)
                            deltas.append(dict(Original=str(self.sr/relative),Copy=str(project/relative),BeforeSha256=sha(raw),
                                AfterSha256=sha(changed),Before=before.hex(),After=after.hex(),Count=1))
                    self.files[project/relative]=changed
                source=project/ORDER[index];flags=[x.replace(str(self.sr),str(project)) for x in flags]
            else:
                project=self.sr;source=directory/(name.replace('-','_')+'.c');self.files[source]=added
                deltas=[dict(Kind='ADDED-CONTROL-TU',Source=str(source),Sha256=sha(added))]
            obj=directory/('%02d-'%index+source.stem+'.o');self.files[obj]=elf(name)
            dependencies=self.compile_pair(first,source,obj,flags,flags,index,project,probe=False)
            compiled=dict(Name=name,TemplateIndex=index,OriginalSource=self.native['Sources'][index]['Source'],Source=str(source),
                SourceSha256=sha(self.files[source]),OriginalObject=str(self.objects[index]),OriginalObjectSha256=sha(self.files[self.objects[index]]),
                Object=str(obj),ObjectSha256=sha(self.files[obj]),Assembly=None,ObjectByteIdenticalToOriginal=False,
                CompileFlags=flags,DiscoveryFlags=list(flags),Dependencies=dependencies,CompileDependenciesVerified=True,
                DiscoveryDependencyFile=str(obj.with_suffix('.discovery.d')),CompileDependencyFile=str(obj.with_suffix('.compile.d')),
                SourceDeltas=deltas,CommandIndices=[first,first+1],SaveTemps=False,SemanticProof=False,CpuExecution=False)
            record=dict(Name=name,Expected=wanted,Status='INTENDED-LINK-REJECTION-PASS',RequiredCellsSatisfied=0,
                        Compilation=compiled,SlimIR=self.slim(first+2,obj))
            selected=list(self.objects)
            if added is None:selected[index]=obj
            else:selected.append(obj)
            if position<2:record['ImportEvidence']=self.imports(first+3,obj,[wanted],wanted)
            else:
                changed='fiber_internal_runtime_port_abi_v2_anchor' if added is None else wanted
                record['ChangedDefinitions']=self.definitions(first+3,obj,[(changed,'D' if added is None else 'T')])
                if added is None:
                    record['ChangedImports']=self.imports(first+4,obj,[])
                    record['ImportEvidence']=copy.deepcopy(anchor_import)
            result,output,partial=self.link(link_index,name,selected,wanted=wanted,added=obj if added is not None else None,source=source)
            if added is None:
                machine=Path(str(output)+'.ltrans0.ltrans.o')
                record['DiagnosticMachine']=dict(Path=str(machine),Sha256=sha(self.files[machine]),Kind='ACTUAL_SAVED_ARM_ELF32_REL')
                classification=H['diagnostics'].classify_undefined(result,wanted,self.tools['Ld'],machine=machine)
            else:classification=H['diagnostics'].classify_duplicate(result,wanted,self.tools['Ld'],obj,self.objects[3],source)
            record.update(Classification=classification,LinkCommandIndex=link_index,FinalImageAbsent=True,PartialMap=str(partial),
                ConsumedObjects=[dict(Index=i,Path=str(path),Sha256=sha(self.files[path])) for i,path in enumerate(selected)])
            self.batch['Controls'].append(record);self.batch['Compilations'].append(compiled)
            self.files[directory/'receipt.json']=encoded(compiled);self.files[self.root/'controls'/(name+'.json')]=encoded(record)
        oracles=H['declarations'].emit_probes(ordinary=H['ordinary'])
        for position,(name,first) in enumerate(zip(('types.c','attributes.c','slot_read.c','slot_write.c','slot_address.c'),(29,32,35,37,39))):
            oracle=oracles[name];accepted=position<2;source=self.root/'abi'/name;self.files[source]=oracle['Source'].encode('ascii')
            obj=source.with_name(Path(name).stem.replace('_','-')+'.o')
            dflags,flags=H['probes'].probe_flags(self.native['Sources'][0]['CompileFlags'],oracle['RequiredCFlags'],accepted)
            deps=self.compile_pair(first,source,obj,dflags,flags,0,self.sr,probe=True)
            if accepted:
                self.files[obj]=elf(name);self.files[obj.with_suffix('.i')]=self.cpp();self.files[obj.with_suffix('.s')]=b'synthetic accepted assembly'
                classification=dict(AcceptedCompile=True)
            else:
                result=self.result(first+1);classification=H['probes'].classify_undeclared(result,oracle['DiagnosticIdentifier'],
                    object_exists=False,source_path=source,source_bytes=self.files[source])
            record=dict(Source=str(source),SourceSha256=sha(self.files[source]),Object=str(obj) if accepted else None,
                Preprocessed=str(obj.with_suffix('.i')) if accepted else None,CompileFlags=flags,DiscoveryFlags=dflags,Dependencies=deps,
                CompileDependenciesVerified=True,DiscoveryDependencyFile=str(obj.with_suffix('.discovery.d')),
                CompileDependencyFile=str(obj.with_suffix('.compile.d')),CommandIndices=[first,first+1],Classification=classification)
            if accepted:record['SlimIR']=self.slim(first+2,obj)
            self.batch['ABIProbes'][name]=record
        self.batch['PreprocessedAttributes']=H['declarations'].inspect_preprocessed_attributes(self.cpp(),ordinary=H['ordinary'])
        for i in range(41,134):self.command(i,['synthetic-out-of-component'])
        self.seal_native();self.seal()

    def seed_flags(self,index):
        target=['-mcpu=cortex-m3','-mthumb','-mfloat-abi=soft','-O2']
        if index==8:return target+['-g0','-DPILOT_HAS_VTOR=1']
        return target+['-std=gnu11','-g0','-ffreestanding','-ffunction-sections','-fdata-sections','-Wall','-Wextra',
            '-Werror=implicit-function-declaration','-Werror=attributes','-Werror=ignored-attributes','-DFIBER_PORT_ARMV7M=1',
            '-DFIBER_PORT_BUILD_SELECTED=1','-DFIBER_SCHEDULER_BASEPRI=16']+['-I'+str(self.sr/name if name else self.sr)
            for name in ('tools/fixtures/classic_final_image','fiber/port/ARM_CM3','fiber/port','fiber','context','')]+[
            '-I'+str(self.seed/'cmsis'),'-include',str(self.sr/'tools/fixtures/classic_final_image/main.h'),
            '-I'+str((self.sr/ORDER[index]).parent)]

    def provider_dependencies(self,index):
        required={ORDER[index],'tools/fixtures/classic_final_image/main.h'}
        if index<=4:required.update(('context/context_port_abi.h','context/context_api_attributes.h','context/context_api_types.h','fiber/fiber_api_attributes.h'))
        if index in (0,1,3,4):required.add('context/context_runtime_port_abi.h')
        paths=sorted({self.sr/name for name in required}|{self.external})
        return [dict(Path=str(path),Sha256=sha(self.files[path])) for path in paths]

    def cpp(self):
        attribute='__attribute__((no_sanitize("address", "undefined", "thread"))) '
        return ('# 1 "'+self.sr.as_posix()+'/context/context_port_abi.h" 1\n'+'\n'.join(attribute+x for x in PROTOTYPES[:8])
            +'\n# 1 "'+self.sr.as_posix()+'/context/context_runtime_port_abi.h" 1\n'+'\n'.join(attribute+x for x in PROTOTYPES[8:])+'\n').encode('ascii')

    def command(self,index,argv,stdout=b'',stderr=b''):
        code=1 if index in (7,12,18,23,28,36,38,40) else 0;prefix='commands/%03d'%index
        row=dict(Label=self.labels[index]['Label'],Argv=list(argv),Cwd=str(self.root),State='TERMINAL',
            Status='EXPECTED-NONZERO' if code else 'PASS',Exit=code,ExpectedExit=code,TimedOut=False,Seconds=0.125,
            Stdout=prefix+'.stdout',Stderr=prefix+'.stderr',StdoutSha256=sha(stdout),StderrSha256=sha(stderr))
        while len(self.batch['Commands'])<=index:self.batch['Commands'].append(None)
        self.batch['Commands'][index]=row;self.streams[index]=(stdout,stderr)
        return self.result(index)

    def result(self,index):
        stdout,stderr=self.streams[index]
        return types.SimpleNamespace(returncode=self.batch['Commands'][index]['Exit'],stdout=stdout,stderr=stderr,timed_out=False,State='TERMINAL')

    def link(self,index,name,objects,wanted=None,added=None,source=None):
        output=self.root/'links'/name/'image.elf';partial=output.with_suffix('.map');self.files[partial]=b'synthetic link map/'+name.encode()
        base=next(r['Argv'] for r in self.native['Commands'] if r['Label']=='link ordinary');argv=[];inserted=False
        for value in base:
            if value=='-v':continue
            if value in [str(x) for x in self.objects]:
                if not inserted:argv.extend(map(str,objects));inserted=True
            elif value.startswith('-Wl,-Map='):argv.append('-Wl,-Map='+str(partial))
            elif value==self.native['Links'][0]['Path']:argv.append(str(output))
            else:argv.append(value)
        stderr=b''
        if wanted is None:self.files[output]=self.original
        elif added is not None:
            stderr=(str(self.tools['Ld'])+': '+str(added)+" (symbol from plugin): in function `"+wanted+"':\r\n"
                +"(.text+0x0): multiple definition of `"+wanted+"'; "+str(self.objects[3])+" (symbol from plugin):(.text+0x0): first defined here\r\n"
                +'collect2.exe: error: ld returned 1 exit status\r\n').encode('ascii')
        else:
            machine=Path(str(output)+'.ltrans0.ltrans.o');self.files[machine]=elf('saved-machine-'+name,executable=True)
            if wanted==self.anchor:
                text=str(self.tools['Ld'])+': '+str(machine)+": in function `fiber_port_context_init':\r\n<artificial>:(.text+0x0): undefined reference to `"+wanted+"'\r\n"
            else:text=str(self.tools['Ld'])+': '+str(machine)+":(.fiber_port_context_cohort_expectation+0x0): undefined reference to `"+wanted+"'\r\n"
            stderr=(text+'collect2.exe: error: ld returned 1 exit status\r\n').encode('ascii')
        return self.command(index,argv,stderr=stderr),output,partial

    def definitions(self,index,obj,rows):
        raw=('\r\n'.join(name+' '+kind+' 0 ' for name,kind in rows)+'\r\n').encode('ascii')
        self.command(index,[str(self.tools['Nm']),'--plugin',str(self.tools['Plugin']),'-P','-S','--defined-only',str(obj)],stdout=raw)
        return H['port_runner'].parse_ir_definitions(raw)

    def imports(self,index,obj,names,expected=None):
        raw=(''.join('         U '+name+'\r\n' for name in names)).encode('ascii')
        self.command(index,[str(self.tools['Nm']),'--plugin',str(self.tools['Plugin']),'-u',str(obj)],stdout=raw)
        evidence=dict(Object=str(obj),Imports=list(names),Plugin=str(self.tools['Plugin']),RawNmSha256=sha(raw))
        if expected is not None:evidence['ExpectedImport']=expected
        return evidence

    def slim(self,index,obj):
        raw=self.files[obj];text=readelf_text(raw)
        self.command(index,[str(self.tools['Readelf']),'-hSW',str(obj)],stdout=text)
        return dict(Object=str(obj),Sha256=sha(raw),SlimIR=True,Sections=H['transport'].section_records(text.decode('ascii')))

    def compile_pair(self,first,source,obj,dflags,cflags,index,project,probe):
        target='pilot-source-'+str(index);discovery=obj.with_suffix('.discovery.d');actual=obj.with_suffix('.compile.d')
        paths={source,project/'tools/fixtures/classic_final_image/main.h',self.external}
        if probe:paths.update(self.sr/'context'/name for name in ('context_port_abi.h','context_runtime_port_abi.h'))
        else:
            if project!=self.sr:paths.update(project/name for name in ('context/context_api_types.h','context/context_api_attributes.h'))
        paths=sorted(paths);raw=(target+': '+' '.join(str(p) for p in paths)+'\n').encode('ascii')
        self.files[discovery]=raw;self.files[actual]=raw
        self.command(first,[str(self.tools['Gcc']),*dflags,'-M','-MF',str(discovery),'-MT',target,str(source)])
        stderr=self.undeclared(source) if first in (35,37,39) else b''
        self.command(first+1,[str(self.tools['Gcc']),*cflags,'-MD','-MF',str(actual),'-MT',target,'-c',str(source),'-o',str(obj)],stderr=stderr)
        return [dict(Path=str(p),Sha256=sha(self.files[p])) for p in paths]

    def undeclared(self,source):
        lines=self.files[source].decode('ascii').splitlines();slot='fiber_internal_runtime_current_context_slot'
        column=lines[4].index(slot)+1;location=str(source)+':5:'+str(column);marker='      | '+' '*(column-1)
        suggestion='fiber_internal_runtime_require_current_context'
        text=[str(source)+": In function 'cm0_abi_"+source.stem+"':",location+": error: '"+slot+"' undeclared (first use in this function); did you mean '"+suggestion+"'?",
            '    5 | '+lines[4],marker+'^'+'~'*(len(slot)-1),marker+suggestion,
            location+': note: each undeclared identifier is reported only once for each function it appears in']
        return ('\r\n'.join(text)+'\r\n').encode('ascii')

    def seal_native(self,providers=True):
        raw=encoded(self.native);self.files[self.capture/'results.json']=raw;self.batch['NativeCapture']['ReceiptSha256']=sha(raw)
        if providers:self.batch['DeclaredProviders']=H['declarations'].inspect_provider_dependencies(self.sources,raw,
            source_root=str(self.sr),capture_root=str(self.capture),ordinary=H['ordinary'])

    def catalog(self):
        path=self.root/'artifacts.json'
        self.files[path]=encoded(dict(Artifacts={p.relative_to(self.root).as_posix():sha(raw)
            for p,raw in self.files.items() if p.is_relative_to(self.root) and p!=path}))
        self.batch['InputHashes']={str(p):sha(raw) for p,raw in self.files.items() if p!=path}

    def seal(self):
        for i,row in enumerate(self.batch['Commands']):
            self.files[self.root/('commands/%03d.json'%i)]=encoded(row)
            for suffix,raw in zip(('.stdout','.stderr'),self.streams[i]):self.files[self.root/('commands/%03d%s'%(i,suffix))]=raw
        self.files[self.root/'commands.json']=encoded(self.batch['Commands']);self.batch['CommandsSha256']=sha(self.files[self.root/'commands.json'])
        self.catalog()

    def change_stream(self,index,stdout=None,stderr=None):
        old=self.streams[index];values=(old[0] if stdout is None else stdout,old[1] if stderr is None else stderr)
        self.streams[index]=values
        self.batch['Commands'][index].update(StdoutSha256=sha(values[0]),StderrSha256=sha(values[1]));self.seal()

    def read(self,path,expected):
        if not isinstance(path,Path) or path not in self.files:raise ValueError('missing synthetic read role/'+str(path))
        if expected is None and path!=self.root/'artifacts.json':raise AssertionError('unexpected unbound read')
        raw=self.files[path]
        if expected is not None and sha(raw)!=expected:raise ValueError('synthetic hash mismatch')
        self.reads.append((path,expected));return raw

    def parse_image(self,path,kind):
        if not str(path).endswith('.ltrans0.ltrans.o') or kind!='ET_REL':raise AssertionError('core must never parse slim IR')
        self.calls.append(('parse',path));return types.SimpleNamespace(data=self.files[path],final=False)

    def compare(self,original,replayed):
        self.calls.append(('compare',original,replayed))
        if (original,replayed)!=(self.capture/'ordinary/image.elf',self.root/'links/positive/image.elf'):raise AssertionError('foreign image role')
        if self.files[original]!=self.original or self.files[replayed]!=self.original:raise ValueError('synthetic unequal image')
        return copy.deepcopy(self.comparison)

    def run(self,**kwargs):
        args=dict(batch=self.batch,native=self.native,root=self.root,core=self.core,helpers=H,read=self.read);args.update(kwargs)
        return m.inspect(**args)


class ControlsTests(unittest.TestCase):
    def test_full_41_not_only_eight_rejections(self):
        model=Model();proof=model.run();self.assertIs(m.require_result(proof),proof)
        self.assertEqual([r['Index'] for r in proof['CommandBindings']],list(range(41)))
        self.assertEqual([r['CompileIndex'] for r in proof['DependencyBindings']], [4,9,14,20,25,30,33,36,38,40])
        self.assertEqual((proof['CommandsReplayed'],proof['SuccessfulCommands'],proof['IntendedRejections']),(41,33,8))
        self.assertEqual((proof['AcceptedProbes'],proof['SlimIRInspections'],proof['PluginNMInspections']),(2,7,8))
        self.assertEqual(len([c for c in model.calls if c[0]=='parse']),3)
        for key in m.NONCLAIMS:self.assertIs(proof[key],False)

    def test_exact_helper_and_core_contract(self):
        model=Model()
        for key in H:
            helpers=dict(H);del helpers[key]
            with self.subTest(key=key),self.assertRaises(m.Rejected):model.run(helpers=helpers)
        with self.assertRaises(m.Rejected):model.run(helpers=dict(H,extra=object()))
        with self.assertRaises(m.Rejected):model.run(core=object())

    def test_pure_no_fs_process_loader_or_o2_admission(self):
        model=Model();before=copy.deepcopy((model.files,model.batch,model.native));modes=H['ordinary'].MODES
        with ExitStack() as stack:
            for name in ('read_bytes','read_text','open','resolve','absolute','stat','lstat','exists','is_file','is_dir','samefile','iterdir','glob','rglob'):
                stack.enter_context(patch.object(Path,name,side_effect=AssertionError('filesystem/'+name)))
            for name in ('stat','lstat','scandir','listdir','system','getcwd'):
                stack.enter_context(patch.object(os,name,side_effect=AssertionError('physical/'+name)))
            stack.enter_context(patch('builtins.open',side_effect=AssertionError('open')))
            stack.enter_context(patch.object(subprocess,'Popen',side_effect=AssertionError('process')))
            stack.enter_context(patch.object(importlib.util,'spec_from_file_location',side_effect=AssertionError('load')))
            stack.enter_context(patch.object(H['ordinary'],'inspect_provider_dependencies',side_effect=AssertionError('O2 admission')))
            model.run()
        self.assertEqual(before,(model.files,model.batch,model.native));self.assertIs(H['ordinary'].MODES,modes)

    def test_aggregate_journal_cannot_differ(self):
        model=Model();rows=copy.deepcopy(model.batch['Commands']);rows[30]['Exit']=1
        model.files[model.root/'commands.json']=encoded(rows);model.batch['CommandsSha256']=sha(encoded(rows));model.catalog()
        with self.assertRaisesRegex(m.Rejected,'aggregate command'):model.run()

    def test_per_command_only_corruption_including_both_accepts(self):
        for index in (0,7,12,18,23,28,29,30,31,32,33,34,36,38,40):
            model=Model();path=model.root/('commands/%03d.json'%index);row=json.loads(model.files[path]);row['Exit']=False
            model.files[path]=encoded(row);model.catalog()
            with self.subTest(index=index),self.assertRaisesRegex(m.Rejected,'per-command'):model.run()

    def test_both_copies_foreign_compiler_nm_readelf_plugin(self):
        for index,position in ((0,0),(4,0),(30,0),(33,0),(1,0),(1,2),(31,0),(34,0)):
            model=Model();model.batch['Commands'][index]['Argv'][position]='C:/foreign/tool.exe';model.seal()
            with self.subTest(index=index,position=position),self.assertRaises(m.Rejected):model.run()

    def test_terminal_literal_fields_and_labels(self):
        for key,value in (('Exit',True),('ExpectedExit',True),('TimedOut',0),('Seconds',True),('Seconds',-1),
                          ('Status','FAIL'),('State','ATTEMPT'),('Label','foreign'),('Cwd','C:/foreign')):
            model=Model();model.batch['Commands'][36][key]=value;model.seal()
            with self.subTest(key=key),self.assertRaises(m.Rejected):model.run()

    def test_successful_compile_streams_are_clean(self):
        for index in (3,4,29,30,32,33):
            model=Model();model.change_stream(index,stderr=b'warning\n')
            with self.subTest(index=index),self.assertRaisesRegex(m.Rejected,'clean successful'):model.run()

    def test_no_other_components_replayed(self):
        model=Model();proof=model.run()
        self.assertNotIn(model.root/'commands/041.json',dict(model.reads));self.assertEqual(proof['CommandsReplayed'],41)
        self.assertFalse(proof['IsolationReplayed']);self.assertFalse(proof['CompleteCellProof'])

    def test_passed_native_is_reparsed_and_hash_bound(self):
        model=Model();model.native['Forged']=True
        with self.assertRaisesRegex(m.Rejected,'reparsed native'):model.run()
        model=Model();del model.batch['InputHashes'][str(model.capture/'results.json')]
        with self.assertRaises(m.Rejected):model.run()

    def test_tool_and_plugin_admission_bytes_required(self):
        for key in ('Gcc','Nm','Readelf','Ld','Plugin'):
            model=Model();del model.batch['InputHashes'][str(model.tools[key])]
            with self.subTest(key=key),self.assertRaises(m.Rejected):model.run()

    def test_every_private_source_copy_is_bound(self):
        for name in ('stale-nvic-expectation','stale-storage-application','stale-reverse-anchor'):
            model=Model();path=model.root/'compilations'/name/'source/context/context_api_types.h'
            model.files[path]+=b' ';model.catalog()
            with self.subTest(name=name),self.assertRaisesRegex(m.Rejected,'canonical private source copy'):model.run()

    def test_exact_one_source_mutation_and_catalog_membership(self):
        model=Model();path=model.root/'compilations/stale-nvic-expectation/source/tools/fixtures/classic_final_image/main.h'
        model.files[path]=model.sources['tools/fixtures/classic_final_image/main.h'];model.catalog()
        with self.assertRaisesRegex(m.Rejected,'canonical private source copy'):model.run()
        model=Model();model.files[model.root/'compilations/stale-nvic-expectation/source/foreign.h']=b'foreign';model.catalog()
        with self.assertRaisesRegex(m.Rejected,'private copy membership'):model.run()

    def test_added_handler_bytes_are_independently_derived(self):
        model=Model();path=model.root/'compilations/duplicate-svc/duplicate_svc.c';model.files[path]=b'void foreign(void) {}\n';model.catalog()
        with self.assertRaisesRegex(m.Rejected,'exact added handler'):model.run()

    def test_control_compile_source_flags_dependency_paths_and_target(self):
        for value in ('foreign-source','foreign-flags','foreign-target','foreign-dep'):
            model=Model();argv=model.batch['Commands'][4]['Argv']
            if value=='foreign-source':argv[argv.index('-c')+1]='C:/foreign/source.c'
            elif value=='foreign-flags':argv.insert(1,'-DUNDECLARED=1')
            elif value=='foreign-target':argv[argv.index('-MT')+1]='pilot-source-3'
            else:argv[argv.index('-MF')+1]='C:/foreign/deps.d'
            model.seal()
            with self.subTest(value=value),self.assertRaises(m.Rejected):model.run()

    def test_ordered_link_objects_and_exact_trailing_output(self):
        for defect in ('swap','output','extra-output'):
            model=Model();argv=model.batch['Commands'][7]['Argv'];positions=[i for i,x in enumerate(argv) if x.endswith('.o')]
            if defect=='swap':argv[positions[0]],argv[positions[1]]=argv[positions[1]],argv[positions[0]]
            elif defect=='output':argv[-1]=str(model.objects[0])
            else:argv.extend(['-o','C:/foreign/image.elf'])
            model.seal()
            with self.subTest(defect=defect),self.assertRaises(m.Rejected):model.run()

    def test_dependency_targets_sets_and_foreign_stage_rejected(self):
        for defect in ('target','set','foreign'):
            model=Model();path=Path(model.batch['Controls'][0]['Compilation']['CompileDependencyFile'])
            if defect=='target':model.files[path]=model.files[path].replace(b'pilot-source-6:',b'pilot-source-5:')
            elif defect=='set':model.files[path]=('pilot-source-6: '+model.batch['Controls'][0]['Compilation']['Source']+'\n').encode()
            else:
                foreign=model.root/'foreign-stage/input.h';model.files[foreign]=b'foreign'
                raw=model.files[path].rstrip()+b' '+str(foreign).encode()+b'\n';model.files[path]=raw
                model.files[path.with_name(path.name.replace('.compile.d','.discovery.d'))]=raw
            model.catalog()
            with self.subTest(defect=defect),self.assertRaises(ValueError):model.run()

    def test_actual_dependency_bytes_read_and_hashed(self):
        model=Model();path=model.external
        def read(name,expected):
            value=model.read(name,expected);return value+b'wrong' if name==path else value
        with self.assertRaisesRegex(m.Rejected,'immutable read bytes'):model.run(read=read)

    def test_original_private_nm_kind_value_duplicates_and_stage(self):
        for raw in (b'foreign D 0 \n',(b'x D 0 \n'*2),b'fiber_port_context_cohort_test_g5_v1 D 0 \n',
                    b'fiber_port_context_cohort_test_g4_v1 T 0 \n',b'fiber_port_context_cohort_test_g4_v1 D 1 \n'):
            model=Model();model.change_stream(1,stdout=raw)
            with self.subTest(raw=raw),self.assertRaises(ValueError):model.run()
        for index in (1,16,22,27):
            model=Model();model.change_stream(index,stdout=model.streams[index][0]+b'foreign ? 0 \r\n')
            with self.subTest(index=index,kind='?'),self.assertRaisesRegex(m.Rejected,'slim definition grammar'):model.run()
        model=Model();model.change_stream(1,stdout=model.streams[1][0]+b'foreign Q 0 \r\n')
        self.assertEqual(model.run()['OriginalPrivate'],model.private)

    def test_unchanged_boot_v1_consumer_is_not_learned_from_claim(self):
        model=Model();model.change_stream(2,stdout=b' U fiber_internal_runtime_port_abi_v2_anchor\n')
        with self.assertRaisesRegex(m.Rejected,'unchanged v1 boot'):model.run()

    def test_control_nm_imports_and_changed_state_definition(self):
        for index,raw in ((6,b' U fiber_port_context_cohort_wrong_g5_v1\n'),(11,b' U fiber_port_storage_cohort_arm_cm3_v2_r0\n'),
                          (16,b'fiber_internal_runtime_port_abi_v1_anchor D 0 \n'),(17,b' U fiber_internal_runtime_port_abi_v1_anchor\n')):
            model=Model();model.change_stream(index,stdout=raw)
            with self.subTest(index=index),self.assertRaises(m.Rejected):model.run()

    def test_readelf_sections_bound_to_actual_header_names_and_sizes(self):
        raw=bytearray(elf('metadata'));header=H['transport'].require_elf32le(bytes(raw))
        for field,value in ((9,0x10),(6,3),(7,2),(8,16)):
            struct.pack_into('<I',raw,header['SectionOffset']+2*40+field*4,value)
        raw=bytes(raw);text=readelf_text(raw).decode('ascii')
        self.assertIn('10 E 3 2 16',text)
        m._readelf_metadata(text,raw,header)
        self.assertEqual(H['transport'].section_records(text),m._binary_sections(raw,header))
        for index in (5,10,15,21,26,31,34):
            model=Model();raw=model.streams[index][0].replace(b'.gnu.lto_test',b'.gnu.lto_fake');model.change_stream(index,stdout=raw)
            with self.subTest(index=index),self.assertRaisesRegex(m.Rejected,'section correspondence'):model.run()
            for name,field,value in (('ES',7,b'10'),('Lk',9,b'1'),('Inf',10,b'1'),('Al',11,b'4')):
                model=Model();lines=model.streams[index][0].splitlines();row=lines[6].split()
                self.assertEqual(row[2],b'.text');self.assertEqual(row[11],b'2')
                row[field]=value;lines[6]=b' '.join(row);model.change_stream(index,stdout=b'\n'.join(lines)+b'\n')
                with self.subTest(index=index,column=name),self.assertRaisesRegex(m.Rejected,'section metadata correspondence'):model.run()
        for field in range(3,10):
            model=Model();lines=model.streams[5][0].splitlines();row=lines[5].split();row[field]=b'1'
            lines[5]=b' '.join(row);model.change_stream(5,stdout=b'\n'.join(lines)+b'\n')
            with self.subTest(null_column=field),self.assertRaisesRegex(m.Rejected,'section-row grammar'):model.run()
        for defect in ('no-start','no-end','duplicate-start','duplicate-end','unmatched','duplicate-index','missing-index','reordered'):
            model=Model();lines=model.streams[5][0].splitlines()
            if defect=='no-start':lines.remove(b'Section Headers:')
            elif defect=='no-end':lines.remove(b'Key to Flags:')
            elif defect=='duplicate-start':lines.insert(3,b'Section Headers:')
            elif defect=='duplicate-end':lines.append(b'Key to Flags:')
            elif defect=='unmatched':lines.insert(6,b'foreign section metadata')
            elif defect=='duplicate-index':lines.insert(7,lines[6])
            elif defect=='missing-index':lines.pop(6)
            else:lines[6],lines[7]=lines[7],lines[6]
            model.change_stream(5,stdout=b'\n'.join(lines)+b'\n')
            with self.subTest(block=defect),self.assertRaises(m.Rejected):model.run()
        model=Model();obj=Path(model.batch['Controls'][0]['Compilation']['Object']);model.files[obj]=elf('fallback',True);model.catalog()
        model.change_stream(5,stdout=readelf_text(model.files[obj]))
        with self.assertRaisesRegex(m.Rejected,'executable fallback'):model.run()

    def test_saved_ltrans_header_and_parser_must_bind_actual_bytes(self):
        model=Model();machine=Path(model.batch['Controls'][0]['DiagnosticMachine']['Path']);model.files[machine]=b'not an ELF';model.catalog()
        with self.assertRaises(ValueError):model.run()
        model=Model()
        def bad(path,kind):return types.SimpleNamespace(data=b'foreign',final=False)
        with self.assertRaisesRegex(m.Rejected,'exact saved native'):model.run(core=types.SimpleNamespace(_ELF=bad,compare_load_images=model.compare))

    def test_undefined_closed_diagnostics_and_status_facade(self):
        model=Model();original=H['diagnostics'].classify_undefined
        def checked(result,*args,**kwargs):
            self.assertFalse(hasattr(result,'Status'));self.assertFalse(hasattr(result,'status'));return original(result,*args,**kwargs)
        with patch.object(H['diagnostics'],'classify_undefined',checked):model.run()
        self.assertEqual(model.batch['Commands'][7]['Status'],'EXPECTED-NONZERO')
        for defect in ('foreign-machine','garbage','stdout'):
            model=Model();out,err=model.streams[7]
            if defect=='foreign-machine':err=err.replace(str(Path(model.batch['Controls'][0]['DiagnosticMachine']['Path'])).encode(),b'C:/foreign/image.elf.ltrans0.ltrans.o')
            elif defect=='garbage':err+=b'extra cause\n'
            else:out=b'foreign output'
            model.change_stream(7,stdout=out,stderr=err)
            with self.subTest(defect=defect),self.assertRaises(ValueError):model.run()

    def test_duplicate_diagnostics_bound_to_added_and_original_objects(self):
        for old,new in ((b'first defined here',b'other diagnostic'),(b'SVC_Handler',b'PendSV_Handler')):
            model=Model();model.change_stream(23,stderr=model.streams[23][1].replace(old,new))
            with self.subTest(old=old),self.assertRaises(ValueError):model.run()

    def test_undeclared_slot_diagnostics_and_manifest_absence(self):
        for index in (36,38,40):
            model=Model();model.change_stream(index,stderr=model.streams[index][1]+b'other error\n')
            with self.subTest(index=index),self.assertRaises(ValueError):model.run()
        for index in (7,12,18,23,28,36,38,40):
            model=Model();model.files[Path(model.batch['Commands'][index]['Argv'][-1])]=b'forbidden retained failed output';model.catalog()
            with self.subTest(index=index),self.assertRaisesRegex(m.Rejected,'failed output present'):model.run()

    def test_both_accepted_probe_sources_cpp_and_save_sets_required(self):
        for stem in ('types','attributes'):
            for suffix in ('.c','.i','.s','.o'):
                model=Model();del model.files[model.root/'abi'/(stem+suffix)];model.catalog()
                with self.subTest(stem=stem,suffix=suffix),self.assertRaises(m.Rejected):model.run()
        model=Model();path=model.root/'abi/attributes.i';model.files[path]=model.files[path].replace(b'"thread"',b'"memory"',1);model.catalog()
        with self.assertRaises(ValueError):model.run()

    def test_stored_controls_probes_and_receipts_are_comparison_only(self):
        for defect in ('control','probe','compilation','per-control','per-compile'):
            model=Model()
            if defect=='control':model.batch['Controls'][0]['Classification']['Qualification']=True
            elif defect=='probe':model.batch['ABIProbes']['types.c']['Classification']['AcceptedCompile']=False
            elif defect=='compilation':model.batch['Compilations'][0]['SourceDeltas']=[]
            else:
                path=model.root/('controls/stale-nvic-expectation.json' if defect=='per-control' else 'compilations/stale-nvic-expectation/receipt.json')
                row=json.loads(model.files[path]);row['Forged']=True;model.files[path]=encoded(row);model.catalog()
            with self.subTest(defect=defect),self.assertRaises(m.Rejected):model.run()

    def test_result_literal_counters_nonclaims_and_closed_schema(self):
        baseline=Model().run()
        for key in m.COUNTS:
            proof=copy.deepcopy(baseline);proof[key]=True
            with self.subTest(key=key),self.assertRaises(m.Rejected):m.require_result(proof)
        for key in m.NONCLAIMS:
            proof=copy.deepcopy(baseline);proof[key]=0
            with self.subTest(key=key),self.assertRaises(m.Rejected):m.require_result(proof)
        proof=copy.deepcopy(baseline);proof['FullCellQualified']=True
        with self.assertRaises(m.Rejected):m.require_result(proof)

    def test_json_finite_duplicates_and_path_aliases(self):
        for raw in (b'{"x":0,"x":1}',b'1e999',b'-1e999',b'NaN',b'Infinity',b'\xff',b'{'):
            with self.subTest(raw=raw),self.assertRaises(m.Rejected):m._json(raw)
        self.assertEqual(m._json(b'{"x":1.25,"y":"1e999"}'),dict(x=1.25,y='1e999'))
        model=Model();model.files[model.root/'artifacts.json']=b'{"Artifacts":{},"overflow":1e999}'
        with self.assertRaisesRegex(m.Rejected,'nonfinite JSON'):model.run()
        for path in ('C:/x/../y','C:/x//y','C:/x/y.','C:/x/y '):
            with self.subTest(path=path),self.assertRaises(m.Rejected):m._path(path)

    def test_result_read_closure_absence_and_nested_nonclaims(self):
        for defect in ('reads','hash','absence','accepted','classifier','objects','source-count','command-label',
                       'positive-map','positive-inputs','segment-type','vector-type','comparison-extra'):
            proof=Model().run()
            if defect=='reads':proof['ReadInputs'].pop();proof['ReadFiles']-=1
            elif defect=='hash':proof['ReadInputs'][0]['Sha256']='F'*64
            elif defect=='absence':proof['AbsentOutputs'][0]['PhysicalAbsenceChecked']=True
            elif defect=='accepted':proof['ABIProbes']['attributes.c']['Classification']['AcceptedCompile']=1
            elif defect=='classifier':proof['Controls'][0]['Classification']['FullABIProof']=True
            elif defect=='objects':proof['Controls'][0]['ConsumedObjects'].reverse()
            elif defect=='source-count':proof['ProjectSourceFiles']=True
            elif defect=='command-label':proof['CommandBindings'][30]['Label']='compile only eight negatives'
            elif defect=='positive-map':proof['PositiveAuthority']['Map']='C:/foreign/image.map'
            elif defect=='positive-inputs':proof['PositiveAuthority']['ReaderInputs'].reverse()
            elif defect=='segment-type':proof['PositiveAuthority']['LoadImageComparison']['Segments'][0]['FileSize']=True
            elif defect=='vector-type':proof['PositiveAuthority']['LoadImageComparison']['VectorAddress']=False
            else:proof['PositiveAuthority']['LoadImageComparison']['Qualified']=True
            with self.subTest(defect=defect),self.assertRaises(m.Rejected):m.require_result(proof)
        baseline=Model().run()
        self.assertEqual(len(m.UNDEFINED_FIELDS),23);self.assertEqual(len(m.DUPLICATE_FIELDS),23)
        for position in range(5):
            for key in ('CompilerExecuted','FullInstructionSemantics'):
                for value in (True,False):
                    proof=copy.deepcopy(baseline);proof['Controls'][position]['Classification'][key]=value
                    with self.subTest(control=position,extra=key,value=value),self.assertRaisesRegex(m.Rejected,'classifier byte binding'):m.require_result(proof)
            proof=copy.deepcopy(baseline);del proof['Controls'][position]['Classification']['DiagnosticNormalization']
            with self.subTest(control=position,missing=True),self.assertRaisesRegex(m.Rejected,'classifier byte binding'):m.require_result(proof)
        for name in m.PROBES:
            for value in (True,False):
                proof=copy.deepcopy(baseline);proof['ABIProbes'][name]['Classification']['FullABIProof']=value
                with self.subTest(probe=name,extra=value),self.assertRaisesRegex(m.Rejected,'probe classification'):m.require_result(proof)
        for path in (('DeclaredProviders',),('DeclaredProviders','SourceInspection'),('PreprocessedAttributes',)):
            for defect in ('empty','missing','extra-false','count-bool','nonclaim-true','nonclaim-int'):
                proof=copy.deepcopy(baseline);record=proof
                for key in path:record=record[key]
                scope=record['Scope']
                if defect=='empty':scope.clear()
                elif defect=='missing':del scope['RequiredCellsSatisfied']
                elif defect=='extra-false':scope['ForeignClaim']=False
                elif defect=='count-bool':scope['RequiredCellsSatisfied']=False
                elif defect=='nonclaim-true':scope['FullABIProof']=True
                else:scope['FullABIProof']=0
                with self.subTest(scope=path,defect=defect),self.assertRaises(m.Rejected):m.require_result(proof)

    def test_returned_proofs_do_not_alias_input_or_helper_globals(self):
        model=Model();proof=model.run();proof['Controls'][0]['Compilation']['CompileFlags'].clear()
        proof['DeclaredProviders']['Providers'].clear();proof['PreprocessedAttributes']['Declarations'].clear()
        self.assertTrue(model.batch['Controls'][0]['Compilation']['CompileFlags']);self.assertEqual(len(model.batch['DeclaredProviders']['Providers']),9)
        self.assertEqual(len(model.batch['PreprocessedAttributes']['Declarations']),12);self.assertIsNone(model.batch['PositiveAuthority']['LoadImageComparison'])


def main():
    global BUFFERS,H,m
    parser=argparse.ArgumentParser(description=__doc__,allow_abbrev=False);parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args();output=args.output_dir.absolute();temporary=Path(tempfile.gettempdir()).absolute()
    if output.exists() or output.is_relative_to(ROOT) or not output.is_relative_to(temporary):parser.error('fresh external TEMP output directory required')
    paths=dict(leaf=HERE/'abi_controls_replay.py',deps=HERE/'dependency_bytes.py',recipes=HERE/'batch_recipes.py',declarations=HERE/'declarations.py',
        ordinary=HERE.parent/'ordinary_final_cell/abi.py',plan=HERE.parent/'ordinary_final_cell/controls.py',
        diagnostics=HERE.parent/'cm3_lto_abi_controls/diagnostics.py',probes=HERE.parent/'cm0_final_cell/components.py',
        port_runner=HERE.parent/'cm3_lto_port_policy/runner.py',guard=HERE/'batch_guard.py',transport=HERE.parent/'cm3_lto_transport/probe.py',
        oracle=HERE.parent/'cm0_final_cell/abi.py')
    sources=(Path(__file__).resolve(),*paths.values(),*(ROOT/name for name in HEADERS+ORDER+EXTRA))
    BUFFERS={path:path.read_bytes() for path in sources};opening={str(path):sha(raw) for path,raw in BUFFERS.items()}
    for name,path in paths.items():
        if name=='oracle':continue
        module=types.ModuleType('_full_abi_test_'+name);module.__file__=str(path)
        def buffered_read(path):
            if path not in BUFFERS:raise AssertionError('unenrolled helper read/'+str(path))
            return BUFFERS[path]
        with patch.object(Path,'read_bytes',buffered_read):exec(compile(BUFFERS[path],str(path),'exec'),module.__dict__)
        if name=='leaf':m=module
        else:H[name]=module
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ControlsTests))
    closing={str(path):sha(path.read_bytes()) for path in sources}
    report=dict(Status='PASS' if result.wasSuccessful() and result.testsRun==METHODS and not result.skipped and opening==closing else 'FAIL',
        Tests=result.testsRun,ExpectedTests=METHODS,Errors=len(result.errors),Failures=len(result.failures),Skipped=len(result.skipped),
        SourceHashes=opening,SourceDrift=opening!=closing,ClosingFilesVerified=sum(opening[k]==v for k,v in closing.items()),
        SyntheticControlsOnly=True,ActualCaptureRead=False,ActualMachineBytesValidated=False,CompilerExecuted=False,
        FullABIProof=False,Qualification=False,RequiredCellsSatisfied=0)
    output.mkdir(parents=True);(output/'results.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n',encoding='ascii')
    print(json.dumps(report,sort_keys=True));return 0 if report['Status']=='PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
