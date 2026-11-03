"""Actual production/reference builds and causal decoded-mechanism checks."""
from __future__ import annotations
from pathlib import Path
import json
import re
import struct
from cm4_mpu_basic_engine import Engine, common, pilot, fp, need, save, digest, GRID, MODES, basic_terminal_controls
ROOT = Path(__file__).resolve().parent
REF = ROOT / "reference"
PIN = "a50edad08b29052631aa469d4df6e6ec7ff68878"

NEW_CHECKS = {
 'sp': ('mov r2,sp\n    ldr r3,[sp,#0]\n    cmp r2,r3\n    bne .Lsp_bad', 'SP_EXACT_CHECK'),
 'cookie12': ('movt r3,#0xc005\n    cmp r2,r3\n    bne .Lcookie_bad', 'COOKIE12_EXACT_CHECK'),
 'cookie16': ('movt r3,#0x1357\n    cmp r2,r3\n    bne .Lcookie_bad', 'COOKIE16_EXACT_CHECK'),
 'control': ('str r2,[r1,#56]\n    cmp r2,#3\n    bne .Lcontrol_bad', 'CONTROL3_EXACT_CHECK'),
 'ipsr': ('str r2,[r1,#60]\n    cmp r2,#0\n    bne .Lorigin_bad', 'IPSR0_EXACT_CHECK')}
NEW_MUTANTS = {f'no-{key}-{part}': reason for key, (_, reason) in NEW_CHECKS.items() for part in ('compare','reject')}
EXPECTED = {'no-save-r4':'PENDSV_RAW_SAVE_TRANSFER', 'no-save-r9':'PENDSV_RAW_SAVE_TRANSFER',
 'no-svc71':'SVC71_OPCODE','no-slot-store':'FAULT_SLOT_OPCODE','no-peer-load':'FAULT_PEER_OPCODE',
 'no-oracle-r9':'GPR_COMPARE_R9', **NEW_MUTANTS}
REF_ROOTS = ('pxPortInitialiseStack','xPortStartScheduler')
REF_HANDLERS = ('vPortSVCHandler','xPortPendSVHandler','xPortSysTickHandler')
REF_ASM_HELPERS = ('vSVCHandler_C','vSystemCallEnter','vSystemCallExit')
REF_REASONS = {'first-psp':'REF_FIRST_PSP','raw-control':'REF_RAW_CONTROL_BEFORE_FP',
               'scheduler-mask':'REF_BASEPRI_SCHEDULER','first-copy':'REF_FIRST_MPU_MAP'}
REF_MUTANTS = {
 'first-psp': ('static void prvRestoreContextOfFirstTask( void )\n{', '" msr psp, r0', 'ARM_CM4_MPU FreeRTOS first-restore lost ordered generated instruction:'),
 'raw-control': ('void xPortPendSVHandler( void )\n{', '" mrs r3, control', 'ARM_CM4_MPU FreeRTOS PendSV-MPU lost ordered generated instruction:'),
 'scheduler-mask': ('void xPortPendSVHandler( void )\n{', '" msr basepri, r0', 'ARM_CM4_MPU FreeRTOS PendSV-MPU lost ordered generated instruction:'),
 'first-copy': ('static void prvRestoreContextOfFirstTask( void )\n{', '" stmia r0, {r4-r11}', 'ARM_CM4_MPU FreeRTOS first-restore lost ordered generated instruction:')}

def compact(i):
    return re.sub(r'\s+','',i['Operands'].split('@')[0]).lower()

class GridBuilds(Engine):
    def mutation(self, original, name, directory):
            if name not in NEW_MUTANTS: return super().mutation(original,name,directory)
            key, part = name[3:].rsplit('-',1)
            anchor, reason = NEW_CHECKS[key]
            text=original.read_text()
            need(text.count(anchor)==1,'Exact stress mutation boundary')
            lines=anchor.splitlines()
            index=-2 if part=='compare' else -1
            lines[index]='    nop'
            changed=text.replace(anchor,'\n'.join(lines))
            target=directory/('mutant-'+original.name)
            target.write_text(changed,encoding='ascii',newline='\n')
            self.generated[str(target.resolve())]=dict(Path=str(target.resolve()),Sha256=digest(target),Role='CompiledExactCheckOmission')
            record=dict(Name=name,Original=str(original),OriginalSha256=digest(original),Mutated=str(target),MutatedSha256=digest(target),Expected=reason)
            save(directory/'mutation.json',record)
            self.generated_mutations.append(record)
            return target

    def compile_units(self,sources,directory,flags,providers,mutant=None):
            if mutant not in NEW_MUTANTS: return super().compile_units(sources,directory,flags,providers,mutant)
            objects,maps=[],[]
            for index,original in enumerate(sources):
                need(str(original.resolve()) in self.inputs,'Original source not enrolled')
                source=self.mutation(original,mutant,directory) if original==self.fixture/'stress.S' else original
                obj=directory/('%02d-'%index+original.stem+'.o');dep=obj.with_suffix('.d')
                result=self.command([self.tools['gcc'],*flags,'-I'+str(original.parent),'-MD','-MF',dep,'-c',source,'-o',obj],'compile actual source with exact stress-check omission')
                need('warning:' not in result['Stderr'],'Compiler warning in stress control')
                self.dependency_check(dep)
                role='port' if original in providers else 'expectation' if original.name=='fiber_port_context_cohort_expectation.c' else 'fixture' if original.is_relative_to(self.fixture) else 'common'
                maps.append(dict(Original=str(original),Compiled=str(source),SourceSha256=digest(source),Object=str(obj),ObjectSha256=digest(obj),Command=result['Record'],Role=role))
                objects.append(obj)
            save(directory/'source-object-map.json',maps)
            return objects,maps

    def audit_mechanisms(self,image):
            super().audit_mechanisms(image)
            body=[i for i in image.body('fixture_register_stress') if not image.is_data(i,'fixture_register_stress')]
            ins={i['Address']:i for i in body}
            # Exact local emitted sequences bind each loaded value to its CMP, BNE,
            # and the independent reason instruction, rather than accepting mere reads.
            def check(seq,reason,code):
                matches=[]
                for j in range(len(body)-len(seq)):
                    if all(body[j+k]['Mnemonic'].split('.')[0]==mn and compact(body[j+k])==op for k,(mn,op) in enumerate(seq)):
                        branch=body[j+len(seq)]
                        kind,target=fp.control_form(branch)
                        reject=ins.get(target)
                        if branch['Mnemonic'].split('.')[0]=='bne' and kind=='conditional' and reject and reject['Mnemonic'].split('.')[0]=='movs' and compact(reject)==f'r0,#{code}': matches.append(j)
                need(len(matches)==1,reason)
            check([('mov','r2,sp'),('ldr','r3,[sp,#0]'),('cmp','r2,r3')],'SP_EXACT_CHECK',122)
            for offset,report,lo,hi,key in ((12,48,51966,49157,'COOKIE12'),(16,52,39903,4951,'COOKIE16')):
                check([('ldr',f'r2,[sp,#{offset}]'),('str',f'r2,[r1,#{report}]'),('movw',f'r3,#{lo}'),('movt',f'r3,#{hi}'),('cmp','r2,r3')],key+'_EXACT_CHECK',123)
            check([('mrs','r2,control'),('str','r2,[r1,#56]'),('cmp','r2,#3')],'CONTROL3_EXACT_CHECK',124)
            check([('mrs','r2,ipsr'),('str','r2,[r1,#60]'),('cmp','r2,#0')],'IPSR0_EXACT_CHECK',125)

    def build_image(self,consumer,case=0,opt='O2',lto=False,archive=False,mutant=None,model=False):
            # One path builds both baseline and omission images, retaining the
            # same provider, prelink owner, and final ELF audits.
            return self.build_complete_image(consumer,case,opt,lto,archive,mutant,model)

    def build_complete_image(self,consumer,case,opt,lto,archive,mutant,model):
            name=('model' if model else consumer+'-'+opt+('-lto' if lto else '-native')+('-archive' if archive else '-direct')+'-case'+str(case)+('-'+mutant if mutant else ''))
            directory=self.build/name; directory.mkdir()
            providers=[self.repo/pilot.PORT/n for n in ('fiber_port.c','fiber_port_boot.c')]
            roles=('engine','state','panic')+(('optional_configuration',) if consumer=='fiber' else ())
            sources=[] if model else list(self.reader.get_runtime_source_paths(self.repo,roles))
            if consumer=='fiber' and not model: sources.append(self.repo/'fiber/lifecycle/fiber_v1.c')
            if not model: sources+=providers+[self.repo/'fiber/port/fiber_port_context_cohort_expectation.c',self.fixture/'access.S',self.fixture/'stress.S',self.fixture/'api_roots.S']
            sources += [self.fixture/n for n in ('startup.S','transport.c','model.c' if model else 'application.c')]
            objects,maps=self.compile_units(sources,directory,self.flags_for(consumer,case,opt,lto,model),providers,mutant)
            proof={}
            if not model:
                state=str(self.reader.get_runtime_source_paths(self.repo,('state',))[0])
                config=str(self.reader.get_runtime_source_paths(self.repo,('optional_configuration',))[0])
                proof=self.audit_common_private(maps,{common.SLOT:state,common.REVERSE:state,common.CONFIG_ANCHOR:config if consumer=='fiber' else None},directory)
                self.audit_provider([Path(m['Object']) for m in maps if m['Role']=='port'],directory)
            archived=[Path(m['Object']) for m in maps if m['Role'] in ('common','port')]
            if archive:
                lib=directory/'libactual-runtime.a'
                self.command([self.tools['ar'],'rcs',lib,*archived],'native AR explicit plugin actual common+port archive')
                linked=[o for o in objects if o not in archived]+[lib]
                self.command([self.tools['ar'],'t',lib],'record actual archive members')
            else: linked=objects
            elf=directory/'runtime.elf'
            self.command([self.tools['gcc'],*pilot.CPU,'-'+opt,'-nostdlib',*(['-flto'] if lto else []),'-Wl,--gc-sections,--no-undefined,--fatal-warnings,-z,noexecstack','-Wl,-Map='+str(directory/'runtime.map'),'-T',self.fixture/'link.ld',*linked,'-o',elf],'grid final native/LTO ELF')
            self.dump(elf)
            image=fp.Image(elf,self.ELFFile)
            audit=self.audit_basic(image,consumer,case,lto,proof,model)
            reason=None
            try:
                if not model: self.audit_mechanisms(image)
            except RuntimeError as e: reason=str(e)
            need(reason==EXPECTED.get(mutant),'Wrong exact codegen discriminator: '+repr((name,reason,EXPECTED.get(mutant))))
            row=dict(Name=name,Consumer=consumer,Case=case,Optimization=opt,LTO=lto,Archive=archive,Status='CODEGEN_CONTROL_REJECTED' if mutant else 'COMPILED',Executed=False,Elf=str(elf),ElfSha256=digest(elf),Audit=audit,ExpectedCodegenRejection=EXPECTED.get(mutant),ActualCodegenRejection=reason,PrelinkPrivateOwners=proof,Mutation=mutant)
            save(directory/'codegen-audit.json',row)
            print(row['Status']+' '+name,flush=True)
            return row

    def dump(self,elf):
            for tool,args,suffix in (('objdump',['-drwC','-Mreg-names-std'],'.dis'),('objdump',['-dr'],'.parity.dis'),('readelf',['-hASsrW','-A','-lW'],'.readelf.txt'),('nm',['-a'],'.nm.txt')):
                elf.with_suffix(suffix).write_text(self.command([self.tools[tool],*args,elf],'inspect actual final ELF')['Stdout'],encoding='ascii')

    def ref_flags(self,opt,lto):
            port=Path(self.a.freertos).resolve()/'portable/GCC/ARM_CM4_MPU'
            return [*pilot.CPU,'-'+opt,'-std=c11','-ffreestanding','-fno-builtin','-fno-common','-ffunction-sections','-fdata-sections','-Wall','-Wextra','-Werror',*(['-flto'] if lto else []),'-DFIBER_FREERTOS_PARITY_ENABLE_MPU=1','-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1','-DFIBER_FREERTOS_PARITY_MPU_REGIONS=8','-DconfigENABLE_ERRATA_837070_WORKAROUND=0','-I'+str(REF),'-I'+str(Path(self.a.freertos).resolve()/'include'),'-I'+str(port)]

    def ref_mutate(self,original,mutant,directory):
            # Instructions are selected only in their real function definition, not
            # declarations or another first/PendSV transfer with the same spelling.
            text=original.read_text(encoding='utf-8'); anchor,prefix,_=REF_MUTANTS[mutant]
            need(text.count(anchor)==1,'Reference exact function mutation boundary')
            head,body=text.split(anchor)
            selected=[]
            for m in re.finditer(r'^.*$',body,re.M):
                line=m.group()
                normalized=re.sub(r'\s+','',line).lower()
                if re.sub(r'\s+','',prefix).lower() in normalized: selected.append(m)
            need(selected,'Reference mutation instruction absent: '+mutant)
            m=selected[0]
            line=body[m.start():m.end()]
            replacement=re.sub(r'".*?\\n"',lambda _: '" nop \\n"',line)
            need(replacement!=line,'Reference mutation did not replace instruction')
            changed=head+anchor+body[:m.start()]+replacement+body[m.end():]
            path=directory/'mutant-port.c'; path.write_text(changed,encoding='utf-8',newline='\n')
            self.generated[str(path.resolve())]=dict(Path=str(path.resolve()),Sha256=digest(path),Role='CompiledActualUpstreamOmission')
            save(directory/'mutation.json',dict(Name=mutant,Original=str(original),OriginalSha256=digest(original),Mutated=str(path),MutatedSha256=digest(path),ExpectedFailure=REF_MUTANTS[mutant][2]))
            return path

    def build_reference(self,opt,lto,archive,mutant=None):
            name=opt+('-lto' if lto else '-native')+('-archive' if archive else '-direct')+('-'+mutant if mutant else '')
            directory=self.build/'reference'/name; directory.mkdir(parents=True)
            port=Path(self.a.freertos).resolve()/'portable/GCC/ARM_CM4_MPU/port.c'
            objects=[]; maps=[]
            for index,original in enumerate([REF/'main.c',REF/'providers.c',REF/'startup.S',port]):
                need(str(original.resolve()) in self.inputs,'Reference source must be enrolled before compile')
                source=self.ref_mutate(original,mutant,directory) if original==port and mutant else original
                obj=directory/(str(index)+'-'+original.stem+'.o');dep=obj.with_suffix('.d')
                self.command([self.tools['gcc'],*self.ref_flags(opt,lto),'-MD','-MF',dep,'-c',source,'-o',obj],'compile actual pinned reference or explicit link-only boundary')
                self.dependency_check(dep)
                maps.append(dict(Original=str(original),Compiled=str(source),SourceSha256=digest(source),Object=str(obj),ObjectSha256=digest(obj),Role='reference_upstream' if original==port else 'reference_scaffold'))
                objects.append(obj)
            save(directory/'source-object-map.json',maps)
            owners=fp.Suite.audit_reference_owners(self,maps,directory)
            for n in REF_ASM_HELPERS:
                definitions=[]
                for m in maps:
                    txt=self.command([self.tools['nm'],'-P','--defined-only',m['Object']],'reference actual inline-ASM helper owner')['Stdout']
                    for line in txt.splitlines():
                        fields=line.split()
                        if fields and fields[0]==n: definitions.append(dict(Source=m['Original'],Compiled=m['Compiled'],Object=m['Object'],ObjectSha256=m['ObjectSha256'],Role=m['Role'],NmType=fields[1]))
                need(len(definitions)==1 and definitions[0]['Role']=='reference_upstream' and definitions[0]['NmType']=='T','Exact upstream inline-ASM helper owner')
                owners[n]=definitions
            save(directory/'upstream-owners.json',owners)
            undefined=self.command([self.tools['nm'],'-u',objects[-1]],'actual upstream object undefined boundaries')['Stdout']
            (directory/'upstream-undefined.txt').write_text(undefined,encoding='ascii')
            if archive:
                lib=directory/'libactual-upstream.a'
                self.command([self.tools['ar'],'rcs',lib,objects[-1]],'archive only actual upstream reference')
                self.command([self.tools['ar'],'t',lib],'record actual reference archive members')
                linked=objects[:-1]+[lib]
            else: linked=objects
            elf=directory/'reference.elf'
            self.command([self.tools['gcc'],*pilot.CPU,'-'+opt,*(['-flto'] if lto else []),'-nostdlib','-Wl,--gc-sections,--no-undefined,--fatal-warnings,-z,noexecstack','-Wl,-Map='+str(directory/'reference.map'),'-T',REF/'link.ld',*linked,'-o',elf],'actual final link-only pinned reference')
            self.dump(elf)
            image=fp.Image(elf,self.ELFFile)
            attrs=elf.with_suffix('.readelf.txt').read_text()
            need(fp.capability_matches(fp.CM4,attrs,pilot.CPU),'Reference exact M4 hard FP capability')
            words=struct.unpack('<256I',image.sections['.isr_vector']['Data'])
            need(image.sections['.isr_vector']['Address']==0 and words[0]==0x20010000 and words[1]==image.symbol('reference_reset_handler','STT_FUNC')['Address'],'Reference reset/vector geometry')
            for index,n in ((11,REF_HANDLERS[0]),(14,REF_HANDLERS[1]),(15,REF_HANDLERS[2])):
                need(words[index]==image.symbol(n,'STT_FUNC')['Address'] and words[index]&1,'Actual strong upstream Thumb handler vector')
            roots=[image.symbol(n,'STT_FUNC',local=lto and bool(owners[n]))['Address'] for n in (*REF_ROOTS,*REF_ASM_HELPERS)]
            section=image.sections['.reference_roots']
            need(not section['Flags']&1 and section['Data']==struct.pack('<5I',*roots),'Exact readonly actual upstream C and inline-ASM helper roots')
            facts=image.sections['.reference_contract']
            values=struct.unpack('<12I',facts['Data'])
            need(not facts['Flags']&1 and values[:11]==(1,4,4,4,8,4,1,128,8,0,0) and values[11]>76,'Actual reference header facts, wrappers v2, no M7 errata')
            tcb=image.symbol('pxCurrentTCB','STT_OBJECT',local=lto)
            need(tcb['Size']==4 and image.sections[tcb['Section']]['Type']=='SHT_NOBITS','Opaque zero TCB boundary, not a fake task')
            for n in ('vTaskSwitchContext','xTaskIncrementTick','xTaskGetMPUSettings'):
                closure=image.no_fp_closure([n]);need('reference_fail_stop' in closure,'Reference boundary missing fail-stop')
            need(not any(n.startswith(('fiber_','ctxrt_')) for n in image.symbols),'Reference acquired subject code')
            for n in ('prvRestoreContextOfFirstTask','vSVCHandler_C'):
                image.symbol(n,'STT_FUNC',local=True)
            upstream_object=maps[-1]
            maptext=(directory/'reference.map').read_text()
            need('port.o' in maptext and (not archive or 'libactual-upstream.a(3-port.o)' in maptext),'Actual upstream owner/extraction absent from final map')
            rejection=None
            try:self.audit_reference_targets(image)
            except RuntimeError as e:rejection=str(e)
            need(rejection==REF_REASONS.get(mutant),'Wrong exact reference discriminator: '+repr((name,rejection,REF_REASONS.get(mutant))))
            row=dict(Name=name,Optimization=opt,LTO=lto,Archive=archive,Status='LINKED',Executed=False,Elf=str(elf),ElfSha256=digest(elf),UpstreamOwners=owners,UpstreamObject=upstream_object,RootBindings={n:image.symbol(n,'STT_FUNC',local=lto)['Binding'] for n in REF_ROOTS},HeaderFacts=values,Mutation=mutant,UndefinedFinal=[],ExpectedCodegenRejection=REF_REASONS.get(mutant),ActualCodegenRejection=rejection)
            save(directory/'elf-audit.json',row)
            print('REFERENCE-LINKED '+name,flush=True)
            return row

    def audit_reference_targets(self,image):
            def body(n):return [i for i in image.body(n) if not image.is_data(i,n)]
            def exact(i,mn,op):return i['Mnemonic'].split('.')[0]==mn and compact(i)==op
            first=body('prvRestoreContextOfFirstTask')
            pd=body('xPortPendSVHandler')
            need(sum(exact(i,'msr','psp,r0') for i in first)==1,'REF_FIRST_PSP')
            raw=[j for j,i in enumerate(pd) if exact(i,'mrs','r3,control')]
            fp_save=[j for j,i in enumerate(pd) if i['Mnemonic'].startswith('vstmia') and compact(i)=='r1!,{s16-s31}']
            need(len(raw)==len(fp_save)==1 and raw[0]<fp_save[0],'REF_RAW_CONTROL_BEFORE_FP')
            masks=[j for j,i in enumerate(pd) if exact(i,'msr','basepri,r0')]
            calls=[j for j,i in enumerate(pd) if fp.control_form(i)==('call',image.symbol('vTaskSwitchContext','STT_FUNC')['Address']&~1)]
            need(len(masks)==2 and len(calls)==1 and masks[0]<calls[0]<masks[1] and
                 exact(pd[masks[0]-1],'mov','r0,#128') and exact(pd[masks[1]-1],'mov','r0,#0'),'REF_BASEPRI_SCHEDULER')
            dsb=[j for j,i in enumerate(first) if i['Mnemonic']=='dsb']
            maps=[j for j,i in enumerate(first) if exact(i,'stmia','r0,{r4,r5,r6,r7,r8,r9,r10,r11}')]
            need(dsb and len([j for j in maps if j<dsb[0]])==1,'REF_FIRST_MPU_MAP')

    def pair(self,subject,reference,output,expected=''):
            self.command([self.tools['powershell'],'-NoProfile','-ExecutionPolicy','Bypass','-File',ROOT/'check_mechanisms.ps1','-Source',self.repo/'tools/freertos_asm_parity.ps1','-LedgerPath',self.repo/'FREERTOS_ASM_PARITY.md','-Reference',Path(reference['Elf']).with_suffix('.parity.dis'),'-Subject',Path(subject['Elf']).with_suffix('.parity.dis'),'-Output',output,'-ExpectedFailure',expected],'actual final ELF maintained decoded mechanism association')
            result=json.loads(output.read_text())
            need(result['Status']==('REJECTED' if expected else 'PASS'),'Mechanism result mismatch')
            return result

    def run(self):
            self.preflight()
            self.report['InheritedPilotParserControls']=pilot.terminal_controls()
            self.report['InheritedPilotModelControls']=pilot.model_controls()
            self.report['GridTerminalControls']=basic_terminal_controls()
            need(len(GRID)==16 and len(set(GRID))==16,'Sixteen exact configuration keys')
            for opt,lto in MODES:
                for archive in (False,True): self.references.append(self.build_reference(opt,lto,archive))
            self.report['ModelProbe']=self.build_image('context',model=True)
            for consumer,opt,lto,archive in GRID:
                for case in (0,1,2): self.rows.append(self.build_image(consumer,case,opt,lto,archive))
            for consumer,opt,lto,archive in (('context','O2',False,False),('fiber','Os',True,True)):
                for mutation in EXPECTED:
                    case=1 if mutation=='no-slot-store' else 2 if mutation=='no-peer-load' else 0
                    self.controls.append(self.build_image(consumer,case,opt,lto,archive,mutation))
            references={(r['Optimization'],r['LTO'],r['Archive']):r for r in self.references}
            for row in self.rows:
                ref=references[(row['Optimization'],row['LTO'],row['Archive'])]
                output=Path(row['Elf']).parent/'reference-association.json'
                result=self.pair(row,ref,output)
                self.associations.append(dict(Consumer=row['Consumer'],Case=row['Case'],Optimization=row['Optimization'],LTO=row['LTO'],Archive=row['Archive'],SubjectElf=row['Elf'],SubjectSha256=row['ElfSha256'],ReferenceElf=ref['Elf'],ReferenceSha256=ref['ElfSha256'],MechanismEvidence=str(output),MechanismEvidenceSha256=digest(output),Checks=len(result['Checks']),BlockSha256=result['BlockSha256'],Status='PASS',Executed=False))
            for opt,lto,archive in (('O2',False,False),('Os',True,True)):
                subject=next(r for r in self.rows if (r['Consumer'],r['Case'],r['Optimization'],r['LTO'],r['Archive'])==('context',0,opt,lto,archive))
                for mutation in REF_MUTANTS:
                    ref=self.build_reference(opt,lto,archive,mutation)
                    output=Path(ref['Elf']).parent/'mechanism-negative.json'
                    result=self.pair(subject,ref,output,REF_MUTANTS[mutation][2])
                    self.ref_controls.append({**ref,'Status':'REJECTED','ExpectedFailure':REF_MUTANTS[mutation][2],
                        'MechanismEvidence':str(output),'Failure':result['Failure']})
            need(len(self.rows)==48 and len(self.references)==8 and len(self.associations)==48 and len(self.controls)==32 and len(self.ref_controls)==8,'Literal 48/8/48/32/8 closure')
            expected={(c,case,opt,lto,a) for c,opt,lto,a in GRID for case in (0,1,2)}
            need({(r['Consumer'],r['Case'],r['Optimization'],r['LTO'],r['Archive']) for r in self.rows}==expected,'Exact request-bound production grid')
            need(all(not r['Executed'] for r in self.rows+self.references+self.associations+self.controls+self.ref_controls),'CPU execution forbidden')
            self.report.update(ProductionImages=48,ReferenceELFs=8,AssociationsCount=48,CompiledSubjectControls=32,CompiledReferenceControls=8,
                NewFinalReferenceParity=False,ReferenceQualification=False,BoundedFinalReferenceMechanisms='PASS',
                ReferencePlan=dict(RequiredFinalReferenceELFs=8,ActualReferenceELFsBuilt=8,RequiredAssociations=48,ActualAssociations=48,Commit=PIN,Executed=False,
                 Limits=['Link-only reference; fail-stop kernel boundaries, no reference execution','Imported ordered SVC/first-restore/PendSV mechanisms; no whole-port byte or semantic equivalence','Upstream always-lazy vs subject eager is an intentional divergence','Compile-only codegen is not execution or hardware qualification','No reuse of unadmitted GRO scanners']))
