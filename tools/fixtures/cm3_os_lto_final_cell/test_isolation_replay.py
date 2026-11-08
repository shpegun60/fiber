"""Synthetic isolation corruption groups and sealed real slim-byte parser tests."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
METHODS = 18
BUFFERS, H, REAL = {}, {}, {}
m = fixture = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


class Model:
    """Extend the frozen ABI synthetic journal, never run its driver or tests."""
    def __init__(self):
        self.base = fixture.Model()
        self.__dict__.update(self.base.__dict__)
        self.sources['tools/runtime_sources.json'] = BUFFERS[ROOT / 'tools/runtime_sources.json']
        self.files[self.sr / 'tools/runtime_sources.json'] = self.sources['tools/runtime_sources.json']
        self.tools['Objdump'] = self.capture / 'toolchain/bin/arm-none-eabi-objdump.exe'
        self.files[self.tools['Objdump']] = b'synthetic admitted objdump'
        self.batch.update(IsolationBuilt=True, SourceOwnershipValidated=True, IsolatedCommon=[])
        ownership_sources = {name:self.files[self.sr / name] for name in m.OWNERSHIP}
        self.batch['SourceOwnership'] = H['ownership'].validate_common_sources(ownership_sources)
        self.batch['SourceOwnershipInputs'] = [dict(Source=name,Path=str(self.sr / name),Sha256=sha(raw)) for name,raw in ownership_sources.items()]
        for i,name in enumerate(m.COMMON):
            source=self.sr/name;obj=self.root/'isolated-common'/(source.stem+'.o');first=41+3*i
            flags=H['probes'].isolated_flags(self.native['Sources'][i]['CompileFlags'],self.sr)
            paths=sorted((source,self.external));deps=[dict(Path=str(p),Sha256=sha(self.files[p])) for p in paths]
            before,after=obj.with_suffix('.discovery.d'),obj.with_suffix('.compile.d');target='pilot-source-'+str(i)
            raw=(target+': '+' '.join(map(str,paths))+'\n').encode('ascii');self.files[before]=self.files[after]=raw
            self.command(first,[str(self.tools['Gcc']),*flags,'-M','-MF',str(before),'-MT',target,str(source)])
            self.command(first+1,[str(self.tools['Gcc']),*flags,'-MD','-MF',str(after),'-MT',target,'-c',str(source),'-o',str(obj)])
            self.files[obj]=fixture.elf('isolated-'+str(i));slim=self.base.slim(first+2,obj)
            self.batch['IsolatedCommon'].append(dict(Source=str(source),SourceSha256=sha(self.files[source]),TemplateIndex=i,
                OriginalObject=str(self.objects[i]),OriginalObjectSha256=sha(self.files[self.objects[i]]),
                Object=str(obj),ObjectSha256=sha(self.files[obj]),SlimIR=slim,
                OriginalCompileFlags=list(self.native['Sources'][i]['CompileFlags']),CompileFlags=flags,DiscoveryFlags=list(flags),
                IncludeDelta=dict(RemovedForcedHeader=str(self.sr/'tools/fixtures/classic_final_image/main.h'),
                    ReplacementSearchPaths=[str(self.sr/p) for p in ('context','fiber')]+[str(self.sr)],OtherSemanticFlagsUnchanged=True),
                DiscoveryDependencies=deps,Dependencies=copy.deepcopy(deps),CompileDependenciesVerified=True,
                DiscoveryDependencyFile=str(before),CompileDependencyFile=str(after),CommandIndices=[first,first+1,first+2],
                ForcedMainHeaderRemoved=True,CmsisAndSelectedPortIncludesRemoved=True,RawIRIdentityClaim=False,
                IRImportClosureValidated=False,SourceToMachineSemanticProof=False))
        selected=[Path(r['Object']) for r in self.batch['IsolatedCommon']]+self.objects[3:]
        self.base.link(50,'isolated-common',selected);self.base.link(51,'isolated-common-emit',selected)
        self.batch['Commands'][51]['Argv'].append('-Wl,--emit-relocs')
        self.fixed=m._paths(self.root,self.sr,self.capture)
        for kind in ('Original','Isolated'):
            self.files[self.fixed[kind+'Machine']]=fixture.elf('slot-machine',True)
            self.files[self.fixed[kind+'Assembly']]=b'synthetic generated assembly'
            self.files[self.fixed[kind+'Map']]=b'synthetic map/'+kind.encode()
            self.files[self.fixed[kind+'Disassembly']]=b'synthetic producer disassembly r10 r11\n'
        self.command(52,[str(self.tools['Objdump']),'-drwC','-z',str(self.fixed['IsolatedEmitELF'])],stdout=self.files[self.fixed['IsolatedDisassembly']])
        self.original_dumps={name:(self.root.parent/'normal'/('original-'+name.lower()+'.dis'),raw)
            for name,raw in (('Final',b'synthetic fresh original disassembly sl fp\n'),('Machine',b'synthetic original machine disassembly\n'))}
        for path,raw in self.original_dumps.values():self.files[path]=raw
        self.batch['IsolatedLinkedObjects']=[dict(Index=i,Path=str(p),Sha256=sha(self.files[p]),OriginalUnchanged=i>=3) for i,p in enumerate(selected)]
        self.batch['IsolatedLinkMap']=str(self.fixed['IsolatedOrdinaryMap']);self.batch['EmitLinkDelta']=['-Wl,--emit-relocs']
        self.batch['IsolationBuild']=dict(Status='BUILT-PENDING-READER',Scope='NATIVE_CM3_OS_LTO_ISOLATION_BUILD_ONLY_PENDING_READER',
            Profile='CM3',Mode='Os-lto',Linkage='direct',LTO=True,First=41,Stop=53,Commands=12,IsolatedCommonObjects=3,
            OriginalObjectsUnchanged=6,DeferredReaderRequired=True,CpuFreeCommonValidated=False,WholeSlotAccessIsolation=False,
            PositiveLinkRevalidated=False,RawIRIdentityClaim=False,Qualification=False,CellContractSatisfied=False,
            RequiredCellSatisfied=False,RequiredCellsSatisfied=0,FullABIProof=False,FullSemanticABIProof=False,
            SourceToMachineSemanticProof=False,CpuExecution=False,BoardExecution=False,GlobalFreezeQualified=False)
        self.refresh()
        self.image_calls=[];self.comparison_calls=[]
        self.core=types.SimpleNamespace(compare_load_images=self.compare,FinalImage=self.final_image)
        self.fake_os=types.SimpleNamespace(inspect=self.slot_inspect,require_result=H['os_slot'].require_result)

    def __getattr__(self,name):
        return getattr(self.base,name)

    def refresh(self):
        suite=types.SimpleNamespace(result=self.native,objects=self.objects,source=lambda i:self.native['Sources'][i],
            api=types.SimpleNamespace(checked_path=Path),watch=types.SimpleNamespace(read=lambda p:self.files[Path(p)]))
        self.batch['IsolationDeferredReader']=H['producer']._deferred(suite,self.fixed['IsolatedOrdinaryELF'],self.fixed['IsolatedOrdinaryMap'],
            self.fixed['IsolatedEmitELF'],self.fixed['IsolatedMap'],self.fixed['IsolatedDisassembly'],self.batch['IsolatedCommon'])
        self.files[self.root/'isolation-build.json']=encoded(dict(Build=self.batch['IsolationBuild'],
            IsolatedCommon=self.batch['IsolatedCommon'],SourceOwnership=self.batch['SourceOwnership'],
            DeferredReader=self.batch['IsolationDeferredReader'],Objects=self.batch['IsolatedLinkedObjects']))
        self.seal()

    def compare(self,left,right):
        self.comparison_calls.append((left,right))
        allowed=[(self.fixed[a],self.fixed[b]) for _,a,b in m.COMPARISONS]
        if (left,right) not in allowed or self.files[left]!=self.files[right]:raise ValueError('unequal or foreign load images')
        return copy.deepcopy(self.comparison)

    def final_image(self,machine,final,disassembly,*,provider_objects,link_map,float_abi):
        self.image_calls.append((machine,final,disassembly))
        providers={str(p).replace('\\','/').casefold():types.SimpleNamespace(data=self.files[p],final=False) for p in provider_objects.values()}
        return types.SimpleNamespace(prelink=types.SimpleNamespace(data=self.files[machine],final=False),
            final=types.SimpleNamespace(data=self.files[final],final=True),providers=providers,link_map_hash=sha(self.files[link_map]),
            hashes=dict(PrelinkSha256=sha(self.files[machine]),FinalSha256=sha(self.files[final]),DisassemblySha256=sha(self.files[disassembly])),
            kind='Original' if machine==self.fixed['OriginalMachine'] else 'Isolated')

    def slot_inspect(self,image,core,neutral,*,port_source,assembly,emit_relocs):
        kind=image.kind;module=H['os_slot'];provider=str(self.fixed[kind+'Machine']).replace('\\','/').casefold()
        def ref(owner,number=0,slot=True):
            symbol=dict(name='synthetic',value=0,size=4,kind='STT_OBJECT',binding='STB_LOCAL',section=1,visibility='STV_DEFAULT',index=1)
            return dict(Owner=owner,Kind=2 if slot else 10,Target=module.SLOT if slot else 'fiber_panic',
                FunctionOffset=number*4,InputSectionIndex=1,InputOffset=number*4,Address=0x100+number*4,
                OriginalBytes='00000000',FinalBytes='00000000',OriginalRelocationSymbol=symbol,FinalRelocationSymbol=dict(symbol))
        bodies=[dict(Name=name,Origin=dict(Name=name,Provider=provider),MachineBodySha256=sha(b'synthetic machine body'),
            FinalBodySha256=sha(b'synthetic final body'),CompleteBodyValidated=True,Size=size,
            References=[ref(name,n,n==0) for n in range(module.REFERENCE_COUNTS[name])],TailNops=0) for name,size in module.SIZES.items()]
        handlers=[]
        for name,register in (('SVC_Handler','r0'),('PendSV_Handler','r1')):
            row=ref(name);row.update(Register=register,MachineLiteralLoads=1,FinalLiteralLoads=1,SlotBearingWordsCensused=8,
                LoadOffset=0,DereferenceOffset=2,BothInstructionStreamsCensused=True,UnsupportedPCAddressFormsRejected=True,CrossOwnerSlotLiteralUsesRejected=True)
            handlers.append(row)
        proof=dict(Status=module.STATUS,Scope=module.SCOPE,Profile='CM3',Mode='Os-lto',Linkage='direct',EmitRelocs=True,
            SlotIsolationValidated=True,SlotOrigin=dict(Name=module.SLOT,Provider=provider,Size=4,SectionSize=4,SymbolOffset=0),SlotAlias='.LANCHOR0',
            SourceSha256=sha(port_source),AssemblySha256=sha(assembly),MachineSha256=sha(image.prelink.data),FinalSha256=sha(image.final.data),
            LinkMapSha256=image.link_map_hash,HandlerLoadPairs=2,HandlerLoads=handlers,
            SourcePairs=[dict(Register=r,SourceLine=i+1) for i,r in enumerate(('r0','r1'))],
            GeneratedPairs=[dict(Owner=n,Register='r'+str(i),GeneratedLine=i+1) for i,n in enumerate(module.HANDLERS)],
            ClosedCommonBodies=6,CommonBodies=bodies,CommonBytes=272,CommonLoads=5,CommonStores=1,Publisher=module.PUBLISHER,
            SlotReferences=8,AppliedSlotReferences=8,RawSectionSymbolsPreserved=True,AllSectionMediatedSlotReferencesValidated=True,RequiredCellsSatisfied=0)
        proof.update(dict.fromkeys(module.FALSE_FIELDS,False));return proof

    def run(self,**changes):
        helpers={k:H[k] for k in m.HELPERS if k not in ('controls_replay','isolation_slots','os_slot','neutral_slot')}
        helpers.update(controls_replay=H['controls'],isolation_slots=H['slots'],os_slot=self.fake_os,neutral_slot=H['neutral_slot'])
        args=dict(batch=self.batch,native=self.native,root=self.root,core=self.core,helpers=helpers,read=self.read,original_dumps=self.original_dumps)
        args.update(changes);return m.inspect(**args)


class IsolationTests(unittest.TestCase):
    def test_complete_twelve_and_shared_join_schema(self):
        model=Model();proof=model.run();self.assertIs(m.require_result(proof),proof)
        self.assertEqual([r['Index'] for r in proof['CommandBindings']],list(range(41,53)))
        self.assertEqual((proof['CommandsReplayed'],proof['DependencyFiles'],proof['SlimIRInspections'],proof['SlotImages']),(12,6,3,2))
        self.assertEqual(set(proof['Inputs']),set(m.ROLE_NAMES));self.assertEqual(len(model.comparison_calls),3)
        self.assertEqual(model.image_calls[0][2],model.original_dumps['Final'][0]);self.assertEqual(len(model.image_calls),2)
        self.assertEqual(proof['OriginalDumps']['Final']['Sha256'],sha(model.original_dumps['Final'][1]))
        self.assertNotEqual(proof['OriginalDumps']['Final']['Sha256'],proof['Inputs']['OriginalDisassembly']['Sha256'])
        self.assertEqual(proof['CommandBindings'][10]['Argv'][-3:],['-o',proof['Inputs']['IsolatedEmitELF']['Path'],'-Wl,--emit-relocs'])
        for key in m.NONCLAIMS:self.assertIs(proof[key],False)

    def test_exact_helpers_native_and_pending_identity(self):
        for defect in ('helper','native','mode','built','seed'):
            model=Model()
            if defect=='helper':
                with self.assertRaises(m.Rejected):model.run(helpers={})
                continue
            if defect=='native':model.native['Unexpected']=True
            elif defect=='mode':model.batch['Mode']='O2-lto'
            elif defect=='built':model.batch['IsolationBuilt']=False
            else:model.batch['SourceSeed']='C:/foreign/source-seed'
            with self.subTest(defect=defect),self.assertRaises(ValueError):model.run()

    def test_all_per_command_copies_and_aggregate_are_bound(self):
        for index in range(41,53):
            model=Model();path=model.root/('commands/%03d.json'%index);row=json.loads(model.files[path]);row['Argv'][0]='C:/foreign/gcc.exe'
            model.files[path]=encoded(row);model.catalog()
            with self.subTest(index=index),self.assertRaises(ValueError):model.run()
        model=Model();model.files[model.root/'commands.json']=encoded([]);model.catalog()
        with self.assertRaises(ValueError):model.run()

    def test_both_copies_foreign_source_compiler_flags_and_outputs(self):
        for index in range(41,53):
            for defect in ('tool','operand'):
                model=Model();argv=model.batch['Commands'][index]['Argv']
                argv[0 if defect=='tool' else -1]='C:/foreign/input.o';model.seal()
                with self.subTest(index=index,defect=defect),self.assertRaises(ValueError):model.run()
        for flag in ('-O2','-ffat-lto-objects','-include','--specs=C:/foreign.specs'):
            model=Model();model.batch['Commands'][42]['Argv'].insert(1,flag);model.seal()
            with self.subTest(flag=flag),self.assertRaises(ValueError):model.run()

    def test_terminal_types_and_clean_streams_all_twelve(self):
        for index in range(41,53):
            for key,value in (('Exit',False),('ExpectedExit',False),('State','RUNNING'),('Status','FAIL'),('TimedOut',0),('Seconds',True),('JournalErrors',['bad'])):
                model=Model();model.batch['Commands'][index][key]=value;model.seal()
                with self.subTest(index=index,key=key),self.assertRaises(ValueError):model.run()
            model=Model();model.change_stream(index,stderr=b'foreign diagnostic')
            with self.subTest(index=index,stream='stderr'),self.assertRaises(ValueError):model.run()
            model=Model();model.change_stream(index,stdout=b'' if index in (43,46,49,52) else b'foreign output')
            with self.subTest(index=index,stream='stdout'),self.assertRaises(ValueError):model.run()

    def test_source_ownership_paths_bytes_and_stored_proofs(self):
        for name in m.OWNERSHIP:
            model=Model();path=model.sr/name;model.files[path]+=b'\nvoid foreign(void) {}\n';model.catalog()
            with self.subTest(source=name),self.assertRaises(ValueError):model.run()
        for defect in ('hash','path','extra','empty'):
            model=Model()
            if defect=='hash':model.batch['SourceOwnershipInputs'][0]['Sha256']='F'*64
            elif defect=='path':model.batch['SourceOwnershipInputs'][0]['Path']='C:/foreign/core.c'
            elif defect=='extra':model.batch['SourceOwnership']['Qualification']=True
            else:model.batch['SourceOwnership']={}
            with self.subTest(defect=defect),self.assertRaises(ValueError):model.run()

    def test_dependency_authority_and_six_raw_files(self):
        for i in range(3):
            for defect in ('target','foreign','cmsis','port','main','missing','bytes'):
                model=Model();row=model.batch['IsolatedCommon'][i];path=Path(row['CompileDependencyFile'])
                if defect=='target':model.files[path]=model.files[path].replace(('pilot-source-'+str(i)).encode(),b'foreign-target')
                elif defect=='missing':del model.files[path]
                elif defect=='bytes':model.files[model.external]+=b'wrong'
                else:
                    p={'foreign':model.root/'other-stage/file.h','cmsis':model.seed/'cmsis/core_cm3.h',
                        'port':model.sr/'fiber/port/ARM_CM3/foreign.h','main':model.sr/'tools/fixtures/classic_final_image/main.h'}[defect]
                    model.files.setdefault(p,b'foreign header');raw=('pilot-source-'+str(i)+': '+str(model.sr/m.COMMON[i])+' '+str(p)+'\n').encode()
                    model.files[path]=model.files[Path(row['DiscoveryDependencyFile'])]=raw
                model.catalog()
                with self.subTest(index=i,defect=defect),self.assertRaises(ValueError):model.run()
        model=Model();model.native['Sources'][0]['ActualCompileDependencies']=[];model.seal_native(False);model.catalog()
        with self.assertRaises(ValueError):model.run()

    def test_full_section_metadata_and_executable_fallback(self):
        for index in (43,46,49):
            for field,value in ((7,b'10'),(9,b'1'),(10,b'1'),(11,b'4')):
                model=Model();lines=model.streams[index][0].splitlines();row=lines[6].split();row[field]=value;lines[6]=b' '.join(row)
                model.change_stream(index,stdout=b'\n'.join(lines)+b'\n')
                with self.subTest(index=index,field=field),self.assertRaises(ValueError):model.run()
        model=Model();path=Path(model.batch['IsolatedCommon'][0]['Object']);model.files[path]=fixture.elf('fallback',True)
        model.change_stream(43,stdout=fixture.readelf_text(model.files[path]))
        with self.assertRaisesRegex(ValueError,'executable fallback'):model.run()

    def test_replacement_and_link_order_emit_position(self):
        for defect in ('objects','links','emit-before','extra-output','output-object'):
            model=Model()
            if defect=='objects':model.batch['IsolatedLinkedObjects'].reverse()
            elif defect=='links':
                argv=model.batch['Commands'][50]['Argv'];a=argv.index(str(model.objects[3]));argv[a],argv[a+1]=argv[a+1],argv[a]
            elif defect=='emit-before':
                argv=model.batch['Commands'][51]['Argv'];argv.insert(argv.index('-o'),argv.pop())
            elif defect=='extra-output':model.batch['Commands'][51]['Argv']+=['-o','C:/foreign/image.elf']
            else:model.batch['Commands'][50]['Argv'][-1]=str(model.objects[3])
            model.seal()
            with self.subTest(defect=defect),self.assertRaises(ValueError):model.run()

    def test_eighteen_fixed_deferred_roles_and_pending_claims(self):
        for name in m.ROLE_NAMES:
            for defect in ('path','hash','role'):
                model=Model();row=next(r for r in model.batch['IsolationDeferredReader']['Inputs'] if r['Role']==name)
                row[{'path':'Path','hash':'Sha256','role':'Role'}[defect]]='F'*64 if defect=='hash' else 'C:/foreign/object.o' if defect=='path' else 'ForeignRole'
                with self.subTest(role=name,defect=defect),self.assertRaises(ValueError):model.run()
        for field in ('IRImportClosureValidated','WholeSlotAccessIsolation','PositiveLinkRevalidated','RawIRIdentityClaim'):
            model=Model();model.batch['IsolationDeferredReader'][field]=True
            with self.subTest(field=field),self.assertRaises(ValueError):model.run()

    def test_compilation_and_build_receipts_are_comparison_only(self):
        for i in range(3):
            for key,value in (('Source','C:/foreign/core.c'),('ObjectSha256','F'*64),('IRImportClosureValidated',True),('CommandIndices',[41,42])):
                model=Model();model.batch['IsolatedCommon'][i][key]=value
                with self.subTest(index=i,key=key),self.assertRaises(ValueError):model.run()
        model=Model();path=model.root/'isolation-build.json';row=json.loads(model.files[path]);row['Build']['Qualification']=True
        model.files[path]=encoded(row);model.catalog()
        with self.assertRaises(ValueError):model.run()

    def test_three_load_comparisons_and_forged_results(self):
        for name,left,right in m.COMPARISONS:
            model=Model();original=model.compare
            def compare(a,b,selected=(model.fixed[left],model.fixed[right])):
                result=original(a,b)
                if (a,b)==selected:result['Identical']=False
                return result
            with self.subTest(name=name),self.assertRaises(ValueError):model.run(core=types.SimpleNamespace(compare_load_images=compare,FinalImage=model.final_image))
        for field,value in (('Entry',True),('ForeignClaim',False)):
            model=Model();model.comparison[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):model.run()

    def test_fresh_dumps_read_roles_content_and_alias_difference(self):
        for name in ('Final','Machine'):
            for defect in ('missing','bytes','pair'):
                model=Model();dumps=dict(model.original_dumps);path,raw=dumps[name]
                if defect=='missing':del model.files[path]
                elif defect=='bytes':model.files[path]+=b'drift'
                else:dumps[name]=[path,raw]
                with self.subTest(role=name,defect=defect),self.assertRaises((ValueError,AssertionError)):model.run(original_dumps=dumps)
        model=Model()
        for path,_ in model.original_dumps.values():model.batch['InputHashes'].pop(str(path))
        proof=model.run();self.assertEqual({Path(r['Path']) for r in proof['OriginalDumps'].values()},
            {Path(r['Path']) for r in proof['ReadInputs']} & {p for p,_ in model.original_dumps.values()})

    def test_reader_must_supply_exact_admitted_bytes(self):
        for role in ('PortSource','IsolatedIR1','IsolatedMachine','OriginalAssembly'):
            model=Model();path=model.fixed[role]
            def read(p,h):
                raw=model.read(p,h);return raw+b'wrong' if p==path else raw
            with self.subTest(role=role),self.assertRaises(ValueError):model.run(read=read)

    def test_closed_result_counts_scopes_and_nested_bindings(self):
        baseline=Model().run()
        for key in (*m.NONCLAIMS,*m.FACTS,*m.COUNTS):
            proof=copy.deepcopy(baseline);proof[key]=True if key in m.NONCLAIMS or key in m.COUNTS else 1
            with self.subTest(key=key),self.assertRaises(ValueError):m.require_result(proof)
        for defect in ('read','slot-extra','slot-input','source-extra','common-extra','section-extra','dump','link'):
            proof=copy.deepcopy(baseline)
            if defect=='read':proof['ReadInputs'].pop();proof['ReadFiles']-=1
            elif defect=='slot-extra':proof['SlotProofs']['FullInstructionSemantics']=False
            elif defect=='slot-input':proof['SlotProofs']['Inputs']['PortSource']['Sha256']='F'*64
            elif defect=='source-extra':proof['SourceOwnership']['Qualified']=False
            elif defect=='common-extra':proof['IsolatedCommon'][0]['ForeignClaim']=False
            elif defect=='section-extra':proof['IsolatedCommon'][0]['SlimIR']['Sections'][0]['ForeignClaim']=False
            elif defect=='dump':proof['OriginalDumps']['Machine']['Sha256']='F'*64
            else:proof['CommandBindings'][10]['Argv'].pop()
            with self.subTest(defect=defect),self.assertRaises(ValueError):m.require_result(proof)

    def test_no_filesystem_process_loading_or_input_alias_mutation(self):
        model=Model();before=encoded(model.batch);native=encoded(model.native)
        def denied(*args,**kwargs):raise AssertionError('forbidden physical operation')
        with patch.object(Path,'exists',denied),patch.object(Path,'stat',denied),patch.object(Path,'open',denied),patch.object(Path,'resolve',denied),\
                patch('subprocess.run',denied),patch('subprocess.Popen',denied),patch('importlib.util.spec_from_file_location',denied):
            proof=model.run()
        self.assertEqual(encoded(model.batch),before);self.assertEqual(encoded(model.native),native)
        proof['IsolatedCommon'][0]['CompileFlags'].clear();proof['SlotProofs']['Inputs'].clear()
        self.assertTrue(model.batch['IsolatedCommon'][0]['CompileFlags'])

    def test_real_saved_slim_byte_parser_positive(self):
        for index in (43,46,49):
            raw,text,claim=REAL[index];header=H['transport'].require_elf32le(raw)
            H['controls']._readelf_metadata(text.decode('ascii'),raw,header)
            rows=H['transport'].section_records(text.decode('ascii'))
            self.assertEqual(rows,H['controls']._binary_sections(raw,header));self.assertEqual(rows,claim['Sections'])
            self.assertEqual(sha(raw),claim['Sha256'])

    def test_real_saved_slim_byte_parser_negative_columns(self):
        for index in (43,46,49):
            raw,text,_=REAL[index];header=H['transport'].require_elf32le(raw)
            lines=text.decode('ascii').splitlines();position=next(i for i,line in enumerate(lines) if '.text ' in line)
            for field in (7,9,10,11):
                bad=list(lines);tokens=bad[position].split();tokens[field]=str(int(tokens[field],16 if field==7 else 10)+1)
                bad[position]=' '.join(tokens)
                with self.subTest(index=index,field=field),self.assertRaises(ValueError):H['controls']._readelf_metadata('\n'.join(bad),raw,header)


def main():
    global BUFFERS,H,REAL,m,fixture
    parser=argparse.ArgumentParser(description=__doc__,allow_abbrev=False);parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args();output=args.output_dir.absolute();temporary=Path(tempfile.gettempdir()).absolute()
    if output.exists() or output.is_relative_to(ROOT) or not output.is_relative_to(temporary):parser.error('fresh external TEMP output required')
    paths=dict(fixture=HERE/'test_abi_controls_replay.py',controls=HERE/'abi_controls_replay.py',leaf=HERE/'isolation_replay.py',
        deps=HERE/'dependency_bytes.py',recipes=HERE/'batch_recipes.py',declarations=HERE/'declarations.py',ordinary=HERE.parent/'ordinary_final_cell/abi.py',
        plan=HERE.parent/'ordinary_final_cell/controls.py',diagnostics=HERE.parent/'cm3_lto_abi_controls/diagnostics.py',
        probes=HERE.parent/'cm0_final_cell/components.py',port_runner=HERE.parent/'cm3_lto_port_policy/runner.py',guard=HERE/'batch_guard.py',
        transport=HERE.parent/'cm3_lto_transport/probe.py',oracle=HERE.parent/'cm0_final_cell/abi.py',
        ownership=HERE.parent/'cm0_final_cell/ownership.py',producer=HERE/'isolation.py',os_slot=HERE/'slot.py',
        neutral_slot=HERE.parent/'cm3_lto_isolation/slot.py',slots=HERE/'isolation_slots.py')
    fixture_raw=paths['fixture'].read_bytes();fixture=types.ModuleType('_isolation_test_fixture');fixture.__file__=str(paths['fixture'])
    exec(compile(fixture_raw,str(paths['fixture']),'exec'),fixture.__dict__)
    project=fixture.HEADERS+fixture.ORDER+fixture.EXTRA+('tools/runtime_sources.json',)
    sources=[Path(__file__).resolve(),*paths.values(),*(ROOT/name for name in project)]
    actual=Path('C:/fzosbatch-20261107-e1');actual_receipt=actual/'results.json';actual_manifest=actual/'artifacts.json'
    batch_raw=actual_receipt.read_bytes();manifest_raw=actual_manifest.read_bytes()
    if sha(batch_raw)!='3DCE7C453AF909B6B917B9A3EED552F1725D70ED9420CEA74A36797ADB12EEC7' or sha(manifest_raw)!='35E2A0B0895AD8458F8476C8E6F672176E39687B69137804E3342DDC663BD635':raise ValueError('sealed real parser fixture drift')
    batch=json.loads(batch_raw);manifest=json.loads(manifest_raw)['Artifacts'];sources.extend((actual_receipt,actual_manifest))
    actual_paths={}
    for index,row in zip((43,46,49),batch['IsolatedCommon']):
        obj=Path(row['Object']);stdout=actual/('commands/%03d.stdout'%index);journal=actual/('commands/%03d.json'%index)
        actual_paths[index]=(obj,stdout,row['SlimIR']);sources.extend((obj,stdout,journal))
    need_unique=list(dict.fromkeys(sources));BUFFERS={path:path.read_bytes() for path in need_unique};opening={str(p):sha(raw) for p,raw in BUFFERS.items()}
    if BUFFERS[paths['fixture']]!=fixture_raw or BUFFERS[actual_receipt]!=batch_raw or BUFFERS[actual_manifest]!=manifest_raw:raise ValueError('opening source drift')
    for name,path in paths.items():
        if name in ('fixture','oracle'):continue
        module=types.ModuleType('_isolation_test_'+name);module.__file__=str(path)
        def buffered_read(p):
            if p not in BUFFERS:raise AssertionError('unenrolled bootstrap source/'+str(p))
            return BUFFERS[p]
        with patch.object(Path,'read_bytes',buffered_read):exec(compile(BUFFERS[path],str(path),'exec'),module.__dict__)
        if name=='leaf':m=module
        else:H[name]=module
    fixture.BUFFERS=BUFFERS;fixture.m=H['controls'];fixture.H={k:H[k] for k in ('deps','recipes','declarations','ordinary','plan','diagnostics','probes','port_runner','guard','transport')}
    for index,(obj,stdout,claim) in actual_paths.items():
        for path in (obj,stdout,actual/('commands/%03d.json'%index)):
            if sha(BUFFERS[path])!=manifest[path.relative_to(actual).as_posix()]:raise ValueError('manifest-bound raw parser fixture')
        if sha(BUFFERS[obj])!=claim['Sha256'] or sha(BUFFERS[stdout])!=batch['Commands'][index]['StdoutSha256']:raise ValueError('raw parser fixture role hash')
        REAL[index]=(BUFFERS[obj],BUFFERS[stdout],claim)
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(IsolationTests))
    closing={str(p):sha(p.read_bytes()) for p in need_unique}
    report=dict(Status='PASS' if result.wasSuccessful() and result.testsRun==METHODS and not result.skipped and opening==closing else 'FAIL',
        Tests=result.testsRun,ExpectedTests=METHODS,Errors=len(result.errors),Failures=len(result.failures),Skipped=len(result.skipped),
        SourceHashes=opening,SourceDrift=opening!=closing,ClosingFilesVerified=sum(opening[k]==h for k,h in closing.items()),
        SyntheticReplayOnly=True,RealSlimParserFixtures=3,ActualFullReplayPerformed=False,CompilerExecuted=False,BoardExecution=False,
        Qualification=False,RequiredCellsSatisfied=0)
    output.mkdir(parents=True);(output/'results.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n',encoding='ascii')
    print(json.dumps({k:v for k,v in report.items() if k!='SourceHashes'},sort_keys=True));return 0 if report['Status']=='PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
