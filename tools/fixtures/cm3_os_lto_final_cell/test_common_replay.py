"""Synthetic corruption groups for the pure forty-five-command common binder."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
METHODS = 24
BUFFERS, H, REAL = {}, {}, {}
m = fixture = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


class Adapter:
    """Only exercise the component boundary; machine predicates have own tests."""
    def __init__(self): self.calls = []

    def inspect(self, core, read, lowerings, native, helpers):
        if set(helpers) != {'attributes', 'attribute_runner', 'common_workers', 'common_effects', 'transport'}:
            raise ValueError('adapter helper boundary')
        self.calls.append(copy.deepcopy(lowerings))
        rows = {}
        for lower in lowerings:
            for row in list(lower['Roles'].values()) + lower['Inputs']: rows[row['Path']] = row['Sha256']
        workers = {name: native['ResolvedWorkers'][name] for name in ('lto1', 'as')}
        for row in workers.values(): rows[row['Path']] = row['Sha256']
        inputs = [dict(Path=path, Sha256=digest, Bytes=len(read(Path(path), digest))) for path, digest in sorted(rows.items(), key=lambda r: Path(r[0]))]
        return dict(Status='CM3-OS-LTO-COMMON-LOWERED-PENDING-ATTRIBUTION',
            Scope='CM3_OS_LTO_SIX_COMMON_LOWERED_COHORTS_ONLY', Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True, Lowerings=copy.deepcopy(lowerings),
            ResolvedWorkers=copy.deepcopy(workers),
            CommonAttributionClosed=False, UnresolvedAttribution=[dict(Synthetic=True)], ReadInputs=inputs,
            WorkerChains=[dict(Group=g,Proof={}) for g in m.GROUPS],
            CommonMachines=[dict(Group=g,Machines=[dict(Role=r,Proof={},OriginalProtectedPredicateRejected=m.MUTATIONS[i] is not None)
                for r in ('Object','Machine')]) for i,g in enumerate(m.GROUPS)],
            **m.LOWERED_COUNTS, **dict.fromkeys(m.LOWERED_NONCLAIMS,False), **dict.fromkeys(m.LOWERED_FACTS,True))

    def require_result(self, proof, helpers):
        if proof['ReadFiles'] != 89: raise ValueError('adapter read count')
        return proof


class Model:
    def __init__(self):
        self.base = fixture.Model();self.__dict__.update(self.base.__dict__)
        extra = ('context/context_api_decl.h', 'context/context_runtime_state.h', 'context/context_panic.h', 'tools/runtime_sources.json')
        for name in extra:
            self.sources[name] = BUFFERS[ROOT / name];self.files[self.sr / name] = self.sources[name]
        names = set(m.OWNERSHIP) | {n for n in self.sources if n.startswith('context/')} | {'fiber/fiber_api_attributes.h'}
        names = sorted(names);self.buffers = {name: self.files[self.sr / name] for name in names}
        for i in range(3):
            self.native['Sources'][i]['ActualCompileDependencies'] = [dict(Path=str(p), Sha256=sha(self.files[p]))
                for p in sorted([self.sr / n for n in names] + [self.external])]
        self.tools['Objdump'] = self.capture / 'toolchain/bin/arm-none-eabi-objdump.exe'
        self.files[self.tools['Objdump']] = b'synthetic objdump'
        self.native['ResolvedWorkers'] = {}
        for name in ('lto1', 'as'):
            path = self.capture / 'toolchain/workers' / (name + '.exe');self.files[path] = ('worker/' + name).encode()
            self.native['ResolvedWorkers'][name] = dict(Path=str(path), Sha256=sha(self.files[path]))
        self.batch.update(CommonAttributesBuilt=True, SourceOwnershipValidated=True)
        self.batch['SourceOwnership'] = H['ownership'].validate_common_sources({n: self.buffers[n] for n in m.OWNERSHIP})
        self.batch['SourceOwnershipInputs'] = [dict(Source=n, Path=str(self.sr / n), Sha256=sha(self.buffers[n])) for n in m.OWNERSHIP]
        specs_raw = b'*link:\n%{fprofile-arcs|fcondition-coverage|fprofile-generate*|coverage:-lgcov}\n'
        self.command(53, [str(self.tools['Gcc']), '-dumpspecs'], stdout=specs_raw)
        self.original_specs = self.root / 'attributes/driver/original.specs';self.specs = self.root / 'attributes/driver/no-auto-gcov.specs'
        self.files[self.original_specs] = specs_raw;adapt = H['attributes'].adapt_specs(specs_raw)
        self.files[self.specs] = adapt['Specs'];adapter = {k:v for k,v in adapt.items() if k != 'Specs'}
        adapter.update(OriginalPath=str(self.original_specs), AdaptedPath=str(self.specs))
        self.trees = {'positive': (self.sr, self.buffers)};controls = []
        self.positive = [self.root / 'attributes/ir/positive' / (Path(n).stem + '.o') for n in m.COMMON]
        for i, role in enumerate(m.ROLES):
            group = 'mutant-' + role;change = H['attributes'].annotation_mutant(role, self.buffers)
            self.trees[group] = (self.root / 'private' / ('attributes-' + group), change['Sources'])
            controls.append(dict(Role=role, Function=change['Function'], Edits=change['Edits'], ReplacedIRRole=role,
                UnchangedIR=[str(p) for j,p in enumerate(self.positive) if j != i], Detected=False, OriginalProtectedPredicateRejected=False))
        stress = H['attributes'].stress_sources()
        for group,key in zip(m.GROUPS[4:], ('Protected', 'Unprotected')):
            self.trees[group] = (self.root / 'private' / ('attributes-' + group), dict(self.buffers, **{'stress.c': stress[key]}))
        for project, buffers in self.trees.values():
            for name,raw in buffers.items(): self.files[project / name] = raw
        compiled = []
        suite = types.SimpleNamespace(base=self.seed, result=self.native, source=lambda i:self.native['Sources'][i])
        for group,index,first in m.BUILDS:
            project,buffers = self.trees[group];is_stress = group.startswith('stress-')
            relative = 'stress.c' if is_stress else m.COMMON[index];source = project / relative
            obj = self.root / 'attributes/ir' / group / (source.stem + '.o')
            flags = H['attributes_phase'].flags_for(suite,index,project,H)
            before,after = obj.with_suffix('.discovery.d'),obj.with_suffix('.compile.d');target = 'pilot-source-' + str(index)
            paths = sorted((source,self.external));deps = [dict(Path=str(p),Sha256=sha(self.files[p])) for p in paths]
            raw = (target + ': ' + ' '.join(map(str,paths)) + '\n').encode();self.files[before] = self.files[after] = raw
            self.command(first,[str(self.tools['Gcc']),*flags,'-M','-MF',str(before),'-MT',target,str(source)])
            self.command(first+1,[str(self.tools['Gcc']),*flags,'-MD','-MF',str(after),'-MT',target,'-c',str(source),'-o',str(obj)])
            self.files[obj] = fixture.elf(group+'-'+str(index));slim = self.base.slim(first+2,obj)
            if is_stress:
                imports = [] if group == 'stress-protected' else sorted(H['attributes'].HOOKS)
                ip = dict(UndefinedValidated=True,MachineCodeValidated=False,Control=True)
            else:
                attrs=H['attributes'];role=m.ROLES[index]
                if role=='engine': imports = sorted((set(attrs.FORWARD)-{attrs.FORWARD[1],attrs.FORWARD[2]}) | {attrs.PANIC,attrs.STATE[0],attrs.STATE[2],attrs.STATE[4],attrs.STATE[5],attrs.COLD})
                elif role=='state': imports = sorted({attrs.PANIC,attrs.FORWARD[1]} | attrs.GCOV_IMPORTS)
                else: imports = sorted({attrs.FORWARD[1],attrs.FORWARD[2]})
                if group!='positive': imports = sorted(set(imports) | attrs.GCOV_IMPORTS)
                ip = attrs.inspect_ir_undefined(imports,role,mutation=group!='positive')
            evidence = self.base.imports(first+3,obj,imports)
            coverage=obj.with_suffix('.gcno');self.files[coverage]=b'synthetic gcov notes/'+group.encode()
            compiled.append(dict(Group=group,Role=m.ROLES[index],TemplateIndex=index,Source=str(source),SourceSha256=sha(buffers[relative]),
                Object=str(obj),ObjectSha256=sha(self.files[obj]),OriginalCompileFlags=self.native['Sources'][index]['CompileFlags'],CompileFlags=flags,
                SlimIR=slim,IRImports=evidence,IRImportProof=ip,CoverageNotes=dict(Path=str(coverage),Sha256=sha(self.files[coverage])),
                DiscoveryDependencies=deps,Dependencies=copy.deepcopy(deps),CompileDependenciesVerified=True,CpuFreeIncludes=True,
                CommandIndices=list(range(first,first+4)),RawIRIdentityClaim=False,SourceToMachineSemanticProof=False))
        lowerings=[]
        for pos,(group,first) in enumerate(zip(m.GROUPS,m.LOWERS)):
            obj=self.root/'attributes/lowered'/group/'aggregate.o';self.files[obj]=fixture.elf('aggregate-'+group,True)
            paths={name:Path(str(obj)+suffix) for name,suffix in m.ROLE_SUFFIXES.items()}
            paths.update(Disassembly=obj.parent/'aggregate.dis',WrapperArgs=self.root/(''.join(obj.parts[1:])+'.lto_wrapper_args'),
                DriverSpecs=self.specs,Diagnostics=self.root/('commands/%03d.stderr'%first))
            objects=list(self.positive)
            if 1<=pos<=3: objects[pos-1]=Path(compiled[pos+2]['Object'])
            if pos>=4: objects=[Path(compiled[pos+2]['Object'])]
            for name,path in paths.items():
                if path not in self.files: self.files[path]=('saved/'+group+'/'+name).encode()
            saved_flags=['-mcpu=cortex-m3','-mthumb','-mfloat-abi=soft','-Os',*m.RAW,'-flto-partition=one','-nostdlib','-r','-flinker-output=nolto-rel','-specs='+str(self.specs)]
            for key,stage in (('WpaArguments','-fwpa'),('LtransArguments','-fltrans')):
                args=[*saved_flags,stage]
                if stage=='-fwpa':args+=['-fltrans-output-list='+str(paths['PartitionList']),*map(str,objects)]
                else:args+=['-o',str(paths['Machine']),str(paths['Intermediate'])]
                self.files[paths[key]]=('\n'.join(args)+'\n').encode()
            flags=H['attributes_phase'].flags_for(suite,0,self.sr,H)
            diagnostic=('actual verbose lower/'+group).encode();dis=('zero inclusive disassembly/'+group).encode()
            self.command(first,[str(self.tools['Gcc']),*flags,'-specs='+str(self.specs),*m.LOWER_FLAGS,*map(str,objects),'-o',str(obj)],stderr=diagnostic)
            self.command(first+1,[str(self.tools['Objdump']),'-drwC','-z',str(obj)],stdout=dis)
            self.files[paths['Diagnostics']]=diagnostic;self.files[paths['Disassembly']]=dis
            lowerings.append(dict(Group=group,Inputs=[dict(Path=str(p),Sha256=sha(self.files[p])) for p in objects],Mutation=m.MUTATIONS[pos],Stress=pos>=4,
                Roles={name:dict(Path=str(p),Sha256=sha(self.files[p])) for name,p in paths.items()},CommandIndices=[first,first+1],
                DisassemblyIncludesZeroes=True,WorkerOptionsValidated=False,EffectsValidated=False,ValidationDeferred=True))
        self.record=dict(Status='BUILT-PENDING-READER',Scope='NATIVE_CM3_OS_LTO_COMMON_ATTRIBUTES_BUILD_ONLY_PENDING_READER',Profile='CM3',Mode='Os-lto',
            Linkage='direct',LTO=True,First=53,Stop=98,Commands=45,Compilations=compiled,Lowerings=lowerings,AnnotationControls=controls,
            SourceOwnership=self.batch['SourceOwnership'],SourceAnnotations=H['attributes'].inspect_sources(self.buffers),DriverAdapter=adapter,
            PairedStress=dict(Function=stress['Function'],RequiredFamilies=stress['RequiredFamilies'],OnlyDifference=stress['OnlyDifference'],
                ProtectedSha256=sha(stress['Protected']),UnprotectedSha256=sha(stress['Unprotected'])),DeferredReaderRequired=True,
            Qualification=False,CellContractSatisfied=False,RequiredCellSatisfied=False,RequiredCellsSatisfied=0,SourceIRProof=False,
            SourceToMachineSemanticProof=False,FullABIProof=False,FullSemanticABIProof=False,CpuExecution=False,BoardExecution=False,GlobalFreezeQualified=False,
            **dict.fromkeys(H['attributes_phase'].DEFERRED,False))
        self.batch['Compilations']+=compiled;self.batch['CommonAttributesDeferredReader']=self.record
        self.base.seal_native(False);self.adapter=Adapter();self.refresh()

    def __getattr__(self,name): return getattr(self.base,name)

    def refresh(self):
        self.files[self.root/'attributes/build.json']=encoded(self.record);self.base.seal()
        self.batch['InputHashes'].pop(str(self.root/'results.json'),None)
        # The batch receipt is caller-admitted, never its own artifact/hash entry.
        self.files[self.root/'results.json']=encoded(self.batch)
        manifest=json.loads(self.files[self.root/'artifacts.json'])
        manifest['Artifacts'].pop('results.json',None);self.files[self.root/'artifacts.json']=encoded(manifest)

    def catalog(self):
        self.base.catalog();self.batch['InputHashes'].pop(str(self.root/'results.json'),None)
        manifest=json.loads(self.files[self.root/'artifacts.json']);manifest['Artifacts'].pop('results.json',None)
        self.files[self.root/'artifacts.json']=encoded(manifest);self.files[self.root/'results.json']=encoded(self.batch)

    def run(self,**changes):
        helpers={k:H[k] for k in m.HELPERS if k!='common_lowered'};helpers['common_lowered']=self.adapter
        args=dict(batch=self.batch,native=self.native,root=self.root,core=self.core,helpers=helpers,read=self.read)
        args.update(changes);return m.inspect(**args)

    def read(self,path,expected=None):
        if path not in self.files:raise ValueError('missing role/'+str(path))
        raw=self.files[path]
        if expected is None and path not in (self.root/'results.json',self.root/'artifacts.json'):raise AssertionError('unbound read')
        if expected is not None and sha(raw)!=expected:raise ValueError('immutable hash mismatch')
        self.reads.append((path,expected));return raw

    def change(self,index,stdout=None,stderr=None):
        self.base.change_stream(index,stdout=stdout,stderr=stderr);self.refresh()


class CommonTests(unittest.TestCase):
    def test_positive_all_commands_cohorts_and_shared_authority(self):
        model=Model();proof=model.run();self.assertIs(m.require_result(proof),proof)
        self.assertEqual([r['Index'] for r in proof['CommandBindings']],list(range(53,98)))
        self.assertEqual((proof['IRBuilds'],proof['DependencyFiles'],proof['LoweringCohorts'],proof['LoweringRoleBindings']),(8,16,6,84))
        self.assertEqual(proof['SourceOwnershipInputs'],model.batch['SourceOwnershipInputs'])
        self.assertEqual(proof['AuthorityInputs']['BatchReceipt']['Sha256'],sha(model.files[model.root/'results.json']))
        self.assertEqual(len(model.adapter.calls),1);self.assertFalse(proof['LoweredProofs']['CommonAttributionClosed'])
        for key in m.NONCLAIMS:self.assertIs(proof[key],False)

    def test_exact_helpers_and_native_receipt_identity(self):
        model=Model();helpers={k:H[k] for k in m.HELPERS if k!='common_lowered'};helpers['common_lowered']=model.adapter;helpers['machine']=object()
        with self.assertRaises(ValueError):model.run(helpers=helpers)
        for defect in ('native','batch','seed','mode','built'):
            model=Model()
            if defect=='native':model.native['Foreign']=True
            elif defect=='batch':model.files[model.root/'results.json']=encoded({})
            elif defect=='seed':model.batch['SourceSeed']='C:/foreign/seed'
            elif defect=='mode':model.batch['Mode']='O2-lto'
            else:model.batch['CommonAttributesBuilt']=False
            with self.subTest(defect=defect),self.assertRaises(ValueError):model.run()

    def test_all_forty_five_per_command_copies(self):
        for index in range(53,98):
            model=Model();path=model.root/('commands/%03d.json'%index);row=json.loads(model.files[path]);row['Argv'][0]='C:/foreign/tool.exe'
            model.files[path]=encoded(row);model.catalog()
            with self.subTest(index=index),self.assertRaisesRegex(ValueError,'per-command'):model.run()

    def test_all_both_copy_tool_and_operand_corruption(self):
        for index in range(53,98):
            for position in (0,-1):
                model=Model();model.batch['Commands'][index]['Argv'][position]='C:/foreign/input.o';model.refresh()
                with self.subTest(index=index,position=position),self.assertRaises(ValueError):model.run()

    def test_terminal_types_and_streams(self):
        for index in range(53,98):
            for key,value in (('Exit',False),('ExpectedExit',False),('TimedOut',0),('Seconds',True),('State','RUNNING'),('JournalErrors',['bad'])):
                model=Model();model.batch['Commands'][index][key]=value;model.refresh()
                with self.subTest(index=index,key=key),self.assertRaises(ValueError):model.run()
        for index in (53,54,55,56,57,66,67,89):
            model=Model();model.change(index,stderr=b'' if index==66 else b'warning: foreign')
            with self.subTest(index=index),self.assertRaises(ValueError):model.run()

    def test_protected_stress_empty_nm_stdout_is_bound(self):
        model=Model();self.assertEqual(model.streams[89][0],b'');proof=model.run()
        self.assertEqual(proof['Compilations'][6]['IRImports']['Imports'],[])
        self.assertEqual(proof['CommandBindings'][89-53]['Stdout']['Sha256'],sha(b''))
        model=Model();model.change(89,stdout=b'         U __gcov_init\n')
        with self.assertRaisesRegex(ValueError,'streams'):model.run()

    def test_exact_specs_original_adapted_and_adapter_fields(self):
        for defect in ('original','adapted','stored','dumpspecs'):
            model=Model()
            if defect=='original':model.files[model.original_specs]+=b'foreign'
            elif defect=='adapted':model.files[model.specs]+=b'-fno-profile-arcs'
            elif defect=='stored':model.record['DriverAdapter']['InstrumentationCounterFlagsAdded']=True
            else:model.change(53,stdout=model.files[model.original_specs]+b'foreign')
            model.refresh()
            with self.subTest(defect=defect),self.assertRaises(ValueError):model.run()

    def test_original_source_hashes_and_ownership_projection(self):
        for name in m.OWNERSHIP:
            model=Model();model.files[model.sr/name]+=b'\nforeign\n';model.refresh()
            with self.subTest(name=name),self.assertRaises(ValueError):model.run()
        for key in ('SourceOwnership','SourceOwnershipInputs'):
            model=Model();model.batch[key]={};model.refresh()
            with self.subTest(key=key),self.assertRaises(ValueError):model.run()

    def test_all_private_source_bytes_and_exact_membership(self):
        for group in m.GROUPS[1:]:
            for defect in ('changed','extra','missing'):
                model=Model();project,buffers=model.trees[group];path=project/sorted(buffers)[0]
                if defect=='changed':model.files[path]+=b'foreign'
                elif defect=='extra':model.files[project/'foreign.h']=b'foreign'
                else:del model.files[path]
                model.refresh()
                with self.subTest(group=group,defect=defect),self.assertRaises(ValueError):model.run()

    def test_mutation_and_stress_comparison_targets_not_authority(self):
        for key in ('AnnotationControls','PairedStress','SourceAnnotations','SourceOwnership'):
            model=Model();model.record[key]={};model.refresh()
            with self.subTest(key=key),self.assertRaises(ValueError):model.run()

    def test_each_build_source_output_flags_and_mt(self):
        for group,index,first in m.BUILDS:
            for defect in ('source','output','flag','mt'):
                model=Model();argv=model.batch['Commands'][first+1]['Argv']
                if defect=='source':argv[argv.index('-c')+1]=str(model.sr/m.COMMON[index]) if group!='positive' else 'C:/foreign/source.c'
                elif defect=='output':argv[-1]='C:/foreign/output.o'
                elif defect=='flag':argv[argv.index('-Os')]='-O2'
                else:argv[argv.index('-MT')+1]='pilot-source-9'
                model.refresh()
                with self.subTest(group=group,first=first,defect=defect),self.assertRaises(ValueError):model.run()

    def test_all_dependency_files_and_targets(self):
        for row in Model().record['Compilations']:
            for suffix in ('.discovery.d','.compile.d'):
                model=Model();path=Path(row['Object']).with_suffix(suffix);model.files[path]=model.files[path].replace(b'pilot-source-',b'foreign-source-');model.refresh()
                with self.subTest(path=path),self.assertRaises(ValueError):model.run()

    def test_dependency_foreign_cmsis_port_and_source_absence(self):
        for defect in ('foreign','cmsis','port','missing-source','main'):
            model=Model();row=model.record['Compilations'][3];project,_=model.trees['mutant-engine'];source=Path(row['Source']);obj=Path(row['Object'])
            foreign={'foreign':model.root/'other/foreign.h','cmsis':model.seed/'cmsis/core_cm3.h','port':project/'fiber/port/ARM_CM3/file.h','main':project/'tools/fixtures/classic_final_image/main.h'}.get(defect)
            paths=[model.external] if foreign is None else [source,foreign]
            if foreign is not None:model.files[foreign]=b'foreign'
            raw=('pilot-source-0: '+' '.join(map(str,paths))+'\n').encode()
            model.files[obj.with_suffix('.discovery.d')]=model.files[obj.with_suffix('.compile.d')]=raw;model.refresh()
            with self.subTest(defect=defect),self.assertRaises(ValueError):model.run()

    def test_readelf_full_columns_and_executable_fallback(self):
        for _,_,first in m.BUILDS:
            for field in (7,9,10,11):
                model=Model();lines=model.streams[first+2][0].splitlines();tokens=lines[6].split();tokens[field]=b'16';lines[6]=b' '.join(tokens)
                model.change(first+2,stdout=b'\n'.join(lines)+b'\n')
                with self.subTest(index=first+2,field=field),self.assertRaises(ValueError):model.run()
        model=Model();obj=Path(model.record['Compilations'][0]['Object']);model.files[obj]=fixture.elf('fallback',True)
        model.change(56,stdout=fixture.readelf_text(model.files[obj]))
        with self.assertRaisesRegex(ValueError,'fallback'):model.run()

    def test_nm_malformed_duplicate_and_foreign_imports(self):
        for raw in (b'unknown ? 0\n',b' U foreign\n',b' U fiber_panic\n U fiber_panic\n',b' D fiber_panic\n'):
            model=Model();model.change(57,stdout=raw)
            with self.subTest(raw=raw),self.assertRaises(ValueError):model.run()

    def test_each_slim_import_and_compilation_comparison_target(self):
        for pos in range(8):
            for key in ('IRImports','IRImportProof','SlimIR','Dependencies','Source'):
                model=Model();model.record['Compilations'][pos][key]='foreign';model.refresh()
                with self.subTest(pos=pos,key=key),self.assertRaises(ValueError):model.run()

    def test_all_cohort_order_and_output_object_substitution(self):
        for first in m.LOWERS:
            for defect in ('input','output','extra-output'):
                model=Model();argv=model.batch['Commands'][first]['Argv']
                if defect=='input':argv[-3]='C:/foreign/input.o'
                elif defect=='output':argv[-1]=argv[-3]
                else:argv+=['-o',argv[-1]]
                model.refresh()
                with self.subTest(index=first,defect=defect),self.assertRaises(ValueError):model.run()
        proof=Model().run();self.assertTrue(all(r['Argv'][-1].endswith('aggregate.o') for r in proof['CommandBindings'] if r['Index'] in m.LOWERS))

    def test_each_fourteen_role_path_hash_and_extra_claim(self):
        for pos in range(6):
            for role in m.ROLE_NAMES:
                model=Model();model.record['Lowerings'][pos]['Roles'][role]['Path']='C:/foreign/role';model.refresh()
                with self.subTest(pos=pos,role=role),self.assertRaises(ValueError):model.run()
            model=Model();model.record['Lowerings'][pos]['WorkerOptionsValidated']=True;model.refresh()
            with self.subTest(pos=pos),self.assertRaises(ValueError):model.run()

    def test_saved_stage_specs_and_real_wpa_metadata(self):
        for defect in ('foreign-list','split-list','alias-list','double-dash-list','foreign-stage','split-specs','extra-specs'):
            model=Model();path=Path(model.record['Lowerings'][0]['Roles']['WpaArguments']['Path']);raw=model.files[path]
            if defect=='foreign-list':raw=raw.replace(b'-fltrans-output-list=',b'-fltrans-output-list=C:\\foreign\\')
            elif defect=='split-list':raw=raw.replace(b'-fltrans-output-list=',b'-fltrans-output-list\n')
            elif defect=='alias-list':raw=raw.replace(b'-fltrans-output-list=',b'-fltrans-output-list=..\\')
            elif defect=='double-dash-list':raw+=b'--fltrans-output-list=C:\\foreign\\list\n'
            elif defect=='foreign-stage':raw+=b'-fltrans\n'
            elif defect=='split-specs':raw=raw.replace(b'-specs=',b'-specs\n')
            else:raw+=b'--specs=C:\\foreign.specs\n'
            model.files[path]=raw;model.refresh()
            with self.subTest(defect=defect),self.assertRaises(ValueError):model.run()
        self.assertEqual(len(Model().run()['Lowerings']),6)

    def test_manifest_wrapper_owners_unknown_members_and_missing_roles(self):
        for defect in ('both-wrappers','neither-wrapper','unknown-output','missing-machine'):
            model=Model();row=model.record['Lowerings'][0];obj=Path(row['Roles']['Object']['Path']);wrapper=Path(row['Roles']['WrapperArgs']['Path'])
            if defect=='both-wrappers':model.files[Path(str(obj)+'.lto_wrapper_args')]=b'foreign owner'
            elif defect=='neither-wrapper':del model.files[wrapper]
            elif defect=='unknown-output':model.files[obj.parent/'foreign.o']=b'foreign output'
            else:del model.files[Path(row['Roles']['Machine']['Path'])]
            model.refresh()
            with self.subTest(defect=defect),self.assertRaises(ValueError):model.run()

    def test_disassembly_and_diagnostics_same_journals(self):
        for pos,first in enumerate(m.LOWERS):
            model=Model();path=Path(model.record['Lowerings'][pos]['Roles']['Disassembly']['Path']);model.files[path]+=b'foreign';model.refresh()
            with self.subTest(index=first+1),self.assertRaises(ValueError):model.run()
            model=Model();model.change(first,stdout=b'foreign stdout')
            with self.subTest(index=first),self.assertRaises(ValueError):model.run()

    def test_result_schema_nonclaims_typed_counts_and_nested_joins(self):
        baseline=Model().run()
        for key in m.NONCLAIMS:
            proof=copy.deepcopy(baseline);proof[key]=True
            with self.subTest(key=key),self.assertRaises(ValueError):m.require_result(proof)
        for key in m.COUNTS:
            proof=copy.deepcopy(baseline);proof[key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):m.require_result(proof)
        for path in ((),('SourceAnnotations',),('DriverAdapter',),('Compilations',0),('Compilations',0,'SlimIR'),('Compilations',0,'IRImportProof'),('Lowerings',0),('AnnotationControls',0),('SourceOwnership',),('LoweredProofs',)):
            proof=copy.deepcopy(baseline);row=proof
            for part in path:row=row[part]
            row['ForeignClaim']=False
            with self.subTest(path=path),self.assertRaises(ValueError):m.require_result(proof)
        for index in range(15):
            for defect in ('duplicate','foreign','source','signature'):
                proof=copy.deepcopy(baseline);rows=proof['SourceOwnership']['CheckedFunctions'];row=rows[index]
                if defect=='duplicate':rows[index]=copy.deepcopy(rows[(index+1)%15])
                elif defect=='foreign':row['Function']='foreign_function'
                elif defect=='source':row['Source']=next(n for n in m.COMMON if n!=row['Source'])
                else:row['Signature']='void '+row['Function']+'(int foreign_argument)'
                with self.subTest(ownership=index,defect=defect),self.assertRaises(ValueError):m.require_result(proof)
        hashes={r['Source']:r['Sha256'] for r in baseline['SourceInputs']}
        for index in range(28):
            for defect in ('duplicate','foreign','path','site'):
                proof=copy.deepcopy(baseline);rows=proof['SourceAnnotations']['Records'];row=rows[index]
                if defect=='duplicate':rows[index]=copy.deepcopy(rows[(index+1)%28])
                elif defect=='foreign':row['Name']='foreign_function'
                elif defect=='path':
                    row['Path']=next(n for n in m.COMMON if n!=row['Path']);row['SourceSha256']=hashes[row['Path']]
                else:row['Site']='Definition' if row['Site']=='Declaration' else 'Declaration'
                with self.subTest(annotation=index,defect=defect),self.assertRaises(ValueError):m.require_result(proof)
        for index in range(3):
            for defect in ('sites','order','function'):
                proof=copy.deepcopy(baseline);edits=proof['AnnotationControls'][index]['Edits']
                if defect=='sites':edits[0]['Site'],edits[1]['Site']=edits[1]['Site'],edits[0]['Site']
                elif defect=='order':edits.reverse()
                else:edits[0]['Function']='foreign_function'
                with self.subTest(control=index,defect=defect),self.assertRaises(ValueError):m.require_result(proof)

    def test_finite_json_duplicate_and_missing_read_role(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":Infinity}',b'{"x":1e999}'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):H['controls_replay']._json(raw)
        model=Model();del model.files[model.specs]
        with self.assertRaises(ValueError):model.run()
        model=Model();missing=Path(model.native['ResolvedWorkers']['lto1']['Path']);del model.files[missing];model.refresh()
        with self.assertRaises(ValueError):model.run()

    def test_no_filesystem_process_or_helper_mutation_and_real_slim_bytes(self):
        model=Model();before=copy.deepcopy(model.batch);native=copy.deepcopy(model.native)
        def forbidden(*a,**k):raise AssertionError('filesystem forbidden')
        with patch.object(Path,'read_bytes',forbidden),patch.object(Path,'read_text',forbidden),patch.object(Path,'stat',forbidden),patch.object(Path,'exists',forbidden),patch.object(Path,'resolve',forbidden):
            proof=model.run()
        self.assertEqual(model.batch,before);self.assertEqual(model.native,native)
        proof['Compilations'][0]['CompileFlags'].clear();self.assertTrue(model.record['Compilations'][0]['CompileFlags'])
        for index,(raw,text,claim) in REAL.items():
            header=H['transport'].require_elf32le(raw);H['controls_replay']._readelf_metadata(text.decode('ascii'),raw,header)
            self.assertEqual(H['controls_replay']._binary_sections(raw,header),claim['Sections'])


def main():
    global BUFFERS,H,REAL,m,fixture
    parser=argparse.ArgumentParser(description=__doc__,allow_abbrev=False);parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args();output=args.output_dir.absolute();temporary=Path(tempfile.gettempdir()).absolute()
    if output.exists() or output.is_relative_to(ROOT) or not output.is_relative_to(temporary):parser.error('fresh external TEMP output required')
    paths=dict(fixture=HERE/'test_abi_controls_replay.py',controls_replay=HERE/'abi_controls_replay.py',leaf=HERE/'common_replay.py',
        deps=HERE/'dependency_bytes.py',recipes=HERE/'batch_recipes.py',declarations=HERE/'declarations.py',ordinary=HERE.parent/'ordinary_final_cell/abi.py',
        plan=HERE.parent/'ordinary_final_cell/controls.py',diagnostics=HERE.parent/'cm3_lto_abi_controls/diagnostics.py',
        probes=HERE.parent/'cm0_final_cell/components.py',port_runner=HERE.parent/'cm3_lto_port_policy/runner.py',guard=HERE/'batch_guard.py',
        transport=HERE.parent/'cm3_lto_transport/probe.py',oracle=HERE.parent/'cm0_final_cell/abi.py',ownership=HERE.parent/'cm0_final_cell/ownership.py',
        attributes=HERE.parent/'cm3_lto_attributes/attributes.py',attribute_runner=HERE.parent/'cm3_lto_attributes/runner.py',
        attributes_phase=HERE/'attributes_phase.py',common_workers=HERE/'common_workers.py',common_effects=HERE/'common_effects.py')
    fixture_raw=paths['fixture'].read_bytes();fixture=types.ModuleType('_common_test_fixture');fixture.__file__=str(paths['fixture'])
    exec(compile(fixture_raw,str(paths['fixture']),'exec'),fixture.__dict__)
    project=fixture.HEADERS+fixture.ORDER+fixture.EXTRA+('context/context_api_decl.h','tools/runtime_sources.json')
    sources=[Path(__file__).resolve(),*paths.values(),*(ROOT/n for n in project)]
    actual=Path('C:/fzosbatch-20261107-e1');batch_path=actual/'results.json';manifest_path=actual/'artifacts.json'
    batch_raw=batch_path.read_bytes();manifest_raw=manifest_path.read_bytes()
    if sha(batch_raw)!='3DCE7C453AF909B6B917B9A3EED552F1725D70ED9420CEA74A36797ADB12EEC7' or sha(manifest_raw)!='35E2A0B0895AD8458F8476C8E6F672176E39687B69137804E3342DDC663BD635':raise ValueError('sealed parser fixtures drift')
    batch=json.loads(batch_raw);manifest=json.loads(manifest_raw)['Artifacts'];sources.extend((batch_path,manifest_path));real={}
    for row in batch['CommonAttributesDeferredReader']['Compilations']:
        index=row['CommandIndices'][2];obj=Path(row['Object']);stdout=actual/('commands/%03d.stdout'%index)
        sources.extend((obj,stdout));real[index]=(obj,stdout,row['SlimIR'])
    sources=list(dict.fromkeys(sources));BUFFERS={p:p.read_bytes() for p in sources};opening={str(p):sha(raw) for p,raw in BUFFERS.items()}
    if BUFFERS[paths['fixture']]!=fixture_raw or BUFFERS[batch_path]!=batch_raw or BUFFERS[manifest_path]!=manifest_raw:raise ValueError('opening drift')
    for name,path in paths.items():
        if name in ('fixture','oracle'):continue
        module=types.ModuleType('_common_test_'+name);module.__file__=str(path)
        def buffered_read(p):
            if p not in BUFFERS:raise AssertionError('unenrolled helper read/'+str(p))
            return BUFFERS[p]
        with patch.object(Path,'read_bytes',buffered_read):exec(compile(BUFFERS[path],str(path),'exec'),module.__dict__)
        if name=='leaf':m=module
        else:H[name]=module
    fixture.BUFFERS=BUFFERS;fixture.m=H['controls_replay'];fixture.H={k:H[k] for k in ('deps','recipes','declarations','ordinary','plan','diagnostics','probes','port_runner','guard','transport')}
    for index,(obj,stdout,claim) in real.items():
        for path in (obj,stdout):
            if sha(BUFFERS[path])!=manifest[path.relative_to(actual).as_posix()]:raise ValueError('manifest-bound parser fixture')
        if sha(BUFFERS[obj])!=claim['Sha256'] or sha(BUFFERS[stdout])!=batch['Commands'][index]['StdoutSha256']:raise ValueError('parser fixture role drift')
        REAL[index]=(BUFFERS[obj],BUFFERS[stdout],claim)
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CommonTests))
    closing={str(p):sha(p.read_bytes()) for p in sources}
    report=dict(Status='PASS' if result.wasSuccessful() and result.testsRun==METHODS and not result.skipped and opening==closing else 'FAIL',
        Tests=result.testsRun,ExpectedTests=METHODS,Errors=len(result.errors),Failures=len(result.failures),Skipped=len(result.skipped),
        SourceHashes=opening,SourceDrift=opening!=closing,ClosingFilesVerified=sum(opening[k]==v for k,v in closing.items()),
        SyntheticBindingReplayOnly=True,RealSlimParserFixtures=len(REAL),ActualFullReplayPerformed=False,MachinePredicatesExercised=False,
        CompilerExecuted=False,BoardExecution=False,Qualification=False,RequiredCellsSatisfied=0)
    output.mkdir(parents=True);raw=encoded(report);(output/'results.json').write_bytes(raw)
    print(json.dumps({k:v for k,v in report.items() if k!='SourceHashes'},sort_keys=True));print('ReceiptSha256='+sha(raw))
    return 0 if report['Status']=='PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
