"""Actual AN505 paired SG execution; explicit fault injection is not a CPU model."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time

spec=importlib.util.spec_from_file_location('a26_rsp',Path(__file__).parents[1]/'cm33_secure_guards'/'aircr_rsp.py')
transport=importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)
Rsp,require=transport.Rsp,transport.require
AIRCR,CPACR,NSACR,FPCCR,FPCCR_NS=0xe000ed0c,0xe000ed88,0xe000ed8c,0xe000ef34,0xe002ef34
INIT,READY,POOL_INIT,POOL_READY=0x53464742,0x53464752,0x53465042,0x53465052
INIT_NAME='fiber_secure_context_gateway_c3fs_v1_initialize'
ALIASES={'ip':'r12','sl':'r10','fp':'r11','sb':'r9'}


def reg(name):
    return ALIASES.get(name.lower(),name.lower())


def fault_valid(record,trap):
    return (record['pc']==trap['pc'] and record['cfsr']==0x10000 and record['hfsr']==0 and
            record['ipsr']==6 and record['frame']==trap['sp']-32 and
            record['xpsr'] & 0x1ff==trap['ipsr'] and record['xpsr'] & (1<<24)!=0 and
            record['exc_return'] & 0x10!=0 and record['exc_return'] & 0x40!=0)


def expected_outcome(case):
    if case in ('success','secure-spSEL2','masks'):
        return 'SUCCESS'
    if (case.startswith(('query-','init-cpacr','trap-','scrub-')) or
            case in ('init-npriv','pool-state-corrupt','pool-entry-unknown')):
        return 'EXACT_TERMINAL'
    if case.startswith(('readback-','pool-result-','pool-entry-')):
        return 'STICKY'
    require(case.startswith(('gate-','pool-marker-','control-','ns-control-','control-ns-read-','lspact-')) or
            case=='bfhfnmins','UNKNOWN_CASE_OUTCOME:'+case)
    return 'FALSE_ADMISSION'


class Execution:
    def __init__(self,root,secure,ns,manifest,case,seconds,control):
        self.root,self.secure,self.ns,self.case,self.control=root,secure,ns,case,control
        self.m=json.loads(Path(manifest).read_text(encoding='utf-8-sig'))
        self.directory=Path(manifest).parent/case
        self.directory.mkdir()
        self.deadline=time.monotonic()+int(seconds)
        self.ins={x['pc']:x for x in self.m['secure']['instructions']}
        self.syms=self.m['secure']['symbols']
        self.ns_syms=self.m['nonsecure']['symbols']
        self.entries={x['body']:name for name,x in self.m['secure']['entries'].items()}
        self.returns={a:name for name,x in self.m['secure']['entries'].items() for a in x['returns']}
        self.gate=self.addr('fiber_secure_context_gateway_state')
        self.pool_state=self.addr('fiber_secure_context_pool_state')
        self.pool=self.addr('fiber_secure_context_pool_image')
        self.pool_size=self.syms['fiber_secure_context_pool_image']['size']
        require(self.pool_size==864,'POOL_GEOMETRY')
        self.events=[]
        self.process=self.connection=None
        self.breakpoints=set()
        self.phase=None
        self.focus_count=0
        self.direct=False
        self.wrong=set()
        self.wrong_done=False
        self.first=False
        self.repeat=False
        self.done=False
        self.active=None
        self.injected=False
        self.tainted=False
        self.pool_finished=False
        self.pool_return=None
        self.fast=False
        self.trap=None
        self.fault=None
        self.after_pool_read=False
        self.source_effects=[]
        self.store_counts={}
        self.step=False
        self.saved=None
        self.query_seen=[]
        self.call_injected=False
        require(self.m.get('control','none')==control,'MANIFEST_CONTROL_MISMATCH')
        self.expected_outcome=expected_outcome(case)
        self.receipt={'Case':case,'ExpectedOutcome':self.expected_outcome,
                      'Machine':'mps2-an505','Control':control,'Verdict':'FAIL',
                      'NoAllocator':True,'SourceMutated':control!='none','Transport':'private AF_UNIX RSP'}

    def addr(self,name): return self.syms[name]['address']
    def event(self,kind,**values): self.events.append({'event':kind,**values})
    def write_reg(self,name,value):
        number,bits=self.rsp.registers[reg(name)]
        require(bits==32,'INJECT_REGISTER_WIDTH')
        require(self.rsp.packet(f'P{number:x}={int(value).to_bytes(4,"little").hex()}')=='OK','INJECT_REGISTER')
    def write_mem(self,address,data):
        require(self.rsp.packet(f'M{address:x},{len(data):x}:{data.hex()}')=='OK','INJECT_MEMORY')
    def word(self,address,value): self.write_mem(address,int(value).to_bytes(4,'little'))
    def bp(self,address,enabled=True):
        if (address in self.breakpoints)==enabled: return
        self.rsp.breakpoint(address,enabled)
        if enabled: self.breakpoints.add(address)
        else: self.breakpoints.remove(address)
    def helper(self,name,r0=0,r1=0):
        saved={x:self.rsp.register(x) for x in ('pc','r0','r1','xpsr')}
        self.write_reg('r0',r0); self.write_reg('r1',r1)
        target=self.addr(name)
        self.write_reg('pc',target)
        reply=self.rsp.packet('s')
        require(reply.startswith(('T05','S05')) and self.rsp.register('pc')==target+
                (2 if name in ('fixture_word_store','fixture_word_load') else 4),'HELPER_INSTRUCTION')
        result=self.rsp.register('r0')
        require(self.rsp.register('xpsr')==saved['xpsr'],'HELPER_EXECUTION_STATE')
        for key,value in saved.items(): self.write_reg(key,value)
        return result
    def read_policy(self,address): return self.helper('fixture_word_load',r1=address)
    def policy(self,address,value):
        self.helper('fixture_word_store',value,address)
        actual=self.read_policy(address)
        self.event('actual_secure_cpu_store',address=address,pending=value,actual=actual)
        return actual
    def special(self,name,value):
        self.helper('fixture_control_ns_store' if name=='control_ns' else 'fixture_control_store',value)
        actual=self.helper('fixture_control_ns_load' if name=='control_ns' else 'fixture_control_load')
        require(actual==value,f'SPECIAL_SEED_READBACK:{name}:{actual:#x}!={value:#x}')
        self.event('actual_secure_cpu_msr',register=name,value=actual)
    def snapshot(self):
        return {'gate':self.rsp.word(self.gate),'pool_state':self.rsp.word(self.pool_state),
                'pool':self.rsp.memory(self.pool,self.pool_size).hex(),
                'control_s':self.helper('fixture_control_load'),'control_ns':self.helper('fixture_control_ns_load'),
                'psp_s':self.rsp.register('psp_s'),'psplim_s':self.rsp.register('psplim_s'),
                'primask':self.rsp.register('primask'),'basepri':self.rsp.register('basepri'),
                'faultmask':self.rsp.register('faultmask'),
                'policy':{str(a):self.read_policy(a) for a in (AIRCR,CPACR,NSACR,FPCCR,FPCCR_NS,0xe002ed88)}}
    def intact(self):
        require(self.rsp.word(self.gate)==0 and self.rsp.word(self.pool_state)==0 and
                self.rsp.memory(self.pool,self.pool_size)==b'\xa5'*self.pool_size,'PREFLIGHT_BACKING_CHANGED')

    def seed(self,query=None):
        c=self.case
        if query is not None:
            match=re.fullmatch(r'query-(\d+)-(cpacr0|cpacr3|cpacr5|npriv)',c)
            if not match or self.injected or self.wrong_done or query!=int(match[1]): return
            if match[2]=='npriv': self.special('control_s',1)
            else: self.policy(CPACR,{'cpacr0':0,'cpacr3':0x300000,'cpacr5':0x500000}[match[2]])
            self.injected=True
            return
        if self.phase not in ('first','repeat'): return
        if self.phase=='repeat' and (self.post_failure() or self.case in ('success','secure-spSEL2')): return
        if c=='masks':
            for name,value in (('fixture_masks_store',1),('fixture_basepri_store',0x80),('fixture_faultmask_store',1)):
                self.helper(name,value)
            require(self.rsp.register('primask')==1 and self.rsp.register('basepri')==0x80 and
                    self.rsp.register('faultmask')==1,'NONZERO_MASK_SEED')
            self.injected=True
        if c.startswith('init-cpacr'):
            self.policy(CPACR,{'init-cpacr0':0,'init-cpacr3':0x300000,'init-cpacr5':0x500000}[c]); self.injected=True
        elif c=='init-npriv': self.special('control_s',1); self.injected=True
        elif c=='secure-spSEL2': self.special('control_s',2); self.injected=True
        elif re.fullmatch(r'control-(4|6|8|10|14)',c): self.special('control_s',int(c.split('-')[1])); self.injected=True
        elif c in ('ns-control-4','ns-control-6'):
            # FPCA is shared. MSR CONTROL_NS can change it only after the NS
            # grant; this necessarily makes the Secure view active too.
            self.policy(NSACR,self.read_policy(NSACR)|0xc00)
            self.special('control_ns',int(c.split('-')[-1])); self.injected=True
        elif c in ('lspact-s','lspact-ns','lspact-both'):
            for address in ((FPCCR,FPCCR_NS) if c=='lspact-both' else (FPCCR,) if c=='lspact-s' else (FPCCR_NS,)):
                value=self.read_policy(address)|1
                require(self.policy(address,value)&1,'LSPACT_SEED')
            self.injected=True
        elif c=='bfhfnmins':
            require(self.policy(AIRCR,0x05fa2500)&0xffff==0x2500,'AIRCR_SEED'); self.injected=True
        elif c.startswith(('gate-','pool-marker-')):
            if c.startswith('gate-'):
                target=self.gate; word={'gate-init':INIT,'gate-ready':READY,'gate-unknown':1}[c]
            else:
                target=self.pool_state
                word={'pool-marker-init':POOL_INIT,'pool-marker-ready':POOL_READY,'pool-marker-unknown':1}[c]
            self.word(target,word); self.injected=True

    def post_failure(self):
        return self.case.startswith(('readback-','pool-result-','pool-entry-'))

    def expected_first(self): return 1 if self.case in ('success','secure-spSEL2','masks') else 0

    def memory_operand(self,item):
        # Integer loads/stores in the qualified production group. Unsupported
        # forms fail closed, never silently skip a possible backend write.
        args=item['args']
        m=re.fullmatch(r'(r\d+|ip|sl|fp|sb),\s*\[(r\d+|sp|pc|ip|sl|fp|sb)'
                       r'(?:,\s*(?:#(-?(?:0x[0-9a-f]+|\d+))|(r\d+|ip|sl|fp|sb)))?\]'
                       r'!?(?:,\s*#-?(?:0x[0-9a-f]+|\d+))?',args)
        require(m is not None,'UNRECOGNIZED_MEMORY_FORM:'+item['text'])
        source,base,offset,index=m.groups()
        base_value=((item['pc']+4)&~3) if base=='pc' else self.rsp.register(reg(base))
        delta=int(offset or '0',0)+(self.rsp.register(reg(index)) if index else 0)
        return reg(source),(base_value+delta)&0xffffffff

    def source_step(self,item):
        op,args=item['op'],item['args']
        pc=item['pc']
        after=None
        if op.startswith(('str','ldr')):
            register,address=self.memory_operand(item)
            width=1 if op.startswith(('strb','ldrb')) else 2 if op.startswith(('strh','ldrh')) else 4
            if op.startswith('str'):
                value=self.rsp.register(register)&((1<<(width*8))-1)
                if address in (AIRCR,NSACR,FPCCR,self.gate,self.pool_state) or self.pool<=address<self.pool+self.pool_size:
                    require(self.phase=='first','REJECTED_CALL_WROTE_BACKEND')
                    require(not self.tainted,'FAILED_READBACK_CONTINUED')
                    if self.expected_first()==0 and not self.post_failure() and not self.case.startswith(('trap-','scrub-','pool-state-')):
                        raise RuntimeError('ADMISSION_WRITE')
                    self.source_effects.append((address,width,value))
                    self.event('source_store',pc=pc,address=address,width=width,value=value)
                    if address==AIRCR:
                        require(width==4 and value>>16==0x05fa and value & 0x6000==0x4000,'AIRCR_FORBIDDEN_POLICY')
                    if address==self.gate:
                        require(value in (INIT,READY),'GATEWAY_PUBLICATION')
                    if address==self.pool_state:
                        require(value in (POOL_INIT,POOL_READY),'POOL_PUBLICATION')
                    if self.pool<=address<self.pool+self.pool_size:
                        require(width==1 and value==0,'POOL_SCRUB_STORE')
                        require(pc not in self.breakpoints,'UNEXPECTED_POOL_LOOP_BREAKPOINT')
                        self.fast=True
                        self.bp(self.m['secure']['pool_read'])
                    if ((self.case=='trap-gate-initial' and address==self.gate and value==INIT) or
                        (self.case=='trap-gate-ready' and address==self.gate and value==READY) or
                        (self.case=='trap-pool-initial' and address==self.pool_state and value==POOL_INIT) or
                        (self.case=='trap-pool-ready' and address==self.pool_state and value==POOL_READY)):
                        after=('memory',address,0)
                else:
                    require(0x30001000<=address and address+width<=0x30004000,'UNOWNED_SOURCE_STORE')
            elif address in (AIRCR,NSACR,FPCCR,self.gate,self.pool_state):
                self.store_counts[address]=self.store_counts.get(address,0)
                if self.phase=='first' and self.source_effects:
                    key=None
                    if address==AIRCR: key='readback-aircr'
                    elif address==NSACR and any(a==NSACR for a,_,_ in self.source_effects): key='readback-nsacr'
                    elif address==FPCCR:
                        writes=sum(1 for a,_,_ in self.source_effects if a==FPCCR)
                        key='readback-lspens' if writes==1 else 'readback-ts' if writes==2 else None
                    if key==self.case and not self.injected:
                        after=('read',register,0x4000 if address==AIRCR else 0x800 if address==NSACR else
                               (1<<29) if key=='readback-lspens' else (1<<26))
        elif op.startswith(('stm','vst','stc')):
            require(op.startswith('stm') and args.startswith('sp!,'),'UNRECOGNIZED_STORE_CLASS')
        elif op=='msr':
            special,register=[x.strip() for x in args.split(',')]
            if special.lower() not in ('apsr_nzcvqg','cpsr_fs'):
                require(self.phase=='first' and special.lower() in ('control','psp','psplim'), 'UNOWNED_SYSTEM_WRITE')
                require(not self.tainted,'FAILED_READBACK_CONTINUED')
                value=self.rsp.register(reg(register))
                require(value==(2 if special.lower()=='control' else 0),'SYSTEM_WRITE_VALUE')
                self.event('source_msr',pc=pc,register=special.lower(),value=value)
        elif op=='mrs':
            register,special=[x.strip() for x in args.split(',')]
            if self.phase=='first' and self.source_effects and not self.injected:
                if self.case=='readback-'+special.lower() and special.lower() in ('psp','psplim'):
                    after=('force',reg(register),8)
                if special.lower()=='control' and re.fullmatch(r'readback-control-(6|10|14)',self.case):
                    after=('force',reg(register),int(self.case.split('-')[-1]))
            if self.phase in ('first','repeat') and not self.source_effects and not self.call_injected and special.lower()=='control_ns' and self.case in ('control-ns-read-4','control-ns-read-6'):
                after=('force',reg(register),int(self.case[-1]))
        return after

    def returned(self,name):
        result=self.rsp.register('r0')
        require(self.rsp.register('sp')==self.call_sp,'CMSE_STACK_NOT_BALANCED')
        require(self.rsp.register('r9')==self.call_r9,'CMSE_R9_NOT_PRESERVED')
        if name!=INIT_NAME:
            require(not self.case.startswith('query-') or not self.injected,'QUERY_MISSING_TERMINAL')
            require(self.snapshot()==self.before,'QUERY_CHANGED_STATE')
            self.event('query_return',name=name,value=result)
            self.query_seen.append(name)
        else:
            if self.phase in ('direct','wrong'):
                require(result==0 and self.snapshot()==self.before,'CALLER_ADMISSION_EFFECT')
            elif self.phase=='first':
                require(result==self.expected_first(),'INITIALIZER_RETURN')
                if result==1:
                    require(self.rsp.word(self.gate)==READY and self.rsp.word(self.pool_state)==POOL_READY and
                            self.rsp.memory(self.pool,self.pool_size)==bytes(self.pool_size),'READY_OR_SCRUB')
                    require(self.rsp.register('control_s')==2 and self.rsp.register('psp_s')==0 and
                            self.rsp.register('psplim_s')==0,'READY_CPU_STATE')
                    require(self.read_policy(NSACR)==(self.before['policy'][str(NSACR)]|0xc00),'NSACR_POLICY')
                    expected=(self.before['policy'][str(FPCCR)]&~(1<<29))|(1<<26)
                    require(self.read_policy(FPCCR)&0xfc000001==expected&0xfc000000,'FPCCR_POLICY')
                    current=self.snapshot()
                    require(all(current[k]==self.before[k] for k in
                            ('primask','basepri','faultmask','control_ns')),'UNOWNED_SPECIAL_REGISTER')
                    require(all(current['policy'][str(a)]==self.before['policy'][str(a)] for a in
                            (CPACR,0xe002ed88)),'UNOWNED_CPACR')
                    require(current['policy'][str(FPCCR_NS)]&0xc0000001==
                            self.before['policy'][str(FPCCR_NS)]&0xc0000001,'UNOWNED_NS_FP_POLICY')
                elif self.post_failure():
                    require(self.injected and self.rsp.word(self.gate)==INIT,'STICKY_INITIALIZING')
                else:
                    require(not self.source_effects and self.snapshot()==self.before,'FALSE_ADMISSION_EFFECT')
                self.saved=self.snapshot()
            else:
                require(result==0 and self.snapshot()==self.before,'REPEAT_CHANGED_STATE')
                if self.post_failure(): require(self.snapshot()==self.saved,'STICKY_RETRY_REOPENED')
            self.event('initializer_return',phase=self.phase,result=result,gate=self.rsp.word(self.gate),
                       pool_state=self.rsp.word(self.pool_state))
            if self.case=='masks' and self.phase in ('first','repeat'):
                for helper,name in (('fixture_masks_store','primask'),('fixture_basepri_store','basepri'),('fixture_faultmask_store','faultmask')):
                    self.helper(helper,self.original_masks[name])
                self.event('test_owned_mask_restore',values=self.original_masks)
        self.active=None

    def run(self):
        outcome=error=None
        try:
            for path,key in ((self.secure,'secure_sha256'),(self.ns,'nonsecure_sha256')):
                require(hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()==self.m[key],'IMAGE_DRIFT')
            with tempfile.TemporaryDirectory(prefix='fiber-c3fs-sg-') as temporary:
                socket_path=str(Path(temporary)/'gdb.sock')
                command=[str(Path(self.root)/'usr/bin/qemu-system-arm'),'-machine','mps2-an505','-accel','tcg',
                         '-display','none','-serial','none','-monitor','none','-no-reboot',
                         '-semihosting-config','enable=on,target=native','-L',str(Path(self.root)/'usr/share/qemu'),
                         '-kernel',self.secure,'-device','loader,file='+self.ns,'-S','-chardev',
                         'socket,id=proof,path='+socket_path+',server=on,wait=off','-gdb','chardev:proof']
                self.receipt['Command']=command
                with (self.directory/'qemu.log').open('wb') as log:
                    self.process=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
                    self.connection=socket.socket(socket.AF_UNIX)
                    while True:
                        require(self.process.poll() is None,'QEMU_STARTUP_EXIT')
                        try: self.connection.connect(socket_path); break
                        except (FileNotFoundError,ConnectionRefusedError):
                            require(time.monotonic()<self.deadline,'QEMU_STARTUP_TIMEOUT'); time.sleep(.01)
                    self.rsp=Rsp(self.connection,self.deadline)
                    self.rsp.discover_registers()
                    self.receipt['Registers']=self.rsp.registers
                    self.rsp.packet('?')
                    checkpoints={self.addr('fixture_direct_done'):'direct_done',self.ns_syms['fixture_wrong_done']['address']:'wrong_done',
                        self.ns_syms['fixture_first_result']['address']:'first_result',
                        self.ns_syms['fixture_repeat_result']['address']:'repeat_result',
                        self.ns_syms['fixture_ns_done']['address']:'done'}
                    self.fault_pc=self.addr('fixture_fault')
                    active=set(self.entries)|set(self.returns)|set(checkpoints)|{self.fault_pc}
                    veneers={v['veneer']:name for name,v in self.m['secure']['entries'].items()}
                    active.update(veneers)
                    active.update(a for b in self.m['secure']['bodies'].values() for a in b['udf'])
                    for pc in active: self.bp(pc)
                    stop=self.rsp.packet('c')
                    while True:
                        if stop.startswith('W'):
                            self.receipt['RSPExit']=stop
                            self.receipt['QemuExit']=self.process.wait(timeout=max(.01,self.deadline-time.monotonic()))
                            break
                        require(stop.startswith(('T05','S05')),'UNEXPECTED_STOP:'+stop)
                        pc=self.rsp.register('pc')&~1
                        if pc in veneers:
                            before=self.rsp.register('control_s')
                            self.bp(pc,False)
                            stop=self.rsp.packet('s')
                            require(stop.startswith(('T05','S05')) and self.rsp.register('pc')==pc+4,'ACTUAL_SG_STEP')
                            after_sg=self.rsp.register('control_s')
                            require(after_sg&8==0,'SG_DID_NOT_CLEAR_SFPA')
                            self.event('actual_sg',name=veneers[pc],control_s_before=before,control_s_after=after_sg,
                                       ipsr=self.rsp.register('xpsr')&0x1ff)
                            self.bp(pc)
                            stop=self.rsp.packet('c')
                            continue
                        if pc in checkpoints:
                            label=checkpoints[pc]
                            if label=='direct_done': self.intact(); self.direct=True
                            elif label=='wrong_done':
                                require(self.direct and self.wrong=={0,14,15},'MISSING_REAL_ORIGINS'); self.wrong_done=True
                            elif label=='first_result': require(self.focus_count==1,'FIRST_CHECKPOINT'); self.first=True
                            elif label=='repeat_result': require(self.first and self.focus_count==2,'REPEAT_CHECKPOINT'); self.repeat=True
                            elif label=='done': require(self.first and self.repeat,'INCOMPLETE_CHECKPOINTS'); self.done=True
                            self.event('checkpoint',label=label)
                        if pc==self.fault_pc:
                            require(self.trap is not None,'UNRELATED_FAULT')
                            frame=self.rsp.register('msp_s')
                            record={'pc':self.rsp.word(frame+24),'xpsr':self.rsp.word(frame+28),'frame':frame,
                                    'ipsr':self.rsp.register('xpsr')&0x1ff,'exc_return':self.rsp.register('lr'),
                                    'cfsr':self.read_policy(0xe000ed28),'hfsr':self.read_policy(0xe000ed2c)}
                            require(fault_valid(record,self.trap),'FAULT_FRAME_MISMATCH')
                            self.fault=record
                            self.event('actual_fault_entry',**record)
                        if pc in self.entries:
                            name=self.entries[pc]
                            require(self.active is None,'NESTED_GATEWAY')
                            self.active=name
                            ipsr=self.rsp.register('xpsr')&0x1ff
                            lr=self.rsp.register('lr')
                            if name==INIT_NAME:
                                if lr&1: self.phase='direct'; require(ipsr==11 and not self.direct,'DIRECT_ORIGIN')
                                elif ipsr!=11: self.phase='wrong'; self.wrong.add(ipsr)
                                else:
                                    require(self.wrong_done,'OWNED_SVC_ORDER')
                                    self.focus_count+=1
                                    self.phase='first' if self.focus_count==1 else 'repeat'
                                    self.original_masks={x:self.rsp.register(x) for x in ('primask','basepri','faultmask')}
                                    self.seed()
                                self.step=True
                                self.call_injected=False
                                self.source_effects=[]
                                self.store_counts={}
                            else:
                                self.phase='query'
                                names=list(self.m['secure']['entries'])
                                query_names=[x for x in names if x!=INIT_NAME]
                                # Stable public query order, independent of ELF symbol order.
                                query_names=['fiber_secure_gateway_c3fs_v1_'+x for x in ('abi_version','context_port_id','context_layout_version','context_feature_mask')]+[
                                    'fiber_secure_context_gateway_c3fs_v1_'+x for x in ('abi_version','stack_alignment','max_stack_bytes','max_contexts')]
                                self.before=self.snapshot()
                                self.seed(query_names.index(name))
                            if name==INIT_NAME: self.before=self.snapshot()
                            self.call_sp=self.rsp.register('sp'); self.call_r9=self.rsp.register('r9')
                            self.event('actual_entry',name=name,phase=self.phase,ipsr=ipsr,lr=lr,
                                       control_s=self.rsp.register('control_s'),control_ns=self.rsp.register('control_ns'))
                        item=self.ins.get(pc)
                        if item and item['op']=='udf':
                            immediate=int(item['args'].split('#')[1].split()[0],0)
                            if immediate==75:
                                require(self.injected and (self.case.startswith(('query-','init-cpacr')) or self.case=='init-npriv'),
                                        'UNEXPECTED_PREFLIGHT_TRAP')
                                if self.case.startswith('query-'):
                                    number=int(self.case.split('-')[1])
                                    names=['fiber_secure_gateway_c3fs_v1_'+x for x in ('abi_version','context_port_id','context_layout_version','context_feature_mask')]+[
                                        'fiber_secure_context_gateway_c3fs_v1_'+x for x in ('abi_version','stack_alignment','max_stack_bytes','max_contexts')]
                                    target=names[number]
                                else: target=INIT_NAME
                                require(self.active==target and pc in self.m['secure']['entries'][target]['udf'],'WRONG_PREFLIGHT_TRAP')
                            else:
                                require(self.injected and self.case.startswith(('trap-','scrub-','pool-state-','pool-entry-unknown')),
                                        'UNEXPECTED_FAIL_CLOSED')
                                target='fiber_secure_context_gateway_fail_closed' if self.case.startswith('trap-gate-') else 'fiber_secure_context_pool_fail_closed'
                                require(pc in self.m['secure']['bodies'][target]['udf'],'WRONG_FAIL_CLOSED_TRAP')
                            self.trap={'pc':pc,'sp':self.rsp.register('sp'),'ipsr':self.rsp.register('xpsr')&0x1ff,'immediate':immediate}
                            self.event('actual_udf',**self.trap)
                            self.step=False
                        if pc in self.returns:
                            self.returned(self.returns[pc]); self.step=False
                        if pc==self.addr('fiber_secure_context_pool_boot_initialize') and self.phase=='first':
                            self.event('actual_pool_entry')
                            self.pool_return=self.rsp.register('lr')&~1
                            self.bp(self.pool_return)
                            if self.case.startswith('pool-entry-'):
                                value={'pool-entry-unknown':1,'pool-entry-init':POOL_INIT,'pool-entry-ready':POOL_READY}[self.case]
                                self.word(self.pool_state,value); self.injected=True
                        if pc==self.pool_return:
                            self.bp(pc,False); self.pool_return=None; self.fast=False; self.step=True
                            require(self.rsp.register('r0') in (0,1),'ACTUAL_POOL_RESULT')
                            if self.rsp.register('r0')==1:
                                require(self.rsp.word(self.pool_state)==POOL_READY and self.rsp.memory(self.pool,self.pool_size)==bytes(self.pool_size),'POOL_COMPLETION')
                                self.pool_finished=True
                            if self.case in ('pool-result-0','pool-result-2'):
                                self.write_reg('r0',int(self.case[-1])); self.injected=self.tainted=True
                                self.event('injected_pool_result',forced=int(self.case[-1]))
                        if pc==self.m['secure']['pool_read'] and self.fast:
                            self.bp(pc,False)
                            require(self.rsp.memory(self.pool,self.pool_size)==bytes(self.pool_size),'WHOLE_SCRUB_BEFORE_READBACK')
                            self.event('whole_actual_scrub',bytes=self.pool_size)
                            if self.case.startswith('scrub-'):
                                target=self.pool if self.case=='scrub-first' else self.pool+self.pool_size-1
                                self.write_mem(target,b'\xa5'); self.injected=True
                                self.event('injected_RAM_corruption',address=target,value=0xa5)
                            self.bp(self.m['secure']['pool_read_done'])
                            self.step=False
                        if pc==self.m['secure']['pool_read_done'] and self.fast:
                            self.bp(pc,False); self.fast=False; self.step=True
                            if self.case=='pool-state-corrupt': self.word(self.pool_state,1); self.injected=True
                        if self.step:
                            require(item is not None,'UNDECODED_EXECUTED_PRODUCTION')
                        after=self.source_step(item) if self.step and item and item['op']!='udf' else None
                        had_bp=pc in self.breakpoints
                        if had_bp: self.bp(pc,False)
                        stop=self.rsp.packet('s')
                        if after:
                            kind,target,value=after
                            if kind=='memory': self.word(target,value)
                            else:
                                actual=self.rsp.register(target)
                                forced=(actual^value) if kind=='read' else value
                                self.write_reg(target,forced)
                                self.tainted=bool(self.source_effects)
                                self.event('injected_destination_after_actual_read',pc=pc,register=target,actual=actual,forced=forced)
                            self.injected=True
                            self.call_injected=True
                        if had_bp: self.bp(pc)
                        if self.fast or not self.step:
                            # Single-step has moved off the current breakpoint.
                            # Continue only to a declared body/return/checkpoint.
                            if not stop.startswith('W') and (self.rsp.register('pc')&~1) not in self.breakpoints:
                                stop=self.rsp.packet('c')
        except Exception as exc:
            outcome,error='REJECT',str(exc)
        finally:
            if self.process and self.process.poll() is None:
                os.killpg(self.process.pid,signal.SIGKILL)
                self.receipt['TerminationExit']=self.process.wait(timeout=2)
            if self.connection: self.connection.close()
            log=(self.directory/'qemu.log').read_text(errors='replace') if (self.directory/'qemu.log').exists() else ''
            if outcome is None:
                try:
                    if self.trap:
                        reports=re.findall(r'FAULT:C3FS-INITIALIZE PC=0x([0-9a-f]{8}) CFSR=0x([0-9a-f]{8}) HFSR=0x([0-9a-f]{8}) IPSR=0x([0-9a-f]{8}) EXC_RETURN=0x([0-9a-f]{8}) FRAME=0x([0-9a-f]{8}) XPSR=0x([0-9a-f]{8})',log)
                        require(self.fault is not None and len(reports)==1 and self.receipt.get('QemuExit')==42,'MISSING_EXACT_FAULT_REPORT')
                        values=[int(x,16) for x in reports[0]]
                        reported=dict(zip(('pc','cfsr','hfsr','ipsr','exc_return','frame','xpsr'),values))
                        require(reported==self.fault and log.count('FAULT-EXIT:C3FS-INITIALIZE\n')==1,'FAULT_REPORT_DIFFERENCE')
                        controls={}
                        for key,bit in (('pc',2),('cfsr',0x80000),('hfsr',0x40000000),('ipsr',1),('frame',4),('xpsr',1),('exc_return',0x10)):
                            changed=dict(reported); changed[key]^=bit
                            controls[key]=not fault_valid(changed,self.trap)
                        require(all(controls.values()),'FAULT_CLASSIFIER_CONTROL')
                        self.receipt['FaultClassifierControls']=controls
                        outcome='EXACT_TERMINAL'
                    else:
                        if self.control=='fp-nop':
                            require(self.first and self.repeat and not self.done and self.receipt.get('QemuExit')==91 and
                                    log.count('FAIL:C3FS-INITIALIZE:0x00000016\n')==1,'FP_NOP_CONTROL_DIAGNOSTIC')
                            outcome='FP_PROBE_CONTROL_REJECTED'
                        else:
                            require(self.done and self.receipt.get('QemuExit')==0 and log.count('PASS:C3FS-INITIALIZE:paired\n')==1 and 'FAULT:' not in log,'INCOMPLETE_PAIRED_EXECUTION')
                            outcome='SUCCESS' if self.expected_first()==1 else 'STICKY' if self.post_failure() else 'FALSE_ADMISSION'
                except Exception as exc:
                    outcome,error='REJECT',str(exc)
            expected_control={'query-preflight':'QUERY_MISSING_TERMINAL','ns-fpca':'ADMISSION_WRITE',
                              'pool-exact':'FAILED_READBACK_CONTINUED','control-exact':'FAILED_READBACK_CONTINUED'}.get(self.control)
            if expected_control:
                passed=outcome=='REJECT' and error==expected_control
            else:
                expected='FP_PROBE_CONTROL_REJECTED' if self.control=='fp-nop' else self.expected_outcome
                passed=outcome==expected
                if not passed and error is None:
                    error='CASE_OUTCOME:'+str(outcome)+'!='+expected
                if passed and self.control=='none' and self.case!='success' and not self.injected:
                    passed=False
                    error='MISSING_CASE_INJECTION'
            self.receipt.update(Verdict='PASS' if passed else 'FAIL',Outcome=outcome,Error=error,
                                DirectSecureSVC=self.direct,WrongNSOrigins=sorted(self.wrong),
                                First=self.first,Repeat=self.repeat,Done=self.done,Injected=self.injected,
                                Fault=self.fault,Trap=self.trap,QueryReturns=len(self.query_seen))
            (self.directory/'events.json').write_text(json.dumps(self.events,indent=2)+'\n')
            (self.directory/'receipt.json').write_text(json.dumps(self.receipt,indent=2)+'\n')
        require(passed,'CASE_FAILED:'+self.case+':'+str(error))
        return self.receipt


def main():
    root,secure,ns,seconds,manifest,case,control=sys.argv[1:]
    result=Execution(root,secure,ns,manifest,case,seconds,control).run()
    print(json.dumps({'Case':case,'Verdict':result['Verdict'],'Outcome':result['Outcome']}))


if __name__=='__main__':
    try: main()
    except Exception as error:
        print('REJECT:'+str(error))
        sys.exit(1)
