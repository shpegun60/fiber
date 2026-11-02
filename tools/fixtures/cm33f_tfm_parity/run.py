"""Actual-source C3FT/M33_NTZ FP proof, not CPU or TF-M execution."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

if sys.flags.optimize or not __debug__:
    raise SystemExit("REJECT:PYTHON:optimization is unsupported")

HERE = Path(__file__).resolve().parent
SHARED = HERE.parent / 'cm55_tfm_parity'
sys.path.append(str(SHARED))
spec = importlib.util.spec_from_file_location('c3ft_proof_base', SHARED / 'run.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
require, digest, write = base.require, base.digest, base.write
PIN = 'a50edad08b29052631aa469d4df6e6ec7ff68878'


class Proof(base.Proof):
    def __init__(self, a):
        super().__init__(a)
        self.fixture = HERE
        self.port = self.repo / 'fiber/port/ARM_CM33F_TFM/non_secure'
        self.ref = Path(a.reference) / 'portable/GCC/ARM_CM33_NTZ/non_secure'
        self.common = ['-mcpu=cortex-m33', '-mthumb', '-mfpu=fpv5-sp-d16',
            '-mfloat-abi='+a.float_abi, '-std=gnu11', a.optimization, '-g0',
            '-ffreestanding', '-fno-builtin', '-fno-common', '-ffunction-sections',
            '-fdata-sections', '-save-temps=obj', '-MMD']
        self.fiber = self.common + ['-Wall', '-Wextra', '-Werror', '-Wundef',
            '-DFIBER_PORT_BUILD_SELECTED=1', '-DFIBER_PORT_ARMV8M_MAINLINE=1'] + [
            '-I'+str(p) for p in (self.build, self.port, self.repo/'fiber/port',
                                 self.repo/'fiber', self.repo, a.cmsis)]
        self.reference = self.common + ['-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1'] + [
            '-I'+str(p) for p in (self.config, Path(a.reference)/'include', self.ref, SHARED)]
        self.independent = []

    def snapshot(self):
        expected = {'fiber_port.c', 'fiber_portmacro.h', 'fiber_port_boot.c', 'fiber_port_boot.h',
            'fiber_port_boot_types.h', 'fiber_port_private.h', 'fiber_port_tfm.c', 'fiber_port_tfm_abi.h',
            'fiber_port_tfm_os_wrapper.c', 'fiber_port_tfm_os_wrapper.h', 'fiber_port_types.h', 'FREERTOS_PARITY.md'}
        actual = {p.name for p in self.port.iterdir() if p.is_file() and p.suffix in ('.c','.h','.ld','.md')}
        require(actual == expected, 'C3FT production inventory changed: '+str(actual ^ expected))
        paths = {self.repo/'tools/freertos_asm_parity.ps1', self.repo/'FREERTOS_ASM_PARITY.md',
                 Path(self.a.arm_gcc), *self.tools.values()}
        paths.update(p for p in HERE.rglob('*') if p.is_file() and '__pycache__' not in p.parts)
        paths.update(SHARED / n for n in ('run.py','elf.py','mutants.py','os_wrapper/mutex.h'))
        paths.add(HERE.parent/'cm33_secure_parity/machine.py')
        paths.add(HERE.parent/'cm33f_mpu_running_parity/check.py')
        for root in (self.port, self.repo, self.repo/'fiber', self.repo/'fiber/port',
                     self.ref, self.tfm, self.config, Path(self.a.reference)/'include', Path(self.a.cmsis)):
            paths.update(p for p in root.iterdir() if p.is_file() and p.suffix in ('.c','.h','.ld','.md')
                and (root != self.repo or p.name in ('mcu_core.h','basic_types.h','FREERTOS_ASM_PARITY.md')))
        for tool in ('cc1','as'):
            p = self.command([self.a.arm_gcc,'-print-prog-name='+tool], 'locate '+tool)['Output'].strip()
            paths.add(Path(p).resolve())
        include = self.command([self.a.arm_gcc,'-print-file-name=include'], 'compiler headers')['Output'].strip()
        paths.update(p for p in Path(include).rglob('*.h'))
        paths.update(p for p in (self.bin.parent/'arm-none-eabi/include').rglob('*.h'))
        self.live = [dict(Path=str(p.resolve()),Sha256=digest(p)) for p in sorted(paths)]
        self.inputs = []
        docs = self.build/'documentation'
        docs.mkdir()
        for row in self.live:
            item = dict(row)
            if Path(row['Path']).suffix == '.md':
                target = docs/('%04d-' % len(self.inputs)+Path(row['Path']).name)
                target.write_bytes(Path(row['Path']).read_bytes())
                require(digest(target) == row['Sha256'], 'document snapshot drift')
                item.update(Path=str(target),SourcePath=row['Path'],Role='DocumentationSnapshot')
            self.inputs.append(item)
        write(self.build/'inputs.before.json',self.inputs)

    def pin(self):
        root = str(Path(self.a.reference).resolve())
        git = ['git','--no-optional-locks','-c','core.fsmonitor=false','-C',root]
        require(self.command(git+['rev-parse','HEAD'],'reference commit')['Output'].strip() == PIN, 'reference commit drift')
        require(not self.command(git+['status','--porcelain=v1','--untracked-files=all','--ignored=matching'],
                                 'reference status')['Output'].strip(), 'reference is not clean')
        tree = self.command(git+['ls-tree','-r','HEAD'],'reference tree')['Output'].splitlines()
        rows = []
        for line in tree:
            m = re.fullmatch(r'100(?:644|755) blob ([0-9a-f]{40})\t(.+)',line)
            if m:
                rows.append(m.groups())
            else:
                require(re.fullmatch(r'160000 commit [0-9a-f]{40}\t.+',line), 'unsupported reference entry')
        args = git+['hash-object','--stdin-paths']
        data = ''.join(path+'\n' for _,path in rows)
        p = subprocess.run(args,input=data,text=True,errors='replace',stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT,timeout=120)
        row = dict(Command=args,Input=data,Label='hash every pinned regular file',ExitCode=p.returncode,Output=p.stdout)
        write(self.build/('command-%04d.json' % len(self.commands)),row)
        self.commands.append(row)
        require(p.returncode == 0 and p.stdout.splitlines() == [sha for sha,_ in rows], 'pinned tracked content drift')

    def sources(self):
        return (
            ('Fiber',self.port/'fiber_port.c',self.fiber),
            ('Boot',self.port/'fiber_port_boot.c',self.fiber),
            ('Init',self.port/'fiber_port_tfm.c',self.fiber),
            ('Wrapper',self.port/'fiber_port_tfm_os_wrapper.c',self.fiber),
            ('Reference',self.ref/'portasm.c',self.reference),
            ('ReferenceConstructor',self.ref/'port.c',self.reference),
            ('ReferenceWrapper',self.tfm/'os_wrapper_freertos.c',self.reference),
            ('ReferenceFpuProbe',self.ref/'port.c',self.reference+['-fno-inline']),
            ('Configuration',HERE/'configuration.c',self.reference),
            ('Geometry',HERE/'geometry.c',self.fiber))

    def compile_inputs(self):
        manifest = dict(Optimization=self.a.optimization,FloatAbi=self.a.float_abi,
                        Receipt=str(self.build/'result.json'))
        for key,source,flags in self.sources():
            manifest[key] = self.compile(source,key,flags)
            manifest[key+'Disassembly'] = manifest[key]+'.dis'
        path = self.build/'check.json'
        write(path,manifest)
        return manifest,path

    def mutate(self, manifest):
        from mutants import cases, INDEPENDENT
        source_map = {key:(src,flags) for key,src,flags in self.sources()}
        for name,side,marker,old,new,*count in cases():
            source,flags = source_map[side]
            text = source.read_text(encoding='utf-8')
            start,end = 0,len(text)
            if marker:
                start = text.rfind(marker)
                require(start >= 0,'mutant function missing: '+name)
                indent = text[text.rfind('\n',0,start)+1:start]
                require(not indent.strip(),'mutant declaration anchor: '+name)
                close = re.search(r'(?m)^'+re.escape(indent)+r'\}',text[start:])
                require(close is not None,'mutant function end missing: '+name)
                end = start+close.end()
            part = text[start:end]
            require(part.count(old) == (count[0] if count else 1),'mutant anchor changed: '+name+'/'+str(part.count(old)))
            copied = self.build/('mutant-'+name+'.c')
            copied.write_text(text[:start]+part.replace(old,new)+text[end:],encoding='utf-8')
            obj = self.compile(copied,'mutant-'+name,flags)
            negative = dict(manifest)
            negative.update({side:obj,side+'Disassembly':obj+'.dis','Receipt':obj+'.unexpected-pass.json'})
            path = Path(obj+'.json')
            write(path,negative)
            r = self.command([sys.executable,'-B',HERE/'check.py',path],'reject '+name,allow=True)
            require(self.mutant_rejection(r),'mutant survived or wrong diagnostic: '+name+'/'+r['Output'])
            self.mutants.append(dict(Name=name,Manifest=str(path),Diagnostic=r['Output'].strip()))
            if name in INDEPENDENT:
                r = self.command([sys.executable,'-B',HERE/'check.py','--oracles-only',path],
                                 'independent reject '+name,allow=True)
                require(self.oracle_rejection(r),'independent oracle accepted mutant or wrong diagnostic: '+name+'/'+r['Output'])
                self.independent.append(dict(Name=name,Diagnostic=r['Output'].strip()))
        require({r['Name'] for r in self.independent} == INDEPENDENT,'independent mutant inventory')

    @staticmethod
    def oracle_rejection(r):
        return r['ExitCode'] == 1 and re.fullmatch(r'REJECT:(?:CONSTRUCTOR|FP_TRANSFER|FPU|POLICY|SYMBOLIC):[^\r\n]+\n?',r['Output']) is not None

    def controls_check(self, manifest):
        diagnostic = 'REJECT:PYTHON:optimization is unsupported'
        for name in ('run.py','check.py','oracles.py','mutants.py'):
            path = HERE/name
            for flag in ('-O','-OO'):
                r = self.command([sys.executable,'-B',flag,path],'optimized guard '+name+flag,allow=True)
                require(self.exact_rejection(r,diagnostic),'optimized guard failed')
                self.controls.append(name+flag)
            saved = os.environ.get('PYTHONOPTIMIZE')
            try:
                for level in ('1','2'):
                    os.environ['PYTHONOPTIMIZE'] = level
                    r = self.command([sys.executable,'-B',path],'environment guard '+name+level,allow=True)
                    require(self.exact_rejection(r,diagnostic),'environment guard failed')
                    self.controls.append(name+'/environment'+level)
            finally:
                if saved is None:
                    os.environ.pop('PYTHONOPTIMIZE',None)
                else:
                    os.environ['PYTHONOPTIMIZE'] = saved
            for level in (1,2):
                code = "from pathlib import Path;import sys;p=sys.argv[1];exec(compile(Path(p).read_text(),p,'exec',optimize=%d),{'__name__':'compiled_import'})" % level
                r = self.command([sys.executable,'-B','-c',code,path],'compiled import '+name+str(level),allow=True)
                require(self.exact_rejection(r,diagnostic),'compiled optimized import guard failed')
                self.controls.append(name+'/compiled'+str(level))
        for flag in ('-O','-OO'):
            r = self.command([sys.executable,'-B',flag,HERE/'check.py','--oracles-only',manifest],
                             'optimized oracle mode',allow=True)
            require(self.exact_rejection(r,diagnostic),'oracle-mode guard failed')
            self.controls.append('oracle-mode'+flag)
        for message in (diagnostic,'REJECT:BODY:counterfeit','REJECT:POLICY:counterfeit'):
            r = self.command([sys.executable,'-B','-c','raise RuntimeError('+repr(message)+')'],
                             'traceback counterfeit',allow=True)
            require(not self.exact_rejection(r,message) and not self.mutant_rejection(r) and not self.oracle_rejection(r),
                    'traceback counterfeit accepted')
            self.controls.append('counterfeit/'+message)
        for name in ('run.py','check.py'):
            text = (HERE/name).read_text()
            anchor = 'raise SystemExit("'+diagnostic+'")'
            require(text.count(anchor) == 1,'guard counterfeit anchor changed')
            path = self.build/('counterfeit-'+name)
            path.write_text(text.replace(anchor,'raise RuntimeError("'+diagnostic+'")'),encoding='ascii')
            r = self.command([sys.executable,'-B','-O',path],'actual guard traceback counterfeit',allow=True)
            require(not self.exact_rejection(r,diagnostic),'actual RuntimeError counterfeit accepted')
            self.controls.append(name+'/actual-RuntimeError-counterfeit')

    def run(self):
        self.snapshot()
        passed = False
        try:
            self.pin()
            self.command([self.a.arm_gcc,'--version'],'compiler version')
            manifest,path = self.compile_inputs()
            self.command([sys.executable,'-B',HERE/'check.py',path],'closed actual-source comparison')
            self.command([sys.executable,'-B',HERE/'check.py','--oracles-only',path],'independent positive')
            self.runs.append(manifest)
            self.mutate(manifest)
            self.controls_check(path)
            self.dependency_closure()
            passed = True
        finally:
            drift = [r for r in self.live+self.inputs if not Path(r['Path']).exists() or digest(r['Path']) != r['Sha256']]
            write(self.build/'inputs.drift.json',drift)
            write(self.build/'status.json',dict(Status='PASS' if passed and not drift else 'INCOMPLETE',
                Optimization=self.a.optimization,FloatAbi=self.a.float_abi,SourceDrift=drift,
                Mutants=self.mutants,IndependentMutants=self.independent,Controls=self.controls,RuntimeProfileAdded=False))
            require(not drift,'C3FT inputs changed; no qualification')
        artifacts = [dict(Path=str(p.resolve()),Sha256=digest(p)) for p in sorted(self.build.rglob('*'))
                     if p.is_file() and p.name != 'artifacts.json']
        write(self.build/'artifacts.json',dict(Status='PASS',ReferenceCommit=PIN,Inputs=self.inputs,Artifacts=artifacts))
        result = json.loads((self.build/'result.json').read_text())
        print('PASS C3FT %s/%s bodies=%d scenarios=%d mutants=%d independent=%d controls=%d; %s' %
            (self.a.optimization,self.a.float_abi,result['Functions'],sum(result['Scenarios'].values()),
             len(self.mutants),len(self.independent),len(self.controls),self.build))


def main():
    p = argparse.ArgumentParser()
    for name in ('repo','arm-gcc','cmsis','reference','build'):
        p.add_argument('--'+name,required=True)
    p.add_argument('--optimization',choices=('-O2','-Os'),required=True)
    p.add_argument('--float-abi',choices=('hard','softfp'),required=True)
    a = p.parse_args()
    build = Path(a.build)
    build.mkdir(parents=True,exist_ok=True)
    require(not any(build.iterdir()),'C3FT proof requires a fresh empty build root')
    # Compile boundary only: real CMSIS implementation and actual production headers.
    (build/'main.h').write_text('''#define __MPU_PRESENT 0U
#define __VTOR_PRESENT 1U
#define __NVIC_PRIO_BITS 4U
#define __FPU_PRESENT 1U
#define __DSP_PRESENT 1U
#define __SAUREGION_PRESENT 1U
#define __Vendor_SysTickConfig 0U
typedef enum IRQn {NonMaskableInt_IRQn=-14,HardFault_IRQn=-13,
MemoryManagement_IRQn=-12,BusFault_IRQn=-11,UsageFault_IRQn=-10,SecureFault_IRQn=-9,
SVCall_IRQn=-5,DebugMonitor_IRQn=-4,PendSV_IRQn=-2,SysTick_IRQn=-1,Device_IRQn=0} IRQn_Type;
#include "core_cm33.h"
''',encoding='ascii')
    Proof(a).run()


if __name__ == '__main__':
    main()
