"""Actual M33/M55 scalar Secure object proofs; no runtime promotion."""
import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

if sys.flags.optimize or not __debug__:
    raise SystemExit("REJECT:PYTHON:optimization is unsupported")

HERE = Path(__file__).resolve().parent
SHARED = HERE.parent / 'cm55_tfm_parity'
sys.path.append(str(SHARED))
spec = importlib.util.spec_from_file_location('c5tf_proof', SHARED / 'run.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
from elf import require


class Proof(base.Proof):
    def __init__(self, a):
        super().__init__(a)
        self.fixture = HERE
        self.mode = a.mode
        m55 = a.mode == 'C5SO'
        self.port = self.repo / {'A30':'fiber/port/ARM_CM33/non_secure',
            'C3SO':'fiber/port/ARM_CM33_SECURE_ONLY/secure','C5SO':'fiber/port/ARM_CM55_SECURE_ONLY/secure'}[a.mode]
        self.ref = Path(a.reference) / {'A30':'portable/GCC/ARM_CM33/non_secure',
            'C3SO':'portable/GCC/ARM_CM33_NTZ/non_secure','C5SO':'portable/GCC/ARM_CM55_NTZ/non_secure'}[a.mode]
        self.secure_ref = Path(a.reference)/('portable/GCC/ARM_CM55/secure' if m55 else 'portable/GCC/ARM_CM33/secure')
        self.common = ['-mcpu=cortex-m55' if m55 else '-mcpu=cortex-m33', '-mthumb', '-mfloat-abi=soft', '-std=gnu11',
            a.optimization, '-g0', '-ffreestanding', '-fno-builtin', '-fno-common',
            '-ffunction-sections', '-fdata-sections', '-save-temps=obj', '-MMD']
        self.fiber = self.common + (['-mcmse'] if a.mode != 'A30' else []) + [
            '-Wall', '-Wextra', '-Werror', '-Wundef', '-DFIBER_PORT_BUILD_SELECTED=1',
            '-DFIBER_PORT_ARMV81M_MAINLINE=1' if m55 else '-DFIBER_PORT_ARMV8M_MAINLINE=1'] + ['-I'+str(p) for p in (
                self.build, self.port, self.repo/'fiber/port', self.repo/'fiber', self.repo, a.cmsis)]
        self.reference = self.common + (['-mcmse'] if a.mode != 'A30' else []) + [
            '-DFIBER_FREERTOS_PARITY_ENABLE_TRUSTZONE='+str(int(a.mode == 'A30')),
            '-DFIBER_FREERTOS_PARITY_SECURE_ONLY='+str(int(a.mode != 'A30'))] + [
            '-I'+str(p) for p in (self.config, Path(a.reference)/'include', self.ref,
                                  self.secure_ref)]

    def snapshot(self):
        paths = {Path(__file__), self.repo/'tools/freertos_asm_parity.ps1',
                 self.repo/'FREERTOS_ASM_PARITY.md', Path(self.a.arm_gcc), *self.tools.values()}
        if os.name == 'nt':
            name = ctypes.create_unicode_buffer(32768)
            require(ctypes.windll.kernel32.GetModuleFileNameW(None,name,len(name)) > 0,
                    'PROVENANCE','cannot locate actual Python module')
            paths.add(Path(name.value))
        else:
            paths.add(Path(sys.executable))
        if self.mode == 'A30':
            paths.update(self.repo/'fiber/port/ARM_CM33/secure'/n for n in (
                'fiber_secure_context_gateway_contract.h','fiber_secure_gateway_contract.h'))
        for root in (HERE, SHARED, self.port, self.repo, self.repo/'fiber', self.repo/'fiber/port',
                     self.ref, self.config, Path(self.a.reference)/'include', Path(self.a.cmsis),
                     self.secure_ref):
            paths.update(p for p in root.iterdir() if p.is_file() and p.suffix in ('.py','.json','.c','.h','.ld','.md')
                         and (root != self.repo or p.name in ('mcu_core.h','basic_types.h','FREERTOS_ASM_PARITY.md')))
        for tool in ('cc1','as'):
            paths.add(Path(self.command([self.a.arm_gcc, '-print-prog-name='+tool], 'locate '+tool)['Output'].strip()).resolve())
        include = Path(self.command([self.a.arm_gcc, '-print-file-name=include'], 'compiler headers')['Output'].strip())
        paths.update(include.rglob('*.h'))
        paths.update((self.bin.parent/'arm-none-eabi/include').rglob('*.h'))
        self.live = [dict(Path=str(p.resolve()), Sha256=base.digest(p)) for p in sorted(paths)]
        self.inputs = []
        (self.build/'documentation').mkdir()
        for row in self.live:
            item = dict(row)
            if Path(row['Path']).suffix == '.md':
                target = self.build/'documentation'/('%04d-' % len(self.inputs)+Path(row['Path']).name)
                target.write_bytes(Path(row['Path']).read_bytes())
                require(base.digest(target) == row['Sha256'], 'DRIFT', 'documentation snapshot changed')
                item.update(Path=str(target), SourcePath=row['Path'], Role='DocumentationSnapshot')
            self.inputs.append(item)
        base.write(self.build/'inputs.before.json', self.inputs)

    def check_controls(self, manifest):
        diagnostic = 'REJECT:PYTHON:optimization is unsupported'
        controls = []
        for module in ('run.py','check.py','mutants.py','machine.py'):
            path = HERE/module
            for flag in ('-O','-OO'):
                r = self.command([sys.executable,'-B',flag,path], 'optimized '+module, allow=True)
                require(self.exact_rejection(r, diagnostic), 'CONTROL', module+'/'+flag)
                controls.append(module+'/'+flag)
            saved = os.environ.get('PYTHONOPTIMIZE')
            try:
                for level in ('1','2'):
                    os.environ['PYTHONOPTIMIZE'] = level
                    r = self.command([sys.executable,'-B',path], 'environment '+module, allow=True)
                    require(self.exact_rejection(r, diagnostic), 'CONTROL', module+'/environment')
                    controls.append(module+'/environment'+level)
            finally:
                if saved is None: os.environ.pop('PYTHONOPTIMIZE',None)
                else: os.environ['PYTHONOPTIMIZE'] = saved
            for level in (1,2):
                code = "from pathlib import Path; import sys; p=sys.argv[1]; exec(compile(Path(p).read_text(),p,'exec',optimize=%d),{'__name__':'compiled_import'})" % level
                r = self.command([sys.executable,'-B','-c',code,path], 'compiled '+module, allow=True)
                require(self.exact_rejection(r, diagnostic), 'CONTROL', module+'/compiled')
                controls.append(module+'/compiled'+str(level))
        for flag in ('-O','-OO'):
            r = self.command([sys.executable,'-B',flag,HERE/'check.py','--behavior-only',manifest], 'optimized classifier', allow=True)
            require(self.exact_rejection(r, diagnostic), 'CONTROL', 'classifier optimization')
            controls.append('classifier/'+flag)
        for code in ('BODY','BRANCH','PYTHON'):
            message = 'REJECT:'+code+':counterfeit'
            r = self.command([sys.executable,'-B','-c','raise RuntimeError('+repr(message)+')'], 'counterfeit', allow=True)
            require(not self.rejected(r), 'CONTROL', 'traceback accepted')
            controls.append('counterfeit/'+code)
        for module in ('run.py','check.py'):
            old = 'raise SystemExit("'+diagnostic+'")'
            text = (HERE/module).read_text()
            require(text.count(old) == 1,'CONTROL','guard mutation anchor')
            path = self.build/('counterfeit-'+module)
            path.write_text(text.replace(old,'raise RuntimeError("'+diagnostic+'")'),encoding='ascii')
            r = self.command([sys.executable,'-B','-O',path], 'actual counterfeit guard', allow=True)
            require(not self.rejected(r),'CONTROL','actual traceback accepted')
            controls.append(module+'/actual-counterfeit')
        return controls

    @staticmethod
    def rejected(r, behavior=False):
        codes = 'BRANCH' if behavior else 'BODY|DEPENDENCY|RELOC|DECODE|INVENTORY|BRANCH|INSTRUCTION'
        return r['ExitCode'] == 1 and re.fullmatch(r'REJECT:(?:'+codes+r'):[^\r\n]+\n?',r['Output']) is not None

    def run(self):
        self.snapshot()
        passed, mutants, controls, independent = False, [], [], []
        try:
            self.command([self.a.arm_gcc,'--version'],'compiler version')
            base.write(self.build/'python.json',dict(Executable=sys.executable,Version=sys.version))
            sources = [('Fiber',self.port/'fiber_port.c',self.fiber),('Boot',self.port/'fiber_port_boot.c',self.fiber),
                ('Reference',self.ref/'portasm.c',self.reference),('ReferenceConstructor',self.ref/'port.c',self.reference)]
            if self.mode == 'A30':
                sources += [('Handlers',self.port/'fiber_port_svc.c',self.fiber),
                            ('Attachment',self.port/'fiber_port_secure_context.c',self.fiber)]
            manifest = dict(Mode=self.mode, Optimization=self.a.optimization, Receipt=str(self.build/'result.json'))
            source_map = {}
            for key, source, flags in sources:
                source_map[key] = source, flags
                manifest[key] = self.compile(source,key,flags)
                manifest[key+'Disassembly'] = manifest[key]+'.dis'
            manifest['Geometry'] = self.compile(HERE/'geometry.c','Geometry',self.fiber)
            manifest['GeometryDisassembly'] = manifest['Geometry']+'.dis'
            path = self.build/'check.json'
            base.write(path,manifest)
            self.command([sys.executable,'-B',HERE/'check.py',path], 'closed actual-source comparison')
            result = json.loads((self.build/'result.json').read_text())
            positive = self.command([sys.executable,'-B',HERE/'check.py','--behavior-only',path], 'independent positive')
            require(positive['Output'] == 'PASS SCALAR_BRANCH_ONLY scenarios=%d (not a parity receipt)\n' % result['Scenarios'],
                    'CONTROL','independent positive diagnostic')
            from mutants import cases
            for case in cases(self.mode):
                name, side, old, new, count, behavior = case
                source, flags = source_map[side]
                text = source.read_text()
                require(text.count(old) == count,'MUTANT','anchor changed '+name+'/'+str(text.count(old)))
                copy = self.build/('mutant-'+name+'.c')
                copy.write_text(text.replace(old,new),encoding='ascii')
                obj = self.compile(copy,'mutant-'+name,flags)
                negative = dict(manifest)
                negative.update({side:obj,side+'Disassembly':obj+'.dis','Receipt':obj+'.unexpected-pass.json'})
                negative_path = Path(obj+'.json')
                base.write(negative_path,negative)
                r = self.command([sys.executable,'-B',HERE/'check.py',negative_path], 'reject '+name, allow=True)
                require(self.rejected(r),'MUTANT','survived/unintended diagnostic '+name+'/'+r['Output'])
                mutants.append(dict(Name=name,Diagnostic=r['Output'].strip()))
                if behavior:
                    r = self.command([sys.executable,'-B',HERE/'check.py','--behavior-only',negative_path], 'independent reject '+name, allow=True)
                    require(self.rejected(r,True),'MUTANT','independent branch oracle '+name+'/'+r['Output'])
                    independent.append(dict(Name=name,Diagnostic=r['Output'].strip()))
            controls = self.check_controls(path)
            self.dependency_closure()
            passed = True
        finally:
            drift = [r for r in self.live+self.inputs if not Path(r['Path']).exists() or base.digest(r['Path']) != r['Sha256']]
            base.write(self.build/'status.json',dict(Status='PASS' if passed and not drift else 'INCOMPLETE',Mode=self.mode,
                SourceDrift=drift,Mutants=mutants,IndependentBranchMutants=independent,Controls=controls,RuntimeProfileAdded=False))
            require(not drift,'DRIFT','source changed; no qualification')
        artifacts = [dict(Path=str(p.resolve()),Sha256=base.digest(p)) for p in sorted(self.build.rglob('*')) if p.is_file() and p.name != 'artifacts.json']
        base.write(self.build/'artifacts.json',dict(Status='PASS',ReferenceCommit='a50edad08b29052631aa469d4df6e6ec7ff68878',Inputs=self.inputs,Artifacts=artifacts))
        print('PASS %s %s: %d closed bodies, %d branch scenarios, %d compiled mutants (%d independent), %d controls; %s' %
              (self.mode,self.a.optimization,result['Functions'],result['Scenarios'],len(mutants),len(independent),len(controls),self.build))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    for name in ('repo','arm-gcc','cmsis','reference','build'): p.add_argument('--'+name,required=True)
    p.add_argument('--optimization',choices=('-O2','-Os'),required=True)
    p.add_argument('--mode',choices=('A30','C3SO','C5SO'),required=True)
    Proof(p.parse_args()).run()
