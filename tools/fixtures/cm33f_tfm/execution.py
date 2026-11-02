"""Actual M33 two-image execution; Secure boot and TF-M NS provider are fixtures."""
from pathlib import Path
import re
from run import Elf, require, digest, write_json, HOSTILE, HOSTILE_LTO_DRIVER, FORWARD

PANICS = {2: 'Q', 3: 'l', 4: 'e', 5: 'E', 6: 'L', 7: 'p', 8: 'b', 9: 'f',
          10: 'i', 11: 'l', 13: 'i', 14: 'G', 15: 'K',
          16: 'p', 17: 'b', 18: 'f', 19: 'i', 20: 'e', 21: 'E',
          22: 'l', 23: 'r', 24: 'B', 25: 't', 26: 'L', 28: 'l', 30: 'p',
          31: 's', 32: 'I', 33: 'p', 34: 'b', 35: 'f', 36: 'R'}


class Execution:
    def __init__(self, proof):
        self.p = proof
        self.f = proof.fixture / 'execution'
        self.root = proof.build / 'actual-execution'
        self.root.mkdir()
        self.groups, self.runs, self.controls = {}, [], []

    def wslpath(self, path):
        return self.p.run(['wsl.exe', '-d', self.p.a.wsl_distro, '--exec', 'wslpath', '-u',
                           str(Path(path).resolve())], 'execution WSL path')['output'].strip()

    def call(self, action, output, *args, allowed=False):
        return self.p.run(['wsl.exe', '-d', self.p.a.wsl_distro, '--exec', 'bash', self.shell,
                          action, self.p.a.qemu_root, self.wslpath(output), *args],
                         'actual M33 QEMU ' + action, timeout=25, allowed=allowed)

    def secure(self):
        d = self.root / 'secure-bootstrap'
        d.mkdir()
        flags = ['-mcpu=cortex-m33', '-mthumb', '-mfloat-abi=soft', '-mgeneral-regs-only', '-mcmse',
                 '-O2', '-ffreestanding', '-fno-builtin', '-ffunction-sections', '-fdata-sections',
                 '-fno-unwind-tables', '-fno-asynchronous-unwind-tables', '-Wall', '-Wextra', '-Werror',
                 '-DEXEC_SECURE=1', '-I' + str(self.f), '-I' + str(self.p.common)]
        objects = []
        for name in ('startup.S', 'secure.c'):
            obj = d / (name + '.o')
            self.p.run([self.p.a.arm_gcc, *flags, '-c', self.f / name, '-o', obj], 'compile test-only Secure bootstrap')
            objects.append(obj)
        elf = d / 'secure.elf'
        self.p.run([self.p.a.arm_gcc, *flags, '-nostdlib', '-Wl,--gc-sections', '-Wl,--no-undefined',
                    '-T', self.f / 'secure.ld', '-Wl,-Map=' + str(elf) + '.map', *objects, '-o', elf],
                   'link test-only Secure bootstrap')
        self.p.evidence(elf)
        self.secure_path = self.wslpath(elf)

    def group(self, abi, opt, lto, lazy, reserved):
        key = (abi, opt, lto, lazy, reserved)
        if key in self.groups:
            return self.groups[key]
        self.p.flags[2] = '-mfloat-abi=' + abi
        policy = 'default-policy' if lazy is None else 'lazy%d' % lazy
        name = '%s-%s%s-%s-%s' % (abi, opt[1:].lower(), '-lto' if lto else '', policy,
                                 'reserved' if reserved else 'ordinary')
        d = self.root / name
        d.mkdir()
        options = [opt, '-D__NVIC_PRIO_BITS=8', '-DEXEC_RESERVED_R9=' + str(reserved), '-I' + str(self.f)]
        if lazy is not None:
            options.append('-DFIBER_FPU_LAZY=' + str(lazy))
        if lto:
            options.append('-flto')
        if reserved:
            options.append('-ffixed-r9')
        objects = []
        for source in self.p.common_sources + self.p.sources:
            obj = d / (source.stem + '.o')
            common = source in self.p.common_sources
            self.p.compile(source, obj, options, selected=not common, cpu=not common)
            objects.append(obj)
        for name in ('startup.S', 'tasks.S'):
            obj = d / (name + '.o')
            self.p.compile(self.f / name, obj, options, selected=False, cpu=False)
            objects.append(obj)
        if lazy is None:
            obj = d / 'default_policy.o'
            self.p.compile(self.p.fixture / 'default_policy.c', obj, options)
            objects.append(obj)
        value = dict(directory=d, objects=objects, options=options, key=key)
        self.groups[key] = value
        return value

    def image(self, group, case, name=None, source=None, replacement=None):
        self.p.flags[2] = '-mfloat-abi=' + group['key'][0]
        d = group['directory'] / (name or ('case-%02d' % case))
        d.mkdir()
        source = source or self.f / 'nonsecure.c'
        obj = d / 'application.o'
        self.p.compile(source, obj, group['options'], extra=['-DEXEC_CASE=' + str(case)])
        objects = list(group['objects'])
        if replacement:
            position, changed = replacement
            objects[position] = changed
        objects.append(obj)
        elf = d / 'nonsecure.elf'
        self.p.run([self.p.a.arm_gcc, *self.p.flags[:4], '-ffunction-sections', '-fdata-sections', *group['options'], '-nostdlib',
                    '-Wl,--gc-sections', '-Wl,--no-undefined', '-Wl,--fatal-warnings',
                    '-T', self.f / 'nonsecure.ld', '-Wl,-Map=' + str(elf) + '.map',
                    *objects, '-o', elf], 'link real common + complete C3FT execution image')
        evidence = self.p.evidence(elf)
        parsed = Elf(elf)
        require(not [s for s in parsed.symbols if s['section'] == 0 and s['name']], 'unresolved execution ELF')
        for symbol, slot in (('SVC_Handler', 11), ('PendSV_Handler', 14)):
            actual = parsed.one(symbol)
            table = parsed.one('fixture_vectors')
            import struct
            require(actual['bind'] == 1 and actual['type'] == 2 and
                    struct.unpack('<I', parsed.at(table['value'] + slot * 4, 4))[0] == actual['value'],
                    'execution must use the real strong production vector: ' + symbol)
        for symbol in ('fiber_init', 'fiber_start', 'fiber_current', 'fiber_schedule',
                       'fiber_scheduler_set_pick_next', 'fiber_internal_runtime_port_abi_v1_anchor'):
            parsed.one(symbol)
        for symbol in FORWARD:
            definition = parsed.one(symbol)
            require(definition['bind'] == 1 and definition['type'] == 2,
                    'execution does not retain the exact eight strong forward definitions: ' + symbol)
        require('Tag_CPU_arch: v8-M.mainline' in evidence['attributes'], 'execution is not M33/v8-M')
        if group['key'][3] is None:
            self.p.default_policy(elf, 8)
        return elf

    @staticmethod
    def fields(text):
        values = {}
        for name, value in re.findall(r'^([A-Z_0-9]+)=0x([0-9a-f]{8})\r?$', text, re.M):
            require(name not in values, 'duplicate execution field: ' + name)
            values[name] = int(value, 16)
        return values

    def classify(self, result, case):
        text = result['output']
        require(not result['timeout'] and result['exit'] == 0, 'execution exit/fault/timeout')
        marker = 'PASS:C3FT-EXEC:' + ('PANIC' if case in PANICS else ('CONSTRUCT' if case in (12, 29) else 'CYCLES'))
        lines = text.splitlines()
        require(lines.count(marker) == 1 and lines[-1:] == [marker] and
                not re.search(r'FAIL:|FAILED_CHECK|Lockup|fatal|Traceback', text), 'execution exact terminal report')
        f = self.fields(text)
        required = {'CASE', 'IPSR', 'CONTROL', 'PRIMASK', 'BASEPRI', 'FAULTMASK', 'PSPLIM', 'CPACR', 'FPCCR',
                    'ENTRY_CPACR', 'ENTRY_FPCCR', 'PROVIDER_CALLS', 'PICK_CALLS', 'BASIC_SAVES',
                    'EXTENDED_SAVES', 'VISIT0', 'VISIT1', 'VISIT2', 'IRQ_ENTERED', 'PENDSV_PENDING',
                    'CTX0_SP', 'MODEL_CPUID', 'MODEL_MVFR0', 'MODEL_MPU_CTRL'}
        require(required <= f.keys() and f['CASE'] == case, 'execution missing/wrong observation')
        require((f['MODEL_CPUID'] >> 4) & 0xfff == 0xd21 and f['MODEL_MPU_CTRL'] == 0,
                'execution wrong physical model/MPU state')
        if case in PANICS:
            expected_ipsr = 15 if case in (10, 13, 19, 28, 30, 32) else (14 if 20 <= case <= 26 else 0)
            require(f['IPSR'] == expected_ipsr, 'execution PANIC origin')
            require(f.get('PANIC') == ord(PANICS[case]), 'execution wrong panic boundary')
            calls = 0 if 10 <= case <= 15 or 28 <= case <= 35 else 1
            require(f['PROVIDER_CALLS'] == calls, 'execution provider admission/effect boundary')
            if case < 16 or 28 <= case <= 35:
                require(f['PICK_CALLS'] == 0 and all(f['VISIT' + str(i)] == 0 for i in range(3)),
                        'execution unexpected startup activation')
            if 20 <= case <= 26:
                require(f['PICK_CALLS'] == 2 and [f['VISIT' + str(i)] for i in range(3)] == [1, 0, 0],
                        'execution resumed Thread after callback failure')
            elif 16 <= case <= 19:
                require(f['PICK_CALLS'] == 1 and f['PENDSV_PENDING'] == 0,
                        'execution failed admission requested a context switch')
            if case in (28, 30):
                require(f.get('PANIC_ORIGIN') == 0 and f.get('PANIC_CONTROL') == 1 and f['IRQ_ENTERED'] == 1,
                        'execution unprivileged panic must stop in its genuine reporting Handler')
            if case in (2, 3, 6, 7, 8, 9, 10, 11, 13, 14, 15, 28, 30, 31, 32, 33, 34, 35):
                require(f['CPACR'] == f['ENTRY_CPACR'] and f['FPCCR'] == f['ENTRY_FPCCR'],
                        'execution admission failure reached CPU FP preparation')
            if case == 36:
                require(f['PICK_CALLS'] == 1 and all(f['VISIT' + str(i)] == 0 for i in range(3)),
                        'execution did not take the actual common task-return boundary')
        elif case in (12, 29):
            require(f['IPSR'] == 15 and f['IRQ_ENTERED'] == 1 and f['PROVIDER_CALLS'] == f['PICK_CALLS'] == 0 and
                    f['CTX0_SP'] != 0 and f['CPACR'] == f['ENTRY_CPACR'] and f['FPCCR'] == f['ENTRY_FPCCR'] and
                    all(f['VISIT' + str(i)] == 0 for i in range(3)) and
                    f.get('CONSTRUCT_ORIGIN') == (15 if case == 12 else 0) and
                    f.get('CONSTRUCT_CONTROL') == (0 if case == 12 else 1),
                    'execution constructor was not environment-neutral/prestart')
        else:
            require(f['IPSR'] == 0 and f['CONTROL'] in (2, 6) and
                    f['PRIMASK'] == f['BASEPRI'] == f['FAULTMASK'] == 0 and
                    f['PROVIDER_CALLS'] == 1 and f['BASIC_SAVES'] >= 10 and f['EXTENDED_SAVES'] >= 20 and
                    all(f['VISIT' + str(i)] >= 12 for i in range(3)), 'execution incomplete common/FP transfer cycles')
        return f

    def run_image(self, elf, case, expected=True):
        result = self.call('run', elf.parent, self.secure_path, self.wslpath(elf), '5', allowed=True)
        Path(str(elf) + '.execution.txt').write_text(result['output'])
        item = dict(elf=str(elf), sha256=digest(elf), case=case, result=result)
        if expected:
            item['observations'] = self.classify(result, case)
            self.runs.append(item)
        return item

    def negative_controls(self, group):
        base = (self.f / 'nonsecure.c').read_text()
        anchor = '    REG(0xe000ed24u) |= 7u << 16u;'
        require(base.count(anchor) == 1, 'execution classifier control anchor drift')
        for name, injection, case, rejection in (
            ('counterfeit-thread-handler-panic', "fiber_panic('e');", 20, 'execution PANIC origin'),
            ('unrelated-fault', '__asm volatile("udf #1");', 0, 'execution exit/fault/timeout'),
            ('missing-observations', 'report_exit(0u, "PASS:C3FT-EXEC:CYCLES\\n");', 0, 'execution missing/wrong observation'),
            ('timeout', 'for (;;) __asm volatile("nop");', 0, 'execution exit/fault/timeout')):
            source = group['directory'] / (name + '.c')
            source.write_text(base.replace(anchor, anchor + '\n    ' + injection))
            elf = self.image(group, case, name=name, source=source)
            item = self.run_image(elf, case, expected=False)
            result = item['result']
            fields = self.fields(result['output'])
            if name == 'unrelated-fault':
                fn = Elf(elf).one('fixture_ns_main')
                begin = fn['value'] & ~1
                require(not result['timeout'] and result['exit'] == 24 and
                        result['output'].splitlines()[-1:] == ['FAIL:C3FT-EXEC:FAULT'] and
                        fields.get('IPSR') == 6 and fields.get('CFSR') == 0x10000 and fields.get('HFSR') == 0 and
                        fields.get('EXC_RETURN') == 0xffffffb8 and fields.get('STACKED_XPSR', 0) & 0x1000000 and
                        fields['STACKED_XPSR'] & 0x1ff == 0 and
                        begin <= fields.get('FAULT_PC', 0) < begin + fn['size'] and
                        Elf(elf).at(fields['FAULT_PC'], 2) == b'\x01\xde',
                        'unrelated-fault control did not reach its own exact basic NS Thread/MSP UDF')
            elif name == 'timeout':
                require(not result['timeout'] and result['exit'] == 124 and not fields and
                        '(timeout)' in result['output'] and 'PASS:' not in result['output'],
                        'timeout control did not reach the bounded QEMU timeout')
            elif name == 'missing-observations':
                require(result['exit'] == 0 and result['output'] == 'PASS:C3FT-EXEC:CYCLES\n',
                        'missing-observations control did not emit its lone counterfeit marker')
            else:
                require(result['exit'] == 0 and fields.get('IPSR') == fields.get('CONTROL') == 0 and
                        fields.get('PANIC') == ord('e'), 'counterfeit Thread panic control wrong path')
            try:
                self.classify(item['result'], case)
            except RuntimeError as error:
                require(str(error) == rejection, 'compiled execution classifier control wrong rejection: ' + str(error))
            else:
                raise RuntimeError('execution classifier falsely accepted ' + name)
            item['rejection'] = rejection
            self.controls.append(item)

    def raw_fixture(self, group):
        self.p.flags[2] = '-mfloat-abi=' + group['key'][0]
        for case in (0, 10, 11, 28, 36):
            obj = group['directory'] / ('raw-fixture-%02d.o' % case)
            self.p.compile(self.f / 'nonsecure.c', obj, group['options'],
                           extra=[*HOSTILE, '-DEXEC_CASE=' + str(case)])
            if group['key'][2]:
                lowered = group['directory'] / ('raw-fixture-%02d-lowered.o' % case)
                self.p.role_group([obj], lowered, group['options'] + HOSTILE_LTO_DRIVER, lower=True)
                obj = lowered
            require(not self.p.compiler_dependencies(obj), 'raw fixture callback/helper compiler dependency')
            evidence = self.p.evidence(obj)
            self.p.fp_transfer_scan(evidence['dis'])
            self.fixture_objects.append(dict(object=str(obj), case=case, abi=group['key'][0], flags=HOSTILE))

    def transfer_mutants(self, group):
        abi, opt, lto, lazy, reserved = group['key']
        self.p.flags[2] = '-mfloat-abi=' + abi
        tests = [
            ('lost-high-save', 3, self.p.sources[0], 'vstmdb r0!, {s16-s31}', 'sub r0, r0, #64', 0, range(316, 332)),
            ('lost-high-restore', 3, self.p.sources[0], 'vldmia r0!, {s16-s31}', 'add r0, r0, #64', 0, range(316, 332)),
            ('clobber-restored-r4', 3, self.p.sources[0], 'ldmia r0!, {r2-r11}',
             'ldmia r0!, {r2-r11}\\nmovs r4,#0', 0, (200,)),
            ('lost-auto-tfm-init', 3, self.p.sources[0], 'fiber_port_tfm_require_initialized();', '(void)0;', 0, (141,)),
            ('lost-init-control-readback', 5, self.p.sources[2],
             "FIBER_REQUIRE(fiber_port_cpu_control() == before->control, 'l');", '(void)before;', 3, None),
            ('lost-init-cpacr-readback', 5, self.p.sources[2],
             "FIBER_REQUIRE(fiber_portCPACR_REG == before->cpacr, 'e');", '(void)before;', 4, None),
            ('lost-init-fpccr-readback', 5, self.p.sources[2],
             "FIBER_REQUIRE(fiber_portFPCCR_REG == before->fpccr, 'E');", '(void)before;', 5, None),
        ]
        if reserved:
            tests = [('wrong-reserved-r9-seed', 3, self.p.sources[0],
                      'frame[fiber_portFRAME_R9] = fiber_port_read_r9();',
                      'frame[fiber_portFRAME_R9] = 0u;', 0, (163,))]
        else:
            tests += [('caller-r9-corruption', 7, self.f / 'startup.S', ' bl fiber_init\n',
                       ' bl fiber_init\n eor r9,r9,#1\n', 0, (161,))]
        for name, index, original, old, new, case, failed_checks in tests:
            target = self.groups[(abi, opt, lto, 0, 0)] if name.startswith('lost-high-') else group
            text = original.read_text()
            require(text.count(old) == (2 if name == 'clobber-restored-r4' else 1),
                    'actual execution mutant anchor drift: ' + name)
            source = target['directory'] / (name + original.suffix)
            head, sep, tail = text.rpartition(old)
            require(sep == old, 'missing exact execution mutant instruction')
            source.write_text(head + new + tail)
            obj = source.with_suffix('.o')
            assembly = source.suffix == '.S'
            self.p.compile(source, obj, target['options'], selected=not assembly, cpu=not assembly)
            elf = self.image(target, case, name=name, replacement=(index, obj))
            item = self.run_image(elf, case, expected=False)
            result = item['result']
            if failed_checks is not None:
                codes = re.findall(r'^FAILED_CHECK=0x([0-9a-f]{8})\r?$', result['output'], re.M)
                require(not result['timeout'] and result['exit'] == 23 and len(codes) == 1 and
                        int(codes[0], 16) in failed_checks and result['output'].endswith('FAIL:C3FT-EXEC\n'),
                        'actual compiled transfer mutant wrong failure: ' + name + '\n' + result['output'])
                item['rejection'] = 'FAILED_CHECK=' + codes[0]
            else:
                require(result['exit'] == 0 and result['output'].splitlines()[-1:] == ['PASS:C3FT-EXEC:CYCLES'],
                        'readback mutant must reach its forbidden later activation: ' + name)
                try:
                    self.classify(result, case)
                except RuntimeError as error:
                    require(str(error) == 'execution exact terminal report', 'readback mutant wrong oracle rejection')
                else:
                    raise RuntimeError('actual readback failure silently accepted: ' + name)
                item['rejection'] = 'missing required pre-activation panic'
            item['mutant'] = name
            self.mutants.append(item)

    def runtime_inspect(self, name):
        d = self.root / name
        d.mkdir()
        self.call('inspect', d)
        return (d / 'runtime-dependencies.sha256').read_text()

    def execute(self):
        require(self.p.a.qemu_root.startswith('/'), 'explicit existing absolute WSL QemuRoot required')
        self.shell = self.wslpath(self.f / 'qemu.sh')
        self.mutants, self.fixture_objects = [], []
        runtime_before = self.runtime_inspect('qemu-before')
        baseline = None
        complete = False
        try:
            self.secure()
            for abi in ('softfp', 'hard'):
                for opt in ('-O2', '-Os'):
                    for lto in (False, True):
                        for lazy in (0, 1, None):
                            for reserved in (0, 1):
                                g = self.group(abi, opt, lto, lazy, reserved)
                                self.run_image(self.image(g, 0), 0)
                                if lazy == 1 and reserved == 0:
                                    if baseline is None:
                                        baseline = g
                                    for case in range(1, 37):
                                        self.run_image(self.image(g, case), case)
                                    self.raw_fixture(g)
                                    self.transfer_mutants(g)
                                elif lazy == 1 and reserved == 1:
                                    self.transfer_mutants(g)
                        print('C3FT actual M33 common/FP execution PASS %s %s LTO=%s' % (abi, opt, lto), flush=True)
            self.negative_controls(baseline)
            complete = True
            return dict(status='PASS', machine='mps2-an505', runs=self.runs, controls=self.controls,
                        mutants=self.mutants, raw_fixture_objects=self.fixture_objects,
                        limitation='Test-only Secure bootstrap grants NS memory/FP; typed NS TF-M provider, not a real Secure TF-M image.')
        finally:
            runtime_after = self.runtime_inspect('qemu-after')
            write_json(self.root / 'execution.receipt.json', dict(runs=self.runs, controls=self.controls,
                       mutants=self.mutants, raw_fixture_objects=self.fixture_objects,
                       status='PASS' if complete and runtime_before == runtime_after else 'FAIL',
                       runtime_before=runtime_before, runtime_after=runtime_after,
                       completed_runs=len(self.runs), completed_controls=len(self.controls)))
            require(runtime_before == runtime_after, 'actual QEMU runtime dependency drift')
