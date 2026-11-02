"""CM33 TF-M A32 helper closure, unchanged transfers and constructor regression."""
import sys

if not __debug__ or sys.flags.optimize:
    raise SystemExit('CM33TFM compiler gate requires ordinary Python without -O/-OO')

import argparse
import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import traceback
from types import SimpleNamespace

sys.dont_write_bytecode = True
PRIOR = '62dca07736a0f50f5f399dff3314dbdfc6e57ce8'
PIN = 'a50edad08b29052631aa469d4df6e6ec7ff68878'
PORT = Path('fiber/port/ARM_CM33_TFM/non_secure')
OPTS = ('O0', 'Og', 'O2', 'Os', 'O3')
NAKED = ('fiber_port_start_first_context', 'SVC_Handler', 'PendSV_Handler')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def load(path):
    spec = importlib.util.spec_from_file_location('cm33_tfm_closure', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def body(dis, symbol):
    match = re.search(r'(?m)^\s*[0-9a-f]+ <' + re.escape(symbol) + r'>:\n', dis)
    require(match is not None, 'Missing native function ' + symbol)
    rest = dis[match.end():]
    end = re.search(r'(?m)^\s*[0-9a-f]+ <[^>]+>:', rest)
    return rest[:end.start()] if end else rest


def ordered(text, patterns, label):
    cursor = 0
    for pattern in patterns:
        found = re.search(pattern, text[cursor:], re.I)
        require(found is not None, label + ' missing ordered mechanism ' + pattern)
        cursor += found.end()


def asm_body(path, symbol):
    text = path.read_text(encoding='ascii')
    start = re.search(r'(?m)^' + re.escape(symbol) + r':\s*$', text)
    require(start is not None, 'Missing compiled assembly body ' + symbol)
    end = re.search(r'(?m)^\s*\.size\s+' + re.escape(symbol) + r'\s*,', text[start.end():])
    require(end is not None, 'Missing assembly size ' + symbol)
    text = text[start.end():start.end() + end.start()]
    chunks = re.findall(r'(?m)^@ \d+ "[^\r\n]+" 1\n(.*?)^@ 0 "" 2\s*$', text, re.S)
    require(len(chunks) == 1, 'Expected one actual naked inline-asm block ' + symbol)
    lines = []
    for line in chunks[0].splitlines():
        line = line.split('@', 1)[0].strip()
        if not line or re.match(r'^\d+\s+"', line):
            continue
        lines.append(re.sub(r'\s+', ' ', line))
    return lines


def immutable_run(args):
    repo, cmsis, build = Path(args.repo).resolve(), Path(args.cmsis_core).resolve(), Path(args.build).resolve()
    root = build / 'immutable-inputs'
    files = {p for directory in (repo, repo / 'fiber', repo / 'fiber/port')
             for p in directory.iterdir() if p.is_file() and p.suffix.lower() in ('.c', '.h', '.inc')}
    files.update(load(repo / 'tools/runtime_sources.py').get_runtime_source_inputs(repo,
                 ('engine', 'state', 'panic', 'optional_configuration', 'legacy_compat', 'facade_bridge')))
    files.update((repo / 'context').glob('*.h'))
    files.update(p for p in (repo / PORT).iterdir() if p.is_file() and p.suffix.lower() in ('.c', '.h'))
    for name in ('cm33_tfm_raw_compiler', 'sensitive_port_closure', 'constructor_r9'):
        files.update(p for p in (repo / 'tools/fixtures' / name).rglob('*') if p.is_file())
    files.update(repo / 'tools' / name for name in
                 ('test_cm33_tfm_raw_compiler.ps1', 'test_sensitive_port_closure.ps1', 'test_constructor_r9.ps1'))
    files.add(repo / 'tools/fixtures/freertos_asm_parity/FreeRTOSConfig.h')
    files.update(p for p in cmsis.rglob('*') if p.is_file())
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest().upper()
    before = {p: digest(p) for p in files}
    rows = []
    for path in sorted(files):
        target = (root / 'cmsis' / path.relative_to(cmsis) if path.is_relative_to(cmsis)
                  else root / 'repo' / path.relative_to(repo))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
        require(digest(target) == before[path], 'Input changed while capturing immutable bytes: ' + str(path))
        rows.append(dict(original=str(path), copy=str(target), sha256=before[path]))
    require(all(digest(path) == value for path, value in before.items()), 'Inputs changed while capturing snapshot')
    manifest = root / 'manifest.json'
    manifest.write_text(json.dumps(dict(files=rows, policy='Only copied bytes are compilation/execution inputs; later live edits do not qualify as these inputs'), indent=2) + '\n', encoding='ascii')
    command = [sys.executable, '-B', root / 'repo/tools/fixtures/cm33_tfm_raw_compiler/run.py',
               '--repo', root / 'repo', '--cmsis-core', root / 'cmsis', '--arm-gcc', args.arm_gcc,
               '--freertos', args.freertos, '--build', build, '--input-snapshot', manifest, '--history-repo', repo]
    if args.development_optimizations:
        command += ['--development-optimizations', args.development_optimizations]
    command = list(map(str, command))
    (root / 'child-command.json').write_text(json.dumps(command, indent=2) + '\n', encoding='ascii')
    print('Verified immutable CM33TFM gate inputs: ' + str(root), flush=True)
    return subprocess.run(command).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'arm-gcc', 'cmsis-core', 'freertos', 'build'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--development-optimizations')
    parser.add_argument('--input-snapshot', help=argparse.SUPPRESS)
    parser.add_argument('--history-repo', help=argparse.SUPPRESS)
    args = parser.parse_args()
    repo, build, kernel = Path(args.repo).resolve(), Path(args.build).resolve(), Path(args.freertos).resolve()
    build.mkdir(parents=True, exist_ok=True)
    if not args.input_snapshot:
        raise SystemExit(immutable_run(args))
    module = load(repo / 'tools/fixtures/sensitive_port_closure/run.py')
    options = args.development_optimizations.split(',') if args.development_optimizations else list(OPTS)
    require(bool(options) and len(set(options)) == len(options) and set(options) <= set(OPTS), 'Invalid optimization list')

    class Audit(module.Audit):
        section_mode = 'sectioned'

        def flags(self, profile, opt, lto, bundle):
            result = super().flags(profile, opt, lto, bundle)
            if self.section_mode == 'unsectioned':
                result = [f for f in result if f != '-ffunction-sections'] + ['-fno-function-sections']
            return result

    audit = Audit(SimpleNamespace(**dict(vars(args), profiles='CM33TFM', optimizations=','.join(options), bundles='baseline,raw',
                                       native_lto_sections='sectioned,unsectioned', all_profiles=False, audit_only=False,
                                       cm7_prefix_root=None, cm0_vtor='0')))
    profile = next(p for p in module.profiles() if p['name'] == 'CM33TFM')
    profiles = [dict(profile, name='C3TF-default', expected_policy=[1, 0, 1]),
                dict(profile, name='C3TF-hash0-map0-rewind0', expected_policy=[0, 0, 0], defines=[
                    'FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=0',
                    'FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=0', 'FIBER_REWIND_MSP=0']),
                dict(profile, name='C3TF-hash1-map1', expected_policy=[1, 1, 1], defines=[
                    'FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=1',
                    'FIBER_VALIDATE_ADDRESS_MAP_ON_SWITCH=1', 'FIBER_REWIND_MSP=1'])]
    report = dict(Status='FAIL', CompleteSuite=False, Scope='CM33TFM only; additional raw-compiler gate, not hardware qualification',
                  Limits=['Mandatory counterflag contract remains separate', 'No global all-profile raw support claim',
                          'No physical exception/FP execution or arbitrary PIC/TLS ABI claim',
                          'External memory and callback implementation closure is not supplied by the object classifier'],
                  PriorRevision=PRIOR, ReferencePin=PIN, Profiles=profiles, Optimizations=options)
    error = None
    try:
        audit.preflight()
        for path in (Path(__file__), Path(__file__).with_name('README.md'), repo / 'tools/test_cm33_tfm_raw_compiler.ps1'):
            audit.track(path)
        audit.run([audit.gcc, '--version'], 'compiler version')
        require(audit.run(['git', '-C', kernel, 'rev-parse', 'HEAD'], 'reference pin').strip() == PIN, 'Wrong reference pin')
        require(not audit.run(['git', '-C', kernel, 'status', '--porcelain'], 'reference clean state').strip(), 'Dirty reference')
        historical = build / 'prior-repo'
        for directory in (Path('.'), Path('fiber'), Path('fiber/port')):
            for source in (repo / directory).iterdir():
                if source.is_file() and source.suffix.lower() in ('.c', '.h', '.inc'):
                    target = historical / directory / source.name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    audit.track(source)
                    shutil.copyfile(source, target)
                    audit.track(target)
        prior_manifest = []
        for source in sorted((repo / PORT).glob('*')):
            if source.suffix.lower() not in ('.c', '.h'):
                continue
            audit.track(source)
            relative = PORT / source.name
            data = audit.run(['git', '-C', args.history_repo, 'show', PRIOR + ':' + relative.as_posix()], 'immutable prior ' + str(relative))
            target = historical / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(data, encoding='ascii', newline='\n')
            audit.track(target)
            prior_manifest.append(dict(path=str(target), revision=PRIOR, sha256=module.digest(target)))
        module.write_json(build / 'prior-source.json', prior_manifest)

        # Reproduce real old-source failures, not an invented parallel model.
        old = Audit(audit.a)
        old.repo, old.build = historical, build / 'prior-failures'
        old.build.mkdir()
        old_profile = dict(profile)
        old.case(old_profile, 'O2', False, 'baseline')
        require(old.cases[-1]['status'] == 'PASS', 'Immutable prior baseline control is not clean')
        old.case(old_profile, 'O2', False, 'raw')
        require(any(d.get('family') == 'instrument' for d in old.cases[-1]['defects']), 'Prior instrumentation leak did not reproduce')
        module.write_json(old.build / 'expected-failures.json', dict(cases=old.cases, inputs=old.inputs))
        for path in old.inputs:
            audit.track(path)
        report['PriorFailures'] = dict(raw_defects=len(old.cases[-1]['defects']),
                                       receipt=str(old.build / 'expected-failures.json'))

        audit.planned_cells = len(profiles) * len(options) * 4 * 2
        for p in profiles:
            for opt in options:
                for lto in (False, True):
                    for section in ('sectioned', 'unsectioned'):
                        audit.section_mode = section
                        # Base case labels only distinguish section modes for LTO.
                        selected = p if lto or section == 'sectioned' else dict(p, name=p['name'] + '-normal-unsectioned')
                        for bundle in ('baseline', 'raw'):
                            audit.case(selected, opt, lto, bundle, section)

        report['TransferChecks'], report['Geometry'], report['InlineControls'] = [], [], []
        audit.section_mode = 'sectioned'
        config = repo / 'tools/fixtures/freertos_asm_parity'
        reference_dir = kernel / 'portable/GCC/ARM_CM33_NTZ/non_secure'
        wrapper = kernel / 'portable/ThirdParty/GCC/ARM_TFM/os_wrapper_freertos.c'
        exports = {'os_wrapper_mutex_create', 'os_wrapper_mutex_acquire', 'os_wrapper_mutex_release', 'os_wrapper_mutex_delete'}
        for p in profiles:
            for opt in OPTS:
                case = build / ('transfers-' + p['name'] + '-' + opt)
                case.mkdir()
                flags = audit.flags(p, opt, False, 'baseline')
                asm, prior_asm = case / 'actual.s', case / 'prior.s'
                audit.run([audit.gcc, *flags, '-S', repo / PORT / 'fiber_port.c', '-o', asm], 'current naked bodies')
                prior_flags = old.flags(p, opt, False, 'baseline')
                audit.run([audit.gcc, *prior_flags, '-S', historical / PORT / 'fiber_port.c', '-o', prior_asm], 'prior naked bodies')
                for symbol in NAKED:
                    actual, previous = asm_body(asm, symbol), asm_body(prior_asm, symbol)
                    require(actual == previous, 'Naked inline assembly changed: ' + symbol)
                    report['TransferChecks'].append(dict(profile=p['name'], opt=opt, symbol=symbol, instructions=len(actual), match=True))
                geometry = audit.compile(Path(__file__).with_name('geometry.c'), case / 'geometry.o', flags)
                elf = module.Elf(geometry)
                symbols = [row for row in elf.objects if row['name'] == 'tfm_raw_geometry']
                require(len(symbols) == 1 and symbols[0]['size'] == 60, 'Wrong actual geometry symbol')
                symbol = symbols[0]
                data = elf.payload(elf.sections[symbol['section']])[symbol['value']:symbol['value'] + symbol['size']]
                values = list(struct.unpack('<15I', data))
                require(values == [1, 0x43335446, 0x10001, 0x82, 10, 1, 72, 76, 76, 4, 0xFFFFFFBC, 0xFFFFFFB8] + p['expected_policy'],
                        'Runtime-selectable/context identity or geometry changed')
                report['Geometry'].append(dict(profile=p['name'], opt=opt, actual=values))
                if opt not in ('O2', 'Os'):
                    continue
                ref_flags = flags + ['-I' + str(config), '-I' + str(kernel / 'include'), '-I' + str(reference_dir)]
                reference = audit.compile(reference_dir / 'portasm.c', case / 'reference.o', ref_flags)
                actual_obj = audit.compile(repo / PORT / 'fiber_port.c', case / 'actual.o', flags)
                ref_dis = audit.run([audit.tools['objdump'], '-drw', reference], 'actual pinned NTZ transfer disassembly')
                cur_dis = audit.run([audit.tools['objdump'], '-drw', actual_obj], 'actual C3TF transfer disassembly')
                (case / 'reference.dis').write_text(ref_dis, encoding='ascii')
                (case / 'actual.dis').write_text(cur_dis, encoding='ascii')
                ordered(body(ref_dis, 'vStartFirstTask'), [r'\bmsr\s+MSP', r'\bcpsie\s+i', r'\bcpsie\s+f', r'\bdsb\b', r'\bisb\b', r'\bsvc\s+\d+'], 'reference first start')
                ordered(body(cur_dis, NAKED[0]), [r'\bcpsid\s+i', r'\bmsr\s+CONTROL', r'\bmsr\s+MSP', r'\bcpsie\s+f', r'\bcpsie\s+i', r'\bdsb\b', r'\bisb\b', r'\bsvc\s+70'], 'Fiber first start')
                ordered(body(ref_dis, 'vRestoreContextOfFirstTask'), [r'\bldmia\s+r0!,\s*\{r1,\s*r2\}', r'\bmsr\s+PSPLIM', r'\bmsr\s+CONTROL', r'\badds\s+r0,\s*#32', r'\bmsr\s+PSP', r'\bmsr\s+BASEPRI', r'\bbx\s+r2'], 'reference first restore')
                ordered(body(cur_dis, 'SVC_Handler'), [r'\bmsr\s+BASEPRI', 'fiber_port_context_validate_restore', r'\bldmia(?:\.w)?\s+r0!,\s*\{r2,\s*r3[^\n]*fp\}', r'\bmsr\s+PSPLIM', r'\bmrs\s+[^,]+,\s*PSPLIM', r'\bmsr\s+CONTROL', r'\bmsr\s+PSP', r'\bbx\s+r3'], 'Fiber first restore')
                restore_pattern = r'\bldmia(?:\.w)?\s+r0!,\s*\{r2[^\n]*fp\}'
                save = r'\bstmdb\s+r0!,\s*\{r2[^\n]*fp\}'
                ordered(body(ref_dis, 'PendSV_Handler'), [r'\bmrs\s+r0,\s*PSP', r'\bmrs\s+r2,\s*PSPLIM', r'\bmov\s+r3,\s*lr', save, r'\bstr\s+r0', r'\bmsr\s+BASEPRI', 'vTaskSwitchContext', r'\bmsr\s+BASEPRI', restore_pattern, r'\bmsr\s+PSPLIM,\s*r2', r'\bmsr\s+PSP,\s*r0', r'\bbx\s+r3'], 'reference PendSV')
                ordered(body(cur_dis, 'PendSV_Handler'), [r'\bmrs\s+r0,\s*PSP', 'fiber_port_context_validate_save_current', r'\bmrs\s+r3,\s*PSPLIM', save, r'\bstr\s+r0', r'\bmsr\s+BASEPRI', 'fiber_port_scheduler_pick_next_from_pendsv', r'\bmsr\s+BASEPRI', restore_pattern, r'\bmsr\s+PSPLIM,\s*r2', r'\bmrs\s+r1,\s*PSPLIM', r'\bmsr\s+PSP,\s*r0', r'\bmrs\s+r1,\s*PSP', r'\bbx\s+r3'], 'Fiber PendSV')
                wrapper_obj = audit.compile(wrapper, case / 'reference-wrapper.o', ref_flags + ['-I' + str(Path(__file__).parent)])
                wrapper_elf = module.Elf(wrapper_obj)
                require(exports <= {f['name'] for f in wrapper_elf.functions}, 'Reference wrapper export mismatch')
                undefined = {row['name'] for row in wrapper_elf.symbols if row['section'] == 0 and row['name']}
                require({'xQueueCreateMutexStatic', 'xQueueSemaphoreTake', 'xQueueGenericSend', 'vQueueDelete'} <= undefined,
                        'Reference wrapper no longer uses the pinned semaphore mechanisms')
                actual_wrapper = audit.compile(repo / PORT / 'fiber_port_tfm_os_wrapper.c', case / 'actual-wrapper.o', flags)
                actual_elf = module.Elf(actual_wrapper)
                require(exports <= {f['name'] for f in actual_elf.functions}, 'Actual wrapper export mismatch')
                imports = sorted({row['name'] for row in actual_elf.symbols if row['section'] == 0 and row['name']})
                require(not any(name.startswith(('xQueue', 'vQueue', 'pvPortMalloc', 'vPortFree')) for name in imports),
                        'Static cooperative wrapper acquired a kernel/heap dependency')
                report['TransferChecks'].append(dict(profile=p['name'], opt=opt, pinned_reference=True,
                    mechanisms=['first-start', 'first-restore', 'PendSV', 'wrapper-ABI-and-semaphore-versus-static-policy'],
                    reference_wrapper_undefined=sorted(undefined), actual_wrapper_undefined=imports,
                    first_restore_delta='Reference discards eight GPR words; Fiber restores all seeded GPRs'))

        for p in profiles:
            for opt in ('O2', 'Os'):
                for lto in (False, True):
                    for section in ('sectioned', 'unsectioned'):
                        audit.section_mode = section
                        directory = build / ('inline-only-' + p['name'] + '-' + opt + '-' + str(lto) + '-' + section)
                        directory.mkdir()
                        original = repo / PORT / 'fiber_portmacro.h'
                        data = original.read_bytes()
                        mutated, removed = re.subn(rb'\bFIBER_API_ATTR_INLINE_SENSITIVE\b', b'', data)
                        require(removed > 0 and mutated.count(b'FIBER_GENERAL_REGS_ONLY') == data.count(b'FIBER_GENERAL_REGS_ONLY') and
                                mutated.count(b'FIBER_API_ATTR_SENSITIVE') == data.count(b'FIBER_API_ATTR_SENSITIVE'), 'Inline-only mutant changed GRO/non-inline policy')
                        for source in (repo / PORT).iterdir():
                            if source.suffix.lower() in ('.c', '.h'):
                                (directory / source.name).write_bytes(mutated if source == original else source.read_bytes())
                        flags = audit.flags(p, opt, lto, 'raw')
                        sources, _ = audit.source_paths(p)
                        objects = [audit.compile(directory / source.name, directory / (source.stem + '.o'), flags) for source in sources]
                        target = directory / 'port-native.o'
                        dis = audit.lower(p, objects, target, flags, lto, section)
                        classification = module.inspect(target, dis)
                        require(any(d['kind'] == 'function-hook' and d['family'] == 'instrument' for d in classification['defects']),
                                'Compiled actual inline-only mutant did not expose instrumentation')
                        module.write_json(directory / 'classification.json', classification)
                        report['InlineControls'].append(dict(profile=p['name'], opt=opt, native_lto=lto, text_layout=section,
                            removed=removed, gro_retained=True, source_sha256=module.digest(original), mutant_sha256=module.digest(directory / original.name)))
        require(all(c['status'] == 'PASS' for c in audit.cases), 'At least one current CM33TFM raw compiler cell failed')
        require(len(audit.cases) == audit.planned_cells, 'Incomplete CM33TFM cell inventory')
        report['Cells'] = audit.cases
        report['Controls'] = audit.controls

        ctor = build / 'constructor-r9'
        ctor.mkdir()
        runner = repo / 'tools/fixtures/constructor_r9/run.py'
        for path in runner.parent.glob('*'):
            if path.is_file():
                audit.track(path)
        audit.track(repo / 'tools/test_constructor_r9.ps1')
        audit.run([sys.executable, '-B', runner, '--repo', repo, '--arm-gcc', audit.gcc,
                   '--cmsis-core', args.cmsis_core, '--build', ctor, '--profiles', 'CM33TFM'], 'maintained actual CM33TFM constructor R9', timeout=1800)
        result = json.loads((ctor / 'results.json').read_text())
        require(result['Verdict'] == 'PASS' and not result['InputDrift'] and not result['Unqualified'] and
                len(result['Runs']) == 16 and len(result['Controls']) == 5 and result['ExecutionCalls'] == 84,
                'Incomplete or failing CM33TFM constructor inventory')
        report['Constructor'] = dict(receipt=str(ctor / 'results.json'), production_elfs=16, compiled_negative_elfs=5,
                                     calls=result['ExecutionCalls'], restore_slices=result['RestoreSlices'], scoped_subset=True)
        report['Status'] = 'PASS'
        report['CompleteSuite'] = not args.development_optimizations
    except Exception as exc:
        error = exc
        report['Error'], report['Traceback'] = str(exc), traceback.format_exc()
    finally:
        after = {path: module.digest(path) if Path(path).is_file() else None for path in audit.inputs}
        report['Inputs'] = [dict(path=p, before_sha256=h, after_sha256=after[p], captured_bytes=audit.input_copies.get(p)) for p, h in sorted(audit.inputs.items())]
        report['InputDrift'] = [p for p, h in audit.inputs.items() if after[p] != h]
        snapshot = json.loads(Path(args.input_snapshot).read_text(encoding='ascii'))
        report['InputSnapshot'] = dict(manifest=args.input_snapshot, files=len(snapshot['files']), policy=snapshot['policy'])
        report['OriginalInputDrift'] = [row['original'] for row in snapshot['files']
                                        if not Path(row['original']).is_file() or module.digest(row['original']) != row['sha256']]
        if report['InputDrift']:
            report['Status'], report['CompleteSuite'] = 'FAIL', False
            error = RuntimeError('CM33TFM proof input drift')
        report['Commands'] = len(audit.commands)
        module.write_json(build / 'results.json', report)
        with (build / 'sha256.csv').open('w', newline='', encoding='ascii') as stream:
            writer = csv.writer(stream)
            writer.writerow(('path', 'sha256'))
            for path in sorted(build.rglob('*')):
                if path.is_file() and path != build / 'sha256.csv':
                    writer.writerow((str(path.relative_to(build)), module.digest(path)))
        print('%s CM33TFM cells=%d controls=%d input_drift=%d receipt=%s' %
              (report['Status'], len(audit.cases), len(audit.controls), len(report['InputDrift']), build / 'results.json'), flush=True)
    if error:
        raise SystemExit(str(error))


if __name__ == '__main__':
    main()
