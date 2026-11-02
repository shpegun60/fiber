"""CM4-only A32/A33 compiler closure, transfer and constructor regression."""
import sys

if not __debug__ or sys.flags.optimize:
    raise SystemExit('CM4 compiler gate requires ordinary Python without -O/-OO')

import argparse
import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import traceback
from types import SimpleNamespace

sys.dont_write_bytecode = True
PRIOR = 'bc520c5a722ca70a461561cf30a59eb4ad8a4b3d'
PIN = 'a50edad08b29052631aa469d4df6e6ec7ff68878'
PORT = Path('fiber/port/ARM_CM4')
OPTS = ('O0', 'Og', 'O2', 'Os', 'O3')
NAKED = ('fiber_port_start_first_context', 'SVC_Handler', 'PendSV_Handler')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def load(path):
    spec = importlib.util.spec_from_file_location('cm4_closure', path)
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
        if not line or re.match(r'^\d+\s+"', line) or line.startswith('.ltorg'):
            continue
        lines.append(re.sub(r'\s+', ' ', line))
    return lines


def pool_controls(audit, module, profile, directory, flags, objects, sources):
    source = next(s for s in sources if s.name == 'fiber_port.c')
    text = audit.run([audit.gcc, *flags, '-E', source], 'actual CM4 pool-control preprocessing')
    pool = re.compile(r'"\.ltorg[^"\r\n]*"')
    require(len(pool.findall(text)) == 3, 'CM4 must contain exactly three terminal pools')
    natural = pool.sub('""', text)
    pressure = pool.sub(lambda match: match[0] + ' ".space 8192\\n"', text)
    removed = pool.sub('""', pressure)
    require(removed.count('".space 8192\\n"') == 3, 'Pool-removal control lost layout pressure')
    index = sources.index(source)
    outcomes = {}
    for name, code, must_fail in (('natural-pool-removal', natural, False),
                                  ('pressure-pools-retained', pressure, False),
                                  ('pressure-pools-removed', removed, True)):
        case = directory / name
        case.mkdir()
        mutant = case / 'actual-cm4.i'
        mutant.write_text(code, encoding='ascii')
        obj = case / 'actual-cm4.o'
        audit.run([audit.gcc, *flags, '-c', mutant, '-o', obj], 'compile actual CM4 ' + name)
        elf = module.Elf(obj)
        require(any(s['name'].startswith('.gnu.lto_') for s in elf.sections) and
                not any(s['flags'] & 4 and s['size'] for s in elf.sections), 'Pool control is not actual slim IR')
        replaced = list(objects)
        replaced[index] = obj
        target = case / 'port-native.o'
        try:
            audit.lower(profile, replaced, target, flags, True, 'unsectioned')
        except RuntimeError:
            require(must_fail or name == 'natural-pool-removal', 'Retained-pool positive failed')
            outcomes[name] = dict(status='literal-range-failure', **audit.literal_range_failure(target))
        else:
            require(not must_fail, 'Pool removal survived actual compiled layout pressure')
            outcomes[name] = dict(status='PASS', sha256=module.digest(target))
    result = dict(profile=profile['name'], source=str(source), source_sha256=module.digest(source),
                  pressure_bytes_per_terminal_pool=8192, outcomes=outcomes,
                  limit='Synthetic unreachable layout pressure; natural removal is not required to fail')
    module.write_json(directory / 'pool-controls.json', result)
    return result


def immutable_run(args):
    repo, cmsis, build = Path(args.repo).resolve(), Path(args.cmsis_core).resolve(), Path(args.build).resolve()
    root = build / 'immutable-inputs'
    files = {p for directory in (repo, repo / 'fiber', repo / 'fiber/port')
             for p in directory.iterdir() if p.is_file() and p.suffix.lower() in ('.c', '.h', '.inc')}
    files.update(p for p in (repo / PORT).iterdir() if p.is_file() and p.suffix.lower() in ('.c', '.h'))
    for name in ('cm4_raw_compiler', 'sensitive_port_closure', 'constructor_r9'):
        files.update(p for p in (repo / 'tools/fixtures' / name).rglob('*') if p.is_file())
    files.update(repo / 'tools' / name for name in
                 ('test_cm4_raw_compiler.ps1', 'test_sensitive_port_closure.ps1', 'test_constructor_r9.ps1'))
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
    command = [sys.executable, '-B', root / 'repo/tools/fixtures/cm4_raw_compiler/run.py',
               '--repo', root / 'repo', '--cmsis-core', root / 'cmsis', '--arm-gcc', args.arm_gcc,
               '--freertos', args.freertos, '--build', build, '--input-snapshot', manifest, '--history-repo', repo]
    if args.development_optimizations:
        command += ['--development-optimizations', args.development_optimizations]
    command = list(map(str, command))
    (root / 'child-command.json').write_text(json.dumps(command, indent=2) + '\n', encoding='ascii')
    print('Verified immutable CM4 gate inputs: ' + str(root), flush=True)
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

    audit = Audit(SimpleNamespace(**dict(vars(args), profiles='CM4', optimizations=','.join(options), bundles='baseline,raw',
                                       native_lto_sections='sectioned,unsectioned', all_profiles=False, audit_only=False,
                                       cm7_prefix_root=None, cm0_vtor='0')))
    profile = next(p for p in module.profiles() if p['name'] == 'CM4')
    profiles = []
    for abi, fpu, lazy in (('soft', 0, 0), ('soft', 1, 0), ('hard', 1, 0), ('softfp', 1, 1)):
        profiles.append(dict(profile, name='CM4-%s-fpu%d-lazy%d' % (abi, fpu, lazy), abi=abi, fpu=fpu,
                             fp='' if abi == 'soft' else 'fpv4-sp-d16', defines=['FIBER_FPU_LAZY=%d' % lazy]))
    report = dict(Status='FAIL', CompleteSuite=False, Scope='CM4 only; additional raw-compiler gate, not hardware qualification',
                  Limits=['Mandatory counterflag contract remains separate', 'No global all-profile raw support claim',
                          'No physical exception/FP execution or arbitrary PIC/TLS ABI claim',
                          'External memory and callback implementation closure is not supplied by the object classifier'],
                  PriorRevision=PRIOR, ReferencePin=PIN, Profiles=profiles, Optimizations=options)
    error = None
    try:
        audit.preflight()
        for path in (Path(__file__), Path(__file__).with_name('README.md'), repo / 'tools/test_cm4_raw_compiler.ps1'):
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
        failed = old.build / 'literal-range'
        failed.mkdir()
        flags = old.flags(old_profile, 'O2', True, 'baseline')
        sources, _ = old.source_paths(old_profile)
        objects = [old.compile(s, failed / (s.stem + '.o'), flags) for s in sources]
        try:
            old.lower(old_profile, objects, failed / 'port-native.o', flags, True, 'unsectioned')
        except RuntimeError:
            literal = old.literal_range_failure(failed / 'port-native.o')
        else:
            raise RuntimeError('Actual immutable prior native-LTO range failure did not reproduce')
        module.write_json(old.build / 'expected-failures.json', dict(cases=old.cases, literal=literal, inputs=old.inputs))
        # Preserve and independently drift-check every historical compiler input.
        for path in old.inputs:
            audit.track(path)
        report['PriorFailures'] = dict(raw_defects=len(old.cases[-1]['defects']), literal=literal)

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

        report['TransferChecks'] = []
        report['PoolControls'] = []
        audit.section_mode = 'sectioned'
        for p in profiles:
            for opt in ('O2', 'Os'):
                case = build / ('transfers-' + p['name'] + '-' + opt)
                case.mkdir()
                flags = audit.flags(p, opt, False, 'baseline')
                asm = case / 'actual.s'
                audit.run([audit.gcc, *flags, '-S', repo / PORT / 'fiber_port.c', '-o', asm], 'current naked bodies')
                prior_flags = old.flags(p, opt, False, 'baseline')
                prior_asm = case / 'prior.s'
                audit.run([audit.gcc, *prior_flags, '-S', historical / PORT / 'fiber_port.c', '-o', prior_asm], 'prior naked bodies')
                for symbol in NAKED:
                    a, b = asm_body(asm, symbol), asm_body(prior_asm, symbol)
                    require(a == b, 'Executable naked assembly changed beyond terminal pools: ' + symbol)
                    report['TransferChecks'].append(dict(profile=p['name'], opt=opt, symbol=symbol, instructions=len(a), match=True))
                if p['abi'] != 'soft':
                    reference = kernel / 'portable/GCC/ARM_CM4F/port.c'
                    config = repo / 'tools/fixtures/freertos_asm_parity'
                    ref_flags = [f for f in flags if f != '-g'] + ['-DFIBER_FREERTOS_PARITY_ENABLE_FPU=1',
                        '-I' + str(config), '-I' + str(kernel / 'include'), '-I' + str(reference.parent)]
                    ref_obj = audit.compile(reference, case / 'reference.o', ref_flags)
                    current_obj = audit.compile(repo / PORT / 'fiber_port.c', case / 'actual.o', flags)
                    ref_dis = audit.run([audit.tools['objdump'], '-drw', ref_obj], 'pinned CM4F transfer disassembly')
                    cur_dis = audit.run([audit.tools['objdump'], '-drw', current_obj], 'actual CM4 transfer disassembly')
                    (case / 'reference.dis').write_text(ref_dis, encoding='ascii')
                    (case / 'actual.dis').write_text(cur_dis, encoding='ascii')
                    first = [r'\bmsr\s+MSP', r'\bmsr\s+CONTROL', r'\bcpsie\s+i', r'\bcpsie\s+f', r'\bdsb\b', r'\bisb\b', r'\bsvc\s+0']
                    ordered(body(ref_dis, 'prvPortStartFirstTask'), first, 'reference first start')
                    ordered(body(cur_dis, NAKED[0]), [r'\bcpsid\s+i', r'\bmsr\s+CONTROL', r'\bmsr\s+MSP', r'\bcpsie\s+i', r'\bcpsie\s+f', r'\bdsb\b', r'\bisb\b', r'\bsvc\s+70'], 'Fiber first start')
                    restore = [r'\bldmia(?:\.w)?\s+r0!,\s*\{r4[^\n]*lr\}', r'\bmsr\s+PSP']
                    ordered(body(ref_dis, 'vPortSVCHandler'), restore + [r'\bmsr\s+BASEPRI', r'\bbx\s+lr'], 'reference first restore')
                    ordered(body(cur_dis, 'SVC_Handler'), [r'\bmsr\s+BASEPRI', 'fiber_port_context_validate_restore'] + restore + [r'\bbx\s+lr'], 'Fiber first restore')
                    save = [r'\bmrs\s+r0,\s*PSP', r'\btst(?:\.w)?\s+lr,\s*#16', r'\bvstmdb(?:eq)?\s+r0!,\s*\{s16-s31\}', r'\bstmdb\s+r0!,\s*\{r4[^\n]*lr\}', r'\bstr\s+r0', r'\bmsr\s+BASEPRI']
                    tail = restore + [r'\btst(?:\.w)?\s+lr,\s*#16', r'\bvldmia(?:eq)?\s+r0!,\s*\{s16-s31\}', r'\bmsr\s+PSP', r'\bisb\b', r'\bbx\s+lr']
                    # The PSP write follows high-FP restoration, not the GPR load.
                    tail = [restore[0]] + tail[2:]
                    ordered(body(ref_dis, 'xPortPendSVHandler'), save + ['vTaskSwitchContext', r'\bmsr\s+BASEPRI'] + tail, 'reference PendSV')
                    ordered(body(cur_dis, 'PendSV_Handler'), [r'\bmrs\s+r0,\s*PSP', 'fiber_port_context_validate_save_current'] + save[1:] + ['fiber_port_scheduler_pick_next_from_pendsv', r'\bmsr\s+BASEPRI'] + tail, 'Fiber PendSV')
                    report['TransferChecks'].append(dict(profile=p['name'], opt=opt, pinned_reference=True,
                        mechanisms=['first-start', 'first-restore', 'PendSV-GPR-and-conditional-FP'], identical_assembly_claim=False))

            pool_case = build / ('pool-controls-' + p['name'])
            pool_case.mkdir()
            flags = audit.flags(p, 'O2', True, 'baseline')
            sources, _ = audit.source_paths(p)
            objects = [audit.compile(s, pool_case / (s.stem + '.o'), flags) for s in sources]
            report['PoolControls'].append(pool_controls(audit, module, p, pool_case, flags, objects, sources))
        require(all(c['status'] == 'PASS' for c in audit.cases), 'At least one current CM4 raw compiler cell failed')
        require(len(audit.cases) == audit.planned_cells, 'Incomplete CM4 cell inventory')
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
                   '--cmsis-core', args.cmsis_core, '--build', ctor, '--profiles', 'CM4'], 'maintained actual CM4 constructor R9', timeout=1800)
        result = json.loads((ctor / 'results.json').read_text())
        require(result['Verdict'] == 'PASS' and not result['InputDrift'] and not result['Unqualified'] and
                len(result['Runs']) == 48 and len(result['Controls']) == 15 and result['ExecutionCalls'] == 252,
                'Incomplete or failing CM4 constructor inventory')
        report['Constructor'] = dict(receipt=str(ctor / 'results.json'), production_elfs=48, compiled_negative_elfs=15,
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
            error = RuntimeError('CM4 proof input drift')
        report['Commands'] = len(audit.commands)
        module.write_json(build / 'results.json', report)
        with (build / 'sha256.csv').open('w', newline='', encoding='ascii') as stream:
            writer = csv.writer(stream)
            writer.writerow(('path', 'sha256'))
            for path in sorted(build.rglob('*')):
                if path.is_file() and path != build / 'sha256.csv':
                    writer.writerow((str(path.relative_to(build)), module.digest(path)))
        print('%s CM4 cells=%d controls=%d input_drift=%d receipt=%s' %
              (report['Status'], len(audit.cases), len(audit.controls), len(report['InputDrift']), build / 'results.json'), flush=True)
    if error:
        raise SystemExit(str(error))


if __name__ == '__main__':
    main()
