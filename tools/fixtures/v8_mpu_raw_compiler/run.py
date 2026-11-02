"""Immutable four-group v8 MPU extension of the maintained raw closure gate."""
import sys

OPT_ERROR = 'Disable PYTHONOPTIMIZE and do not use -O/-OO for v8 MPU raw compiler proof'
if not __debug__ or sys.flags.optimize:
    raise SystemExit(OPT_ERROR)

import argparse
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import traceback

sys.dont_write_bytecode = True
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
GROUPS = ('CM33MPU', 'CM55MPU', 'CM55FMPU', 'CM55MVEFMPU')
OPTS = ('O0', 'Og', 'O2', 'Os', 'O3')


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n', encoding='ascii')


def load_engine(repo):
    path = repo / 'tools/fixtures/sensitive_port_closure/run.py'
    spec = importlib.util.spec_from_file_location('v8_mpu_closure_engine', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def variants(engine):
    selected = [p for p in engine.profiles() if p['name'] in GROUPS]
    need({p['name'] for p in selected} == set(GROUPS), 'Missing maintained MPU group')
    result = []
    for original in selected:
        need(original['kind'] in ('mpu', 'fpmpu'), 'Unexpected group mechanics')
        for regions in (8, 16):
            for abi in ('hard', 'softfp') if original['fpu'] else ('soft',):
                p = dict(original, name=original['name'] + '-r%d-' % regions + abi,
                         abi=abi, base_name=original['name'], total_regions=regions, vtor=1)
                p['defines'] = [re.sub(r'(_MPU_TOTAL_REGIONS=)8$', r'\g<1>' + str(regions), d)
                                for d in original['defines']]
                need(sum(d.endswith('_MPU_TOTAL_REGIONS=' + str(regions)) for d in p['defines']) == 1,
                     'Region variant did not change the exact manifest')
                result.append(p)
    need(len(result) == 12, 'Expected twelve exact group/region/FP-ABI variants')
    return result


def make_snapshot(args):
    repo, cmsis, build = (Path(x).resolve() for x in (args.repo, args.cmsis_core, args.build))
    engine = load_engine(repo)
    admitted = variants(engine)
    root = build / 'immutable-inputs'
    root.mkdir()
    files = set(repo.glob('*.h')) | set((repo / 'fiber').rglob('*.h'))
    files |= set((repo / 'fiber').glob('*.c')) | set(cmsis.rglob('*.h'))
    spec = importlib.util.spec_from_file_location('v8_mpu_runtime_sources', repo / 'tools/runtime_sources.py')
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    files.update(reader.get_runtime_source_inputs(repo,
                 ('engine', 'state', 'panic', 'optional_configuration', 'legacy_compat', 'facade_bridge')))
    files.update((repo / 'context').glob('*.h'))
    files |= {repo / 'fiber/port/fiber_port_context_cohort_expectation.c'}
    for p in admitted:
        files |= {f for f in (repo / 'fiber/port' / p['directory']).iterdir() if f.is_file()}
    for fixture in ('sensitive_port_closure', 'v8_mpu_raw_compiler'):
        files |= {f for f in (repo / 'tools/fixtures' / fixture).iterdir() if f.is_file()}
    files |= {repo / 'tools/test_sensitive_port_closure.ps1', repo / 'tools/test_v8_mpu_raw_compiler.ps1'}
    rows = []
    for source in sorted(files):
        try:
            target = root / 'cmsis' / source.relative_to(cmsis)
        except ValueError:
            target = root / 'repo' / source.relative_to(repo)
        data = source.read_bytes()
        value = hashlib.sha256(data).hexdigest().upper()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        need(sha(source) == value and sha(target) == value, 'Input drift during snapshot: ' + str(source))
        rows.append(dict(original=str(source), copy=str(target), sha256=value))
    manifest = root / 'manifest.json'
    write_json(manifest, dict(files=rows, policy='Only these immutable copies are compiler inputs'))
    command = [sys.executable, '-B', str(root / 'repo/tools/fixtures/v8_mpu_raw_compiler/run.py'),
               '--repo', str(root / 'repo'), '--cmsis-core', str(root / 'cmsis'),
               '--arm-gcc', args.arm_gcc, '--build', str(build), '--optimizations', args.optimizations,
               '--input-snapshot', str(manifest)]
    write_json(build / 'immutable-launch.json', dict(command=command, manifest_sha256=sha(manifest)))
    return subprocess.run(command).returncode


def execute(args):
    repo, build = Path(args.repo).resolve(), Path(args.build).resolve()
    engine = load_engine(repo)
    admitted = variants(engine)
    opts = args.optimizations.split(',')
    need(opts and len(set(opts)) == len(opts) and set(opts) <= set(OPTS), 'Invalid optimization subset')
    # The maintained classifier, ordinary-cold common exception, flags, lowering,
    # real-function mutants and dependency capture are reused unchanged.
    class Audit(engine.Audit):
        def case(self, p, opt, lto, bundle, section_mode='sectioned'):
            super().case(p, opt, lto, bundle, section_mode)
            if bundle != 'raw' or opt not in ('O2', 'Os'):
                return
            port_sources, _ = self.source_paths(p)
            flags = self.flags(p, opt, lto, bundle)
            mode = 'native-lto-' + section_mode if lto else 'normal'
            label = p['name'] + '-' + opt + '-' + mode + '-' + bundle
            directory = build / label / 'cpu-inline-only-removal'
            directory.mkdir()
            header = port_sources[0].parent / 'fiber_portmacro.h'
            original = header.read_bytes()
            pattern = rb'(FIBER_API_ATTR_INLINE_SENSITIVE)( FIBER_GENERAL_REGS_ONLY\s+fiber_portFORCE_INLINE (?:uint32_t|void) fiber_port_cpu_\w+\s*\()'
            mutant, count = re.subn(pattern, rb'\2', original)
            need(count == 9 and mutant.count(b'FIBER_GENERAL_REGS_ONLY') == original.count(b'FIBER_GENERAL_REGS_ONLY')
                 and mutant.count(b'FIBER_API_ATTR_SENSITIVE') == original.count(b'FIBER_API_ATTR_SENSITIVE'),
                 'CPU-only attribute mutant must remove exactly nine bundles, retain GRO and non-inline bundles')
            for source in port_sources[0].parent.iterdir():
                if source.suffix in ('.c', '.h'):
                    (directory / source.name).write_bytes(mutant if source == header else source.read_bytes())
            objects = [self.compile(directory / source.name, directory / (source.stem + '.o'), flags)
                       for source in port_sources]
            target = directory / 'port-native.o'
            dis = self.lower(p, objects, target, flags, lto, section_mode)
            classified = engine.inspect(target, dis)
            need(any(d['kind'] == 'function-hook' and d['family'] == 'instrument'
                     for d in classified['defects']), 'CPU-only attribute removal did not expose actual instrumentation')
            engine.write_json(directory / 'classification.json', classified)
            self.controls.append(dict(case=label, kind='actual-cpu-inline-only-bundle-removal',
                                      annotations_removed=count, gro_retained=True,
                                      original_header_sha256=sha(header), mutant_header_sha256=sha(directory / header.name),
                                      expected='function-hook:instrument'))

    # Finish() reports this exact twelve-variant inventory, not all repository ports.
    engine.profiles = lambda: admitted
    args.profiles = ','.join(p['name'] for p in admitted)
    args.all_profiles = False
    args.bundles = 'baseline,raw'
    args.native_lto_sections = 'sectioned,unsectioned'
    args.cm0_vtor = '0'
    args.cm7_prefix_root = None
    args.audit_only = False
    audit = Audit(args)
    complete = False
    try:
        audit.preflight()
        audit.track(__file__)
        audit.track(repo / 'tools/test_v8_mpu_raw_compiler.ps1')
        audit.planned_cells = len(admitted) * len(opts) * 3 * 2
        for p in admitted:
            for opt in opts:
                for lto, layout in ((False, 'sectioned'), (True, 'sectioned'), (True, 'unsectioned')):
                    for bundle in ('baseline', 'raw'):
                        audit.case(p, opt, lto, bundle, layout)
        complete = True
    except Exception as error:
        audit.errors.append(dict(error=str(error), traceback=traceback.format_exc()))
    status = audit.finish(complete)
    path = build / 'results.json'
    receipt = json.loads(path.read_text())
    receipt['CompleteSuite'] = complete and set(opts) == set(OPTS) and receipt['Status'] == 'PASS'
    receipt['Scope'] = 'Four selected v8 MPU source groups; 8/16 regions, scalar soft or FP hard/softfp; raw compiler closure only'
    receipt['ExternalMemoryPolicy'] = ('memcpy/memset are classified normal imports. Their external implementations and application callbacks '
                                       'are not supplied or qualified by this relocatable-object gate. No helper-hook allowance is broadened.')
    receipt['FullGrid'] = dict(variants=12, cells=360, cpu_only_mutants=72, optimizations=list(OPTS))
    write_json(path, receipt)
    # Original completion manifest, after the final receipt update; not a later rehash.
    with (build / 'sha256.csv').open('w', newline='', encoding='ascii') as stream:
        writer = csv.writer(stream)
        writer.writerow(('path', 'sha256'))
        for artifact in sorted(build.rglob('*')):
            if artifact.is_file() and artifact.name != 'sha256.csv':
                writer.writerow((str(artifact.relative_to(build)), sha(artifact)))
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('repo', 'arm-gcc', 'cmsis-core', 'build'):
        parser.add_argument('--' + option, required=True)
    parser.add_argument('--optimizations', default=','.join(OPTS))
    parser.add_argument('--input-snapshot')
    args = parser.parse_args()
    return execute(args) if args.input_snapshot else make_snapshot(args)


if __name__ == '__main__':
    sys.exit(main())
