"""Opt-in CM4 MPU8 basic grid; capture local dependencies before importing them."""
from __future__ import annotations
import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
HERE = Path(__file__).resolve().parent
RELATIVE = 'tools/fixtures/classic_cm4_mpu_basic_grid'


def need(value, message):
    if not value:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest().upper()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='ascii')


def failure_text(failure):
    return type(failure).__name__ + ': ' + str(failure)


def capture(args):
    repo = Path(args.repo).resolve(strict=True)
    need(HERE == repo / RELATIVE, 'Runner must belong to the selected source repository/export')
    root = Path(args.build_root).resolve()
    need(not root.exists() and not root.is_relative_to(repo), 'Use an absent external evidence directory')
    root.mkdir(parents=True)
    target = root / 'source'
    original = dict(Repository=str(repo), Cmsis=str(Path(args.cmsis).resolve(strict=True)),
                    FreeRTOS=str(Path(args.freertos).resolve(strict=True)))
    names = {p.relative_to(repo).as_posix() for p in repo.glob('*.h')}
    for directory in ('context', 'fiber', 'fiber/port', 'fiber/lifecycle', 'fiber/port/ARM_CM4_MPU'):
        for suffix in ('*.h', '*.c'):
            names.update(p.relative_to(repo).as_posix() for p in (repo / directory).glob(suffix))
    names.update(('tools/runtime_sources.py', 'tools/runtime_sources.ps1', 'tools/runtime_sources.json',
        'tools/freertos_asm_parity.ps1', 'FREERTOS_ASM_PARITY.md',
        'tools/test_classic_cm4_mpu_basic_grid.ps1',
        'tools/fixtures/classic_cm4_mpu_context_runtime/run.py',
        'tools/fixtures/classic_fp_context_runtime/run.py',
        'tools/fixtures/classic_context_runtime/run.py',
        'tools/fixtures/classic_context_runtime/qemu.sh', 'tools/fixtures/arm_control/qemu.sh'))
    for path in HERE.rglob('*'):
        if not path.is_file() or '__pycache__' in path.parts:
            continue
        need(path.suffix in ('.py', '.ps1', '.c', '.h', '.S', '.ld', '.json', '.md'), 'Unexpected fixture input')
        names.add(path.relative_to(repo).as_posix())
    records = []

    def copy(source, destination, role, expected=None):
        need(source.is_file() and not source.is_symlink(), 'Missing/reparse captured dependency: ' + str(source))
        data = source.read_bytes()
        sha = digest(data)
        need(expected is None or sha == expected, 'Pinned reference content mismatch: ' + str(source))
        destination.parent.mkdir(parents=True, exist_ok=True)
        need(not destination.exists(), 'Duplicate captured dependency')
        destination.write_bytes(data)
        need(digest(source.read_bytes()) == digest(destination.read_bytes()) == sha, 'Capture-time dependency drift')
        records.append(dict(Original=str(source.resolve()), Captured=str(destination.resolve()), Sha256=sha, Role=role))

    for relative in sorted(names):
        copy(repo / relative, target / relative, 'SelectedRepositorySource')
    pinned = json.loads((target / RELATIVE / 'pinned_reference.json').read_text())
    need(pinned['ExpectedCommit'] == 'a50edad08b29052631aa469d4df6e6ec7ff68878' and
         len(pinned['Files']) == 26 and len({r['Path'] for r in pinned['Files']}) == 26, 'Exact pinned inventory')
    reference = root / 'reference'
    for row in pinned['Files']:
        relative = Path(row['Path'])
        need(not relative.is_absolute() and '..' not in relative.parts, 'Unsafe pinned input')
        copy(Path(original['FreeRTOS']) / relative, reference / relative, 'PinnedReference', row['Sha256'])
    cmsis = root / 'cmsis'
    headers = sorted(Path(original['Cmsis']).rglob('*.h'))
    need(headers, 'Missing CMSIS header closure')
    for path in headers:
        copy(path, cmsis / path.relative_to(original['Cmsis']), 'CMSIS')
    # The shared ELF helper imports pyelftools during preflight. Capture its
    # source and version metadata first; existing bytecode is never copied.
    need(not any(n == 'elftools' or n.startswith('elftools.') for n in sys.modules), 'Unexpected preloaded pyelftools')
    distribution = importlib.metadata.distribution('pyelftools')
    need(distribution.version == '0.33' and distribution.files, 'Existing pyelftools 0.33 distribution required')
    python_copy = root / 'python'
    package_files = []
    for item in distribution.files:
        relative = Path(str(item))
        need(not relative.is_absolute() and '..' not in relative.parts, 'Unsafe Python distribution path')
        if ((relative.parts[0] == 'elftools' and relative.suffix == '.py') or
                (relative.parts[0].endswith('.dist-info') and relative.name in ('METADATA', 'WHEEL', 'RECORD'))):
            source = Path(distribution.locate_file(item)).resolve(strict=True)
            copy(source, python_copy / relative, 'PythonPackage')
            package_files.append(relative.as_posix())
    need('elftools/__init__.py' in package_files and 'elftools/elf/elffile.py' in package_files, 'Missing captured ELF package closure')
    sys.path.insert(0, str(python_copy))
    manifest = root / 'capture.json'
    save(manifest, dict(SchemaVersion=1, Originals=original, Files=records,
        Attribution='Fresh selected source/reference/helper bytes; no historical receipt or Git attribution required'))
    args.repo, args.cmsis, args.freertos = str(target), str(cmsis), str(reference)
    args.build_root = str(root / 'evidence')
    args.capture_manifest = str(manifest)
    args.output_root = str(root)
    # Every local helper and all selected source bytes exist in this closed copy
    # before the first local import. There is no missing-file/live-tree fallback.
    for row in records:
        need(digest(Path(row['Captured']).read_bytes()) == row['Sha256'], 'Pre-import captured byte drift')
    return target / RELATIVE, records


def load(name, path, records):
    need(name not in sys.modules, 'Unexpected preloaded grid helper')
    row = next((r for r in records if r['Captured'] == str(path.resolve())), None)
    need(row is not None, 'Uncaptured local import')
    data = path.read_bytes()
    need(digest(data) == row['Sha256'], 'Captured module changed before import')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for name in ('repo', 'gcc', 'cmsis', 'freertos', 'build-root'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--qemu-root')
    parser.add_argument('--wsl-distro', default='Ubuntu-24.04')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--execute-grid', action='store_true')
    mode.add_argument('--compile-only', action='store_true')
    args = parser.parse_args()
    need(__debug__ and not sys.flags.optimize, 'Disable Python optimization')
    if args.execute_grid:
        need(type(args.qemu_root) is str and args.qemu_root.startswith('/') and args.wsl_distro,
             'Execution requires an explicit existing absolute WSL QemuRoot; never provisions')
    folder, records = capture(args)
    load('cm4_mpu_basic_engine', folder / 'engine.py', records)
    load('cm4_mpu_basic_builds', folder / 'build.py', records)
    load('cm4_mpu_basic_contracts', folder / 'contracts.py', records)
    module = load('cm4_mpu_basic_suite', folder / 'suite.py', records)
    suite = module.BasicGrid(args)
    error = None
    try:
        suite.run()
    except Exception as failure:
        error = failure_text(failure)
    if not suite.finish(error):
        raise RuntimeError('Preserve failed basic grid: ' + str(suite.build) + ': ' + str(suite.report['Error']))
    print(suite.report['Verdict'] + ' ' + str(suite.build), flush=True)


if __name__ == '__main__':
    main()
