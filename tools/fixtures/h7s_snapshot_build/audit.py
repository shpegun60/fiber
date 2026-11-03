"""Bounded, offline STM32CubeIDE H7S Boot snapshot build and ELF admission."""
import argparse
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import time
import traceback
import uuid
import xml.etree.ElementTree as ET
import zipfile

if not __debug__ or os.environ.get('PYTHONOPTIMIZE'):
    raise SystemExit('Unoptimized Python is required; PYTHONOPTIMIZE must be unset.')

PIN = '471ec5cfd1e69aefc273f6dd47d487bb1b4e5c6a'
PROJECT = 'h7s_fiber_test_Boot'
APP_CORE = 'app_core/fiber/'
PORT = APP_CORE + 'fiber/port/ARM_CM7/r0p1/'
STATE = APP_CORE + 'context/context_runtime_state.o'
CONFIG = APP_CORE + 'context/context_configuration.o'
SLOT = 'fiber_internal_runtime_current_context_slot'
REVERSE = 'fiber_internal_runtime_port_abi_v1_anchor'
CONFIG_ANCHOR = 'fiber_internal_runtime_context_configuration_abi_v1_anchor'
RAM_REGIONS = ((0x24000000, 0x24072000), (0x20000000, 0x20010000),
               (0x30000000, 0x30008000), (0x38800000, 0x38801000), (0, 0x10000))
MEMORY_REGIONS = ((0x08000000, 0x08010000),) + RAM_REGIONS
FORWARD = ('fiber_port_context_init', 'fiber_port_runtime_prepare_start',
           'fiber_port_runtime_select_first', 'fiber_port_runtime_start_first',
           'fiber_port_runtime_schedule', 'fiber_port_require_scheduler_configuration_environment',
           'fiber_port_runtime_memory_barrier', 'fiber_port_panic_wait')
CONTEXT = ('ctxrt_v1_init', 'ctxrt_v1_current', 'ctxrt_v1_set_dispatcher',
           'ctxrt_v1_start', 'ctxrt_v1_yield')
LEGACY = ('fiber_init', 'fiber_current', 'fiber_scheduler_set_pick_next',
          'fiber_start', 'fiber_schedule')
CORE = ('gpdma', 'gpio', 'main', 'stm32h7rsxx_hal_msp', 'stm32h7rsxx_it',
        'syscalls', 'sysmem', 'system_stm32h7rsxx', 'usart')
HAL = ('', '_cortex', '_dma', '_dma_ex', '_exti', '_flash', '_flash_ex',
       '_gpio', '_pwr', '_pwr_ex', '_rcc', '_rcc_ex', '_uart', '_uart_ex')
EXPECTED = frozenset(
    ['Core/Src/' + n + '.o' for n in CORE] +
    ['Core/Startup/startup_stm32h7s3l8hx.o', 'app_core/app_core.o'] +
    ['Drivers/STM32H7RSxx_HAL_Driver/stm32h7rsxx_hal' + n + '.o' for n in HAL] +
    [APP_CORE + 'context/' + n + '.o' for n in
     ('context_core', 'context_runtime_state', 'context_panic', 'context_configuration')] +
    [APP_CORE + 'fiber/fiber_core.o', APP_CORE + 'fiber/lifecycle/fiber_v1.o',
     APP_CORE + 'fiber/port/fiber_port_context_cohort_expectation.o'] +
    [PORT + n + '.o' for n in ('fiber_port', 'fiber_port_boot', 'fiber_port_exception')])


class AuditError(RuntimeError):
    pass


def need(condition, code):
    if not condition:
        raise AuditError(code)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest().upper()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2), encoding='utf-8')


def inside(path, root):
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except ValueError:
        return False


def admit_path(path, roots):
    need(any(inside(path, root) for root in roots), 'PATH_ESCAPE: ' + str(path))


def inventory(objects):
    need(len(objects) == len(set(objects)), 'DUPLICATE_OBJECT')
    need(set(objects) == EXPECTED and len(objects) == 35,
         'OBJECT_SET: missing=' + str(sorted(EXPECTED - set(objects))) +
         ' extra=' + str(sorted(set(objects) - EXPECTED)))


def compile_options(command, group, source, config):
    tokens = shlex.split(command)
    need(config in ('Debug', 'Release'), 'COMPILE_CONFIGURATION')
    languages = {'C_SRCS': ('C', '.c', 'arm-none-eabi-gcc', 'c'),
                 'CPP_SRCS': ('C++', '.cpp', 'arm-none-eabi-g++', 'c++'),
                 'S_SRCS': ('assembler', '.s', 'arm-none-eabi-gcc', 'assembler-with-cpp')}
    need(group in languages, 'COMPILE_SOURCE_GROUP')
    language, suffix, compiler, explicit = languages[group]
    need(Path(source).suffix == suffix and tokens and tokens[0] == compiler, 'COMPILE_LANGUAGE')
    overrides = []
    for i, token in enumerate(tokens):
        if token == '-x':
            need(i + 1 < len(tokens), 'COMPILE_LANGUAGE')
            overrides.append(tokens[i + 1])
        elif token.startswith('-x'):
            overrides.append(token[2:])
    need(overrides == [explicit] if language == 'assembler' else
         overrides in ([], [explicit]), 'COMPILE_LANGUAGE')
    need(tokens.count('-c') == 1 and tokens.count('$<') == 1 and
         tokens.count('-o') == 1 and tokens.index('-o') + 1 < len(tokens) and
         tokens[tokens.index('-o') + 1] == '$@', 'COMPILE_INPUT_OUTPUT')
    optimization = [t for t in tokens if t.startswith('-O')]
    standards = [t for t in tokens if t.startswith('-std=')]
    if language == 'assembler':
        need(not optimization and not standards, 'ASSEMBLER_OPTIONS_DRIFT')
    else:
        expected = '-Os' if config == 'Release' else ('-O2' if language == 'C' else '-O1')
        need(optimization == [expected], 'COMPILE_OPTIMIZATION_DRIFT')
        standard = '-std=gnu11' if language == 'C' else (
            '-std=gnu++20' if config == 'Debug' else '-std=gnu++14')
        need(standards == [standard], 'COMPILE_STANDARD_DRIFT')
    return language


def generated_compile_rules(content, directory, subdir, config):
    directory = Path(directory).resolve()
    logical = re.sub(r'\\\r?\n', ' ', content)
    sources, objects, records = {}, [], []
    for line in logical.splitlines():
        match = re.fullmatch(r'(C_SRCS|CPP_SRCS|S_SRCS|S_UPPER_SRCS|OBJS)\s*\+=\s*(.*)', line)
        if not match:
            continue
        group, words = match[1], match[2].split()
        for word in words:
            path = (directory / word).resolve()
            if group == 'OBJS':
                admit_path(path, [directory])
                objects.append(path.relative_to(directory).as_posix())
            else:
                need(str(path) not in sources, 'DUPLICATE_SOURCE_DECLARATION')
                sources[str(path)] = group
    need(len(objects) == len(set(objects)), 'DUPLICATE_DECLARED_OBJECT')
    lines = content.splitlines()
    for i, line in enumerate(lines):
        if not line.startswith('\t') or 'arm-none-eabi-' not in line:
            continue
        need(i > 0, 'COMPILE_RULE_HEADER')
        header = re.fullmatch(r'([^:]+):\s+(\S+)\s+(\S+)', lines[i - 1])
        need(header is not None and header[3] == subdir, 'COMPILE_RULE_HEADER')
        targets, source_pattern = header[1].split(), str((directory / header[2]).resolve())
        object_patterns = [t for t in targets if t.endswith('.o')]
        need(len(object_patterns) == 1, 'COMPILE_RULE_TARGET')
        target = object_patterns[0]
        need(all(t == target[:-2] + suffix for t in targets for suffix in
                 [Path(t).suffix]) and set(Path(t).suffix for t in targets) <= {'.o', '.su', '.cyclo'},
             'COMPILE_RULE_TARGET')
        need(source_pattern.count('%') <= 1 and target.count('%') == source_pattern.count('%'),
             'COMPILE_RULE_PATTERN')
        pattern = re.escape(source_pattern).replace('%', '(.+)')
        matches = [(source, group, re.fullmatch(pattern, source)) for source, group in sources.items()]
        matches = [(source, group, match) for source, group, match in matches if match]
        need(matches, 'UNASSOCIATED_COMPILE_RULE')
        for source, group, match in matches:
            obj = (directory / target.replace('%', match[1] if '%' in target else '')).resolve()
            admit_path(obj, [directory])
            relative = obj.relative_to(directory).as_posix()
            need(relative in objects, 'UNDECLARED_COMPILE_OBJECT')
            language = compile_options(line.strip(), group, source, config)
            records.append(dict(Source=source, Object=relative, Group=group, Language=language,
                                Command=line.strip(), Rule=lines[i - 1], Subdir=subdir))
    need(len(records) == len(sources) == len(objects) and
         len({r['Source'] for r in records}) == len(sources) and
         {r['Object'] for r in records} == set(objects), 'COMPILE_ASSOCIATION_COVERAGE')
    return records


def hooks(attributes):
    need(not attributes.get('prebuildStep', '').strip() and
         not attributes.get('postbuildStep', '').strip(), 'BUILD_HOOK')


def headless_ok(code, text):
    need(code == 0, 'HEADLESS_EXIT: ' + str(code))
    need(not re.search(r'No (?:Config|Project) matched|Could not obtain lock|Workspace already in use|'
                       r'Headless build encountered errors|does(?:n.t| not) appear to be a CDT project', text, re.I),
         'HEADLESS_SELECTION_OR_WORKSPACE')


def binding(symbol, kind, size):
    need(symbol['st_info']['bind'] == 'STB_GLOBAL' and
         symbol['st_info']['type'] == kind and symbol['st_size'] == size,
         'SYMBOL_BINDING_OR_GEOMETRY: ' + symbol.name)


def definition_owner(found, owners, types):
    need(len(found) == 1 and found[0]['Object'] in owners and
         found[0]['Type'] in types, 'DEFINITION_OWNER')


def handler_owner(name, found):
    expected = [('Core/Src/stm32h7rsxx_it.o', 'W'),
                ('Core/Startup/startup_stm32h7s3l8hx.o', 'W'),
                (PORT + 'fiber_port.o', 'T')]
    need(name in ('SVC_Handler', 'PendSV_Handler') and
         sorted((r['Object'], r['Type']) for r in found) == sorted(expected),
         'HANDLER_OWNER: ' + name + ': ' + str(found))


def handler_binding(symbol):
    need(symbol['st_info']['bind'] == 'STB_GLOBAL' and
         symbol['st_info']['type'] == 'STT_FUNC' and symbol['st_size'] > 0,
         'ELF_STRONG_HANDLER')


def reset_owner(found):
    need(found == [{'Object': 'Core/Startup/startup_stm32h7s3l8hx.o', 'Type': 'W'}],
         'RESET_OWNER: ' + str(found))


def reset_binding(symbol, section):
    start = symbol['st_value'] & ~1
    need(symbol['st_info']['bind'] == 'STB_WEAK' and
         symbol['st_info']['type'] == 'STT_FUNC' and symbol['st_value'] & 1 and
         symbol['st_size'] > 0 and section['sh_flags'] & 6 == 6 and
         section['sh_type'] == 'SHT_PROGBITS' and section['sh_addr'] <= start and
         start + symbol['st_size'] <= section['sh_addr'] + section['sh_size'], 'ELF_RESET_BINDING_EXTENT')


def reset_entry(entry, msp, reset):
    need(msp == 0x20010000 and entry == reset and entry & 1, 'ELF_RESET_ENTRY_MSP')


def contained_extent(start, size, regions):
    return (0 <= start < 0x100000000 and 0 < size <= 0x100000000 - start and
            any(lo <= start and start + size <= hi for lo, hi in regions))


def load_extents(segment, file_size):
    need(0 <= segment['p_filesz'] <= segment['p_memsz'] and
         0 <= segment['p_offset'] <= file_size and
         segment['p_filesz'] <= file_size - segment['p_offset'], 'ELF_LOAD_FILE_GEOMETRY')
    if segment['p_memsz']:
        need(contained_extent(segment['p_vaddr'], segment['p_memsz'], MEMORY_REGIONS), 'ELF_MEMORY_REGION')
    if segment['p_filesz']:
        need(contained_extent(segment['p_paddr'], segment['p_filesz'], MEMORY_REGIONS),
             'ELF_PHYSICAL_LOAD_REGION')


def file_backing(start, size, section, segment, file_size):
    offset = section['sh_offset'] + start - section['sh_addr']
    return (0 <= offset <= file_size and size <= file_size - offset and
            segment['p_vaddr'] <= start and start + size <= segment['p_vaddr'] + segment['p_filesz'] and
            offset == segment['p_offset'] + start - segment['p_vaddr'])


def executable_storage(symbol, section, loads, file_size):
    start, size = symbol['st_value'] & ~1, symbol['st_size']
    need(symbol['st_value'] & 1 and section is not None and
         section['sh_type'] == 'SHT_PROGBITS' and section['sh_flags'] & 6 == 6 and
         contained_extent(start, size, [(section['sh_addr'], section['sh_addr'] + section['sh_size'])]) and
         any(s['p_flags'] & 1 and file_backing(start, size, section, s, file_size) for s in loads),
         'ELF_HANDLER_EXECUTABLE_STORAGE')


def current_slot_storage(symbol, section, loads, file_size):
    start, size = symbol['st_value'], symbol['st_size']
    need(start % 4 == 0 and section is not None and
         section['sh_type'] in ('SHT_PROGBITS', 'SHT_NOBITS') and section['sh_flags'] & 3 == 3 and
         contained_extent(start, size, RAM_REGIONS) and
         contained_extent(start, size, [(section['sh_addr'], section['sh_addr'] + section['sh_size'])]) and
         any(s['p_flags'] & 2 and s['p_vaddr'] <= start and start + size <= s['p_vaddr'] + s['p_memsz'] and
             (section['sh_type'] == 'SHT_NOBITS' or file_backing(start, size, section, s, file_size))
             for s in loads), 'ELF_CURRENT_SLOT_WRITABLE_RAM')


def vector_target(actual, expected):
    need(actual & 1 and actual == (expected | 1), 'VECTOR_TARGET')


def expectation_values(values, runtime, storage):
    need(len(values) == 3 and values.count(runtime) == 1 and
         values.count(storage) == 2, 'COHORT_EXPECTATIONS')


def no_reparse(path):
    info = Path(path).lstat()
    need(not stat.S_ISLNK(info.st_mode) and
         not getattr(info, 'st_file_attributes', 0) & 0x400, 'REPARSE_INPUT: ' + str(path))


class Run:
    def __init__(self, args):
        self.a = args
        self.repo, self.boot, self.ide = (Path(p).resolve(strict=True) for p in
                                        (args.repo, args.boot, args.ide))
        self.root = Path(args.build_root or ('C:/h7sb-' + uuid.uuid4().hex[:12])).resolve()
        need(not self.root.exists(), 'BUILD_ROOT_MUST_NOT_EXIST')
        need(re.fullmatch(r'[A-Za-z]:', self.root.drive) is not None, 'LOCAL_BUILD_ROOT_REQUIRED')
        need(not re.search(r'\s', str(self.root)) and len(str(self.root)) < 60, 'SHORT_BUILD_ROOT_REQUIRED')
        need(not inside(self.root, self.boot) and not inside(self.boot, self.root) and
             not inside(self.root, self.ide), 'BUILD_ROOT_NOT_ISOLATED')
        self.root.mkdir(parents=True)
        self.project = self.root / 'snapshot/h7s_fiber_test/Boot'
        self.firmware = self.project.parent
        self.library = self.project / 'app_core/fiber'
        self.workspace = self.root / 'workspace'
        self.configuration = self.root / 'configuration'
        self.commands, self.inputs, self.generated, self.rows = [], {}, {}, []
        self.report = dict(Verdict='FAIL', CompleteSuite=False, BuildRoot=str(self.root),
                           SourceCommit=args.commit, SourceAttribution='Pinned production export; outer project separately content-addressed',
                           BoardExecuted=False, QemuExecuted=False, CubeMxExecuted=False,
                           ElfAdmissionRevision=2,
                           SupersededElfAdmissionReceiptSha256='3E18C92F0ED00B9467B4384FFD191C97C84DEBE8AF2C2DD926ADE4BCD0926075',
                           Commands=self.commands, Inputs=[], Configurations=self.rows,
                           ExpectedObjects=sorted(EXPECTED), ExpectedBuilds=['Debug', 'Release'],
                           InputDrift=[], GeneratedProjectMetadata=[], Error=None)
        self.receipt = self.root / 'results.json'
        save(self.receipt, self.report)

    def command(self, argv, label, timeout=120, env=None, cwd=None):
        argv = [str(x) for x in argv]
        index = len(self.commands)
        record = dict(Label=label, Arguments=argv, Cwd=str(cwd or self.root),
                      ExitCode=None, TimedOut=False)
        self.commands.append(record)
        stdout, stderr = self.root / ('command-%03d.stdout' % index), self.root / ('command-%03d.stderr' % index)
        record.update(Stdout=str(stdout), Stderr=str(stderr))
        start = time.monotonic()
        with stdout.open('wb') as out, stderr.open('wb') as err:
            child = subprocess.Popen(argv, cwd=cwd or self.root, env=env, stdout=out, stderr=err,
                                     creationflags=subprocess.CREATE_NO_WINDOW)
            record['Pid'] = child.pid
            try:
                record['ExitCode'] = child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                record['TimedOut'] = True
                # Only the child created for this recorded command is terminated.
                subprocess.run([str(Path(os.environ['SystemRoot']) / 'System32/taskkill.exe'),
                                '/PID', str(child.pid), '/T', '/F'], capture_output=True, check=False)
                child.wait(timeout=30)
                raise AuditError('COMMAND_TIMEOUT: ' + label)
            finally:
                record['Seconds'] = time.monotonic() - start
                save(self.root / ('command-%03d.json' % index), record)
        need(record['ExitCode'] == 0, 'COMMAND_EXIT: ' + label + ': ' + str(record['ExitCode']))
        return stdout.read_text(encoding='utf-8-sig', errors='replace')

    def enroll(self, path, role, copy=None):
        no_reparse(path)
        path = Path(path).resolve(strict=True)
        no_reparse(path)
        need(path.is_file(), 'FILE_INPUT_REQUIRED: ' + str(path))
        key = str(path)
        if key in self.inputs:
            need(sha(path) == self.inputs[key]['BeforeSha256'], 'INPUT_CHANGED: ' + key)
            return
        digest = sha(path)
        if copy:
            copy = Path(copy)
            copy.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, copy)
            need(sha(copy) == digest and sha(path) == digest, 'COPY_DRIFT: ' + key)
        self.inputs[key] = dict(Path=key, Role=role, BeforeSha256=digest,
                                Copy=str(copy) if copy else None, AfterSha256=None)

    def enroll_tree(self, directory, role, destination=None):
        directory = Path(directory).resolve(strict=True)
        no_reparse(directory)
        for base, dirs, files in os.walk(directory):
            for name in dirs:
                no_reparse(Path(base) / name)
            for name in files:
                path = Path(base) / name
                target = Path(destination) / path.relative_to(directory) if destination else None
                if role == 'OuterProject':
                    self.outer_file(path, target)
                else:
                    self.enroll(path, role, target)

    def outer_file(self, path, target):
        target = Path(target)
        relative = target.relative_to(self.root / 'snapshot')
        sealed = self.root / 'inputs/outer' / relative
        self.enroll(path, 'OuterProject', sealed)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(sealed, target)
        if target.name in ('.project', '.cproject') or '.settings' in target.parts:
            self.report['GeneratedProjectMetadata'].append(dict(Path=str(target),
                OriginalCopy=str(sealed), BeforeSha256=sha(target), AfterSha256=None))
        else:
            self.enroll(target, 'SnapshotOuterSource')

    def harness(self):
        import elftools
        need(elftools.__version__ == '0.33', 'PYELFTOOLS_VERSION_REQUIRED_0_33')
        self.elftools = elftools
        self.enroll_tree(Path(elftools.__file__).parent, 'PythonModule')
        buf = ctypes.create_unicode_buffer(32768)
        need(ctypes.windll.kernel32.GetModuleFileNameW(None, buf, len(buf)), 'PYTHON_IMAGE_IDENTITY')
        self.enroll(buf.value, 'PythonImage')
        for name in ('audit.py', 'test_audit.py', 'README.md'):
            self.enroll(Path(__file__).parent / name, 'Harness', self.root / 'harness' / name)
        self.enroll(self.repo / 'tools/test_h7s_snapshot_build.ps1', 'Harness',
                    self.root / 'harness/test_h7s_snapshot_build.ps1')
        temporary = self.root / 'harness-tmp'
        temporary.mkdir()
        env = dict(os.environ, TEMP=str(temporary), TMP=str(temporary))
        self.command([sys.executable, '-B', self.root / 'harness/test_audit.py'], 'maintained negative audit controls', env=env)

    def export_library(self):
        self.git = Path(shutil.which('git.exe') or '').resolve(strict=True)
        need(self.git.is_file(), 'GIT_REQUIRED')
        self.enroll(self.git, 'Tool')
        actual = self.command([self.git, '-C', self.repo, 'rev-parse', self.a.commit + '^{commit}'], 'resolve pinned production commit').strip()
        need(actual == PIN and self.a.commit == PIN, 'EXACT_471EC5C_REQUIRED')
        self.report['ObservedHead'] = self.command([self.git, '-C', self.repo, 'rev-parse', 'HEAD'], 'record live HEAD').strip()
        self.report['TrackedWorktreeStatus'] = self.command([self.git, '--no-optional-locks', '-C', self.repo,
            'status', '--porcelain=v1', '--untracked-files=no'], 'record tracked status only')
        paths = ['basic_types.h', 'mcu_core.h', 'context', 'fiber']
        tree = self.command([self.git, '-C', self.repo, 'ls-tree', '-r', self.a.commit, '--', *paths], 'pinned production tree')
        blobs = {}
        for line in tree.splitlines():
            match = re.fullmatch(r'(100644|100755) blob ([a-f0-9]{40})\t(.+)', line)
            need(match is not None, 'PRODUCTION_TREE_ENTRY')
            name = match[3]
            need(not Path(name).is_absolute() and '..' not in Path(name).parts and not name.startswith('tools/'), 'EXPORT_PATH')
            blobs[name] = match[2]
        archive = self.root / 'production.zip'
        self.command([self.git, '-c', 'core.autocrlf=false', '-c', 'core.eol=lf',
                      '-C', self.repo, 'archive', '--format=zip', '-o', archive,
                      self.a.commit, '--', *paths], 'export pinned production only')
        self.library.mkdir(parents=True)
        extracted = set()
        with zipfile.ZipFile(archive) as z:
            for entry in z.infolist():
                if entry.is_dir():
                    continue
                need(entry.filename in blobs and not stat.S_ISLNK(entry.external_attr >> 16), 'UNEXPECTED_ARCHIVE_ENTRY')
                data = z.read(entry)
                oid = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
                need(oid == blobs[entry.filename], 'GIT_BLOB_IDENTITY: ' + entry.filename)
                target = self.library / entry.filename
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                self.enroll(target, 'PinnedProduction')
                extracted.add(entry.filename)
        need(extracted == set(blobs), 'INCOMPLETE_PRODUCTION_EXPORT')
        self.report['ProductionExport'] = dict(Commit=actual, Archive=str(archive),
                                               ArchiveSha256=sha(archive), Files=blobs, IncludesTools=False)

    def outer_snapshot(self):
        need({p.name for p in (self.boot / 'app_core').iterdir() if p.is_file()} ==
             {'app_core.cpp', 'app_core.h', 'platform.h'}, 'UNREVIEWED_OUTER_APP_FILE')
        need(not any((self.boot / n).exists() for n in
                     ('makefile.init', 'makefile.defs', 'makefile.targets')), 'OUTER_MAKE_HOOK_FILE')
        for name in ('.project', '.cproject', 'STM32H7S3L8HX_FLASH.ld', 'STM32H7S3L8HX_RAM.ld'):
            self.outer_file(self.boot / name, self.project / name)
        for name in ('org.eclipse.cdt.core.prefs', 'org.eclipse.core.resources.prefs',
                     'language.settings.xml', 'stm32cubeide.project.prefs'):
            self.outer_file(self.boot / '.settings' / name, self.project / '.settings' / name)
        self.enroll_tree(self.boot / 'Core', 'OuterProject', self.project / 'Core')
        for name in ('app_core.cpp', 'app_core.h', 'platform.h'):
            self.outer_file(self.boot / 'app_core' / name, self.project / 'app_core' / name)
        drivers = self.boot.parent / 'Drivers'
        for name in ('CMSIS/Include', 'CMSIS/Device/ST/STM32H7RSxx/Include', 'STM32H7RSxx_HAL_Driver/Inc'):
            self.enroll_tree(drivers / name, 'OuterProject', self.firmware / 'Drivers' / name)
        desc = ET.parse(self.project / '.project').getroot()
        need(desc.findtext('name') == PROJECT and not list(desc.findall('./projects/project')), 'PROJECT_IDENTITY')
        names = [x.findtext('name') for x in desc.findall('./buildSpec/buildCommand')]
        need(names == ['org.eclipse.cdt.managedbuilder.core.genmakebuilder',
                       'org.eclipse.cdt.managedbuilder.core.ScannerConfigBuilder'], 'PROJECT_BUILDERS')
        need(not list(desc.findall('./buildSpec/buildCommand/arguments/*')), 'CUSTOM_BUILDER_ARGUMENTS')
        links = desc.findall('./linkedResources/link')
        need(len(links) == 14, 'HAL_LINK_COUNT')
        for link in links:
            uri, name = link.findtext('locationURI'), link.findtext('name')
            need(link.findtext('type') == '1' and uri.startswith('PARENT-1-PROJECT_LOC/Drivers/') and
                 '..' not in Path(uri).parts, 'LINKED_RESOURCE_ESCAPE')
            relative = uri.removeprefix('PARENT-1-PROJECT_LOC/')
            need(name == 'Drivers/STM32H7RSxx_HAL_Driver/' + Path(relative).name, 'HAL_LINK_ALIAS')
            source = self.boot.parent / relative
            admit_path(source, [drivers / 'STM32H7RSxx_HAL_Driver/Src'])
            self.outer_file(source, self.firmware / relative)
        self.config_preflight(self.project / '.cproject')
        script = (self.project / 'STM32H7S3L8HX_FLASH.ld').read_text()
        script = re.sub(r'/\*.*?\*/', '', script, flags=re.S)
        need(not re.search(r'\b(?:INCLUDE|INPUT|GROUP|SEARCH_DIR|OUTPUT)\b', script), 'EXTERNAL_LINKER_DIRECTIVE')
        need(not (self.project / 'Debug').exists() and not (self.project / 'Release').exists(), 'STALE_BUILD_OUTPUT')

    def config_preflight(self, path):
        configs = ET.parse(path).getroot().findall('.//configuration')
        need({c.get('name') for c in configs} == {'Debug', 'Release'} and len(configs) == 2, 'EXACT_CONFIGURATIONS')
        dirs = {p.name for p in (self.library / 'fiber/port').iterdir() if p.is_dir()}
        for config in configs:
            hooks(config.attrib)
            entries = config.findall('./sourceEntries/entry')
            need({x.get('name') for x in entries} == {'app_core', 'Core', 'Drivers'} and len(entries) == 3, 'SOURCE_ENTRIES')
            entry = next(x for x in entries if x.get('name') == 'app_core')
            excluded = set(entry.get('excluding', '').split('|'))
            need('fiber/tools' in excluded and 'fiber/fiber/lifecycle' not in excluded, 'TOOLS_AND_LIFECYCLE_ADMISSION')
            need({d for d in dirs if 'fiber/fiber/port/' + d not in excluded} == {'ARM_CM7'}, 'ALTERNATE_PORT_ADMISSION')
            builder = config.find('.//builder')
            need(builder is not None and builder.get('managedBuildOn') == 'true' and
                 builder.get('buildPath') == '${workspace_loc:/' + PROJECT + '}/' + config.get('name'), 'BUILD_PATH')
            need(not any(builder.get(key, '').strip() for key in
                         ('command', 'arguments', 'buildCommand', 'buildArguments',
                          'incrementalBuildTarget', 'autoBuildTarget', 'cleanBuildTarget')), 'CUSTOM_BUILD_COMMAND')
            for option in config.findall('.//option'):
                value = option.get('value', '')
                need(not re.match(r'^[A-Za-z]:[/\\]|^[/\\]{2}', value), 'ABSOLUTE_PROJECT_OPTION')
                if option.get('superClass', '').endswith('linker.option.script'):
                    need(value == '${workspace_loc:/${ProjName}/STM32H7S3L8HX_FLASH.ld}', 'LINKER_SCRIPT_OPTION')

    def tool_snapshot(self):
        self.gcc, self.make = Path(self.a.gcc).resolve(strict=True), Path(self.a.make).resolve(strict=True)
        self.toolchain = self.gcc.parent.parent
        self.launcher = self.ide / 'stm32cubeidec.exe'
        self.java = self.ide / 'plugins/com.st.stm32cube.ide.jre.win64_3.4.300.202604201452/jre/bin/java.exe'
        for path in (self.gcc, self.make, self.launcher, self.java):
            admit_path(path, [self.ide])
            need(path.is_file(), 'INSTALLED_TOOL_REQUIRED')
        config = self.ide / 'configuration/config.ini'
        bundles = self.ide / 'configuration/org.eclipse.equinox.simpleconfigurator/bundles.info'
        self.enroll(config, 'InstallationMetadata')
        self.enroll(bundles, 'InstallationMetadata')
        for name in ('stm32cubeide.ini', 'stm32cubeidec.exe', 'headless-build.bat'):
            self.enroll(self.ide / name, 'Tool')
        self.configuration.mkdir()
        output = []
        locations = []
        for line in bundles.read_text().splitlines():
            if not line or line.startswith('#'):
                output.append(line)
                continue
            parts = line.split(',')
            need(len(parts) == 5 and not re.match(r'^[a-z]+:', parts[2], re.I), 'BUNDLE_LOCATION_GRAMMAR')
            path = (self.ide / parts[2]).resolve(strict=True)
            admit_path(path, [self.ide])
            locations.append(path)
            parts[2] = path.as_uri() + ('/' if path.is_dir() else '')
            output.append(','.join(parts))
        for path in locations:
            if path.is_dir():
                self.enroll_tree(path, 'InstalledBundle')
            else:
                self.enroll(path, 'InstalledBundle')
        print('Active bundle/tool files enrolled: ' + str(len(self.inputs)), flush=True)
        # Launcher bootstrap and p2 paths must not fall back to shared configuration.
        derived = config.read_text()
        for key in ('osgi.framework', 'osgi.framework.extensions', 'osgi.bundles'):
            match = re.search(r'(?m)^' + re.escape(key) + r'=(.+)$', derived)
            need(match is not None, 'OSGI_BOOTSTRAP_PROPERTY')
            value = match[1].replace('\\:', ':')
            name = re.search(r'(org\.eclipse\.[^/:@]+\.jar)', value)
            need(name is not None, 'OSGI_BOOTSTRAP_JAR')
            jar = self.ide / 'plugins' / name[1]
            self.enroll(jar, 'InstalledBootstrap')
            replacement = ('reference:' if value.startswith('reference:') else '') + jar.as_uri()
            if '@' in value:
                replacement += '@' + value.split('@', 1)[1]
            derived = derived.replace(match[0], key + '=' + replacement)
        bundle_copy = self.configuration / 'org.eclipse.equinox.simpleconfigurator/bundles.info'
        bundle_copy.parent.mkdir()
        bundle_copy.write_text('\n'.join(output) + '\n', encoding='utf-8')
        derived = re.sub(r'(?m)^org\.eclipse\.equinox\.simpleconfigurator\.configUrl=.*$',
                         'org.eclipse.equinox.simpleconfigurator.configUrl=' + bundle_copy.as_uri(), derived)
        derived = re.sub(r'(?m)^eclipse\.p2\.data\.area=.*$',
                         'eclipse.p2.data.area=' + (self.root / 'p2').as_uri(), derived)
        (self.configuration / 'config.ini').write_text(derived, encoding='utf-8')
        self.enroll_tree(self.ide / 'p2', 'InstalledP2Metadata', self.root / 'p2')
        for name in ('home', 'appdata', 'localappdata', 'tmp', 'workspace'):
            (self.root / name).mkdir()
        env = dict(os.environ)
        for name in ('GCC_EXEC_PREFIX', 'COMPILER_PATH', 'LIBRARY_PATH', 'CPATH', 'C_INCLUDE_PATH',
                     'CPLUS_INCLUDE_PATH', 'MAKEFLAGS', 'MFLAGS', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS',
                     'JDK_JAVA_OPTIONS', 'CL', 'SHELLOPTS', 'BASH_ENV', 'ENV'):
            env.pop(name, None)
        for name, directory in (('HOME', 'home'), ('USERPROFILE', 'home'), ('APPDATA', 'appdata'),
                                ('LOCALAPPDATA', 'localappdata'), ('TEMP', 'tmp'), ('TMP', 'tmp')):
            env[name] = str(self.root / directory)
        system_root = os.environ['SystemRoot']
        env['PATH'] = os.pathsep.join((str(self.make.parent), str(self.gcc.parent),
                                      str(Path(system_root) / 'System32'), system_root))
        env['HOMEDRIVE'], env['HOMEPATH'] = self.root.drive, str(self.root / 'home')[2:]
        self.env = env
        save(self.root / 'child-environment.json', {n: env[n] for n in
             ('PATH', 'HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP', 'HOMEDRIVE', 'HOMEPATH')})
        self.report['CompilerVersion'] = self.command([self.gcc, '--version'], 'compiler identity', env=env)
        self.command([self.make, '--version'], 'make identity', env=env)
        self.report['Preflight'] = 'PASS: isolated configuration/workspace/home; exact source/configuration admission; no launch hooks'
        print(self.report['Preflight'], flush=True)

    def build(self, config, first):
        row = dict(Configuration=config, Status='STAGED', Elf=None)
        self.rows.append(row)
        command = [self.launcher, '--launcher.suppressErrors', '-nosplash', '-install', self.ide,
                   '-configuration', self.configuration, '-data', self.workspace,
                   '-application', 'org.eclipse.cdt.managedbuilder.core.headlessbuild', '-no-indexer']
        if first:
            command += ['-import', self.project]
        command += ['-build', PROJECT + '/' + config, '-vm', self.java, '-vmargs',
                    '-Duser.home=' + str(self.root / 'home'), '-Djava.io.tmpdir=' + str(self.root / 'tmp')]
        stdout = self.command(command, 'fresh headless ' + config, timeout=self.a.timeout, env=self.env)
        record = self.commands[-1]
        text = stdout + Path(record['Stderr']).read_text(encoding='utf-8', errors='replace')
        headless_ok(record['ExitCode'], text)
        directory = self.project / config
        need(directory.is_dir(), 'NO_GENERATED_CONFIGURATION')
        elf = directory / (PROJECT + '.elf')
        need(elf.is_file(), 'NO_FRESH_ELF')
        row['Admission'] = self.recipe_audit(directory, text)
        row['Ownership'] = self.owner_audit(directory)
        attributes = self.command([self.gcc.with_name('arm-none-eabi-readelf.exe'), '-hAlSWs', elf],
                                  'final ELF attributes ' + config)
        need('Tag_CPU_arch: v7E-M' in attributes and 'Tag_FP_arch: FPv5/FP-D16' in attributes and
             'Tag_ABI_VFP_args: VFP registers' in attributes, 'FINAL_CPU_FP_ATTRIBUTES')
        self.command([self.gcc.with_name('arm-none-eabi-objdump.exe'), '-drwC', '-Mreg-names-std', elf],
                     'final ELF disassembly ' + config)
        row['ElfAudit'] = self.elf_audit(elf, row['Ownership'])
        row['NegativeElfControls'] = self.elf_controls(elf, row['Ownership'])
        row.update(Status='PASS', Elf=str(elf), ElfSha256=sha(elf))
        save(directory / 'qualification.json', row)
        print('PASS H7S snapshot ' + config, flush=True)

    def recipe_audit(self, directory, console):
        response = directory / 'objects.list'
        objects = []
        for line in response.read_text().splitlines():
            need(re.fullmatch(r'"\./[A-Za-z0-9_./-]+\.o"', line), 'RESPONSE_GRAMMAR')
            objects.append(line[3:-1])
        inventory(objects)
        includes = re.findall(r'(?m)^-include ([A-Za-z0-9_./-]+/subdir\.mk)\s*$',
                              (directory / 'makefile').read_text())
        need(includes and len(includes) == len(set(includes)), 'GENERATED_SUBDIRS')
        compile_records = []
        for name in includes:
            path = directory / name
            admit_path(path, [directory])
            content = path.read_text()
            compile_records += generated_compile_rules(content, directory, name, directory.name)
        inventory([r['Object'] for r in compile_records])
        sources = {r['Source'] for r in compile_records}
        need(len(sources) == 35 and all(s in self.inputs for s in sources), 'EXACT_35_ENROLLED_SOURCE_FILES')
        need({language: sum(r['Language'] == language for r in compile_records) for language in
              ('C', 'C++', 'assembler')} == {'C': 33, 'C++': 1, 'assembler': 1}, 'EXACT_COMPILE_LANGUAGES')
        assembler = next(r for r in compile_records if r['Language'] == 'assembler')
        need(assembler['Object'] == 'Core/Startup/startup_stm32h7s3l8hx.o', 'EXPECTED_STARTUP_ASSEMBLER')
        by_object = {r['Object']: r for r in compile_records}
        rules = list(dict.fromkeys(r['Command'] for r in compile_records))
        need('fiber_v1.c' in {Path(p).name for p in sources}, 'LIFECYCLE_NOT_REGENERATED')
        for rule in rules + [l.strip() for l in (directory / 'makefile').read_text().splitlines()
                             if l.startswith('\tarm-none-eabi-g++')]:
            need('-mcpu=cortex-m7' in rule and '-mfpu=fpv5-d16' in rule and
                 '-mfloat-abi=hard' in rule and '-flto' not in rule, 'GENERATED_TARGET_FLAGS')
            for raw in re.findall(r'(?i)[A-Z]:[/\\][^"\s]+', rule):
                admit_path(raw.replace('\\', '/'), [self.firmware, self.toolchain])
            need(str(self.boot).replace('\\', '/') not in rule.replace('\\', '/'), 'LIVE_BOOT_RECIPE')
        source_objects = []
        for path in sorted(directory.rglob('*.d')):
            text = re.sub(r'\\\r?\n', ' ', path.read_text())
            first = text.split(': ', 1)
            need(len(first) == 2, 'DEPFILE_GRAMMAR')
            dependencies = first[1].split('\n', 1)[0]
            need(dependencies.strip(), 'EMPTY_DEPFILE')
            used = []
            for word in re.findall(r'(?:\\.|[^\s])+', dependencies):
                raw = re.sub(r'\\([ #:\\])', r'\1', word)
                candidate = Path(raw)
                if not candidate.is_absolute():
                    candidate = directory / candidate
                candidate = candidate.resolve(strict=True)
                need(str(candidate) in self.inputs, 'UNENROLLED_DEPENDENCY: ' + str(candidate))
                need(sha(candidate) == self.inputs[str(candidate)]['BeforeSha256'], 'DEPENDENCY_DRIFT')
                used.append(str(candidate))
            obj = path.with_suffix('.o')
            relative = obj.relative_to(directory).as_posix()
            need(relative in EXPECTED and used[0] in sources, 'DEPENDENCY_SOURCE_OBJECT')
            if relative.startswith('Drivers/'):
                expected_source = self.firmware / 'Drivers/STM32H7RSxx_HAL_Driver/Src' / (obj.stem + '.c')
            elif relative == 'app_core/app_core.o':
                expected_source = self.project / 'app_core/app_core.cpp'
            else:
                expected_source = self.project / Path(relative).with_suffix('.s' if relative.startswith('Core/Startup/') else '.c')
            need(Path(used[0]) == expected_source.resolve(), 'SOURCE_OBJECT_OWNER')
            need(used[0] == by_object[relative]['Source'], 'DEPFILE_COMPILE_RULE_ASSOCIATION')
            source_objects.append(dict(Source=used[0], SourceSha256=self.inputs[used[0]]['BeforeSha256'],
                                       Object=str(obj), ObjectSha256=sha(obj),
                                       Depfile=str(path), DepfileSha256=sha(path), Dependencies=used,
                                       CompileRule=by_object[relative]))
        need(len(list(directory.rglob('*.d'))) == 35, 'EXACT_35_DEPFILES')
        need(len({r['Source'] for r in source_objects}) == 35, 'EXACT_35_COMPILED_SOURCES')
        save(directory / 'source-object-map.json', source_objects)
        self.config_preflight(self.project / '.cproject')
        return dict(Objects=objects, Sources=sorted(sources), Depfiles=35,
                    SourceObjectMap=str(directory / 'source-object-map.json'), LifecycleIncluded=True,
                    Regenerated=True, NoLiveBootPaths=True, CompileAssociations=compile_records, Rules=rules)

    def owner_audit(self, directory):
        definitions = {}
        nm = self.gcc.with_name('arm-none-eabi-gcc-nm.exe')
        for name in sorted(EXPECTED):
            obj = directory / name
            text = self.command([nm, '-P', '--defined-only', obj], 'prelink owner ' + directory.name + ' ' + name)
            for line in text.splitlines():
                parts = line.split()
                need(len(parts) >= 2, 'NM_GRAMMAR')
                definitions.setdefault(parts[0], []).append(dict(Object=name, Type=parts[1]))
        def owned(name, owner, types):
            found = definitions.get(name, [])
            try:
                definition_owner(found, owner, types)
            except AuditError as error:
                raise AuditError('OWNER: ' + name + ': ' + str(found)) from error
        port = {PORT + n + '.o' for n in ('fiber_port', 'fiber_port_boot', 'fiber_port_exception')}
        for name in FORWARD:
            owned(name, port, ('T',))
        for name in ('SVC_Handler', 'PendSV_Handler'):
            handler_owner(name, definitions.get(name, []))
        reset_owner(definitions.get('Reset_Handler', []))
        for name in CONTEXT:
            owned(name, {APP_CORE + 'context/context_core.o'}, ('T',))
        for name in LEGACY:
            owned(name, {APP_CORE + 'fiber/fiber_core.o'}, ('T',))
        for name in (SLOT, REVERSE):
            owned(name, {STATE}, ('B', 'D', 'R'))
        owned(CONFIG_ANCHOR, {CONFIG}, ('B', 'D', 'R'))
        cohorts = {}
        for prefix, key in (('fiber_port_context_cohort_', 'RuntimeCohort'),
                            ('fiber_port_storage_cohort_', 'StorageCohort')):
            names = [n for n in definitions if n.startswith(prefix) and 'expectation' not in n]
            need(len(names) == 1, 'PRELINK_COHORT_PROVIDER_COUNT')
            owned(names[0], port, ('R',))
            cohorts[key] = names[0]
        cohorts['Definitions'] = definitions
        save(directory / 'prelink-owners.json', cohorts)
        return cohorts

    def elf_audit(self, path, owners):
        from elftools.elf.elffile import ELFFile
        stream = io.BytesIO(path) if isinstance(path, bytes) else Path(path).open('rb')
        with stream:
            elf = ELFFile(stream)
            need(elf.elfclass == 32 and elf.little_endian and elf['e_machine'] == 'EM_ARM' and
                 elf['e_type'] == 'ET_EXEC' and elf['e_flags'] & 0x400, 'ELF_TARGET')
            file_size = stream.seek(0, io.SEEK_END)
            loads = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
            need(loads, 'ELF_LOAD_SEGMENTS')
            for segment in loads:
                load_extents(segment, file_size)
            symbols = list(elf.get_section_by_name('.symtab').iter_symbols())
            need(not [s.name for s in symbols if s.name and s['st_shndx'] == 'SHN_UNDEF'], 'ELF_UNRESOLVED')
            def unique(name):
                found = [s for s in symbols if s.name == name and s['st_shndx'] != 'SHN_UNDEF']
                need(len(found) == 1, 'ELF_UNIQUE: ' + name)
                return found[0]
            def section_for(symbol):
                index = symbol['st_shndx']
                return elf.get_section(index) if isinstance(index, int) and 0 < index < elf.num_sections() else None
            for name in ('SVC_Handler', 'PendSV_Handler'):
                handler = unique(name)
                handler_binding(handler)
                executable_storage(handler, section_for(handler), loads, file_size)
            reset = unique('Reset_Handler')
            need(section_for(reset) is not None, 'ELF_RESET_SECTION')
            reset_binding(reset, section_for(reset))
            executable_storage(reset, section_for(reset), loads, file_size)
            slot = unique(SLOT)
            binding(slot, 'STT_OBJECT', 4)
            current_slot_storage(slot, section_for(slot), loads, file_size)
            binding(unique(REVERSE), 'STT_OBJECT', 1)
            for name in (*CONTEXT, *LEGACY, *FORWARD, CONFIG_ANCHOR):
                found = [s for s in symbols if s.name == name and s['st_shndx'] != 'SHN_UNDEF']
                if found:
                    need(len(found) == 1 and found[0]['st_info']['bind'] == 'STB_GLOBAL', 'ELF_LIVE_API_BINDING')
            vector = elf.get_section_by_name('.isr_vector')
            need(vector is not None and vector['sh_addr'] == 0x08000000 and vector['sh_size'] == 0x2b0 and
                 vector['sh_flags'] & 2 and not vector['sh_flags'] & 1, 'ELF_VECTOR_SECTION')
            words = struct.unpack('<172I', vector.data())
            reset_entry(elf['e_entry'], words[0], reset['st_value'])
            for index, name in ((1, 'Reset_Handler'), (11, 'SVC_Handler'), (14, 'PendSV_Handler')):
                vector_target(words[index], unique(name)['st_value'])
            values = {}
            for key in ('RuntimeCohort', 'StorageCohort'):
                s = unique(owners[key])
                binding(s, 'STT_OBJECT', 1)
                section = elf.get_section(s['st_shndx'])
                need(section.data()[s['st_value'] - section['sh_addr']] == 1, 'ELF_COHORT_VALUE')
                values[key] = s['st_value']
            expectation = elf.get_section_by_name('.fiber_port_context_cohort_expectation')
            need(expectation is not None and expectation['sh_size'] == 12 and expectation['sh_flags'] & 2 and
                 not expectation['sh_flags'] & 1, 'ELF_EXPECTATION_SECTION')
            pointers = list(struct.unpack('<3I', expectation.data()))
            expectation_values(pointers, values['RuntimeCohort'], values['StorageCohort'])
            live = {s.name for s in symbols if s['st_shndx'] != 'SHN_UNDEF'}
            return dict(VectorSlots={str(i): words[i] for i in (1, 11, 14)}, InitialMsp=words[0],
                        ResetBinding='STB_WEAK', ResetOwner='Core/Startup/startup_stm32h7s3l8hx.o',
                        ResetAddress=reset['st_value'], ResetBytes=reset['st_size'],
                        RuntimeCohort=owners['RuntimeCohort'], StorageCohort=owners['StorageCohort'],
                        ExpectationPointers=pointers, CurrentSlot=unique(SLOT)['st_value'],
                        HandlerExecutableStorage=True, CurrentSlotWritableRam=True,
                        PhysicalLoadExtentsChecked=True,
                        LoadSegments=[dict(Virtual=s['p_vaddr'], MemoryBytes=s['p_memsz'],
                                           Physical=s['p_paddr'], FileBytes=s['p_filesz']) for s in loads],
                        LiveContext=[n for n in CONTEXT if n in live], LiveLegacy=[n for n in LEGACY if n in live],
                        OptionalConfigurationAnchorLive=CONFIG_ANCHOR in live,
                        UnusedApisMayBeGarbageCollected=True, NoUnresolved=True)

    def elf_controls(self, path, owners):
        from elftools.elf.elffile import ELFFile
        original = path.read_bytes()
        with path.open('rb') as stream:
            elf = ELFFile(stream)
            vector = elf.get_section_by_name('.isr_vector')['sh_offset']
            expectation = elf.get_section_by_name('.fiber_port_context_cohort_expectation')['sh_offset']
            table = elf.get_section_by_name('.symtab')
            svc = [i for i, s in enumerate(table.iter_symbols()) if s.name == 'SVC_Handler']
            reset = [i for i, s in enumerate(table.iter_symbols()) if s.name == 'Reset_Handler']
            need(len(svc) == len(reset) == 1 and table['sh_entsize'] == 16, 'CONTROL_ELF32_SYMBOL_GEOMETRY')
            svc_info = table['sh_offset'] + svc[0] * table['sh_entsize'] + 12
            reset_info = table['sh_offset'] + reset[0] * table['sh_entsize'] + 12
            slot = [i for i, s in enumerate(table.iter_symbols()) if s.name == SLOT]
            need(len(slot) == 1 and elf['e_phentsize'] == 32, 'CONTROL_ELF32_LOAD_GEOMETRY')
            slot_record = table['sh_offset'] + slot[0] * table['sh_entsize']
            text_index = next(i for i, s in enumerate(elf.iter_sections()) if s.name == '.text')
            load_index = next(i for i, s in enumerate(elf.iter_segments()) if s['p_type'] == 'PT_LOAD' and s['p_filesz'])
            load_record = elf['e_phoff'] + load_index * elf['e_phentsize']
        cases = [('svc-thumb-clear', vector + 44,
                  struct.pack('<I', struct.unpack_from('<I', original, vector + 44)[0] & ~1), 'VECTOR_TARGET'),
                 ('pendsv-points-reset', vector + 56, original[vector + 4:vector + 8], 'VECTOR_TARGET'),
                 ('bad-expectation-pointer', expectation, struct.pack('<I', 0), 'COHORT_EXPECTATIONS'),
                 ('weak-final-svc', svc_info, bytes([(original[svc_info] & 15) | (2 << 4)]), 'ELF_STRONG_HANDLER'),
                 ('strong-final-reset', reset_info, bytes([(original[reset_info] & 15) | (1 << 4)]), 'ELF_RESET_BINDING_EXTENT'),
                 ('wrong-reset-entry', 24, struct.pack('<I', 0), 'ELF_RESET_ENTRY_MSP'),
                 ('wrong-initial-msp', vector, struct.pack('<I', 0), 'ELF_RESET_ENTRY_MSP'),
                 ('reset-vector-thumb-clear', vector + 4,
                  struct.pack('<I', struct.unpack_from('<I', original, vector + 4)[0] & ~1), 'VECTOR_TARGET')]
        cases = [(name, [(offset, value)], reason) for name, offset, value, reason in cases]
        cases += [('svc-foreign-executable-address',
                   [(svc_info - 8, struct.pack('<I', 0x60000001)), (vector + 44, struct.pack('<I', 0x60000001))],
                   'ELF_HANDLER_EXECUTABLE_STORAGE'),
                  ('slot-readonly-flash', [(slot_record + 4, struct.pack('<I', 0x080002B0)),
                                           (slot_record + 14, struct.pack('<H', text_index))],
                   'ELF_CURRENT_SLOT_WRITABLE_RAM'),
                  ('load-foreign-physical-address', [(load_record + 12, struct.pack('<I', 0xDEAD0000))],
                   'ELF_PHYSICAL_LOAD_REGION')]
        records = []
        for name, patches, reason in cases:
            changed = bytearray(original)
            for offset, value in patches:
                changed[offset:offset + len(value)] = value
            output = path.parent / ('audit-negative-' + name + '.elf')
            output.write_bytes(changed)
            try:
                self.elf_audit(bytes(changed), owners)
            except AuditError as error:
                need(str(error) == reason, 'WRONG_ELF_CONTROL_REASON: ' + str(error))
                records.append(dict(Name=name, File=str(output), Sha256=sha(output), Rejection=str(error),
                                    Patches=[dict(Offset=o, Bytes=v.hex()) for o, v in patches]))
            else:
                raise AuditError('ELF_CONTROL_FALSE_PASS: ' + name)
        return records

    def finish(self):
        for record in self.report['GeneratedProjectMetadata']:
            path = Path(record['Path'])
            record['AfterSha256'] = sha(path) if path.is_file() else None
        for record in self.inputs.values():
            path = Path(record['Path'])
            after = sha(path) if path.is_file() else None
            record['AfterSha256'] = after
            if after != record['BeforeSha256']:
                self.report['InputDrift'].append(str(path))
            if record['Copy'] and sha(record['Copy']) != record['BeforeSha256']:
                self.report['InputDrift'].append(record['Copy'])
        if self.report['InputDrift']:
            self.report['Verdict'] = 'FAIL'
        self.report['Inputs'] = list(self.inputs.values())
        save(self.receipt, self.report)
        artifacts = [dict(Path=str(p), Sha256=sha(p), Bytes=p.stat().st_size)
                     for p in sorted(self.root.rglob('*')) if p.is_file() and p.name != 'artifacts.json']
        save(self.root / 'artifacts.json', artifacts)
        print('BUILD_ROOT=' + str(self.root), flush=True)
        print('RECEIPT_SHA256=' + sha(self.receipt), flush=True)
        print('VERDICT=' + self.report['Verdict'] + ' INPUTS=' + str(len(self.inputs)) +
              ' ARTIFACTS=' + str(len(artifacts)) + ' DRIFT=' + str(len(self.report['InputDrift'])), flush=True)


def main():
    p = argparse.ArgumentParser()
    for name in ('repo', 'boot', 'ide', 'gcc', 'make'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--commit', default=PIN)
    p.add_argument('--build-root')
    p.add_argument('--timeout', type=int, default=900)
    p.add_argument('--preflight-only', action='store_true')
    run = Run(p.parse_args())
    try:
        run.harness()
        run.export_library()
        run.outer_snapshot()
        run.tool_snapshot()
        if not run.a.preflight_only:
            run.build('Debug', True)
            run.build('Release', False)
            need([r['Configuration'] for r in run.rows if r['Status'] == 'PASS'] == ['Debug', 'Release'], 'INCOMPLETE_BUILD_GRID')
            run.report['CompleteSuite'] = True
        run.report['Verdict'] = 'PASS'
    except Exception as error:
        run.report.update(Error=str(error), Traceback=traceback.format_exc())
        print('FAIL ' + str(error), flush=True)
    finally:
        run.finish()
    if run.report['Verdict'] != 'PASS':
        return 1
    print('PASS H7S snapshot ' + ('preflight only; CompleteSuite=false' if run.a.preflight_only else 'Debug+Release build/audit'), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
