"""One retained CM0/O2 link-control suite; no cell/ABI/runtime qualification.

Suite admission performs no commands and creates no output. Call start(), then
command()/compile_tuple()/run_link_controls(), and finish(error=None). Generic
command completion is not an intended-diagnostic or semantic PASS. run_controls
is the standalone five-control convenience entry point. No command runs on import.
"""
import copy
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import sys
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[3]
REPLAY = 'tools/freeze_replay.py'
REPLAY_SHA = '142BDDE647122DB2D66EF66E4C44A33ECEAA9292FFE304EF3C7CBCC740283275'
NATIVE = 'tools/fixtures/classic_final_image/run.py'
NATIVE_SHA = 'FBCBA0C4FF480E139ADE401ECFA90822E9EA01A6AB554CEF157036EC9DE7F014'
FACADE = 'tools/fixtures/context_facade/run.py'
FACADE_SHA = '7D08E0311C11B611F380262900B6A6DAAF5E65924B95051055069494DB532A13'
PROCESS = 'tools/fixtures/freeze_cohorts/process_runner.py'
PROCESS_SHA = 'D00D16DBFC69C3F49DF24D8F8A7329045DD9545AF50CB37A39ACB38EAC48B104'
RECEIPT_SHA = 'D5FF0D8A8368EC38C816ABC627D506278EB47978676A69ACC11FD19603D96FBB'
ARTIFACTS_SHA = 'ACB4BD4EE450EADD25E3EB727BB27B3C0AF780C6D00195669D3C656E6266E11B'
INVENTORY_SHA = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
COHORT = 'cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default'
CONTROLS = ('stale-nvic-expectation', 'stale-storage-application', 'stale-reverse-anchor', 'duplicate-svc', 'duplicate-pendsv')
SOURCES = ('context/context_core.c', 'context/context_runtime_state.c', 'context/context_panic.c',
           'fiber/port/ARM_CM0/fiber_port.c', 'fiber/port/ARM_CM0/fiber_port_boot.c',
           'fiber/port/ARM_CM0/fiber_port_exception.c', 'fiber/port/fiber_port_context_cohort_expectation.c',
           'tools/fixtures/classic_final_image/application.c', 'tools/fixtures/classic_final_image/startup.S')


class Rejected(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected('cm0-cell-controls: ' + message)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False, ensure_ascii=True) + '\n').encode('ascii')


def same(actual, expected, message):
    need(encoded(actual) == encoded(expected), message)


def module(name, path, raw):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def diagnostic_text(raw):
    need(type(raw) is bytes, 'diagnostic bytes')
    text = raw.decode('utf-8', errors='strict').replace('\r\n', '\n')
    need('\r' not in text and '\x00' not in text, 'diagnostic line endings/NUL')
    return text


def classify_duplicate(result, expected, linker, added_object, original_object, added_source):
    """Bounded GNU ld duplicate-function grammar, distinct from unresolved."""
    need(type(result.returncode) is int and result.returncode == 1 and result.stdout == b''
         and result.timed_out is False and expected in ('SVC_Handler', 'PendSV_Handler'), 'duplicate result shape')
    text = diagnostic_text(result.stderr)
    need(text.endswith('\n'), 'terminated duplicate diagnostic')
    lines = text[:-1].split('\n')
    need(len(lines) in (2, 3) and lines[-1] == 'collect2.exe: error: ld returned 1 exit status', 'closed duplicate trailer/line count')
    absolute = r'(?:[A-Za-z]:[\\/]|/)[^:\r\n\x00]+'
    obj = absolute + r'[.]o'
    ld = re.compile(r'(?P<path>' + absolute + r'): (?P<body>.+)')
    first = ld.fullmatch(lines[0])
    need(first is not None and Path(first['path']).resolve() == Path(linker).resolve(), 'duplicate linker identity')
    body = first['body']
    if len(lines) == 3:
        heading = re.fullmatch(r'(?P<object>' + obj + r"): in function `" + re.escape(expected) + r"':", body)
        need(heading is not None and Path(heading['object']).resolve() == Path(added_object).resolve(), 'duplicate heading owner')
        body = lines[1]
        left = re.escape(Path(added_source).name)
    else:
        left = r'(?P<added>' + obj + r')'
    section = r'\(\.text[.]' + re.escape(expected) + r'\+0x[0-9a-fA-F]+\)'
    pattern = (left + ':' + section + r": multiple definition of `" + re.escape(expected)
               + r"'; (?P<original>" + obj + r'):fiber_port[.]c:' + section + r': first defined here')
    match = re.fullmatch(pattern, body)
    need(match is not None and Path(match['original']).resolve() == Path(original_object).resolve(), 'exact duplicate symbol and original provider')
    if len(lines) == 2:
        need(Path(match['added']).resolve() == Path(added_object).resolve(), 'exact added provider')
    return dict(DuplicateSymbols=[expected], AddedObject=str(added_object), OriginalObject=str(original_object),
                Linker=str(linker), DiagnosticTextSha256=sha(text.encode('utf-8')), DiagnosticNormalization='CRLF-TO-LF-ONLY')


class Suite:
    def __init__(self, native_build, *, native_receipt_sha256, native_artifacts_sha256, output_dir):
        need(not sys.flags.optimize, 'unoptimized Python required')
        same([native_receipt_sha256, native_artifacts_sha256], [RECEIPT_SHA, ARTIFACTS_SHA], 'exact contracted retained producer')
        replay_path = ROOT / REPLAY
        for path in (replay_path, *replay_path.parents):
            info = path.lstat()
            need(not path.is_symlink() and not getattr(info, 'st_file_attributes', 0) & 0x400, 'dispatcher reparse path')
        replay_bytes = replay_path.read_bytes()
        need(sha(replay_bytes) == REPLAY_SHA, 'fixed replay utility')
        self.api = module('_cm0_cell_controls_replay', replay_path, replay_bytes)
        self.watch = self.api.Closure()
        need(self.watch.read(replay_path, REPLAY_SHA) == replay_bytes, 'executed utility bytes')
        self.base = self.api.checked_path(native_build, directory=True)
        self.output = self.api.checked_path(output_dir, fresh=True)
        self.admission = self.api.Admission(self.watch)
        self.bundle = self.admission.bundle(dict(Build=str(self.base), ReceiptSha256=RECEIPT_SHA, ArtifactsSha256=ARTIFACTS_SHA))
        self.result = self.bundle['Result']
        same([self.result['Verdict'], self.result['Profile'], self.result['Mode'], self.result['Cohort'], self.result['Linkage'], self.result['LTO']],
             ['NATIVE-FINAL-TWIN-BUILD-PASS', 'CM0', 'O2', COHORT, 'direct', False], 'fixed positive scope')
        need(self.result['Error'] is None and self.result['InputDrift'] == [] and self.result['SourceInventorySha256'] == INVENTORY_SHA,
             'closed current positive authority')
        self.sources = copy.deepcopy(self.result['Sources'])
        same([row['Source'] for row in self.sources], [str(self.base / 'source' / name) for name in SOURCES], 'nine exact ordered source providers')
        self.objects = tuple(self.base / 'objects' / ('%02d-' % index + Path(name).stem + '.o') for index, name in enumerate(SOURCES))
        same([row['Object'] for row in self.sources], [str(path) for path in self.objects], 'nine exact object identities')
        inputs = self.watch.json(self.base / 'inputs.json')['Files']
        inventory_root = Path(self.result['SourceInventoryReceipt'])
        catalog = {Path(row['Original']): row['Sha256'] for row in inputs}
        self.inventory = self.admission.snapshot(dict(Build=str(inventory_root), ReceiptSha256=catalog[inventory_root / 'results.json'],
            ArtifactsSha256=catalog[inventory_root / 'artifacts.json']), current=True)
        need(self.inventory['SourceInventorySha256'] == INVENTORY_SHA, 'exact E9 fingerprint')
        self.native = module('_cm0_cell_controls_native', ROOT / NATIVE, self.watch.read(ROOT / NATIVE, NATIVE_SHA))
        self.facade = module('_cm0_cell_controls_facade', ROOT / FACADE, self.watch.read(ROOT / FACADE, FACADE_SHA))
        self.process = module('_cm0_cell_controls_process', ROOT / PROCESS, self.watch.read(ROOT / PROCESS, PROCESS_SHA))
        self.watch.read(Path(__file__).resolve())
        contract = ROOT / 'tools/fixtures/freeze_cohorts/CM0_CELL_CONTRACT.md'
        self.watch.read(contract)
        commands = self.result['Commands']
        need(len(commands) == 73 and all(row['Status'] == 'PASS' and row['Exit'] == 0 and row['TimedOut'] is False for row in commands), 'positive command closure')
        self.tools = {}
        for key, label in (('gcc', 'compiler version'), ('nm', 'inspect 03-fiber_port.o.nm'),
                           ('objdump', 'inspect 03-fiber_port.o.dis'), ('readelf', 'inspect 03-fiber_port.o.attributes')):
            rows = [row for row in commands if row['Label'] == label]
            need(len(rows) == 1, 'unique actual tool role: ' + key)
            path = self.api.checked_path(rows[0]['Argv'][0])
            need(path in self.watch.hashes, 'tool must be a sealed retained input')
            self.tools[key] = path
        indices = [index for index, row in enumerate(commands) if row['Label'] == 'resolve ld']
        need(len(indices) == 1, 'actual linker resolution')
        linker_text = self.watch.read(self.base / ('command-%04d.stdout' % indices[0])).decode('utf-8').strip()
        self.tools['ld'] = self.api.checked_path(Path(linker_text).resolve(strict=True))
        need(self.tools['ld'] in self.watch.hashes, 'resolved linker must be authenticated')
        links = [row for row in commands if row['Label'] == 'link ordinary']
        need(len(links) == 1 and [row['Kind'] for row in self.result['Links']] == ['ordinary', 'emit-relocs'], 'positive ordinary recipe')
        self.link_argv = list(links[0]['Argv'])
        need([value for value in self.link_argv if value.endswith('.o')] == [str(path) for path in self.objects], 'exact direct link object order')
        need(not any('whole-archive' in value or value in ('-u', '-U') or '-flto' in value for value in self.link_argv), 'no archive/forced-anchor/LTO controls')
        self.environment = self.native.process_environment(os.environ)
        denied = self.watch.denied | {path.parent for path in self.watch.hashes}
        need(all(not self.output.is_relative_to(path) and not path.is_relative_to(self.output) for path in denied), 'output overlaps admitted inputs')
        self.watch.close()
        self.commands, self.expected, self.identities = [], {}, {}
        self._started = self._finished = self._controls_done = False
        self.report = dict(Status='FAIL', Scope='CM0_O2_DIRECT_FIVE_LINK_CONTROLS_ONLY', Base=dict(Build=str(self.base),
            ReceiptSha256=RECEIPT_SHA, ArtifactsSha256=ARTIFACTS_SHA), Cohort=COHORT, Profile='CM0', Mode='O2', Linkage='direct',
            SourceInventorySha256=INVENTORY_SHA, PositiveLinkRevalidated=False, Controls=[], Compilations=[],
            Error=None, PrimaryError=None, ClosingErrors=[], CellContractSatisfied=False, RequiredCellSatisfied=False,
            RequiredCellsSatisfied=0, FullABIProof=False, FullSemanticABIProof=False, PolicyEquivalence=False,
            CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False, OutputSealVerified=False)

    def source(self, index):
        need(type(index) is int and 0 <= index < 9, 'literal source index')
        return copy.deepcopy(self.sources[index])

    def _write(self, name, raw):
        name = self.api.relative_name(name)
        path = self.output / name
        self.api.checked_path(path, fresh=not path.exists())
        need(path not in self.watch.hashes or sha(raw) == self.watch.hashes[path], 'cannot rewrite consumed input')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        need(path.read_bytes() == raw, 'intended output bytes')
        info = path.stat()
        self.expected[name], self.identities[name] = sha(raw), (info.st_dev, info.st_ino, info.st_nlink, info.st_size)
        return path

    def _save(self, name, value):
        return self._write(name, encoded(value))

    def write_input(self, name, raw):
        need(self._started and not self._finished and type(raw) is bytes, 'active suite and input bytes required')
        path = self._write(name, raw)
        self.watch.read(path, sha(raw))
        return path

    def record_output(self, path, *, required=True):
        need(type(required) is bool, 'literal output requirement')
        path = Path(path)
        need(path.is_relative_to(self.output), 'owned output path')
        if not path.exists() and not required:
            return None
        path = self.api.checked_path(path)
        raw = path.read_bytes()
        name = path.relative_to(self.output).as_posix()
        info = path.stat()
        need(name not in self.expected or self.expected[name] == sha(raw), 'generated output changed')
        self.expected[name], self.identities[name] = sha(raw), (info.st_dev, info.st_ino, info.st_nlink, info.st_size)
        return dict(Path=str(path), Sha256=sha(raw))

    def start(self):
        need(not self._started, 'suite starts only once')
        self.watch.close()
        self.api.checked_path(self.output, fresh=True)
        self.output.mkdir(parents=True)
        self._started = True
        self._save('environment.json', self.environment)
        self._save('commands.json', self.commands)
        self._save('results.json', self.report)
        return self

    def verify_objects(self):
        for path, row in zip(self.objects, self.sources):
            self.watch.read(path, row['ObjectSha256'])

    def command(self, argv, label, expected_failure=False):
        need(self._started and not self._finished and type(expected_failure) is bool, 'active suite and literal expected-failure flag')
        need(type(argv) is list and argv and all(type(item) is str for item in argv), 'no-shell command array')
        executable = self.api.checked_path(argv[0])
        need(executable in set(self.tools.values()) - {self.tools['ld']}, 'only admitted compiler/inspection tools')
        self.watch.close()
        self.verify_objects()
        prefix = 'commands/%03d' % len(self.commands)
        row = dict(Label=label, Argv=list(argv), Cwd=str(self.output), State='ATTEMPT', ExpectedExit=1 if expected_failure else 0)
        self.commands.append(row)
        self._save(prefix + '.json', row)
        self._save('commands.json', self.commands)
        stdout = stderr = b''
        result = primary = tb = None
        try:
            result = self.process.run(argv, cwd=str(self.output), env=dict(self.environment), timeout=60)
            need(type(result.stdout) is bytes and type(result.stderr) is bytes and type(result.returncode) is int
                 and type(result.timed_out) is bool and type(result.elapsed) in (int, float)
                 and math.isfinite(result.elapsed) and result.elapsed >= 0, 'managed result schema')
            stdout, stderr = result.stdout, result.stderr
            row.update(Exit=result.returncode, TimedOut=result.timed_out, Seconds=result.elapsed)
            need(result.returncode == row['ExpectedExit'] and result.timed_out is False and b'[process-runner]' not in stderr,
                 'unexpected tool exit/timeout/cleanup: ' + label)
            row['Status'] = 'EXPECTED-NONZERO' if expected_failure else 'PASS'
        except BaseException as error:
            primary, tb = error, error.__traceback__
            row.update(Status='FAIL', Error=type(error).__name__ + ': ' + str(error))
        row.update(State='TERMINAL', Stdout=prefix + '.stdout', Stderr=prefix + '.stderr',
                   StdoutSha256=sha(stdout), StderrSha256=sha(stderr))
        failures = []
        def persist(name, action):
            try:
                action()
            except BaseException as error:
                message = 'terminal journal ' + name + ': ' + type(error).__name__ + ': ' + str(error)
                failures.append(message)
                self.report['ClosingErrors'].append(message)
                row.setdefault('JournalErrors', []).append(message)
                row['Status'] = 'FAIL'
        persist(prefix + '.stdout', lambda: self._write(prefix + '.stdout', stdout))
        persist(prefix + '.stderr', lambda: self._write(prefix + '.stderr', stderr))
        persist(prefix + '.json', lambda: self._save(prefix + '.json', row))
        persist('commands.json', lambda: self._save('commands.json', self.commands))
        if failures:
            persist(prefix + '.json', lambda: self._save(prefix + '.json', row))
            persist('commands.json', lambda: self._save('commands.json', self.commands))
        if primary is not None:
            raise primary.with_traceback(tb)
        if failures:
            raise Rejected('cm0-cell-controls: terminal journal failure: ' + failures[0])
        return result

    def _name(self, name):
        need(type(name) is str and re.fullmatch(r'[a-z][a-z0-9-]*', name), 'closed output namespace')
        return name

    def compile_tuple(self, index, *, name, mutations=(), source_bytes=None, save_temps=False):
        """Compile one positive TU; expected compile failures use command().

        With no mutation/new source, Source and CompileFlags are the exact
        retained values, plus only optional -save-temps=obj. Mutation triples
        refer to paths below the retained source tree and are applied once.
        """
        row = self.source(index)
        name = self._name(name)
        need(type(save_temps) is bool and isinstance(mutations, (tuple, list)), 'literal compile options')
        need(source_bytes is None or type(source_bytes) is bytes, 'new source bytes')
        need(not mutations or source_bytes is None, 'separate source addition and source mutation')
        directory = self.output / 'compilations' / name
        need(not directory.exists(), 'fresh compilation namespace')
        source, flags = Path(row['Source']), list(row['CompileFlags'])
        deltas = []
        if mutations:
            changes = {}
            for relative, before, after in mutations:
                self.api.relative_name(relative)
                need(relative not in changes and type(before) is bytes and before and type(after) is bytes and before != after, 'unique exact mutation')
                changes[relative] = (before, after)
            base_source = self.base / 'source'
            private_source = directory / 'source'
            found = set()
            for relative, expected in self.bundle['Artifacts'].items():
                if not relative.startswith('source/'):
                    continue
                suffix = relative[len('source/'):]
                raw = self.watch.read(self.base / relative, expected)
                changed = raw
                if suffix in changes:
                    before, after = changes[suffix]
                    need(raw.count(before) == 1, 'mutation anchor exactly once: ' + suffix)
                    changed = raw.replace(before, after, 1)
                    found.add(suffix)
                    deltas.append(dict(Original=str(self.base / relative), Copy=str(private_source / suffix),
                        BeforeSha256=sha(raw), AfterSha256=sha(changed), Before=before.hex(), After=after.hex(), Count=1))
                self.write_input((private_source / suffix).relative_to(self.output).as_posix(), changed)
            need(found == set(changes), 'all mutation files are admitted source copies')
            source = private_source / source.relative_to(base_source)
            flags = [flag.replace(str(base_source), str(private_source)) for flag in flags]
        elif source_bytes is not None:
            source = self.write_input((directory / (name.replace('-', '_') + '.c')).relative_to(self.output).as_posix(), source_bytes)
            deltas.append(dict(Kind='ADDED-CONTROL-TU', Source=str(source), Sha256=sha(source_bytes)))
        discovery_flags = list(flags)
        if save_temps:
            flags.append('-save-temps=obj')
        obj = directory / ('%02d-' % index + source.stem + '.o')
        obj.parent.mkdir(parents=True, exist_ok=True)
        discovery, actual = obj.with_suffix('.discovery.d'), obj.with_suffix('.compile.d')
        target = 'pilot-source-' + str(index)
        self.watch.read(source)
        gcc = str(self.tools['gcc'])
        first_command = len(self.commands)
        self.command([gcc, *discovery_flags, '-M', '-MF', str(discovery), '-MT', target, str(source)], 'discover ' + name)
        self.record_output(discovery)
        discovered = self.native.read_dependencies(discovery)
        self.command([gcc, *flags, '-MD', '-MF', str(actual), '-MT', target, '-c', str(source), '-o', str(obj)], 'compile ' + name)
        self.record_output(actual)
        object_record = self.record_output(obj)
        compiled = self.native.read_dependencies(actual)
        def dependencies(paths):
            result = []
            for path in paths:
                path = self.api.checked_path(path)
                need(path.is_relative_to(self.output) or path in self.watch.hashes, 'unadmitted compiler dependency')
                data = self.watch.read(path)
                result.append(dict(Path=str(path), Sha256=sha(data)))
            return result
        before, after = dependencies(discovered), dependencies(compiled)
        self.native.require_compile_dependencies(before, after)
        assembly = None
        if save_temps:
            self.record_output(obj.with_suffix('.i'))
            assembly = self.record_output(obj.with_suffix('.s'))
        evidence = dict(Name=name, TemplateIndex=index, OriginalSource=row['Source'], Source=str(source),
            SourceSha256=sha(self.watch.read(source)), OriginalObject=row['Object'], OriginalObjectSha256=row['ObjectSha256'],
            Object=object_record['Path'], ObjectSha256=object_record['Sha256'], Assembly=assembly,
            ObjectByteIdenticalToOriginal=object_record['Sha256'] == row['ObjectSha256'],
            CompileFlags=flags, DiscoveryFlags=discovery_flags, Dependencies=after, CompileDependenciesVerified=True,
            DiscoveryDependencyFile=str(discovery), CompileDependencyFile=str(actual), SourceDeltas=deltas,
            CommandIndices=list(range(first_command, len(self.commands))), SaveTemps=save_temps,
            SemanticProof=False, CpuExecution=False)
        self.report['Compilations'].append(evidence)
        self._save('compilations/' + name + '/receipt.json', evidence)
        self.verify_objects()
        return copy.deepcopy(evidence)

    def _link(self, name, objects, expected_failure=False):
        name = self._name(name)
        directory = self.output / 'links' / name
        need(not directory.exists(), 'fresh link namespace')
        directory.mkdir(parents=True)
        elf, link_map = directory / 'image.elf', directory / 'image.map'
        argv = []
        inserted = False
        for value in self.link_argv:
            if value in [str(path) for path in self.objects]:
                if not inserted:
                    argv.extend(str(path) for path in objects)
                    inserted = True
                continue
            if value.startswith('-Wl,-Map='):
                argv.append('-Wl,-Map=' + str(link_map))
            elif value == self.result['Links'][0]['Path']:
                argv.append(str(elf))
            else:
                argv.append(value)
        # Objects may all be replaced by control paths; count the generated list explicitly.
        need([value for value in argv if value.endswith('.o')] == [str(path) for path in objects], 'exact linked control object order')
        result = self.command(argv, 'link ' + name, expected_failure=expected_failure)
        self.record_output(link_map, required=not expected_failure)
        if expected_failure:
            need(not elf.exists(), 'failed link must not leave a final image')
        else:
            self.record_output(elf)
        self.verify_objects()
        return result, elf, link_map

    def _undefined(self, obj, name):
        result = self.command([str(self.tools['nm']), '-u', str(obj)], 'imports ' + name)
        names = []
        for line in diagnostic_text(result.stdout).splitlines():
            match = re.fullmatch(r'\s*U ([A-Za-z_][A-Za-z0-9_]*)', line)
            need(match is not None, 'complete strong undefined nm row')
            names.append(match[1])
        need(len(names) == len(set(names)), 'unique undefined symbols')
        return names, dict(Object=str(obj), Imports=names, RawNmSha256=sha(result.stdout))

    def _imports(self, obj, name, prefix):
        names, evidence = self._undefined(obj, name)
        wanted = [symbol for symbol in names if symbol.startswith(prefix)]
        need(len(wanted) == 1, 'one actual expected import')
        return wanted[0], dict(evidence, ExpectedImport=wanted[0])

    def _definitions(self, obj, label):
        result = self.command([str(self.tools['nm']), '-P', '-S', '--defined-only', str(obj)], 'definitions ' + label)
        records = []
        for line in diagnostic_text(result.stdout).splitlines():
            match = re.fullmatch(r'(\S+) ([A-Za-z?]) ([0-9a-fA-F]+)(?: ([0-9a-fA-F]+))?', line)
            need(match is not None, 'complete defined nm row')
            records.append(dict(Name=match[1], Kind=match[2], Value=int(match[3], 16), Size=int(match[4], 16) if match[4] else None))
        return records

    def run_link_controls(self):
        need(self._started and not self._finished and not getattr(self, '_controls_started', False), 'one batched link suite')
        self._controls_started = True
        positive, positive_elf, positive_map = self._link('positive', self.objects)
        original = self.watch.read(self.result['Links'][0]['Path'], self.result['Links'][0]['Sha256'])
        reproduced = self.watch.read(positive_elf, self.expected[positive_elf.relative_to(self.output).as_posix()])
        need(reproduced == original, 'same objects/flags must reproduce the retained ordinary ELF bytes')
        self.report.update(PositiveLinkRevalidated=True, PositiveAuthority=dict(Original=self.result['Links'][0]['Path'],
            OriginalSha256=sha(original), Replayed=str(positive_elf), ReplayedSha256=sha(reproduced), Map=str(positive_map),
            ElfByteIdentical=True, Scope='SAME_OBJECTS_AND_LINK_FLAGS_RAW_ELF_REPRODUCTION_ONLY'))
        runtime_nm = self.watch.read(self.objects[3].with_suffix('.nm')).decode('ascii')
        private = [line.split()[0] for line in runtime_nm.splitlines() if line.startswith('fiber_port_context_cohort_')]
        need(len(private) == 1 and private[0].count('_g2_') == 1, 'actual private identity with NVIC2')
        alternate = private[0].replace('_g2_', '_g3_', 1)
        anchor, anchor_import = self._imports(self.objects[4], 'unchanged-boot-v1', 'fiber_internal_runtime_port_abi_')
        need(anchor == 'fiber_internal_runtime_port_abi_v1_anchor', 'actual unchanged reverse-v1 consumer')
        specs = (
            (CONTROLS[0], 6, (('tools/fixtures/classic_final_image/main.h', b'#define __NVIC_PRIO_BITS 2U', b'#define __NVIC_PRIO_BITS 3U'),), None, alternate),
            (CONTROLS[1], 7, (('fiber/port/ARM_CM0/fiber_port_types.h', b'#define FIBER_PORT_STORAGE_COHORT_REVISION 1', b'#define FIBER_PORT_STORAGE_COHORT_REVISION 999'),), None, 'fiber_port_storage_cohort_arm_cm0_v999_r0'),
            (CONTROLS[2], 1, (('context/context_runtime_state.c', b'const unsigned char fiber_internal_runtime_port_abi_v1_anchor =',
                b'const unsigned char fiber_internal_runtime_port_abi_v2_anchor ='),), None, anchor),
            (CONTROLS[3], 3, (), b'void SVC_Handler(void) { for (;;) { } }\n', 'SVC_Handler'),
            (CONTROLS[4], 3, (), b'void PendSV_Handler(void) { for (;;) { } }\n', 'PendSV_Handler'),
        )
        for name, index, mutations, added, expected in specs:
            record = dict(Name=name, Status='FAIL', Expected=expected, ProviderIndex=index if added is None else 9,
                ReplacedIndex=index if added is None else None, RequiredCellsSatisfied=0, SemanticProof=False)
            self.report['Controls'].append(record)
            self._save('results.json', self.report)
            compilation = self.compile_tuple(index, name=name, mutations=mutations, source_bytes=added)
            obj = Path(compilation['Object'])
            self.watch.read(obj, compilation['ObjectSha256'])
            selected = list(self.objects)
            if added is None:
                selected[index] = obj
            else:
                selected.append(obj)
            if name == CONTROLS[0]:
                imported, import_record = self._imports(obj, name, 'fiber_port_context_cohort_')
                need(imported == alternate and imported != private[0], 'actual alternate NVIC import, not a fake anchor')
                record['ImportEvidence'] = import_record
            elif name == CONTROLS[1]:
                imported, import_record = self._imports(obj, name, 'fiber_port_storage_cohort_')
                need(imported == expected, 'actual stale application storage import')
                record['ImportEvidence'] = import_record
            elif name == CONTROLS[2]:
                definitions = self._definitions(obj, name)
                names = [row['Name'] for row in definitions]
                need(names.count('fiber_internal_runtime_port_abi_v2_anchor') == 1 and anchor not in names,
                     'state defines only the changed anchor')
                changed = next(row for row in definitions if row['Name'] == 'fiber_internal_runtime_port_abi_v2_anchor')
                need(changed['Kind'] == 'R' and changed['Size'] == 1, 'actual changed data anchor')
                imports, changed_imports = self._undefined(obj, name)
                need(anchor not in imports, 'old-anchor failure must come from unchanged consumers, not changed state')
                record.update(ChangedDefinitions=definitions, ChangedImports=changed_imports, ImportEvidence=anchor_import)
            else:
                definitions = self._definitions(obj, name)
                selected_defs = [row for row in definitions if row['Name'] == expected]
                need(len(selected_defs) == 1 and selected_defs[0]['Kind'] == 'T' and selected_defs[0]['Size'] > 0,
                     'one actual strong duplicate handler')
                record['AddedDefinition'] = selected_defs[0]
            first = len(self.commands)
            result, elf, link_map = self._link(name, selected, expected_failure=True)
            if added is None:
                text_result = SimpleNamespace(returncode=result.returncode, stdout=diagnostic_text(result.stdout), stderr=diagnostic_text(result.stderr))
                need('lto-wrapper' not in text_result.stderr, 'ordinary control cannot use LTO notices')
                missing = self.facade.classify_unresolved(text_result, expected, self.tools['ld'])
                need(missing == expected, 'closed intended unresolved classification')
                classification = dict(MissingSymbols=[missing], DiagnosticTextSha256=sha(text_result.stderr.encode('utf-8')),
                                      DiagnosticNormalization='CRLF-TO-LF-ONLY', ClassifierSha256=FACADE_SHA)
            else:
                classification = classify_duplicate(result, expected, self.tools['ld'], obj, self.objects[3], compilation['Source'])
            self.verify_objects()
            self.watch.close()
            record.update(Status='INTENDED-LINK-REJECTION-PASS', Compilation=compilation, Classification=classification,
                LinkCommandIndex=first, FinalImageAbsent=not elf.exists(), PartialMap=str(link_map) if link_map.exists() else None,
                ConsumedObjects=[dict(Index=position, Path=str(path), Sha256=sha(self.watch.read(path))) for position, path in enumerate(selected)])
            self._save('controls/' + name + '.json', record)
            self._save('results.json', self.report)
        same([row['Name'] for row in self.report['Controls']], list(CONTROLS), 'all five ordered actual controls')
        need(all(row['Status'] == 'INTENDED-LINK-REJECTION-PASS' for row in self.report['Controls']), 'all intended rejection controls')
        self._controls_done = True
        return copy.deepcopy(self.report['Controls'])

    def _verify_outputs(self):
        actual = self.api.files_under(self.output)
        same(sorted(actual), sorted(self.expected), 'exact declared output membership')
        identities = set()
        for name, path in actual.items():
            info = path.stat()
            identity = (info.st_dev, info.st_ino, info.st_nlink, info.st_size)
            need(identity == self.identities[name] and info.st_nlink == 1 and identity[:2] not in identities, 'output physical alias/drift')
            identities.add(identity[:2])
            need(sha(path.read_bytes()) == self.expected[name], 'output hash drift: ' + name)

    def _failure(self, error):
        message = type(error).__name__ + ': ' + str(error)
        if self.report['PrimaryError'] is None:
            self.report.update(Error=message, PrimaryError=message)
        elif self.report['PrimaryError'] != message:
            self.report['ClosingErrors'].append(message)
        self.report.update(Status='FAIL', OutputSealVerified=False)

    def finish(self, error=None):
        need(not self._finished, 'finish only once')
        self._finished = True
        if error is None and not (self._controls_done and self.report['PositiveLinkRevalidated']
                and len(self.report['Controls']) == 5 and self.commands
                and all(row['State'] == 'TERMINAL' and row['Status'] in ('PASS', 'EXPECTED-NONZERO') for row in self.commands)):
            error = Rejected('cm0-cell-controls: incomplete or failed control suite')
        if error is not None:
            self._failure(error)
        if not self._started:
            return copy.deepcopy(self.report)
        try:
            self.verify_objects()
            self.watch.close()
            self._verify_outputs()
            self.report.update(Status='CM0-O2-DIRECT-LINK-CONTROLS-PASS' if error is None else 'FAIL',
                OutputSealVerified=True, InputClosureVerified=error is None, ClosingFilesVerified=len(self.watch.hashes),
                InputHashes={str(path): value for path, value in sorted(self.watch.hashes.items())},
                InputPhysicalIdentities={str(path): list(value) for path, value in sorted(self.watch.identities.items())},
                Commands=self.commands, CommandsSha256=self.expected['commands.json'],
                IntendedLinkRejects=sum(row['Status'] == 'INTENDED-LINK-REJECTION-PASS' for row in self.report['Controls']))
            self._save('results.json', self.report)
            manifest = {name: value for name, value in self.expected.items() if name != 'artifacts.json'}
            self._save('artifacts.json', dict(Artifacts=manifest))
            self.watch.close()
            self._verify_outputs()
            same(self.api.structured((self.output / 'artifacts.json').read_bytes()), dict(Artifacts=manifest), 'written manifest semantics')
        except BaseException as failure:
            self._failure(failure)
            try:
                self._save('results.json', self.report)
                actual = self.api.files_under(self.output)
                self._write('artifacts.json', encoded(dict(Artifacts={name: sha(path.read_bytes()) for name, path in actual.items() if name != 'artifacts.json'})))
            except BaseException:
                pass
        return copy.deepcopy(self.report)


ControlSession = Suite


def run_controls(native_build, *, native_receipt_sha256, native_artifacts_sha256, output_dir):
    suite = Suite(native_build, native_receipt_sha256=native_receipt_sha256,
                  native_artifacts_sha256=native_artifacts_sha256, output_dir=output_dir)
    error = None
    try:
        suite.start()
        suite.run_link_controls()
    except BaseException as failure:
        error = failure
    return suite.finish(error)
