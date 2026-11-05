"""Capture ordinary frozen components from explicit tools, never qualify cells."""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent
REPLAY = 'tools/freeze_replay.py'
REPLAY_SHA = '142BDDE647122DB2D66EF66E4C44A33ECEAA9292FFE304EF3C7CBCC740283275'
CONTRACT = 'tools/fixtures/freeze_cohorts/CAPTURE_CONTRACT.md'
RUNNER = 'tools/fixtures/freeze_cohorts/process_runner.py'
NATIVE = 'tools/fixtures/classic_final_image/run.py'
MODES = ('O0', 'Og', 'O2', 'Os', 'O3')
PIN = 'a50edad08b29052631aa469d4df6e6ec7ff68878'
PROFILES = {
    'CM0': ('cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default', 'CM0', 'cm0'),
    'CM0PLUS': ('cm0-cortex-m0plus-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default', 'CM0', 'cm0'),
    'CM0PLUSVTOR': ('cm0-cortex-m0plus-soft-nofpu-none-v1-mpu0-p2-b0-aapcs-default', 'CM0', 'cm0'),
    'CM3': ('cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default', 'CM3', 'cm3'),
    'CM4': ('cm4-cortex-m4-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default', 'CM4', 'classic'),
    'CM7': ('cm7-cortex-m7-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default', 'CM7', 'classic'),
}
CHECKPOINTS = ('before-prelink', 'after-prelink', 'before-link-ordinary', 'after-link-ordinary',
               'before-link-emit-relocs', 'after-link-emit-relocs', 'closing')
NATIVE_ROOTS = ('fiber_port_start_first_context', 'SVC_Handler', 'PendSV_Handler')
REFERENCE_ROOTS = ('prvPortStartFirstTask', 'vPortSVCHandler', 'xPortPendSVHandler')
CM0_ROOTS = ('vStartFirstTask', 'SVC_Handler', 'vPortSVCHandler_C', 'vRestoreContextOfFirstTask', 'PendSV_Handler')


class Rejected(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected('freeze-capture: ' + message)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def same(actual, expected, message):
    need(encoded(actual) == encoded(expected), message)


def routes():
    return {profile + '/' + mode + '/direct': dict(Profile=profile, Mode=mode, Linkage='direct',
                Cohort=cohort, SourceGroup=group, ArtifactRole='runtime',
                Gate='tools/fixtures/' + family + '_final_join/join.py')
            for profile, (cohort, group, family) in PROFILES.items() for mode in MODES}


def validate_request(value):
    need(type(value) is dict and set(value) == {'SchemaVersion', 'Routes'}, 'exact request fields')
    need(type(value['SchemaVersion']) is int and value['SchemaVersion'] == 1, 'literal schema version 1')
    rows = value['Routes']
    need(type(rows) is list and 0 < len(rows) <= 30 and all(type(row) is str for row in rows), 'nonempty ordinary route list')
    need(len(set(rows)) == len(rows) and all(row in routes() for row in rows), 'unique closed ordinary routes')
    return list(rows)


def stage_arguments(route_id, stage, *, gcc, cmsis, git, freertos, python_modules, inventory,
                    case_dir, native=None, reference=None):
    need(type(route_id) is str and route_id in routes(), 'closed ordinary route')
    need(type(stage) is str and stage in ('Native', 'Reference', 'Join'), 'fixed stage')
    route, case_dir = routes()[route_id], Path(case_dir)
    profile, mode = route['Profile'], route['Mode']
    if stage == 'Join':
        need(type(native) is dict and type(reference) is dict, 'both producer descriptors required')
        result = [str(ROOT / route['Gate'])]
        for side, row in (('native', native), ('reference', reference)):
            need(set(row) == {'Build', 'ReceiptSha256', 'ArtifactsSha256'}, 'exact producer descriptor')
            result.extend(['--' + side + '-build', str(row['Build']), '--' + side + '-receipt-sha256', row['ReceiptSha256'],
                           '--' + side + '-artifacts-sha256', row['ArtifactsSha256']])
        return [*result, '--output-dir', str(case_dir / stage), '--profile', profile, '--mode', mode]
    need(native is None and reference is None, 'producer stage does not accept descriptors')
    if stage == 'Native':
        result = [str(ROOT / NATIVE), '--gcc', str(gcc), '--cmsis', str(cmsis)]
    else:
        family = PROFILES[profile][2]
        fixture = 'classic_final_image' if family == 'classic' else family + '_final_image'
        result = [str(ROOT / ('tools/fixtures/' + fixture + '/reference_run.py')), '--gcc', str(gcc),
                  '--git', str(git), '--freertos', str(freertos)]
    return [*result, '--python-modules', str(python_modules), '--inventory', str(inventory),
            '--profile', profile, '--mode', mode, '--output-dir', str(case_dir / stage)]


def scope_report():
    return dict(Status='FAIL', Error=None, PrimaryError=None, ClosingErrors=[],
        Scope='CURRENT_INVENTORY_ORDINARY_COMPONENT_CAPTURE_ONLY', Cases=[], Pending=[],
        CatalogReady=False, FinalBatchClosureRequired=True, InputClosureVerified=False, OutputSealVerified=False,
        RequiredCellSatisfied=False, RequiredCellsSatisfied=0, CompleteObjectProof=False,
        FullABIProof=False, APIProof=False, FinalReferenceParity=False, InstructionEquivalence=False,
        PolicyEquivalence=False, CpuExecution=False, BoardExecution=False, GlobalFreezeQualified=False,
        Counts=dict(Cases=0, TranslationUnits=0, Links=0, Checkpoints=0, ToolCommands=0,
                    ClosedBodies=0, Mechanisms=0, OuterPythonInvocations=0))


def expected_counts(request):
    result = dict(Cases=len(request), TranslationUnits=0, Links=4 * len(request), Checkpoints=14 * len(request),
                  ToolCommands=0, ClosedBodies=0, Mechanisms=3 * len(request), OuterPythonInvocations=3 * len(request))
    for route_id in request:
        cm0 = routes()[route_id]['SourceGroup'] == 'CM0'
        result['TranslationUnits'] += 14 if cm0 else 13
        result['ToolCommands'] += 152 if cm0 else 144
        result['ClosedBodies'] += 8 if cm0 else 6
    return result


def pinned_replay():
    path = ROOT / REPLAY
    for parent in (path, *path.parents):
        info = parent.lstat()
        need(not parent.is_symlink() and not getattr(info, 'st_file_attributes', 0) & 0x400, 'dispatcher reparse path')
    raw = path.read_bytes()
    need(sha(raw) == REPLAY_SHA, 'fixed dispatcher source')
    spec = importlib.util.spec_from_file_location('_freeze_capture_replay', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module, raw


def prepare(args):
    need(not sys.flags.optimize, 'unoptimized Python required')
    api, replay_raw = pinned_replay()
    watch = api.Closure()
    need(watch.read(ROOT / REPLAY, REPLAY_SHA) == replay_raw, 'dispatcher parsed/executed buffer')
    same(routes(), {key: row for key, row in api.routes().items() if row['Mode'] in MODES}, 'exact pinned ordinary routes')
    request_path = api.checked_path(args.request)
    request_raw = watch.read(request_path, api.digest(args.request_sha256))
    need(request_raw.isascii(), 'ASCII request')
    request = validate_request(api.structured(request_raw))
    admission = api.Admission(watch)
    inventory = admission.snapshot(dict(Build=args.inventory, ReceiptSha256=api.digest(args.inventory_receipt_sha256),
                                       ArtifactsSha256=api.digest(args.inventory_artifacts_sha256)), current=True)
    for name, value in api.SOURCE_PINS.items():
        watch.read(ROOT / name, value)
    watch.read(Path(__file__).resolve())
    watch.read(ROOT / CONTRACT)
    tools = {key: api.checked_path(getattr(args, key)) for key in ('gcc', 'git')}
    directories = {key: api.checked_path(getattr(args, key), directory=True)
                   for key in ('cmsis', 'freertos', 'python_modules')}
    for name in ('objdump', 'readelf', 'nm'):
        tools[name] = api.checked_path(tools['gcc'].with_name('arm-none-eabi-' + name + '.exe'))
    interpreter = api.interpreter_path()
    for path in (*tools.values(), interpreter):
        watch.read(path)
    memberships = {}
    for root, suffix in ((directories['cmsis'], '.h'), (directories['python_modules'] / 'elftools', '.py')):
        root = api.checked_path(root, directory=True)
        names = {name: path for name, path in api.files_under(root).items() if path.suffix == suffix}
        need(names, 'nonempty explicit CMSIS/parser inputs')
        memberships[root] = (suffix, set(names))
        for path in names.values():
            watch.read(path)
    environment = api.process_environment(dict(os.environ))
    output = api.checked_path(args.output_dir, fresh=True)
    denied = watch.denied | set(directories.values()) | {interpreter.parent, request_path.parent}
    denied |= {path.parent for path in watch.hashes}
    need(all(not output.is_relative_to(path) and not path.is_relative_to(output) for path in denied), 'output/input overlap')
    for route_id in request:
        route = routes()[route_id]
        cells = [row for row in inventory['Required']['RequiredCells'] if api._cell_key(row) == api._selection_key(route)]
        need(len(cells) == 1 and cells[0]['SourceGroup'] == route['SourceGroup'], 'exact inventory route cell')
    native = api.fixed_module('_freeze_capture_native', NATIVE, watch)
    recipe = api.fixed_module('_freeze_capture_recipe', 'tools/fixtures/freeze_cohorts/build_recipe.py', watch)
    ref_recipe = api.fixed_module('_freeze_capture_reference_recipe', 'tools/fixtures/freeze_cohorts/reference_recipe.py', watch)
    runner = api.fixed_module('_freeze_capture_runner', RUNNER, watch)
    watch.close()
    return Capture(api, watch, admission, inventory, request, request_raw, request_path, output,
                   tools, directories, memberships, interpreter, environment, native, recipe, ref_recipe, runner)


class Capture:
    def __init__(self, api, watch, admission, inventory, request, request_raw, request_path, output,
                 tools, directories, memberships, interpreter, environment, native, recipe, ref_recipe, runner):
        self.api, self.watch, self.admission, self.inventory = api, watch, admission, inventory
        self.request, self.request_raw, self.request_path, self.output = request, request_raw, request_path, output
        self.tools, self.directories, self.memberships = tools, directories, memberships
        self.interpreter, self.environment, self.runner = interpreter, environment, runner
        self.native, self.recipe, self.ref_recipe = native, recipe, ref_recipe
        self.expected, self.output_identities, self.commands, self.completed = {}, {}, [], []
        self.opening_paths, self.opening_roots = set(watch.hashes), set(watch.trees)
        self.opening_buffers = dict(watch.buffers)
        self._started = self._completed = False
        self._active_case = None
        self.report = scope_report()
        self.report.update(Request=dict(Path=str(request_path), Sha256=sha(request_raw), Routes=list(request)),
            Dispatcher=dict(Path=str(ROOT / REPLAY), Sha256=REPLAY_SHA), SourcePins=dict(api.SOURCE_PINS),
            Inventory=dict(inventory['Bundle']['Descriptor'], SourceInventorySha256=inventory['SourceInventorySha256']),
            Interpreter=dict(ModulePath=str(interpreter), Sha256=watch.hashes[interpreter], Version=sys.version),
            ToolInputs={key: dict(Path=str(path), Sha256=watch.hashes[path], PhysicalIdentity=list(watch.identities[path]))
                        for key, path in tools.items()}, ExpectedCounts=expected_counts(request))
        self.report['Cases'] = [dict(Route=route_id, Profile=routes()[route_id]['Profile'], Mode=routes()[route_id]['Mode'],
            Status='PENDING', Stage=None, CaseClosed=False, Descriptors={}, Audits={}, RequiredCellSatisfied=False,
            RequiredCellsSatisfied=0, GlobalFreezeQualified=False) for route_id in request]

    def _write(self, name, raw):
        name = self.api.relative_name(name)
        path = self.output / name
        self.api.checked_path(path, fresh=not path.exists())
        path.parent.mkdir(parents=True, exist_ok=True)
        self.api.checked_path(path.parent, directory=True)
        path.write_bytes(raw)
        need(path.read_bytes() == raw, 'intended output bytes: ' + name)
        info = path.stat()
        self.expected[name] = sha(raw)
        self.output_identities[name] = (info.st_dev, info.st_ino, info.st_nlink, info.st_size)
        return path

    def _json(self, name, value):
        return self._write(name, encoded(value))

    def _pending(self):
        rows = [dict(Route=row['Route'], Status=row['Status'], Stage=row['Stage'],
                     Reason='FAILED_STAGE_OR_CLOSURE' if row['Status'] == 'FAIL' else 'NOT_COMPLETED',
                     RequiredCellSatisfied=False, RequiredCellsSatisfied=0)
                for row in self.report['Cases'] if not row['CaseClosed']]
        self.report['Pending'] = rows
        return dict(Routes=rows, CatalogReady=self.report['CatalogReady'],
                    FinalBatchClosureRequired=self.report['FinalBatchClosureRequired'],
                    RequiredCellsSatisfied=0, GlobalFreezeQualified=False)

    def _memberships(self):
        for root, (suffix, names) in self.memberships.items():
            same(sorted(name for name, path in self.api.files_under(root).items() if path.suffix == suffix), sorted(names),
                 'opening CMSIS/parser membership')

    def _close_inputs(self, paths=None, roots=None):
        for path in tuple(self.watch.hashes if paths is None else paths):
            self.watch.read(path, self.watch.hashes[path])
        for root in tuple(self.watch.trees if roots is None else roots):
            same(sorted(self.api.files_under(root)), sorted(self.watch.trees[root]), 'closing input artifact membership')
        self._memberships()

    def _verify_outputs(self, prefix=None):
        actual = self.api.files_under(self.output)
        same(sorted(actual), sorted(self.expected), 'exact output membership')
        seen = set()
        for name, path in actual.items():
            info = path.stat()
            identity = (info.st_dev, info.st_ino, info.st_nlink, info.st_size)
            need(identity == self.output_identities[name] and info.st_nlink == 1 and identity[:2] not in seen, 'output physical identity')
            seen.add(identity[:2])
            if prefix is None or name.startswith(prefix) or not name.startswith('cases/'):
                need(sha(path.read_bytes()) == self.expected[name], 'output hash drift: ' + name)

    def _snapshot(self, case_dir):
        buffers = dict(self.opening_buffers)
        aliases = []
        package = self.directories['python_modules'] / 'elftools'
        for original, data in self.opening_buffers.items():
            relative = original.relative_to(ROOT) if original.is_relative_to(ROOT) else None
            parser = original.relative_to(package) if original.is_relative_to(package) else None
            if relative is None and parser is None:
                continue
            for side in ('Native', 'Reference'):
                copy = (case_dir / side / 'source' / relative if relative is not None
                        else case_dir / side / 'python/elftools' / parser)
                need(copy not in buffers or buffers[copy] == data, 'source alias collision')
                buffers[copy] = data
                aliases.append(dict(Original=str(original), Copy=str(copy), Sha256=sha(data), OpeningPhysicalInput=False))
        sources = {}
        for original, data in sorted(buffers.items()):
            name = 'source-bytes/' + sha(data) + '.py'
            if name not in self.expected:
                self._write(name, data)
            sources[str(original)] = dict(Captured=str(self.output / name), Sha256=sha(data))
        self.sources, self.aliases = sources, aliases
        name = 'sources/' + case_dir.name + '.json'
        self.source_snapshot = self._json(name, dict(Loader=str(ROOT / self.api.LOADER), Sources=sources,
            Aliases=aliases, ClosedRoots=[str(ROOT), str(self.output), str(self.inventory['Bundle']['Root'])]))
        self.source_snapshot_sha = self.expected[name]

    def _actual_aliases(self, side, case_dir, executed):
        used = {row['Path'] for row in executed}
        for row in self.aliases:
            copy = Path(row['Copy'])
            if not copy.is_relative_to(case_dir / side):
                continue
            need(str(copy) not in used or copy.is_file(), 'executed future alias was never materialized')
            if copy.exists():
                value = self.watch.read(copy, row['Sha256'])
                need(value == self.opening_buffers[Path(row['Original'])], 'actual source/parser copy differs from admitted source')

    def command(self, argv, label, timeout=900):
        need(type(argv) is list and all(type(value) is str for value in argv)
             and argv[:6] == [str(self.interpreter), '-I', '-S', '-B', '-c', self.api.BOOTSTRAP], 'fixed immutable Python bootstrap')
        labels = {route_id + ':' + stage for route_id in self.request for stage in ('Native', 'Reference', 'Join')}
        need(type(label) is str and label in labels and type(timeout) is int and 0 < timeout <= 900, 'bounded requested stage')
        prefix = 'commands/%03d' % len(self.commands)
        row = dict(Label=label, Argv=list(argv), Cwd=str(self.output), State='ATTEMPT', TimeoutSeconds=timeout,
                   RunnerSha256=self.api.SOURCE_PINS[RUNNER], EnvironmentSha256=sha(encoded(self.environment)))
        self.commands.append(row)
        self._json(prefix + '.json', row)
        self._json('commands.json', self.commands)
        stdout = stderr = b''
        result, primary, primary_traceback = None, None, None
        try:
            result = self.runner.run(argv, cwd=str(self.output), env=dict(self.environment), timeout=timeout)
            need(type(result.stdout) is bytes and type(result.stderr) is bytes and type(result.returncode) is int
                 and type(result.timed_out) is bool and type(result.elapsed) in (int, float)
                 and math.isfinite(result.elapsed) and result.elapsed >= 0, 'typed managed result')
            stdout, stderr = result.stdout, result.stderr
            row.update(ReturnCode=result.returncode, TimedOut=result.timed_out, Seconds=result.elapsed,
                       Cleanup='FAILED_OR_UNCONFIRMED' if result.returncode == 125 or b'[process-runner]' in stderr else 'MANAGED_RUNNER_RETURNED')
            need(result.returncode == 0 and result.timed_out is False and b'[process-runner]' not in stderr, 'failed stage: ' + label)
            row['Status'] = 'PASS'
        except BaseException as error:
            primary, primary_traceback = error, error.__traceback__
            row.update(Status='FAIL', Error=type(error).__name__ + ': ' + str(error))
        row.update(State='TERMINAL', Stdout=prefix + '.stdout', Stderr=prefix + '.stderr',
                   StdoutSha256=sha(stdout), StderrSha256=sha(stderr))
        journal_errors = []

        def persist(name, action):
            try:
                action()
            except BaseException as failure:
                message = 'terminal journal ' + name + ': ' + type(failure).__name__ + ': ' + str(failure)
                journal_errors.append(message)
                self.report['ClosingErrors'].append(message)
                row.setdefault('JournalErrors', []).append(message)
                row['Status'] = 'FAIL'
                if primary is None:
                    row['Error'] = 'terminal journal persistence failed'

        # A missing stream must not suppress the other stream or terminal records.
        persist(prefix + '.stdout', lambda: self._write(prefix + '.stdout', stdout))
        persist(prefix + '.stderr', lambda: self._write(prefix + '.stderr', stderr))
        persist(prefix + '.json', lambda: self._json(prefix + '.json', row))
        persist('commands.json', lambda: self._json('commands.json', self.commands))
        if journal_errors:
            # Repair metadata after a one-shot failure; this cannot restore PASS.
            persist(prefix + '.json', lambda: self._json(prefix + '.json', row))
            persist('commands.json', lambda: self._json('commands.json', self.commands))
        if primary is not None:
            raise primary.with_traceback(primary_traceback)
        if journal_errors:
            raise Rejected('freeze-capture: terminal journal persistence failed: ' + journal_errors[0])
        return result

    def _artifact(self, route):
        cohorts = [row for row in self.inventory['Manifest']['cohorts'] if row['id'] == route['Cohort']]
        need(len(cohorts) == 1 and len(cohorts[0]['artifacts']) == 1, 'unique exact cohort artifact')
        return cohorts[0]['artifacts'][0]

    def _input_rows(self, bundle):
        root, result = bundle['Root'], bundle['Result']
        if 'inputs.json' in bundle['Artifacts']:
            inputs = self.watch.json(root / 'inputs.json', bundle['Artifacts']['inputs.json'])
            rows, generated = inputs['Files'], inputs['Generated']
        else:
            rows, generated = result['Inputs'], {}
        need(type(rows) is list and rows and type(generated) is dict, 'complete input records')
        originals = [self.api.checked_path(row['Original']) for row in rows]
        need(len(set(originals)) == len(rows), 'unique input originals')
        paths = set(originals)
        paths.update(self.api.checked_path(row['Captured']) for row in rows if row['Captured'] is not None)
        paths.update(self.api.checked_path(path) for path in generated)
        return rows, generated, paths

    def _producer(self, bundle, route, side):
        root, result = bundle['Root'], bundle['Result']
        profile, mode = route['Profile'], route['Mode']
        cm0, cm3 = route['SourceGroup'] == 'CM0', profile == 'CM3'
        expected = self._artifact(route)
        same(result['CohortArtifact'], expected, 'full typed inventory artifact')
        same([result['Profile'], result['Mode'], result['Cohort'], result['Linkage'], result['LTO']],
             [profile, mode, route['Cohort'], 'direct', False], 'exact producer selection')
        need(Path(result['SourceInventoryReceipt']) == self.inventory['Bundle']['Root']
             and result['SourceInventorySha256'] == self.inventory['SourceInventorySha256'], 'current inventory authority')
        verdict = ('NATIVE-FINAL-TWIN-BUILD-PASS' if side == 'Native' else
                   'REFERENCE-CM0-FINAL-TWIN-BUILD-PASS' if cm0 else
                   'REFERENCE-CM3-FINAL-TWIN-BUILD-PASS' if cm3 else 'REFERENCE-CLASSIC-FP-FINAL-TWIN-BUILD-PASS')
        need(result['Verdict'] == verdict and result['Error'] is None and result['InputDrift'] == [], 'producer terminal result')
        scope = ('NATIVE_CM0_DIRECT_TWIN_BUILD_ONLY' if cm0 else 'NATIVE_CM3_DIRECT_TWIN_BUILD_ONLY' if cm3
                 else 'NATIVE_CLASSIC_FP_DIRECT_TWIN_BUILD_ONLY') if side == 'Native' else (
                 'PINNED_REFERENCE_CM0_FIVE_OWNING_PRELINK_ROOTS_AND_DIRECT_TWINS_ONLY' if cm0 else
                 'PINNED_REFERENCE_CM3_THREE_OWNING_PRELINK_ROOTS_AND_DIRECT_TWINS_ONLY' if cm3 else
                 'PINNED_REFERENCE_' + profile + '_' + mode + '_DIRECT_TWIN_BUILD_ONLY')
        same(result['ProofScope'], scope, 'exact producer scope')
        fixture_name = 'classic_final_image' if side == 'Native' or not (cm0 or cm3) else ('cm0' if cm0 else 'cm3') + '_final_image'
        fixture = root / 'source/tools/fixtures' / fixture_name
        if side == 'Reference':
            fixture /= 'reference'
        source_root = root / 'source'
        if side == 'Native':
            cohort, port, storage, selected = self.native.selection(profile, mode)
            need(cohort == route['Cohort'], 'fixed native model cohort')
            relative = (*self.native.COMMON_SOURCES, *selected, 'fiber/port/fiber_port_context_cohort_expectation.c',
                        'tools/fixtures/classic_final_image/application.c', 'tools/fixtures/classic_final_image/startup.S')
            sources = [source_root / name for name in relative]
            flags = self.recipe.native_flags(expected, mode, fixture, source_root / 'fiber/port' / port, source_root, root / 'cmsis')
            need(self.watch.read(fixture / 'main.h') == self.recipe.cmsis_main(expected['target']).encode('ascii'), 'generated hardware facts')
            guard = result['PrelinkStartupLiteralGuard']
            same([guard['ExpectedLiteralCount'], guard['ObservedLiteralCount'], guard['LiteralPredicateSatisfied']],
                 [int(expected['target']['vtor']), int(expected['target']['vtor']), True], 'source-backed startup VTOR guard')
        else:
            sources = [*(root / 'freertos' / name for name in expected['upstream_sources']),
                       *(fixture / name for name in ('providers.c', 'consumer.c', 'startup.S'))]
            binding = self.ref_recipe.reference_recipe(expected, mode, fixture, root / 'freertos')
            flags = binding['Flags']
            config = binding['ConfigText']
            if cm0:
                config = config.removesuffix('#endif\n') + ('#undef configCHECK_HANDLER_INSTALLATION\n#define configCHECK_HANDLER_INSTALLATION %d\n#endif\n' % int(expected['target']['vtor']))
                same(result['FixtureHandlerInstallationCheck'], int(expected['target']['vtor']), 'CM0 handler-check VTOR policy')
            elif cm3:
                config = config.removesuffix('#endif\n') + ('#undef configCHECK_HANDLER_INSTALLATION\n#define configCHECK_HANDLER_INSTALLATION 1\n'
                    '#undef configPRIO_BITS\n#define configPRIO_BITS 4\n#define __NVIC_PRIO_BITS 4\n#endif\n')
            need(self.watch.read(fixture / 'FreeRTOSConfig.h') == config.encode('ascii'), 'exact generated reference config')
            need(result['ReferenceCommit'] == PIN and result['ReferenceClosingIdentityVerified'] is True
                 and result['ArtifactSealVerified'] is True and result['ReferenceBuilt'] is True, 'reference pin/closing/seal')
            if not cm0 and not cm3:
                policy = result['FPCCRPolicy']
                same([policy['DeclaredNativePolicy'], policy['ReferencePolicy'], policy['ReferenceBits'], policy['PolicyEquivalenceProven']],
                     ['eager', 'upstream-lazy', 0xC0000000, False], 'unresolved eager/lazy policy difference')
            for row in result['ReferenceFileBindings']:
                actual = self.watch.read(row['Original'], row['WorktreeSha256'])
                need(self.watch.read(row['Captured'], row['WorktreeSha256']) == actual, 'pinned source copy')
                blob = self.watch.read(row['GitBlob'], row['GitBlobSha256'])
                same(self.admission.inventory.reference_bytes_match(actual, blob), row['ByteComparison'], 'pinned whole-file comparison')
        same(result['CompileFlags'], flags, 'full recipe flags')
        rows = result['Sources']
        same([row['Source'] for row in rows], [str(path) for path in sources], 'ordered exact source ownership')
        same(result['TranslationUnits'], len(sources), 'literal TU count')
        same([row['Stage'] for row in result['ObjectChecks']], list(CHECKPOINTS), 'seven ordered object checkpoints')
        need(all(row['Status'] == 'PASS' for row in result['ObjectChecks']), 'all object checkpoints pass')
        commands = result['Commands']
        need(type(commands) is list and len(commands) == (73 if side == 'Native' else 79 if cm0 else 71), 'exact tool command count')
        same(self.watch.json(root / 'commands.json'), commands, 'command aggregate/report binding')
        for index, command in enumerate(commands):
            need(command['Status'] == 'PASS' and type(command['Exit']) is int and command['Exit'] == 0
                 and command['TimedOut'] is False and command['Error'] is None and type(command['Seconds']) in (int, float)
                 and math.isfinite(command['Seconds']) and command['Seconds'] >= 0, 'successful terminal tool command')
            same(self.watch.json(root / ('command-%04d.json' % index)), command, 'terminal command sidecar')
            executable = self.api.checked_path(command['Argv'][0])
            need(executable in self.watch.hashes, 'tool executable must be an authenticated input')
            self.watch.read(executable, self.watch.hashes[executable])
        objects = []
        for index, (row, source) in enumerate(zip(rows, sources)):
            obj = root / 'objects' / ('%02d-' % index + source.stem + '.o')
            same(row['Object'], str(obj), 'exact object path')
            self.watch.read(source, row['SourceSha256'])
            self.watch.read(obj, row['ObjectSha256'])
            actual_flags = (self.native.startup_flags(expected, mode) if side == 'Native' else
                            [*expected['compile_flags'], '-' + mode, '-g0']) if source.suffix == '.S' else (
                            [*flags, '-I' + str(source.parent)] if side == 'Native' else flags)
            same(row['CompileFlags'], actual_flags, 'per-TU exact flags')
            need(row['CompileDependenciesVerified'] is True and row['Dependencies'], 'nonempty verified dependencies')
            same(row['ActualCompileDependencies'], row['Dependencies'], 'discovery/actual dependency equality')
            for dependency in row['Dependencies']:
                self.watch.read(dependency['Path'], dependency['Sha256'])
            for field in ('DiscoveryDependencyFile', 'CompileDependencyFile'):
                self.watch.read(row[field])
            compiler = str(self.tools['gcc'])
            discovery = [compiler, *actual_flags, '-M', '-MF', row['DiscoveryDependencyFile'], '-MT', 'pilot-source-' + str(index), str(source)]
            compile_argv = [compiler, *actual_flags, '-MD', '-MF', row['CompileDependencyFile'], '-MT', 'pilot-source-' + str(index), '-c', str(source), '-o', str(obj)]
            need(sum(command['Argv'] == discovery for command in commands) == 1
                 and sum(command['Argv'] == compile_argv for command in commands) == 1, 'actual exact discovery and compile argv')
            objects.append(obj)
        same([row['Kind'] for row in result['Links']], ['ordinary', 'emit-relocs'], 'two ordered twins')
        for link in result['Links']:
            name = link['Kind']
            elf, link_map = root / (name + '.elf'), root / (name + '.map')
            same([link['Path'], link['Map']], [str(elf), str(link_map)], 'fixed twin/map identities')
            self.watch.read(elf, link['Sha256'])
            self.watch.read(link_map, link['MapSha256'])
            argv = [str(self.tools['gcc']), *expected['compile_flags'], '-' + mode, '-nostdlib',
                    '-Wl,--gc-sections,--no-undefined,--fatal-warnings,--build-id=none,-z,noexecstack', '-T', str(fixture / 'link.ld'),
                    *(str(obj) for obj in objects), *(['-Wl,--emit-relocs'] if name == 'emit-relocs' else []),
                    '-Wl,-Map=' + str(link_map), '-o', str(elf)]
            matches = [command for command in commands if command['Label'] == 'link ' + name]
            need(len(matches) == 1, 'one actual link per twin')
            same(matches[0]['Argv'], argv, 'exact direct link argv')
        roots = result['PrelinkNativeRoots' if side == 'Native' else 'PrelinkReferenceRoots']
        names = NATIVE_ROOTS if side == 'Native' else CM0_ROOTS if cm0 else REFERENCE_ROOTS
        same([row['Name'] for row in roots], list(names), 'complete ordered owning prelink roots')
        need(result['TwinLoadImageIdentical'] is True and result['TwinAllocatedSectionsIdentical'] is True, 'actual own twins')
        return dict(TranslationUnits=len(sources), Links=2, Checkpoints=7, ToolCommands=len(commands), PrelinkRoots=len(roots))

    def _audit(self, case, side, case_dir):
        root = case_dir / side
        raw = self.watch.read(root / 'results.json')
        manifest_raw = self.watch.read(root / 'artifacts.json')
        descriptor = dict(Build=str(root), ReceiptSha256=sha(raw), ArtifactsSha256=sha(manifest_raw))
        bundle = self.admission.bundle(descriptor)
        result = bundle['Result']
        same(result, self.api.structured(raw), 'same parsed receipt buffer')
        rows, generated, inputs = self._input_rows(bundle)
        self.admission.require_inventory_binding(bundle, self.inventory)
        need(type(result['RequiredCellsSatisfied']) is int and result['RequiredCellsSatisfied'] == 0, 'zero cell credit')
        for key in ('GlobalFreezeQualified', 'PolicyEquivalence', 'CpuExecution', 'BoardExecution', 'CompleteObjectProof'):
            need(result[key] is False, 'literal nonclaim: ' + key)
        route = routes()[case['Route']]
        if side == 'Join':
            evidence = self.api.report_evidence(case['Route'], result)
            selection = dict(Native=case['Descriptors']['Native'], Reference=case['Descriptors']['Reference'])
            self.api.require_bindings(result, selection)
            same(result['SourceInventorySha256'], self.inventory['SourceInventorySha256'], 'join inventory fingerprint')
            need(result['ReferenceCommit'] == PIN, 'join reference pin')
            stats = dict(ClosedBodies=evidence['ClosedBodies'], Mechanisms=3, ToolCommands=0,
                         EvidenceSha256=sha(encoded(evidence)))
        else:
            stats = self._producer(bundle, route, side)
        for name, value in dict(bundle['Artifacts'], **{'artifacts.json': descriptor['ArtifactsSha256']}).items():
            relative = (root / name).relative_to(self.output).as_posix()
            self.expected[relative] = value
            self.output_identities[relative] = self.watch.identities[root / name]
        stats.update(Artifacts=len(bundle['Artifacts']), OriginalInputs=len(rows),
                     CapturedInputs=sum(row['Captured'] is not None for row in rows), GeneratedInputs=len(generated),
                     CommandsSha256=bundle['Artifacts'].get('commands.json'))
        case['Descriptors'][side], case['Audits'][side] = descriptor, stats
        return inputs

    def _execute_case(self, case):
        self._active_case = case
        route_id = case['Route']
        case_dir = self.output / 'cases' / (case['Profile'] + '-' + case['Mode'])
        before = set(self.watch.hashes)
        self._snapshot(case_dir)
        inputs = set()
        for side in ('Native', 'Reference', 'Join'):
            case.update(Status='RUNNING', Stage=side)
            self._json('results.json', self.report)
            self._json('pending.json', self._pending())
            kwargs = dict(gcc=self.tools['gcc'], cmsis=self.directories['cmsis'], git=self.tools['git'],
                freertos=self.directories['freertos'], python_modules=self.directories['python_modules'],
                inventory=self.inventory['Bundle']['Root'], case_dir=case_dir)
            if side == 'Join':
                kwargs.update(native=case['Descriptors']['Native'], reference=case['Descriptors']['Reference'])
            arguments = stage_arguments(route_id, side, **kwargs)
            entry = Path(arguments[0])
            self.watch.read(entry, self.api.SOURCE_PINS[entry.relative_to(ROOT).as_posix()])
            trace = 'execution/' + case_dir.name + '-' + side + '.json'
            (self.output / 'execution').mkdir(exist_ok=True)
            argv = [str(self.interpreter), '-I', '-S', '-B', '-c', self.api.BOOTSTRAP,
                    str(self.source_snapshot), self.source_snapshot_sha, str(entry), str(self.output / trace), *arguments[1:]]
            self._close_inputs(self.opening_paths, self.opening_roots)
            self._verify_outputs(case_dir.relative_to(self.output).as_posix() + '/')
            self.command(argv, route_id + ':' + side)
            self.api.Dispatcher._trace(self, trace, entry)
            record = self.watch.json(self.output / trace, self.expected[trace])
            case.setdefault('ExecutionTraces', {})[side] = dict(Path=str(self.output / trace), Sha256=self.expected[trace])
            inputs |= self._audit(case, side, case_dir)
            for copied_side in (('Native', 'Reference') if side == 'Join' else (side,)):
                self._actual_aliases(copied_side, case_dir, record['Executed'])
        case_paths = inputs | (set(self.watch.hashes) - before) | self.opening_paths
        case_roots = self.opening_roots | {case_dir / side for side in ('Native', 'Reference', 'Join')}
        self._close_inputs(case_paths, case_roots)
        case.update(Status='VERIFIED_COMPONENTS_ONLY', Stage='CLOSING', CaseClosed=True,
                    CurrentSnapshotEligible=True, SourceInventorySha256=self.inventory['SourceInventorySha256'],
                    ClosingFilesVerified=len(case_paths))
        name = (case_dir / 'case-results.json').relative_to(self.output).as_posix()
        self._json(name, case)
        self._verify_outputs(case_dir.relative_to(self.output).as_posix() + '/')
        self.completed.append(case['Route'])
        self._active_case = None
        self.report['Counts'] = expected_counts(self.completed)
        self._json('pending.json', self._pending())
        self._json('results.json', self.report)

    def _catalog(self):
        return dict(SchemaVersion=1, Selections=[dict(Route=case['Route'], Inventory=self.inventory['Bundle']['Descriptor'],
                    Native=case['Descriptors']['Native'], Reference=case['Descriptors']['Reference'],
                    PriorJoin=case['Descriptors']['Join']) for case in self.report['Cases'] if case['CaseClosed']])

    def _fail(self, error):
        message = type(error).__name__ + ': ' + str(error)
        if self.report['PrimaryError'] is None:
            self.report.update(Error=message, PrimaryError=message)
        elif message != self.report['PrimaryError']:
            self.report['ClosingErrors'].append(message)
        self.report.update(Status='FAIL', CatalogReady=False, FinalBatchClosureRequired=True,
                           InputClosureVerified=False, OutputSealVerified=False)
        for case in self.report['Cases']:
            if case['Status'] == 'RUNNING' or (case is self._active_case and case['Route'] not in self.completed):
                case.update(Status='FAIL', Error=message, CaseClosed=False, CurrentSnapshotEligible=False)

    def finish(self, error=None):
        if error is None and not (self._completed and self.completed == self.request
                                 and len(self.commands) == 3 * len(self.request)):
            error = Rejected('freeze-capture: incomplete/empty capture cannot PASS')
        if error is not None:
            self._fail(error)
        if not self._started:
            return False
        try:
            self._close_inputs()
            self._verify_outputs()
            if error is None:
                same(self.report['Counts'], expected_counts(self.request), 'all expected aggregate counts')
                need(all(case['CaseClosed'] and case['Status'] == 'VERIFIED_COMPONENTS_ONLY' for case in self.report['Cases']), 'all requested cases closed')
            self.report.update(Status='PASS' if error is None else 'FAIL', CatalogReady=error is None,
                FinalBatchClosureRequired=error is not None,
                InputClosureVerified=error is None, OutputSealVerified=True, ClosingFilesVerified=len(self.watch.hashes),
                InputHashes={str(path): value for path, value in sorted(self.watch.hashes.items())},
                InputPhysicalIdentities={str(path): list(value) for path, value in sorted(self.watch.identities.items())},
                CommandsSha256=self.expected['commands.json'])
            self._json('catalog.json', self._catalog())
            self._json('pending.json', self._pending())
            self._json('results.json', self.report)
            manifest = {name: value for name, value in self.expected.items() if name != 'artifacts.json'}
            self._json('artifacts.json', dict(Artifacts=manifest))
            self._close_inputs()
            self._verify_outputs()
            same(self.api.structured((self.output / 'artifacts.json').read_bytes()), dict(Artifacts=manifest), 'written manifest semantics')
            return error is None
        except BaseException as failure:
            self._fail(failure)
            try:
                self._json('catalog.json', self._catalog())
                self._json('pending.json', self._pending())
                self._json('results.json', self.report)
                actual = self.api.files_under(self.output)
                manifest = {name: sha(path.read_bytes()) for name, path in actual.items() if name != 'artifacts.json'}
                self._write('artifacts.json', encoded(dict(Artifacts=manifest)))
            except BaseException:
                pass
            return False

    def run(self):
        need(not self._started, 'capture can run only once')
        error = None
        try:
            self.api.checked_path(self.output, fresh=True)
            self._close_inputs()
            self.output.mkdir(parents=True)
            self._started = True
            self._write('request.json', self.request_raw)
            self._json('environment.json', self.environment)
            self._json('opening-inputs.json', dict(Files=[dict(Path=str(path), Sha256=self.watch.hashes[path],
                PhysicalIdentity=list(self.watch.identities[path])) for path in sorted(self.opening_paths)]))
            self._json('commands.json', self.commands)
            self._json('results.json', self.report)
            self._json('pending.json', self._pending())
            for case in self.report['Cases']:
                self._execute_case(case)
            self._completed = True
        except BaseException as failure:
            error = failure
        return self.finish(error)


def main(argv=None):
    need(not sys.flags.optimize, 'unoptimized Python required')
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('gcc', 'cmsis', 'git', 'freertos', 'python-modules', 'inventory',
                 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'request', 'request-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    capture = prepare(args)
    passed = capture.run()
    print(capture.report['Status'], capture.report.get('Error'), str(capture.output), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
