"""Fresh identity, opt-in execution, and FAIL-first bounded-grid finalization."""
from __future__ import annotations
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
from cm4_mpu_basic_engine import pilot, fp, common, need, save, digest, load, basic_terminal
from cm4_mpu_basic_builds import GridBuilds
from cm4_mpu_basic_contracts import validate, closing_controls, synthetic

HERE = Path(__file__).resolve().parent


class BasicGrid(GridBuilds):
    def __init__(self, args):
        args.execute_pilot = args.execute_grid
        super().__init__(args)
        self.fixture = HERE
        self.generated_mutations, self.controls, self.faults = [], [], []
        self.references, self.associations, self.ref_controls = [], [], []
        self.workers, self.plugin = {}, None
        self.report.pop('ExistingReferenceMechanismGate', None)
        self.report.update(Verdict='FAIL', CompleteSuite=False, CompileOnly=not args.execute_grid,
            Execution='NOT_RUN', Scope='CM4/AN386 MPU8 hard-FP compiled, eager/basic FP-inactive two-consumer 16-config grid only; no FP-active/MPU16/softfp/all-opt/board/global parity claim',
            Rows=self.rows, CompiledControls=self.controls, References=self.references, Associations=self.associations,
            ReferenceControls=self.ref_controls, ReferenceExecuted=False, NewFinalReferenceParity=False,
            ArtifactsVerifiedBeforePass=False, CaptureManifest=args.capture_manifest)

    def command(self, argv, label, **kwargs):
        argv = list(map(str, argv))
        name = Path(argv[0]).name.lower()
        need(name not in ('git', 'git.exe'), 'Git is not required or permitted by this source-byte gate')
        if name in ('wsl', 'wsl.exe', 'bash', 'bash.exe') or name.startswith('qemu'):
            need(self.a.execute_grid, 'Compile-only must not launch WSL/QEMU')
        if self.plugin and name in ('arm-none-eabi-nm.exe', 'arm-none-eabi-ar.exe'):
            need(not any(a.startswith('--plugin') for a in argv[1:]), 'Duplicate plugin argument')
            argv.insert(1, '--plugin=' + str(self.plugin))
        return super().command(argv, label, **kwargs)

    def git(self, *args, **kwargs):
        raise RuntimeError('No historical receipt or Git identity dependency')

    def repo_inventory(self):
        manifest = Path(self.a.capture_manifest)
        captured = json.loads(manifest.read_text())
        self.enroll(manifest, 'CaptureManifest')
        for row in captured['Files']:
            need(digest(row['Original']) == digest(row['Captured']) == row['Sha256'], 'Opening capture identity drift')
            self.enroll(row['Original'], 'Original:' + row['Role'])
            self.enroll(row['Captured'], 'Captured:' + row['Role'])
        self.capture = captured
        self.reader = load('cm4_mpu_basic_source_reader', self.repo / 'tools/runtime_sources.py')
        # Exercise all role owners against the closed copy before compiling any.
        self.reader.get_runtime_source_inputs(self.repo, ('engine', 'state', 'panic', 'optional_configuration'))
        self.report['SourceIdentity'] = dict(Attribution='FRESH_CLOSED_SELECTED_BYTE_CAPTURE',
            Files=len(captured['Files']), Manifest=str(manifest), ManifestSha256=digest(manifest),
            HistoricalReceiptRequired=False, GitInvoked=False)

    def reference_identity(self, enroll=False):
        contract = json.loads((HERE / 'pinned_reference.json').read_text())
        for row in contract['Files']:
            path = Path(self.a.freertos) / row['Path']
            need(digest(path) == row['Sha256'], 'Pinned reference file mismatch')
            if enroll:
                self.enroll(path, 'PinnedReference')
        if enroll:
            self.report['ReferenceIdentity'] = dict(ExpectedCommit=contract['ExpectedCommit'], Files=26,
                Attribution='Checked-in selected port/include hash inventory plus fresh complete compiler dependencies; not a clean Git tree claim',
                InventorySha256=digest(HERE / 'pinned_reference.json'), Executed=False)

    def inspect_qemu(self, name):
        if not self.a.execute_grid:
            return dict(Execution='NOT_RUN', Reason='Compile-only prohibits WSL/QEMU')
        return fp.Suite.inspect_qemu(self, name)

    def preflight(self):
        common.Suite.preflight(self)
        gcc = self.tools['gcc']
        self.plugin = Path(self.command([gcc, '-print-file-name=liblto_plugin.dll'], 'resolve exact LTO plugin')['Stdout'].strip()).resolve(strict=True)
        self.enroll(self.plugin, 'ExplicitLTOPlugin')
        for key in ('nm', 'ar'):
            self.tools[key] = (gcc.parent / ('arm-none-eabi-' + key + '.exe')).resolve(strict=True)
            self.enroll(self.tools[key], 'ActualNativeInspectionTool')
            self.command([self.tools[key], '--version'], 'actual native ' + key + ' with explicit plugin')
        for name in ('cc1', 'as', 'collect2', 'ld', 'lto1', 'lto-wrapper'):
            reported = self.command([gcc, '-print-prog-name=' + name], 'resolve actual compiler delegate ' + name)['Stdout'].strip()
            need(Path(reported).is_absolute(), 'Compiler delegate must be absolute')
            path = Path(reported).resolve(strict=True)
            self.enroll(path, 'ActualCompilerDelegate')
            self.workers[name] = dict(Path=str(path), Sha256=digest(path))
        self.report['ExplicitTools'] = dict(CompilerWorkers=self.workers,
            NativeNM=dict(Path=str(self.tools['nm']), Sha256=digest(self.tools['nm'])),
            NativeAR=dict(Path=str(self.tools['ar']), Sha256=digest(self.tools['ar'])),
            Plugin=dict(Path=str(self.plugin), Sha256=digest(self.plugin)))
        save(self.build / 'inputs.before.json', list(self.inputs.values()))
        self.report['ClosingContractControls'] = closing_controls()
        self.report['FinalizerControls'] = self.finalizer_controls()
        control_file = self.build / 'closing-controls.json'
        control_output = self.build / 'powershell-finalizer-controls.json'
        save(control_file, dict(ClosingContractControls=self.report['ClosingContractControls'],
                               FinalizerControls=self.report['FinalizerControls']))
        checked = self.command([self.tools['powershell'], '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
            self.repo / 'tools/test_classic_cm4_mpu_basic_grid.ps1', '-ContractControls', control_file,
            '-ContractControlsOutput', control_output], 'independent PowerShell typed closing/finalizer controls')
        need('CM4_MPU_BASIC_GRID_CONTRACT_CONTROLS_PASS' in checked['Stdout'], 'Missing independent PowerShell closing controls')
        ps_controls = json.loads(control_output.read_text())
        need(len(ps_controls['Controls']) == 25 and sum(c['Accepted'] for c in ps_controls['Controls']) == 1,
             'Literal PowerShell actual-assertion controls')
        self.report['PowerShellFinalizerControls'] = ps_controls

    def execute(self, row):
        need(self.a.execute_grid, 'Execution was not requested')
        need(digest(row['Elf']) == row['ElfSha256'], 'ELF changed before execution')
        actual = self.command(['wsl.exe', '-d', self.a.wsl_distro, '--', 'bash',
            self.wsl_path(self.repo / 'tools/fixtures/arm_control/qemu.sh'), 'run', self.a.qemu_root,
            self.wsl_path(Path(row['Elf']).parent), 'mps2-an386', self.wsl_path(row['Elf']), '12'],
            'actual bounded MPU grid ' + row['Name'], timeout=25, expected=None)
        if row['Name'] == 'model':
            self.report['ObservedModel'] = pilot.model_terminal(actual)
        else:
            need(basic_terminal(actual, row['Consumer'], row['Case'], row['Audit']['Addresses']), 'Wrong exact basic-grid terminal: ' + row['Name'])
        row.update(Actual=actual, Executed=True, Status='PASS')
        save(Path(row['Elf']).parent / 'execution.json', row)

    def run(self):
        super().run()
        if self.a.execute_grid:
            self.execute(self.report['ModelProbe'])
            for row in self.rows:
                self.execute(row)
        self.report['Execution'] = 'BOUNDED_BASIC_GRID' if self.a.execute_grid else 'NOT_RUN'

    def close_identity(self):
        self.reference_identity()
        for name, opening in self.workers.items():
            reported = self.command([self.tools['gcc'], '-print-prog-name=' + name], 'closing actual compiler delegate ' + name)['Stdout'].strip()
            path = Path(reported).resolve(strict=True)
            need(str(path) == opening['Path'] and digest(path) == opening['Sha256'], 'Compiler delegate drift')
        for row in self.capture['Files']:
            need(digest(row['Original']) == digest(row['Captured']) == row['Sha256'], 'Closing original/captured source drift')
        actual = {str(p.resolve()) for p in self.repo.rglob('*') if p.is_file()}
        expected = {r['Captured'] for r in self.capture['Files'] if Path(r['Captured']).is_relative_to(self.repo)}
        need(actual == expected, 'Captured selected-source inventory drift')
        if self.a.execute_grid:
            need(self.inspect_qemu('qemu-after') == self.qemu_before, 'QEMU/tool/library drift')

    def finish(self, error):
        self.report.update(Verdict='FAIL', CompleteSuite=False, ArtifactsVerifiedBeforePass=False, Error=error, InputCount=len(self.inputs))
        try:
            save(self.build / 'results.json', self.report)
            if error is None:
                self.close_identity()
            drift = self.input_drift()
            self.report['InputDrift'] = drift
            need(not drift, 'Original/captured/tool/generated input drift')
            save(self.build / 'inputs.after.json', [dict(Path=p, Sha256=digest(p) if Path(p).is_file() else None) for p in self.inputs])
            save(self.build / 'dependencies.json', self.dependencies)
            save(self.build / 'generated-inputs.json', list(self.generated.values()))
            save(self.build / 'results.json', self.report)
            self.artifact_manifest(verify=True)
            if error is not None:
                return False
            self.verify_model_artifact()
            need(not self.input_drift(), 'Input drift during first artifact verification')
            candidate = dict(self.report, Verdict='BASIC-GRID-PASS' if self.a.execute_grid else 'COMPILE-PREFLIGHT-PASS',
                             CompleteSuite=self.a.execute_grid, CompileOnly=not self.a.execute_grid,
                             ArtifactsVerifiedBeforePass=True, Error=None)
            validate(candidate, self.a.execute_grid)
            self.report.update(candidate)
            save(self.build / 'results.json', self.report)
            self.artifact_manifest(verify=True)
            self.verify_model_artifact()
            need(not self.input_drift(), 'Input drift during final artifact verification')
            return True
        except Exception as failure:
            self.report.update(Verdict='FAIL', CompleteSuite=False, ArtifactsVerifiedBeforePass=False,
                               Error=(str(error) + '; ' if error is not None else '') + 'finalizer: ' + str(failure))
            try:
                save(self.build / 'results.json', self.report)
            except Exception as write_failure:
                self.report['FailureReceiptWriteError'] = str(write_failure)
            try:
                self.artifact_manifest(verify=False)
            except Exception as manifest_failure:
                self.report['FailureManifestError'] = str(manifest_failure)
                try:
                    save(self.build / 'results.json', self.report)
                except Exception as write_failure:
                    self.report['FailureReceiptWriteError'] = str(write_failure)
            return False

    def verify_model_artifact(self):
        model = self.report.get('ModelProbe')
        need(type(model) is dict and type(model.get('Elf')) is str and bool(model['Elf'].strip()) and
             type(model.get('ElfSha256')) is str, 'model-artifact-identity')
        expected = self.build / 'model/runtime.elf'
        need(Path(model['Elf']).resolve(strict=True) == expected.resolve(strict=True), 'model-artifact-path')
        manifest = json.loads((self.build / 'artifacts.json').read_text())
        actual = digest(expected)
        need(actual == model['ElfSha256'] == manifest['Artifacts'].get('model/runtime.elf'), 'model-artifact-hash')
        self.report['ModelArtifactBinding'] = dict(Verified=True, ArtifactRelative='model/runtime.elf',
            Elf=str(expected), ElfSha256=actual, ManifestEntrySha256=actual)

    def finalizer_controls(self):
        root = self.build / 'orchestration-finalizer-controls'
        root.mkdir()
        controls = []
        entry = load('cm4_mpu_basic_entry_failure_tools', HERE / 'run.py')
        for name, fail_at, run_error in (('positive', 0, None), ('first-manifest', 1, None),
                ('final-manifest', 2, None), ('prior-error', 0, 'SYNTHETIC_RUN_FAILURE'),
                ('empty-error', 0, str(RuntimeError())), ('zero-error', 0, 0), ('false-error', 0, False),
                ('empty-exception', 0, entry.failure_text(RuntimeError())),
                ('model-artifact-hash', 0, None), ('model-artifact-path', 0, None)):
            receiver = BasicGrid.__new__(BasicGrid)
            receiver.a = SimpleNamespace(execute_grid=False)
            receiver.build = root / name
            receiver.build.mkdir()
            receiver.report = synthetic(False)
            receiver.report['Scope'] = 'Synthetic actual-finalizer control; model file is non-ELF orchestration data, not target evidence'
            model = receiver.build / 'model/runtime.elf'
            model.parent.mkdir()
            model.write_bytes(b'SYNTHETIC_FINALIZER_MODEL_NOT_AN_ARM_ELF')
            receiver.report['ModelProbe'].update(Elf=str(model), ElfSha256=digest(model))
            if name == 'model-artifact-hash':
                receiver.report['ModelProbe']['ElfSha256'] = '0' * 64
            if name == 'model-artifact-path':
                shadow = receiver.build / 'shadow.elf'
                shadow.write_bytes(model.read_bytes())
                receiver.report['ModelProbe']['Elf'] = str(shadow)
            receiver.inputs, receiver.generated, receiver.dependencies = {}, {}, []
            receiver.close_identity = lambda: None
            receiver.input_drift = lambda: []
            calls = []
            def manifest(verify=False):
                persisted = json.loads((receiver.build / 'results.json').read_text())
                calls.append(dict(Verify=verify, Verdict=persisted['Verdict'], ArtifactsVerifiedBeforePass=persisted['ArtifactsVerifiedBeforePass']))
                if verify and sum(c['Verify'] for c in calls) == fail_at:
                    raise RuntimeError('SYNTHETIC_MANIFEST_FAILURE_' + str(fail_at))
                return common.Suite.artifact_manifest(receiver, verify=verify)
            receiver.artifact_manifest = manifest
            accepted = BasicGrid.finish(receiver, run_error)
            persisted = json.loads((receiver.build / 'results.json').read_text())
            expected = name == 'positive'
            need(accepted is expected and persisted['ArtifactsVerifiedBeforePass'] is expected and
                 persisted['Verdict'] == ('COMPILE-PREFLIGHT-PASS' if expected else 'FAIL'), 'Actual finalizer causal control: ' + name)
            need(calls[0] == dict(Verify=True, Verdict='FAIL', ArtifactsVerifiedBeforePass=False), 'Premature persisted PASS before artifact verification')
            if fail_at:
                need(persisted['Error'] == 'finalizer: SYNTHETIC_MANIFEST_FAILURE_' + str(fail_at) and
                     calls[-1] == dict(Verify=False, Verdict='FAIL', ArtifactsVerifiedBeforePass=False), 'Wrong late-manifest failure recovery')
            elif run_error is not None:
                need(type(persisted['Error']) is type(run_error) and persisted['Error'] == run_error and len(calls) == 1,
                     'Prior failure promoted/replaced')
            elif name.startswith('model-artifact-'):
                need(persisted['Error'] == 'finalizer: ' + name and len(calls) == 2 and
                     calls[-1] == dict(Verify=False, Verdict='FAIL', ArtifactsVerifiedBeforePass=False), 'Wrong model binding failure')
            else:
                need(len(calls) == 2 and calls[1] == dict(Verify=True, Verdict='COMPILE-PREFLIGHT-PASS', ArtifactsVerifiedBeforePass=True), 'Final verified manifest missing')
            controls.append(dict(Name=name, Accepted=accepted, PersistedVerdict=persisted['Verdict'], Error=persisted['Error'],
                Calls=deepcopy(calls), Receipt=str(receiver.build / 'results.json'), ReceiptSha256=digest(receiver.build / 'results.json')))
        need(len(controls) == 10 and sum(c['Accepted'] for c in controls) == 1, 'Literal ten actual finalizer controls')
        return dict(Controls=controls, Scope='Actual BasicGrid.finish with manifest fault injection; orchestration only, no target execution')
