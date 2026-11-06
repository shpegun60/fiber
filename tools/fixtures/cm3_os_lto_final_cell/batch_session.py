"""Explicit Os batch session over frozen mode-neutral managed-tool methods.

This is infrastructure, not a qualifier or CLI. The caller independently
authenticates every supplied module, helper buffer and genuine Os capture.
The O2 constructors, phase drivers, finish and verdict functions are not used.
"""
import copy
import hashlib
from pathlib import Path


SCOPE = 'CURRENT_CM3_OS_LTO_INTEGRATED_BATCH_IN_PROGRESS'
PHASES = ('ABIControls', 'Isolation', 'CommonAttributes', 'PortPolicy')


def need(value, message):
    if not value:
        raise ValueError('cm3-os-lto-batch-session: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def suite_type(utility, lto_methods):
    """Reuse only neutral I/O, compilation, plugin and saved-worker mechanics."""
    inherited = lto_methods.suite_type(utility)

    class Suite(inherited):
        def __init__(self, environment, modules, sources):
            witness = environment['Witness']
            need(type(modules) is dict and type(sources) is dict and sources,
                'explicit authenticated modules and bootstrap buffers')
            need(Path(__file__).resolve() in sources, 'session source must be an enrolled bootstrap buffer')
            self.api, self.watch = witness.replay_api, witness.watch
            self.output = witness.output
            self.result = copy.deepcopy(witness.groups['Native']['Result'])
            self.modules, self.witness = modules, witness
            self.native, self.process = modules['native'], modules['process']
            self.transport = witness.api
            self.sources = copy.deepcopy(self.result['Sources'])
            recipes = modules['recipes']
            need(len(self.sources) == 9, 'nine ordered actual source providers')
            for index, row in enumerate(self.sources):
                self.api.same(recipes.compile_flags(self.result, index), row['CompileFlags'],
                    'actual Os compilation flags: ' + str(index))
            self.objects = tuple(self.api.checked_path(row['Object']) for row in self.sources)
            need(len(set(self.objects)) == 9, 'distinct original Os objects')
            self.link_argv = recipes.link_recipe(self.result, self.objects)
            self.base = self.api.checked_path(self.result['SeedBuild'], directory=True)
            need(self.base == witness.groups['Native']['Seed'].root, 'admitted ordinary source Seed')
            self.bundle = dict(Artifacts=self.watch.structured(self.base / 'artifacts.json')['Artifacts'])
            source_root = self.base / 'source'
            need(all(Path(row['Source']).is_relative_to(source_root) for row in self.sources),
                'source paths belong to the admitted source-copy Seed')
            tool_root = Path(self.result['CapturedCompiler']).parent.parent
            self.tools = {name: self.api.checked_path(tool_root / 'bin' / ('arm-none-eabi-' + name + '.exe'))
                for name in ('gcc', 'nm', 'objdump', 'readelf')}
            self.tools['ld'] = self.api.checked_path(self.result['ResolvedWorkers']['ld']['Path'])
            self.plugin = self.api.checked_path(self.result['LTOPlugin']['Path'])
            need(all(path in self.watch.hashes for path in (*self.tools.values(), self.plugin)),
                'all command tools and plugin must already be authenticated capture inputs')
            need(self.link_argv[0] == str(self.tools['gcc']), 'same admitted compiler for links')
            self.environment = self.watch.structured(witness.groups['Native']['Root'] / 'environment.json')
            need(type(self.environment) is dict and all(type(key) is str and type(value) is str
                for key, value in self.environment.items()), 'literal captured process environment')
            self.environment.update(TEMP=str(self.output / 'tmp'), TMP=str(self.output / 'tmp'))
            for path, raw in sources.items():
                need(isinstance(path, Path) and type(raw) is bytes
                    and path in witness.buffers and witness.buffers[path] == raw
                    and self.watch.read(path, sha(raw)) == raw,
                    'bootstrap buffers must be enrolled before capture admission closes')
            self.api.checked_path(self.output, fresh=True)
            self.watch.close()
            self.commands, self.expected, self.identities = [], {}, {}
            self._started = self._finished = self._controls_done = False
            self.phases, self.phase_start = [], None
            self.report = dict(Status='FAIL', Scope=SCOPE, Profile='CM3', Mode='Os-lto',
                Linkage='direct', LTO=True, SourceInventorySha256=self.result['SourceInventorySha256'],
                CurrentInventory=copy.deepcopy(witness.report['CurrentInventory']),
                NativeCapture=dict(Build=str(witness.groups['Native']['Root']),
                    ReceiptSha256=witness.groups['Native']['ReceiptSha256'],
                    ArtifactsSha256=witness.groups['Native']['ManifestSha256']),
                SourceSeed=self.result['SeedBuild'], Compilations=[], Controls=[], Phases=self.phases,
                Error=None, PrimaryError=None, ClosingErrors=[], InputClosureVerified=False,
                OutputSealVerified=False, RequiredCellCount=2774, RequiredCellsSatisfied=0,
                RequiredCellSatisfied=False, CellContractSatisfied=False, Qualification=False,
                FullABIProof=False, FullSemanticABIProof=False, SourceIRProof=False,
                SourceToMachineSemanticProof=False, CpuExecution=False, BoardExecution=False,
                HostedCIQualified=False, GlobalFreezeQualified=False)

        def start(self):
            utility.Suite.start(self)
            info = self.output.stat()
            self.output_identity = info.st_dev, info.st_ino
            (self.output / 'tmp').mkdir()
            self.report['CapturedSources'] = [dict(Original=str(path), Sha256=sha(raw),
                Captured=str(self.write_input('source-buffers/%04d-%s' % (index, path.name), raw)))
                for index, (path, raw) in enumerate(sorted(self.witness.buffers.items()))]
            return self

        def begin_phase(self, name):
            need(self._started and not self._finished and self.phase_start is None,
                'one active phase in an active session')
            need(len(self.phases) < len(PHASES) and name == PHASES[len(self.phases)],
                'fixed ordered batch phase')
            self.phase_start = name, len(self.commands)

        def end_phase(self):
            need(self.phase_start is not None and not self._finished, 'active phase required')
            name, first = self.phase_start
            expected = dict(ABIControls=41, Isolation=12, CommonAttributes=45, PortPolicy=36)[name]
            rows = self.commands[first:]
            need(len(rows) == expected and all(type(row) is dict and row.get('State') == 'TERMINAL'
                and row.get('Status') in ('PASS', 'EXPECTED-NONZERO') and row.get('TimedOut') is False
                and type(row.get('Exit')) is int and type(row.get('ExpectedExit')) is int
                and row['Exit'] == row['ExpectedExit'] == (1 if row['Status'] == 'EXPECTED-NONZERO' else 0)
                and not row.get('JournalErrors') for row in rows),
                'complete typed terminal command range: ' + name)
            self.phases.append(dict(Name=name, First=first, Stop=len(self.commands), Commands=expected))
            self.phase_start = None
            self._save('phases.json', self.phases)

        def run_link_controls(self):
            raise ValueError('Os batch must provide its own control-phase orchestration')

        def finish(self, error=None):
            raise ValueError('Os batch must provide its own replay and final verdict/seal')

    return Suite
