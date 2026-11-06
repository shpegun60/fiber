"""Current-E9 constructor for the unchanged CM3 Os-LTO replay witness."""
import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE_SHA = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
MODE = 'Os-lto'


def need(condition, message):
    if not condition:
        raise ValueError('current-cm3-os-admission: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def _descriptor(replay, build, receipt, artifacts):
    return dict(Build=str(replay.checked_path(build, directory=True)),
        ReceiptSha256=replay.digest(receipt), ArtifactsSha256=replay.digest(artifacts))


def _declared_descriptor(replay, value):
    need(type(value) is dict and set(value) == {'Build', 'ReceiptSha256', 'ArtifactsSha256'},
         'exact declared evidence descriptor')
    return _descriptor(replay, value['Build'], value['ReceiptSha256'], value['ArtifactsSha256'])


def _merge_environment(witness, environment):
    guard, seed = environment['Watch'], environment['Seed']
    for path, digest in tuple(guard.hashes.items()):
        witness.watch.read(path, digest)
    for root, artifacts in tuple(guard.trees.items()):
        witness.watch.tree(root, artifacts)
    for path, digest in tuple(seed.closure.hashes.items()):
        witness.watch.read(path, digest)
    for root, names in tuple(seed.closure.memberships.items()):
        witness.watch.tree(root, {name: seed.closure.hashes[root / name] for name in names})
    witness.outer_watch.denied.update(guard.denied)
    for path, raw in seed.buffers.items():
        need(witness.watch.read(path, sha(raw)) == raw, 'same admitted Seed source buffer')
        witness._buffer(path, raw)


def _capture_inputs(witness, bundle):
    root, result, artifacts = (bundle[name] for name in ('Root', 'Result', 'Artifacts'))
    inputs = witness.watch.structured(root / 'inputs.json', artifacts['inputs.json'])
    need(type(inputs) is dict and type(inputs.get('Files')) is list and inputs['Files']
         and type(inputs.get('Watched')) is list and inputs['Watched'], 'complete capture input catalogs')
    originals = set()
    for row in inputs['Files']:
        need(type(row) is dict and set(row) == {'Original', 'Captured', 'Sha256'}, 'exact capture provider row')
        original, captured = witness.api.regular(row['Original']), witness.api.regular(row['Captured'])
        digest = witness.api.digest_text(row['Sha256'])
        need(original not in originals, 'unique captured-input provider')
        originals.add(original)
        need(captured.is_relative_to(root) and artifacts.get(captured.relative_to(root).as_posix()) == digest,
             'captured provider/manifest binding')
        raw = witness.watch.read(captured, digest)
        need(witness.watch.read(original, digest) == raw, 'original/captured provider bytes')
        if original.suffix == '.py':
            witness._buffer(original, raw)
            witness._buffer(captured, raw)
    watched = set()
    for row in inputs['Watched']:
        need(type(row) is dict and set(row) == {'Path', 'Sha256'}, 'exact watched input row')
        path = witness.api.regular(row['Path'])
        need(path not in watched, 'unique watched input')
        watched.add(path)
        witness.watch.read(path, witness.api.digest_text(row['Sha256']))
    need(type(result.get('ClosingFilesVerified')) is int
         and result['ClosingFilesVerified'] == len(watched), 'literal complete capture closing count')


def _require_record(witness, capture, side, bundle, current, producer):
    result = bundle['Result']
    capture.require_capture(result, capture.select(side.lower(), MODE), sealed=True)
    for field, expected in (('SeedMode', 'O2'), ('SeedSide', side)):
        need(type(result.get(field)) is str and result[field] == expected, 'exact Os ' + field)
    witness.api.same(result.get('OptimizationTransform'),
        dict(Original='-O2', Captured='-Os', OtherSeedFlagsUnchanged=True), 'exact Os optimization transform')
    witness.api.same(result.get('CaptureProducer'), producer, 'authenticated current capture producer')
    witness.api.same(_declared_descriptor(witness.replay_api, result.get('CurrentInventory')),
        current['Bundle']['Descriptor'], 'independent current inventory descriptor')
    need(witness.api.checked_path(result['SourceInventoryReceipt']) == current['Bundle']['Root'],
         'capture uses the independently admitted current inventory')


def witness_type(legacy, capture, *, extra_sources):
    """The caller authenticates these immutable bootstrap bytes before execution."""
    need(type(extra_sources) is dict and extra_sources, 'authenticated bootstrap buffers required')
    sources = {}
    for name, raw in extra_sources.items():
        path = legacy.stable(name)
        need(type(raw) is bytes and path not in sources, 'unique immutable bootstrap source bytes')
        sources[path] = raw
    capture_path = ROOT / 'tools/fixtures/cm3_current_lto_capture/capture.py'
    legacy_path = ROOT / 'tools/fixtures/cm3_os_lto_join/witness.py'
    required = {Path(__file__).resolve(), HERE / 'CONTRACT.md', HERE / 'witness.py', capture_path, legacy_path}
    need(required <= set(sources), 'capture, legacy, adapter, runner and contract buffers required')
    need(legacy.stable(legacy.__file__) == legacy_path and legacy.stable(capture.__file__) == capture_path
         and legacy.ROOT == capture.ROOT == ROOT, 'fixed module source identities')

    class CurrentOsWitness(legacy.Witness):
        def __init__(self, args):
            modules, outer = capture.load_environment()
            self.api, self.replay_api = modules['api'], modules['replay']
            self.outer_watch = outer
            self.output = self.api.checked_path(args.output_dir, must_exist=False)
            self.buffers, self.groups, self.identities = {}, {}, {}
            for path, raw in sources.items():
                need(outer.read(path, sha(raw)) == raw, 'executed bootstrap buffer/physical source binding')
                self._buffer(path, raw)
            producer = dict(Path=str(capture_path), Sha256=sha(sources[capture_path]))
            admission = self.replay_api.Admission(outer)
            current_descriptor = _descriptor(self.replay_api, args.inventory,
                args.inventory_receipt_sha256, args.inventory_artifacts_sha256)
            current = admission.snapshot(current_descriptor, current=True)
            self.api.same(current['SourceInventorySha256'], SOURCE_SHA, 'fixed current-E9 source cut')
            need(type(current['Required']['RequiredCellCount']) is int
                 and current['Required']['RequiredCellCount'] == 2774, 'complete current inventory plan')
            bundles = {}
            for side in ('Native', 'Reference'):
                prefix = side.lower()
                descriptor = _descriptor(self.replay_api, getattr(args, prefix + '_build'),
                    getattr(args, prefix + '_receipt_sha256'), getattr(args, prefix + '_artifacts_sha256'))
                bundle = admission.bundle(descriptor)
                admission.require_inventory_binding(bundle, current, required=True)
                _require_record(self, capture, side, bundle, current, producer)
                bundles[side] = bundle
            need(bundles['Native']['Root'] != bundles['Reference']['Root'], 'distinct native/reference captures')

            environments = {}
            for side, bundle in bundles.items():
                result = bundle['Result']
                seed_descriptor = _descriptor(self.replay_api, result['SeedBuild'],
                    result['SeedReceiptSha256'], result['SeedArtifactsSha256'])
                self.api.same(_declared_descriptor(self.replay_api, result.get('SeedAuthority')),
                              seed_descriptor, 'capture/ordinary Seed authority')
                selected = SimpleNamespace(side=side.lower(), mode=MODE,
                    seed_build=seed_descriptor['Build'], seed_receipt_sha256=seed_descriptor['ReceiptSha256'],
                    seed_artifacts_sha256=seed_descriptor['ArtifactsSha256'],
                    inventory=current_descriptor['Build'],
                    inventory_receipt_sha256=current_descriptor['ReceiptSha256'],
                    inventory_artifacts_sha256=current_descriptor['ArtifactsSha256'], output_dir=str(self.output))
                environment = capture.prepare(selected)
                self.api.same(environment['Current']['Bundle']['Descriptor'], current_descriptor,
                              'same independently admitted inventory in current Seed preparation')
                self.api.same(environment['Group']['Descriptor'], seed_descriptor, 'same prepared ordinary Seed')
                self.api.same(environment['Producer'], producer, 'same guarded current capture module')
                environments[side] = environment

            self.watch = capture.CombinedClosure(self.api, environments['Native']['Seed'].closure, outer)
            for side, environment in environments.items():
                _merge_environment(self, environment)
                bundle = bundles[side]
                _capture_inputs(self, bundle)
                root, result, artifacts = (bundle[name] for name in ('Root', 'Result', 'Artifacts'))
                seed = environment['Seed']
                need(seed.inventory == current['Bundle']['Root'], 'current inventory in both Seeds')
                ledger = seed.inventory / 'inputs/FREERTOS_ASM_PARITY.md'
                need(ledger in seed.originals, 'master ledger is an authenticated Seed input')
                master = self.watch.read(ledger, seed.originals[ledger]['Sha256'])
                self.groups[side] = dict(Root=root, Result=result, Artifacts=artifacts, Seed=seed,
                    ReceiptSha256=bundle['Descriptor']['ReceiptSha256'],
                    ManifestSha256=bundle['Descriptor']['ArtifactsSha256'], Roles=self._roles(root, artifacts, result),
                    Inventory=seed.inventory, MasterLedger=ledger, MasterLedgerBytes=master,
                    Package=seed.root / 'python/elftools')

            native, reference = self.groups['Native'], self.groups['Reference']
            need(native['Inventory'] == reference['Inventory']
                 and native['MasterLedgerBytes'] == reference['MasterLedgerBytes'],
                 'same captured current master ledger on both sides')
            files = [row['Path'] for group in self.groups.values() for row in group['Roles'].values()]
            need(len(files) == 14 and all(not path.samefile(other)
                 for index, path in enumerate(files) for other in files[:index]),
                 'fourteen physically distinct positive binary roles')
            need(native['Roles']['Machine']['Bytes'] != reference['Roles']['Machine']['Bytes'],
                 'distinct own actual machines')
            for relative, digest in legacy.FIXED.items():
                path = ROOT / relative
                self._buffer(path, self.watch.read(path, digest))
            for path, raw in tuple(outer.buffers.items()):
                self._buffer(path, raw)
            os_producer = legacy.load('current_os_replay_fixed_recipe', ROOT / legacy.PRODUCER,
                                      self.buffers[ROOT / legacy.PRODUCER])
            for side, group in self.groups.items():
                self._commands(side, group, os_producer)
            self.policy = self.watch.read(ROOT / legacy.POLICY, legacy.POLICY_SHA)

            git_rows = [row for row in reference['Seed'].commands if row['Label'] == 'reference git rev-parse']
            need(len(git_rows) == 2 and git_rows[0]['Argv'][0] == git_rows[1]['Argv'][0],
                 'one seed-authenticated external Git provenance tool')
            self.provenance_git = self.api.regular(git_rows[0]['Argv'][0])
            need(self.provenance_git in reference['Seed'].originals and self.provenance_git in self.watch.hashes
                 and not self.provenance_git.is_relative_to(self.output)
                 and not any(self.provenance_git.is_relative_to(group['Root']) for group in self.groups.values()),
                 'nonexecuted external Git provenance identity')
            self.watch.read(self.api.regular(legacy.interpreter_path()))
            denied = {ROOT, *outer.denied, *(group['Root'] for group in self.groups.values()),
                      *(path.parent for path in self.watch.hashes)}
            need(not self.output.exists() and all(not self.output.is_relative_to(path)
                 and not path.is_relative_to(self.output) for path in denied),
                 'fresh output disjoint from every authenticated input root')
            for path in self.watch.hashes:
                self.identities[path] = self._physical(path)
            self.close()
            self.expected = {'results.json', 'artifacts.json'}
            self.report = dict(Status='FAIL', Error=None, Scope='CM3_OS_LTO_SIX_BODY_MECHANISM_JOIN_ONLY',
                Profile='CM3', Mode=MODE, Cohort=self.api.COHORT, ReferenceCommit=legacy.PIN,
                SourceInventoryReceipt=str(current['Bundle']['Root']), SourceInventorySha256=SOURCE_SHA,
                CurrentInventory=copy.deepcopy(current_descriptor), CurrentCaptureProducer=producer,
                CurrentReplaySources=[dict(Path=str(path), Sha256=sha(raw)) for path, raw in sorted(sources.items())],
                CanonicalProtocolValidated=False, FinalRootRelocationProof=False,
                Qualification=False, FinalReferenceParity=False, FullABIProof=False, FullSemanticABIProof=False,
                SourceIRProof=False, PolicyEquivalence=False, SourceToMachineSemanticProof=False,
                OriginalTranslationUnitOwnership=False, CompleteObjectProof=False, CpuExecution=False,
                BoardExecution=False, GlobalFreezeQualified=False, HostedCIQualified=False,
                RequiredCellSatisfied=False, RequiredCellsSatisfied=0, RequiredCellCount=2774,
                NativeCommandsExecuted=0, ProducerCompilersReexecuted=False, MutantsReexecuted=False,
                NonexecutedGitProvenanceTool=dict(Path=str(self.provenance_git),
                    Sha256=self.watch.hashes[self.provenance_git], PhysicalIdentity=self.identities[self.provenance_git]),
                Interpreter=dict(ModulePath=str(legacy.interpreter_path()),
                    Sha256=self.watch.hashes[self.api.regular(legacy.interpreter_path())], Version=legacy.sys.version))

    return CurrentOsWitness
