"""Capture current-source native/reference CM3 LTO images; never execute them."""
import argparse
import copy
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PINS = {
    'replay': ('tools/freeze_replay.py', '142BDDE647122DB2D66EF66E4C44A33ECEAA9292FFE304EF3C7CBCC740283275'),
    'api': ('tools/fixtures/cm3_lto_transport/probe.py', 'F2D4CA9F1FC1F7FAE07F275913F7DFC688BFD8570AEE32DE2144EE1EA187F626'),
    'reference': ('tools/fixtures/cm3_reference_lto_transport/probe.py', '1D1FDC0D644123FEF1E182107A8062A0BA9BCCB385DA0C2D13BDFD741290F2C3'),
    'legacy': ('tools/fixtures/cm3_reference_lto_transport/admission.py', '27C192C12E30BD4F1A872D6A8586B85C303AF6D6873A85A26238BE7DD4962ECC'),
    'os': ('tools/fixtures/cm3_os_lto_transport/probe.py', 'F5F75D7439B97049B5440695CB78862AA0815D7E1E69224BDBDC2B9AADE2AD01'),
    'profiles': ('tools/fixtures/ordinary_final_cell/profiles.py', 'BDD5C9A1F490FF3156CB4DC752F0C411F6FA07852BA5024124E91CC05601CFCD'),
    'parameterized': ('tools/fixtures/cm3_current_lto_capture/admission.py', 'BB4927C3046CC7FEEB42BF37D84CDF0790CB6C58D7C5F17E0AB2983E6727AEAF'),
    'commands': ('tools/fixtures/cm3_current_lto_capture/commands.py', 'C89CF702850D10582479F57D24590F13AFB757ECBE3A45BEF77F1B705DECC6BF'),
}
BUFFER_PINS = {
    'loader': ('tools/fixtures/cm3_final_roots/reference_witness.py', 'AED0DBAC11EB8644EED71F9FAF36C67B2854DE19262A78CC7EA601FA7A3DD99C'),
    'binding': ('tools/fixtures/classic_final_join/join.py', '2785F72E5F86257A403141EB856BB8D49F0A9A6CF4D005CC858D8D2B60EBF013'),
}
SOURCE_SHA = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'
REFERENCE_PIN = 'a50edad08b29052631aa469d4df6e6ec7ff68878'
COHORT = 'cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default'
CONTRACT = 'CURRENT_CM3_LTO_SOURCE_CAPTURE_V1'
NONCLAIMS = ('Qualification', 'FullABIProof', 'FullSemanticABIProof', 'SourceIRProof',
    'SourceToMachineSemanticProof', 'OriginalTranslationUnitOwnership', 'CanonicalProtocolValidated',
    'FinalRootRelocationProof', 'FinalReferenceParity', 'PolicyEquivalence', 'CompleteObjectProof',
    'CpuExecution', 'BoardExecution', 'GlobalFreezeQualified', 'HostedCIQualified', 'ArchiveExtraction')


def need(condition, message):
    if not condition:
        raise ValueError('cm3-current-lto-capture: ' + message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def module(name, path, raw):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    exec(compile(raw, str(path), 'exec'), result.__dict__)
    return result


def select(side, mode):
    need(type(side) is str and side in ('native', 'reference'), 'one exact capture side')
    need(type(mode) is str and mode in ('O2-lto', 'Os-lto'), 'one exact LTO mode')
    count = 9 if side == 'native' else 4
    suffix = 'O2' if mode == 'O2-lto' else 'OS'
    prefix = 'NATIVE' if side == 'native' else 'PINNED_REFERENCE'
    return dict(Side=side, Mode=mode, SeedMode='O2', Profile='CM3', Cohort=COHORT,
        Route='CM3/' + mode + '/direct/' + side, TranslationUnits=count, SlimIRObjects=count - 1,
        DriverCommands=4 * count + 21, Scope=prefix + '_CM3_' + suffix + '_LTO_CAPTURE_FEASIBILITY_ONLY')


def seed_args(args):
    model = select(args.side, args.mode)
    side = model['Side']
    return SimpleNamespace(**{side + '_build': args.seed_build,
        side + '_receipt_sha256': args.seed_receipt_sha256,
        side + '_artifacts_sha256': args.seed_artifacts_sha256, 'output_dir': args.output_dir})


def load_environment():
    need(not sys.flags.optimize and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
         'fresh isolated unoptimized -I -S -B Python required')
    need(not any(n == 'elftools' or n.startswith('elftools.') for n in sys.modules), 'no inherited ELF parser state')
    relative, digest = PINS['replay']
    path, raw = ROOT / relative, (ROOT / relative).read_bytes()
    need(sha(raw) == digest, 'fixed outer admission buffer')
    replay = module('_current_cm3_lto_replay', path, raw)
    watch = replay.Closure()
    need(watch.read(path, digest) == raw, 'executed replay buffer')
    buffers = {name: watch.read(ROOT / rel, pin) for name, (rel, pin) in PINS.items() if name != 'replay'}
    modules = {'replay': replay}
    modules.update({name: module('_current_cm3_lto_' + name, ROOT / PINS[name][0], data)
                    for name, data in buffers.items()})
    watch.read(Path(__file__).resolve())
    watch.read(HERE / 'CONTRACT.md')
    watch.read(replay.interpreter_path())
    for relative, digest in BUFFER_PINS.values():
        watch.read(ROOT / relative, digest)
    return modules, watch


@contextmanager
def bound_loader_read(watch):
    """Bind only the legacy native constructor's unpinned bootstrap read."""
    relative, digest = BUFFER_PINS['loader']
    selected = ROOT / relative
    raw = watch.read(selected, digest)
    original_read = Path.read_bytes
    evidence = dict(Path=str(selected), Sha256=digest, Reads=0, PhysicalClosingOutsideReadHook=False)

    def read(path):
        if Path(path).absolute() == selected:
            evidence['Reads'] += 1
            return raw
        return original_read(path)

    with patch.object(Path, 'read_bytes', read):
        yield evidence


class CombinedClosure:
    """Keep legacy hash/membership checks and modern physical closing together."""
    def __init__(self, api, legacy, guard):
        self.api, self.legacy, self.guard = api, legacy, guard
        self.hashes, self.memberships = legacy.hashes, legacy.memberships
        for path, digest in tuple(legacy.hashes.items()):
            guard.read(path, digest)
        for path, digest in tuple(guard.hashes.items()):
            legacy.read(path, digest)
        for root, names in legacy.memberships.items():
            guard.tree(root, {name: legacy.hashes[root / name] for name in names})

    def read(self, path, expected=None):
        raw = self.legacy.read(path, expected)
        need(self.guard.read(path, sha(raw)) == raw, 'same legacy/physical input buffer')
        return raw

    def structured(self, path, expected=None):
        return json.loads(self.read(path, expected), object_pairs_hook=self.api.unique_object)

    def tree(self, root, artifacts):
        self.legacy.tree(root, artifacts)
        self.guard.tree(root, artifacts)

    def close(self):
        self.legacy.close()
        self.guard.close()


def prepare(args):
    model = select(args.side, args.mode)
    modules, watch = load_environment()
    replay, api = modules['replay'], modules['api']
    admission = replay.Admission(watch)
    current = admission.snapshot(dict(Build=args.inventory,
        ReceiptSha256=replay.digest(args.inventory_receipt_sha256),
        ArtifactsSha256=replay.digest(args.inventory_artifacts_sha256)), current=True)
    replay.same(current['SourceInventorySha256'], SOURCE_SHA, 'fixed current source cut')
    group = admission.bundle(dict(Build=args.seed_build,
        ReceiptSha256=replay.digest(args.seed_receipt_sha256),
        ArtifactsSha256=replay.digest(args.seed_artifacts_sha256)))
    admission.require_inventory_binding(group, current, required=True)
    require_seed = modules['profiles'].require_native if args.side == 'native' else modules['profiles'].require_reference
    require_seed(group['Result'], 'CM3', 'O2')
    translated = seed_args(args)
    if args.side == 'native':
        with bound_loader_read(watch) as bootstrap:
            seed = api.Seed(translated)
        need(bootstrap['Reads'] > 0, 'native constructor consumes the admitted loader buffer')
    else:
        seed = modules['parameterized'].seed_type(modules['legacy'])(api, translated)
        bootstrap = dict(Mode='LEGACY_REFERENCE_PINNED_BOOTSTRAP', PhysicalClosingOutsideReadHook=False)
    # Physical closing must not use the temporary constructor-buffer read hook.
    watch.close()
    bootstrap['PhysicalClosingOutsideReadHook'] = True
    replay.same(seed.result, group['Result'], 'same fully admitted ordinary seed')
    need(seed.inventory == current['Bundle']['Root'], 'seed uses the independently admitted current inventory')
    for name, field in (('results.json', 'ReceiptSha256'), ('artifacts.json', 'ArtifactsSha256')):
        path = seed.inventory / name
        replay.same(seed.originals[path]['Sha256'], current['Bundle']['Descriptor'][field],
                    'captured seed/current inventory descriptor: ' + name)
    seed.closure = CombinedClosure(api, seed.closure, watch)
    denied = watch.denied | {path.parent for path in watch.hashes}
    need(all(not seed.output.is_relative_to(root) and not root.is_relative_to(seed.output) for root in denied),
         'output overlaps the outer admission/source/tool/helper closure')
    seed.closure.close()
    helpers = [dict(Path=str(ROOT / rel), Sha256=pin) for rel, pin in (*PINS.values(), *BUFFER_PINS.values())]
    return dict(Modules=modules, Watch=watch, Current=current, Group=group, Model=model,
        Seed=seed, Args=translated, Helpers=helpers, Bootstrap=bootstrap,
        Producer=dict(Path=str(Path(__file__).resolve()), Sha256=watch.hashes[Path(__file__).resolve()]))


def require_capture(report, model, *, sealed):
    for field in ('Profile', 'Mode', 'Cohort', 'Scope', 'TranslationUnits', 'SlimIRObjects'):
        need(type(report.get(field)) is type(model[field]) and report[field] == model[field], 'capture field: ' + field)
    need(report.get('CaptureContract') == CONTRACT and report.get('CurrentCaptureRoute') == model['Route']
         and report.get('SourceInventorySha256') == SOURCE_SHA, 'current capture/inventory identity')
    need(report.get('Status') == 'PASS' and report.get('Error') is None
         and report.get('PrimaryError') is None and report.get('ClosingErrors') == []
         and report.get('InputClosureVerified') is True, 'complete successful capture input closing')
    need(report.get('Linkage') == 'direct' and report.get('LTO') is True
         and report.get('RequiredCellSatisfied') is False and type(report.get('RequiredCellsSatisfied')) is int
         and report['RequiredCellsSatisfied'] == 0 and type(report.get('RequiredCellCount')) is int
         and report['RequiredCellCount'] == 2774,
         'literal zero credit and direct LTO identity')
    need(all(report.get(name) is False for name in NONCLAIMS), 'non-promoting capture scope')
    need(type(report.get('SavedMachineObjects')) is int and report['SavedMachineObjects'] == 2
         and type(report.get('FinalExecutableLinks')) is int and report['FinalExecutableLinks'] == 2
         and type(report.get('Sources')) is list and len(report['Sources']) == model['TranslationUnits']
         and type(report.get('Links')) is list and len(report['Links']) == 2,
         'both genuine machine/image twins and all sources')
    need(report.get('TwinLoadImageCompared') is True and report.get('TwinLoadImageIdentical') is True
         and report.get('TwinAllocatedSectionsIdentical') is True and report.get('TwinLoadImages', {}).get('Identical') is True,
         'actual structural twin comparison')
    commands = report.get('Commands')
    need(type(commands) is list and len(commands) == model['DriverCommands']
         and all(row.get('Status') == 'PASS' and type(row.get('Exit')) is int and row['Exit'] == 0
                 and row.get('State') == 'TERMINAL' and row.get('TimedOut') is False
                 and row.get('Error') is None for row in commands),
         'all exact terminal successful driver commands')
    if model['Side'] == 'reference':
        need(report.get('ReferenceBuilt') is True and report.get('ReferenceCommit') == REFERENCE_PIN,
             'actual pinned-reference capture')
    if sealed:
        need(report.get('OutputSealVerified') is True, 'complete intended-byte output seal')


def probe_type(environment):
    modules, model, seed = (environment[k] for k in ('Modules', 'Model', 'Seed'))
    api, side = modules['api'], model['Side']
    if model['Mode'] == 'Os-lto':
        base = modules['os'].probe_type(api, side, modules['reference'] if side == 'reference' else None)
    else:
        base = api.Probe if side == 'native' else modules['reference'].probe_type(api)

    class Probe(base):
        def __init__(self, selected, args):
            super().__init__(selected, args)
            self.report.update(dict.fromkeys(NONCLAIMS, False))
            self.report.update(CaptureContract=CONTRACT, CurrentCaptureRoute=model['Route'],
                SourceInventorySha256=SOURCE_SHA, RequiredCellCount=2774,
                PrimaryError=None, ClosingErrors=[],
                CurrentInventory=copy.deepcopy(environment['Current']['Bundle']['Descriptor']),
                SeedAuthority=copy.deepcopy(environment['Group']['Descriptor']),
                ConstructorBootstrap=copy.deepcopy(environment['Bootstrap']),
                CaptureProducer=copy.deepcopy(environment['Producer']),
                FrozenCaptureHelpers=copy.deepcopy(environment['Helpers']))

        def verify_tools(self):
            super().verify_tools()
            for path, digest in self.tool_hashes.items():
                seed.closure.read(path, digest)

        def command(self, argv, label, *, cwd=None, timeout=120):
            return modules['commands'].command(self, api, argv, label, cwd=cwd, timeout=timeout)

        def write_seal(self):
            if self.report.get('Status') == 'PASS':
                require_capture(self.report, model, sealed=False)
                authority = environment['Group']['Descriptor']
                need(Path(self.report['SeedBuild']) == environment['Group']['Root']
                     and self.report['SeedReceiptSha256'] == authority['ReceiptSha256']
                     and self.report['SeedArtifactsSha256'] == authority['ArtifactsSha256'],
                     'actual build uses the independently admitted seed descriptor')
                need(Path(self.report['SourceInventoryReceipt']) == environment['Current']['Bundle']['Root'],
                     'actual build uses the independently admitted inventory')
            elif self.report.get('PrimaryError') is None:
                self.report['PrimaryError'] = self.report.get('Error')
            self.report['InputHashes'] = {str(p): digest for p, digest in seed.closure.hashes.items()}
            self.report['InputPhysicalIdentities'] = {str(p): list(identity)
                for p, identity in environment['Watch'].identities.items()}
            need(set(self.report['InputHashes']) == set(self.report['InputPhysicalIdentities']),
                 'complete captured input physical identity surface')
            self.report['OutputSealVerified'] = True
            receipt = encoded(self.report)
            expected = {name: sha(path.read_bytes()) for name, path in api.files_under(self.output).items()
                        if name not in ('results.json', 'artifacts.json')}
            expected['results.json'] = sha(receipt)
            manifest = encoded(dict(Artifacts=expected))
            self.manifest_hash = sha(manifest)
            (self.output / 'results.json').write_bytes(receipt)
            (self.output / 'artifacts.json').write_bytes(manifest)
            actual = {name: sha(path.read_bytes()) for name, path in api.files_under(self.output).items()
                      if name != 'artifacts.json'}
            api.same(actual, expected, 'intended receipt and exact output membership')
            need((self.output / 'artifacts.json').read_bytes() == manifest, 'intended manifest bytes')
            need((self.output / 'results.json').read_bytes() == receipt, 'intended receipt bytes')
            return expected

        def persist_failure_evidence(self):
            """Best-effort consistent diagnostics, not a successful closing seal."""
            self.report['OutputSealVerified'] = False
            receipt = encoded(self.report)
            (self.output / 'results.json').write_bytes(receipt)
            expected = {name: sha(path.read_bytes()) for name, path in api.files_under(self.output).items()
                        if name not in ('results.json', 'artifacts.json')}
            expected['results.json'] = sha(receipt)
            manifest = encoded(dict(Artifacts=expected))
            (self.output / 'artifacts.json').write_bytes(manifest)
            need((self.output / 'results.json').read_bytes() == receipt, 'fallback FAIL receipt bytes')
            need((self.output / 'artifacts.json').read_bytes() == manifest, 'fallback FAIL manifest bytes')

    return Probe


def run(environment):
    seed = environment['Seed']
    probe = probe_type(environment)(seed, environment['Args'])
    seed.output.mkdir(parents=True)
    error = None
    try:
        probe.build()
    except BaseException as failure:
        error = failure
        message = type(failure).__name__ + ': ' + str(failure)
        if probe.report.get('PrimaryError') is None:
            probe.report['PrimaryError'] = message
        elif probe.report['PrimaryError'] != message:
            probe.report['ClosingErrors'].append('build closing: ' + message)
    try:
        finished = probe.finish(error)
    except BaseException as failure:
        force_failure(probe, failure)
    else:
        if finished is not True or not succeeded(probe.report, environment['Model']['Side'],
                                                environment['Model']['Mode']):
            force_failure(probe, ValueError('finish result and complete sealed capture must agree'))
    return probe.report


def force_failure(probe, failure):
    """Never leave a promoting receipt after an unexpected finishing failure."""
    message = type(failure).__name__ + ': ' + str(failure)
    probe.report.update(Status='FAIL', InputClosureVerified=False, OutputSealVerified=False,
                        Error=probe.report.get('Error') or message,
                        PrimaryError=probe.report.get('PrimaryError') or message)
    try:
        probe.write_seal()
    except BaseException as closing:
        probe.report['ClosingErrors'].append('failure seal: ' + type(closing).__name__ + ': ' + str(closing))
        probe.report['OutputSealVerified'] = False
        try:
            probe.persist_failure_evidence()
        except BaseException as persistence:
            probe.report['ClosingErrors'].append('failure receipt: ' + type(persistence).__name__ + ': ' + str(persistence))
            # Independently retry diagnostic revocation, never the build or tools.
            try:
                probe.persist_failure_evidence()
            except BaseException as final_error:
                probe.report['ClosingErrors'].append('final failure receipt: ' + type(final_error).__name__ + ': ' + str(final_error))


def succeeded(report, side, mode):
    try:
        require_capture(report, select(side, mode), sealed=True)
    except (ValueError, KeyError, TypeError, AttributeError):
        return False
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--side', required=True, choices=('native', 'reference'))
    parser.add_argument('--mode', required=True, choices=('O2-lto', 'Os-lto'))
    for name in ('seed-build', 'seed-receipt-sha256', 'seed-artifacts-sha256', 'inventory',
                 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    try:
        report = run(prepare(args))
    except BaseException as failure:
        print('Current CM3 LTO capture failed: ' + type(failure).__name__ + ': ' + str(failure), file=sys.stderr)
        return 1
    print(json.dumps({name: report.get(name) for name in ('Status', 'CurrentCaptureRoute', 'Error',
        'InputClosureVerified', 'OutputSealVerified', 'RequiredCellsSatisfied')}, sort_keys=True))
    return 0 if succeeded(report, args.side, args.mode) else 1


if __name__ == '__main__':
    raise SystemExit(main())
