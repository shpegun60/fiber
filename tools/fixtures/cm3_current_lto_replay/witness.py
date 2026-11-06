"""Replay current CM3 Os-LTO roots/protocols using unchanged ELF predicates."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PINS = {
    'capture': ('tools/fixtures/cm3_current_lto_capture/capture.py',
        '1191CDCDA9FC9312B09858D6439674DBCA19ABFCE5B0108F3575AEF3C65C0852'),
    'legacy': ('tools/fixtures/cm3_os_lto_join/witness.py',
        'BEC9C699F8C62A69CB2BF35B24CF51D8815329517F83A11517BF9657D294D7AB'),
    'admission': ('tools/fixtures/cm3_current_lto_replay/os_admission.py',
        'DA5EB7F209A1787A8C909267B258D7E5B835E64B77785ACCF052306D9D91E857'),
}
CONTRACT_SHA = 'CDB260181CF3A1E4999E392A7478921198A1B868DC108261390ADBC3E490A0EF'
SOURCE = '69A66CB09D699EA45A30B21BF4DBCD569CBE637A7770125E76EE64323D862313'


def need(value, message):
    if not value:
        raise ValueError('current-cm3-os-lto-replay: ' + message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def load(name, path, raw):
    result = importlib.util.module_from_spec(importlib.util.spec_from_file_location(name, path))
    sys.modules[name] = result
    exec(compile(raw, str(path), 'exec'), result.__dict__)
    return result


def prepare(args):
    need(not sys.flags.optimize and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
         'fresh unoptimized isolated -I -S -B Python required')
    need(not any(name == 'elftools' or name.startswith('elftools.') for name in sys.modules),
         'no inherited parser state')
    sources = {}
    for relative, pin in (*PINS.values(), ('tools/fixtures/cm3_current_lto_replay/CONTRACT.md', CONTRACT_SHA)):
        path = ROOT / relative
        raw = path.read_bytes()
        need(digest(raw) == pin, 'fixed authenticated source buffer: ' + relative)
        sources[path] = raw
    sources[Path(__file__).resolve()] = Path(__file__).resolve().read_bytes()
    modules = {name: load('_current_cm3_os_replay_' + name, ROOT / row[0], sources[ROOT / row[0]])
               for name, row in PINS.items()}
    witness = modules['admission'].witness_type(modules['legacy'], modules['capture'],
        extra_sources=sources)(args)
    return witness, modules


def require_result(witness, modules):
    report = witness.report
    need(report.get('Status') == modules['legacy'].PASS and report.get('Error') is None,
         'complete successful replay')
    need(report.get('SourceInventorySha256') == SOURCE, 'exact current source fingerprint')
    replay = witness.replay_api
    replay.report_evidence('CM3/Os-lto/direct', report)
    return report


def persist_failure_evidence(witness):
    """Write consistent diagnostic bytes without claiming a successful seal."""
    witness.report.update(Status='FAIL', InputClosureVerified=False, OutputSealVerified=False,
        CanonicalProtocolValidated=False, FinalRootRelocationProof=False, ImmutableInputsConsumed=False)
    encode = lambda value: (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')
    receipt = encode(witness.report)
    (witness.output / 'results.json').write_bytes(receipt)
    artifacts = {name: digest(path.read_bytes())
                 for name, path in witness.replay_api.files_under(witness.output).items()
                 if name not in ('results.json', 'artifacts.json')}
    artifacts['results.json'] = digest(receipt)
    manifest = encode(dict(Artifacts=artifacts))
    (witness.output / 'artifacts.json').write_bytes(manifest)
    need((witness.output / 'results.json').read_bytes() == receipt, 'fallback FAIL receipt bytes')
    need((witness.output / 'artifacts.json').read_bytes() == manifest, 'fallback FAIL manifest bytes')


def revoke_failure(witness, error):
    message = type(error).__name__ + ': ' + str(error)
    report = witness.report
    report['PrimaryError'] = report.get('PrimaryError') or report.get('Error') or message
    closing = report.setdefault('ClosingErrors', [])
    try:
        witness._fail(message)
    except BaseException as secondary:
        closing.append('failure hook: ' + type(secondary).__name__ + ': ' + str(secondary))
        print(closing[-1], file=sys.stderr)
    report.update(Status='FAIL', InputClosureVerified=False, OutputSealVerified=False,
        CanonicalProtocolValidated=False, FinalRootRelocationProof=False, ImmutableInputsConsumed=False)
    report['Error'] = report.get('Error') or message
    try:
        witness._seal()
    except BaseException as secondary:
        closing.append('failure seal: ' + type(secondary).__name__ + ': ' + str(secondary))
        print(closing[-1], file=sys.stderr)
        report['OutputSealVerified'] = False
        for attempt in range(2):
            try:
                persist_failure_evidence(witness)
                break
            except BaseException as persistence:
                closing.append('failure persistence %d: %s: %s' %
                    (attempt + 1, type(persistence).__name__, persistence))
                print(closing[-1], file=sys.stderr)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('native-build', 'native-receipt-sha256', 'native-artifacts-sha256',
                 'reference-build', 'reference-receipt-sha256', 'reference-artifacts-sha256',
                 'inventory', 'inventory-receipt-sha256', 'inventory-artifacts-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    witness = None
    try:
        with patch('subprocess.Popen', side_effect=AssertionError('replay cannot execute processes')), \
                patch('os.system', side_effect=AssertionError('replay cannot execute shell commands')):
            witness, modules = prepare(args)
            need(witness.run() is True, 'replay run failed: ' + str(witness.report.get('Error')))
            report = require_result(witness, modules)
    except BaseException as error:
        if witness is not None and witness.output.exists():
            try:
                revoke_failure(witness, error)
            except BaseException as closing:
                print('Failure evidence could not be sealed: ' + str(closing), file=sys.stderr)
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps({key: report.get(key) for key in ('Status', 'Profile', 'Mode',
        'InputClosureVerified', 'OutputSealVerified', 'TransportControlsExecuted',
        'CanonicalControlsExecuted', 'RequiredCellsSatisfied')}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
