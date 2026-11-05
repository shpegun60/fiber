"""Execute closed, frozen proof gates; retain components, never qualify cells."""
import argparse
import copy
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import sys


ROOT = Path(__file__).resolve().parent.parent
MODES = ('O0', 'Og', 'O2', 'Os', 'O3')
PIN = 'a50edad08b29052631aa469d4df6e6ec7ff68878'
PROFILES = {
    'CM0': ('cm0-cortex-m0-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default', 'CM0'),
    'CM0PLUS': ('cm0-cortex-m0plus-soft-nofpu-none-v0-mpu0-p2-b0-aapcs-default', 'CM0'),
    'CM0PLUSVTOR': ('cm0-cortex-m0plus-soft-nofpu-none-v1-mpu0-p2-b0-aapcs-default', 'CM0'),
    'CM4': ('cm4-cortex-m4-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default', 'CM4'),
    'CM7': ('cm7-cortex-m7-hard-fpu-eager-v1-mpu0-p4-b16-aapcs-default', 'CM7'),
    'CM3': ('cm3-cortex-m3-soft-nofpu-none-v1-mpu0-p4-b16-aapcs-default', 'CM3'),
}
INVENTORY = 'tools/freeze_cohorts.py'
RUNNER = 'tools/fixtures/freeze_cohorts/process_runner.py'
LOADER = 'tools/fixtures/cm3_final_roots/reference_witness.py'
SOURCE_PINS = {
    INVENTORY: '0BE5B1B70A231F73606837B526ED8F1BE36A439859F50A0AAF9E7BE26EEE1A2D',
    RUNNER: 'D00D16DBFC69C3F49DF24D8F8A7329045DD9545AF50CB37A39ACB38EAC48B104',
    LOADER: 'AED0DBAC11EB8644EED71F9FAF36C67B2854DE19262A78CC7EA601FA7A3DD99C',
    'tools/fixtures/classic_final_join/join.py': '2785F72E5F86257A403141EB856BB8D49F0A9A6CF4D005CC858D8D2B60EBF013',
    'tools/fixtures/cm0_final_join/join.py': '88EBCDB9F8E12670F2FEC199011FA764DCAA4BEDC8F71516D4CD1BD57CF57ACD',
    'tools/fixtures/cm3_final_join/join.py': 'E53CDD177EF04124B766AD54301D58AA2B73D0C67AE9FBA43C979DC557C5A012',
    'tools/fixtures/cm3_lto_join/witness.py': '413089068C1C42ED1B9BE3E0E67E8E56BB6ABDF55CA3E3D866AC657C74B7EA97',
    'tools/fixtures/cm3_os_lto_join/witness.py': 'BEC9C699F8C62A69CB2BF35B24CF51D8815329517F83A11517BF9657D294D7AB',
    'tools/fixtures/cm3_lto_archive_join/witness.py': 'FFD12847C2362F4145F5F1693A7AAFD9FEAC0D30FAA2CC1AF8FF35F179753C4E',
    'tools/fixtures/classic_final_image/run.py': 'FBCBA0C4FF480E139ADE401ECFA90822E9EA01A6AB554CEF157036EC9DE7F014',
    'tools/fixtures/classic_final_image/reference_run.py': 'FB5E1FA3CEE51E8069A15CDC6E3F31F47CA046EF0320960F9CA9C8809C2F1838',
    'tools/fixtures/classic_final_image/reference_elf.py': 'CDE457FEB11A1DCC1D0F41D394C7E62C4B3AA0E109A3D70979CE320914215A4D',
    'tools/fixtures/classic_final_image/elf.py': '3A8F4E42B42189CDDAE44DE6AFA4468F24781B6EDFD13F02491C96C1E0729809',
    'tools/fixtures/classic_final_join/admission.py': 'D860F31BAD2A8E2A9FD976FE90CD30D44C59B8FD915F7FF89F86BA004F4E80A4',
    'tools/freeze_classic_fp_mechanisms.py': '684B90DC53C3989A462E41D3315362C087ED1900AEEA923BE9246C03779446C2',
    'tools/freeze_cm3_mechanisms.py': '6062D2B00EB1E4C8382207C01E55F5A11613EBE235EDA1E855B630161A0B11DE',
    'tools/freeze_cm0_mechanisms.py': 'D6F51EC262017275640E78F99AE556302F70A163BCD0654DE17C457A91C31476',
    'tools/runtime_sources.py': '0F8E530CA9EBB3FC88BCE4C2BC296093AAA59DCA845182F20151C17D844F0595',
    'tools/fixtures/freeze_cohorts/build_recipe.py': 'C62B0892786044C33680774D23B22C54C857E4C6F00148651FB0B6E639A34F68',
    'tools/fixtures/freeze_cohorts/reference_recipe.py': '84916E79046A5199F0224CD40EA7FB95B75B3E8F3D072CE76F7CE0B8BFC8E21B',
    'tools/fixtures/cm55_tfm_parity/elf.py': '394BA0549C2325BC5BB988EB1A6EBA89263CAF3E351189582931C59A64D5752D',
    'tools/fixtures/cm4_cm7_freeze_parity/check.py': '6E81B3434333402F6FE17B6920676790D819B6FBDCB3FFE9C6384060123A8447',
    'tools/fixtures/cm0_freeze_parity/closed_roots.py': '5FA69CE3BD4C46F5644DB29AB59E3476023728D76A2DCDBD515F0B9E3C5C91FC',
    'tools/fixtures/cm0_final_image/reference_run.py': '6F1171044756C0F285E2B58B9DBC0D03B44B883B759241E6037A4CFAB53D0404',
    'tools/fixtures/cm0_final_roots/reference_elf.py': 'B4518296657268BBDCA59C87242D533D1BE43AA69A4FC6511456D75E015FB142',
    'tools/fixtures/cm0_final_join/admission.py': '3F0A400183195102B98543A519CAC2D6D86414A1B5411760EB75F19F94CDE81E',
    'tools/fixtures/cm3_final_image/reference_run.py': '0091CA8ECCEE8B34C25B290BEE46C0BE3A3BF0656B2689EC664EF15F35776CBA',
    'tools/fixtures/cm3_final_image/admission.py': '2D1DA1B87129438717666E669B347A0E91F998F5A75BEB961CA9FDDE44F1D87D',
    'tools/fixtures/cm3_final_roots/reference_elf.py': '1F62F514EE90F1A0051F4C6028FE8AA74134A66573C64CFD88FB7BCA9DE80F28',
    'tools/fixtures/cm3_final_join/admission.py': 'D3E4DF449B91218BC7EF7C479B9665F2ACD861A9CB815DDA193ECFF2AFBDDFE1',
    'tools/fixtures/cm3_freeze_parity/check.py': 'F0D9CD4F48912FB6E5455AA365BF73FFCF356BAFAD922B3A73ACA992A616A11A',
    'tools/fixtures/cm3_lto_transport/probe.py': 'F2D4CA9F1FC1F7FAE07F275913F7DFC688BFD8570AEE32DE2144EE1EA187F626',
    'tools/fixtures/cm3_reference_lto_transport/probe.py': '1D1FDC0D644123FEF1E182107A8062A0BA9BCCB385DA0C2D13BDFD741290F2C3',
    'tools/fixtures/cm3_reference_lto_transport/admission.py': '27C192C12E30BD4F1A872D6A8586B85C303AF6D6873A85A26238BE7DD4962ECC',
    'tools/fixtures/cm3_lto_roots/native.py': 'D4BA0378FA50E11A570D40180149794B16EB0807E36DC902C19840E32D1AF05D',
    'tools/fixtures/cm3_reference_lto_roots/reference.py': '3E53C4C0C5030B973A599FBDD0CB0B7FDECC625DEFD8C204A8C9691C5F6A616D',
    'tools/fixtures/cm3_lto_roots/mutations.py': '32BDE6CA67B12EEC9975D24D6628C5576EA29F33121CD60310F1F010CF272353',
    'tools/fixtures/cm3_reference_lto_roots/mutations.py': 'E20E55734138E5F9AE76019D3C3EF1260EE708FDF222DC72E5C8B5552E02029C',
    'tools/fixtures/cm3_lto_protocol/protocol.py': 'BA3B630BB1FEA67C81D2EE18C84F6D2A47DE9802E8763F52EE55DB34CD65F419',
    'tools/fixtures/cm3_reference_lto_protocol/protocol.py': '200B277D03DF4236FE887907F732BC2A26898D8C15C1544D917B3DC3CF6BF798',
    'tools/fixtures/cm3_lto_protocol/witness.py': '39E1994A74DB225CD3BB2010AE07C49FD1DB2EE2006BCAD2FC59BD3092E6CF51',
    'tools/fixtures/cm3_reference_lto_protocol/witness.py': 'B3968C5C51BCB7DFF13425B6656715DB4FA9674C18503AA04FDE7EA0A0F89D5F',
    'tools/fixtures/cm3_lto_roots/witness.py': '5BFA66061B9BFAC9B7C6AF872AB831E69613DDDA03C0FA40E439E36273963713',
    'tools/fixtures/cm3_reference_lto_roots/witness.py': '3B9168D52F7AA63339264A8E7B655DF94FF1AC644FF08D20E4B617CED5699B54',
    'tools/fixtures/cm3_lto_join/join.py': 'F4EF2402495FF90C6D781762EC2B85A458F7DA702F14B2C6A1581D9E09343CE3',
    'tools/fixtures/cm3_os_lto_transport/probe.py': 'F5F75D7439B97049B5440695CB78862AA0815D7E1E69224BDBDC2B9AADE2AD01',
    'tools/fixtures/cm3_os_lto_join/compose.py': '359BB0E7463F4514F5964529702DDC07CCED773927970AC3C246A1B7E845367E',
    'tools/fixtures/cm3_lto_archive_roots/witness.py': '7D65BACFC6CDCFA4B02324905693675A1CA26AEDF92008415CC77645A94E1A6A',
    'tools/fixtures/cm3_lto_archive/probe.py': 'E2E068AEBEE77E344EA924B08CCE61E0B57D0B5B2F04652D9391680351655FF7',
    'tools/fixtures/cm3_reference_lto_archive/probe.py': '966501D5AB3F8D5EC33375514FC9CA5E43833564DBFA6684D0C1A4E61702BB3B',
}
STOPPED = frozenset(('cm33f_secure_transfer_reference', 'm55_secure_closed_parity',
    'test_cm33f_secure_transfer_reference.ps1', 'test_m55_secure_closed_parity.ps1'))
DESCRIPTOR_KEYS = {'Build', 'ReceiptSha256', 'ArtifactsSha256'}
SELECTION_KEYS = {'Route', 'Inventory', 'Native', 'Reference', 'PriorJoin'}


class Rejected(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise Rejected('freeze-replay: ' + message)


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def same(actual, expected, message):
    need(encoded(actual) == encoded(expected), message)


def digest(value):
    need(type(value) is str and re.fullmatch('[0-9A-F]{64}', value) is not None, 'uppercase SHA256 required')
    return value


def structured(data):
    def pairs(items):
        result, seen = {}, set()
        for key, value in items:
            need(key.casefold() not in seen, 'duplicate/case-aliased JSON key')
            seen.add(key.casefold())
            result[key] = value
        return result
    def constant(value):
        raise Rejected('freeze-replay: nonfinite JSON value ' + value)
    return json.loads(data.decode('utf-8-sig'), object_pairs_hook=pairs, parse_constant=constant)


def absolute_text(value):
    need(type(value) is str and value.isascii() and value and all(ord(c) >= 32 for c in value), 'literal absolute path')
    path = PureWindowsPath(value) if PureWindowsPath(value).is_absolute() else PurePosixPath(value)
    need(path.is_absolute() and '..' not in path.parts and not STOPPED.intersection(p.casefold() for p in path.parts),
         'unsafe/protected path')
    return value


def routes():
    result = {}
    for profile, (cohort, group) in PROFILES.items():
        family = 'cm0_final_join' if profile.startswith('CM0') else 'cm3_final_join' if profile == 'CM3' else 'classic_final_join'
        for mode in MODES:
            result[profile + '/' + mode + '/direct'] = dict(Profile=profile, Mode=mode, Linkage='direct',
                Cohort=cohort, SourceGroup=group, ArtifactRole='runtime', Gate='tools/fixtures/' + family + '/join.py')
    for mode, linkage, gate in (('O2-lto', 'direct', 'cm3_lto_join'),
                               ('Os-lto', 'direct', 'cm3_os_lto_join'), ('O2-lto', 'archive', 'cm3_lto_archive_join')):
        result['CM3/' + mode + '/' + linkage] = dict(Profile='CM3', Mode=mode, Linkage=linkage,
            Cohort=PROFILES['CM3'][0], SourceGroup='CM3', ArtifactRole='runtime', Gate='tools/fixtures/' + gate + '/witness.py')
    return result


def route_for(route_id):
    need(type(route_id) is str and route_id in routes(), 'unknown route')
    return routes()[route_id]


def descriptor(value):
    need(type(value) is dict and set(value) == DESCRIPTOR_KEYS, 'exact evidence descriptor')
    absolute_text(value['Build'])
    digest(value['ReceiptSha256'])
    digest(value['ArtifactsSha256'])


def validate_catalog(value):
    need(type(value) is dict and set(value) == {'SchemaVersion', 'Selections'}
         and type(value['SchemaVersion']) is int and value['SchemaVersion'] == 1, 'catalog schema')
    rows = value['Selections']
    need(type(rows) is list and 0 < len(rows) <= 33, 'nonempty bounded selections')
    seen = set()
    for row in rows:
        need(type(row) is dict and set(row) == SELECTION_KEYS, 'exact selection fields')
        route_for(row['Route'])
        need(row['Route'] not in seen, 'duplicate route')
        seen.add(row['Route'])
        for role in ('Inventory', 'Native', 'Reference', 'PriorJoin'):
            descriptor(row[role])
    return copy.deepcopy(rows)


def gate_arguments(route_id, selection, output):
    row = validate_catalog(dict(SchemaVersion=1, Selections=[selection]))[0]
    need(row['Route'] == route_id, 'route/selection mismatch')
    route, args = route_for(route_id), []
    for side in ('Native', 'Reference'):
        item = row[side]
        args.extend(('--' + side.lower() + '-build', item['Build'],
            '--' + side.lower() + '-receipt-sha256', item['ReceiptSha256'],
            '--' + side.lower() + '-artifacts-sha256', item['ArtifactsSha256']))
    args.extend(('--output-dir', absolute_text(str(output))))
    if route['Mode'] in MODES:
        args.extend(('--profile', route['Profile'], '--mode', route['Mode']))
    return args


def scope_report():
    return dict(Status='FAIL', Error=None, PrimaryError=None, ClosingErrors=[], Scope='FROZEN_GATE_COMPONENT_REPLAY_ONLY',
        RequiredCellCount=2774, RequiredCellSatisfied=False, RequiredCellsSatisfied=0,
        Qualification=False, FullABIProof=False, APIProof=False, GlobalFreezeQualified=False,
        FinalReferenceParity=False, CompleteObjectProof=False, SourceIRProof=False,
        SourceToMachineSemanticProof=False, RuntimeProof=False, CpuExecution=False,
        BoardExecution=False, HostedCIQualified=False, CompilerInvocations=0, NativeCommandsExecuted=0,
        ProofGateInvocations=0, ComponentsUsable=False, InputClosureVerified=False,
        OutputSealVerified=False, Selections=[], Components=[])


def process_environment(environ):
    need(type(environ) is dict and all(type(k) is str and type(v) is str for k, v in environ.items()), 'environment strings')
    lookup = {}
    forbidden = {'pythonpath', 'pythonhome', 'pythonstartup', 'pythoninspect', 'ld_preload', 'ld_library_path',
        'gcc_exec_prefix', 'compiler_path', 'library_path', 'cpath', 'c_include_path', 'cplus_include_path',
        'objc_include_path', 'collect_gcc_options'}
    allowed = {'path', 'systemroot', 'windir', 'temp', 'tmp', 'comspec', 'pathext', 'os',
               'systemdrive', 'processor_architecture', 'number_of_processors'}
    for key, value in environ.items():
        folded = key.casefold()
        need(folded not in lookup and folded not in forbidden, 'aliased/injection environment variable: ' + key)
        lookup[folded] = key
    return {lookup[key]: environ[lookup[key]] for key in sorted(allowed & set(lookup))}


def checked_path(value, *, directory=False, fresh=False):
    absolute_text(str(value))
    path = Path(os.path.abspath(value))
    for ancestor in (path, *path.parents):
        if ancestor.exists() or ancestor.is_symlink():
            info = ancestor.stat(follow_symlinks=False)
            need(not ancestor.is_symlink() and not getattr(info, 'st_file_attributes', 0) & 0x400, 'reparse/symlink input')
    need(path.resolve(strict=not fresh) == path, 'physical/lexical path mismatch')
    if fresh:
        need(not path.exists(), 'fresh output required')
    else:
        need(path.is_dir() if directory else path.is_file(), 'regular input required: ' + str(path))
    return path


def relative_name(value):
    need(type(value) is str and value.isascii() and '\\' not in value and ':' not in value, 'portable artifact name')
    path = PurePosixPath(value)
    need(path.parts and not path.is_absolute() and path.as_posix() == value
         and all(p not in ('.', '..') for p in path.parts)
         and not STOPPED.intersection(p.casefold() for p in path.parts), 'unsafe artifact name')
    return value


def files_under(root):
    root, result, seen = checked_path(root, directory=True), {}, set()
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in directories:
            checked_path(Path(directory) / name, directory=True)
        for name in files:
            path = checked_path(Path(directory) / name)
            relative = relative_name(path.relative_to(root).as_posix())
            need(relative.casefold() not in seen, 'case-aliased artifact')
            seen.add(relative.casefold())
            result[relative] = path
    return result


class Closure:
    def __init__(self):
        self.hashes, self.identities, self.physical, self.trees, self.buffers = {}, {}, {}, {}, {}
        self.denied = {ROOT}

    def read(self, path, expected=None):
        path = checked_path(path)
        before = path.stat()
        identity = (before.st_dev, before.st_ino, before.st_nlink, before.st_size)
        need(identity[:2] not in self.physical or self.physical[identity[:2]] == path, 'physical input/source alias')
        data = path.read_bytes()
        after = path.stat()
        need(identity == (after.st_dev, after.st_ino, after.st_nlink, after.st_size), 'input changed while reading')
        value = sha(data)
        need(expected is None or value == digest(expected), 'input SHA256 mismatch: ' + str(path))
        need(path not in self.hashes or (self.hashes[path] == value and self.identities[path] == identity), 'input drift: ' + str(path))
        self.hashes[path], self.identities[path], self.physical[identity[:2]] = value, identity, path
        if path.suffix == '.py':
            self.buffers[path] = data
        return data

    def json(self, path, expected=None):
        return structured(self.read(path, expected))

    def tree(self, root, expected):
        root = checked_path(root, directory=True)
        need(type(expected) is dict and expected, 'nonempty artifact tree')
        need(root not in self.trees or self.trees[root] == expected, 'conflicting artifact tree')
        actual = files_under(root)
        same(sorted(actual), sorted(expected), 'complete artifact membership: ' + str(root))
        for name, value in expected.items():
            self.read(actual[relative_name(name)], digest(value))
        self.trees[root] = dict(expected)
        self.denied.add(root)

    def close(self):
        for path, value in tuple(self.hashes.items()):
            self.read(path, value)
        for root, expected in tuple(self.trees.items()):
            same(sorted(files_under(root)), sorted(expected), 'closing artifact membership: ' + str(root))


def fixed_module(name, relative, closure):
    path = ROOT / relative
    data = closure.read(path, SOURCE_PINS[relative])
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


def interpreter_path():
    if os.name != 'nt':
        return checked_path(sys.executable)
    buffer = ctypes.create_unicode_buffer(32768)
    function = ctypes.WinDLL('kernel32', use_last_error=True).GetModuleFileNameW
    function.argtypes, function.restype = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32), ctypes.c_uint32
    count = function(None, buffer, len(buffer))
    need(0 < count < len(buffer), 'actual interpreter module path')
    return checked_path(buffer.value)


class Admission:
    def __init__(self, closure):
        self.closure, self.bundles, self.snapshots = closure, {}, {}
        self.inventory = fixed_module('freeze_replay_inventory', INVENTORY, closure)

    def bundle(self, item, *, inventory=False):
        descriptor(item)
        root = checked_path(item['Build'], directory=True)
        if root in self.bundles:
            bundle = self.bundles[root]
            same(bundle['Descriptor'], item, 'conflicting evidence descriptor')
            return bundle
        watch = self.closure
        result = watch.json(root / 'results.json', item['ReceiptSha256'])
        manifest = watch.json(root / 'artifacts.json', item['ArtifactsSha256'])
        need(type(result) is dict and type(manifest) is dict and type(manifest.get('Artifacts')) is dict,
             'structured result and artifact manifest')
        artifacts = manifest['Artifacts']
        need(artifacts.get('results.json') == item['ReceiptSha256'] and 'artifacts.json' not in artifacts,
             'receipt must be bound by manifest')
        watch.tree(root, dict(artifacts, **{'artifacts.json': item['ArtifactsSha256']}))
        bundle = dict(Root=root, Result=result, Artifacts=artifacts, Descriptor=copy.deepcopy(item), Nested=[])
        self.bundles[root] = bundle
        if inventory:
            return bundle
        files = []
        if 'inputs.json' in artifacts:
            inputs = watch.json(root / 'inputs.json', artifacts['inputs.json'])
            need(type(inputs) is dict and type(inputs.get('Files')) is list and inputs['Files'], 'producer input bindings')
            files.extend(inputs['Files'])
            need(type(inputs.get('Generated', {})) is dict, 'generated input bindings')
            for path, value in inputs.get('Generated', {}).items():
                captured = checked_path(path)
                need(captured.is_relative_to(root) and artifacts.get(captured.relative_to(root).as_posix()) == value,
                     'generated input/manifest binding')
                watch.read(captured, value)
            if 'Watched' in inputs:
                need(type(inputs['Watched']) is list and inputs['Watched'], 'nonempty watched input catalog')
                for row in inputs['Watched']:
                    watch.read(row['Path'], digest(row['Sha256']))
        if 'Inputs' in result:
            need(type(result['Inputs']) is list and result['Inputs'], 'nonempty gate input bindings')
            _integer(result.get('ClosingFilesVerified'), len(result['Inputs']), 'complete gate input closing count')
            files.extend(result['Inputs'])
        if 'InputHashes' in result:
            hashes = result['InputHashes']
            need(type(hashes) is dict and hashes, 'nonempty gate input hashes')
            need(type(result.get('ClosingFilesVerified')) is int and result['ClosingFilesVerified'] == len(hashes),
                 'exact prior closing count')
            for path, value in hashes.items():
                watch.read(path, digest(value))
        for row in files:
            need(type(row) is dict and {'Original', 'Captured', 'Sha256'} <= set(row), 'input binding fields')
            original, value = checked_path(row['Original']), digest(row['Sha256'])
            raw = watch.read(original, value)
            watch.denied.add(original.parent)
            if row['Captured'] is not None:
                captured = checked_path(row['Captured'])
                need(captured.is_relative_to(root) and artifacts.get(captured.relative_to(root).as_posix()) == value,
                     'captured input/manifest binding')
                need(captured != original and not captured.samefile(original), 'original/captured physical alias')
                need(watch.read(captured, value) == raw, 'original/captured byte equality')
        need(files or result.get('InputHashes'), 'complete retained input catalog required')
        for prefix in ('Seed', 'Capture'):
            if prefix + 'Build' in result:
                nested = dict(Build=result[prefix + 'Build'], ReceiptSha256=result[prefix + 'ReceiptSha256'],
                              ArtifactsSha256=result[prefix + 'ArtifactsSha256'])
                bundle['Nested'].append(self.bundle(nested))
        return bundle

    def require_inventory_binding(self, bundle, snapshot, *, required=True):
        pending, seen, facts = [bundle], set(), []
        while pending:
            current = pending.pop()
            if current['Root'] in seen:
                continue
            seen.add(current['Root'])
            result = current['Result']
            if 'SourceInventoryReceipt' in result:
                need(checked_path(result['SourceInventoryReceipt'], directory=True) == snapshot['Bundle']['Root'],
                     'reachable source inventory receipt disagrees with selected historical snapshot')
                facts.append(dict(Build=str(current['Root']), Field='SourceInventoryReceipt', Value=result['SourceInventoryReceipt']))
            if 'SourceInventorySha256' in result:
                same(digest(result['SourceInventorySha256']), snapshot['SourceInventorySha256'],
                     'reachable source fingerprint disagrees with selected historical snapshot')
                facts.append(dict(Build=str(current['Root']), Field='SourceInventorySha256', Value=result['SourceInventorySha256']))
            pending.extend(current['Nested'])
        need(not required or facts, 'selected side has no reachable source inventory authority')
        return facts

    def snapshot(self, item, *, current=False):
        bundle = self.bundle(item, inventory=True)
        root, result = bundle['Root'], bundle['Result']
        if root in self.snapshots:
            snapshot = self.snapshots[root]
        else:
            watch, api = self.closure, self.inventory
            need(result.get('Verdict') == 'INVENTORY-PLAN-PASS' and result.get('Error') is None
                 and result.get('GlobalFreezeQualified') is False and result.get('ReferenceCommit') == PIN,
                 'authenticated inventory scope')
            rows = watch.json(root / 'capture.json')['Files']
            need(type(rows) is list and rows, 'nonempty inventory capture')
            captured, fingerprints, originals = {}, {}, set()
            for row in rows:
                need(type(row) is dict and set(row) == {'Original', 'Captured', 'Sha256'}, 'inventory capture row')
                original, path = absolute_text(row['Original']), checked_path(row['Captured'])
                need(original not in originals and path.is_relative_to(root / 'inputs'), 'inventory input identity')
                originals.add(original)
                name = relative_name(path.relative_to(root / 'inputs').as_posix())
                need(name not in captured and bundle['Artifacts'].get('inputs/' + name) == row['Sha256'], 'inventory input membership')
                captured[name] = watch.read(path, digest(row['Sha256']))
                fingerprints[name] = row['Sha256']
                watch.denied.add(Path(original).parent)
            source_sha = api.sha(api.encoded(dict(sorted(fingerprints.items()))))
            same(source_sha, result['SourceInventorySha256'], 'recomputed inventory source fingerprint')
            manifest_bytes = captured['tools/freeze_cohorts.json']
            same(sha(manifest_bytes), result['ManifestSha256'], 'inventory canonical manifest hash')
            manifest = api.read_json(manifest_bytes)
            registry_bytes = captured['tools/fixtures/sensitive_port_closure/run.py']
            registry = api.read_registry(registry_bytes)
            api.validate_manifest(manifest, registry)
            required = api.plan(manifest)
            same(watch.json(root / 'required-cells.json'), required, 'recomputed complete canonical plan')
            same(sha(watch.read(root / 'required-cells.json')), result['RequiredCellsSha256'], 'required plan hash')
            same(result['RequiredCellCount'], required['RequiredCellCount'], 'inventory planned cell count')
            upstream = {name for cohort in manifest['cohorts'] for artifact in cohort['artifacts'] for name in artifact['upstream_sources']}
            bindings = result['ReferenceFileBindings']
            need(type(bindings) is list and len(bindings) == len(upstream)
                 and {row['Path'] for row in bindings} == upstream, 'complete pinned inventory sources')
            for row in bindings:
                worktree = captured['pinned-reference/' + relative_name(row['Path'])]
                blob = watch.read(root / 'reference-blobs' / row['Path'], row['GitBlobSha256'])
                same(sha(worktree), row['WorktreeSha256'], 'pinned inventory worktree hash')
                same(api.reference_bytes_match(worktree, blob), row['ByteComparison'], 'whole-file pinned byte comparison')
            snapshot = dict(Bundle=bundle, SourceInventorySha256=source_sha, Manifest=manifest,
                            Registry=registry, Required=required)
            self.snapshots[root] = snapshot
        if current:
            current_manifest = self.inventory.read_json(self.closure.read(ROOT / 'tools/freeze_cohorts.json'))
            current_registry = self.inventory.read_registry(self.closure.read(ROOT / 'tools/fixtures/sensitive_port_closure/run.py'))
            self.inventory.validate_manifest(current_manifest, current_registry)
            same(snapshot['Manifest'], current_manifest, 'CURRENT inventory must bind current declared manifest')
            same(snapshot['Registry'], current_registry, 'CURRENT inventory must bind current registry facts')
            same(snapshot['Required'], self.inventory.plan(current_manifest), 'CURRENT complete plan')
            need(snapshot['Required']['RequiredCellCount'] == 2774, 'current 2774-key baseline; no reduced inventory')
        return snapshot


def _integer(value, expected, message):
    need(type(value) is int and value == expected, message)


def report_evidence(route_id, result):
    """Check the fixed receipt interface, not the gate's ELF/protocol semantics."""
    route = route_for(route_id)
    need(type(result) is dict and result.get('Error') is None, 'successful structured gate report')
    ordinary = route['Mode'] in MODES
    cm0 = route['Profile'].startswith('CM0')
    if ordinary:
        scope = ('CM0_FAMILY_FINAL_MECHANISM_COMPOSITION_ONLY' if cm0 else
                 'CM3_FINAL_MECHANISM_COMPOSITION_ONLY' if route['Profile'] == 'CM3' else 'CLASSIC_FP_FINAL_MECHANISM_COMPOSITION_ONLY')
        status, proof, closed = 'PASS', result.get('ProtocolProof'), 8 if cm0 else 6
        roots = dict(Native=result.get('NativeFinalRoots'), Reference=result.get('ReferenceFinalRoots'))
        twins = dict(Native=result.get('NativeTwins'), Reference=result.get('ReferenceTwins'))
    else:
        scope, status = {
            ('O2-lto', 'direct'): ('CM3_O2_LTO_SIX_BODY_MECHANISM_JOIN_ONLY', 'CM3-LTO-JOIN-PASS-NOT-QUALIFIED'),
            ('Os-lto', 'direct'): ('CM3_OS_LTO_SIX_BODY_MECHANISM_JOIN_ONLY', 'CM3-OS-LTO-JOIN-PASS-NOT-QUALIFIED'),
            ('O2-lto', 'archive'): ('CM3_O2_LTO_P4_B16_ARCHIVE_SIX_CLOSED_ROOT_JOIN_ONLY', 'CM3-LTO-ARCHIVE-JOIN-PASS-NOT-QUALIFIED'),
        }[(route['Mode'], route['Linkage'])]
        joined = result.get('JoinProof')
        need(type(joined) is dict, 'complete fresh joined evidence')
        proof, roots, closed = joined.get('ProtocolProof'), joined.get('Roots'), 6
        need(type(result.get('RecomputedSides')) is dict and set(result['RecomputedSides']) == {'Native', 'Reference'}, 'both independently replayed sides')
        twins = {side: result['RecomputedSides'][side]['Twins'] for side in ('Native', 'Reference')}
        need(joined.get('CanonicalProtocolValidated') is True, 'joined canonical evidence')
        _integer(joined.get('ClosedBodies'), 6, 'six joined bodies')
        need(result.get('InputClosureVerified') is True and result.get('ImmutableInputsConsumed') is True, 'immutable input closing')
    same([result.get('Status'), result.get('Scope'), result.get('Profile'), result.get('Mode')],
         [status, scope, route['Profile'], route['Mode']], 'exact selected gate verdict/scope/profile/mode')
    for key in ('Cohort', 'Linkage'):
        if key in result:
            same(result[key], route[key], 'exact optional gate ' + key)
    need(result.get('OutputSealVerified') is True and type(result.get('ClosingFilesVerified')) is int
         and result['ClosingFilesVerified'] > 0, 'nonempty closed fresh gate evidence')
    for key in ('GlobalFreezeQualified', 'FinalReferenceParity', 'CompleteObjectProof', 'PolicyEquivalence', 'CpuExecution', 'BoardExecution'):
        need(result.get(key) is False, 'literal gate nonclaim: ' + key)
    for key in ('FullABIProof', 'APIProof', 'Qualification', 'RequiredCellSatisfied', 'SourceIRProof', 'SourceToMachineSemanticProof'):
        if key in result:
            need(result[key] is False, 'no gate promotion: ' + key)
    _integer(result.get('RequiredCellsSatisfied'), 0, 'zero gate cell credit')
    for key in ('InputDrift', 'CapturedInputDrift', 'UnexpectedOutputMembers', 'MissingDeclaredOutputMembers'):
        if key in result:
            same(result[key], [], 'gate drift/nonmembership: ' + key)
    need(type(proof) is dict and type(roots) is dict and set(roots) == {'Native', 'Reference'}, 'full proof and roots')
    _integer(proof.get('ClosedBodies'), closed, 'exact full body count')
    expected_verdict = 'CM0-CLOSED-ROOTS-PASS' if cm0 else 'CM3-CLOSED-ROOTS-PASS' if route['Profile'] == 'CM3' else 'CLASSIC-FP-CLOSED-ROOTS-PASS'
    need(proof.get('Verdict') == expected_verdict, 'fixed checker verdict')
    need(type(proof.get('RootEvidence')) is list and len(proof['RootEvidence']) == closed, 'all canonical bodies retained')
    need(type(proof.get('Mechanisms')) is list and len(proof['Mechanisms']) == 3
         and len({row['Name'] for row in proof['Mechanisms']}) == 3, 'three distinct mechanism records')
    need(type(proof.get('DifferenceIds')) is list and proof['DifferenceIds']
         and len(set(proof['DifferenceIds'])) == len(proof['DifferenceIds']), 'explicit unique differences')
    for side, count in (('Native', 3), ('Reference', 5 if cm0 else 3)):
        need(type(roots[side]) is list and len(roots[side]) == count
             and len({row['Name'] for row in roots[side]}) == count, 'complete unique final root records')
        need(type(twins[side]) is dict and twins[side].get('Identical') is True and twins[side].get('Segments'), 'actual within-side twin evidence')
    controls = 'NOT_EXECUTED_BY_THIS_GATE'
    if not ordinary and route_id == 'CM3/O2-lto/direct':
        _integer(result.get('PriorTransportControlsAuthenticated'), 32, 'authenticated prior transport controls')
        _integer(result.get('PriorCanonicalControlsAuthenticated'), 2, 'authenticated prior canonical controls')
        need(result.get('MutantsReexecuted') is False, 'prior controls are not reexecution')
        controls = 'AUTHENTICATED_PRIOR_32_PLUS_2_NOT_REEXECUTED'
    elif not ordinary:
        _integer(result.get('TransportControlsExecuted'), 32, 'fresh transport control count')
        _integer(result.get('CanonicalControlsExecuted'), 2, 'fresh canonical control count')
        need(result.get('MutantsReexecuted') is True, 'fresh actual control execution')
        for side in ('Native', 'Reference'):
            rows = result['Controls'][side]
            need(type(rows['Transport']) is list and len(rows['Transport']) == 16
                 and type(rows['Canonical']) is list and len(rows['Canonical']) == 1, 'actual side control catalogs')
            for row in rows['Transport'] + rows['Canonical']:
                need(row.get('Status') == 'PASS' and row.get('Files'), 'successful edited actual control evidence')
                _integer(row.get('ClosingFilesVerified'), 6 if row in rows['Canonical'] else 5, 'actual control closing count')
        controls = 'EXECUTED_FRESH_32_PLUS_2'
    return dict(ProtocolProof=proof, Roots=roots, Twins=twins, NegativeControls=controls,
                ClosedBodies=closed, DifferenceIds=proof['DifferenceIds'])


def require_bindings(result, selection):
    rows = result.get('ProducerBindings')
    need(type(rows) is list and len(rows) == 2 and [row.get('Side') for row in rows] == ['Native', 'Reference'], 'ordered producer bindings')
    for side, row in zip(('Native', 'Reference'), rows):
        expected = selection[side]
        need(checked_path(row['Build'], directory=True) == checked_path(expected['Build'], directory=True), 'actual selected input identity')
        same(row['ReceiptSha256'], expected['ReceiptSha256'], 'actual selected input receipt')
        value = row.get('ArtifactsSha256', result.get(side + 'ArtifactsSha256'))
        same(value, expected['ArtifactsSha256'], 'actual selected input artifact manifest')


def _selection_key(route):
    return (route['Cohort'], 'runtime', 'final', route['Mode'], route['Linkage'])


def _cell_key(row):
    return tuple(row[key] for key in ('Cohort', 'ArtifactRole', 'Representation', 'Mode', 'Linkage'))


def prepare(args):
    """Complete all caller-bound admission before any output directory is made."""
    need(not sys.flags.optimize, 'unoptimized interpreter required')
    watch = Closure()
    catalog_path = checked_path(args.catalog)
    catalog_bytes = watch.read(catalog_path, digest(args.catalog_sha256))
    need(catalog_bytes.isascii(), 'ASCII catalog')
    selections = validate_catalog(structured(catalog_bytes))
    admission = Admission(watch)
    current = admission.snapshot(dict(Build=args.inventory, ReceiptSha256=digest(args.inventory_receipt_sha256),
                                     ArtifactsSha256=digest(args.inventory_artifacts_sha256)), current=True)
    entries = []
    for selection in selections:
        snapshot = admission.snapshot(selection['Inventory'])
        groups = {side: admission.bundle(selection[side]) for side in ('Native', 'Reference', 'PriorJoin')}
        need(len({row['Root'] for row in groups.values()}) == 3, 'native/reference/prior role alias')
        route = route_for(selection['Route'])
        for model in (snapshot, current):
            matching = [row for row in model['Required']['RequiredCells'] if _cell_key(row) == _selection_key(route)]
            need(len(matching) == 1 and matching[0]['SourceGroup'] == route['SourceGroup'], 'exact cohort/role/source-group cell admission')
        inventory_facts = {side: admission.require_inventory_binding(groups[side], snapshot)
                           for side in ('Native', 'Reference')}
        inventory_facts['PriorJoin'] = admission.require_inventory_binding(groups['PriorJoin'], snapshot, required=False)
        evidence = report_evidence(selection['Route'], groups['PriorJoin']['Result'])
        require_bindings(groups['PriorJoin']['Result'], selection)
        entries.append(dict(Selection=selection, Route=route, Snapshot=snapshot, Groups=groups,
                            Evidence=evidence, InventoryFacts=inventory_facts))
    for name, value in SOURCE_PINS.items():
        watch.read(ROOT / name, value)
    watch.read(Path(__file__).resolve())
    watch.read(ROOT / 'tools/fixtures/freeze_cohorts/REPLAY_CONTRACT.md')
    interpreter = interpreter_path()
    watch.read(interpreter)
    environment = process_environment(dict(os.environ))
    output = checked_path(args.output_dir, fresh=True)
    denied = watch.denied | {interpreter.parent} | {path.parent for path in watch.hashes if path != catalog_path}
    need(all(not output.is_relative_to(path) and not path.is_relative_to(output) for path in denied)
         and not catalog_path.is_relative_to(output), 'output overlaps authenticated input/source/tool roots')
    watch.close()
    runner = fixed_module('freeze_replay_managed_runner', RUNNER, watch)
    return Dispatcher(output, watch, admission, current, entries, environment, interpreter, runner, catalog_path)


# The existing loader handles nested spec loaders. Normal package imports and
# direct read_bytes loaders also consume the same admitted immutable buffers.
BOOTSTRAP = r'''
import hashlib, importlib.machinery, json, sys
from pathlib import Path
from unittest.mock import patch
snapshot, expected, entry, trace, *arguments = sys.argv[1:]
raw = Path(snapshot).read_bytes()
if hashlib.sha256(raw).hexdigest().upper() != expected:
    raise RuntimeError('replay immutable source snapshot mismatch')
model = json.loads(raw)
buffers = {}
for original, row in model['Sources'].items():
    data = Path(row['Captured']).read_bytes()
    if hashlib.sha256(data).hexdigest().upper() != row['Sha256']:
        raise RuntimeError('replay captured source mismatch')
    buffers[Path(original).resolve()] = data
loader_path = Path(model['Loader']).resolve()
namespace = {'__file__': str(loader_path), '__name__': '_replay_frozen_loader'}
exec(compile(buffers[loader_path], str(loader_path), 'exec'), namespace)
graph = namespace['FrozenSources'](buffers)
original_spec = graph.original_spec
read_bytes = Path.read_bytes
get_code = importlib.machinery.SourceFileLoader.get_code
executed = [{'Name': '_replay_frozen_loader', 'Path': str(loader_path),
             'Sha256': hashlib.sha256(buffers[loader_path]).hexdigest().upper()}]
def code_objects(code):
    yield code
    for item in code.co_consts:
        if type(item) is type(code):
            yield from code_objects(item)
templates = {code.co_name: code for code in code_objects(namespace['FrozenSources'].spec.__code__)
             if code.co_name in ('exec_module', 'create_module')}
loader_sha = hashlib.sha256(buffers[loader_path]).hexdigest().upper()
def source_spec(name, location, *, loader=None, submodule_search_locations=None):
    if loader is None:
        return graph.spec(name, location, submodule_search_locations=submodule_search_locations)
    path = Path(location).resolve()
    methods = vars(type(loader))
    execute, create = methods.get('exec_module'), methods.get('create_module')
    code = getattr(execute, '__code__', None)
    origin = Path(code.co_filename).resolve() if code is not None else None
    if (submodule_search_locations is not None or path not in buffers or origin not in buffers
        or hashlib.sha256(buffers[origin]).hexdigest().upper() != loader_sha
        or code != templates['exec_module'].replace(co_filename=str(origin))
        or getattr(create, '__code__', None) != templates['create_module'].replace(co_filename=str(origin))):
        raise RuntimeError('replay unapproved custom loader')
    cells = dict(zip(code.co_freevars, execute.__closure__ or ()))
    if set(cells) != {'data', 'name', 'owner', 'path'}:
        raise RuntimeError('replay unapproved custom loader closure')
    data, owner = cells['data'].cell_contents, cells['owner'].cell_contents
    if (type(data) is not bytes or data != buffers[path] or type(getattr(owner, 'buffers', None)) is not dict
        or owner.buffers.get(path) != data or cells['name'].cell_contents != name
        or Path(cells['path'].cell_contents).resolve() != path
        or type(getattr(owner, 'executed', None)) is not list):
        raise RuntimeError('replay nested source bytes outside authenticated snapshot')
    class TracedLoader(namespace['importlib'].abc.Loader):
        def create_module(self, spec):
            return create(loader, spec)
        def exec_module(self, module):
            executed.append({'Name': name, 'Path': str(path),
                             'Sha256': hashlib.sha256(data).hexdigest().upper()})
            return execute(loader, module)
    return original_spec(name, path, loader=TracedLoader())
def source_read(path):
    key = Path(path).resolve()
    return buffers[key] if key in buffers else read_bytes(path)
def source_code(owner, name):
    path = Path(owner.path).resolve()
    if path in buffers:
        data = buffers[path]
        executed.append({'Name': name, 'Path': str(path), 'Sha256': hashlib.sha256(data).hexdigest().upper()})
        return compile(data, str(path), 'exec')
    if any(path.is_relative_to(Path(root)) for root in model['ClosedRoots']):
        raise RuntimeError('replay import outside authenticated source closure')
    return get_code(owner, name)
sys.dont_write_bytecode = True
sys.argv = [entry, *arguments]
exit_code = 1
try:
    with patch('importlib.util.spec_from_file_location', side_effect=source_spec), patch.object(Path, 'read_bytes', source_read), patch.object(importlib.machinery.SourceFileLoader, 'get_code', source_code):
        graph.load('__main__', Path(entry))
    exit_code = 0
except SystemExit as error:
    exit_code = error.code if type(error.code) is int else 0 if error.code is None else 1
    raise
finally:
    record = {'SourceSnapshotSha256': expected, 'Entry': entry, 'ExitCode': exit_code,
              'Executed': executed + graph.executed}
    Path(trace).write_bytes((json.dumps(record, indent=2, sort_keys=True, allow_nan=False) + '\n').encode('ascii'))
'''


class Dispatcher:
    def __init__(self, output, watch, admission, current, entries, environment, interpreter, runner, catalog_path):
        self.output, self.watch, self.admission = output, watch, admission
        self.current, self.entries = current, entries
        self.environment, self.interpreter, self.runner = environment, interpreter, runner
        self.catalog_path = catalog_path
        self.environment['PATH'] = str(interpreter.parent)
        self.report, self.commands, self.expected, self.output_identities = scope_report(), [], {}, {}
        self._completed, self._started = False, False
        self.report['RequiredCellCount'] = current['Required']['RequiredCellCount']
        self.report['CurrentInventory'] = dict(current['Bundle']['Descriptor'], SourceInventorySha256=current['SourceInventorySha256'])
        self.report['Catalog'] = dict(Path=str(catalog_path), Sha256=watch.hashes[catalog_path])
        self.report['Interpreter'] = dict(ModulePath=str(interpreter), Sha256=watch.hashes[interpreter], Version=sys.version)
        self.report['SourcePins'] = dict(SOURCE_PINS)

    def _write(self, name, data):
        name = relative_name(name)
        path = self.output / name
        checked_path(path, fresh=not path.exists())
        path.parent.mkdir(parents=True, exist_ok=True)
        checked_path(path.parent, directory=True)
        path.write_bytes(data)
        need(path.read_bytes() == data, 'written intended output bytes: ' + name)
        info = path.stat()
        self.output_identities[name] = (info.st_dev, info.st_ino, info.st_nlink, info.st_size)
        self.expected[name] = sha(data)
        return path

    def _json(self, name, value):
        return self._write(name, encoded(value))

    def _snapshot_sources(self):
        sources = {}
        for original, data in sorted(self.watch.buffers.items()):
            value = sha(data)
            name = 'source-bytes/' + value + '.py'
            if name not in self.expected:
                self._write(name, data)
            sources[str(original)] = dict(Captured=str(self.output / name), Sha256=value)
        self.sources = sources
        model = dict(Loader=str(ROOT / LOADER), Sources=sources,
                     ClosedRoots=[str(ROOT), *(str(root) for root in self.admission.bundles)])
        self.source_snapshot = self._json('source-snapshot.json', model)
        self.source_snapshot_sha = self.expected['source-snapshot.json']

    def command(self, argv, label, timeout=1200):
        need(type(argv) is list and all(type(item) is str for item in argv)
             and argv[:6] == [str(self.interpreter), '-I', '-S', '-B', '-c', BOOTSTRAP], 'only fixed Python proof bootstrap permitted')
        need(type(label) is str and label in routes() and type(timeout) is int and 0 < timeout <= 1200,
             'bounded closed-route command')
        ordinal = len(self.commands)
        prefix = 'commands/%02d' % ordinal
        row = dict(Label=label, Argv=list(argv), Cwd=str(self.output), State='ATTEMPT', TimeoutSeconds=timeout,
                   RunnerSha256=SOURCE_PINS[RUNNER], EnvironmentSha256=sha(encoded(self.environment)))
        self.commands.append(row)
        self.report['ProofGateInvocations'] = len(self.commands)
        self._json(prefix + '.json', row)
        self._json('commands.json', self.commands)
        result, stdout, stderr = None, b'', b''
        try:
            result = self.runner.run(argv, cwd=str(self.output), env=dict(self.environment), timeout=timeout)
            stdout, stderr = result.stdout, result.stderr
            need(type(stdout) is bytes and type(stderr) is bytes and type(result.returncode) is int
                 and type(result.timed_out) is bool, 'managed byte result')
            row.update(ReturnCode=result.returncode, TimedOut=result.timed_out, ElapsedSeconds=result.elapsed,
                Cleanup=('FAILED_OR_UNCONFIRMED' if result.returncode == 125 or b'[process-runner]' in stderr
                         else 'MANAGED_RUNNER_RETURNED'))
            return result
        except BaseException as error:
            row.update(Error=type(error).__name__ + ': ' + str(error), Cleanup='FAILED_OR_UNCONFIRMED')
            raise
        finally:
            row['State'] = 'TERMINAL'
            row['StdoutSha256'], row['StderrSha256'] = sha(stdout), sha(stderr)
            row['Stdout'], row['Stderr'] = prefix + '.stdout', prefix + '.stderr'
            self._write(prefix + '.stdout', stdout)
            self._write(prefix + '.stderr', stderr)
            self._json(prefix + '.json', row)
            self._json('commands.json', self.commands)

    def _trace(self, name, entry):
        path = checked_path(self.output / name)
        data = path.read_bytes()
        record = structured(data)
        same(record.get('SourceSnapshotSha256'), self.source_snapshot_sha, 'executed source snapshot identity')
        same(record.get('Entry'), str(entry), 'executed gate entry')
        _integer(record.get('ExitCode'), 0, 'gate bootstrap normal completion')
        rows = record.get('Executed')
        need(type(rows) is list and rows, 'executed immutable helper buffers')
        for row in rows:
            need(type(row) is dict and row.get('Path') in self.sources, 'executed helper must belong to immutable closure')
            same(row['Sha256'], self.sources[row['Path']]['Sha256'], 'executed helper source hash')
        need(any(Path(row['Path']) == entry for row in rows), 'actual gate entry execution recorded')
        need(path.read_bytes() == data, 'execution trace drift')
        self.expected[name] = sha(data)
        info = path.stat()
        self.output_identities[name] = (info.st_dev, info.st_ino, info.st_nlink, info.st_size)

    def _gate(self, entry):
        selection, route = entry['Selection'], entry['Route']
        route_id = selection['Route']
        name = route_id.replace('/', '-')
        child = checked_path(self.output / 'replays' / name, fresh=True)
        trace = 'execution/' + name + '.json'
        (self.output / 'execution').mkdir(exist_ok=True)
        gate = ROOT / route['Gate']
        argv = [str(self.interpreter), '-I', '-S', '-B', '-c', BOOTSTRAP, str(self.source_snapshot),
                self.source_snapshot_sha, str(gate), str(self.output / trace), *gate_arguments(route_id, selection, child)]
        self._verify_own_files()
        result = self.command(argv, route_id)
        self.report['ProofGateInvocations'] = len(self.commands)
        if result.timed_out or result.returncode != 0 or b'[process-runner]' in result.stderr:
            failed = dict(Route=route_id, ReturnCode=result.returncode, TimedOut=result.timed_out,
                          ChildReportAuthenticated=False)
            try:
                path = checked_path(child / 'results.json')
                data = path.read_bytes()
                failed.update(Report=str(path), ReportSha256=sha(data), ChildError=structured(data).get('Error'))
            except Exception as error:
                failed['ChildReportReadError'] = type(error).__name__ + ': ' + str(error)
            self.report['FailedGate'] = failed
            raise Rejected('freeze-replay: proof gate command failed/timeout/cleanup: ' + route_id
                           + ('; child: ' + str(failed['ChildError']) if failed.get('ChildError') else ''))
        self._trace(trace, gate)
        raw = checked_path(child / 'results.json').read_bytes()
        raw_manifest = checked_path(child / 'artifacts.json').read_bytes()
        fresh_descriptor = dict(Build=str(child), ReceiptSha256=sha(raw), ArtifactsSha256=sha(raw_manifest))
        fresh = self.admission.bundle(fresh_descriptor)
        same(fresh['Result'], structured(raw), 'fresh report read/parsed buffer identity')
        evidence = report_evidence(route_id, fresh['Result'])
        require_bindings(fresh['Result'], selection)
        fresh_inventory_facts = self.admission.require_inventory_binding(fresh, entry['Snapshot'], required=False)
        same(evidence, entry['Evidence'], 'fresh replay must reproduce authenticated prior root/protocol/twin evidence')
        for relative, value in dict(fresh['Artifacts'], **{'artifacts.json': fresh_descriptor['ArtifactsSha256']}).items():
            name = child.relative_to(self.output).as_posix() + '/' + relative
            self.expected[name] = value
            self.output_identities[name] = self.watch.identities[child / relative]
        self._verify_own_files()
        source_sha = entry['Snapshot']['SourceInventorySha256']
        current_sha = self.current['SourceInventorySha256']
        component = dict(Id=route_id, Route=route_id, Status='VERIFIED_COMPONENTS_ONLY',
            Scope=fresh['Result']['Scope'], HistoricalInventory=selection['Inventory'],
            SourceInventorySha256=source_sha, CurrentSourceInventorySha256=current_sha,
            CurrentSnapshotEligible=source_sha == current_sha,
            Replay=fresh_descriptor, PriorJoin=selection['PriorJoin'], ClosedBodies=evidence['ClosedBodies'],
            ReachableInventoryFacts=copy.deepcopy(entry['InventoryFacts']),
            FreshInventoryFacts=fresh_inventory_facts,
            Components=['final-root-transport', 'canonical-mechanisms', 'within-side-twins'],
            NegativeControls=evidence['NegativeControls'], EvidenceSha256=sha(encoded(evidence)),
            RequiredCellSatisfied=False, RequiredCellsSatisfied=0, FullABIProof=False, APIProof=False,
            GlobalFreezeQualified=False)
        self.report['Components'].append(component)
        self.report['Selections'].append(dict(Route=route_id, Status='REPLAYED_COMPONENTS_ONLY',
            SourceInventorySha256=source_sha, CurrentSnapshotEligible=source_sha == current_sha, Replay=fresh_descriptor))

    def _coverage(self):
        required, rows, missing = self.current['Required'], [], []
        by_key = {_selection_key(route_for(row['Route'])): row for row in self.report['Components']}
        for cell in required['RequiredCells']:
            record = copy.deepcopy(cell)
            component = by_key.get(_cell_key(cell))
            current = [component['Id']] if component and component['CurrentSnapshotEligible'] else []
            historical = [component['Id']] if component and not component['CurrentSnapshotEligible'] else []
            obligations = required['PlannedProofRequirements'][cell['ArtifactRole']]
            record.update(Status='PENDING', VerifiedComponentReferences=current, HistoricalComponentReferences=historical,
                RequiredCellSatisfied=False, RequiredCellsSatisfied=0, MissingWholeCellRequirements=list(obligations))
            rows.append(record)
            missing.append(dict(Key=list(_cell_key(cell)), MissingWholeCellRequirements=list(obligations),
                                Reason='PARTIAL_COMPONENTS_ARE_NOT_WHOLE_CELL_PROOF' if component else 'NO_VERIFIED_COMPONENT_IN_THIS_RUN',
                                RouteAvailable=any(_selection_key(route) == _cell_key(cell) for route in routes().values())))
        same([_cell_key(row) for row in rows], [_cell_key(row) for row in required['RequiredCells']], 'all canonical keys retained in order')
        self._json('coverage.json', dict(SourceInventorySha256=self.current['SourceInventorySha256'], Cells=rows,
                                       GlobalFreezeQualified=False, RequiredCellsSatisfied=0))
        self._json('missing-work.json', dict(Cells=missing, Backlog=self.current['Manifest']['scope_backlog'],
                                           RequiredCellsSatisfied=0, GlobalFreezeQualified=False))

    def _verify_own_files(self):
        actual = files_under(self.output)
        same(sorted(actual), sorted(self.expected), 'exact dispatcher/child output membership')
        identities = set()
        for name, value in self.expected.items():
            info = actual[name].stat()
            identity = (info.st_dev, info.st_ino, info.st_nlink, info.st_size)
            need(identity == self.output_identities[name] and info.st_nlink == 1 and identity[:2] not in identities,
                 'output physical alias/identity drift: ' + name)
            identities.add(identity[:2])
            need(sha(actual[name].read_bytes()) == value, 'dispatcher output changed: ' + name)

    def _fail(self, error):
        message = type(error).__name__ + ': ' + str(error)
        if self.report.get('Error') is None:
            self.report.update(Error=message, PrimaryError=message)
        elif message != self.report['Error']:
            self.report.setdefault('ClosingErrors', []).append(message)
        self.report.update(Status='FAIL', ComponentsUsable=False, InputClosureVerified=False, OutputSealVerified=False)

    def finish(self, error=None):
        if error is None and not (getattr(self, '_completed', False) and self.commands
                                 and len(self.commands) == len(self.entries)
                                 and len(self.report['Components']) == len(self.entries)):
            error = Rejected('freeze-replay: uncompleted/empty dispatcher cannot PASS')
        if error is not None:
            self._fail(error)
        if not getattr(self, '_started', False):
            return False
        try:
            need(self._started and self.output.is_dir(), 'dispatcher was not started')
            self.watch.close()
            self._verify_own_files()
            self.report['ClosingFilesVerified'] = len(self.watch.hashes)
            self.report['InputHashes'] = {str(path): value for path, value in sorted(self.watch.hashes.items())}
            self.report['InputPhysicalIdentities'] = {str(path): list(value) for path, value in sorted(self.watch.identities.items())}
            self.report['InputClosureVerified'] = error is None
            self.report['ComponentsUsable'] = error is None
            self.report['Status'] = 'PASS' if error is None else 'FAIL'
            self.report['OutputSealVerified'] = True
            self._json('results.json', self.report)
            manifest = {name: value for name, value in self.expected.items() if name != 'artifacts.json'}
            self._json('artifacts.json', dict(Artifacts=manifest))
            self.watch.close()
            self._verify_own_files()
            return error is None
        except BaseException as failure:
            self._fail(failure)
            try:
                # Failure recovery describes readable retained bytes; it cannot
                # turn failed proof/closing into usable components or PASS.
                self._json('results.json', self.report)
                actual = files_under(self.output)
                failure_manifest = {name: sha(path.read_bytes()) for name, path in actual.items() if name != 'artifacts.json'}
                self._write('artifacts.json', encoded(dict(Artifacts=failure_manifest)))
            except BaseException:
                pass
            return False

    def run(self):
        need(not self._started, 'one-shot dispatcher cannot overwrite a completed attempt')
        error = None
        try:
            checked_path(self.output, fresh=True)
            self.watch.close()
            self.output.mkdir(parents=True)
            self._started = True
            self._json('results.json', self.report)
            self._json('catalog.json', structured(self.watch.read(self.catalog_path)))
            self._json('required-cells.json', self.current['Required'])
            self._json('backlog.json', self.current['Manifest']['scope_backlog'])
            self._json('environment.json', self.environment)
            self._json('commands.json', self.commands)
            self._snapshot_sources()
            for entry in self.entries:
                self._gate(entry)
            self._coverage()
            self._completed = True
        except BaseException as failure:
            error = failure
        return self.finish(error)


def main(argv=None):
    need(not sys.flags.optimize, 'unoptimized interpreter required')
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in ('inventory', 'inventory-receipt-sha256', 'inventory-artifacts-sha256',
                 'catalog', 'catalog-sha256', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    dispatcher = prepare(args)
    passed = dispatcher.run()
    print(dispatcher.report['Status'], dispatcher.report.get('Error') or '', str(dispatcher.output))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
