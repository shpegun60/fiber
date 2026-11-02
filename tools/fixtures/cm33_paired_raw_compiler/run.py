"""Bounded actual-source paired CM33 raw compiler regression controls."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from types import SimpleNamespace

OPT_ERROR = 'REJECT:PYTHON:optimization is unsupported'
if sys.flags.optimize or not __debug__:
    raise SystemExit(OPT_ERROR)

HERE = Path(__file__).resolve().parent
PREFIX = 'fiber_secure_context_cohort_c33s_g1'
HISTORICAL = 'b181ee7'
ROOT = Path('fiber/port/ARM_CM33')
NS = ROOT / 'non_secure'
SEC = ROOT / 'secure'
QUERIES = (
    'fiber_secure_gateway_v1_abi_version',
    'fiber_secure_gateway_v1_context_port_id',
    'fiber_secure_gateway_v1_context_layout_version',
    'fiber_secure_gateway_v1_context_feature_mask',
    'fiber_secure_context_gateway_v1_abi_version',
    'fiber_secure_context_gateway_v1_stack_alignment',
    'fiber_secure_context_gateway_v1_max_stack_bytes',
    'fiber_secure_context_gateway_v1_max_contexts',
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n', encoding='ascii')


def replace_once(path, old, new):
    text = path.read_text(encoding='ascii')
    require(text.count(old) == 1, 'Mutation anchor changed: ' + str(path))
    path.write_text(text.replace(old, new), encoding='ascii')


class Proof:
    def __init__(self, args):
        self.a = args
        self.repo = Path(args.repo).resolve()
        self.build = Path(args.build).resolve()
        self.commands, self.checks, self.inputs = [], [], []
        self.raw = self.build / 'closure'

    def command(self, command, label, allow=False):
        command = [str(v) for v in command]
        r = subprocess.run(command, capture_output=True, text=True, errors='replace',
                           cwd=self.build, timeout=120)
        row = dict(Label=label, Command=command, ExitCode=r.returncode,
                   Stdout=r.stdout, Stderr=r.stderr)
        write(self.build / ('command-%03d.json' % len(self.commands)), row)
        self.commands.append(row)
        require(allow or r.returncode == 0, label + ': ' + r.stderr[-3000:])
        return r

    def check(self, name, condition, **evidence):
        require(condition, name)
        self.checks.append(dict(Name=name, **evidence))

    def own_inputs(self):
        directory = self.build / 'owned-inputs'
        directory.mkdir()
        sources = [self.repo / 'tools/test_cm33_paired_raw_compiler.ps1',
                   *sorted(HERE.glob('*'))]
        for n, path in enumerate(sources):
            if not path.is_file():
                continue
            before = digest(path)
            copy = directory / ('%03d-' % n + path.name)
            shutil.copyfile(path, copy)
            require(digest(copy) == before, 'Owned input changed during capture')
            self.inputs.append(dict(Path=str(path), Copy=str(copy), Sha256=before))

    def guard_controls(self):
        path = Path(__file__).resolve()
        for label, argv in [
            ('direct-O', ['-O', path]), ('direct-OO', ['-OO', path]),
            *[('compiled-'+str(level), ['-c',
               "from pathlib import Path; p=%r; exec(compile(Path(p).read_text(),p,'exec',optimize=%d),"
               "{'__name__':'compiled_import'})" % (str(path), level)]) for level in (1, 2)],
        ]:
            r = self.command([sys.executable, '-B', *argv], label, allow=True)
            self.check('exact Python guard '+label, r.returncode == 1 and r.stdout == '' and
                       r.stderr.splitlines() == [OPT_ERROR])
        r = self.command([sys.executable,'-B','-c','raise RuntimeError(%r)' % OPT_ERROR],
                         'counterfeit diagnostic', allow=True)
        self.check('counterfeit traceback rejected', not (r.returncode == 1 and r.stdout == '' and
                   r.stderr.splitlines() == [OPT_ERROR]))

    def load_shared(self):
        self.copy = self.raw / 'immutable-inputs/repo'
        path = self.copy / 'tools/fixtures/sensitive_port_closure/run.py'
        spec = importlib.util.spec_from_file_location('c33_raw_shared', path)
        self.lib = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.lib)
        self.profiles = {p['name']: dict(p, vtor=1) for p in self.lib.profiles()
                         if p['name'] in ('C33S', 'C33S_GATEWAY')}
        require(len(self.profiles) == 2, 'Exact paired profile inventory')

    def audit(self, name, repo=None):
        directory = self.build / 'controls' / name
        directory.mkdir(parents=True)
        root = directory / 'repo'
        shutil.copytree(repo or self.copy, root)
        args = SimpleNamespace(repo=str(root), build=str(directory),
            arm_gcc=self.a.arm_gcc, cmsis_core=str(self.raw/'immutable-inputs/cmsis'),
            cm7_prefix_root=None)
        return self.lib.Audit(args)

    def compile_group(self, audit, profile, opt, lto, source=None):
        p = self.profiles[profile]
        flags = audit.flags(p, opt, lto, 'raw')
        sources, _ = audit.source_paths(p)
        if source:
            sources = [audit.repo / source]
        objects = [audit.compile(s, audit.build/(s.stem+'.o'), flags) for s in sources]
        target = audit.build / 'native.o'
        dis = audit.lower(p, objects, target, flags, lto, 'unsectioned' if lto else 'sectioned')
        return target, dis

    def expected_literal_failure(self, audit, profile, opt):
        try:
            self.compile_group(audit, profile, opt, True)
        except RuntimeError:
            evidence = audit.literal_range_failure(audit.build/'native.o')
            self.check(audit.build.name, all(PREFIX in row['instruction']
                       for row in evidence['diagnostics']), **evidence)
        else:
            raise RuntimeError('Literal-range control unexpectedly lowered')

    def historical(self):
        commit = self.command(['git', '-C', self.repo, 'rev-parse', HISTORICAL+'^{commit}'],
                              'resolve historical source').stdout.strip()
        require(re.fullmatch(r'[0-9a-f]{40}', commit) and commit.startswith(HISTORICAL),
                'Historical commit identity')
        audit = self.audit('historical-source')
        rows = []
        for path in sorted((self.copy/ROOT).rglob('*')):
            if path.is_file() and path.suffix in ('.c', '.h'):
                relative = path.relative_to(self.copy)
                r = self.command(['git','-C',self.repo,'show',commit+':'+relative.as_posix()],
                                 'historical '+relative.as_posix())
                target = audit.repo/relative
                target.write_text(r.stdout, encoding='ascii')
                rows.append(dict(Path=str(target), Sha256=digest(target)))
        write(audit.build/'historical-sources.json',dict(Commit=commit, Files=rows,
            SharedContracts='Captured current shared contracts, not a historical repository claim'))
        self.historical_repo = audit.repo
        ns = self.audit('historical-ns-o0', self.historical_repo)
        try:
            self.compile_group(ns, 'C33S', 'O0', False, NS/'fiber_port.c')
        except RuntimeError:
            diagnostic = ns.commands[-1]['stderr']
            errors = [line for line in diagnostic.splitlines() if ': error:' in line]
            self.check('historical NS actual raw inline mismatch', errors and
                all('inlining failed in call to' in line and 'function not considered for inlining' in line
                    for line in errors) and all(name in diagnostic for name in (
                    'fiber_port_initial_xpsr', 'fiber_port_stacked_pc', 'fiber_port_read_r9')),
                Diagnostics=errors)
        else:
            raise RuntimeError('Historical NS raw failure not reproduced')
        sec = self.audit('historical-secure-o2', self.historical_repo)
        self.expected_literal_failure(sec, 'C33S_GATEWAY', 'O2')

    def hooked_mutant(self, name, path, edits, root):
        audit = self.audit(name)
        for relative, old, new in edits:
            replace_once(audit.repo/relative, old, new)
        profile = 'C33S_GATEWAY' if path.is_relative_to(SEC) else 'C33S'
        target, dis = self.compile_group(audit, profile, 'O2', False, path)
        result = self.lib.inspect(target, dis, None if root is None else {root}, True)
        write(audit.build/'classification.json', result)
        hooks = [d for d in result['defects'] if d['kind'] == 'function-hook' and d['family'] == 'instrument']
        self.check(name, bool(hooks), ClassifiedHooks=hooks)

    def mutants(self):
        self.hooked_mutant('ns-inline-bundle-removal', NS/'fiber_port.c', [
            (NS/'fiber_portmacro.h', 'FIBER_API_ATTR_INLINE_SENSITIVE FIBER_GENERAL_REGS_ONLY',
             'FIBER_GENERAL_REGS_ONLY')], None)
        self.hooked_mutant('ns-hash-helper-bundle-removal', NS/'fiber_port_boot.c', [
            (NS/'fiber_port_boot.c',
             'static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY\nuint32_t fiber_port_hash32_accum',
             'static FIBER_GENERAL_REGS_ONLY\nuint32_t fiber_port_hash32_accum')],
            'fiber_port_boot_record_compute_hash')
        self.hooked_mutant('secure-inline-bundle-removal', SEC/'fiber_secure_context_gateway.c', [
            (SEC/'fiber_secure_context_gateway.c',
             'FIBER_API_ATTR_INLINE_SENSITIVE FIBER_GENERAL_REGS_ONLY\nuint32_t fiber_secure_context_cpu_ipsr',
             'FIBER_GENERAL_REGS_ONLY\nuint32_t fiber_secure_context_cpu_ipsr')], None)
        # Revert one admission site only; do not neutralize any caller check.
        self.hooked_mutant('secure-cmsis-caller-wrapper', SEC/'fiber_secure_context_gateway.c', [
            (SEC/'fiber_secure_context_gateway.c',
             'if ((__builtin_arm_cmse_nonsecure_caller() == 0) || (fiber_secure_context_cpu_ipsr() !=\n'
             '\t\t\tFIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_SVC_EXCEPTION_NUMBER)',
             'if ((cmse_nonsecure_caller() == 0) || (fiber_secure_context_cpu_ipsr() !=\n'
             '\t\t\tFIBER_ARM_CM33_SECURE_CONTEXT_GATEWAY_SVC_EXCEPTION_NUMBER)')], None)

    def pressure(self):
        address = ('"movw %[cohort_byte], #:lower16:" FIBER_C33S_PRIVATE_COHORT_KEY "\\n\\t" \\\n'
                   '\t\t"movt %[cohort_byte], #:upper16:" FIBER_C33S_PRIVATE_COHORT_KEY "\\n\\t"')
        old = '"ldr %[cohort_byte], =" FIBER_C33S_PRIVATE_COHORT_KEY "\\n\\t"'
        for opt in ('O2', 'Os'):
            good = self.audit('pressure-retained-'+opt)
            for query in QUERIES:
                name = ('fiber_secure_gateway.c' if query.startswith('fiber_secure_gateway_')
                        else 'fiber_secure_context_gateway.c')
                source = good.repo/SEC/name
                text = source.read_text(encoding='ascii')
                pattern = r'(\buint32_t '+re.escape(query)+r'\(void\)\s*\{\s*FIBER_C33S_PRIVATE_COHORT_RETAIN\(\);)'
                matches = list(re.finditer(pattern, text))
                require(len(matches) == 1, 'Pressure query anchor '+query)
                match = matches[0]
                padding = '\n\t__asm volatile("b 991f\\n\\t.space 8192\\n\\t991:" ::: "memory");'
                source.write_text(text[:match.end()]+padding+text[match.end():], encoding='ascii')
            target, _ = self.compile_group(good, 'C33S_GATEWAY', opt, True)
            self.check('range-independent positive '+opt, target.is_file(), NativeSha256=digest(target))
            bad = self.audit('pressure-removed-'+opt, good.repo)
            replace_once(bad.repo/SEC/'fiber_secure_context_cohort.h', address, old)
            self.expected_literal_failure(bad, 'C33S_GATEWAY', opt)

    def exact_queries(self):
        for opt in ('O2', 'Os'):
            audit = self.audit('exact-query-'+opt)
            flags = audit.flags(self.profiles['C33S_GATEWAY'], opt, False, 'raw')
            objects = {}
            for name in ('fiber_secure_gateway', 'fiber_secure_context_gateway'):
                objects[name] = self.lib.Elf(audit.compile(audit.repo/SEC/(name+'.c'),
                                            audit.build/(name+'.o'), flags))
            for query in QUERIES:
                name = 'fiber_secure_gateway' if query.startswith('fiber_secure_gateway_') else 'fiber_secure_context_gateway'
                obj = objects[name]
                fn = [f for f in obj.functions if f['name'] == query]
                require(len(fn) == 1, 'Exact query function '+query)
                rels = [r for r in obj.relocations if r['section'] == fn[0]['section']]
                pairs = sorted((r['type'],r['symbol']['name']) for r in rels)
                keys = {n for _,n in pairs if n.startswith(PREFIX)}
                self.check(query+'/'+opt, len(keys) == 1 and pairs == sorted([
                    (10, 'fiber_secure_context_pool_c33s_v1_cohort_provider'),
                    (47, next(iter(keys))), (48, next(iter(keys)))]), Relocations=pairs)

    def ordinary_unsectioned(self):
        audit = self.audit('ordinary-unsectioned')
        original_flags = audit.flags

        def flags(profile, opt, lto, bundle):
            require(not lto, 'Ordinary-unsectioned control cannot lower LTO')
            return [v for v in original_flags(profile, opt, lto, bundle)
                    if v != '-ffunction-sections'] + ['-fno-function-sections']

        audit.flags = flags
        for profile in self.profiles.values():
            for opt in ('O0', 'Og', 'O2', 'Os', 'O3'):
                for bundle in ('baseline', 'raw'):
                    audit.case(profile, opt, False, bundle, 'unsectioned')
        drift = [p for p, value in audit.inputs.items() if digest(p) != value]
        self.check('20 ordinary unsectioned cells', len(audit.cases) == 20 and
                   not drift and all(row['status'] == 'PASS' for row in audit.cases))
        path = audit.build/'results.json'
        write(path,dict(Status='PASS', Scope='Ordinary native unsectioned text; data sections retained',
            Cases=audit.cases,Controls=audit.controls,InputDrift=drift,
            Inputs=[dict(Path=p,Sha256=value) for p,value in sorted(audit.inputs.items())]))
        self.ordinary = dict(Receipt=str(path),Sha256=digest(path),
                             Cells=len(audit.cases),Controls=len(audit.controls))

    def transfers(self):
        def section(elf, name):
            functions = [f for f in elf.functions if f['name'] == name]
            require(len(functions) == 1, 'Exact naked function '+name)
            index = functions[0]['section']
            return (elf.payload(elf.sections[index]).hex(), sorted((r['offset'],r['type'],r['symbol']['name'])
                    for r in elf.relocations if r['section'] == index))
        for opt in ('O2', 'Os'):
            images = []
            for label, repo in (('before',self.historical_repo),('after',self.copy)):
                audit = self.audit('transfer-'+opt+'-'+label, repo)
                flags = audit.flags(self.profiles['C33S'], opt, False, 'baseline')
                obj = audit.compile(audit.repo/NS/'fiber_port_svc.c', audit.build/'handlers.o', flags)
                dis = audit.run([audit.tools['objdump'],'-drwC',obj], 'naked transfer bytes/relocations')
                obj.with_suffix('.dis').write_text(dis,encoding='ascii')
                images.append(self.lib.Elf(obj))
                source = audit.repo/NS/'fiber_port.c'
                macros = audit.run([audit.gcc,*flags,'-E','-dM',source], 'exact selected-port macros')
                selected = sorted(line for line in macros.splitlines()
                    if re.match(r'#define (?:FIBER_PORT_|fiber_port)',line)
                    and not line.startswith('#define fiber_portFORCE_INLINE '))
                (audit.build/'selected-macros.json').write_text(json.dumps(selected,indent=2)+'\n',encoding='ascii')
                if label == 'before':
                    before_macros = selected
                else:
                    self.check('frozen selected-port macros '+opt, selected == before_macros)
            for name in ('fiber_port_start_first_context','SVC_Handler','PendSV_Handler'):
                pre, post = (section(elf,name) for elf in images)
                self.check('unchanged naked '+name+'/'+opt, pre == post,
                           Bytes=len(bytes.fromhex(post[0])), Relocations=post[1],
                           Sha256=hashlib.sha256(bytes.fromhex(post[0])).hexdigest().upper())

    def run(self):
        self.own_inputs()
        self.guard_controls()
        self.raw.mkdir()
        script = self.repo/'tools/fixtures/sensitive_port_closure/run.py'
        command = [sys.executable,'-B',script,'--repo',self.repo,'--arm-gcc',self.a.arm_gcc,
                   '--cmsis-core',self.a.cmsis_core,'--build',self.raw,'--profiles','C33S,C33S_GATEWAY',
                   '--optimizations','O0,Og,O2,Os,O3','--bundles','baseline,raw',
                   '--native-lto-sections','sectioned,unsectioned','--immutable-inputs']
        write(self.build/'closure-command.json',[str(v) for v in command])
        require(subprocess.run([str(v) for v in command]).returncode == 0, 'Shared raw closure did not pass')
        result = json.loads((self.raw/'results.json').read_text())
        self.check('complete 60-cell raw closure', result['Status'] == 'PASS' and
            result['CompleteSuite'] and not result['AuditOnly'] and not result['Errors'] and
            not result['InputDrift'] and result['CellCounts'] == dict(
                planned=60,attempted=60,completed=60,passed=60,failed=0,unqualified=0))
        self.load_shared()
        self.ordinary_unsectioned()
        self.historical()
        self.mutants()
        self.pressure()
        self.exact_queries()
        self.transfers()
        for row in self.inputs:
            require(digest(row['Path']) == row['Sha256'] == digest(row['Copy']), 'Owned input drift')
        manifest = json.loads((self.raw/'immutable-inputs/manifest.json').read_text())
        require(all(digest(r['copy']) == r['sha256'] for r in manifest['files']), 'Immutable input drift')
        write(self.build/'results.json', dict(Status='PASS', CompleteSuite=True,
            Scope='Paired CM33 raw compiler closure; no runtime, architecture execution or profile activation claim',
            ClosureReceipt=str(self.raw/'results.json'), ClosureSha256=digest(self.raw/'results.json'),
            OrdinaryUnsectioned=self.ordinary,
            Checks=self.checks, Inputs=self.inputs, PreRepairCommit=HISTORICAL,
            SourceSnapshot=str(self.raw/'immutable-inputs/manifest.json'),
            SourceSnapshotSha256=digest(self.raw/'immutable-inputs/manifest.json')))
        artifacts = [dict(Path=str(p),Sha256=digest(p)) for p in sorted(self.build.rglob('*'))
                     if p.is_file() and p.name != 'artifacts.json']
        write(self.build/'artifacts.json',dict(Status='PASS', Artifacts=artifacts))
        print('PASS C33 paired raw: 80 cells, %d controls, %d scoped checks; %s' %
              (len(result['Controls'])+self.ordinary['Controls'],len(self.checks),self.build),flush=True)


def main():
    parser = argparse.ArgumentParser()
    for option in ('repo','arm-gcc','cmsis-core','build'):
        parser.add_argument('--'+option,required=True)
    args = parser.parse_args()
    proof = Proof(args)
    try:
        proof.run()
    except Exception as e:
        write(proof.build/'results.json',dict(Status='FAIL',CompleteSuite=False,
            Error=str(e),Checks=proof.checks,Inputs=proof.inputs))
        raise


if __name__ == '__main__':
    main()
