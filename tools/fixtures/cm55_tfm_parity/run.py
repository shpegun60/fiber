"""Actual-source M55_NTZ CPU and TF-M wrapper comparison (not a CPU emulator)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import re

if sys.flags.optimize or not __debug__:
    raise SystemExit("REJECT:PYTHON:optimization is unsupported")


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="ascii")


class Proof:
    POLICY_READERS = {'ipsr': 'IPSR', 'primask': 'PRIMASK', 'faultmask': 'FAULTMASK',
                      'control': 'CONTROL', 'psplim': 'PSPLIM'}
    POLICY_COUNTS = {'fiber_port_tfm.c': {'ipsr': 3, 'primask': 3, 'faultmask': 3, 'control': 3, 'psplim': 2},
                     'fiber_port_tfm_os_wrapper.c': {'ipsr': 1, 'primask': 2, 'faultmask': 1, 'control': 3}}

    def __init__(self, a):
        self.a = a
        self.repo, self.build = Path(a.repo).resolve(), Path(a.build).resolve()
        self.fixture = Path(__file__).resolve().parent
        self.port = self.repo / "fiber/port/ARM_CM55_TFM/non_secure"
        self.ref = Path(a.reference) / "portable/GCC/ARM_CM55_NTZ/non_secure"
        self.tfm = Path(a.reference) / "portable/ThirdParty/GCC/ARM_TFM"
        self.config = self.repo / "tools/fixtures/freertos_asm_parity"
        self.bin = Path(a.arm_gcc).parent
        self.tools = {n: self.bin / ("arm-none-eabi-" + n + ".exe") for n in ("objdump", "readelf")}
        self.commands, self.runs, self.mutants, self.controls = [], [], [], []
        self.dataflow_mutants = []
        self.common = ["-mcpu=cortex-m55", "-mthumb", "-mfloat-abi=soft", "-std=gnu11",
                       a.optimization, "-g0", "-ffreestanding", "-fno-builtin", "-fno-common",
                       "-ffunction-sections", "-fdata-sections", "-save-temps=obj", "-MMD"]
        self.fiber = self.common + ["-Wall", "-Wextra", "-Werror", "-Wundef",
            "-DFIBER_PORT_BUILD_SELECTED=1", "-DFIBER_PORT_ARMV81M_MAINLINE=1"] + [
            "-I" + str(p) for p in (self.build, self.port, self.repo / "fiber/port", self.repo / "fiber", self.repo, a.cmsis)]
        self.reference = self.common + ["-I" + str(p) for p in (
            self.config, Path(a.reference) / "include", self.ref, self.fixture)]

    def command(self, args, label, allow=False):
        args = list(map(str, args))
        p = subprocess.run(args, cwd=self.build, text=True, errors="replace",
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        row = dict(Command=args, Label=label, ExitCode=p.returncode, Output=p.stdout)
        write(self.build / ("command-%04d.json" % len(self.commands)), row)
        self.commands.append(row)
        require(allow or p.returncode == 0, label + " failed: " + p.stdout[-6000:])
        return row

    def compile(self, source, name, flags):
        obj = self.build / (name + ".o")
        self.command([self.a.arm_gcc, *flags, "-c", source, "-o", obj], "compile " + name)
        for tool, options, ext in (("objdump", ["-dr"], ".dis"),
                                   ("readelf", ["-A", "-h", "-S", "-s", "-r", "-W"], ".elf.txt")):
            row = self.command([self.tools[tool], *options, obj], tool + " " + name)
            Path(str(obj) + ext).write_text(row["Output"], encoding="ascii")
        return str(obj)

    def snapshot(self):
        expected_profile = {'fiber_port.c', 'fiber_portmacro.h', 'fiber_port_boot.c', 'fiber_port_boot.h',
            'fiber_port_boot_types.h', 'fiber_port_private.h', 'fiber_port_tfm.c', 'fiber_port_tfm_abi.h',
            'fiber_port_tfm_os_wrapper.c', 'fiber_port_tfm_os_wrapper.h', 'fiber_port_types.h', 'FREERTOS_PARITY.md'}
        actual_profile = {p.name for p in self.port.iterdir() if p.is_file() and p.suffix in ('.c', '.h', '.ld', '.md')}
        require(actual_profile == expected_profile, 'C5TF 12-file production inventory changed: ' + str(actual_profile ^ expected_profile))
        paths = {Path(__file__), self.fixture / "check.py", self.repo / "tools/freertos_asm_parity.ps1",
                 self.repo / "FREERTOS_ASM_PARITY.md", Path(self.a.arm_gcc), *self.tools.values()}
        for root in (self.fixture, self.port, self.repo / 'fiber/port/ARM_CM33_TFM/non_secure', self.repo, self.repo / "fiber", self.repo / "fiber/port",
                     self.ref, self.tfm, self.config, Path(self.a.reference) / "include", Path(self.a.cmsis)):
            paths.update(p for p in root.rglob("*") if root == self.fixture and p.is_file())
            paths.update(p for p in root.iterdir() if p.is_file() and p.suffix in (".c", ".h", ".ld", ".md")
                         and (root != self.repo or p.name in ("mcu_core.h", "basic_types.h", "FREERTOS_ASM_PARITY.md")))
        for tool in ("cc1", "as"):
            p = self.command([self.a.arm_gcc, "-print-prog-name=" + tool], "locate " + tool)["Output"].strip()
            paths.add(Path(p).resolve())
        include = self.command([self.a.arm_gcc, "-print-file-name=include"], "compiler headers")["Output"].strip()
        paths.update(p for p in Path(include).rglob("*.h"))
        paths.update(p for p in (self.bin.parent / "arm-none-eabi/include").rglob("*.h"))
        self.live = [dict(Path=str(p.resolve()), Sha256=digest(p)) for p in sorted(paths)]
        inputs = []
        docs = self.build / "documentation"
        docs.mkdir()
        for row in self.live:
            item = dict(row)
            if Path(row["Path"]).suffix == ".md":
                target = docs / ("%03d-" % len(inputs) + Path(row["Path"]).name)
                target.write_bytes(Path(row["Path"]).read_bytes())
                require(digest(target) == row["Sha256"], "documentation changed during snapshot")
                item.update(Path=str(target), SourcePath=row["Path"], Role="DocumentationSnapshot")
            inputs.append(item)
        self.inputs = inputs
        write(self.build / "inputs.before.json", inputs)
        write(self.build / 'production-profile.json', [r for r in inputs if Path(r.get('SourcePath', r['Path'])).parent == self.port])

    @classmethod
    def compare_policy_sources(cls, left_sources, right_sources):
        require(set(left_sources) == set(right_sources) == set(cls.POLICY_COUNTS),
                'A32 policy source-relation file inventory changed')
        dialects = set()
        for name, counts in cls.POLICY_COUNTS.items():
            left, right = left_sources[name], right_sources[name]
            if name == 'fiber_port_tfm.c':
                right = right.replace('/* ARM_CM55 TF-M Non-secure interface initialization. */',
                                      '/* ARM_CM33 TF-M Non-secure interface initialization. */')
                right = right.replace('fiber_port_arm_cm55_tfm_integration_bundle_v1_anchor',
                                      'fiber_port_arm_cm33_tfm_integration_bundle_v1_anchor')
            dialect = None
            for reader, count in counts.items():
                call = 'fiber_port_cpu_read_' + reader + '()'
                cmsis = '__get_' + cls.POLICY_READERS[reader] + '()'
                require(right.count(call) == count and right.count(cmsis) == 0,
                        'A32 C5TF reader count changed: ' + name + '/' + reader)
                raw_count, cmsis_count = left.count(call), left.count(cmsis)
                require((raw_count == count and cmsis_count == 0) or
                        (cmsis_count == count and raw_count == 0),
                        'A32 C3TF reader count changed: ' + name + '/' + reader)
                current = 'canonical' if raw_count else 'CMSIS'
                require(dialect is None or dialect == current, 'A32 C3TF reader dialect mixed: ' + name)
                dialect = current
                left = left.replace(call, cmsis)
                right = right.replace(call, cmsis)
            require(left == right, 'M33/C5TF wrapper policy source relation changed; review difference explicitly: ' + name)
            dialects.add(dialect)
        require(len(dialects) == 1, 'A32 C3TF policy reader dialects differ between files')
        return dialects.pop()

    def policy_source_controls(self, left_sources, right_sources):
        variants = {}
        for dialect in ('CMSIS', 'canonical'):
            sources = dict(left_sources)
            for name, counts in self.POLICY_COUNTS.items():
                for reader in counts:
                    call = 'fiber_port_cpu_read_' + reader + '()'
                    cmsis = '__get_' + self.POLICY_READERS[reader] + '()'
                    old, new = (call, cmsis) if dialect == 'CMSIS' else (cmsis, call)
                    sources[name] = sources[name].replace(old, new)
            variants[dialect] = sources
        records = []

        def check(label, left, right, expected=None):
            try:
                dialect = self.compare_policy_sources(left, right)
            except RuntimeError as error:
                require(expected is not None and str(error) == expected,
                        'Policy source control rejected for unintended reason: ' + label + '/' + str(error))
                records.append(dict(Name=label, Diagnostic=str(error)))
            else:
                require(expected is None, 'Policy source mismatch survived: ' + label)
                records.append(dict(Name=label, Dialect=dialect, Status='PASS'))
            self.controls.append('policy-source/' + label)

        for dialect, sources in variants.items():
            check(dialect + '/positive', sources, right_sources)
            for name, counts in self.POLICY_COUNTS.items():
                for reader in counts:
                    call = ('fiber_port_cpu_read_' + reader + '()' if dialect == 'canonical'
                            else '__get_' + self.POLICY_READERS[reader] + '()')
                    changed = dict(sources, **{name: sources[name].replace(call, '0u', 1)})
                    check(dialect + '/' + name + '/missing-' + reader, changed, right_sources,
                          'A32 C3TF reader count changed: ' + name + '/' + reader)
                prefix = 'fiber_port_cpu_read_' if dialect == 'canonical' else '__get_'
                ipsr = prefix + ('ipsr' if dialect == 'canonical' else 'IPSR') + '()'
                fault = prefix + ('faultmask' if dialect == 'canonical' else 'FAULTMASK') + '()'
                swapped = sources[name].replace(ipsr, '@IPSR@').replace(fault, ipsr).replace('@IPSR@', fault)
                body_error = 'M33/C5TF wrapper policy source relation changed; review difference explicitly: ' + name
                check(dialect + '/' + name + '/same-count-register-swap',
                      dict(sources, **{name: swapped}), right_sources, body_error)
                anchor = "== 0u, 'i')"
                require(sources[name].count(anchor) == 1, 'Policy numeric mutation anchor changed')
                numeric = sources[name].replace(anchor, "== 1u, 'i')")
                check(dialect + '/' + name + '/numeric-policy',
                      dict(sources, **{name: numeric}), right_sources, body_error)
                other_ipsr = '__get_IPSR()' if dialect == 'canonical' else 'fiber_port_cpu_read_ipsr()'
                mixed = sources[name].replace(ipsr, other_ipsr)
                check(dialect + '/' + name + '/mixed-readers',
                      dict(sources, **{name: mixed}), right_sources, 'A32 C3TF reader dialect mixed: ' + name)
            other = variants['canonical' if dialect == 'CMSIS' else 'CMSIS']
            changed = dict(sources, **{'fiber_port_tfm.c': other['fiber_port_tfm.c']})
            check(dialect + '/mixed-files', changed, right_sources,
                  'A32 C3TF policy reader dialects differ between files')
        for name, counts in self.POLICY_COUNTS.items():
            for reader in counts:
                call, cmsis = 'fiber_port_cpu_read_' + reader + '()', '__get_' + self.POLICY_READERS[reader] + '()'
                changed = dict(right_sources, **{name: right_sources[name].replace(call, cmsis, 1)})
                check('C5TF/' + name + '/noncanonical-' + reader, variants['canonical'], changed,
                      'A32 C5TF reader count changed: ' + name + '/' + reader)
        require(len(records) == 43, 'Policy source control inventory incomplete')
        write(self.build / 'wrapper-policy-controls.json', dict(Status='PASS', Controls=records,
              Scope='Source-relation controls, not compiled parity or CPU behavior'))

    def policy_source_relation(self):
        other = self.repo / 'fiber/port/ARM_CM33_TFM/non_secure'
        left = {name: (other / name).read_text(encoding='utf-8') for name in self.POLICY_COUNTS}
        right = {name: (self.port / name).read_text(encoding='utf-8') for name in self.POLICY_COUNTS}
        dialect = self.compare_policy_sources(left, right)
        self.policy_source_controls(left, right)
        write(self.build / 'wrapper-policy-source.json', dict(Status='PASS',
            Wrapper='C3TF complete CMSIS or canonical-reader dialect; C5TF canonical only; exact counts and body relation',
            Initializer='exact profile comment, integration-bundle symbol and the same count-checked reader dialect policy',
            C3tfReaderDialect=dialect, ReaderCounts=self.POLICY_COUNTS,
            CompiledSource='unaltered actual C5TF production; substitutions are source-relation checks only',
            CpuReference='actual ARM_CM55_NTZ, not M33 wrapper CPU code'))

    @staticmethod
    def exact_rejection(result, diagnostic):
        return result['ExitCode'] == 1 and result['Output'] in (diagnostic, diagnostic+'\n')

    def guard_controls(self, manifest):
        diagnostic = 'REJECT:PYTHON:optimization is unsupported'
        for module in ('run.py', 'check.py', 'elf.py', 'symbolic.py', 'oracles.py', 'policy.py', 'mutants.py'):
            path = self.fixture / module
            for flag in ('-O', '-OO'):
                r = self.command([sys.executable, '-B', flag, path], 'guard ' + module + flag, allow=True)
                require(self.exact_rejection(r, diagnostic), 'optimized invocation guard failed: ' + module)
                self.controls.append(module+flag)
            saved = os.environ.get('PYTHONOPTIMIZE')
            try:
                for level in ('1', '2'):
                    os.environ['PYTHONOPTIMIZE'] = level
                    r = self.command([sys.executable, '-B', path], 'environment guard ' + module + level, allow=True)
                    require(self.exact_rejection(r, diagnostic), 'environment guard failed: ' + module)
                    self.controls.append(module+'/PYTHONOPTIMIZE='+level)
            finally:
                if saved is None:
                    os.environ.pop('PYTHONOPTIMIZE', None)
                else:
                    os.environ['PYTHONOPTIMIZE'] = saved
            for level in (1, 2):
                code = "from pathlib import Path; import sys; p=sys.argv[1]; exec(compile(Path(p).read_text(),p,'exec',optimize=%d),{'__name__':'compiled_import'})" % level
                r = self.command([sys.executable, '-B', '-c', code, path], 'compiled import ' + module + str(level), allow=True)
                require(self.exact_rejection(r, diagnostic), 'compiled optimized import guard failed: ' + module)
                self.controls.append(module+'/compiled-import-'+str(level))
        for flag in ('-O', '-OO'):
            r = self.command([sys.executable, '-B', flag, self.fixture / 'check.py', '--r9-dataflow-only', manifest],
                             'optimized R9 dataflow mode', allow=True)
            require(self.exact_rejection(r, diagnostic), 'optimized R9 dataflow mode guard failed')
            self.controls.append('r9-dataflow-mode/'+flag)
        for message in (diagnostic, 'REJECT:BODY:counterfeit', 'REJECT:R9_CAPTURE:counterfeit'):
            r = self.command([sys.executable, '-B', '-c', 'raise RuntimeError('+repr(message)+')'], 'traceback counterfeit', allow=True)
            require(not self.exact_rejection(r, message) and not self.mutant_rejection(r) and not self.dataflow_rejection(r),
                    'traceback counterfeit accepted')
            self.controls.append('traceback-counterfeit/'+message)
        for module in ('run.py', 'check.py'):
            text = (self.fixture / module).read_text()
            old = 'raise SystemExit("'+diagnostic+'")'
            require(text.count(old) == 1, 'counterfeit guard anchor changed')
            path = self.build / ('counterfeit-'+module)
            path.write_text(text.replace(old, 'raise RuntimeError("'+diagnostic+'")'), encoding='ascii')
            r = self.command([sys.executable, '-B', '-O', path], 'actual SystemExit-to-RuntimeError counterfeit', allow=True)
            require(not self.exact_rejection(r, diagnostic), 'actual guard traceback counterfeit accepted')
            self.controls.append(module+'/actual-RuntimeError-counterfeit')

    @staticmethod
    def mutant_rejection(result):
        return result['ExitCode'] == 1 and re.fullmatch(r'REJECT:(?:BODY|DEPENDENCY|RELOC|INSTRUCTION|DECODE|INVENTORY):[^\r\n]+\n?', result['Output']) is not None

    @staticmethod
    def dataflow_rejection(result):
        return result['ExitCode'] == 1 and re.fullmatch(r'REJECT:(?:CONSTRUCTOR|R9_CAPTURE):[^\r\n]+\n?', result['Output']) is not None

    def dependency_closure(self):
        known = {str(Path(r['Path']).resolve()).casefold() for r in self.live}
        records = []
        for dep in self.build.glob('*.d'):
            text = dep.read_text().replace('\\\n', ' ')
            require(': ' in text, 'malformed dependency output: ' + str(dep))
            for token in re.findall(r'(?:\\ |[^\s])+', text.partition(': ')[2]):
                p = Path(token.replace('\\ ', ' ')).resolve()
                generated = p.is_relative_to(self.build)
                require(p.is_file() and (generated or str(p).casefold() in known), 'unhashed compile dependency: ' + str(p))
                records.append(dict(DependencyFile=str(dep), Path=str(p), Sha256=digest(p), Role='Artifact' if generated else 'Source'))
        write(self.build / 'dependencies.json', records)

    def run(self):
        self.snapshot()
        passed = False
        try:
            self.command([self.a.arm_gcc, "--version"], "compiler version")
            self.policy_source_relation()
            write(self.build / "python.json", dict(Executable=sys.executable, Version=sys.version))
            manifest = dict(Optimization=self.a.optimization, Receipt=str(self.build / "result.json"))
            sources = (
                ("Fiber", self.port / "fiber_port.c", self.fiber),
                ("Boot", self.port / "fiber_port_boot.c", self.fiber),
                ("Init", self.port / "fiber_port_tfm.c", self.fiber),
                ("Wrapper", self.port / "fiber_port_tfm_os_wrapper.c", self.fiber),
                ("Reference", self.ref / "portasm.c", self.reference),
                ("ReferenceConstructor", self.ref / "port.c", self.reference),
                ("ReferenceWrapper", self.tfm / "os_wrapper_freertos.c", self.reference))
            source_map = {key: (source, flags) for key, source, flags in sources}
            for key, source, flags in sources:
                manifest[key] = self.compile(source, key, flags)
                manifest[key + "Disassembly"] = manifest[key] + ".dis"
            manifest['Geometry'] = self.compile(self.fixture / 'geometry.c', 'Geometry', self.fiber)
            manifest['GeometryDisassembly'] = manifest['Geometry']+'.dis'
            path = self.build / "check.json"
            write(path, manifest)
            self.command([sys.executable, "-B", self.fixture / "check.py", path], "closed actual-source comparison")
            result = json.loads(Path(manifest['Receipt']).read_text())
            dataflow = self.command([sys.executable, '-B', self.fixture / 'check.py', '--r9-dataflow-only', path],
                                    'independent R9 dataflow positive')
            expected_count = result['Scenarios']['Constructor']+result['Scenarios']['CapturedR9']
            require(dataflow['Output'] == 'PASS C5TF_R9_DATAFLOW_ONLY scenarios=%d (not a parity receipt)\n' % expected_count,
                    'independent R9 dataflow positive diagnostic changed')
            self.runs.append(manifest)
            from mutants import cases, R9_DATAFLOW_MUTANTS
            for case in cases():
                name, side, marker, old, new, *count = case
                source, flags = source_map[side]
                text = source.read_text(encoding='utf-8')
                start, end = 0, len(text)
                if marker:
                    start = text.rfind(marker)
                    require(start >= 0, 'mutation function marker missing: ' + name)
                    line = text.rfind('\n', 0, start)+1
                    indent = text[line:start]
                    require(not indent.strip(), 'mutation marker not at declaration: ' + name)
                    close = re.search(r'(?m)^' + re.escape(indent) + r'\}', text[start:])
                    require(close is not None, 'mutation function end missing: ' + name)
                    end = start+close.end()
                part = text[start:end]
                expected_count = count[0] if count else 1
                require(part.count(old) == expected_count, 'mutation anchor count changed: ' + name + '/' + str(part.count(old)))
                copy = self.build / ('mutant-' + name + '.c')
                copy.write_text(text[:start]+part.replace(old, new)+text[end:], encoding='utf-8')
                obj = self.compile(copy, 'mutant-' + name, flags)
                negative = dict(manifest)
                negative.update({side: obj, side+'Disassembly': obj+'.dis', 'Receipt': obj+'.unexpected-pass.json'})
                negative_path = Path(obj+'.json')
                write(negative_path, negative)
                result = self.command([sys.executable, '-B', self.fixture / 'check.py', negative_path], 'reject ' + name, allow=True)
                require(self.mutant_rejection(result),
                        'mutant survived or failed for unintended reason: ' + name + '/' + result['Output'])
                self.mutants.append(dict(Name=name, Side=side, Manifest=str(negative_path), Diagnostic=result['Output'].strip()))
                if name in R9_DATAFLOW_MUTANTS:
                    independent = self.command([sys.executable, '-B', self.fixture / 'check.py', '--r9-dataflow-only', negative_path],
                                               'independent dataflow rejects '+name, allow=True)
                    require(self.dataflow_rejection(independent), 'independent R9 oracle accepted compiled mutant or wrong diagnostic: '+name+'/'+independent['Output'])
                    self.dataflow_mutants.append(dict(Name=name, Manifest=str(negative_path), Diagnostic=independent['Output'].strip()))
            require({r['Name'] for r in self.dataflow_mutants} == R9_DATAFLOW_MUTANTS, 'independent R9 mutant inventory incomplete')
            self.guard_controls(path)
            self.dependency_closure()
            passed = True
        finally:
            drift = [r for r in self.live + self.inputs if not Path(r["Path"]).exists() or digest(r["Path"]) != r["Sha256"]]
            write(self.build / "inputs.drift.json", drift)
            write(self.build / "status.json", dict(Status="PASS" if passed and not drift else "INCOMPLETE",
                Optimization=self.a.optimization, RuntimeProfileAdded=False, SourceDrift=drift,
                Configurations=self.runs, Mutants=self.mutants, R9DataflowMutants=self.dataflow_mutants, Controls=self.controls))
            require(not drift, "C5TF inputs changed during proof; no qualification")
        artifacts = [dict(Path=str(p.resolve()), Sha256=digest(p)) for p in sorted(self.build.rglob('*'))
                     if p.is_file() and p.name != 'artifacts.json']
        require(all(Path(r['Path']).is_relative_to(self.build) for r in artifacts), 'artifact escaped evidence root')
        write(self.build / "artifacts.json", dict(Status="PASS", ReferenceCommit="a50edad08b29052631aa469d4df6e6ec7ff68878",
            Inputs=self.inputs, Artifacts=artifacts))
        result = json.loads((self.build / 'result.json').read_text())
        print("PASS C5TF actual M55_NTZ/TF-M " + self.a.optimization + ': %d bodies, %d scenarios, %d compiled mutants (%d independent R9 rejections), %d harness controls; %s' %
              (result['Functions'], sum(result['Scenarios'].values()), len(self.mutants), len(self.dataflow_mutants), len(self.controls), self.build))


def main():
    p = argparse.ArgumentParser()
    for name in ("repo", "arm-gcc", "cmsis", "reference", "build"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--optimization", choices=("-O2", "-Os"), required=True)
    Proof(p.parse_args()).run()


if __name__ == "__main__":
    main()
