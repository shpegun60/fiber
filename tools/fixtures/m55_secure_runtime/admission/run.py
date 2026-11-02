"""C55S public/default/archive admission, not Secure runtime execution.

The ELF/cold-read mechanics follow the separately maintained C3FT gate. This
gate compiles the C55S sources independently; no sibling object/provider is used.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

PUBLIC = set('fiber_init fiber_current fiber_start fiber_schedule fiber_scheduler_set_pick_next'.split())
REVERSE = 'fiber_internal_runtime_port_abi_v1_anchor'
STORAGE = 'fiber_port_storage_cohort_arm_cm55_v1_r0'
FORWARD = set(('fiber_port_context_init fiber_port_runtime_memory_barrier fiber_port_panic_wait '
               'fiber_port_require_scheduler_configuration_environment fiber_port_runtime_prepare_start '
               'fiber_port_runtime_select_first fiber_port_runtime_start_first fiber_port_runtime_schedule').split())


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().upper()


def runtime_reader(repo):
    spec = importlib.util.spec_from_file_location('c55s_runtime_sources', Path(repo) / 'tools/runtime_sources.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n', encoding='ascii')


def require_undefined_only(result, expected):
    prefix = 'negative-link-diagnostics: '
    require(result['exit'] == 1 and not result['timeout'], prefix + 'not an ordinary linker failure')
    actual, context, pending, summary = set(), False, False, False
    for line in result['output'].splitlines():
        if not line.strip():
            continue
        require(not summary, prefix + 'text after final collect2 summary: ' + line)
        if re.fullmatch(r".+[/\\]ld(?:\.exe)?: .+: in function [`'][^`'\r\n]+['`]:", line):
            require(not pending, prefix + 'function context without an undefined diagnostic')
            context, pending = True, True
            continue
        undefined = re.fullmatch(
            r"(?:[A-Za-z]:)?[^:\r\n]+:\(\.[A-Za-z0-9_.$]+(?:\+0x[0-9a-fA-F]+)?\): "
            r"undefined reference to [`']([A-Za-z_$][A-Za-z0-9_$]*)['`]", line)
        if undefined:
            require(context, prefix + 'undefined diagnostic without linker function context')
            actual.add(undefined[1])
            pending = False
            continue
        if line == 'collect2.exe: error: ld returned 1 exit status':
            require(context and actual and not pending, prefix + 'summary without undefined diagnostics')
            summary = True
            continue
        raise RuntimeError(prefix + 'unclassified linker output: ' + line)
    require(summary and actual == set(expected), prefix + 'missing summary or nonexact undefined set')


class Elf:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        require(self.data[:7] == b'\x7fELF\x01\x01\x01', 'requires little-endian ELF32')
        h = struct.unpack_from('<16sHHIIIIIHHHHHH', self.data)
        require(h[2] == 40, 'requires actual ARM target')
        self.sections = []
        for n in range(h[12]):
            x = struct.unpack_from('<10I', self.data, h[6] + n * h[11])
            self.sections.append(dict(zip(('name', 'type', 'flags', 'address', 'offset', 'size',
                                           'link', 'info', 'alignment', 'entsize'), x)))
        strings = self.payload(self.sections[h[13]])
        for s in self.sections:
            s['name'] = self.string(strings, s['name'])
        self.symbols = []
        for s in self.sections:
            if s['type'] != 2:
                continue
            names = self.payload(self.sections[s['link']])
            require(s['entsize'] == 16, 'bad symbol entry')
            for offset in range(s['offset'], s['offset'] + s['size'], 16):
                name, value, size, info, other, section = struct.unpack_from('<IIIBBH', self.data, offset)
                self.symbols.append(dict(name=self.string(names, name), value=value, size=size,
                                         bind=info >> 4, type=info & 15, section=section))

    @staticmethod
    def string(data, offset):
        return data[offset:data.index(b'\0', offset)].decode('ascii')

    def payload(self, section):
        return self.data[section['offset']:section['offset'] + section['size']]

    def definitions(self, name):
        return [s for s in self.symbols if s['name'] == name and s['section']]

    def one(self, name):
        found = self.definitions(name)
        require(len(found) == 1, 'missing/ambiguous definition: ' + name)
        return found[0]

    def at(self, address, length):
        sections = [s for s in self.sections if s['type'] != 8 and s['address'] <= address and
                    address + length <= s['address'] + s['size']]
        require(len(sections) == 1, 'ambiguous/unmapped ELF bytes')
        section = sections[0]
        offset = section['offset'] + address - section['address']
        return self.data[offset:offset + length]


def observe(path, bits):
    elf = Elf(path)
    symbol = elf.one('c55s_default_policy')
    section = elf.sections[symbol['section']]
    offset = symbol['value'] - section['address']
    require(symbol['size'] == 36 and symbol['bind'] == 1 and symbol['type'] == 1 and
            section['flags'] & 2 and not section['flags'] & 1 and section['type'] != 8 and
            0 <= offset and offset + 36 <= section['size'], 'policy data not exact readonly target storage')
    actual = struct.unpack('<9I', elf.payload(section)[offset:offset + 36])
    expected = (0, 1, 1, 0, 0, 1, 32, 2 if bits == 8 else 1 << (8 - bits), 0)
    require(actual == expected, 'C55S non-default policy: ' + repr(actual))
    return dict(elf=str(path), sha256=digest(path), priority_bits=bits, values=actual)


class Proof:
    def __init__(self, args):
        self.a = args
        self.repo, self.out = Path(args.repo), Path(args.build)
        self.fixture = Path(__file__).resolve().parent
        self.ns = self.repo / 'fiber/port/ARM_CM55/non_secure'
        self.secure = self.repo / 'fiber/port/ARM_CM55/secure'
        self.common = self.repo / 'fiber'
        self.commands, self.links, self.policies, self.headers, self.public_controls = [], [], [], [], []
        self.link_controls = []
        self.base = ['-mcpu=cortex-m55', '-mthumb', '-mfloat-abi=soft', '-mgeneral-regs-only',
                     '-ffreestanding', '-fno-builtin', '-fno-common', '-ffunction-sections', '-fdata-sections',
                     '-fno-unwind-tables', '-fno-asynchronous-unwind-tables', '-Wall', '-Wextra', '-Werror', '-Wundef']
        self.bin = Path(args.arm_gcc).parent
        self.tools = {n: self.bin / ('arm-none-eabi-' + n + '.exe') for n in
                      ('g++', 'gcc-ar', 'gcc-nm', 'objdump', 'readelf')}
        self.ns_sources = [self.ns / n for n in ('fiber_port.c', 'fiber_port_boot.c', 'fiber_port_runtime.c',
                           'fiber_port_secure_context.c', 'fiber_port_svc.c', 'fiber_port_pendsv.c')]
        self.runtime_sources = runtime_reader(self.repo)
        self.common_roles = ('engine', 'state', 'optional_configuration', 'panic', 'legacy_compat')
        self.common_sources = list(self.runtime_sources.get_runtime_source_paths(self.repo, self.common_roles))
        state = self.runtime_sources.get_runtime_source_paths(self.repo, ('state',))
        require(len(state) == 1, 'Expected exactly one runtime state owner')
        self.state_source = state[0]

    def run(self, argv, allowed=False):
        argv = list(map(str, argv))
        try:
            p = subprocess.run(argv, cwd=self.out, capture_output=True, text=True, errors='replace', timeout=120)
            result = dict(command=argv, exit=p.returncode, output=p.stdout + p.stderr, timeout=False)
        except subprocess.TimeoutExpired:
            result = dict(command=argv, exit=None, output='', timeout=True)
        self.commands.append(result)
        save(self.out / ('command-%04d.json' % (len(self.commands) - 1)), result)
        if not allowed:
            require(result['exit'] == 0 and not result['timeout'], 'command failed: ' + result['output'][-5000:])
        return result

    def compile(self, source, output, options, private=False, secure=False, cxx=False, public=False, extra=(), allowed=False):
        flags = [*self.base, '-std=gnu++17' if cxx else '-std=gnu11', *options,
                 '-I' + str(self.repo), '-I' + str(self.common), '-I' + str(self.repo / 'context'), '-I' + str(self.common / 'port'),
                 '-I' + str(self.fixture.parent), '-I' + str(self.secure if secure else self.ns),
                 '-DFIBER_PORT_BUILD_SELECTED=1', '-DFIBER_PORT_ARMV81M_MAINLINE=1']
        if private:
            flags += ['-I' + self.a.cmsis, '-include', str(self.fixture.parent / 'main.h')]
        if secure:
            flags += ['-mcmse', '-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_COUNT=3u',
                      '-DFIBER_ARM_CM55_SECURE_CONTEXT_MAX_STACK_BYTES=1024u']
        if cxx:
            flags += ['-x', 'c++', '-fno-exceptions', '-fno-rtti']
        if public:
            flags += ['-H']
        result = self.run([self.tools['g++'] if cxx else self.a.arm_gcc, *flags, *extra,
                           '-c', source, '-o', output], allowed=allowed)
        if public and result['exit'] == 0:
            headers = [Path(x).resolve() for x in re.findall(r'^\.+ (.+)$', result['output'], re.M)]
            forbidden = {'main.h', 'mcu_core.h', 'fiber_port_private.h', 'fiber_portmacro.h',
                         'fiber_runtime_state.h', 'fiber_runtime_port_abi.h', 'fiber_port_runtime_abi.h',
                         'fiber_port_boot.h', 'fiber_port_secure_context_abi.h',
                         'fiber_port_secure_gateway_abi.h', 'fiber_port_secure_context_gateway_abi.h'}
            require(any(h.name == 'fiber_core.h' for h in headers) and
                    not any(h.name in forbidden or h.is_relative_to(Path(self.a.cmsis)) for h in headers),
                    'public consumer acquired CMSIS/private/optional dependency')
            expected = {self.repo / name for name in (
                'fiber/fiber_core.h', 'fiber/fiber_api_decl.h', 'fiber/fiber_api_attributes.h',
                'fiber/fiber_api_types.h', 'fiber/port/fiber_port_selected.h', 'fiber/port/fiber_port_select.h',
                'fiber/port/fiber_static_assert.h', 'fiber/port/fiber_port_storage_cohort.h',
                'fiber/port/fiber_port_storage_cohort_expectation.h',
                'fiber/port/ARM_CM55/non_secure/fiber_port_types.h',
                'fiber/port/ARM_CM55/non_secure/fiber_port_boot_types.h')}
            require({h for h in headers if h.is_relative_to(self.repo)} == expected,
                    'public consumer acquired an unexpected repository header')
            save(str(output) + '.includes.json', list(map(str, headers)))
            self.headers.append(dict(object=str(output), includes=list(map(str, headers))))
        return result

    def optional_header_control(self, d, options):
        source, obj = d / 'optional-declaration-leak.c', d / 'optional-declaration-leak.o'
        source.write_text((self.fixture / 'constructor.c').read_text() +
            '\n#include "fiber/port/ARM_CM55/non_secure/fiber_port_secure_context_abi.h"\n')
        rejected = False
        try:
            self.compile(source, obj, options, public=True)
        except RuntimeError as error:
            require(str(error) == 'public consumer acquired CMSIS/private/optional dependency',
                    'optional-header control failed for unrelated reason: ' + str(error))
            require(obj.is_file() and {n for n,t in self.nm(obj, True)} == {'fiber_init', STORAGE},
                    'declaration-only optional-header control changed its public imports')
            rejected = True
        require(rejected, 'declaration-only optional header was accepted in a plain public consumer')
        self.public_controls.append(dict(object=str(obj), rejection='compiled declaration-only optional dependency',
                                         unchanged_imports=['fiber_init', STORAGE]))

    def nm(self, path, undefined=False):
        text = self.run([self.tools['gcc-nm'], '-P', '-u' if undefined else '--defined-only', path])['output']
        result = []
        for line in text.splitlines():
            m = re.fullmatch(r'(\S+)\s+([A-Za-z?])(?:\s+[0-9a-fA-F]+){0,2}', line.strip())
            require(m is not None, 'unparsed nm line: ' + line)
            result.append((m[1], m[2]))
        return result

    def evidence(self, path):
        result = self.run([self.tools['objdump'], '-drwC', path])['output']
        Path(str(path) + '.dis').write_text(result)
        for tool, flags, extension in (('readelf', ['-hASsW'], '.readelf'), ('gcc-nm', ['-a', '-S'], '.nm')):
            Path(str(path) + extension).write_text(self.run([self.tools[tool], *flags, path])['output'])
        return result

    def archive(self, output, objects):
        self.run([self.tools['gcc-ar'], 'rcs', output, *objects])
        listing = self.run([self.tools['gcc-ar'], 't', output])['output'].splitlines()
        require(listing == [Path(p).name for p in objects], 'archive member drift')
        return output

    def link(self, output, objects, options, missing=None, secure=False, contract=False):
        flags = [*self.base, *options, '-nostdlib', '-Wl,--gc-sections', '-Wl,--no-undefined',
                 '-Wl,--fatal-warnings', '-Wl,--build-id=none', '-T', self.fixture / ('secure.ld' if secure else 'nonsecure.ld'),
                 '-Wl,-Map=' + str(output) + '.map']
        if secure:
            flags += ['-mcmse', '-Wl,--cmse-implib,--out-implib=' + str(output) + '.import.o',
                      '-Wl,--section-start=.gnu.sgstubs=0x10008000',
                      '-T', self.secure / 'fiber_secure_context_cohort_contract.ld']
        if contract:
            flags += ['-T', self.ns / 'fiber_port_first_start_contract.ld']
        result = self.run([self.a.arm_gcc, *flags, *objects, '-o', output], allowed=missing is not None)
        if missing is not None:
            require_undefined_only(result, missing)
        else:
            require(not self.nm(output, True), 'unresolved final ELF')
            self.evidence(output)
        self.links.append(dict(elf=str(output), sha256=digest(output) if output.exists() else None,
                               expected_missing=sorted(missing or [])))

    def link_classifier_controls(self, d, options):
        source, obj = d / 'link-diagnostic-control.c', d / 'link-diagnostic-control.o'
        template = ('extern const unsigned char ' + REVERSE + ';\n'
                    '__attribute__((used,externally_visible)) volatile unsigned char '
                    'diagnostic_storage[%du];\n'
                    'void Reset_Handler(void) { diagnostic_storage[0] = ' + REVERSE + '; }\n')
        source.write_text(template % 1)
        self.compile(source, obj, options)
        self.link(d / 'missing-only-control.elf', [obj], options, missing={REVERSE})
        original = dict(self.commands[-1])
        self.link_controls.append(dict(mode=d.name, name='compiled-missing-only',
                                       accepted=self.links.pop(), command=original))

        # Exercise Proof.link itself, not a disconnected copy of its classifier.
        real_run = self.run
        terminal = 'collect2.exe: error: ld returned 1 exit status'
        mutations = [('RAM-overflow', "ld.exe: region `RAM' overflowed by 1 bytes"),
                     ('linker-assertion', 'ld.exe: controlled linker assertion failed'),
                     ('LTO-error', 'lto-wrapper.exe: fatal error: controlled failure'),
                     ('warning', 'ld.exe: warning: controlled warning'),
                     ('unknown-output', 'unclassified diagnostic control')]
        results = [(name, dict(original, output=original['output'].replace(terminal, text + '\n' + terminal)))
                   for name, text in mutations]
        results += [('missing-summary', dict(original, output=original['output'].replace(terminal, ''))),
                    ('extra-undefined', dict(original, output=original['output'].replace(
                        terminal, "control.c:(.text.Reset_Handler+0x4): undefined reference to `unexpected_symbol'\n" + terminal))),
                    ('timeout', dict(original, timeout=True, exit=None)),
                    ('success-exit', dict(original, exit=0))]
        try:
            for name, result in results:
                self.run = lambda argv, allowed=False, result=result: result
                try:
                    self.link(d / ('counterfeit-' + name + '.elf'), [obj], options, missing={REVERSE})
                except RuntimeError as error:
                    require(str(error).startswith('negative-link-diagnostics: '),
                            'link classifier control rejected for unrelated reason: ' + str(error))
                    self.link_controls.append(dict(mode=d.name, name=name, kind='synthetic-result-through-Proof.link',
                                                   rejection=str(error), result=result))
                else:
                    raise RuntimeError('Proof.link accepted mixed/counterfeit diagnostic: ' + name)
        finally:
            self.run = real_run

        source.write_text(template % 65537)
        self.compile(source, obj, options)
        try:
            self.link(d / 'compiled-mixed-error.elf', [obj], options, missing={REVERSE})
        except RuntimeError as error:
            result = self.commands[-1]
            require(str(error).startswith('negative-link-diagnostics: ') and
                    re.search(r'undefined reference to [`\']' + REVERSE, result['output']) and
                    re.search(r"region [`']RAM['`] overflowed by \d+ bytes?", result['output']),
                    'compiled mixed-error control rejected for unrelated reason: ' + str(error))
            self.link_controls.append(dict(mode=d.name, name='compiled-missing-plus-RAM-overflow',
                                           kind='actual-compiled-link-through-Proof.link',
                                           rejection=str(error), result=result))
        else:
            raise RuntimeError('Proof.link accepted actual missing-v1 plus RAM overflow')

    def cold_read(self, path):
        elf = Elf(path)
        function, marker = elf.one('fiber_port_context_init'), elf.one(REVERSE)
        require(marker['size'] == 1 and elf.at(marker['value'], 1) == b'\1' and
                not elf.sections[marker['section']]['flags'] & 1, 'reverse-v1 marker not readonly one-byte 1')
        begin = function['value'] & ~1
        loaded, found = {}, False
        for line in Path(str(path) + '.dis').read_text().splitlines():
            insn = re.match(r'\s*([0-9a-f]+):\s+(?:[0-9a-f]{4}\s+){1,2}\s*([a-z][a-z0-9.]*)\s*(.*)', line)
            if not insn or not begin <= int(insn[1], 16) < begin + function['size']:
                continue
            op = insn[2].removesuffix('.w')
            args = re.sub(r'\b(?:ip|sb|sl|fp)\b', lambda m: {'ip':'r12', 'sb':'r9', 'sl':'r10', 'fp':'r11'}[m[0]], insn[3])
            literal = re.match(r'(r\d+),\s*\[pc,\s*#\d+\].*?\(([0-9a-f]+)\s', args)
            if op == 'ldr' and literal:
                loaded[literal[1]] = struct.unpack('<I', elf.at(int(literal[2], 16), 4))[0]
            elif op == 'ldrb':
                source = re.match(r'r\d+,\s*\[(r\d+)(?:,\s*#(\d+))?\]', args)
                if source and loaded.get(source[1], -1) + int(source[2] or 0) == marker['value']:
                    found = True
                destination = re.match(r'(r\d+),', args)
                if destination:
                    loaded.pop(destination[1], None)
            else:
                destination = re.match(r'(r\d+),', args)
                if destination and op not in ('cmp', 'str', 'strb', 'strh', 'tst'):
                    loaded.pop(destination[1], None)
                if op in ('bl', 'blx'):
                    for r in ('r0','r1','r2','r3','r12'):
                        loaded.pop(r, None)
        require(found, 'constructor lacks exact generated cold reverse-v1 read')

    def constructor(self, d, common, port, options, hooks):
        text = self.state_source.read_text()
        anchors = re.findall(r'const unsigned char ' + REVERSE + r' =\n[ \t]+\(unsigned char\)FIBER_RUNTIME_PORT_ABI_VERSION;', text)
        require(len(anchors) == 1, 'marker-only pre-v1 common model boundary drift')
        anchor = anchors[0]
        source, obj = d / 'pre-v1-common-state.c', d / 'pre-v1-common-state.o'
        source.write_text(text.replace(anchor, ''))
        self.compile(source, obj, options)
        require(not any(n == REVERSE for n, t in self.nm(obj) + self.nm(obj, True)), 'pre-v1 model still has marker')
        current = self.archive(d / 'libcommon-current.a', common)
        require(len(common) == len(self.common_sources) and self.common_sources.count(self.state_source) == 1,
                'Missing/ambiguous state object mapping')
        stale = self.archive(d / 'libcommon-pre-v1.a', [obj if source == self.state_source else current
                                                    for source, current in zip(self.common_sources, common)])
        full_port = self.archive(d / 'libport-current.a', port)
        boot = self.ns_sources[1].read_text()
        retain = 'FIBER_RUNTIME_PORT_ABI_RETAIN_V1();'
        require(boot.count(retain) == 1 and boot.index(retain) > boot.index('void fiber_port_context_init('),
                'exact constructor-only no-retain mutation boundary drift')
        mutant_source, mutant = d / 'constructor-no-retain.c', d / 'constructor-no-retain.o'
        mutant_source.write_text(boot.replace(retain, '(void)0;'))
        self.compile(mutant_source, mutant, options, private=True)
        mutant_port = self.archive(d / 'libport-no-retain.a', [port[0], mutant, *port[2:]])
        for cxx in (False, True):
            language = 'cpp' if cxx else 'c'
            app = d / ('constructor-' + language + '.o')
            self.compile(self.fixture / 'constructor.c', app, options, cxx=cxx, public=True)
            require({n for n, t in self.nm(app, True)} == {'fiber_init', STORAGE}, 'constructor imports beyond public init/storage')
            for name, common_archive, port_archive, missing in (
                ('current', current, full_port, None), ('pre-v1', stale, full_port, {REVERSE}),
                ('causal-no-retain', stale, mutant_port, None)):
                output = d / ('constructor-' + language + '-' + name + '.elf')
                self.link(output, [app, hooks, '-Wl,--start-group', common_archive, port_archive,
                                   '-Wl,--end-group'], options, missing=missing)
                if missing is not None:
                    continue
                elf = Elf(output)
                require(not any(elf.definitions(n) for n in ('fiber_start','fiber_schedule','SVC_Handler','PendSV_Handler',
                    'fiber_port_secure_context_attach','fiber_secure_context_gateway_c55s_v1_initialize')),
                    'constructor-only archive link accidentally retained runtime/optional/Secure roots')
                if name == 'current':
                    self.cold_read(output)
                else:
                    require(not elf.definitions(REVERSE), 'no-retain causal link still has reverse-v1 dependency')

    def execute(self):
        require(not sys.flags.optimize, 'optimized Python proof unsupported')
        complete = False
        try:
            for opt in ('-O2','-Os'):
                for lto in (False, True):
                    d = self.out / (opt[1:].lower() + ('-lto' if lto else ''))
                    d.mkdir()
                    options = [opt] + (['-flto'] if lto else [])
                    self.link_classifier_controls(d, options)
                    port, common, secure = [], [], []
                    for source in self.ns_sources:
                        obj = d / source.with_suffix('.o').name
                        self.compile(source, obj, options, private=True)
                        port.append(obj)
                    for source in self.common_sources:
                        obj = d / source.with_suffix('.o').name
                        self.compile(source, obj, options)
                        common.append(obj)
                    for name in ('fiber_secure_gateway.c','fiber_secure_context_gateway.c','fiber_secure_context_pool.c'):
                        obj = d / name.replace('.c','.o')
                        self.compile(self.secure / name, obj, options, private=True, secure=True)
                        secure.append(obj)
                    root = d / 'secure-roots.o'
                    self.compile(self.fixture / 'secure_roots.c', root, options, private=True, secure=True)
                    provider = d / 'secure-provider.elf'
                    self.link(provider, [root, *secure], options, secure=True)
                    imports = Path(str(provider) + '.import.o')
                    names = {n for n, t in self.nm(imports) if not n.startswith('$')}
                    require(len(names) == 12 and all(n.startswith(('fiber_secure_gateway_c55s_v1_',
                            'fiber_secure_context_gateway_c55s_v1_')) for n in names), 'Secure import not exact twelve production gateways')
                    hooks, policy = d / 'hooks.o', d / 'default-policy.o'
                    self.compile(self.fixture / 'hooks.c', hooks, options)
                    self.compile(self.fixture / 'default_policy.c', policy, options, private=True)
                    control = self.compile(self.fixture / 'default_policy.c', d / 'not-default.o', options,
                        private=True, extra=['-DFIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH=0'], allowed=True)
                    errors = re.findall(r'^.*error: (.+)$', control['output'], re.M)
                    require(control['exit'] not in (None, 0) and errors ==
                            ['static assertion failed: "C55S default policy: FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH == 1"'],
                            'default-policy observer control failed for unrelated reason')
                    archive = self.archive(d / 'libcomplete.a', [*common, *port])
                    vectors, expectation = d / 'vectors.o', d / 'build-expectation.o'
                    self.compile(self.fixture / 'vectors.c', vectors, options)
                    self.compile(self.common / 'port/fiber_port_context_cohort_expectation.c',
                                 expectation, options, private=True)
                    source = self.repo / 'tools/fixtures/portable_application.c'
                    for cxx in (False, True):
                        language = 'cpp' if cxx else 'c'
                        app, startup = d / ('portable-' + language + '.o'), d / ('startup-' + language + '.o')
                        self.compile(source, app, options, cxx=cxx, public=True,
                                     extra=['-D_Alignas(n)=__attribute__((aligned(n)))'] if cxx else [])
                        require({n for n,t in self.nm(app, True)} == PUBLIC | {STORAGE}, 'portable app imports beyond five calls/storage')
                        self.compile(self.fixture / 'portable_startup.c', startup, options, cxx=cxx)
                        for archived in (False, True):
                            elf = d / ('portable-' + language + ('-archive' if archived else '-direct') + '.elf')
                            objects = [archive] if archived else [*common, *port]
                            self.link(elf, [startup, app, hooks, policy, vectors, expectation,
                                           '-Wl,--start-group', *objects, '-Wl,--end-group', imports],
                                      options, contract=True)
                            parsed = Elf(elf)
                            self.policies.append(observe(elf, 3))
                            for name in ('portable_fixture_stack_1','portable_fixture_stack_2'):
                                stacks = [s for s in parsed.symbols if s['section'] and s['name'].endswith(name)]
                                require(len(stacks) == 1 and stacks[0]['size'] == 2048 and stacks[0]['value'] % 8 == 0,
                                        'portable stack size/alignment lost')
                            for name in FORWARD | {'SVC_Handler','PendSV_Handler'}:
                                require(parsed.one(name)['bind'] == 1, 'weak/nonunique actual provider: ' + name)
                            for name in (STORAGE, REVERSE):
                                marker = parsed.one(name)
                                require(marker['bind'] in (0, 1) and marker['type'] == 1 and marker['size'] == 1 and
                                        not parsed.sections[marker['section']]['flags'] & 1 and
                                        parsed.at(marker['value'], 1) == b'\1', 'not exact readonly marker: ' + name)
                            table = parsed.one('admission_vectors')
                            for name, slot in (('SVC_Handler',11),('PendSV_Handler',14)):
                                require(struct.unpack('<I', parsed.at(table['value'] + slot * 4, 4))[0] ==
                                        parsed.one(name)['value'], 'portable vector does not use actual handler')
                    self.constructor(d, common, port, options, hooks)
                    self.optional_header_control(d, options)
                    print('PASS C55S admission ' + d.name, flush=True)
            complete = True
        finally:
            save(self.out / 'admission.receipt.json', dict(status='PASS' if complete else 'FAIL',
                links=self.links, default_policy=self.policies, public_includes=self.headers,
                public_controls=self.public_controls,
                link_controls=self.link_controls,
                source_scope='immutable copied C55S/common sources; no real execution in this static phase',
                no_retain_control='compiled constructor-only causal link, intentionally not executed',
                pre_v1_common_model='only the actual v1 definition removed, not a complete historical checkout',
                runtimeSelectable=0, commands=len(self.commands)))
            save(self.out / 'commands.json', self.commands)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--observe-policy')
    parser.add_argument('--priority-bits', type=int)
    for name in ('repo','build','arm-gcc','cmsis'):
        parser.add_argument('--' + name)
    args = parser.parse_args()
    require(not sys.flags.optimize, 'optimized Python proof unsupported')
    if args.observe_policy:
        item = observe(args.observe_policy, args.priority_bits)
        save(args.observe_policy + '.default-policy.json', item)
        print('PASS C55S exact default observer', flush=True)
    else:
        require(all((args.repo,args.build,args.arm_gcc,args.cmsis)), 'missing admission arguments')
        Proof(args).execute()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print('FAIL C55S admission: ' + str(error), file=sys.stderr, flush=True)
        sys.exit(1)
