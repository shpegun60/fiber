"""Invented port journals with real neutral metadata/worker validators."""

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
METHODS = 25
BUFFERS, H, REAL = {}, {}, {}
m = fixture = lower_fixture = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def worker_suite(native, read):
    return types.SimpleNamespace(watch=types.SimpleNamespace(read=read), api=types.SimpleNamespace(checked_path=Path),
        admitted=types.SimpleNamespace(base=types.SimpleNamespace(stable_path=Path)), result=native,
        objects=[Path(r['Object']) for r in native['Sources']], transport=H['transport'], modules={'policy': H['port_phase']})


class Adapter:
    """Replay real neutral workers on invented bytes, never machine semantics."""
    def __init__(self): self.calls = []

    def inspect(self, core, read, plans, native, helpers, *, roles, ir_definitions):
        if set(helpers) != set(m.ADAPTER_HELPERS): raise ValueError('adapter helper boundary')
        self.calls.append(copy.deepcopy(plans))
        return H['port_lowered'].inspect(core, read, plans, native, helpers, roles=roles, ir_definitions=ir_definitions)

    def require_result(self, proof, helpers):
        return H['port_lowered'].require_result(proof, helpers)


class Model:
    def __init__(self):
        self.base = fixture.Model();self.__dict__.update(self.base.__dict__)
        self.machine_fixture = lower_fixture.Fixture();self.core = self.machine_fixture.core
        for name in ('context/context_api_decl.h', 'tools/runtime_sources.json'):
            self.sources[name] = BUFFERS[ROOT / name];self.files[self.sr / name] = self.sources[name]
        # link.ld is deliberately NOT a compilation dependency.
        common_names = set(m.OWNERSHIP) | {n for n in self.sources if n.startswith('context/')}
        for i in range(3):
            paths = sorted({self.sr / n for n in common_names} | {self.external})
            self.native['Sources'][i]['ActualCompileDependencies'] = [dict(Path=str(p), Sha256=sha(self.files[p])) for p in paths]
        self.tools['Objdump'] = self.capture / 'toolchain/bin/arm-none-eabi-objdump.exe';self.files[self.tools['Objdump']] = b'invented objdump'
        self.native['ResolvedWorkers'] = {}
        for name in ('lto1', 'as'):
            path = self.capture / 'toolchain/workers' / (name + '.exe');self.files[path] = ('invented worker/' + name).encode()
            self.native['ResolvedWorkers'][name] = dict(Path=str(path), Sha256=sha(self.files[path]))
        self.batch.update(PortPolicyBuilt=True, SourceOwnershipValidated=True,
            SourceOwnership=H['ownership'].validate_common_sources({n: self.files[self.sr / n] for n in m.OWNERSHIP}),
            SourceOwnershipInputs=[dict(Source=n, Path=str(self.sr / n), Sha256=sha(self.files[self.sr / n])) for n in m.OWNERSHIP],
            PortPolicySelectedSourceHashes={n: sha(self.files[self.sr / n]) for n in m.SELECTED})
        self.suite = types.SimpleNamespace(base=self.seed, result=self.native, source=lambda i: self.native['Sources'][i], objects=self.objects)
        specs_raw = b'*link:\n%{fprofile-arcs|fcondition-coverage|fprofile-generate*|coverage:-lgcov}\n'
        self.original_specs = self.root / 'port-policy/driver/original.specs';self.specs = self.root / 'port-policy/driver/no-auto-gcov.specs'
        self.files[self.original_specs] = specs_raw;adapt = H['attributes'].adapt_specs(specs_raw);self.files[self.specs] = adapt['Specs']
        adapter = {k: v for k, v in adapt.items() if k != 'Specs'};adapter.update(OriginalPath=str(self.original_specs), AdaptedPath=str(self.specs))
        self.batch['PortPolicyDriverAdapter'] = adapter;self.command(98, [str(self.tools['Gcc']), '-dumpspecs'], stdout=specs_raw)
        stress = H['policy'].stress_source(H['attributes'])['Source']
        self.batch['PortPolicyPairedStress'] = dict(SourceSha256=sha(stress), SameSourceBytes=True, OnlyPolicyFlagDifference=list(m.COUNTERS),
            RawOnlySpecsAdapter=True, StressActivationValidated=False, RawAttributesProof=False)
        for group in m.GROUPS[1:3]: self.files[self.root / 'port-policy/private' / group / 'stress.c'] = stress
        compiled, definitions = [], {}
        for group, index, first, count in m.BUILDS:
            selected, supported = group == 'selected', group != 'stress-raw'
            source = self.sr / m.SELECTED[index - 3] if selected else self.root / 'port-policy/private' / group / 'stress.c'
            obj = self.root / 'port-policy/ir' / group / (source.stem + '.o');self.files[obj] = fixture.elf(group + '-' + str(index))
            flags = H['port_phase'].flags_for(self.suite, H, index, supported=supported)
            before, after = obj.with_suffix('.discovery.d'), obj.with_suffix('.compile.d');target = 'pilot-source-' + str(index)
            paths = sorted((source, self.external));raw = (target + ': ' + ' '.join(map(str, paths)) + '\n').encode()
            self.files[before] = self.files[after] = raw;dependencies = [dict(Path=str(p), Sha256=sha(self.files[p])) for p in paths]
            self.command(first, [str(self.tools['Gcc']), *flags, '-M', '-MF', str(before), '-MT', target, str(source)])
            self.command(first + 1, [str(self.tools['Gcc']), *flags, '-MD', '-MF', str(after), '-MT', target, '-c', str(source), '-o', str(obj)])
            slim = self.base.slim(first + 2, obj)
            imports = [] if group == 'stress-supported' else ['__gcov_init'] if group == 'stress-raw' else ['fiber_panic']
            evidence = self.base.imports(first + 3, obj, imports);defined = None
            if selected:
                role = m.ROLES[index - 3];policy = H['policy']
                rows = [(n, 'T') for n in policy.RUNTIME] + [(policy.PRIVATE, 'D'), (policy.STORAGE, 'D')] if role == 'runtime' else [
                    (n, 'W' if n == 'fiber_fallback_initial_msp' else 'T') for n in policy.BOOT] if role == 'boot' else [(n, 'T') for n in policy.EXCEPTION]
                defined = self.base.definitions(first + 4, obj, rows);definitions[role] = defined
            coverage = None
            if not supported:
                note = obj.with_suffix('.gcno');self.files[note] = b'invented uncancelled profile notes';coverage = dict(Path=str(note), Sha256=sha(self.files[note]))
            compiled.append(dict(Group=group, TemplateIndex=index, Source=str(source), SourceSha256=sha(self.files[source]), Object=str(obj),
                ObjectSha256=sha(self.files[obj]), OriginalCompileFlags=list(self.native['Sources'][index]['CompileFlags']), CompileFlags=flags,
                SlimIR=slim, IRImports=evidence, IRDefinitions=defined, CoverageNotes=coverage, DiscoveryDependencyFile=str(before), CompileDependencyFile=str(after),
                DiscoveryDependencies=dependencies, Dependencies=copy.deepcopy(dependencies), CompileDependenciesVerified=True,
                OriginalSelectedSourceUnchanged=selected, SupportedPolicy=supported, CommandIndices=list(range(first, first + count)),
                RawIRIdentityClaim=False, SourceToMachineSemanticProof=False))
        self.batch['PortPolicyCompilations'] = compiled;self.batch['PortPolicyIRDefinitionSurface'] = H['policy'].inspect_ir_definitions(definitions)
        lowers, roles = [], {};selected = [Path(r['Object']) for r in compiled[:3]]
        for pos, (group, first) in enumerate(zip(m.GROUPS, m.LOWERS)):
            output = m._layout(self.root, group);machine = Path(str(output) + '.ltrans0.ltrans.o');supported = group != 'stress-raw';final = group == 'Final'
            specs = None if supported else self.specs
            objects = self.objects[:3] + selected + self.objects[6:] if final else selected if pos == 0 else [Path(compiled[pos + 2]['Object'])]
            for suffix in m.SUFFIXES: self.files[Path(str(output) + suffix)] = ('invented saved/' + group + '/' + suffix).encode()
            old_output = self.machine_fixture.plans[pos]['Output']
            for target, original in ((output, old_output), (machine, Path(str(old_output) + '.ltrans0.ltrans.o'))):
                self.machine_fixture.images[target] = copy.deepcopy(self.machine_fixture.images[original])
                self.files[target] = self.machine_fixture.raw[original]
            if final: self.files[output.with_suffix('.map')] = b'invented final map'
            wrapper = self.root / (''.join(output.parts[1:]) + '.lto_wrapper_args');self.files[wrapper] = b'invented wrapper args'
            worker_flags = ['-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-mlibarch=armv7-m', '-march=armv7-m', '-Os', *m.RAW,
                *(m.COUNTERS if supported else ()), '-flto-partition=one', '-nostdlib', *([] if final else ['-r']),
                '-flinker-output=exec' if final else '-flinker-output=nolto-rel', *([] if specs is None else ['-specs=' + str(specs)])]
            ir = [p for p in objects if p != self.objects[8]];intermediate = Path(str(output) + '.ltrans0.o')
            saved_flags = [*worker_flags, '-mlibarch=armv7-m', '-march=armv7-m']
            for suffix, args in (('.ltrans_args', [*saved_flags, '-fwpa', '-fltrans-output-list=' + str(output) + '.ltrans.out', *map(str, ir)]),
                    ('.ltrans0.ltrans_args', [*saved_flags, '-fltrans', '-o', str(machine), str(intermediate)]),
                    ('.wpa.args.0', list(map(str, ir))), ('.ltrans0.ltrans.args.0', [str(intermediate)])):
                self.files[Path(str(output) + suffix)] = ('\n'.join(args) + '\n').encode()
            self.files[Path(str(output) + '.ltrans.out')] = ('0\n' + str(intermediate) + '\n').encode()
            invocation = []
            for stage, suffix in (('-fwpa', '.wpa.args.0'), ('-fltrans', '.ltrans0.ltrans.args.0')):
                argv = [self.native['ResolvedWorkers']['lto1']['Path'], *worker_flags, stage]
                if stage == '-fltrans': argv += ['-o', str(output) + '.ltrans0.ltrans.s']
                invocation.append(' ' + ' '.join([*argv, '@' + str(output) + suffix]))
            invocation.append(' ' + ' '.join([self.native['ResolvedWorkers']['as']['Path'], '-o', str(machine), str(output) + '.ltrans0.ltrans.s']))
            diagnostic = ('\n'.join(invocation) + '\n').encode()
            if final: argv, _ = H['port_phase'].final_arguments(self.suite, {}, selected, output, output.with_suffix('.map'))
            else:
                flags = H['port_phase'].flags_for(self.suite, H, 3, supported=supported)
                argv = [str(self.tools['Gcc']), *flags, *([] if specs is None else ['-specs=' + str(specs)]), *m.LOWER_FLAGS, *map(str, objects), '-o', str(output)]
            self.command(first, argv, stderr=diagnostic)
            saved = [dict(Path=str(p), Sha256=sha(self.files[p])) for p in sorted(p for p in self.files if p.is_relative_to(output.parent))]
            saved.append(dict(Path=str(wrapper), Sha256=sha(self.files[wrapper])))
            dumps = []
            for offset, target in ((1, output), (2, machine)):
                original = old_output if offset == 1 else Path(str(old_output) + '.ltrans0.ltrans.o')
                raw = self.machine_fixture.raw[Path(str(original) + '.dis')];path = Path(str(target) + '.dis');self.files[path] = raw
                self.command(first + offset, [str(self.tools['Objdump']), '-drwC', '-z', str(target)], stdout=raw);dumps.append(dict(Path=str(path), Sha256=sha(raw)))
            worker = H['port_runner'].worker_chain(worker_suite(self.native, lambda p, expected=None: self.files[p]), output, objects, diagnostic, supported=supported, specs=specs)
            if final:
                row = dict(Path=str(output), Sha256=sha(self.files[output]), Map=str(output.with_suffix('.map')), MapSha256=sha(self.files[output.with_suffix('.map')]),
                    ActualWorker=worker, Disassembly=dumps[0], WorkerDisassembly=dumps[1], Objects=list(map(str, objects)),
                    UnchangedOtherSixObjects=[dict(Index=i, Path=str(self.objects[i]), Sha256=sha(self.files[self.objects[i]])) for i in (0, 1, 2, 6, 7, 8)],
                    OriginalFinalStageArgv=copy.deepcopy(next(r['Argv'] for r in self.native['Commands'] if r['Label'] == 'link ordinary')), Argv=argv,
                    WrapperArgs=str(wrapper), WrapperArgsSha256=sha(self.files[wrapper]), SavedOutputs=saved, GlobalSupportedCounterPolicy=True,
                    CommandIndices=[first, first + 1, first + 2], **dict.fromkeys(m.FINAL_FALSE, False))
                self.batch['PortPolicyFinalLink'] = row
                pairs = [('Final/ELF', output), ('Final/Map', output.with_suffix('.map')), ('Final/Disassembly', Path(dumps[0]['Path'])),
                    ('Final/Machine', machine), ('Final/MachineDisassembly', Path(dumps[1]['Path'])), ('Final/Startup', self.objects[8])]
            else:
                row = dict(Group=group, Object=str(output), ObjectSha256=sha(self.files[output]), Inputs=[dict(Path=str(p), Sha256=sha(self.files[p])) for p in objects],
                    ActualWorker=worker, Disassembly=dumps[0], WorkerDisassembly=dumps[1], WrapperArgs=str(wrapper), WrapperArgsSha256=sha(self.files[wrapper]),
                    SavedOutputs=saved, SupportedPolicy=supported, CommandIndices=[first, first + 1, first + 2], MachineEffectsValidated=False, StressActivationValidated=False)
                lowers.append(row);pairs = [(group + '/Aggregate', output), (group + '/AggregateDisassembly', Path(dumps[0]['Path'])),
                    (group + '/Machine', machine), (group + '/MachineDisassembly', Path(dumps[1]['Path']))]
            for name, path in pairs: roles[name] = dict(Role=name, Path=str(path), Sha256=sha(self.files[path]))
        self.batch['PortPolicyLowerings'] = lowers;self.batch['PortPolicyDeferredReader'] = m._deferred(roles);self.batch['PortPolicyBuild'] = m._build_record()
        self.base.seal_native(False);self.adapter = Adapter();self.refresh()

    def __getattr__(self, name): return getattr(self.base, name)

    def refresh(self):
        self.files[self.root / 'port-policy-build.json'] = encoded(dict(Build=self.batch['PortPolicyBuild'], Compilations=self.batch['PortPolicyCompilations'],
            Lowerings=self.batch['PortPolicyLowerings'], FinalLink=self.batch['PortPolicyFinalLink'], DeferredReader=self.batch['PortPolicyDeferredReader']))
        self.base.seal();self.catalog()

    def catalog(self):
        self.base.catalog();self.batch['InputHashes'].pop(str(self.root / 'results.json'), None)
        manifest = json.loads(self.files[self.root / 'artifacts.json']);manifest['Artifacts'].pop('results.json', None)
        self.files[self.root / 'artifacts.json'] = encoded(manifest);self.files[self.root / 'results.json'] = encoded(self.batch)

    def read(self, path, expected=None):
        if path not in self.files: raise ValueError('missing role/' + str(path))
        raw = self.files[path]
        if expected is None and path not in (self.root / 'results.json', self.root / 'artifacts.json'): raise AssertionError('unbound read')
        if expected is not None and sha(raw) != expected: raise ValueError('immutable hash mismatch')
        self.reads.append((path, expected));return raw

    def run(self, **changes):
        helpers = {k: H[k] for k in m.HELPERS if k != 'port_lowered'};helpers['port_lowered'] = self.adapter
        args = dict(batch=self.batch, native=self.native, root=self.root, core=self.core, helpers=helpers, read=self.read);args.update(changes)
        return m.inspect(**args)

    def change(self, index, stdout=None, stderr=None):
        self.base.change_stream(index, stdout=stdout, stderr=stderr);self.refresh()


class PortTests(unittest.TestCase):
    def test_positive_36_commands_and_census_joins(self):
        model = Model();proof = model.run();self.assertIs(m.require_result(proof), proof)
        self.assertEqual([r['Index'] for r in proof['CommandBindings']], list(range(98, 134)))
        self.assertEqual((proof['IRBuilds'], proof['DependencyFiles'], proof['SelectedDefinitions'], len(proof['Inputs'])), (5, 10, 31, 18))
        self.assertEqual(proof['SourceOwnershipInputs'], model.batch['SourceOwnershipInputs'])
        self.assertEqual(len(model.adapter.calls), 1)
        self.assertEqual([p['Group'] for p in model.adapter.calls[0]], list(m.GROUPS))
        self.assertEqual([b['CoverageNotes'] is None for b in proof['Compilations']], [True] * 4 + [False])
        expected = ['-mlibarch=armv7-m', '-march=armv7-m'] * 2
        for row in proof['Lowerings'] + [proof['FinalLink']]:
            for name in ('WpaOptions', 'LtransOptions'): self.assertEqual(row['ActualWorker'][name]['CanonicalWorkerArchitecture'], expected)
        for key in m.NONCLAIMS: self.assertIs(proof[key], False)

    def test_link_script_explicit_read_hash_and_missing_role(self):
        model = Model();path = model.sr / 'tools/fixtures/classic_final_image/link.ld'
        self.assertNotIn(str(path), [d['Path'] for s in model.native['Sources'] for d in s['ActualCompileDependencies']])
        proof = model.run();self.assertEqual(proof['AuthorityInputs']['LinkScript'], dict(Path=str(path), Sha256=sha(model.files[path])))
        self.assertIn((path, sha(model.files[path])), model.reads)
        for defect in ('hash', 'missing', 'authority'):
            model = Model();path = model.sr / 'tools/fixtures/classic_final_image/link.ld'
            if defect == 'hash': model.files[path] += b'foreign'
            elif defect == 'missing': del model.files[path]
            else: del model.batch['InputHashes'][str(path)];model.files[model.root / 'results.json'] = encoded(model.batch)
            with self.subTest(defect=defect), self.assertRaises(ValueError): model.run()

    def test_exact_helpers_and_authority_receipts(self):
        model = Model();helpers = {k: H[k] for k in m.HELPERS if k != 'port_lowered'};helpers['port_lowered'] = model.adapter;helpers['foreign'] = object()
        with self.assertRaises(ValueError): model.run(helpers=helpers)
        for defect in ('native', 'batch', 'seed', 'mode', 'built'):
            model = Model()
            if defect == 'native': model.native['Foreign'] = True
            elif defect == 'batch': model.files[model.root / 'results.json'] = encoded({})
            elif defect == 'seed': model.batch['SourceSeed'] = 'C:/foreign/seed'
            elif defect == 'mode': model.batch['Mode'] = 'O2-lto'
            else: model.batch['PortPolicyBuilt'] = False
            with self.subTest(defect=defect), self.assertRaises(ValueError): model.run()

    def test_all_thirty_six_per_command_copies(self):
        for index in range(98, 134):
            model = Model();path = model.root / ('commands/%03d.json' % index);row = json.loads(model.files[path]);row['Argv'][0] = 'C:/foreign/tool.exe'
            model.files[path] = encoded(row);model.catalog()
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, 'per-command'): model.run()

    def test_both_copies_foreign_tool_or_operand(self):
        for index in range(98, 134):
            for position in (0, -1):
                model = Model();model.batch['Commands'][index]['Argv'][position] = 'C:/foreign/input.o';model.refresh()
                with self.subTest(index=index, position=position), self.assertRaises(ValueError): model.run()

    def test_terminal_types_and_streams(self):
        for index in (98, 99, 100, 101, 102, 103, 114, 120, 131, 133):
            for key, value in (('Exit', False), ('ExpectedExit', False), ('TimedOut', 0), ('Seconds', True), ('State', 'RUNNING'), ('JournalErrors', ['bad'])):
                model = Model();model.batch['Commands'][index][key] = value;model.refresh()
                with self.subTest(index=index, key=key), self.assertRaises(ValueError): model.run()
            model = Model();model.change(index, stderr=b'' if index in m.LOWERS else b'warning: foreign')
            with self.subTest(index=index, key='stderr'), self.assertRaises(ValueError): model.run()

    def test_empty_supported_stress_imports_are_hashed(self):
        model = Model();self.assertEqual(model.streams[120][0], b'');proof = model.run()
        self.assertEqual(proof['Compilations'][3]['IRImports']['Imports'], [])
        self.assertEqual(proof['CommandBindings'][22]['Stdout']['Sha256'], sha(b''))
        model = Model();model.change(120, stdout=b'         U __gcov_init\n')
        with self.assertRaisesRegex(ValueError, 'streams'): model.run()

    def test_specs_original_adapted_hashes_and_comparison_target(self):
        for defect in ('original', 'adapted', 'stored', 'dumpspecs'):
            model = Model()
            if defect == 'original': model.files[model.original_specs] += b'foreign'
            elif defect == 'adapted': model.files[model.specs] += b'foreign'
            elif defect == 'stored': model.batch['PortPolicyDriverAdapter']['InstrumentationCounterFlagsAdded'] = True
            else: model.change(98, stdout=model.files[model.original_specs] + b'foreign')
            model.refresh()
            with self.subTest(defect=defect), self.assertRaises(ValueError): model.run()

    def test_sources_independently_derived_and_original_hashes(self):
        for name in m.OWNERSHIP + m.SELECTED:
            model = Model();model.files[model.sr / name] += b'\nforeign\n';model.refresh()
            with self.subTest(name=name), self.assertRaises(ValueError): model.run()
        for pos in range(5):
            model = Model();row = model.batch['PortPolicyCompilations'][pos];foreign = model.root / 'foreign.c'
            model.files[foreign] = model.files[Path(row['Source'])];row['Source'] = str(foreign);model.refresh()
            with self.subTest(pos=pos), self.assertRaises(ValueError): model.run()

    def test_stress_identical_source_and_exact_private_namespaces(self):
        for defect in ('changed', 'foreign', 'paired'):
            model = Model();path = model.root / 'port-policy/private/stress-raw/stress.c'
            if defect == 'changed': model.files[path] += b'foreign'
            elif defect == 'foreign': model.files[path.parent / 'foreign.h'] = b'foreign'
            else: model.batch['PortPolicyPairedStress']['SameSourceBytes'] = False
            model.refresh()
            with self.subTest(defect=defect), self.assertRaises(ValueError): model.run()

    def test_compile_flags_and_mt_mf_source_output_provenance(self):
        for _, _, first, _ in m.BUILDS:
            for defect in ('flags', 'source', 'output', 'mt', 'mf'):
                model = Model();args = model.batch['Commands'][first + 1]['Argv']
                if defect == 'flags': args[args.index('-Os')] = '-O2'
                elif defect == 'source': args[args.index('-c') + 1] = 'C:/foreign/source.c'
                elif defect == 'output': args[-1] = 'C:/foreign/object.o'
                elif defect == 'mt': args[args.index('-MT') + 1] = 'foreign-target'
                else: args[args.index('-MF') + 1] = 'C:/foreign/dependency.d'
                model.refresh()
                with self.subTest(first=first, defect=defect), self.assertRaises(ValueError): model.run()

    def test_dependency_actual_bytes_and_pair_accounting(self):
        model = Model();proof = model.run()
        self.assertEqual((proof['DependencyPairEntries'], proof['DependencyListedRows'], proof['UniqueDependencyPaths']), (10, 20, 6))
        for pos in range(5):
            for defect in ('missing', 'foreign', 'target', 'different'):
                model = Model();row = model.batch['PortPolicyCompilations'][pos];path = Path(row['CompileDependencyFile']);raw = model.files[path]
                if defect == 'missing': raw = (('pilot-source-' + str(row['TemplateIndex'])) + ': ' + str(model.external) + '\n').encode()
                elif defect == 'foreign': raw = raw.rstrip() + b' C:/foreign/header.h\n'
                elif defect == 'target': raw = raw.replace(b'pilot-source-', b'foreign-source-')
                else: raw = raw.replace(str(model.external).encode(), b'')
                model.files[path] = raw;model.refresh()
                with self.subTest(pos=pos, defect=defect), self.assertRaises(ValueError): model.run()
        model = Model();row = model.batch['PortPolicyCompilations'][0];path = Path(row['CompileDependencyFile'])
        model.files[path] = model.files[path].rstrip() + (' ' + row['Source'] + '\n').encode();model.refresh()
        self.assertEqual(model.run()['DependencyPairEntries'], 10)

    def test_slim_elf_and_full_section_columns(self):
        for _, _, first, _ in m.BUILDS:
            for column in (6, 7, 8, 9):
                model = Model();raw = model.streams[first + 2][0];lines = raw.decode().splitlines()
                line = next(i for i, text in enumerate(lines) if '.text ' in text);parts = lines[line].split()
                # ES, Lk, Inf, Al are the final fields around the AX flag.
                position = {6: -5, 7: -3, 8: -2, 9: -1}[column];parts[position] = '9';lines[line] = ' '.join(parts)
                model.change(first + 2, stdout=('\n'.join(lines) + '\n').encode())
                with self.subTest(first=first, column=column), self.assertRaises(ValueError): model.run()
        model = Model();row = model.batch['PortPolicyCompilations'][0];obj = Path(row['Object']);model.files[obj] = fixture.elf('fat', True)
        row['ObjectSha256'] = sha(model.files[obj]);model.refresh()
        with self.assertRaises(ValueError): model.run()

    def test_plugin_import_grammar_and_saved_import_targets(self):
        for raw in (b'foreign ? 0\n', b' U valid\nforeign\n', b' U duplicate\n U duplicate\n', b' U bad-name\n'):
            model = Model();model.change(102, stdout=raw)
            with self.subTest(raw=raw), self.assertRaises(ValueError): model.run()
        model = Model();model.batch['PortPolicyCompilations'][0]['IRImports']['Imports'] = ['forged'];model.refresh()
        with self.assertRaises(ValueError): model.run()

    def test_exact_definition_role_name_kind_value_size_catalog(self):
        model = Model();proof = model.run()
        weak = next(r for r in proof['IRDefinitionSurface']['Definitions'] if r['Name'] == 'fiber_fallback_initial_msp');self.assertEqual(weak['Kind'], 'W')
        for pos, index in enumerate((103, 108, 113)):
            for defect in ('name', 'kind', 'value', 'size', 'unknown', 'duplicate', 'role'):
                model = Model();rows = copy.deepcopy(model.batch['PortPolicyCompilations'][pos]['IRDefinitions'])
                if defect == 'name': rows[0]['Name'] = 'foreign'
                elif defect == 'kind': rows[0]['Kind'] = 'D'
                elif defect == 'value': rows[0]['Value'] = 1
                elif defect == 'size': rows[0]['Size'] = 4
                elif defect == 'unknown': rows.append(dict(Name='foreign', Kind='?', Value=0, Size=None))
                elif defect == 'duplicate': rows.append(copy.deepcopy(rows[0]))
                else: rows = copy.deepcopy(model.batch['PortPolicyCompilations'][(pos + 1) % 3]['IRDefinitions'])
                raw = ''.join(r['Name'] + ' ' + r['Kind'] + ' ' + format(r['Value'], 'x') + (' ' + format(r['Size'], 'x') if r['Size'] is not None else '') + '\n' for r in rows).encode()
                model.change(index, stdout=raw)
                with self.subTest(index=index, defect=defect), self.assertRaises(ValueError): model.run()
        model = Model();model.batch['PortPolicyIRDefinitionSurface']['Definitions'][0]['Name'] = 'forged';model.refresh()
        with self.assertRaises(ValueError): model.run()

    def test_wpa_exact_stage_and_canonical_output_list(self):
        model = Model();output = m._layout(model.root, 'selected');path = Path(str(output) + '.ltrans_args')
        self.assertIn(('-fltrans-output-list=' + str(output) + '.ltrans.out').encode(), model.files[path]);model.run()
        for suffix in ('.ltrans_args', '.ltrans0.ltrans_args'):
            for defect in ('stage', 'alias', 'split', 'foreign', 'duplicate', 'response'):
                model = Model();output = m._layout(model.root, 'selected');path = Path(str(output) + suffix);raw = model.files[path]
                marker = b'-fwpa\n' if suffix == '.ltrans_args' else b'-fltrans\n'
                if defect == 'stage': raw = raw.replace(marker, b'-fwpa=foreign\n')
                elif defect == 'alias': raw += b'--fltrans-output-list=foreign\n'
                elif defect == 'split': raw += b'-fltrans-output-list\nC:/foreign/out\n'
                elif defect == 'foreign': raw += b'-fltrans-output-list=C:/foreign/out\n'
                elif defect == 'duplicate': raw += ('-fltrans-output-list=' + str(output) + '.ltrans.out\n').encode()
                else: raw += b'@C:/foreign/response\n'
                model.files[path] = raw;model.refresh()
                with self.subTest(suffix=suffix, defect=defect), self.assertRaises(ValueError): model.run()

    def test_saved_policy_and_only_raw_specs(self):
        for group in m.GROUPS:
            for suffix in ('.ltrans_args', '.ltrans0.ltrans_args'):
                for flag in ('-O2', '-mcpu=cortex-m4', '-marm', '-flto-partition=balanced', '-flinker-output=rel', '--specs=foreign', '-specs', '-specs=C:/foreign/specs'):
                    model = Model();path = Path(str(m._layout(model.root, group)) + suffix);model.files[path] += (flag + '\n').encode();model.refresh()
                    with self.subTest(group=group, suffix=suffix, flag=flag), self.assertRaises(ValueError): model.run()

    def test_aggregate_output_is_not_an_input_and_replacement_is_exact(self):
        model = Model();proof = model.run()
        for index in (114, 121, 128):
            args = proof['CommandBindings'][index - 98]['Argv'];self.assertTrue(args[-1].endswith('aggregate.o'))
            self.assertEqual(args[-2], '-o')
            model = Model();args = model.batch['Commands'][index]['Argv'];args[args.index('-o') - 1] = args[-1];model.refresh()
            with self.subTest(index=index), self.assertRaises(ValueError): model.run()

    def test_final_nine_order_and_unchanged_other_six(self):
        model = Model();proof = model.run();self.assertEqual([r['Index'] for r in proof['FinalLink']['UnchangedOtherSixObjects']], [0, 1, 2, 6, 7, 8])
        for defect in ('object', 'order', 'map', 'emit', 'output', 'other'):
            model = Model();args = model.batch['Commands'][131]['Argv']
            if defect == 'object': args[args.index(str(model.objects[0]))] = 'C:/foreign/input.o'
            elif defect == 'order': i = args.index(str(model.objects[0]));args[i], args[i + 1] = args[i + 1], args[i]
            elif defect == 'map': args[args.index(next(a for a in args if a.startswith('-Wl,-Map=')))] = '-Wl,-Map=C:/foreign/map'
            elif defect == 'emit': args.remove('-Wl,--emit-relocs')
            elif defect == 'output': args[-1] = 'C:/foreign/output.elf'
            else: model.batch['PortPolicyFinalLink']['UnchangedOtherSixObjects'][0]['Sha256'] = 'A' * 64
            model.refresh()
            with self.subTest(defect=defect), self.assertRaises(ValueError): model.run()

    def test_saved_namespace_wrapper_and_dump_hash_joins(self):
        for defect in ('extra', 'missing', 'wrapper', 'dump', 'zero'):
            model = Model();output = m._layout(model.root, 'selected')
            if defect == 'extra': model.files[output.parent / 'foreign.txt'] = b'foreign'
            elif defect == 'missing': del model.files[Path(str(output) + '.res')]
            elif defect == 'wrapper': model.files[Path(str(output) + '.lto_wrapper_args')] = b'second owner'
            elif defect == 'dump': model.files[Path(str(output) + '.dis')] += b'foreign'
            else: model.batch['Commands'][115]['Argv'].remove('-z')
            model.refresh()
            with self.subTest(defect=defect), self.assertRaises(ValueError): model.run()

    def test_all_stored_worker_targets_are_comparison_only(self):
        for pos in range(4):
            for defect in ('extra', 'machine', 'specs', 'options', 'execution'):
                model = Model();worker = (model.batch['PortPolicyLowerings'][pos] if pos < 3 else model.batch['PortPolicyFinalLink'])['ActualWorker']
                if defect == 'extra': worker['CompilerExecuted'] = True
                elif defect == 'machine': worker['MachineSha256'] = 'A' * 64
                elif defect == 'specs': worker['DriverSpecs'] = dict(Path='C:/foreign/specs', Sha256='A' * 64)
                elif defect == 'options': worker['WpaOptions']['AttributeEffectsValidated'] = True
                else: worker['Execution']['OsProcessTraceVerified'] = True
                model.refresh()
                with self.subTest(pos=pos, defect=defect), self.assertRaises(ValueError): model.run()

    def test_result_schema_nonclaims_catalogs_and_read_joins(self):
        proof = Model().run()
        for key in m.COUNTS:
            row = copy.deepcopy(proof);row[key] = True
            with self.subTest(key=key), self.assertRaises(ValueError): m.require_result(row)
        for key in m.NONCLAIMS:
            row = copy.deepcopy(proof);row[key] = True
            with self.subTest(key=key), self.assertRaises(ValueError): m.require_result(row)
        for path in ((), ('Compilations', 0), ('FinalLink',), ('Inputs', 'Final/ELF'), ('SourceOwnership',), ('IRDefinitionSurface',)):
            row = copy.deepcopy(proof);target = row
            for part in path: target = target[part]
            target['ForeignClaim'] = False
            with self.subTest(path=path), self.assertRaises(ValueError): m.require_result(row)
        for defect in ('ownership', 'definition', 'role', 'read', 'count', 'cohort'):
            row = copy.deepcopy(proof)
            if defect == 'ownership': row['SourceOwnership']['CheckedFunctions'][1] = copy.deepcopy(row['SourceOwnership']['CheckedFunctions'][0])
            elif defect == 'definition': row['IRDefinitionSurface']['Definitions'][0]['Role'] = 'foreign'
            elif defect == 'role': row['Inputs']['Final/ELF']['Role'] = 'foreign'
            elif defect == 'read': row['ReadInputs'].pop();row['ReadFiles'] -= 1
            elif defect == 'count': row['DependencyListedRows'] += 1
            else: row['SourceCohort'][0]['NativeObjectSha256'] = 'A' * 64
            with self.subTest(defect=defect), self.assertRaises(ValueError): m.require_result(row)

    def test_real_adapter_validator_at_outer_boundary(self):
        proof = Model().run();helpers = {k: H[k] for k in m.ADAPTER_HELPERS}
        self.assertIs(H['port_lowered'].require_result(proof['LoweredProofs'], helpers), proof['LoweredProofs'])
        for defect in ('metadata', 'role', 'control', 'deep-function', 'deep-stress', 'vector'):
            row = copy.deepcopy(proof);nested = row['LoweredProofs']
            if defect == 'metadata': nested['ToolInvocations'] = True
            elif defect == 'role': nested['Inputs']['Final/ELF']['Role'] = 'foreign'
            elif defect == 'control': nested['ControlBytes'][next(iter(nested['ControlBytes']))] += '00'
            elif defect == 'deep-function': nested['Machines'][0]['Images'][0]['Proof']['FunctionEvidence'][0]['Name'] = 'foreign'
            elif defect == 'deep-stress': nested['Machines'][2]['Images'][0]['Proof']['Effects']['RootEvidence'][0]['WholePolicy'] = True
            else: nested['Machines'][3]['Images'][0]['Proof']['FinalRootVectorBindings']['CanonicalRootProtocolsValidated'] = True
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                m.require_result(row)
                H['port_lowered'].require_result(nested, helpers)

    def test_finite_json_duplicate_and_missing_roles(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): H['controls_replay']._json(raw)
        for suffix in ('.wpa.args.0', '.ltrans_args', '.ltrans0.ltrans.o'):
            model = Model();del model.files[Path(str(m._layout(model.root, 'selected')) + suffix)];model.refresh()
            with self.subTest(suffix=suffix), self.assertRaises(ValueError): model.run()

    def test_no_filesystem_process_or_input_mutation(self):
        model = Model();before = copy.deepcopy(model.batch);native = copy.deepcopy(model.native)
        def forbidden(*args, **kwargs): raise AssertionError('filesystem forbidden')
        with patch.object(Path, 'read_bytes', forbidden), patch.object(Path, 'read_text', forbidden), patch.object(Path, 'stat', forbidden), patch.object(Path, 'exists', forbidden), patch.object(Path, 'resolve', forbidden):
            proof = model.run()
        self.assertEqual(model.batch, before);self.assertEqual(model.native, native)
        proof['Compilations'][0]['CompileFlags'].clear();self.assertTrue(model.batch['PortPolicyCompilations'][0]['CompileFlags'])
        dependency_rows, unique = [], set()
        for raw, text, claim, before, after, target in REAL.values():
            header = H['transport'].require_elf32le(raw);H['controls_replay']._readelf_metadata(text.decode('ascii'), raw, header)
            self.assertEqual(H['controls_replay']._binary_sections(raw, header), claim['Sections'])
            a = H['deps'].parse(before, target=target);b = H['deps'].parse(after, target=target)
            self.assertEqual(a, b);dependency_rows.append(len(a));unique.update(a)
        self.assertEqual(dependency_rows, [38, 39, 36, 11, 11]);self.assertEqual((sum(dependency_rows), 2 * sum(dependency_rows), len(unique)), (135, 270, 43))


def initialize(helpers=None, *, parser_fixtures=False):
    """Snapshot every executed fixture/helper source before making a model."""
    global BUFFERS, H, REAL, m, fixture, lower_fixture
    BUFFERS, H, REAL = {}, {}, {}
    paths = dict(fixture=HERE / 'test_abi_controls_replay.py', controls_replay=HERE / 'abi_controls_replay.py', leaf=HERE / 'port_replay.py',
        deps=HERE / 'dependency_bytes.py', recipes=HERE / 'batch_recipes.py', declarations=HERE / 'declarations.py', ordinary=HERE.parent / 'ordinary_final_cell/abi.py',
        plan=HERE.parent / 'ordinary_final_cell/controls.py', diagnostics=HERE.parent / 'cm3_lto_abi_controls/diagnostics.py', probes=HERE.parent / 'cm0_final_cell/components.py',
        port_runner=HERE.parent / 'cm3_lto_port_policy/runner.py', guard=HERE / 'batch_guard.py', transport=HERE.parent / 'cm3_lto_transport/probe.py',
        oracle=HERE.parent / 'cm0_final_cell/abi.py', ownership=HERE.parent / 'cm0_final_cell/ownership.py', attributes=HERE.parent / 'cm3_lto_attributes/attributes.py',
        port_phase=HERE / 'port_policy_phase.py', policy=HERE.parent / 'cm3_lto_port_policy/policy.py', census=HERE / 'port_census.py', effects=HERE / 'common_effects.py',
        port_lowered=HERE / 'port_lowered.py', lower_fixture=HERE / 'test_port_lowered.py',
        port_model=HERE.parent / 'cm3_lto_port_policy/test_policy.py', stress_model=HERE / 'test_common_effects.py')
    fixture_raw = paths['fixture'].read_bytes();fixture = types.ModuleType('_port_test_fixture');fixture.__file__ = str(paths['fixture'])
    exec(compile(fixture_raw, str(paths['fixture']), 'exec'), fixture.__dict__)
    project = fixture.HEADERS + fixture.ORDER + fixture.EXTRA + ('context/context_api_decl.h', 'tools/runtime_sources.json')
    sources = list(dict.fromkeys([Path(__file__).resolve(), *paths.values(), *(ROOT / n for n in project)]))
    real = {}
    if parser_fixtures:
        actual = Path('C:/fzosbatch-20261107-e1');batch_path, manifest_path = actual / 'results.json', actual / 'artifacts.json'
        batch_raw, manifest_raw = batch_path.read_bytes(), manifest_path.read_bytes()
        if sha(batch_raw) != '3DCE7C453AF909B6B917B9A3EED552F1725D70ED9420CEA74A36797ADB12EEC7' or sha(manifest_raw) != '35E2A0B0895AD8458F8476C8E6F672176E39687B69137804E3342DDC663BD635':
            raise ValueError('sealed raw parser fixture drift')
        batch, manifest = json.loads(batch_raw), json.loads(manifest_raw)['Artifacts'];sources.extend((batch_path, manifest_path))
        for row in batch['PortPolicyCompilations']:
            index = row['CommandIndices'][2];obj = Path(row['Object']);stdout = actual / ('commands/%03d.stdout' % index)
            before, after = Path(row['DiscoveryDependencyFile']), Path(row['CompileDependencyFile'])
            sources.extend((obj, stdout, before, after));real[index] = (obj, stdout, row['SlimIR'], before, after, 'pilot-source-' + str(row['TemplateIndex']))
    sources = list(dict.fromkeys(sources))
    BUFFERS = {p: p.read_bytes() for p in sources}
    if BUFFERS[paths['fixture']] != fixture_raw: raise ValueError('opening fixture drift')
    if parser_fixtures and (BUFFERS[batch_path] != batch_raw or BUFFERS[manifest_path] != manifest_raw): raise ValueError('opening parser fixture drift')
    for index, (obj, stdout, claim, before, after, target) in real.items():
        for path in (obj, stdout, before, after):
            if sha(BUFFERS[path]) != manifest[path.relative_to(actual).as_posix()]: raise ValueError('manifest-bound parser fixture')
        if sha(BUFFERS[obj]) != claim['Sha256'] or sha(BUFFERS[stdout]) != batch['Commands'][index]['StdoutSha256']: raise ValueError('parser fixture role drift')
        REAL[index] = (BUFFERS[obj], BUFFERS[stdout], claim, BUFFERS[before], BUFFERS[after], target)
    for name, path in paths.items():
        if name in ('fixture', 'oracle', 'port_model'): continue
        module = types.ModuleType('_port_test_' + name);module.__file__ = str(path)
        def buffered_read(p):
            if p not in BUFFERS: raise AssertionError('unenrolled helper read/' + str(p))
            return BUFFERS[p]
        with patch.object(Path, 'read_bytes', buffered_read): exec(compile(BUFFERS[path], str(path), 'exec'), module.__dict__)
        if name == 'leaf': m = module
        else: H[name] = module
    if helpers is not None:
        if type(helpers) is not dict or not set(m.HELPERS) | {'port_replay'} <= set(helpers): raise ValueError('explicit real composition helper subset')
        m = helpers['port_replay'];H.update({k: helpers[k] for k in H if k in helpers})
    fixture.BUFFERS = BUFFERS;fixture.m = H['controls_replay'];fixture.H = {k: H[k] for k in
        ('deps', 'recipes', 'declarations', 'ordinary', 'plan', 'diagnostics', 'probes', 'port_runner', 'guard', 'transport')}
    # The old synthetic policy model imports its policy. Supply the already
    # buffered module instead of allowing a second physical source load.
    module = types.ModuleType('_port_test_port_model');module.__file__ = str(paths['port_model'])
    loader = types.SimpleNamespace(exec_module=lambda module: None)
    with patch.object(importlib.util, 'spec_from_file_location', return_value=types.SimpleNamespace(loader=loader)), \
            patch.object(importlib.util, 'module_from_spec', return_value=H['policy']):
        exec(compile(BUFFERS[paths['port_model']], str(paths['port_model']), 'exec'), module.__dict__)
    H['port_model'] = module;lower_fixture = H['lower_fixture'];lower_fixture.API = H['port_lowered']
    lower_fixture.H = {k: H[k] for k in m.ADAPTER_HELPERS};lower_fixture.M = dict(H)
    return sources


def synthetic_result(helpers):
    """Composer regression fixture: real validators, invented journals/images."""
    initialize(helpers)
    return Model().run()


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False);parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args();output = args.output_dir.absolute();temporary = Path(tempfile.gettempdir()).absolute()
    if output.exists() or output.is_relative_to(ROOT) or not output.is_relative_to(temporary): parser.error('fresh external TEMP output required')
    sources = initialize(parser_fixtures=True);opening = {str(p): sha(raw) for p, raw in BUFFERS.items()}
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(PortTests))
    closing = {str(p): sha(p.read_bytes()) for p in sources}
    report = dict(Status='PASS' if result.wasSuccessful() and result.testsRun == METHODS and not result.skipped and opening == closing else 'FAIL',
        Tests=result.testsRun, ExpectedTests=METHODS, Errors=len(result.errors), Failures=len(result.failures), Skipped=len(result.skipped),
        SourceHashes=opening, SourceDrift=opening != closing, ClosingFilesVerified=sum(opening[k] == v for k, v in closing.items()),
        SyntheticBindingReplayOnly=True, ActualFullReplayPerformed=False, RealSlimParserFixtures=len(REAL),
        ActualMachinePredicatesExercised=False, CompilerExecuted=False, BoardExecution=False, Qualification=False, RequiredCellsSatisfied=0)
    output.mkdir(parents=True);raw = encoded(report);(output / 'results.json').write_bytes(raw)
    print(json.dumps({k: v for k, v in report.items() if k != 'SourceHashes'}, sort_keys=True));print('ReceiptSha256=' + sha(raw))
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
