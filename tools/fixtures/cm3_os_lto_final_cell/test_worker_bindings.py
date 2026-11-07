"""Synthetic journal/cohort corruption controls, never actual compiler evidence."""

import argparse
import copy
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
METHODS = 30
m = HELPERS = None


def sha(raw):
    return hashlib.sha256(raw).hexdigest().upper()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode('ascii')


def saved(values):
    return ('\n'.join(arg.replace('\\', '\\\\') for arg in values) + '\n').encode('ascii')


class Model:
    """All paths and file bytes are invented and held in dictionaries."""
    def __init__(self):
        self.root = Path('C:/synthetic-worker-bindings/batch')
        self.external = self.root.parent / 'native'
        self.gcc = self.external / 'toolchain/bin/arm-none-eabi-gcc.exe'
        self.objdump = self.gcc.with_name('arm-none-eabi-objdump.exe')
        self.files, self.streams, self.reads = {}, {}, []
        self.batch = dict(Status='BUILT-PENDING-READER', Profile='CM3', Mode='Os-lto',
                          Linkage='direct', LTO=True, Commands=[])
        self.native = dict(Status='PASS', Profile='CM3', Mode='Os-lto', Linkage='direct', LTO=True,
                           CapturedCompiler=str(self.gcc), Sources=[])
        for index in range(134):
            self.journal(index, 'unused synthetic command', ['synthetic-unused'])
        self.flags = ['-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft', '-Os', '-flto', '-fno-fat-lto-objects']
        self.raw_flags = self.flags + list(m.RAW)
        self.supported_flags = self.raw_flags + list(m.COUNTERS)
        self.seed = self.root.parent / 'seed'
        relative_sources = tuple('context/' + stem + '.c' for stem in m.STEMS)
        relative_sources += tuple('fiber/port/ARM_CM3/' + stem + '.c' for stem in m.PORT_STEMS)
        relative_sources += ('fiber/port/fiber_port_context_cohort_expectation.c',
                             'tools/fixtures/classic_final_image/application.c',
                             'tools/fixtures/classic_final_image/startup.S')
        originals = []
        for index, relative in enumerate(relative_sources):
            source = self.seed / 'source' / relative
            source_binding = self.put(source, ('synthetic separately admitted native source/' + relative).encode('ascii'))
            path = self.external / 'objects' / ('%02d-original.o' % index)
            binding = self.put(path, ('synthetic separately admitted native object/%d' % index).encode('ascii'))
            self.native['Sources'].append(dict(Source=str(source), SourceSha256=source_binding['Sha256'],
                                               Object=str(path), ObjectSha256=binding['Sha256']))
            originals.append(path)
        self.native['SeedBuild'] = str(self.seed)
        common_specs, common_adapter = self.adapter('attributes/driver', 53)
        port_specs, port_adapter = self.adapter('port-policy/driver', 98)
        common = dict(Compilations=[], Lowerings=[], DriverAdapter=common_adapter)
        self.batch['CommonAttributesDeferredReader'] = common
        common_ir = []
        for position, (group, index, first) in enumerate((('positive', 0, 54), ('positive', 1, 58),
                ('positive', 2, 62), ('mutant-engine', 0, 68), ('mutant-state', 1, 74),
                ('mutant-panic', 2, 80), ('stress-protected', 0, 86), ('stress-unprotected', 0, 92))):
            stem = 'stress' if position >= 6 else m.STEMS[index]
            path = self.root / 'attributes/ir' / group / (stem + '.o')
            binding = self.put(path, ('synthetic common IR/' + group + '/' + stem).encode('ascii'))
            row = dict(Group=group, TemplateIndex=index, Role=('engine', 'state', 'panic')[index],
                       Object=str(path), ObjectSha256=binding['Sha256'], CompileFlags=list(self.raw_flags),
                       CommandIndices=list(range(first, first + 4)))
            if position < 3:
                source = Path(self.native['Sources'][index]['Source'])
            else:
                private = self.root / 'private' / ('attributes-' + group)
                source = private / 'stress.c' if position >= 6 else private / 'context' / (stem + '.c')
            self.compilation(row, first, source)
            common['Compilations'].append(row)
            common_ir.append(path)
        cohorts = [common_ir[:3]]
        for index in range(3):
            objects = common_ir[:3]
            objects[index] = common_ir[index + 3]
            cohorts.append(objects)
        cohorts += [[common_ir[6]], [common_ir[7]]]
        for position, (group, first, objects) in enumerate(zip(m.COMMON, (66, 72, 78, 84, 90, 96), cohorts)):
            output = self.root / 'attributes/lowered' / group / 'aggregate.o'
            row = self.lower(output, group, first, objects, common_specs, None, common=True)
            row.update(Mutation=m.MUTATIONS[position], Stress=position >= 4)
            common['Lowerings'].append(row)

        self.batch.update(PortPolicyDriverAdapter=port_adapter, PortPolicyCompilations=[], PortPolicyLowerings=[])
        port_ir = []
        for position, (group, index, first, count) in enumerate((('selected', 3, 99, 5),
                ('selected', 4, 104, 5), ('selected', 5, 109, 5),
                ('stress-supported', 3, 117, 4), ('stress-raw', 3, 124, 4))):
            stem = m.PORT_STEMS[position] if position < 3 else 'stress'
            path = self.root / 'port-policy/ir' / group / (stem + '.o')
            binding = self.put(path, ('synthetic port IR/' + group + '/' + stem).encode('ascii'))
            row = dict(Group=group, TemplateIndex=index,
                Object=str(path), ObjectSha256=binding['Sha256'], SupportedPolicy=group != 'stress-raw',
                CompileFlags=list(self.supported_flags if group != 'stress-raw' else self.raw_flags),
                CommandIndices=list(range(first, first + count)))
            source = (Path(self.native['Sources'][index]['Source']) if position < 3 else
                      self.root / 'port-policy/private' / group / 'stress.c')
            self.compilation(row, first, source, port=True)
            self.batch['PortPolicyCompilations'].append(row)
            port_ir.append(path)
        for position, (group, first, objects) in enumerate(zip(m.PORT, (114, 121, 128),
                                                             (port_ir[:3], [port_ir[3]], [port_ir[4]]))):
            output = self.root / 'port-policy/lowered' / group / 'aggregate.o'
            self.batch['PortPolicyLowerings'].append(self.lower(output, group, first, objects,
                port_specs if position == 2 else None, position != 2))

        original_output = self.external / 'ordinary/image.elf'
        original_map = original_output.with_suffix('.map')
        original = [str(self.gcc), *self.flags[:4], '-flto', *m.SAVED, '-nostdlib',
                    '-Wl,--gc-sections,--no-undefined,--fatal-warnings', '-T', str(self.external / 'link.ld'),
                    *map(str, originals), '-Wl,-Map=' + str(original_map), '-o', str(original_output)]
        self.native.update(Commands=[dict(Label='link ordinary', Argv=original)], Links=[dict(Path=str(original_output))])
        output = self.root / 'port-policy/final-supported/image.elf'
        link_map = output.with_suffix('.map')
        objects = originals[:3] + port_ir[:3] + originals[6:]
        replacements = {str(old): str(new) for old, new in zip(originals, objects)}
        replacements[str(original_output)] = str(output)
        argv = ['-Wl,-Map=' + str(link_map) if arg.startswith('-Wl,-Map=') else replacements.get(arg, arg)
                for arg in original]
        start = argv.index(str(objects[0]))
        argv[start:start] = ['-Wl,--emit-relocs', *m.RAW, *m.COUNTERS]
        final = self.lower(output, 'final-supported', 131, objects, None, True, final_argv=argv)
        binding, map_binding = self.binding(output), self.put(link_map, b'synthetic final map')
        final.update(Path=str(output), Sha256=binding['Sha256'], Map=str(link_map),
                     MapSha256=map_binding['Sha256'], Objects=list(map(str, objects)),
                     OriginalFinalStageArgv=copy.deepcopy(original), Argv=argv,
                     UnchangedOtherSixObjects=[dict(Index=index, **self.binding(originals[index]))
                                               for index in (0, 1, 2, 6, 7, 8)])
        self.batch['PortPolicyFinalLink'] = final
        self.seal()

    def put(self, path, value):
        self.files[Path(path)] = value
        return self.binding(path)

    def binding(self, path):
        return dict(Path=str(path), Sha256=sha(self.files[Path(path)]))

    def journal(self, index, label, argv, stdout=b'', stderr=b''):
        prefix = 'commands/%03d' % index
        row = dict(Label=label, Argv=list(argv), Cwd=str(self.root), State='TERMINAL', Status='PASS',
                   Exit=0, ExpectedExit=0, TimedOut=False, Seconds=0.25,
                   Stdout=prefix + '.stdout', Stderr=prefix + '.stderr',
                   StdoutSha256=sha(stdout), StderrSha256=sha(stderr))
        commands = self.batch['Commands']
        if index == len(commands):
            commands.append(row)
        else:
            commands[index] = row
        self.streams[index] = (stdout, stderr)

    def adapter(self, directory, index):
        source = b'*lib:\n%{fprofile-arcs|fcondition-coverage|fprofile-generate*|coverage:-lgcov}\n'
        rebuilt = HELPERS['attributes'].adapt_specs(source)
        original, adapted = self.root / directory / 'original.specs', self.root / directory / 'no-auto-gcov.specs'
        self.put(original, source)
        self.put(adapted, rebuilt['Specs'])
        self.journal(index, 'dump compiler specs', [str(self.gcc), '-dumpspecs'], stdout=source)
        record = {key: value for key, value in rebuilt.items() if key != 'Specs'}
        record.update(OriginalPath=str(original), AdaptedPath=str(adapted))
        return adapted, record

    def compilation(self, row, first, source, *, port=False):
        if source not in self.files:
            self.put(source, ('synthetic private compilation source/' + str(source)).encode('ascii'))
        row.update(Source=str(source), SourceSha256=self.binding(source)['Sha256'])
        obj = Path(row['Object'])
        discovery, actual = obj.with_suffix('.discovery.d'), obj.with_suffix('.compile.d')
        target = 'pilot-source-' + str(row['TemplateIndex'])
        for path in (discovery, actual):
            self.put(path, (target + ': ' + str(source) + '\n').encode('ascii'))
        if port:
            row.update(DiscoveryDependencyFile=str(discovery), CompileDependencyFile=str(actual))
        prefix = [str(self.gcc), *row['CompileFlags']]
        label = row['Group'] + ' ' + obj.stem
        self.journal(first, 'discover ' + label, [*prefix, '-M', '-MF', str(discovery), '-MT', target, str(source)])
        self.journal(first + 1, 'compile ' + label,
                     [*prefix, '-MD', '-MF', str(actual), '-MT', target, '-c', str(source), '-o', str(obj)])

    def lower(self, output, group, first, objects, specs, supported, *, common=False, final_argv=None):
        flags = self.supported_flags if supported else self.raw_flags
        argv = final_argv or [str(self.gcc), *flags, *([] if specs is None else ['-specs=' + str(specs)]),
                             *m.SAVED, '-nostdlib', '-r', '-flinker-output=nolto-rel',
                             *map(str, objects), '-o', str(output)]
        diagnostics = ('synthetic compiler reported worker transcript/' + str(first)).encode('ascii')
        self.journal(first, 'link final-supported' if final_argv else 'lower ' + group, argv, stderr=diagnostics)
        output_binding = self.put(output, ('synthetic output/' + str(output)).encode('ascii'))
        machine = Path(str(output) + '.ltrans0.ltrans.o')
        self.put(machine, b'synthetic worker object, not an ELF')
        ir = objects[:-1] if final_argv else objects
        lower = ['-flto-partition=one', '-nostdlib'] + ([] if final_argv else ['-r', '-flinker-output=nolto-rel'])
        spec_flags = [] if specs is None else ['-specs=' + str(specs)]
        wpa = [*flags, *lower, *spec_flags, '-fwpa', '-fltrans-output-list=' + str(output) + '.ltrans.out', *map(str, ir)]
        ltrans = [*flags, *lower, *spec_flags, '-fltrans', '-o', str(machine), str(output) + '.ltrans0.o']
        self.put(Path(str(output) + '.ltrans_args'), saved(wpa))
        self.put(Path(str(output) + '.ltrans0.ltrans_args'), saved(ltrans))
        dis_path = output.with_suffix('.dis') if common else Path(str(output) + '.dis')
        dis_bytes = ('synthetic zero-inclusive disassembly/' + str(output)).encode('ascii')
        dis = self.put(dis_path, dis_bytes)
        self.journal(first + 1, 'disassemble ' + group, [str(self.objdump), '-drwC', '-z', str(output)], stdout=dis_bytes)
        row = dict(Group=group, Inputs=[self.binding(path) for path in objects],
                   CommandIndices=list(range(first, first + (2 if common else 3))))
        if common:
            roles = dict(Object=output_binding, Machine=self.binding(machine), Disassembly=dis,
                         WpaArguments=self.binding(Path(str(output) + '.ltrans_args')),
                         LtransArguments=self.binding(Path(str(output) + '.ltrans0.ltrans_args')),
                         DriverSpecs=self.binding(specs), Diagnostics=dict(Path=str(self.root / ('commands/%03d.stderr' % first)),
                                                                          Sha256=sha(diagnostics)))
            row['Roles'] = roles
        else:
            worker_dis_path = Path(str(machine) + '.dis')
            worker_dis_bytes = ('synthetic zero-inclusive disassembly/' + str(machine)).encode('ascii')
            worker_dis = self.put(worker_dis_path, worker_dis_bytes)
            self.journal(first + 2, 'disassemble worker ' + group,
                         [str(self.objdump), '-drwC', '-z', str(machine)], stdout=worker_dis_bytes)
            row.update(Object=str(output), ObjectSha256=output_binding['Sha256'], SupportedPolicy=supported,
                       Disassembly=dis, WorkerDisassembly=worker_dis,
                       ActualWorker=dict(Untrusted=True, DriverSpecs=dict(Path='C:/never-read/forged.specs')))
        return row

    def seal(self):
        for index, row in enumerate(self.batch['Commands']):
            prefix = self.root / ('commands/%03d' % index)
            self.files[Path(str(prefix) + '.json')] = encoded(row)
            for suffix, value in zip(('.stdout', '.stderr'), self.streams[index]):
                self.files[Path(str(prefix) + suffix)] = value
        command_bytes = encoded(self.batch['Commands'])
        self.files[self.root / 'commands.json'] = command_bytes
        self.batch['CommandsSha256'] = sha(command_bytes)
        self.catalog()

    def catalog(self):
        manifest_path = self.root / 'artifacts.json'
        artifacts = {path.relative_to(self.root).as_posix(): sha(value) for path, value in self.files.items()
                     if path.is_relative_to(self.root) and path != manifest_path}
        self.files[manifest_path] = encoded(dict(Artifacts=artifacts))
        self.batch['InputHashes'] = {str(path): sha(value) for path, value in self.files.items() if path != manifest_path}

    def read(self, path, expected=None):
        if not isinstance(path, Path) or path not in self.files:
            raise AssertionError('unadmitted synthetic read/' + str(path))
        value = self.files[path]
        if expected is not None and sha(value) != expected:
            raise ValueError('synthetic reader hash mismatch')
        self.reads.append((path, expected))
        return value

    def run(self, reader=None, helpers=None):
        return m.bind(self.batch, self.root, self.native, reader or self.read, helpers or HELPERS)

    def compilations(self):
        return self.batch['CommonAttributesDeferredReader']['Compilations'] + self.batch['PortPolicyCompilations']

    def saved_path(self, chain=0, stage=0):
        if chain < 6:
            output = self.root / 'attributes/lowered' / m.COMMON[chain] / 'aggregate.o'
        elif chain < 9:
            output = self.root / 'port-policy/lowered' / m.PORT[chain - 6] / 'aggregate.o'
        else:
            output = self.root / 'port-policy/final-supported/image.elf'
        return Path(str(output) + ('.ltrans_args' if stage == 0 else '.ltrans0.ltrans_args'))

    def saved_edit(self, path, change):
        values = HELPERS['attribute_runner'].argument_lines(self.files[path])
        change(values)
        self.files[path] = saved(values)
        self.seal()


class BindingTests(unittest.TestCase):
    def test_ten_ordered_plans_have_exact_contract_and_no_semantic_claims(self):
        model = Model()
        result = model.run()
        self.assertEqual(len(result), 10)
        self.assertEqual([row['Group'] for row in result], list(m.COMMON) + list(m.PORT) + ['Final'])
        for index, row in enumerate(result):
            self.assertEqual(set(row), {'Component', 'Group', 'Output', 'Objects', 'Specs', 'Diagnostics', 'Supported', 'StoredWorker'})
            self.assertIsInstance(row['Output'], Path)
            self.assertIs(type(row['Objects']), list)
            self.assertIs(type(row['Diagnostics']), bytes)
            self.assertIs(row['Supported'], None if index < 6 else index != 8)
            if index < 6:
                self.assertIsNone(row['StoredWorker'])
            else:
                self.assertIs(type(row['StoredWorker']), dict)
        self.assertEqual([len(row['Objects']) for row in result], [3, 3, 3, 3, 1, 1, 3, 1, 1, 9])
        self.assertEqual(result[0]['Specs'], model.root / 'attributes/driver/no-auto-gcov.specs')
        self.assertEqual(result[8]['Specs'], model.root / 'port-policy/driver/no-auto-gcov.specs')
        self.assertIsNone(result[-1]['Specs'])

    def test_pure_bind_cannot_touch_filesystem_or_mutate_inputs(self):
        model = Model()
        opening = copy.deepcopy((model.batch, model.native, model.files))
        with ExitStack() as stack:
            for name in ('read_bytes', 'read_text', 'open', 'resolve', 'absolute', 'stat', 'lstat', 'exists',
                         'is_file', 'is_dir', 'samefile', 'iterdir', 'glob', 'rglob'):
                stack.enter_context(patch.object(Path, name, side_effect=AssertionError('physical Path operation/' + name)))
            for name in ('stat', 'lstat', 'listdir', 'scandir', 'getcwd', 'system'):
                stack.enter_context(patch.object(os, name, side_effect=AssertionError('physical os operation/' + name)))
            result = model.run()
        self.assertEqual(opening, (model.batch, model.native, model.files))
        result[6]['StoredWorker']['Untrusted'] = False
        self.assertTrue(model.batch['PortPolicyLowerings'][0]['ActualWorker']['Untrusted'])

    def test_canonical_actual_serialized_wpa_output_list_is_bound(self):
        model = Model()
        for chain in range(10):
            path = model.saved_path(chain)
            self.assertIn(b'\\\\', model.files[path])
            values = HELPERS['attribute_runner'].argument_lines(model.files[path])
            expected = '-fltrans-output-list=' + str(path)[:-len('.ltrans_args')] + '.ltrans.out'
            self.assertEqual([arg for arg in values if arg.startswith('-fltrans-output-list')], [expected])
        self.assertEqual(len(model.run()), 10)

    def test_wpa_output_list_missing_split_alias_duplicate_and_foreign_rejected(self):
        for chain in (0, 6, 8, 9):
            for defect in ('missing', 'split', 'long', 'duplicate', 'foreign', 'suffix-alias', 'dotdot'):
                model = Model()
                path = model.saved_path(chain)
                def change(values):
                    index = next(i for i, arg in enumerate(values) if arg.startswith('-fltrans-output-list='))
                    arg = values[index]
                    values[index:index + 1] = {
                        'missing': [], 'split': ['-fltrans-output-list', arg.split('=', 1)[1]],
                        'long': ['-' + arg], 'duplicate': [arg, arg],
                        'foreign': ['-fltrans-output-list=C:/foreign.ltrans.out'],
                        'suffix-alias': [arg.replace('-fltrans-output-list=', '-fltrans-output-list-alias=')],
                        'dotdot': [arg.replace('.ltrans.out', '/../image.ltrans.out')],
                    }[defect]
                model.saved_edit(path, change)
                with self.subTest(chain=chain, defect=defect), self.assertRaises(m.Rejected):
                    model.run()

    def test_output_list_not_permitted_in_ltrans_or_driver(self):
        for where in ('ltrans', 'driver'):
            model = Model()
            if where == 'ltrans':
                model.saved_edit(model.saved_path(stage=1), lambda values: values.append('-fltrans-output-list=C:/foreign'))
            else:
                model.batch['Commands'][66]['Argv'].append('-fltrans-output-list=C:/foreign')
                model.seal()
            with self.subTest(where=where), self.assertRaises(m.Rejected):
                model.run()

    def test_fixed_compilation_order_indices_counts_and_types(self):
        for defect in ('common-order', 'common-template', 'common-range', 'common-count', 'port-order', 'port-template', 'port-policy'):
            model = Model()
            common = model.batch['CommonAttributesDeferredReader']['Compilations']
            port = model.batch['PortPolicyCompilations']
            if defect == 'common-order':
                common.reverse()
            elif defect == 'common-template':
                common[0]['TemplateIndex'] = False
            elif defect == 'common-range':
                common[0]['CommandIndices'] = [54, 55, 56]
            elif defect == 'common-count':
                common.pop()
            elif defect == 'port-order':
                port.reverse()
            elif defect == 'port-template':
                port[0]['TemplateIndex'] = 4
            else:
                port[4]['SupportedPolicy'] = 0
            with self.subTest(defect=defect), self.assertRaises(m.Rejected):
                model.run()

    def test_mutant_only_replaces_its_fixed_positive_slot(self):
        model = Model()
        result = model.run()
        for index in range(3):
            changed = [slot for slot in range(3) if result[index + 1]['Objects'][slot] != result[0]['Objects'][slot]]
            self.assertEqual(changed, [index])
        row = model.batch['CommonAttributesDeferredReader']['Lowerings'][1]
        row['Inputs'].reverse()
        with self.assertRaises(m.Rejected):
            model.run()

    def test_common_group_mutation_stress_and_input_hash_are_typed(self):
        for field, value in (('Group', 'mutant-engine'), ('Mutation', 'foreign'), ('Stress', 0), ('Inputs', [])):
            model = Model()
            model.batch['CommonAttributesDeferredReader']['Lowerings'][0][field] = value
            with self.subTest(field=field), self.assertRaises(m.Rejected):
                model.run()
        model = Model()
        model.batch['CommonAttributesDeferredReader']['Lowerings'][0]['Inputs'][0]['Sha256'] = '0' * 64
        with self.assertRaises(m.Rejected):
            model.run()

    def test_exact_lowering_command_ranges_and_labels(self):
        for index in (66, 72, 78, 84, 90, 96, 114, 121, 128, 131):
            model = Model()
            model.batch['Commands'][index]['Label'] = 'foreign command'
            model.seal()
            with self.subTest(index=index), self.assertRaises(m.Rejected):
                model.run()
        for key in ('common', 'port', 'final'):
            model = Model()
            row = (model.batch['CommonAttributesDeferredReader']['Lowerings'][0] if key == 'common' else
                   model.batch['PortPolicyLowerings'][0] if key == 'port' else model.batch['PortPolicyFinalLink'])
            row['CommandIndices'].append(0)
            with self.subTest(key=key), self.assertRaises(m.Rejected):
                model.run()

    def test_command_list_and_per_command_json_must_match_report(self):
        for target in ('commands.json', 'commands/066.json', 'commands/098.json', 'commands/133.json'):
            model = Model()
            value = json.loads(model.files[model.root / target])
            if type(value) is list:
                value[66]['Exit'] = False
            else:
                value['Exit'] = False
            model.files[model.root / target] = encoded(value)
            if target == 'commands.json':
                model.batch['CommandsSha256'] = sha(model.files[model.root / target])
            model.catalog()
            with self.subTest(target=target), self.assertRaises((m.Rejected, ValueError)):
                model.run()

    def test_terminal_status_exit_timeout_and_duration_fail_closed(self):
        for field, value in (('Exit', False), ('ExpectedExit', False), ('TimedOut', 0), ('Status', 'FAIL'),
                             ('State', 'ATTEMPT'), ('Seconds', True), ('Seconds', -1), ('JournalErrors', ['failed'])):
            model = Model()
            model.batch['Commands'][66][field] = value
            model.seal()
            with self.subTest(field=field, value=value), self.assertRaises(m.Rejected):
                model.run()

    def test_stream_paths_hashes_and_clean_stream_contract(self):
        for defect in ('path', 'hash', 'stdout', 'stderr-empty', 'dump-stderr'):
            model = Model()
            row = model.batch['Commands'][66]
            if defect == 'path':
                row['Stderr'] = 'commands/072.stderr'
            elif defect == 'hash':
                row['StderrSha256'] = '0' * 64
            elif defect == 'stdout':
                model.streams[66] = (b'unwanted stdout', model.streams[66][1])
                row['StdoutSha256'] = sha(b'unwanted stdout')
            elif defect == 'stderr-empty':
                model.streams[66] = (b'', b'')
                row['StderrSha256'] = sha(b'')
            else:
                model.streams[53] = (model.streams[53][0], b'unwanted stderr')
                model.batch['Commands'][53]['StderrSha256'] = sha(b'unwanted stderr')
            model.seal()
            with self.subTest(defect=defect), self.assertRaises(m.Rejected):
                model.run()

    def test_common_diagnostics_are_exact_same_journal_binding(self):
        for field, value in (('Path', 'C:/foreign.stderr'), ('Sha256', '0' * 64)):
            model = Model()
            model.batch['CommonAttributesDeferredReader']['Lowerings'][0]['Roles']['Diagnostics'][field] = value
            with self.subTest(field=field), self.assertRaises(m.Rejected):
                model.run()

    def test_specs_reconstructed_not_taken_from_adapter_claims(self):
        for component in ('common', 'port'):
            for field, value in (('OriginalSha256', '0' * 64), ('AdaptedSha256', '0' * 64),
                                 ('Offset', True), ('OriginalPath', 'C:/foreign.specs'), ('OnlyRemovedBytes', 'other')):
                model = Model()
                adapter = (model.batch['CommonAttributesDeferredReader']['DriverAdapter'] if component == 'common'
                           else model.batch['PortPolicyDriverAdapter'])
                adapter[field] = value
                with self.subTest(component=component, field=field), self.assertRaises(m.Rejected):
                    model.run()

    def test_specs_bytes_and_dump_stdout_must_agree(self):
        for defect in ('original', 'adapted', 'stdout'):
            model = Model()
            directory = model.root / 'port-policy/driver'
            adapter = model.batch['PortPolicyDriverAdapter']
            if defect == 'original':
                path = directory / 'original.specs'
                model.files[path] += b'foreign\n'
                adapter['OriginalSha256'] = sha(model.files[path])
            elif defect == 'adapted':
                path = directory / 'no-auto-gcov.specs'
                model.files[path] += b'foreign\n'
                adapter['AdaptedSha256'] = sha(model.files[path])
            else:
                stdout = model.streams[98][0] + b'foreign\n'
                model.streams[98] = (stdout, b'')
                model.batch['Commands'][98]['StdoutSha256'] = sha(stdout)
            model.seal()
            with self.subTest(defect=defect), self.assertRaises(m.Rejected):
                model.run()

    def test_saved_specs_all_split_extra_long_missing_and_duplicate_forms(self):
        for chain in (0, 6, 8, 9):
            for stage in (0, 1):
                for defect in ('split', 'long', 'extra', 'duplicate', 'missing'):
                    model = Model()
                    def change(values):
                        owned = [arg for arg in values if arg.startswith('-specs=')]
                        values[:] = [arg for arg in values if arg not in owned]
                        original = owned[0] if owned else '-specs=C:/foreign.specs'
                        values += {'split': ['-specs', original.split('=', 1)[1]], 'long': ['-' + original],
                                   'extra': owned + ['-specs=C:/foreign.specs'], 'duplicate': [original, original],
                                   'missing': [] if owned else [original]}[defect]
                    model.saved_edit(model.saved_path(chain, stage), change)
                    with self.subTest(chain=chain, stage=stage, defect=defect), self.assertRaises(m.Rejected):
                        model.run()

    def test_saved_stage_and_lowering_flags_not_just_intended_driver_flags(self):
        for chain in (0, 6, 8, 9):
            for stage in (0, 1):
                for defect in ('foreign-stage', 'duplicate-stage', 'stage-value', 'missing-partition', 'foreign-partition', 'optimization'):
                    model = Model()
                    def change(values):
                        marker = '-fwpa' if stage == 0 else '-fltrans'
                        if defect == 'foreign-stage':
                            values.append('-fltrans' if stage == 0 else '-fwpa')
                        elif defect == 'duplicate-stage':
                            values.append(marker)
                        elif defect == 'stage-value':
                            values[values.index(marker)] = marker + '=foreign'
                        elif defect == 'missing-partition':
                            values.remove('-flto-partition=one')
                        elif defect == 'foreign-partition':
                            values.append('-flto-partition=balanced')
                        else:
                            values.append('-O2')
                    model.saved_edit(model.saved_path(chain, stage), change)
                    with self.subTest(chain=chain, stage=stage, defect=defect), self.assertRaises(m.Rejected):
                        model.run()

    def test_driver_order_output_flags_and_specs_cannot_be_rebound(self):
        for index in (66, 114, 128, 131):
            for defect in ('order', 'output', 'output-duplicate', 'output-not-final', 'lower-flag', 'specs', 'stage'):
                model = Model()
                argv = model.batch['Commands'][index]['Argv']
                if defect == 'order':
                    positions = [i for i, arg in enumerate(argv) if arg.endswith('.o')]
                    if len(positions) == 1:
                        argv[positions[0]] = 'C:/foreign.o'
                    else:
                        argv[positions[0]], argv[positions[1]] = argv[positions[1]], argv[positions[0]]
                elif defect == 'output':
                    argv[argv.index('-o') + 1] = 'C:/foreign-output.o'
                elif defect == 'output-duplicate':
                    argv.extend(('-o', argv[-1]))
                elif defect == 'output-not-final':
                    argv.append('-v')
                elif defect == 'lower-flag':
                    argv.remove('-flto-partition=one')
                elif defect == 'specs':
                    argv.extend(('--specs', 'C:/foreign.specs'))
                else:
                    argv.append('-fwpa')
                model.seal()
                with self.subTest(index=index, defect=defect), self.assertRaises(m.Rejected):
                    model.run()

    def test_final_replaces_only_three_selected_and_keeps_native_startup(self):
        model = Model()
        plan = model.run()[-1]
        self.assertEqual(plan['Objects'][8], Path(model.native['Sources'][8]['Object']))
        for index in (0, 1, 2, 6, 7, 8):
            self.assertEqual(plan['Objects'][index], Path(model.native['Sources'][index]['Object']))
        for defect in ('objects', 'unchanged', 'native-hash', 'recipe'):
            model = Model()
            final = model.batch['PortPolicyFinalLink']
            if defect == 'objects':
                final['Objects'][8] = final['Objects'][0]
            elif defect == 'unchanged':
                final['UnchangedOtherSixObjects'][0]['Index'] = False
            elif defect == 'native-hash':
                model.native['Sources'][8]['ObjectSha256'] = '0' * 64
            else:
                final['OriginalFinalStageArgv'].append('-r')
            with self.subTest(defect=defect), self.assertRaises(m.Rejected):
                model.run()

    def test_stored_actual_worker_is_only_copied_never_used_as_authority(self):
        model = Model()
        for row in model.batch['PortPolicyLowerings'] + [model.batch['PortPolicyFinalLink']]:
            row['ActualWorker'] = dict(Machine='C:/foreign-machine.o', WpaInputs=[], DriverSpecs='C:/foreign.specs', Execution={})
        result = model.run()
        self.assertEqual(len(result), 10)
        self.assertFalse(any('foreign' in str(path) for path, _ in model.reads))
        self.assertEqual(result[8]['Specs'], model.root / 'port-policy/driver/no-auto-gcov.specs')
        self.assertEqual(result[8]['StoredWorker']['Machine'], 'C:/foreign-machine.o')

    def test_manifest_membership_input_hashes_and_reader_bytes_are_verified(self):
        for defect in ('missing', 'traversal', 'input-hash', 'reader-bytes', 'reader-type', 'duplicate-json'):
            model = Model()
            manifest_path = model.root / 'artifacts.json'
            manifest = json.loads(model.files[manifest_path])
            if defect == 'missing':
                del manifest['Artifacts']['commands/066.json']
            elif defect == 'traversal':
                manifest['Artifacts']['../foreign'] = '0' * 64
            elif defect == 'input-hash':
                model.batch['InputHashes'][str(model.saved_path())] = '0' * 64
            if defect == 'duplicate-json':
                model.files[manifest_path] = b'{"Artifacts":{},"Artifacts":{}}'
            else:
                model.files[manifest_path] = encoded(manifest)
            def reader(path, expected=None):
                value = model.read(path, expected)
                if path == model.root / 'commands.json':
                    if defect == 'reader-bytes':
                        return value + b'changed'
                    if defect == 'reader-type':
                        return bytearray(value)
                return value
            with self.subTest(defect=defect), self.assertRaises(m.Rejected):
                model.run(reader)

    def test_no_implicit_helper_missing_reader_or_foreign_mode(self):
        for defect in ('helper', 'batch-mode', 'native-mode', 'lto', 'relative-root'):
            model = Model()
            helpers = dict(HELPERS)
            if defect == 'helper':
                helpers['implicit_runner'] = object()
            elif defect == 'batch-mode':
                model.batch['Mode'] = 'O2-lto'
            elif defect == 'native-mode':
                model.native['Mode'] = 'O2-lto'
            elif defect == 'lto':
                model.batch['LTO'] = 1
            else:
                model.root = Path('relative')
            with self.subTest(defect=defect), self.assertRaises(m.Rejected):
                model.run(helpers=helpers)
        model = Model()
        with self.assertRaises(m.Rejected):
            m.bind(model.batch, model.root, model.native, None, HELPERS)

    def test_zero_inclusive_disassembly_journal_and_saved_bytes_are_bound(self):
        for defect in ('flag', 'worker-target', 'saved-bytes'):
            model = Model()
            if defect == 'flag':
                model.batch['Commands'][115]['Argv'].remove('-z')
            elif defect == 'worker-target':
                model.batch['Commands'][116]['Argv'][-1] = 'C:/foreign-worker.o'
            else:
                path = Path(model.batch['PortPolicyLowerings'][0]['Disassembly']['Path'])
                model.files[path] += b'changed'
            model.seal()
            with self.subTest(defect=defect), self.assertRaises(m.Rejected):
                model.run()

    def test_all_compilation_sources_and_discovery_compile_journals_are_read(self):
        model = Model()
        self.assertEqual(len(model.run()), 10)
        reads = dict(model.reads)
        rows = model.compilations()
        self.assertEqual(len({row['Source'] for row in rows}), 13)
        for position, row in enumerate(rows):
            source = Path(row['Source'])
            self.assertEqual(reads[source], row['SourceSha256'])
            self.assertEqual(model.batch['InputHashes'][str(source)], row['SourceSha256'])
            self.assertEqual(source.is_relative_to(model.root), position in (3, 4, 5, 6, 7, 11, 12))
            self.assertEqual('DiscoveryDependencyFile' in row, position >= 8)
            for index in row['CommandIndices'][:2]:
                for suffix in ('.json', '.stdout', '.stderr'):
                    path = model.root / ('commands/%03d%s' % (index, suffix))
                    self.assertEqual(reads[path], sha(model.files[path]))

    def test_discovery_compile_per_command_only_corruption_is_rejected(self):
        for position in range(13):
            for offset in (0, 1):
                model = Model()
                index = model.compilations()[position]['CommandIndices'][offset]
                path = model.root / ('commands/%03d.json' % index)
                forged = json.loads(model.files[path])
                forged['Argv'][0] = 'C:/foreign-compiler.exe'
                model.files[path] = encoded(forged)
                model.catalog()
                with self.subTest(position=position, offset=offset), self.assertRaisesRegex(m.Rejected, 'per-command journal/' + str(index)):
                    model.run()

    def test_both_journal_copies_foreign_compiler_and_source_are_rejected(self):
        for position in range(13):
            for offset in (0, 1):
                for defect in ('compiler', 'source'):
                    model = Model()
                    row = model.compilations()[position]
                    index = row['CommandIndices'][offset]
                    argv = model.batch['Commands'][index]['Argv']
                    if defect == 'compiler':
                        argv[0] = 'C:/foreign-compiler.exe'
                    else:
                        argv[argv.index(row['Source'])] = model.native['Sources'][8]['Source']
                    model.seal()
                    with self.subTest(position=position, offset=offset, defect=defect), self.assertRaisesRegex(m.Rejected, 'recorded (discovery|compile) argv/'):
                        model.run()

    def test_discovery_compile_dependency_target_mode_output_and_flags_are_exact(self):
        for position in (0, 3, 7, 8, 11, 12):
            for offset in (0, 1):
                for defect in ('dependency', 'target', 'mode', 'output', 'flags', 'label'):
                    model = Model()
                    row = model.compilations()[position]
                    index = row['CommandIndices'][offset]
                    command = model.batch['Commands'][index]
                    argv = command['Argv']
                    if defect == 'dependency':
                        argv[argv.index('-MF') + 1] = row['Object'] + '.foreign.d'
                    elif defect == 'target':
                        argv[argv.index('-MT') + 1] = 'pilot-source-foreign'
                    elif defect == 'mode':
                        marker = '-M' if offset == 0 else '-MD'
                        argv[argv.index(marker)] = '-MD' if offset == 0 else '-M'
                    elif defect == 'output':
                        if offset == 0:
                            argv.extend(('-o', row['Object']))
                        else:
                            argv[argv.index('-o') + 1] = 'C:/foreign-output.o'
                    elif defect == 'flags':
                        argv[argv.index('-Os')] = '-O2'
                    else:
                        command['Label'] += '-foreign'
                    model.seal()
                    with self.subTest(position=position, offset=offset, defect=defect), self.assertRaises(m.Rejected):
                        model.run()

    def test_compile_sources_are_independent_of_record_and_journal_claims(self):
        for position in range(13):
            model = Model()
            row = model.compilations()[position]
            original_source = row['Source']
            foreign = model.native['Sources'][8]
            row.update(Source=foreign['Source'], SourceSha256=foreign['SourceSha256'])
            for index in row['CommandIndices'][:2]:
                argv = model.batch['Commands'][index]['Argv']
                argv[argv.index(original_source)] = foreign['Source']
            model.seal()
            with self.subTest(position=position), self.assertRaisesRegex(m.Rejected, 'independent compilation source path'):
                model.run()
        for position in (0, 3, 6, 8, 11, 12):
            for defect in ('input-missing', 'hash', 'bytes'):
                model = Model()
                row = model.compilations()[position]
                source = Path(row['Source'])
                if defect == 'input-missing':
                    del model.batch['InputHashes'][str(source)]
                elif defect == 'hash':
                    row['SourceSha256'] = '0' * 64
                else:
                    model.files[source] += b'changed source bytes'
                    model.catalog()
                with self.subTest(position=position, defect=defect), self.assertRaises(m.Rejected):
                    model.run()

    def test_recorded_dependency_paths_are_checked_when_present(self):
        for position in (0, 3, 6, 8, 11, 12):
            for field in ('DiscoveryDependencyFile', 'CompileDependencyFile'):
                model = Model()
                row = model.compilations()[position]
                row[field] = 'C:/foreign-dependencies.d'
                with self.subTest(position=position, field=field), self.assertRaisesRegex(m.Rejected, 'recorded dependency path/'):
                    model.run()
        model = Model()
        for row in model.compilations():
            obj = Path(row['Object'])
            row.update(DiscoveryDependencyFile=str(obj.with_suffix('.discovery.d')),
                       CompileDependencyFile=str(obj.with_suffix('.compile.d')))
        self.assertEqual(len(model.run()), 10)

    def test_discovery_compile_streams_must_be_clean_and_terminal(self):
        for position in (0, 3, 7, 8, 11, 12):
            for offset in (0, 1):
                for defect in ('stdout', 'stderr', 'exit', 'timeout'):
                    model = Model()
                    index = model.compilations()[position]['CommandIndices'][offset]
                    row = model.batch['Commands'][index]
                    if defect in ('stdout', 'stderr'):
                        stdout, stderr = (b'unwanted stdout', b'') if defect == 'stdout' else (b'', b'unwanted stderr')
                        model.streams[index] = stdout, stderr
                        row.update(StdoutSha256=sha(stdout), StderrSha256=sha(stderr))
                    elif defect == 'exit':
                        row['Exit'] = False
                    else:
                        row['TimedOut'] = True
                    model.seal()
                    with self.subTest(position=position, offset=offset, defect=defect), self.assertRaises(m.Rejected):
                        model.run()


def main():
    global m, HELPERS
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.absolute()
    if output.exists() or output == ROOT or ROOT in output.parents:
        raise SystemExit('fresh external output directory required')
    paths = dict(bindings=HERE / 'worker_bindings.py',
                 attributes=ROOT / 'tools/fixtures/cm3_lto_attributes/attributes.py',
                 port_policy=HERE / 'port_policy_phase.py',
                 attribute_runner=ROOT / 'tools/fixtures/cm3_lto_attributes/runner.py',
                 guard=HERE / 'batch_guard.py')
    sources = (Path(__file__).resolve(), *paths.values())
    buffers = {path: path.read_bytes() for path in sources}
    opening = {str(path): sha(value) for path, value in buffers.items()}
    loaded = {}
    for name, path in paths.items():
        spec = importlib.util.spec_from_file_location('_os_worker_bindings_test_' + name, path)
        module = importlib.util.module_from_spec(spec)
        exec(compile(buffers[path], str(path), 'exec'), module.__dict__)
        loaded[name] = module
    m = loaded.pop('bindings')
    HELPERS = loaded
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(BindingTests))
    closing = {str(path): sha(path.read_bytes()) for path in sources}
    report = dict(Status='PASS' if result.wasSuccessful() and result.testsRun == METHODS
                  and not result.skipped and opening == closing else 'FAIL',
                  Tests=result.testsRun, Failures=len(result.failures), Errors=len(result.errors), Skipped=len(result.skipped),
                  SourceHashes=opening, SourceDrift=opening != closing, SyntheticControlsOnly=True,
                  WorkerPlans=10, ActualMachineBytesValidated=False, CompilerExecuted=False,
                  RecordedCompileCommandsBound=True, CompilationProvenanceReplayed=False,
                  SourceToIRSemanticProof=False, SourceToMachineSemanticProof=False,
                  Qualification=False, RequiredCellsSatisfied=0)
    output.mkdir(parents=True)
    (output / 'results.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n', encoding='ascii')
    print(json.dumps(report, sort_keys=True))
    return 0 if report['Status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
