"""Negative controls for the qualification oracle, not a CPU model."""
import os
from pathlib import Path
import tempfile
import unittest

if not __debug__ or os.environ.get('PYTHONOPTIMIZE'):
    raise SystemExit('Unoptimized Python required.')

from audit import (AuditError, EXPECTED, admit_path, binding, definition_owner,
                   compile_options, expectation_values, generated_compile_rules,
                   current_slot_storage, executable_storage, load_extents,
                   handler_binding, handler_owner, headless_ok, hooks, inventory,
                   PORT, reset_binding, reset_entry, reset_owner, vector_target)


class AuditControls(unittest.TestCase):
    def rejects(self, reason, function, *args):
        with self.assertRaisesRegex(AuditError, '^' + reason):
            function(*args)

    def rejects_exact(self, reason, function, *args):
        with self.assertRaises(AuditError) as raised:
            function(*args)
        self.assertEqual(str(raised.exception), reason)

    def test_exact_source_inventory(self):
        inventory(sorted(EXPECTED))
        self.assertEqual(len(EXPECTED), 35)
        for name in ('context_core', 'context_runtime_state', 'context_panic', 'context_configuration'):
            values = [p for p in EXPECTED if not p.endswith('/' + name + '.o')]
            self.rejects('OBJECT_SET', inventory, values)
        self.rejects('OBJECT_SET', inventory, sorted(EXPECTED - {'app_core/fiber/fiber/lifecycle/fiber_v1.o'}))
        self.rejects('DUPLICATE_OBJECT', inventory, sorted(EXPECTED) + [sorted(EXPECTED)[0]])
        self.rejects('OBJECT_SET', inventory, sorted(EXPECTED) + ['app_core/fiber/fiber/port/ARM_CM4/fiber_port.o'])

    def test_hooks(self):
        hooks({})
        hooks({'prebuildStep': ' ', 'postbuildStep': ''})
        self.rejects('BUILD_HOOK', hooks, {'prebuildStep': 'echo hidden'})
        self.rejects('BUILD_HOOK', hooks, {'postbuildStep': 'program board'})

    def test_paths(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            admit_path(root / 'inside', [root])
            self.rejects('PATH_ESCAPE', admit_path, root / '../escape', [root])
            self.rejects('PATH_ESCAPE', admit_path, root.parent / (root.name + '-prefix-collision'), [root])

    def test_terminal_selection(self):
        headless_ok(0, 'Headless build completed successfully')
        self.rejects('HEADLESS_EXIT', headless_ok, 1, 'Headless build completed successfully')
        for text in ('WARNING: No Config matched Debug', 'WARNING: No Project matched Boot',
                     'Could not obtain lock for workspace location', 'Workspace already in use!',
                     'Headless build encountered errors', 'x does not appear to be a CDT project'):
            self.rejects('HEADLESS_SELECTION_OR_WORKSPACE', headless_ok, 0, text)

    def test_vector_targets(self):
        vector_target(0x08001235, 0x08001235)
        self.rejects('VECTOR_TARGET', vector_target, 0x08001234, 0x08001235)
        self.rejects('VECTOR_TARGET', vector_target, 0x08001679, 0x08001235)

    def test_retained_expectations(self):
        expectation_values([0x100, 0x200, 0x200], 0x100, 0x200)
        self.rejects('COHORT_EXPECTATIONS', expectation_values, [0x100, 0x200], 0x100, 0x200)
        self.rejects('COHORT_EXPECTATIONS', expectation_values, [0, 0x200, 0x200], 0x100, 0x200)
        self.rejects('COHORT_EXPECTATIONS', expectation_values, [0x100, 0x100, 0x200], 0x100, 0x200)

    def test_exact_prelink_owner(self):
        value = {'Object': 'context/state.o', 'Type': 'B'}
        definition_owner([value], {'context/state.o'}, ('B',))
        self.rejects('DEFINITION_OWNER', definition_owner, [], {'context/state.o'}, ('B',))
        self.rejects('DEFINITION_OWNER', definition_owner, [value, value], {'context/state.o'}, ('B',))
        self.rejects('DEFINITION_OWNER', definition_owner, [value], {'port/state.o'}, ('B',))
        self.rejects('DEFINITION_OWNER', definition_owner, [dict(value, Type='b')], {'context/state.o'}, ('B',))
        self.rejects('DEFINITION_OWNER', definition_owner, [dict(value, Type='V')], {'context/state.o'}, ('B',))

    def test_final_binding(self):
        class Symbol(dict):
            name = 'current-slot'
        value = Symbol(st_info={'bind': 'STB_GLOBAL', 'type': 'STT_OBJECT'}, st_size=4)
        binding(value, 'STT_OBJECT', 4)
        for kind in ('STB_WEAK', 'STB_LOCAL'):
            wrong = Symbol(value, st_info={'bind': kind, 'type': 'STT_OBJECT'})
            self.rejects('SYMBOL_BINDING_OR_GEOMETRY', binding, wrong, 'STT_OBJECT', 4)
        self.rejects('SYMBOL_BINDING_OR_GEOMETRY', binding, value, 'STT_FUNC', 4)
        self.rejects('SYMBOL_BINDING_OR_GEOMETRY', binding, value, 'STT_OBJECT', 1)

    def test_exact_handler_owner(self):
        weak = [{'Object': 'Core/Src/stm32h7rsxx_it.o', 'Type': 'W'},
                {'Object': 'Core/Startup/startup_stm32h7s3l8hx.o', 'Type': 'W'}]
        strong = {'Object': PORT + 'fiber_port.o', 'Type': 'T'}
        for name in ('SVC_Handler', 'PendSV_Handler'):
            handler_owner(name, weak + [strong])
            handler_owner(name, [strong] + list(reversed(weak)))
            for bad in (weak + [strong, {'Object': 'unexpected.o', 'Type': 'W'}],
                        [dict(weak[0], Type='T'), weak[1], strong],
                        weak, weak + [strong, strong],
                        weak + [dict(strong, Object=PORT + 'fiber_port_boot.o')],
                        [weak[0], dict(weak[1], Object='unexpected.o'), strong]):
                self.rejects('HANDLER_OWNER', handler_owner, name, bad)
        self.rejects('HANDLER_OWNER', handler_owner, 'fiber_port_runtime_schedule', weak + [strong])
        self.rejects('DEFINITION_OWNER', definition_owner, weak + [strong], {strong['Object']}, ('T',))

    def test_final_handler_binding(self):
        value = dict(st_info={'bind': 'STB_GLOBAL', 'type': 'STT_FUNC'}, st_size=20)
        handler_binding(value)
        for bind in ('STB_WEAK', 'STB_LOCAL'):
            self.rejects('ELF_STRONG_HANDLER', handler_binding,
                         dict(value, st_info={'bind': bind, 'type': 'STT_FUNC'}))
        self.rejects('ELF_STRONG_HANDLER', handler_binding, dict(value, st_size=0))
        self.rejects('ELF_STRONG_HANDLER', handler_binding,
                     dict(value, st_info={'bind': 'STB_GLOBAL', 'type': 'STT_OBJECT'}))

    def test_exact_reset_owner(self):
        value = {'Object': 'Core/Startup/startup_stm32h7s3l8hx.o', 'Type': 'W'}
        reset_owner([value])
        for bad in ([], [dict(value, Object='foreign.o')], [dict(value, Type='T')],
                    [dict(value, Object='foreign.o', Type='T')], [value, value],
                    [value, {'Object': 'foreign.o', 'Type': 'T'}]):
            self.rejects('RESET_OWNER', reset_owner, bad)

    def test_final_reset_binding_extent(self):
        value = dict(st_info={'bind': 'STB_WEAK', 'type': 'STT_FUNC'},
                     st_value=0x08001001, st_size=56)
        section = dict(sh_flags=6, sh_type='SHT_PROGBITS', sh_addr=0x08001000, sh_size=56)
        reset_binding(value, section)
        for wrong in (dict(value, st_info={'bind': 'STB_GLOBAL', 'type': 'STT_FUNC'}),
                      dict(value, st_info={'bind': 'STB_WEAK', 'type': 'STT_OBJECT'}),
                      dict(value, st_value=0x08001000), dict(value, st_size=0),
                      dict(value, st_size=58), dict(value, st_value=0x08000fff)):
            self.rejects('ELF_RESET_BINDING_EXTENT', reset_binding, wrong, section)
        self.rejects('ELF_RESET_BINDING_EXTENT', reset_binding, value, dict(section, sh_flags=2))

    def test_reset_entry_and_vector(self):
        reset_entry(0x08001001, 0x20010000, 0x08001001)
        for entry, msp, reset in ((0x08002001, 0x20010000, 0x08001001),
                                  (0x08001000, 0x20010000, 0x08001000),
                                  (0x08001001, 0x20000000, 0x08001001)):
            self.rejects('ELF_RESET_ENTRY_MSP', reset_entry, entry, msp, reset)
        vector_target(0x08001001, 0x08001001)
        self.rejects('VECTOR_TARGET', vector_target, 0x08001000, 0x08001001)
        self.rejects('VECTOR_TARGET', vector_target, 0x08002001, 0x08001001)

    def test_handler_executable_storage(self):
        symbol = dict(st_value=0x08001001, st_size=20)
        section = dict(sh_type='SHT_PROGBITS', sh_flags=6, sh_addr=0x08001000,
                       sh_size=0x100, sh_offset=0x1000)
        load = dict(p_flags=5, p_vaddr=0x08000000, p_filesz=0x2000, p_offset=0)
        executable_storage(symbol, section, [load], 0x3000)
        cases = [(dict(symbol, st_value=0x60000001), section, [load], 0x3000),
                 (dict(symbol, st_value=0x08001000), section, [load], 0x3000),
                 (dict(symbol, st_size=0x102), section, [load], 0x3000),
                 (symbol, None, [load], 0x3000),
                 (symbol, dict(section, sh_type='SHT_NOBITS'), [load], 0x3000),
                 (symbol, dict(section, sh_flags=2), [load], 0x3000),
                 (symbol, dict(section, sh_flags=4), [load], 0x3000),
                 (symbol, section, [], 0x3000),
                 (symbol, section, [dict(load, p_flags=4)], 0x3000),
                 (symbol, section, [dict(load, p_filesz=0x1005)], 0x3000),
                 (symbol, section, [dict(load, p_offset=1)], 0x3000),
                 (symbol, section, [load], 0x1005)]
        for args in cases:
            self.rejects_exact('ELF_HANDLER_EXECUTABLE_STORAGE', executable_storage, *args)

    def test_current_slot_writable_ram(self):
        symbol = dict(st_value=0x24001b08, st_size=4)
        section = dict(sh_type='SHT_NOBITS', sh_flags=3, sh_addr=0x24000010,
                       sh_size=0x1b04, sh_offset=0x10)
        load = dict(p_flags=6, p_vaddr=0x24000010, p_memsz=0x1b04, p_filesz=0, p_offset=0x10)
        current_slot_storage(symbol, section, [load], 0x3000)
        data = dict(sh_type='SHT_PROGBITS', sh_flags=3, sh_addr=0x24000000,
                    sh_size=12, sh_offset=0x2000)
        data_load = dict(p_flags=6, p_vaddr=0x24000000, p_memsz=12, p_filesz=12, p_offset=0x2000)
        current_slot_storage(dict(symbol, st_value=0x24000000), data, [data_load], 0x3000)
        text = dict(sh_type='SHT_PROGBITS', sh_flags=6, sh_addr=0x080002b0,
                    sh_size=0x100, sh_offset=0x12b0)
        cases = [(dict(symbol, st_value=0x080002b0), text, [load]),
                 (dict(symbol, st_value=0x24001b09), section, [load]),
                 (symbol, None, [load]), (symbol, dict(section, sh_flags=2), [load]),
                 (symbol, dict(section, sh_size=0x1afa), [load]),
                 (symbol, section, [dict(load, p_flags=4)]),
                 (symbol, section, [dict(load, p_memsz=0x1afa)]),
                 (symbol, section, []),
                 (dict(symbol, st_value=0x60000000), dict(section, sh_addr=0x60000000),
                  [dict(load, p_vaddr=0x60000000)]),
                 (dict(symbol, st_value=0x24071ffc, st_size=8),
                  dict(section, sh_addr=0x24071f00, sh_size=0x200),
                  [dict(load, p_vaddr=0x24071f00, p_memsz=0x200)]),
                 (dict(symbol, st_value=0x24000000), data, [dict(data_load, p_filesz=0)])]
        for args in cases:
            self.rejects_exact('ELF_CURRENT_SLOT_WRITABLE_RAM', current_slot_storage, *args, 0x3000)

    def test_virtual_and_physical_load_extents(self):
        load = dict(p_vaddr=0x08000000, p_paddr=0x08000000, p_filesz=0x100,
                    p_memsz=0x100, p_offset=0x1000)
        load_extents(load, 0x2000)
        load_extents(dict(load, p_vaddr=0x24000000), 0x2000)
        load_extents(dict(load, p_vaddr=0x24000000, p_filesz=0, p_paddr=0xdead0000), 0x2000)
        for address in (0xdead0000, 0x0800fffc, 0xfffffffc):
            self.rejects_exact('ELF_PHYSICAL_LOAD_REGION', load_extents,
                               dict(load, p_paddr=address), 0x2000)
        self.rejects_exact('ELF_MEMORY_REGION', load_extents, dict(load, p_vaddr=0x60000000), 0x2000)
        for change in ({'p_memsz': 1}, {'p_offset': 0x3000}, {'p_filesz': 0x1001, 'p_memsz': 0x1001}):
            self.rejects_exact('ELF_LOAD_FILE_GEOMETRY', load_extents, dict(load, **change), 0x2000)

    def test_compile_language_and_options(self):
        for config, copt, cppopt, standard in (('Debug', '-O2', '-O1', 'gnu++20'),
                                                ('Release', '-Os', '-Os', 'gnu++14')):
            c = 'arm-none-eabi-gcc "$<" -c -std=gnu11 ' + copt + ' -o "$@"'
            cpp = 'arm-none-eabi-g++ "$<" -c -std=' + standard + ' ' + cppopt + ' -o "$@"'
            assembly = 'arm-none-eabi-gcc -c -x assembler-with-cpp -o "$@" "$<"'
            self.assertEqual(compile_options(c, 'C_SRCS', 'one.c', config), 'C')
            self.assertEqual(compile_options(cpp, 'CPP_SRCS', 'one.cpp', config), 'C++')
            self.assertEqual(compile_options(assembly, 'S_SRCS', 'startup.s', config), 'assembler')
            for command, group, source, opt in ((c, 'C_SRCS', 'one.c', copt),
                                                 (cpp, 'CPP_SRCS', 'one.cpp', cppopt)):
                for changed in (command.replace(opt, ''), command.replace(opt, '-O0'),
                                command + ' ' + opt, command + ' -O3', command.replace(opt, opt + '0')):
                    self.rejects('COMPILE_OPTIMIZATION_DRIFT', compile_options,
                                 changed, group, source, config)
                for changed in (command + ' -x assembler-with-cpp', command + ' -x c++ -x c',
                                command.replace('arm-none-eabi-g', 'arm-none-eabi-unknown-g')):
                    self.rejects('COMPILE_LANGUAGE', compile_options, changed, group, source, config)
            self.rejects('COMPILE_LANGUAGE', compile_options, assembly, 'C_SRCS', 'one.c', config)
            self.rejects('COMPILE_LANGUAGE', compile_options,
                         assembly.replace('assembler-with-cpp', 'c'), 'S_SRCS', 'startup.s', config)
            self.rejects('COMPILE_LANGUAGE', compile_options, c, 'C_SRCS', 'one.cpp', config)
            self.rejects('ASSEMBLER_OPTIONS_DRIFT', compile_options,
                         assembly + ' -O2', 'S_SRCS', 'startup.s', config)
            self.rejects('COMPILE_STANDARD_DRIFT', compile_options,
                         cpp.replace(standard, 'gnu++17'), 'CPP_SRCS', 'one.cpp', config)
            self.rejects('COMPILE_STANDARD_DRIFT', compile_options,
                         cpp + ' -std=gnu++11', 'CPP_SRCS', 'one.cpp', config)

    def test_generated_rule_associations(self):
        content = ('C_SRCS += ../Core/one.c ../Core/two.c\n'
                   'OBJS += ./Core/one.o ./Core/two.o\n'
                   'Core/%.o Core/%.su Core/%.cyclo: ../Core/%.c Core/subdir.mk\n'
                   '\tarm-none-eabi-gcc "$<" -c -std=gnu11 -O2 -o "$@"\n')
        with tempfile.TemporaryDirectory() as root:
            records = generated_compile_rules(content, root, 'Core/subdir.mk', 'Debug')
            self.assertEqual([r['Object'] for r in records], ['Core/one.o', 'Core/two.o'])
            self.assertEqual([Path(r['Source']).name for r in records], ['one.c', 'two.c'])
            self.rejects('COMPILE_LANGUAGE', generated_compile_rules,
                         content.replace('C_SRCS', 'CPP_SRCS'), root, 'Core/subdir.mk', 'Debug')
            self.rejects('UNASSOCIATED_COMPILE_RULE', generated_compile_rules,
                         content.replace('../Core/%.c Core/subdir', '../Other/%.c Core/subdir'),
                         root, 'Core/subdir.mk', 'Debug')
            self.rejects('UNDECLARED_COMPILE_OBJECT', generated_compile_rules,
                         content.replace('OBJS += ./Core/one.o ./Core/two.o', 'OBJS += ./Core/one.o'),
                         root, 'Core/subdir.mk', 'Debug')
            self.rejects('COMPILE_ASSOCIATION_COVERAGE', generated_compile_rules,
                         content + 'C_SRCS += ../Other/three.c\nOBJS += ./Other/three.o\n',
                         root, 'Core/subdir.mk', 'Debug')
            extra = ('Other/extra.o: ../Other/extra.c Core/subdir.mk\n'
                     '\tarm-none-eabi-gcc "$<" -c -std=gnu11 -O2 -o "$@"\n')
            self.rejects('UNASSOCIATED_COMPILE_RULE', generated_compile_rules,
                         content + extra, root, 'Core/subdir.mk', 'Debug')


if __name__ == '__main__':
    unittest.main(verbosity=2)
