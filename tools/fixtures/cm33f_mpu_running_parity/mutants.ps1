function Get-Cm33fRunningMutants {
    # Operands are changed in copied actual C inline assembly, then assembled
    # by the same compiler. No synthetic disassembly is passed to the oracle.
    return @(
        @{Name='save-low-offset'; From='adds  r0, #0x20'; To='adds  r0, #0x24'},
        @{Name='save-fp-predicate'; From='bne   2f'; To='beq   2f'},
        @{Name='save-high-count'; From='vstmia r1!, {s16-s31}'; To='vstmia r1!, {s16-s30}'},
        @{Name='save-low-count'; From='vldmia r0, {s0-s16}'; To='vldmia r0, {s0-s15}'},
        @{Name='save-high-writeback'; From='vstmia r1!, {s16-s31}'; To='vstmia r1, {s16-s31}'},
        @{Name='save-fp-order'; From='vstmia r1!, {s16-s31}'; Swap='vldmia r0, {s0-s16}'},
        @{Name='save-core-count'; From='ldmia r0, {r4-r11}'; To='ldmia r0, {r4-r10}'},
        @{Name='save-special-source'; From='stmia r1!, {r0, r3, r4, lr}'; To='stmia r1!, {r2, r3, r4, lr}'},
        @{Name='save-cursor-publication'; From='str   r1, [r2, #0]'; To='str   r0, [r2, #0]'; Occurrence=0; Count=2},
        @{Name='restore-cursor-publication'; From='str   r1, [r2, #0]'; To='str   r0, [r2, #0]'; Occurrence=1; Count=2},
        @{Name='restore-low-count'; From='vldmdb r1!, {s0-s16}'; To='vldmdb r1!, {s0-s15}'},
        @{Name='restore-high-addressing'; From='vldmdb r1!, {s16-s31}'; To='vldmia r1, {s16-s31}'},
        @{Name='restore-core-writeback'; From='stmia r0!, {r4-r11}'; To='stmia r0, {r4-r11}'},
        @{Name='restore-fp-order'; From='vldmdb r1!, {s0-s16}'; Swap='vldmdb r1!, {s16-s31}'},
        @{Name='restore-fp-predicate'; From='bne   3f'; To='beq   3f'},
        @{Name='restore-control-mask'; From='and   r5, r5, #7'; To='and   r5, r5, #5'},
        @{Name='restore-control-entry-confusion'; From='cmp   r5, r4'; To='cmp   r5, #1'},
        @{Name='remove-save-preflight'; From='bl    fiber_port_pendsv_validate_save_current'; To='nop'},
        @{Name='foreign-scheduler-call'; From='bl    fiber_port_scheduler_pick_next_from_pendsv'; To='bl    foreign_scheduler'},
        @{Name='foreign-current-slot'; From='=fiber_internal_runtime_current_context_slot'; To='=foreign_current_slot'},
        @{Name='current-slot-addend'; From='=fiber_internal_runtime_current_context_slot'; To='=fiber_internal_runtime_current_context_slot + 4'},
        @{Name='scheduler-call-addend'; From='bl    fiber_port_scheduler_pick_next_from_pendsv'; To='bl    fiber_port_scheduler_pick_next_from_pendsv+4'; Code='RELOC'},
        @{Name='unknown-coprocessor'; From='mov   r2, r1'; To='.inst.w 0xED810000 \n" "mov   r2, r1'},
        @{Name='unknown-encoding'; From='mov   r2, r1'; To='.inst.w 0xFFFFFFFF \n" "mov   r2, r1'},
        @{Name='reference-low-offset'; Reference=$true; From='add r2, r2, #0x20'; To='add r2, r2, #0x24'},
        @{Name='reference-low-count'; Reference=$true; From='vldmiaeq r2, {s0-s16}'; To='vldmiaeq r2, {s0-s15}'},
        @{Name='reference-reverse-addressing'; Reference=$true; From='vldmdbeq r1!, {s16-s31}'; To='vldmiaeq r1, {s16-s31}'},
        @{Name='svc-extended-token'; Svc=$true; From='bic   r3, r3, #0x10'; To='bic   r3, r3, #0x20'},
        @{Name='svc-raw-psp-offset'; Svc=$true; From='2: mrs r0, psp'; To='2: mrs r0, psp \n" "adds r0, #72'},
        @{Name='svc-origin-before-frame'; Svc=$true; From='cmp   r3, #11'; To='cmp   r3, #14'},
        @{Name='svc-foreign-dispatch'; Svc=$true; From='=fiber_port_svc_dispatch + 1'; To='=foreign_svc_dispatch + 1'},
        @{Name='svc-yield-number'; Svc=$true; From='fiber_portSTRINGIFY(fiber_portSVC_YIELD)'; To='fiber_portSTRINGIFY(fiber_portSVC_RETURN)'; Code='SVC-YIELD'},
        @{Name='svc-return-number'; Svc=$true; From='fiber_portSTRINGIFY(fiber_portSVC_RETURN)'; To='fiber_portSTRINGIFY(fiber_portSVC_YIELD)'; Code='SVC-RETURN'}
    )
}

function New-Cm33fRunningMutation {
    param([string]$Text, [hashtable]$Mutation)
    $expected = if ($Mutation.ContainsKey('Count')) { $Mutation.Count } else { 1 }
    $matches = [regex]::Matches($Text, [regex]::Escape($Mutation.From))
    if ($matches.Count -ne $expected) {
        throw "C3FP running mutation anchor changed: $($Mutation.Name): $($matches.Count) != $expected"
    }
    $index = if ($Mutation.ContainsKey('Occurrence')) { $Mutation.Occurrence } else { 0 }
    $match = $matches[$index]
    if ($Mutation.ContainsKey('Swap')) {
        $other = [regex]::Matches($Text, [regex]::Escape($Mutation.Swap))
        if ($other.Count -ne 1 -or $match.Index -ge $other[0].Index+$other[0].Length) {
            throw "C3FP running swap anchor changed: $($Mutation.Name)"
        }
        return $Text.Substring(0, $match.Index) + $Mutation.Swap +
            $Text.Substring($match.Index+$match.Length, $other[0].Index-$match.Index-$match.Length) +
            $Mutation.From + $Text.Substring($other[0].Index+$other[0].Length)
    }
    return $Text.Substring(0, $match.Index) + $Mutation.To + $Text.Substring($match.Index+$match.Length)
}
