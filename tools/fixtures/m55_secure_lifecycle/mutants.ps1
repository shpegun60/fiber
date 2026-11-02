function GetLifecycleMutants {
    $cases=@()
    foreach($op in @('allocate','load','save')) {
        $cases+=@{Name="mutant-$op-origin";kind='success';Operation=$op;
            Pattern='__builtin_arm_cmse_nonsecure_caller\(\) == 0';Replace='0';
            kill=if($op -eq 'allocate') {'admission-before-backend'} else {'return-value'}}
        $cases+=@{Name="mutant-$op-control-mask";kind='success';Operation=$op;
            Pattern='control != 2u';Replace='(control & 3u) != 2u';
            kill=if($op -eq 'allocate') {'admission-before-backend'} else {'return-value'}}
        $cases+=@{Name="mutant-$op-exception";kind='success';Operation=$op;
            Pattern='FIBER_ARM_CM55_SECURE_CONTEXT_GATEWAY_PENDSV_EXCEPTION_NUMBER';Replace=if($op -eq 'save') {'11u'} else {'15u'};
            kill=if($op -eq 'allocate') {'admission-before-backend'} else {'return-value'}}
    }
    $cases+=@{Name='mutant-load-pointer-first';kind='success';Operation='load';
        Pattern='msr psplim, %0';Replace='msr psp, %0';kill='load-write-order'}
    $cases+=@{Name='mutant-save-pointer-first';kind='success';Operation='save';
        Pattern='msr psplim, %0';Replace='msr psp, %0';kill='save-write-order'}
    $cases+=@{Name='mutant-save-wrong-publication';kind='success';Operation='save';
        Pattern='(current_stack_pointer =\s*)stack_pointer;';Replace='${1}(stack_pointer - 8u);';kill='save-publish-value'}
    $cases+=@{Name='mutant-save-missing-exact-readback';kind='success';Operation='save';
        Pattern='\|\|\s*\(\(\(volatile FiberSecureContextRecord \*\)record\)->current_stack_pointer !=\s*stack_pointer\)';
        Replace='';kill='save-publish-readback'}
    $cases+=@{Name='mutant-load-ignore-limit-readback';kind='readback';target='load-a-first';register='psplim';read=2;Operation='load';
        Pattern='if \(limit_after != stack_limit\)';Replace='if (0)';kill='readback-failure-advanced'}
    $cases+=@{Name='mutant-save-ignore-limit-readback';kind='readback';target='save-a-first';register='psplim';read=2;Operation='save';
        Pattern='if \(limit_after != 0u\)';Replace='if (0)';kill='readback-failure-advanced'}
    foreach($opcode in @('stl','stlex')) {
        $instruction=if($opcode -eq 'stl') {'stl %0, [%1]'} else {'stlex r12, %0, [%1]'}
        $clobber=if($opcode -eq 'stl') {'"memory"'} else {'"r12", "memory"'}
        $cases+=@{Name="control-unknown-$opcode";kind='success';Operation='load';
            Pattern='uint32_t exception_number;';
            Replace=('uint32_t exception_number; __asm volatile ("'+$instruction+'" :: "r" (0u), "r" (0x30000000u) : '+$clobber+');');
            kill='unqualified-store';kill_step='unready-load'}
    }
    foreach($case in $cases) {
        $case.kill_op=@{allocate=1;load=2;save=3}[$case.Operation]
        $case.kill_direct=$false
        if($case.Name -like '*-origin') {
            $case.kill_step=if($case.Operation -eq 'save') {'direct-pendsv'} else {'direct-svc'}
            $case.kill_direct=$true
        } elseif($case.Name -like 'control-unknown-*') { $case.kill_step='unready-load' }
        elseif($case.Name -like '*-control-mask') { $case.kill_step='control-'+$case.Operation+'-6' }
        elseif($case.Name -like '*-exception') { $case.kill_step=if($case.Operation -eq 'save') {'wrong-svc-save'} else {'wrong-systick-'+$case.Operation} }
        elseif($case.Name -eq 'mutant-load-pointer-first') { $case.kill_step='load-a-first' }
        elseif($case.Name -like '*-ignore-limit-readback') { $case.kill_step=$case.target }
        else { $case.kill_step='save-at-limit' }
    }
    return $cases
}
