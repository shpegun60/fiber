static void check_mpu_attribute_encoding(uint32_t rbar_attributes,
        uint32_t rlar_attributes, int expected_valid)
{
    FiberPortMpuRegionRegisters encoded = {0xA5A55A5Au, 0x5A5AA5A5u};
    const int valid = fiber_port_mpu_try_encode_exact_region(
        0x20002000u, 0x20002040u, 4u, rbar_attributes, rlar_attributes, &encoded);
    if (valid != expected_valid) {
        fprintf(stderr, "MPU SH oracle mismatch: rbar=0x%08x rlar=0x%08x expected=%d actual=%d\n",
            (unsigned)rbar_attributes, (unsigned)rlar_attributes, expected_valid, valid);
    }
    CHECK(valid == expected_valid);
    CHECK(fiber_port_mpu_rbar_attributes_are_valid(rbar_attributes) == expected_valid);
    CHECK(encoded.rbar == (expected_valid ?
        (0x20002000u | rbar_attributes) : 0xA5A55A5Au));
    CHECK(encoded.rlar == (expected_valid ?
        (0x20002021u | rlar_attributes) : 0x5A5AA5A5u));
}

static void test_mpu_shareability_encoding(void)
{
    /* Raw architectural fields, independent of the dictionary under test:
     * SH=0 non-shareable, 1 reserved, 2 outer, 3 inner; AP occupies [2:1]. */
    for (uint32_t sh = 0u; sh < 4u; ++sh) {
        for (uint32_t ap = 0u; ap < 4u; ++ap) {
            for (uint32_t xn = 0u; xn < 2u; ++xn) {
                const uint32_t attributes = (sh << 3u) | (ap << 1u) | xn;
                for (uint32_t index = 0u; index < 2u; ++index) {
                    check_mpu_attribute_encoding(attributes, index << 1u, sh != 1u);
                    for (unsigned bit = 5u; bit < 32u; ++bit) {
                        check_mpu_attribute_encoding(attributes | (UINT32_C(1) << bit),
                            index << 1u, 0);
                    }
                }
            }
        }
    }
}

static void reset_cpu(void)
{
    primask = basepri = faultmask = control = ipsr = psplim = 0;
    psp = 0;
    reg_cpacr = reg_fpccr = int_ctrl = ccr = shcsr = mpu_ctrl = mpu_rnr = mair0 = 0;
    first_irq_priority = 0x5A;
    svc_priority = pendsv_priority = 13;
    memory_layout = (FiberPortMpuMemoryLayout) {
        0x00400000u, 0x00800000u, 0x08020000u, 0x08040000u,
        0x08040000u, 0x08050000u, 0x30000020u, 0x30010000u,
        0x30000000u, 0x30000020u, 0x20000000u, 0x20010000u
    };
}

static void configure_context(FiberContext *ctx, uint32_t *frame, int extended)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->boot.begin = (void *)0x20000000u;
    ctx->boot.stack_base = 0x20000000u;
    ctx->boot.stack_top = 0x20001000u;
    ctx->boot.entry = (entry_t)0x08020020u;
    ctx->mair0 = fiber_portMPU_MAIR0_DEFAULT;
    CHECK(fiber_port_mpu_try_encode_exact_region(ctx->boot.stack_base,
        ctx->boot.stack_top, 4, fiber_portMPU_REGION_READ_WRITE |
        fiber_portMPU_REGION_EXECUTE_NEVER, 0, &ctx->mpu_regions[0]));
    CHECK(fiber_port_mpu_try_encode_exact_region(memory_layout.current_context_slot_start,
        memory_layout.current_context_slot_end, 5, fiber_portMPU_REGION_READ_ONLY |
        fiber_portMPU_REGION_EXECUTE_NEVER, 0, &ctx->mpu_regions[1]));
    memset(frame, 0, FIBER_PORT_EXC_BASE_BYTES + FIBER_PORT_EXC_FP_EXT_BYTES);
    frame[6] = 0x08040002u;
    frame[7] = fiber_portXPSR_THUMB_BIT;
    if (extended) {
        /* Nonzero S1/S4 must not be mistaken for basic PSPLIM/cursor_limit. */
        for (unsigned int i = 0; i < 16; ++i) {
            ctx->protected_context.extended.high_fp_s16_s31[i] = 0x41000000u + i;
            ctx->protected_context.extended.low_fp_s0_s15_fpscr[i] = 0x42000000u + i;
            frame[8 + i] = 0x43000000u + i;
        }
        frame[24] = 0x12340200u; /* FPSCR, deliberately different from xPSR. */
        frame[25] = 0xDEAD0200u; /* Reserved/VPR sentinel. */
        ctx->protected_context.extended.psp = (uint32_t)(uintptr_t)frame;
        ctx->protected_context.extended.psplim = (uint32_t)ctx->boot.stack_base;
        ctx->protected_context.extended.control = 5;
        ctx->protected_context.extended.exc_return = fiber_portEXTENDED_EXC_RETURN;
        ctx->protected_context.extended.pc = frame[6];
        ctx->protected_context.extended.xpsr = frame[7];
        ctx->protected_context_cursor = &ctx->protected_context.extended.cursor_limit;
    } else {
        ctx->protected_context.basic.psp = (uint32_t)(uintptr_t)frame;
        ctx->protected_context.basic.psplim = (uint32_t)ctx->boot.stack_base;
        ctx->protected_context.basic.control = 1;
        ctx->protected_context.basic.exc_return = fiber_portINITIAL_EXC_RETURN;
        ctx->protected_context.basic.pc = frame[6];
        ctx->protected_context.basic.xpsr = frame[7];
        ctx->protected_context_cursor = &ctx->protected_context.basic.cursor_limit;
    }
}

static void load_mpu(const FiberContext *ctx)
{
    FiberPortMpuGlobalRegionImage global;
    fiber_port_mpu_build_global_regions(&global);
    memcpy(active_regions, global.regions, sizeof(global.regions));
    memcpy(active_regions + 4, ctx->mpu_regions, sizeof(ctx->mpu_regions));
    mpu_ctrl = fiber_portMPU_CTRL_REQUIRED;
    shcsr = fiber_portSCB_MEMFAULTENA_BIT;
    mair0 = ctx->mair0;
    mpu_rnr = fiber_portMPU_LAST_CONTEXT_BLOCK_REGION;
}

static unsigned int matches(uintptr_t address)
{
    unsigned int count = 0;
    for (unsigned int i = 0; i < fiber_portMPU_TOTAL_REGIONS; ++i) {
        const FiberPortMpuRegionRegisters *r = &active_regions[i];
        if ((r->rlar & 1) && address >= (r->rbar & 0xFFFFFFE0u) &&
            address <= ((r->rlar & 0xFFFFFFE0u) | 31u)) ++count;
    }
    return count;
}

static void check_disjoint_mpu(void)
{
    for (unsigned int i = 0; i < fiber_portMPU_TOTAL_REGIONS; ++i) {
        for (unsigned int j = i + 1; j < fiber_portMPU_TOTAL_REGIONS; ++j) {
            const FiberPortMpuRegionRegisters *a = &active_regions[i], *b = &active_regions[j];
            if (!(a->rlar & b->rlar & 1)) continue;
            uintptr_t a0 = a->rbar & 0xFFFFFFE0u, b0 = b->rbar & 0xFFFFFFE0u;
            uintptr_t a1 = (a->rlar & 0xFFFFFFE0u) | 31u, b1 = (b->rlar & 0xFFFFFFE0u) | 31u;
            CHECK(a1 < b0 || b1 < a0);
        }
    }
    CHECK(matches(0x30000000u) == 1);
    CHECK(matches(0x3000001Fu) == 1);
    CHECK(matches(0x30000020u) == 1);
    CHECK((active_regions[5].rbar & 7) == (fiber_portMPU_REGION_READ_ONLY | 1));
}

static void test_control_transitions(void)
{
    /* First restore begins in a privileged MSP-origin SVC. The actual source
     * writes the synthetic template 3, which remains readable as 3 in Handler. */
    control = 0u;
    ipsr = 0u;
    host_exception_entry(11u);
    CHECK(__get_CONTROL() == 0u);
    CHECK(host_restore_first_control(3u) == 3u);
    CHECK(ipsr == 11u && __get_CONTROL() == 3u);
    CHECK(__get_CONTROL() != 1u);
    EXPECT_PANIC('l', host_restore_first_control(1u));
    CHECK(ipsr == 11u && __get_CONTROL() == 1u);
    CHECK(host_restore_first_control(3u) == 3u);
    host_exception_return(fiber_portINITIAL_EXC_RETURN);
    CHECK(ipsr == 0u && __get_CONTROL() == 3u);

    /* Activation clears targeted-bank SPSEL and FPCA, preserving nPRIV and
     * masks. Every supported protected CONTROL representation must survive a
     * privileged MSR plus MRS exactly, even while IPSR is nonzero. */
    const uint32_t saved_controls[] = {1u, 3u, 5u, 7u};
    for (unsigned int i = 0u; i < sizeof(saved_controls) / sizeof(saved_controls[0]); ++i) {
        uint32_t saved = saved_controls[i];
        control = 7u;
        ipsr = 0u;
        primask = 1u;
        basepri = FIBER_PORT_SCHEDULER_BASEPRI;
        host_exception_entry(14u);
        CHECK(ipsr == 14u && __get_CONTROL() == 1u);
        CHECK(primask == 1u && basepri == FIBER_PORT_SCHEDULER_BASEPRI);
        CHECK(host_restore_runtime_control(saved) == saved);
        CHECK(ipsr == 14u && __get_CONTROL() == saved);
        CHECK((__get_CONTROL() & 2u) == (saved & 2u));
        host_exception_return((saved & 4u) ?
            fiber_portEXTENDED_EXC_RETURN : fiber_portINITIAL_EXC_RETURN);
        CHECK(ipsr == 0u && __get_CONTROL() == (saved | 2u));
        host_exception_entry(11u);
        CHECK(ipsr == 11u && __get_CONTROL() == 1u);
    }
    /* Directly set and clear SPSEL without changing Handler mode. */
    __set_CONTROL(3u);
    CHECK(ipsr == 11u && __get_CONTROL() == 3u);
    __set_CONTROL(1u);
    CHECK(ipsr == 11u && __get_CONTROL() == 1u);
    control = ipsr = primask = basepri = 0u;
}

static void check_corrupt_trailing_guard(FiberContext *ctx, const char *form)
{
    ctx->protected_context.words[53] = 0xA5A55A5Au;
    expecting_panic = 1;
    if (setjmp(panic_jump) == 0) {
        fiber_port_context_validate_restore(ctx);
        fprintf(stderr, "guard53 corruption accepted: form=%s\n", form);
        exit(1);
    } else {
        CHECK(panic_code == 'P');
        CHECK(ctx->protected_context.words[53] == 0xA5A55A5Au);
    }
    expecting_panic = 0;
    ctx->protected_context.words[53] = 0u;
}

static void test_same_context_saved_representations(uint32_t *frame)
{
    FiberContext ctx;
    uint32_t gp[8], high_fp[16], before[54];
    for (unsigned i = 0; i < 8; ++i) gp[i] = 0x51000000u + i;
    for (unsigned i = 0; i < 16; ++i) high_fp[i] = 0x61000000u + i;

    /* Start with the actual cold, basic constructor representation. The host
     * model supplies admitted exception frames/tokens; it does not claim to
     * execute exception entry or assert that every task remains FP-active. */
    configure_context(&ctx, frame, 0);
    ctx.protected_context.basic.control = 3u;
    ctx.protected_context.basic.pc = 0x08020020u;
    ctx.protected_context.basic.lr = 0x08040021u;
    fiber_port_context_validate_initial_restore(&ctx);
    CHECK(ctx.protected_context.words[20] == 0u);
    CHECK(ctx.protected_context.words[53] == 0u);
    ctx.protected_context_cursor = &ctx.protected_context.words[0];

    for (unsigned i = 0; i < 17; ++i) frame[8 + i] = 0x71000000u + i;
    control = 7u; ipsr = 0u;
    host_exception_entry(14u);
    CHECK(control == 1u);
    psp = (uintptr_t)frame; psplim = (uint32_t)ctx.boot.stack_base;
    load_mpu(&ctx);
    fiber_port_pendsv_validate_save_current(&ctx, frame, fiber_portEXTENDED_EXC_RETURN);
    host_protected_save(&ctx, frame, fiber_portEXTENDED_EXC_RETURN, gp, high_fp);
    CHECK(ctx.protected_context_cursor == &ctx.protected_context.words[53]);
    CHECK(ctx.protected_context.words[20] == 0x71000004u); /* Extended S4. */
    CHECK(ctx.protected_context.words[53] == 0u);
    fiber_port_context_validate_restore(&ctx);
    memcpy(before, ctx.protected_context.words, sizeof(before));
    check_corrupt_trailing_guard(&ctx, "extended");

    /* The inverse restore leaves image bytes intact and resets only its cursor.
     * Supply a basic frame as a representation input, not as a demonstrated
     * five-API FPCA teardown: stopping FP instructions or unprivileged MSR
     * CONTROL cannot clear FPCA. The save must overwrite only words 0..19. */
    ctx.protected_context_cursor = &ctx.protected_context.words[0];
    control = 3u; ipsr = 0u;
    host_exception_entry(14u);
    CHECK(control == 1u);
    frame[0] = 0x81000000u;
    fiber_port_pendsv_validate_save_current(&ctx, frame, fiber_portINITIAL_EXC_RETURN);
    host_protected_save(&ctx, frame, fiber_portINITIAL_EXC_RETURN, gp, high_fp);
    CHECK(ctx.protected_context_cursor == &ctx.protected_context.words[20]);
    CHECK(ctx.protected_context.words[8] == frame[0]);
    CHECK(ctx.protected_context.words[19] == 0xFFFFFFBCu);
    CHECK(memcmp(ctx.protected_context.words + 20, before + 20, 34 * sizeof(uint32_t)) == 0);
    memcpy(before, ctx.protected_context.words, sizeof(before));
    expecting_panic = 1;
    if (setjmp(panic_jump) == 0) {
        fiber_port_context_validate_restore(&ctx);
    } else {
        fprintf(stderr, "same-context basic-after-extended rejected: panic=%c S4=0x%08x guard53=0x%08x\n",
            panic_code, (unsigned)ctx.protected_context.words[20],
            (unsigned)ctx.protected_context.words[53]);
        exit(1);
    }
    expecting_panic = 0;
    CHECK(memcmp(ctx.protected_context.words, before, sizeof(before)) == 0);
    check_corrupt_trailing_guard(&ctx, "basic");
    const unsigned invalid_cursors[] = {0u, 19u, 21u, 52u, 54u};
    for (volatile unsigned i = 0; i < sizeof(invalid_cursors) / sizeof(invalid_cursors[0]); ++i) {
        ctx.protected_context_cursor = &ctx.protected_context.words[invalid_cursors[i]];
        EXPECT_PANIC('P', fiber_port_context_validate_restore(&ctx));
    }
    ctx.protected_context_cursor = NULL;
    EXPECT_PANIC('P', fiber_port_context_validate_restore(&ctx));
    ctx.protected_context_cursor = (uint32_t *)((uintptr_t)&ctx.protected_context.words[20] + 1u);
    EXPECT_PANIC('P', fiber_port_context_validate_restore(&ctx));
    printf("PASS: representation-only cold basic -> extended -> basic, S4=0x%08x preserved; guard53 rejects both forms\n",
        (unsigned)ctx.protected_context.words[20]);
    control = ipsr = 0u;
}

int main(void)
{
    test_mpu_shareability_encoding();
    uint32_t *const frame = VirtualAlloc((void *)0x20000000u, 0x10000u,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    unsigned char *const veneers = VirtualAlloc((void *)0x08040000u, 0x10000u,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    CHECK(frame == (void *)0x20000000u && veneers == (void *)0x08040000u);
    veneers[0] = fiber_portSVC_YIELD; veneers[1] = 0xDF;
    veneers[8] = fiber_portSVC_RETURN; veneers[9] = 0xDF;
    reset_cpu();
    test_control_transitions();

    /* A01: real startup call chain, including nested interrupt-mask probe. */
    fiber_port_runtime_prepare_start();
    CHECK(primask == 0 && bundle_checks == 1 && vector_checks == 2);
    CHECK(first_irq_priority == 0x5A && svc_priority == 0 && pendsv_priority == 255);
    CHECK((ccr & fiber_portSCB_CCR_STKALIGN_BIT) != 0);
    for (unsigned int prior = 0; prior < 2; ++prior) {
        primask = prior;
        CHECK(fiber_port_probe_implemented_priority_mask() == 0xFF);
        CHECK(primask == prior && first_irq_priority == 0x5A);
    }
    primask = 0;

    /* A02: reject the previous overlay, then decode every enabled region. */
    memory_layout.privileged_sram_start = 0x30000000u;
    EXPECT_PANIC('L', fiber_port_mpu_linker_layout_check(&memory_layout));
    memory_layout.privileged_sram_start = 0x30000020u;
    FiberContext a, b;
    configure_context(&a, frame, 0);
    configure_context(&b, frame + 128, 1);
    load_mpu(&a);
    check_disjoint_mpu();

    /* A03/A04: synthetic first image and actual Handler saves both restore. */
    a.protected_context.basic.control = 3;
    a.protected_context.basic.pc = 0x08020020u;
    a.protected_context.basic.lr = 0x08040021u;
    fiber_port_context_validate_initial_restore(&a);
    a.protected_context.basic.control = 1;
    EXPECT_PANIC('q', fiber_port_context_validate_initial_restore(&a));
    a.protected_context.basic.control = 3;
    fiber_port_context_validate_restore(&a);
    a.protected_context.basic.control = 1;
    a.protected_context.basic.pc = 0x08040002u;
    fiber_port_context_validate_restore(&a);
    a.protected_context.basic.pc += 2;
    EXPECT_PANIC('c', fiber_port_context_validate_restore(&a));
    a.protected_context.basic.pc = 0x08040002u;
    a.protected_context.basic.control = 0;
    EXPECT_PANIC('q', fiber_port_context_validate_restore(&a));
    a.protected_context.basic.control = 1;
    fiber_port_context_validate_restore(&b);

    /* A03/A06/A07/A08: basic and extended yield, before lazy materialization,
     * with both live Handler FPCA values and poisoned inactive union metadata. */
    for (volatile unsigned int extended = 0; extended < 2; ++extended) {
        FiberContext *volatile ctx = extended ? &b : &a;
        uint32_t *volatile f = extended ? frame + 128 : frame;
        volatile uint32_t er = extended ? fiber_portEXTENDED_EXC_RETURN : fiber_portINITIAL_EXC_RETURN;
        ctx->protected_context_cursor = &ctx->protected_context.words[0];
        control = 3u;
        ipsr = 0u;
        host_exception_entry(11u);
        CHECK(__get_CONTROL() == 1u);
        psp = (uintptr_t)f; psplim = (uint32_t)ctx->boot.stack_base;
        load_mpu(ctx);
        for (unsigned int fpca = 0; fpca < 2; ++fpca) {
            __set_CONTROL(1u | (fpca << 2));
            reg_fpccr &= ~fiber_portFPCCR_LSPACT_BIT;
            if (FIBER_FPU_LAZY && extended) reg_fpccr |= fiber_portFPCCR_LSPACT_BIT;
            CHECK(fiber_port_running_svc_core_frame(ctx, f, er) == f);
            fiber_port_svc_dispatch(f, er, ctx);
            CHECK((int_ctrl & fiber_portNVIC_PENDSVSET_BIT) != 0 && primask == 0);
            int_ctrl = 0;
            ipsr = 14;
            fiber_port_pendsv_validate_save_current(ctx, f, er);
            ipsr = 11;
        }
        if (extended) {
            CHECK(ctx->protected_context.basic.cursor_limit != 0);
            CHECK(ctx->protected_context.basic.psplim != psplim);
        }
        /* A legal post-MSR value is not the entry state required by these
         * preflight validators. Never hide SPSEL by making MRS return RAZ. */
        __set_CONTROL(3u);
        CHECK(ipsr == 11u && __get_CONTROL() == 3u);
        EXPECT_PANIC('l', fiber_port_running_svc_core_frame(ctx, f, er));
        host_exception_entry(11u);
        CHECK(__get_CONTROL() == 1u);
        psplim += 32;
        EXPECT_PANIC('L', fiber_port_running_svc_core_frame(ctx, f, er));
        psplim -= 32;
        EXPECT_PANIC('l', fiber_port_running_svc_core_frame(ctx, f, 0));
    }
    if (FIBER_FPU_LAZY) {
        reg_fpccr |= fiber_portFPCCR_LSPACT_BIT;
        fiber_port_fpu_require_configured();
        EXPECT_PANIC('E', fiber_port_fpu_require_ready());
    }
    reg_fpccr &= ~fiber_portFPCCR_LSPACT_BIT;
    test_same_context_saved_representations(frame + 256);

    /* A12: inaccessible PSPs must panic in the production bounds checks. A read
     * before the guards would terminate this process instead of longjmp. */
    a.protected_context_cursor = &a.protected_context.words[0];
    control = 1; ipsr = 14; psplim = (uint32_t)a.boot.stack_base;
    psp = 0x1FFF0000u;
    EXPECT_PANIC('P', fiber_port_validate_running_context_frame(&a, (void *)psp, fiber_portINITIAL_EXC_RETURN));
    EXPECT_PANIC('P', fiber_port_running_svc_core_frame(&a, (void *)psp, fiber_portINITIAL_EXC_RETURN));
    psp = 0x20010000u;
    EXPECT_PANIC('P', fiber_port_validate_running_context_frame(&a, (void *)psp, fiber_portEXTENDED_EXC_RETURN));
    psp = UINTPTR_MAX & ~(uintptr_t)7;
    EXPECT_PANIC('O', fiber_port_validate_running_context_frame(&a, (void *)psp, fiber_portINITIAL_EXC_RETURN));
    psp = (uintptr_t)frame;
    a.boot.stack_top = psp + 32;
    fiber_port_validate_running_context_frame(&a, frame, fiber_portINITIAL_EXC_RETURN);
    frame[7] |= fiber_portXPSR_STACK_ALIGN_BIT;
    EXPECT_PANIC('P', fiber_port_validate_running_context_frame(&a, frame, fiber_portINITIAL_EXC_RETURN));
    frame[7] &= ~fiber_portXPSR_STACK_ALIGN_BIT;
    a.boot.stack_top = psp + 104;
    fiber_port_validate_running_context_frame(&a, frame, fiber_portEXTENDED_EXC_RETURN);
    frame[25] ^= fiber_portXPSR_STACK_ALIGN_BIT;
    fiber_port_validate_running_context_frame(&a, frame, fiber_portEXTENDED_EXC_RETURN);
    frame[7] |= fiber_portXPSR_STACK_ALIGN_BIT;
    EXPECT_PANIC('P', fiber_port_validate_running_context_frame(&a, frame, fiber_portEXTENDED_EXC_RETURN));
    a.boot.stack_top += 4;
    fiber_port_validate_running_context_frame(&a, frame, fiber_portEXTENDED_EXC_RETURN);
    frame[7] &= ~fiber_portXPSR_STACK_ALIGN_BIT;
    a.boot.stack_top = 0x20001000u;

    /* Actual scheduler bridge and MPU replacement, same-context then A-B-A.
     * Transfers themselves are target assembly, so cursor movement is modeled. */
    configure_context(&a, frame, 0);
    configure_context(&b, frame + 128, 1);
    current_slot = &a;
    for (unsigned int step = 0; step < 3; ++step) {
        scheduled = step == 1 ? &b : &a;
        ipsr = 14; control = 1; primask = 0; basepri = FIBER_PORT_SCHEDULER_BASEPRI;
        int_ctrl = 0;
        load_mpu(current_slot);
        CHECK(fiber_port_scheduler_pick_next_from_pendsv(current_slot) == scheduled);
        primask = 1;
        fiber_port_mpu_switch_to_context(scheduled);
        CHECK(current_slot == scheduled);
        CHECK(mpu_ctrl == fiber_portMPU_CTRL_REQUIRED);
        check_disjoint_mpu();
    }
    CHECK(publications == 3);
    CHECK(VirtualFree(frame, 0, MEM_RELEASE));
    CHECK(VirtualFree(veneers, 0, MEM_RELEASE));
    printf("PASS: %u source-derived state checks, %u regions, lazy=%u\n",
        checks, fiber_portMPU_TOTAL_REGIONS, FIBER_FPU_LAZY);
    return 0;
}
