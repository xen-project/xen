/*
 * xen/arch/arm/vsmc.c
 *
 * Generic handler for SMC and HVC calls according to
 * ARM SMC calling convention
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */


#include <xen/lib.h>
#include <xen/types.h>
#include <public/arch-arm/smccc.h>
#include <asm/monitor.h>
#include <asm/psci.h>
#include <asm/regs.h>
#include <asm/smccc.h>
#include <asm/traps.h>

/* Number of functions currently supported by Hypervisor Service. */
#define XEN_SMCCC_FUNCTION_COUNT 3

/* Number of functions currently supported by Standard Service Service Calls. */
#define SSSC_SMCCC_FUNCTION_COUNT 13

static bool fill_uid(struct cpu_user_regs *regs, xen_uuid_t uuid)
{
    int n;

    /*
     * UID is returned in registers r0..r3, four bytes per register,
     * first byte is stored in low-order bits of a register.
     * (ARM DEN 0028B page 14)
     */
    for (n = 0; n < 4; n++)
    {
        const uint8_t *bytes = uuid.a + n * 4;
        uint32_t r;

        r = bytes[0];
        r |= bytes[1] << 8;
        r |= bytes[2] << 16;
        r |= bytes[3] << 24;

        set_user_reg(regs, n, r);
    }

    return true;
}

static bool fill_revision(struct cpu_user_regs *regs, uint32_t major,
                         uint32_t minor)
{
    /*
     * Revision is returned in registers r0 and r1.
     * r0 stores major part of the version
     * r1 stores minor part of the version
     * (ARM DEN 0028B page 15)
     */
    set_user_reg(regs, 0, major);
    set_user_reg(regs, 1, minor);

    return true;
}

static bool fill_function_call_count(struct cpu_user_regs *regs, uint32_t cnt)
{
    /*
     * Function call count is retuned as any other return value in register r0
     * (ARM DEN 0028B page 17)
     */
    set_user_reg(regs, 0, cnt);

    return true;
}

/* SMCCC interface for hypervisor. Tell about itself. */
static bool handle_hypervisor(struct cpu_user_regs *regs)
{
    switch ( smccc_get_fn(get_user_reg(regs, 0)) )
    {
    case ARM_SMCCC_FUNC_CALL_COUNT:
        return fill_function_call_count(regs, XEN_SMCCC_FUNCTION_COUNT);
    case ARM_SMCCC_FUNC_CALL_UID:
        return fill_uid(regs, XEN_SMCCC_UID);
    case ARM_SMCCC_FUNC_CALL_REVISION:
        return fill_revision(regs, XEN_SMCCC_MAJOR_REVISION,
                             XEN_SMCCC_MINOR_REVISION);
    default:
        return false;
    }
}

#define PSCI_SET_RESULT(reg, val) set_user_reg(reg, 0, val)
#define PSCI_ARG(reg, n) get_user_reg(reg, n)

#ifdef CONFIG_ARM_64
#define PSCI_ARG32(reg, n) (uint32_t)(get_user_reg(reg, n))
#else
#define PSCI_ARG32(reg, n) PSCI_ARG(reg, n)
#endif

/* Existing (pre SMCCC) APIs. This includes PSCI 0.1 interface */
static bool handle_existing_apis(struct cpu_user_regs *regs)
{
    /* Only least 32 bits are significant (ARM DEN 0028B, page 12) */
    switch ( (uint32_t)get_user_reg(regs, 0) )
    {
    case PSCI_cpu_off:
    {
        uint32_t pstate = PSCI_ARG32(regs, 1);

        perfc_incr(vpsci_cpu_off);
        PSCI_SET_RESULT(regs, do_psci_cpu_off(pstate));
        return true;
    }
    case PSCI_cpu_on:
    {
        uint32_t vcpuid = PSCI_ARG32(regs, 1);
        register_t epoint = PSCI_ARG(regs, 2);

        perfc_incr(vpsci_cpu_on);
        PSCI_SET_RESULT(regs, do_psci_cpu_on(vcpuid, epoint));
        return true;
    }
    default:
        return false;
    }
}

/* PSCI 0.2 interface and other Standard Secure Calls */
static bool handle_sssc(struct cpu_user_regs *regs)
{
    uint32_t fid = (uint32_t)get_user_reg(regs, 0);

    switch ( smccc_get_fn(fid) )
    {
    case PSCI_0_2_FN_PSCI_VERSION:
        perfc_incr(vpsci_version);
        PSCI_SET_RESULT(regs, do_psci_0_2_version());
        return true;

    case PSCI_0_2_FN_CPU_OFF:
        perfc_incr(vpsci_cpu_off);
        PSCI_SET_RESULT(regs, do_psci_0_2_cpu_off());
        return true;

    case PSCI_0_2_FN_MIGRATE_INFO_TYPE:
        perfc_incr(vpsci_migrate_info_type);
        PSCI_SET_RESULT(regs, do_psci_0_2_migrate_info_type());
        return true;

    case PSCI_0_2_FN_MIGRATE_INFO_UP_CPU:
        perfc_incr(vpsci_migrate_info_up_cpu);
        PSCI_SET_RESULT(regs, do_psci_0_2_migrate_info_up_cpu());
        return true;

    case PSCI_0_2_FN_SYSTEM_OFF:
        perfc_incr(vpsci_system_off);
        do_psci_0_2_system_off();
        PSCI_SET_RESULT(regs, PSCI_INTERNAL_FAILURE);
        return true;

    case PSCI_0_2_FN_SYSTEM_RESET:
        perfc_incr(vpsci_system_reset);
        do_psci_0_2_system_reset();
        PSCI_SET_RESULT(regs, PSCI_INTERNAL_FAILURE);
        return true;

    case PSCI_0_2_FN_CPU_ON:
    {
        register_t vcpuid = PSCI_ARG(regs, 1);
        register_t epoint = PSCI_ARG(regs, 2);
        register_t cid = PSCI_ARG(regs, 3);

        perfc_incr(vpsci_cpu_on);
        PSCI_SET_RESULT(regs, do_psci_0_2_cpu_on(vcpuid, epoint, cid));
        return true;
    }

    case PSCI_0_2_FN_CPU_SUSPEND:
    {
        uint32_t pstate = PSCI_ARG32(regs, 1);
        register_t epoint = PSCI_ARG(regs, 2);
        register_t cid = PSCI_ARG(regs, 3);

        perfc_incr(vpsci_cpu_suspend);
        PSCI_SET_RESULT(regs, do_psci_0_2_cpu_suspend(pstate, epoint, cid));
        return true;
    }

    case PSCI_0_2_FN_AFFINITY_INFO:
    {
        register_t taff = PSCI_ARG(regs, 1);
        uint32_t laff = PSCI_ARG32(regs, 2);

        perfc_incr(vpsci_cpu_affinity_info);
        PSCI_SET_RESULT(regs, do_psci_0_2_affinity_info(taff, laff));
        return true;
    }

    case PSCI_0_2_FN_MIGRATE:
    {
        uint32_t tcpu = PSCI_ARG32(regs, 1);

        perfc_incr(vpsci_cpu_migrate);
        PSCI_SET_RESULT(regs, do_psci_0_2_migrate(tcpu));
        return true;
    }

    case ARM_SMCCC_FUNC_CALL_COUNT:
        return fill_function_call_count(regs, SSSC_SMCCC_FUNCTION_COUNT);

    case ARM_SMCCC_FUNC_CALL_UID:
        return fill_uid(regs, SSSC_SMCCC_UID);

    case ARM_SMCCC_FUNC_CALL_REVISION:
        return fill_revision(regs, SSSC_SMCCC_MAJOR_REVISION,
                             SSSC_SMCCC_MINOR_REVISION);

    default:
        return false;
    }
}

/*
 * vsmccc_handle_call() - handle SMC/HVC call according to ARM SMCCC.
 * returns true if that was valid SMCCC call (even if function number
 * was unknown).
 */
static bool vsmccc_handle_call(struct cpu_user_regs *regs)
{
    bool handled = false;
    const union hsr hsr = { .bits = regs->hsr };
    register_t funcid = get_user_reg(regs, 0);

    /*
     * Check immediate value for HVC32, HVC64 and SMC64.
     * It is not so easy to check immediate value for SMC32,
     * because it is not stored in HSR.ISS field. To get immediate
     * value we need to disassemble instruction at current pc, which
     * is expensive. So we will assume that it is 0x0.
     */
    switch ( hsr.ec )
    {
    case HSR_EC_HVC32:
#ifdef CONFIG_ARM_64
    case HSR_EC_HVC64:
    case HSR_EC_SMC64:
#endif
        if ( (hsr.iss & HSR_XXC_IMM_MASK) != 0)
            return false;
        break;
    case HSR_EC_SMC32:
        break;
    default:
        return false;
    }

    /* 64 bit calls are allowed only from 64 bit domains. */
    if ( smccc_is_conv_64(funcid) && is_32bit_domain(current->domain) )
    {
        set_user_reg(regs, 0, ARM_SMCCC_ERR_UNKNOWN_FUNCTION);
        return true;
    }

    /*
     * Special case: identifier range for existing APIs.
     * This range is described in SMCCC (ARM DEN 0028B, page 16),
     * but it does not conforms to standard function identifier
     * encoding.
     */
    if ( funcid >= ARM_SMCCC_RESERVED_RANGE_START &&
         funcid <= ARM_SMCCC_RESERVED_RANGE_END )
        handled = handle_existing_apis(regs);
    else
    {
        switch ( smccc_get_owner(funcid) )
        {
        case ARM_SMCCC_OWNER_HYPERVISOR:
            handled = handle_hypervisor(regs);
            break;
        case ARM_SMCCC_OWNER_STANDARD:
            handled = handle_sssc(regs);
            break;
        }
    }

    if ( !handled )
    {
        gprintk(XENLOG_INFO, "Unhandled SMC/HVC: %08"PRIregister"\n", funcid);

        /* Inform caller that function is not supported. */
        set_user_reg(regs, 0, ARM_SMCCC_ERR_UNKNOWN_FUNCTION);
    }

    return true;
}

void do_trap_smc(struct cpu_user_regs *regs, const union hsr hsr)
{
    int rc = 0;

    if ( !check_conditional_instr(regs, hsr) )
    {
        advance_pc(regs, hsr);
        return;
    }

    /* If monitor is enabled, let it handle the call. */
    if ( current->domain->arch.monitor.privileged_call_enabled )
        rc = monitor_smc();

    if ( rc == 1 )
        return;

    /*
     * Use standard routines to handle the call.
     * vsmccc_handle_call() will return false if this call is not
     * SMCCC compatible (e.g. immediate value != 0). As it is not
     * compatible, we can't be sure that guest will understand
     * ARM_SMCCC_ERR_UNKNOWN_FUNCTION.
     */
    if ( vsmccc_handle_call(regs) )
        advance_pc(regs, hsr);
    else
        inject_undef_exception(regs, hsr);
}

void do_trap_hvc_smccc(struct cpu_user_regs *regs)
{
    const union hsr hsr = { .bits = regs->hsr };

    /*
     * vsmccc_handle_call() will return false if this call is not
     * SMCCC compatible (e.g. immediate value != 0). As it is not
     * compatible, we can't be sure that guest will understand
     * ARM_SMCCC_ERR_UNKNOWN_FUNCTION.
     */
    if ( !vsmccc_handle_call(regs) )
        inject_undef_exception(regs, hsr);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
