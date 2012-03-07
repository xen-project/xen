/******************************************************************************
 * perfmon.c for xenoprof
 * This is based linux/arch/ia64/oprofile/perfmon.c, but heavily rewritten.
 *
 * Copyright (c) 2006 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
/**
 * @file perfmon.c
 *
 * @remark Copyright 2003 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon <levon@movementarian.org>
 */

#include <xen/config.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/xenoprof.h>
#include <asm/perfmon.h>
#include <asm/ptrace.h>
#include <asm/vmx.h>    /* for vmx_user_mode() */

// XXX move them to an appropriate header file
extern int is_active(struct domain *d);

static int allow_virq;
static int allow_ints;

static int
xenoprof_is_xen_mode(struct vcpu *v, struct pt_regs *regs)
{
    if (VMX_DOMAIN(v))
        return !vmx_user_mode(regs);
    return ring_0(regs);
}

static int
xenoprof_handler(struct task_struct *task, void *buf, pfm_ovfl_arg_t *arg,
                 struct pt_regs *regs, unsigned long stamp)
{
    unsigned long ip = profile_pc(regs);
    int event = arg->pmd_eventid;
    struct vcpu *v = current;
    int mode = xenoprofile_get_mode(v, regs);

    // see pfm_do_interrupt_handler() in xen/arch/ia64/linux-xen/perfmon.c.
    // It always passes task as NULL. This is work around
    BUG_ON(task != NULL);

    arg->ovfl_ctrl.bits.reset_ovfl_pmds = 1;
    if (!allow_virq || !allow_ints)
        return 0;

    // Note that log event actually expect cpu_user_regs, cast back 
    // appropriately when doing the backtrace implementation in ia64
    xenoprof_log_event(v, regs, ip, mode, event);
    // send VIRQ_XENOPROF
    if (is_active(v->domain) && !xenoprof_is_xen_mode(v, regs) &&
        !is_idle_vcpu(v))
        send_guest_vcpu_virq(v, VIRQ_XENOPROF);

    return 0;
}

// same as linux OPROFILE_FMT_UUID
#define XENOPROF_FMT_UUID { \
    0x77, 0x7a, 0x6e, 0x61, 0x20, 0x65, 0x73, 0x69, 0x74, 0x6e, 0x72, 0x20, 0x61, 0x65, 0x0a, 0x6c }

static pfm_buffer_fmt_t xenoprof_fmt = {
    .fmt_name    = "xenoprof_format",
    .fmt_uuid    = XENOPROF_FMT_UUID,
    .fmt_handler = xenoprof_handler,
};

static char * get_cpu_type(void)
{
    __u8 family = local_cpu_data->family;

    switch (family) {
        case 0x07:
            return "ia64/itanium";
        case 0x1f:
            return "ia64/itanium2";
        default:
            return "ia64/ia64";
    }
}

static int using_xenoprof;

int __init
xenprof_perfmon_init(void)
{
    int ret = pfm_register_buffer_fmt(&xenoprof_fmt);
    if (ret)
        return -ENODEV;
    using_xenoprof = 1;
    printk("xenoprof: using perfmon.\n");
    return 0;
}
__initcall(xenprof_perfmon_init);

#ifdef notyet
void xenoprof_perfmon_exit(void)
{
    if (!using_xenoprof)
        return;

    pfm_unregister_buffer_fmt(xenoprof_fmt.fmt_uuid);
}
__exitcall(xenoprof_perfmon_exit);
#endif

///////////////////////////////////////////////////////////////////////////
// glue methods for xenoprof and perfmon.
int
xenoprof_arch_init(int *num_events, char *cpu_type)
{
    *num_events = 0;
    strlcpy(cpu_type, get_cpu_type(), XENOPROF_CPU_TYPE_SIZE);
    return 0;
}

int
xenoprof_arch_reserve_counters(void)
{
    // perfmon takes care
    return 0;
}

int
xenoprof_arch_counter(XEN_GUEST_HANDLE(void) arg)
{
    return -ENOSYS;
}

int
xenoprof_arch_setup_events(void)
{
    // perfmon takes care
    return 0;
}

//XXX SMP: sync by IPI?
int
xenoprof_arch_enable_virq(void)
{
    allow_virq = 1;
    return 0;
}

//XXX SMP: sync by IPI?
int
xenoprof_arch_start(void)
{
	allow_ints = 1;
    return 0;
}

//XXX SMP: sync by IPI?
void
xenoprof_arch_stop(void)
{
	allow_ints = 0;
}

//XXX SMP: sync by IPI?
void
xenoprof_arch_disable_virq(void)
{
    allow_virq = 0;
}

void
xenoprof_arch_release_counters(void)
{
    // perfmon takes care
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
