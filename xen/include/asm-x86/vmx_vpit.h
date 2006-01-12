#ifndef _VMX_VIRPIT_H
#define _VMX_VIRPIT_H

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/time.h>
#include <xen/errno.h>
#include <xen/timer.h>
#include <asm/vmx_vmcs.h>
#include <asm/vmx_vpic.h>

#define PIT_FREQ 1193181

#define LSByte 0
#define MSByte 1
#define LSByte_multiple 2
#define MSByte_multiple 3

struct vmx_virpit {
    /* for simulation of counter 0 in mode 2*/
    u64 period_cycles;	                /* pit frequency in cpu cycles */
    u64 inject_point; /* the time inject virt intr */
    u64 shift;  /* save the value of offset - drift */
    s_time_t scheduled;                 /* scheduled timer interrupt */
    struct timer pit_timer;  /* periodic timer for mode 2*/
    unsigned int channel;  /* the pit channel, counter 0~2 */
    unsigned int pending_intr_nr; /* the couner for pending timer interrupts */
    u32 period;		/* pit frequency in ns */
    int first_injected;                 /* flag to prevent shadow window */

    /* virtual PIT state for handle related I/O */
    int read_state;
    int count_LSB_latched;
    int count_MSB_latched;

    unsigned int count;  /* the 16 bit channel count */
    unsigned int init_val; /* the init value for the counter */
};

/* to hook the ioreq packet to get the PIT initializaiton info */
extern void vmx_hooks_assist(struct vcpu *v);

static __inline__ s_time_t get_pit_scheduled(
    struct vcpu *v, 
    struct vmx_virpit *vpit)
{
    if ( is_irq_enabled(v, 0) ) {
        return vpit->scheduled;
    }
    else
        return -1;
}
extern void set_tsc_shift(struct vcpu *v,struct vmx_virpit *vpit);

#endif /* _VMX_VIRPIT_H_ */
