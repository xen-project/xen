#ifndef _VMX_VIRPIT_H
#define _VMX_VIRPIT_H
#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/time.h>
#include <xen/errno.h>
#include <xen/ac_timer.h>
#include <asm/vmx_vmcs.h>

#define PIT_FREQ 1193181

#define LSByte 0
#define MSByte 1
#define LSByte_multiple 2
#define MSByte_multiple 3

struct vmx_virpit_t {
    /* for simulation of counter 0 in mode 2*/
    int vector;				/* the pit irq vector */
    unsigned int period;		/* the frequency. e.g. 10ms*/
    unsigned int channel;		/* the pit channel, counter 0~2 */
    unsigned long *intr_bitmap;
    unsigned int pending_intr_nr;	/* the couner for pending timer interrupts */
    unsigned long long inject_point;	/* the time inject virt intr */
    struct ac_timer pit_timer;		/* periodic timer for mode 2*/
    int first_injected;                 /* flag to prevent shadow window */

    /* virtual PIT state for handle related I/O */
    int read_state;
    int count_LSB_latched;
    int count_MSB_latched;

    unsigned int count;		/* the 16 bit channel count */
    unsigned int init_val;	/* the init value for the counter */

} ;

/* to hook the ioreq packet to get the PIT initializaiton info */
extern void vmx_hooks_assist(struct exec_domain *d);

#endif /* _VMX_VIRPIT_H_ */
