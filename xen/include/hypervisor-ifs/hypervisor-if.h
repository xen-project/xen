/******************************************************************************
 * hypervisor-if.h
 * 
 * Guest OS interface to Xen.
 */

#ifndef __HYPERVISOR_IF_H__
#define __HYPERVISOR_IF_H__

#include "arch/hypervisor-if.h"

/*
 * HYPERVISOR "SYSTEM CALLS"
 */

/* EAX = vector; EBX, ECX, EDX, ESI, EDI = args 1, 2, 3, 4, 5. */
#define __HYPERVISOR_set_trap_table        0
#define __HYPERVISOR_mmu_update            1
#define __HYPERVISOR_console_write         2 /* DEPRECATED */
#define __HYPERVISOR_set_gdt               3
#define __HYPERVISOR_stack_switch          4
#define __HYPERVISOR_set_callbacks         5
#define __HYPERVISOR_net_io_op             6
#define __HYPERVISOR_fpu_taskswitch        7
#define __HYPERVISOR_sched_op              8
#define __HYPERVISOR_dom0_op               9
#define __HYPERVISOR_network_op           10
#define __HYPERVISOR_block_io_op          11
#define __HYPERVISOR_set_debugreg         12
#define __HYPERVISOR_get_debugreg         13
#define __HYPERVISOR_update_descriptor    14
#define __HYPERVISOR_set_fast_trap        15
#define __HYPERVISOR_dom_mem_op           16
#define __HYPERVISOR_multicall            17
#define __HYPERVISOR_kbd_op               18
#define __HYPERVISOR_update_va_mapping    19
#define __HYPERVISOR_set_timer_op         20
#define __HYPERVISOR_event_channel_op     21
#define __HYPERVISOR_xen_version          22
#define __HYPERVISOR_console_io           23
#define __HYPERVISOR_physdev_op           24

/*
 * MULTICALLS
 * 
 * Multicalls are listed in an array, with each element being a fixed size 
 * (BYTES_PER_MULTICALL_ENTRY). Each is of the form (op, arg1, ..., argN)
 * where each element of the tuple is a machine word. 
 */
#define ARGS_PER_MULTICALL_ENTRY 8


/* 
 * VIRTUAL INTERRUPTS
 * 
 * Virtual interrupts that a guest OS may receive from the hypervisor.
 */

#define VIRQ_BLKDEV     0  /* A block device response has been queued. */
#define VIRQ_TIMER      1  /* A timeout has been updated. */
#define VIRQ_DIE        2  /* OS is about to be killed. Clean up please! */
#define VIRQ_DEBUG      3  /* Request guest to dump debug info (gross!) */
#define VIRQ_NET        4  /* There are packets for transmission. */
#define VIRQ_PS2        5  /* PS/2 keyboard or mouse event(s) */
#define VIRQ_STOP       6  /* Prepare for stopping and possible pickling */
#define VIRQ_EVTCHN     7  /* Event pending on an event channel */
#define VIRQ_VBD_UPD    8  /* Event to signal VBDs should be reprobed */
#define VIRQ_CONSOLE    9  /* This is only for domain-0 initial console. */
#define VIRQ_PHYSIRQ   10  /* Event to signal pending physical IRQs. */
#define VIRQ_MISDIRECT 11  /* Catch-all virtual interrupt. */
#define NR_VIRQS       12

/*
 * MMU_XXX: specified in least 2 bits of 'ptr' field. These bits are masked
 *  off to get the real 'ptr' value.
 * All requests specify relevent address in 'ptr'. This is either a
 * machine/physical address (MA), or linear/virtual address (VA).
 * Normal requests specify update value in 'value'.
 * Extended requests specify command in least 8 bits of 'value'. These bits
 *  are masked off to get the real 'val' value. Except for MMUEXT_SET_LDT 
 *  which shifts the least bits out.
 */
/* A normal page-table update request. */
#define MMU_NORMAL_PT_UPDATE     0 /* checked '*ptr = val'. ptr is MA.       */
/* Update an entry in the machine->physical mapping table. */
#define MMU_MACHPHYS_UPDATE      2 /* ptr = MA of frame to modify entry for  */
/* An extended command. */
#define MMU_EXTENDED_COMMAND     3 /* least 8 bits of val demux further      */
/* Extended commands: */
#define MMUEXT_PIN_L1_TABLE      0 /* ptr = MA of frame to pin               */
#define MMUEXT_PIN_L2_TABLE      1 /* ptr = MA of frame to pin               */
#define MMUEXT_PIN_L3_TABLE      2 /* ptr = MA of frame to pin               */
#define MMUEXT_PIN_L4_TABLE      3 /* ptr = MA of frame to pin               */
#define MMUEXT_UNPIN_TABLE       4 /* ptr = MA of frame to unpin             */
#define MMUEXT_NEW_BASEPTR       5 /* ptr = MA of new pagetable base         */
#define MMUEXT_TLB_FLUSH         6 /* ptr = NULL                             */
#define MMUEXT_INVLPG            7 /* ptr = NULL ; val = VA to invalidate    */
#define MMUEXT_SET_LDT           8 /* ptr = VA of table; val = # entries     */
/* NB. MMUEXT_SET_SUBJECTDOM must consist of *_L followed immediately by *_H */
#define MMUEXT_SET_SUBJECTDOM_L  9 /* (ptr[31:15],val[31:15]) = dom[31:0]    */
#define MMUEXT_SET_SUBJECTDOM_H 10 /* (ptr[31:15],val[31:15]) = dom[63:32]   */
#define MMUEXT_CMD_MASK        255
#define MMUEXT_CMD_SHIFT         8

/* These are passed as 'flags' to update_va_mapping. They can be ORed. */
#define UVMF_FLUSH_TLB          1 /* Flush entire TLB. */
#define UVMF_INVLPG             2 /* Flush the VA mapping being updated. */


/*
 * SCHEDOP_* - Scheduler hypercall operations.
 */
#define SCHEDOP_yield           0   /* Give up the CPU voluntarily.      */
#define SCHEDOP_block           1   /* Block until an event is received. */
#define SCHEDOP_exit            3   /* Exit and kill this domain.        */
#define SCHEDOP_stop            4   /* Stop executing this domain.       */

/*
 * Commands to HYPERVISOR_console_io().
 */
#define CONSOLEIO_write         0
#define CONSOLEIO_read          1

#ifndef __ASSEMBLY__

typedef u64 domid_t;
/* DOMID_SELF is used in certain contexts to refer to oneself. */
#define DOMID_SELF (~1ULL)

#include "network.h"
#include "block.h"

/*
 * Send an array of these to HYPERVISOR_mmu_update()
 */
typedef struct
{
    unsigned long ptr, val; /* *ptr = val */
} mmu_update_t;

/*
 * Send an array of these to HYPERVISOR_multicall()
 */
typedef struct
{
    unsigned long op;
    unsigned long args[7];
} multicall_entry_t;

/* Event channel endpoints per domain. */
#define NR_EVENT_CHANNELS 1024

/*
 * Xen/guestos shared data -- pointer provided in start_info.
 * NB. We expect that this struct is smaller than a page.
 */
typedef struct shared_info_st
{
    /*
     * If bit 0 in evtchn_upcall_pending is transitioned 0->1, and bit 0 in 
     * evtchn_upcall_mask is clear, then an asynchronous upcall is scheduled. 
     * The upcall mask can be used to prevent unbounded reentrancy and stack 
     * overflow (in this way, acts as a kind of interrupt-enable flag).
     */
    unsigned long evtchn_upcall_pending;
    unsigned long evtchn_upcall_mask;

    /*
     * A domain can have up to 1024 "event channels" on which it can send
     * and receive asynchronous event notifications. There are three classes
     * of event that are delivered by this mechanism:
     *  1. Bi-directional inter- and intra-domain connections. Domains must
     *     arrange out-of-band to set up a connection (usually the setup
     *     is initiated and organised by a privileged third party such as
     *     software running in domain 0).
     *  2. Physical interrupts. A domain with suitable hardware-access
     *     privileges can bind an event-channel port to a physical interrupt
     *     source.
     *  3. Virtual interrupts ('events'). A domain can bind an event-channel
     *     port to a virtual interrupt source, such as the virtual-timer
     *     device or the emergency console.
     * 
     * Event channels are addressed by a "port index" between 0 and 1023.
     * Each channel is associated with three bits of information:
     *  1. PENDING -- notifies the domain that there is a pending notification
     *     to be processed. This bit is cleared by the guest.
     *  2. EXCEPTION -- notifies the domain that there has been some
     *     exceptional event associated with this channel (e.g. remote
     *     disconnect, physical IRQ error). This bit is cleared by the guest.
     *     A 0->1 transition of this bit will cause the PENDING bit to be set.
     *  3. MASK -- if this bit is clear then a 0->1 transition of PENDING
     *     will cause an asynchronous upcall to be scheduled. This bit is only
     *     updated by the guest. It is read-only within Xen. If a channel
     *     becomes pending while the channel is masked then the 'edge' is lost
     *     (i.e., when the channel is unmasked, the guest must manually handle
     *     pending notifications as no upcall will be scheduled by Xen).
     * 
     * To expedite scanning of pending notifications, any 0->1 pending
     * transition on an unmasked channel causes a corresponding bit in a
     * 32-bit selector to be set. Each bit in the selector covers a 32-bit
     * word in the PENDING bitfield array.
     */
    u32 evtchn_pending[32];
    u32 evtchn_pending_sel;
    u32 evtchn_exception[32];
    u32 evtchn_mask[32];

    /*
     * Time: The following abstractions are exposed: System Time, Clock Time,
     * Domain Virtual Time. Domains can access Cycle counter time directly.
     */
    u64                cpu_freq;        /* CPU frequency (Hz).               */

    /*
     * The following values are updated periodically (and not necessarily
     * atomically!). The guest OS detects this because 'time_version1' is
     * incremented just before updating these values, and 'time_version2' is
     * incremented immediately after. See the Xen-specific Linux code for an
     * example of how to read these values safely (arch/xen/kernel/time.c).
     */
    unsigned long      time_version1;   /* A version number for info below.  */
    unsigned long      time_version2;   /* A version number for info below.  */
    tsc_timestamp_t    tsc_timestamp;   /* TSC at last update of time vals.  */
    u64                system_time;     /* Time, in nanosecs, since boot.    */
    unsigned long      wc_sec;          /* Secs  00:00:00 UTC, Jan 1, 1970.  */
    unsigned long      wc_usec;         /* Usecs 00:00:00 UTC, Jan 1, 1970.  */
    u64                domain_time;     /* Domain virtual time, in nanosecs. */

    /*
     * Timeout values:
     * Allow a domain to specify a timeout value in system time and 
     * domain virtual time.
     */
    u64                wall_timeout;
    u64                domain_timeout;

    /*
     * The index structures are all stored here for convenience. The rings 
     * themselves are allocated by Xen but the guestos must create its own 
     * mapping -- the machine address is given in the startinfo structure to 
     * allow this to happen.
     */
    net_idx_t net_idx[MAX_DOMAIN_VIFS];

    execution_context_t execution_context;

} shared_info_t;

/*
 * NB. We expect that this struct is smaller than a page.
 */
typedef struct start_info_st {
    /* THE FOLLOWING ARE FILLED IN BOTH ON INITIAL BOOT AND ON RESUME.     */
    unsigned long nr_pages;	  /* total pages allocated to this domain. */
    unsigned long shared_info;	  /* MACHINE address of shared info struct.*/
    unsigned long flags;          /* SIF_xxx flags.                        */
    /* THE FOLLOWING ARE ONLY FILLED IN ON INITIAL BOOT (NOT RESUME).      */
    unsigned long pt_base;	  /* VIRTUAL address of page directory.    */
    unsigned long mod_start;	  /* VIRTUAL address of pre-loaded module. */
    unsigned long mod_len;	  /* Size (bytes) of pre-loaded module.    */
    unsigned char cmd_line[1];	  /* Variable-length options.              */
} start_info_t;

/* These flags are passed in the 'flags' field of start_info_t. */
#define SIF_PRIVILEGED 1          /* Is the domain privileged? */
#define SIF_INITDOMAIN 2          /* Is thsi the initial control domain? */

/* For use in guest OSes. */
extern shared_info_t *HYPERVISOR_shared_info;

#endif /* !__ASSEMBLY__ */

#endif /* __HYPERVISOR_IF_H__ */
