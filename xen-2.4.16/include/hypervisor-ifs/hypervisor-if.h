/******************************************************************************
 * hypervisor-if.h
 * 
 * Interface to Xeno hypervisor.
 */

#include "network.h"
#include "block.h"

#ifndef __HYPERVISOR_IF_H__
#define __HYPERVISOR_IF_H__

typedef struct trap_info_st
{
    unsigned char  vector;  /* exception/interrupt vector */
    unsigned char  dpl;     /* privilege level            */
    unsigned short cs;      /* code selector              */
    unsigned long  address; /* code address               */
} trap_info_t;


typedef struct
{
#define PGREQ_ADD_BASEPTR    0
#define PGREQ_REMOVE_BASEPTR 1
    unsigned long ptr, val; /* *ptr = val */
} page_update_request_t;


/* EAX = vector; EBX, ECX, EDX, ESI, EDI = args 1, 2, 3, 4, 5. */

#define __HYPERVISOR_set_trap_table  0
#define __HYPERVISOR_pt_update       1
#define __HYPERVISOR_console_write   2
#define __HYPERVISOR_set_pagetable   3
#define __HYPERVISOR_set_guest_stack 4
#define __HYPERVISOR_net_update      5
#define __HYPERVISOR_fpu_taskswitch  6
#define __HYPERVISOR_yield           7
#define __HYPERVISOR_exit            8
#define __HYPERVISOR_dom0_op         9
#define __HYPERVISOR_network_op     10
#define __HYPERVISOR_set_debugreg   11
#define __HYPERVISOR_get_debugreg   12

#define TRAP_INSTR "int $0x82"


/* Event message note:
 *
 * Here, as in the interrupts to the guestos, additional network interfaces
 * are defined.  These definitions server as placeholders for the event bits,
 * however, in the code these events will allways be referred to as shifted
 * offsets from the base NET events.
 */

/* Events that a guest OS may receive from the hypervisor. */
#define EVENT_BLK_TX   0x01 /* packets for transmission. */
#define EVENT_BLK_RX   0x02 /* empty buffers for receive. */
#define EVENT_TIMER    0x04 /* a timeout has been updated. */
#define EVENT_DIE      0x08 /* OS is about to be killed. Clean up please! */
#define EVENT_NET_TX   0x10 /* packets for transmission. */
#define EVENT_NET_RX   0x20 /* empty buffers for receive. */
#define EVENT_NET2_TX  0x40 /* packets for transmission. */
#define EVENT_NET2_RX  0x80 /* empty buffers for receive. */

/* should these macros and the ones below test for range violation? */
#define EVENT_NET_TX_FOR_VIF(x)    (EVENT_NET_TX << (2 * x))
#define EVENT_NET_RX_FOR_VIF(x)    (EVENT_NET_RX << (2 * x))


/* Bit offsets, as opposed to the above masks. */
#define _EVENT_BLK_TX  0
#define _EVENT_BLK_RX  1
#define _EVENT_TIMER   2
#define _EVENT_DIE     3
#define _EVENT_NET_TX  4
#define _EVENT_NET_RX  5
#define _EVENT_NET2_TX 6
#define _EVENT_NET2_RX 7

#define _EVENT_NET_TX_FOR_VIF(x)    (_EVENT_NET_TX + (2 * x))
#define _EVENT_NET_RX_FOR_VIF(x)    (_EVENT_NET_RX + (2 * x))

/*
 * NB. We expect that this struct is smaller than a page.
 */
typedef struct shared_info_st {

    /* Bitmask of outstanding event notifications hypervisor -> guest OS. */
    unsigned long events;
    /*
     * Hypervisor will only signal event delivery via the "callback
     * exception" when this value is non-zero. Hypervisor clears this when
     * notiying the guest OS -- this prevents unbounded reentrancy and
     * stack overflow (in this way, acts as an interrupt-enable flag).
     */
    unsigned long events_enable;

    /*
     * Address for callbacks hypervisor -> guest OS.
     * Stack frame looks like that of an interrupt.
     * Code segment is the default flat selector.
     * This handler will only be called when events_enable is non-zero.
     */
    unsigned long event_address;

    /*
     * Hypervisor uses this callback when it takes a fault on behalf of
     * an application. This can happen when returning from interrupts for
     * example: various faults can occur when reloading the segment
     * registers, and executing 'iret'.
     * This callback is provided with an extended stack frame, augmented
     * with saved values for segment registers %ds and %es:
     *  %ds, %es, %eip, %cs, %eflags [, %oldesp, %oldss]
     * Code segment is the default flat selector.
     * FAULTS WHEN CALLING THIS HANDLER WILL TERMINATE THE DOMAIN!!!
     */
    unsigned long failsafe_address;

    /*
     * CPU ticks since start of day.
     * `wall_time' counts CPU ticks in real time.
     * `domain_time' counts CPU ticks during which this domain has run.
     */
    unsigned long ticks_per_ms; /* CPU ticks per millisecond */
    /*
     * Current wall_time can be found by rdtsc. Only possible use of
     * variable below is that it provides a timestamp for last update
     * of domain_time.
     */
    unsigned long long wall_time;
    unsigned long long domain_time;

    /*
     * Timeouts for points at which guest OS would like a callback.
     * This will probably be backed up by a timer heap in the guest OS.
     * In Linux we use timeouts to update 'jiffies'.
     */
    unsigned long long wall_timeout;
    unsigned long long domain_timeout;

    /*
     * Real-Time Clock. This shows time, in seconds, since 1.1.1980.
     * The timestamp shows the CPU 'wall time' when RTC was last read.
     * Thus it allows a mapping between 'real time' and 'wall time'.
     */
    unsigned long      rtc_time;
    unsigned long long rtc_timestamp;

} shared_info_t;

/*
 * NB. We expect that this struct is smaller than a page.
 */
typedef struct start_info_st {
    unsigned long nr_pages;       /* total pages allocated to this domain */
    shared_info_t *shared_info;   /* start address of shared info struct */
    unsigned long  pt_base;       /* address of page directory */
    unsigned long phys_base;
    unsigned long mod_start;      /* start address of pre-loaded module */
    unsigned long mod_len;        /* size (bytes) of pre-loaded module */
    net_ring_t *net_rings;
    int num_net_rings;
    blk_ring_t *blk_ring;         /* block io communication rings */
    unsigned long frame_table;    /* mapping of the frame_table for dom0 */
    unsigned char cmd_line[1];    /* variable-length */
} start_info_t;

/* For use in guest OSes. */
extern shared_info_t *HYPERVISOR_shared_info;

#endif /* __HYPERVISOR_IF_H__ */
