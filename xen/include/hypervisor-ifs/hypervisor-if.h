/******************************************************************************
 * hypervisor-if.h
 * 
 * Interface to Xeno hypervisor.
 */

#ifndef __HYPERVISOR_IF_H__
#define __HYPERVISOR_IF_H__

/*
 * SEGMENT DESCRIPTOR TABLES
 */
/* The first few GDT entries are reserved by Xen. */
#define FIRST_DOMAIN_GDT_ENTRY	40
/*
 * These flat segments are in the Xen-private section of every GDT. Since 
 * these are also present in the initial GDT, many OSes will be able to avoid 
 * installing their own GDT.
 */
#define FLAT_RING1_CS		0x0019
#define FLAT_RING1_DS		0x0021
#define FLAT_RING3_CS		0x002b
#define FLAT_RING3_DS		0x0033


/*
 * HYPERVISOR "SYSTEM CALLS"
 */

/* EAX = vector; EBX, ECX, EDX, ESI, EDI = args 1, 2, 3, 4, 5. */
#define __HYPERVISOR_set_trap_table	   0
#define __HYPERVISOR_pt_update		   1
#define __HYPERVISOR_console_write	   2
#define __HYPERVISOR_set_gdt		   3
#define __HYPERVISOR_stack_switch          4
#define __HYPERVISOR_set_callbacks         5
#define __HYPERVISOR_net_update		   6
#define __HYPERVISOR_fpu_taskswitch	   7
#define __HYPERVISOR_yield		   8
#define __HYPERVISOR_exit		   9
#define __HYPERVISOR_dom0_op		  10
#define __HYPERVISOR_network_op		  11
#define __HYPERVISOR_block_io_op	  12
#define __HYPERVISOR_set_debugreg	  13
#define __HYPERVISOR_get_debugreg	  14
#define __HYPERVISOR_update_descriptor	  15
#define __HYPERVISOR_set_fast_trap	  16
#define __HYPERVISOR_dom_mem_op		  17
#define __HYPERVISOR_multicall		  18
#define __HYPERVISOR_kbd_op               19
#define __HYPERVISOR_iopl                 20

/* And the trap vector is... */
#define TRAP_INSTR "int $0x82"


/*
 * MULTICALLS
 * 
 * Multicalls are listed in an array, with each element being a fixed size 
 * (BYTES_PER_MULTICALL_ENTRY). Each is of the form (op, arg1, ..., argN)
 * where each element of the tuple is a machine word. 
 */
#define BYTES_PER_MULTICALL_ENTRY 32


/* EVENT MESSAGES
 *
 * Here, as in the interrupts to the guestos, additional network interfaces
 * are defined.	 These definitions server as placeholders for the event bits,
 * however, in the code these events will allways be referred to as shifted
 * offsets from the base NET events.
 */

/* Events that a guest OS may receive from the hypervisor. */
#define EVENT_BLK_RESP 0x01 /* A block device response has been queued. */
#define EVENT_TIMER    0x02 /* A timeout has been updated. */
#define EVENT_DIE      0x04 /* OS is about to be killed. Clean up please! */
#define EVENT_DEBUG    0x08 /* Request guest to dump debug info (gross!) */
#define EVENT_NET_TX   0x10 /* There are packets for transmission. */
#define EVENT_NET_RX   0x20 /* There are empty buffers for receive. */
#define EVENT_KBD      0x40 /* PS/2 keyboard or mouse event(s) */

/* Bit offsets, as opposed to the above masks. */
#define _EVENT_BLK_RESP 0
#define _EVENT_TIMER	1
#define _EVENT_DIE	2
#define _EVENT_NET_TX	3
#define _EVENT_NET_RX	4
#define _EVENT_DEBUG	5
#define _EVENT_KBD      6

/*
 * Virtual addresses beyond this are not modifiable by guest OSes.
 * The machine->physical mapping table starts at this address, read-only
 * to all domains except DOM0.
 */
#define HYPERVISOR_VIRT_START (0xFC000000UL)
#ifndef machine_to_phys_mapping
#define machine_to_phys_mapping ((unsigned long *)HYPERVISOR_VIRT_START)
#endif


/*
 * PAGE UPDATE COMMANDS AND FLAGS
 * 
 * PGREQ_XXX: specified in least 2 bits of 'ptr' field. These bits are masked
 *  off to get the real 'ptr' value.
 * All requests specify relevent machine address in 'ptr'.
 * Normal requests specify update value in 'value'.
 * Extended requests specify command in least 8 bits of 'value'. These bits
 *  are masked off to get the real 'val' value. Except for PGEXT_SET_LDT 
 *  which shifts the least bits out.
 */
/* A normal page-table update request. */
#define PGREQ_NORMAL		0 /* does a checked form of '*ptr = val'   */
/* Update an entry in the machine->physical mapping table. */
#define PGREQ_MPT_UPDATE	1 /* ptr = frame to modify table entry for */
/* An extended command. */
#define PGREQ_EXTENDED_COMMAND	2 /* least 8 bits of val demux further     */
/* DOM0 can make entirely unchecked updates which do not affect refcnts. */
#define PGREQ_UNCHECKED_UPDATE	3 /* does an unchecked '*ptr = val'        */
/* Extended commands: */
#define PGEXT_PIN_L1_TABLE	0 /* ptr = frame to pin                    */
#define PGEXT_PIN_L2_TABLE	1 /* ptr = frame to pin                    */
#define PGEXT_PIN_L3_TABLE	2 /* ptr = frame to pin                    */
#define PGEXT_PIN_L4_TABLE	3 /* ptr = frame to pin                    */
#define PGEXT_UNPIN_TABLE	4 /* ptr = frame to unpin                  */
#define PGEXT_NEW_BASEPTR	5 /* ptr = new pagetable base to install   */
#define PGEXT_TLB_FLUSH		6 /* ptr = NULL                            */
#define PGEXT_INVLPG		7 /* ptr = NULL ; val = page to invalidate */
#define PGEXT_SET_LDT           8 /* ptr = linear address; val = # entries */
#define PGEXT_CMD_MASK	      255
#define PGEXT_CMD_SHIFT		8


/*
 * Master "switch" for enabling/disabling event delivery.
 */
#define EVENTS_MASTER_ENABLE_MASK 0x80000000UL
#define EVENTS_MASTER_ENABLE_BIT  31


#ifndef __ASSEMBLY__

#include "network.h"
#include "block.h"

/*
 * Send an array of these to HYPERVISOR_set_trap_table()
 */
typedef struct trap_info_st
{
    unsigned char  vector;  /* exception/interrupt vector */
    unsigned char  dpl;	    /* privilege level		  */
    unsigned short cs;	    /* code selector		  */
    unsigned long  address; /* code address		  */
} trap_info_t;

/*
 * Send an array of these to HYPERVISOR_pt_update()
 */
typedef struct
{
    unsigned long ptr, val; /* *ptr = val */
} page_update_request_t;

/*
 * Send an array of these to HYPERVISOR_multicall()
 */
typedef struct
{
    unsigned long op;
    unsigned long args[7];
} multicall_entry_t;

/*
 * Xen/guestos shared data -- pointer provided in start_info.
 * NB. We expect that this struct is smaller than a page.
 */
typedef struct shared_info_st {

    /* Bitmask of outstanding event notifications hypervisor -> guest OS. */
    unsigned long events;
    /*
     * Hypervisor will only signal event delivery via the "callback exception"
     * when a pending event is not masked. The mask also contains a "master
     * enable" which prevents any event delivery. This mask can be used to
     * prevent unbounded reentrancy and stack overflow (in this way, acts as a
     * kind of interrupt-enable flag).
     */
    unsigned long events_mask;

    /*
     * Time: The following abstractions are exposed: System Time, Clock Time,
     * Domain Virtual Time. Domains can access Cycle counter time directly.
     * XXX RN: Need something to pass NTP scaling to GuestOS.
     */

    u64		  cpu_freq;	    /* to calculate ticks -> real time */

    /* System Time */
    long long	       system_time;	/* in ns */
    unsigned long      st_timestamp;	/* cyclecounter at last update */

    /* Wall Clock Time */
    u32		       wc_version;	/* a version number for info below */
    long	       tv_sec;		/* essentially a struct timeval */
    long	       tv_usec;
    long long	       wc_timestamp;	/* system time at last update */
    
    /* Domain Virtual Time */
    unsigned long long domain_time;
	
    /*
     * Timeout values:
     * Allow a domain to specify a timeout value in system time and 
     * domain virtual time.
     */
    unsigned long long wall_timeout;
    unsigned long long domain_timeout;

    /*
     * The index structures are all stored here for convenience. The rings 
     * themselves are allocated by Xen but the guestos must create its own 
     * mapping -- the machine address is given in the startinfo structure to 
     * allow this to happen.
     */
    net_idx_t net_idx[MAX_DOMAIN_VIFS];

} shared_info_t;

/*
 * NB. We expect that this struct is smaller than a page.
 */
typedef struct start_info_st {
    unsigned long nr_pages;	  /* total pages allocated to this domain */
    shared_info_t *shared_info;	  /* VIRTUAL address of shared info struct */
    unsigned long  pt_base;	  /* VIRTUAL address of page directory */
    unsigned long mod_start;	  /* VIRTUAL address of pre-loaded module */
    unsigned long mod_len;	  /* size (bytes) of pre-loaded module */
    /* Machine address of net rings for each VIF. Will be page aligned. */
    unsigned long net_rings[MAX_DOMAIN_VIFS];
    /* Machine address of block-device ring. Will be page aligned. */
    unsigned long blk_ring;
    unsigned int  dom_id;
    unsigned long flags; 
    unsigned char cmd_line[1];	  /* variable-length */
} start_info_t;

/* These flags are passed in the 'flags' field of start_info_t. */
#define SIF_PRIVILEGED 1          /* Is the domain privileged? */
#define SIF_CONSOLE    2          /* Does the domain own the physical console? */

/* For use in guest OSes. */
extern shared_info_t *HYPERVISOR_shared_info;

#endif /* !__ASSEMBLY__ */

#endif /* __HYPERVISOR_IF_H__ */
