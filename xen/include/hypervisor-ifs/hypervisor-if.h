/******************************************************************************
 * hypervisor-if.h
 * 
 * Guest OS interface to Xen.
 */

#ifndef __HYPERVISOR_IF_H__
#define __HYPERVISOR_IF_H__

/* GCC-specific way to pack structure definitions (no implicit padding). */
#define PACKED __attribute__ ((packed))

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
#define __HYPERVISOR_update_va_mapping_otherdomain 25

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
 * MMU-UPDATE REQUESTS
 * 
 * HYPERVISOR_mmu_update() accepts a list of (ptr, val) pairs.
 * ptr[1:0] specifies the appropriate MMU_* command.
 * 
 * GPS (General-Purpose Subject)
 * -----------------------------
 *  This domain that must own all non-page-table pages that are involved in
 *  MMU updates. By default it is the domain that executes mmu_update(). If the
 *  caller has sufficient privilege then it can be changed by executing
 *  MMUEXT_SET_SUBJECTDOM.
 * 
 * PTS (Page-Table Subject)
 * ------------------------
 *  This domain must own all the page-table pages that are subject to MMU
 *  updates. By default it is the domain that executes mmu_update(). If the
 *  caller has sufficient privilege then it can be changed by executing
 *  MMUEXT_SET_SUBJECTDOM with val[14] (SET_PAGETABLE_SUBJECTDOM) set.
 * 
 * ptr[1:0] == MMU_NORMAL_PT_UPDATE:
 * Updates an entry in a page table.
 * ptr[:2]  -- machine address of the page-table entry to modify [1]
 * val      -- value to write [2]
 * 
 * ptr[1:0] == MMU_MACHPHYS_UPDATE:
 * Updates an entry in the machine->pseudo-physical mapping table.
 * ptr[:2]  -- machine address within the frame whose mapping to modify [3]
 * val      -- value to write into the mapping entry
 *  
 * ptr[1:0] == MMU_EXTENDED_COMMAND:
 * val[7:0] -- MMUEXT_* command
 * 
 *   val[7:0] == MMUEXT_(UN)PIN_*_TABLE:
 *   ptr[:2]  -- machine address of frame to be (un)pinned as a p.t. page [1]
 * 
 *   val[7:0] == MMUEXT_NEW_BASEPTR:
 *   ptr[:2]  -- machine address of new page-table base to install in MMU [1]
 * 
 *   val[7:0] == MMUEXT_TLB_FLUSH:
 *   no additional arguments
 * 
 *   val[7:0] == MMUEXT_INVLPG:
 *   ptr[:2]  -- linear address to be flushed from the TLB
 * 
 *   val[7:0] == MMUEXT_SET_LDT:
 *   ptr[:2]  -- linear address of LDT base (NB. must be page-aligned)
 *   val[:8]  -- number of entries in LDT
 * 
 *   val[7:0] == MMUEXT_SET_SUBJECTDOM:
 *   val[14]  -- if TRUE then sets the PTS in addition to the GPS.
 *   (ptr[31:15],val[31:15]) -- dom[31:0]
 * 
 *   val[7:0] == MMUEXT_REASSIGN_PAGE:
 *   ptr[:2]  -- machine address within page to be reassigned to the GPS.
 * 
 *   val[7:0] == MMUEXT_RESET_SUBJECTDOM:
 *   Resets both the GPS and the PTS to their defaults (i.e., calling domain).
 * 
 * Notes on constraints on the above arguments:
 *  [1] The page frame containing the machine address must belong to the PTS.
 *  [2] If the PTE is valid (i.e., bit 0 is set) then the specified page frame
 *      must belong to: 
 *       (a) the PTS (if the PTE is part of a non-L1 table); or
 *       (b) the GPS (if the PTE is part of an L1 table).
 *  [3] The page frame containing the machine address must belong to the GPS.
 */
#define MMU_NORMAL_PT_UPDATE     0 /* checked '*ptr = val'. ptr is MA.       */
#define MMU_MACHPHYS_UPDATE      2 /* ptr = MA of frame to modify entry for  */
#define MMU_EXTENDED_COMMAND     3 /* least 8 bits of val demux further      */
#define MMUEXT_PIN_L1_TABLE      0 /* ptr = MA of frame to pin               */
#define MMUEXT_PIN_L2_TABLE      1 /* ptr = MA of frame to pin               */
#define MMUEXT_PIN_L3_TABLE      2 /* ptr = MA of frame to pin               */
#define MMUEXT_PIN_L4_TABLE      3 /* ptr = MA of frame to pin               */
#define MMUEXT_UNPIN_TABLE       4 /* ptr = MA of frame to unpin             */
#define MMUEXT_NEW_BASEPTR       5 /* ptr = MA of new pagetable base         */
#define MMUEXT_TLB_FLUSH         6 /* ptr = NULL                             */
#define MMUEXT_INVLPG            7 /* ptr = VA to invalidate                 */
#define MMUEXT_SET_LDT           8 /* ptr = VA of table; val = # entries     */
#define MMUEXT_SET_SUBJECTDOM    9 /* (ptr[31:15],val[31:15]) = dom[31:0]    */
#define SET_PAGETABLE_SUBJECTDOM (1<<14) /* OR into 'val' arg of SUBJECTDOM  */
#define MMUEXT_REASSIGN_PAGE    10
#define MMUEXT_RESET_SUBJECTDOM 11
#define MMUEXT_CMD_MASK        255
#define MMUEXT_CMD_SHIFT         8

/* These are passed as 'flags' to update_va_mapping. They can be ORed. */
#define UVMF_FLUSH_TLB          1 /* Flush entire TLB. */
#define UVMF_INVLPG             2 /* Flush the VA mapping being updated. */


/*
 * Commands to HYPERVISOR_sched_op().
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

/*
 * Commands to HYPERVISOR_dom_mem_op().
 */
#define MEMOP_increase_reservation 0
#define MEMOP_decrease_reservation 1

#ifndef __ASSEMBLY__

typedef u32 domid_t;
/* DOMID_SELF is used in certain contexts to refer to oneself. */
#define DOMID_SELF (0x7FFFFFFEU)

#include "network.h"
#include "block.h"

/*
 * Send an array of these to HYPERVISOR_mmu_update().
 * NB. The fields are natural pointer/address size for this architecture.
 */
typedef struct
{
    memory_t ptr;    /* Machine address of PTE. */
    memory_t val;    /* New contents of PTE.    */
} PACKED mmu_update_t;

/*
 * Send an array of these to HYPERVISOR_multicall().
 * NB. The fields are natural register size for this architecture.
 */
typedef struct
{
    cpureg_t op;
    cpureg_t args[7];
} PACKED multicall_entry_t;

/* Event channel endpoints per domain. */
#define NR_EVENT_CHANNELS 1024

/* No support for multi-processor guests. */
#define MAX_VIRT_CPUS 1

/*
 * Xen/guestos shared data -- pointer provided in start_info.
 * NB. We expect that this struct is smaller than a page.
 */
typedef struct shared_info_st
{
    /*
     * Per-VCPU information goes here. This will be cleaned up more when Xen 
     * actually supports multi-VCPU guests.
     */
    struct {
        /*
         * 'evtchn_upcall_pending' is written non-zero by Xen to indicate
         * a pending notification for a particular VCPU. It is then cleared 
         * by the guest OS /before/ checking for pending work, thus avoiding
         * a set-and-check race. Note that the mask is only accessed by Xen
         * on the CPU that is currently hosting the VCPU. This means that the
         * pending and mask flags can be updated by the guest without special
         * synchronisation (i.e., no need for the x86 LOCK prefix).
         * This may seem suboptimal because if the pending flag is set by
         * a different CPU then an IPI may be scheduled even when the mask
         * is set. However, note:
         *  1. The task of 'interrupt holdoff' is covered by the per-event-
         *     channel mask bits. A 'noisy' event that is continually being
         *     triggered can be masked at source at this very precise
         *     granularity.
         *  2. The main purpose of the per-VCPU mask is therefore to restrict
         *     reentrant execution: whether for concurrency control, or to
         *     prevent unbounded stack usage. Whatever the purpose, we expect
         *     that the mask will be asserted only for short periods at a time,
         *     and so the likelihood of a 'spurious' IPI is suitably small.
         * The mask is read before making an event upcall to the guest: a
         * non-zero mask therefore guarantees that the VCPU will not receive
         * an upcall activation. The mask is cleared when the VCPU requests
         * to block: this avoids wakeup-waiting races.
         */
        u8 evtchn_upcall_pending;
        u8 evtchn_upcall_mask;
        u8 pad0, pad1;
    } PACKED vcpu_data[MAX_VIRT_CPUS];  /*   0 */

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
    u32 evtchn_pending[32];             /*   4 */
    u32 evtchn_pending_sel;             /* 132 */
    u32 evtchn_exception[32];           /* 136 */
    u32 evtchn_mask[32];                /* 264 */

    /*
     * Time: The following abstractions are exposed: System Time, Clock Time,
     * Domain Virtual Time. Domains can access Cycle counter time directly.
     */
    u64                cpu_freq;        /* 392: CPU frequency (Hz).          */

    /*
     * The following values are updated periodically (and not necessarily
     * atomically!). The guest OS detects this because 'time_version1' is
     * incremented just before updating these values, and 'time_version2' is
     * incremented immediately after. See the Xen-specific Linux code for an
     * example of how to read these values safely (arch/xen/kernel/time.c).
     */
    u32                time_version1;   /* 400 */
    u32                time_version2;   /* 404 */
    tsc_timestamp_t    tsc_timestamp;   /* TSC at last update of time vals.  */
    u64                system_time;     /* Time, in nanosecs, since boot.    */
    u32                wc_sec;          /* Secs  00:00:00 UTC, Jan 1, 1970.  */
    u32                wc_usec;         /* Usecs 00:00:00 UTC, Jan 1, 1970.  */
    u64                domain_time;     /* Domain virtual time, in nanosecs. */

    /*
     * Timeout values:
     * Allow a domain to specify a timeout value in system time and 
     * domain virtual time.
     */
    u64                wall_timeout;    /* 440 */
    u64                domain_timeout;  /* 448 */

    /*
     * The index structures are all stored here for convenience. The rings 
     * themselves are allocated by Xen but the guestos must create its own 
     * mapping -- the machine address is given in the startinfo structure to 
     * allow this to happen.
     */
    net_idx_t net_idx[MAX_DOMAIN_VIFS];

    execution_context_t execution_context;

} PACKED shared_info_t;

/*
 * Start-of-day memory layout for the initial domain (DOM0):
 *  1. The domain is started within contiguous virtual-memory region.
 *  2. The contiguous region begins and ends on an aligned 4MB boundary.
 *  3. The region start corresponds to the load address of the OS image.
 *     If the load address is not 4MB aligned then the address is rounded down.
 *  4. This the order of bootstrap elements in the initial virtual region:
 *      a. relocated kernel image
 *      b. initial ram disk              [mod_start, mod_len]
 *      c. list of allocated page frames [mfn_list, nr_pages]
 *      d. bootstrap page tables         [pt_base, CR3 (x86)]
 *      e. start_info_t structure        [register ESI (x86)]
 *      f. bootstrap stack               [register ESP (x86)]
 *  5. Bootstrap elements are packed together, but each is 4kB-aligned.
 *  6. The initial ram disk may be omitted.
 *  7. The list of page frames forms a contiguous 'pseudo-physical' memory
 *     layout for the domain. In particular, the bootstrap virtual-memory
 *     region is a 1:1 mapping to the first section of the pseudo-physical map.
 *  8. All bootstrap elements are mapped read-writeable for the guest OS. The
 *     only exception is the bootstrap page table, which is mapped read-only.
 *  9. There is guaranteed to be at least 512kB padding after the final
 *     bootstrap element. If necessary, the bootstrap virtual region is
 *     extended by an extra 4MB to ensure this.
 */

/*
 * This is the basic bootstrap information structure as passed by Xen to the
 * initial controller domain. We want this structure to be easily extended by
 * more sophisticated domain builders and controllers, so we make the basic
 * fields of this structure available via a BASIC_START_INFO macro.
 * 
 * Extended version of start_info_t should be defined as:
 *  typedef struct {
 *      BASIC_START_INFO;
 *      <...extra fields...>
 *  } extended_start_info_t;
 */
#define MAX_CMDLINE 256
#define BASIC_START_INFO                                                      \
    /* THE FOLLOWING ARE FILLED IN BOTH ON INITIAL BOOT AND ON RESUME.     */ \
    memory_t nr_pages;       /*  0: Total pages allocated to this domain. */  \
    _MEMORY_PADDING(A);                                                       \
    memory_t shared_info;    /*  8: MACHINE address of shared info struct.*/  \
    _MEMORY_PADDING(B);                                                       \
    u32      flags;          /* 16: SIF_xxx flags.                        */  \
    u32      __pad;                                                           \
    /* THE FOLLOWING ARE ONLY FILLED IN ON INITIAL BOOT (NOT RESUME).      */ \
    memory_t pt_base;        /* 24: VIRTUAL address of page directory.    */  \
    _MEMORY_PADDING(C);                                                       \
    memory_t nr_pt_frames;   /* 32: Number of bootstrap p.t. frames.      */  \
    _MEMORY_PADDING(D);                                                       \
    memory_t mfn_list;       /* 40: VIRTUAL address of page-frame list.   */  \
    _MEMORY_PADDING(E);                                                       \
    memory_t mod_start;      /* 48: VIRTUAL address of pre-loaded module. */  \
    _MEMORY_PADDING(F);                                                       \
    memory_t mod_len;        /* 56: Size (bytes) of pre-loaded module.    */  \
    _MEMORY_PADDING(G);                                                       \
    u8 cmd_line[MAX_CMDLINE] /* 64 */

typedef struct {
    BASIC_START_INFO;
} PACKED start_info_t; /* 320 bytes */

/* These flags are passed in the 'flags' field of start_info_t. */
#define SIF_PRIVILEGED    (1<<0)  /* Is the domain privileged? */
#define SIF_INITDOMAIN    (1<<1)  /* Is this the initial control domain? */

/* For use in guest OSes. */
extern shared_info_t *HYPERVISOR_shared_info;

#endif /* !__ASSEMBLY__ */

#endif /* __HYPERVISOR_IF_H__ */
