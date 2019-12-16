/******************************************************************************
 * xenguest.h
 *
 * A library for guest domain management in Xen.
 *
 * Copyright (c) 2003-2004, K A Fraser.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef XENGUEST_H
#define XENGUEST_H

#define XC_NUMA_NO_NODE   (~0U)

#define XCFLAGS_LIVE      (1 << 0)
#define XCFLAGS_DEBUG     (1 << 1)

#define X86_64_B_SIZE   64 
#define X86_32_B_SIZE   32

/*
 * User not using xc_suspend_* / xc_await_suspent may not want to
 * include the full libxenevtchn API here.
 */
struct xenevtchn_handle;

/* For save's precopy_policy(). */
struct precopy_stats
{
    unsigned int iteration;
    unsigned int total_written;
    long dirty_count; /* -1 if unknown */
};

/*
 * A precopy_policy callback may not be running in the same address
 * space as libxc an so precopy_stats is passed by value.
 */
typedef int (*precopy_policy_t)(struct precopy_stats, void *);

/* callbacks provided by xc_domain_save */
struct save_callbacks {
    /*
     * Called after expiration of checkpoint interval,
     * to suspend the guest.
     */
    int (*suspend)(void *data);

    /*
     * Called before and after every batch of page data sent during
     * the precopy phase of a live migration to ask the caller what
     * to do next based on the current state of the precopy migration.
     *
     * Should return one of the values listed below:
     */
#define XGS_POLICY_ABORT          (-1) /* Abandon the migration entirely
                                        * and tidy up. */
#define XGS_POLICY_CONTINUE_PRECOPY 0  /* Remain in the precopy phase. */
#define XGS_POLICY_STOP_AND_COPY    1  /* Immediately suspend and transmit the
                                        * remaining dirty pages. */
    precopy_policy_t precopy_policy;

    /*
     * Called after the guest's dirty pages have been
     *  copied into an output buffer.
     * Callback function resumes the guest & the device model,
     *  returns to xc_domain_save.
     * xc_domain_save then flushes the output buffer, while the
     *  guest continues to run.
     */
    int (*postcopy)(void *data);

    /*
     * Called after the memory checkpoint has been flushed
     * out into the network. Typical actions performed in this
     * callback include:
     *   (a) send the saved device model state (for HVM guests),
     *   (b) wait for checkpoint ack
     *   (c) release the network output buffer pertaining to the acked checkpoint.
     *   (c) sleep for the checkpoint interval.
     *
     * returns:
     * 0: terminate checkpointing gracefully
     * 1: take another checkpoint
     */
    int (*checkpoint)(void *data);

    /*
     * Called after the checkpoint callback.
     *
     * returns:
     * 0: terminate checkpointing gracefully
     * 1: take another checkpoint
     */
    int (*wait_checkpoint)(void *data);

    /* Enable qemu-dm logging dirty pages to xen */
    int (*switch_qemu_logdirty)(uint32_t domid, unsigned enable, void *data); /* HVM only */

    /* to be provided as the last argument to each callback function */
    void *data;
};

/* Type of stream.  Plain, or using a continuous replication protocol? */
typedef enum {
    XC_STREAM_PLAIN,
    XC_STREAM_REMUS,
    XC_STREAM_COLO,
} xc_stream_type_t;

/**
 * This function will save a running domain.
 *
 * @param xch a handle to an open hypervisor interface
 * @param io_fd the file descriptor to save a domain to
 * @param dom the id of the domain
 * @param flags XCFLAGS_xxx
 * @param stream_type XC_STREAM_PLAIN if the far end of the stream
 *        doesn't use checkpointing
 * @param recv_fd Only used for XC_STREAM_COLO.  Contains backchannel from
 *        the destination side.
 * @return 0 on success, -1 on failure
 */
int xc_domain_save(xc_interface *xch, int io_fd, uint32_t dom,
                   uint32_t flags, struct save_callbacks *callbacks,
                   xc_stream_type_t stream_type, int recv_fd);

/* callbacks provided by xc_domain_restore */
struct restore_callbacks {
    /*
     * Called once the STATIC_DATA_END record has been received/inferred.
     *
     * For compatibility with older streams, provides a list of static data
     * expected to be found in the stream, which was missing.  A higher level
     * toolstack is responsible for providing any necessary compatibiltiy.
     */
#define XGR_SDD_MISSING_CPUID (1 << 0)
#define XGR_SDD_MISSING_MSR   (1 << 1)
    int (*static_data_done)(unsigned int missing, void *data);

    /* Called after a new checkpoint to suspend the guest. */
    int (*suspend)(void *data);

    /*
     * Called after the secondary vm is ready to resume.
     * Callback function resumes the guest & the device model,
     * returns to xc_domain_restore.
     */
    int (*postcopy)(void *data);

    /*
     * A checkpoint record has been found in the stream.
     * returns:
     */
#define XGR_CHECKPOINT_ERROR    0 /* Terminate processing */
#define XGR_CHECKPOINT_SUCCESS  1 /* Continue reading more data from the stream */
#define XGR_CHECKPOINT_FAILOVER 2 /* Failover and resume VM */
    int (*checkpoint)(void *data);

    /*
     * Called after the checkpoint callback.
     *
     * returns:
     * 0: terminate checkpointing gracefully
     * 1: take another checkpoint
     */
    int (*wait_checkpoint)(void *data);

    /*
     * callback to send store gfn and console gfn to xl
     * if we want to resume vm before xc_domain_save()
     * exits.
     */
    void (*restore_results)(xen_pfn_t store_gfn, xen_pfn_t console_gfn,
                            void *data);

    /* to be provided as the last argument to each callback function */
    void *data;
};

/**
 * This function will restore a saved domain.
 *
 * Domain is restored in a suspended state ready to be unpaused.
 *
 * @param xch a handle to an open hypervisor interface
 * @param io_fd the file descriptor to restore a domain from
 * @param dom the id of the domain
 * @param store_evtchn the xenstore event channel for this domain to use
 * @param store_mfn filled with the gfn of the store page
 * @param store_domid the backend domain for xenstore
 * @param console_evtchn the console event channel for this domain to use
 * @param console_mfn filled with the gfn of the console page
 * @param console_domid the backend domain for xenconsole
 * @param stream_type XC_STREAM_PLAIN if the far end of the stream is using
 *        checkpointing
 * @param callbacks non-NULL to receive a callback to restore toolstack
 *        specific data
 * @param send_back_fd Only used for XC_STREAM_COLO.  Contains backchannel to
 *        the source side.
 * @return 0 on success, -1 on failure
 */
int xc_domain_restore(xc_interface *xch, int io_fd, uint32_t dom,
                      unsigned int store_evtchn, unsigned long *store_mfn,
                      uint32_t store_domid, unsigned int console_evtchn,
                      unsigned long *console_mfn, uint32_t console_domid,
                      xc_stream_type_t stream_type,
                      struct restore_callbacks *callbacks, int send_back_fd);

/**
 * This function will create a domain for a paravirtualized Linux
 * using file names pointing to kernel and ramdisk
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the id of the domain
 * @parm mem_mb memory size in megabytes
 * @parm image_name name of the kernel image file
 * @parm ramdisk_name name of the ramdisk image file
 * @parm cmdline command line string
 * @parm flags domain creation flags
 * @parm store_evtchn the store event channel for this domain to use
 * @parm store_mfn returned with the mfn of the store page
 * @parm console_evtchn the console event channel for this domain to use
 * @parm conole_mfn returned with the mfn of the console page
 * @return 0 on success, -1 on failure
 */
int xc_linux_build(xc_interface *xch,
                   uint32_t domid,
                   unsigned int mem_mb,
                   const char *image_name,
                   const char *ramdisk_name,
                   const char *cmdline,
                   const char *features,
                   unsigned long flags,
                   unsigned int store_evtchn,
                   unsigned long *store_mfn,
                   unsigned int console_evtchn,
                   unsigned long *console_mfn);

struct xc_hvm_firmware_module {
    uint8_t  *data;
    uint32_t  length;
    uint64_t  guest_addr_out;
};

/*
 * Sets *lockfd to -1.
 * Has deallocated everything even on error.
 */
int xc_suspend_evtchn_release(xc_interface *xch,
                              struct xenevtchn_handle *xce,
                              uint32_t domid, int suspend_evtchn, int *lockfd);

/**
 * This function eats the initial notification.
 * xce must not be used for anything else
 * See xc_suspend_evtchn_init_sane re lockfd.
 */
int xc_suspend_evtchn_init_exclusive(xc_interface *xch,
                                     struct xenevtchn_handle *xce,
                                     uint32_t domid, int port, int *lockfd);

/* xce must not be used for anything else */
int xc_await_suspend(xc_interface *xch, struct xenevtchn_handle *xce,
                     int suspend_evtchn);

/**
 * The port will be signaled immediately after this call
 * The caller should check the domain status and look for the next event
 * On success, *lockfd will be set to >=0 and *lockfd must be preserved
 * and fed to xc_suspend_evtchn_release.  (On error *lockfd is
 * undefined and xc_suspend_evtchn_release is not allowed.)
 */
int xc_suspend_evtchn_init_sane(xc_interface *xch,
                                struct xenevtchn_handle *xce,
                                uint32_t domid, int port, int *lockfd);

int xc_mark_page_online(xc_interface *xch, unsigned long start,
                        unsigned long end, uint32_t *status);

int xc_mark_page_offline(xc_interface *xch, unsigned long start,
                          unsigned long end, uint32_t *status);

int xc_query_page_offline_status(xc_interface *xch, unsigned long start,
                                 unsigned long end, uint32_t *status);

int xc_exchange_page(xc_interface *xch, uint32_t domid, xen_pfn_t mfn);


/**
 * Memory related information, such as PFN types, the P2M table,
 * the guest word width and the guest page table levels.
 */
struct xc_domain_meminfo {
    unsigned int pt_levels;
    unsigned int guest_width;
    xen_pfn_t *pfn_type;
    xen_pfn_t *p2m_table;
    unsigned long p2m_size;
};

int xc_map_domain_meminfo(xc_interface *xch, uint32_t domid,
                          struct xc_domain_meminfo *minfo);

int xc_unmap_domain_meminfo(xc_interface *xch, struct xc_domain_meminfo *mem);

/**
 * This function map m2p table
 * @parm xch a handle to an open hypervisor interface
 * @parm max_mfn the max pfn
 * @parm prot the flags to map, such as read/write etc
 * @parm mfn0 return the first mfn, can be NULL
 * @return mapped m2p table on success, NULL on failure
 */
xen_pfn_t *xc_map_m2p(xc_interface *xch,
                      unsigned long max_mfn,
                      int prot,
                      unsigned long *mfn0);
#endif /* XENGUEST_H */
