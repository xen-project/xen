/******************************************************************************
 * xenctrl.h
 * 
 * A library for low-level access to the Xen control interfaces.
 * 
 * Copyright (c) 2003-2004, K A Fraser.
 */

#ifndef XENCTRL_H
#define XENCTRL_H

#include <stdint.h>

typedef uint8_t            u8;
typedef uint16_t           u16;
typedef uint32_t           u32;
typedef uint64_t           u64;
typedef int8_t             s8;
typedef int16_t            s16;
typedef int32_t            s32;
typedef int64_t            s64;

#include <sys/ptrace.h>
#include <xen/xen.h>
#include <xen/dom0_ops.h>
#include <xen/version.h>
#include <xen/event_channel.h>
#include <xen/sched.h>
#include <xen/sched_ctl.h>
#include <xen/acm.h>

#ifdef __ia64__
#define XC_PAGE_SHIFT           14
#else
#define XC_PAGE_SHIFT           12
#endif
#define XC_PAGE_SIZE            (1UL << XC_PAGE_SHIFT)
#define XC_PAGE_MASK            (~(XC_PAGE_SIZE-1))

/*
 *  DEFINITIONS FOR CPU BARRIERS
 */ 

#if defined(__i386__)
#define mb()  __asm__ __volatile__ ( "lock; addl $0,0(%%esp)" : : : "memory" )
#define rmb() __asm__ __volatile__ ( "lock; addl $0,0(%%esp)" : : : "memory" )
#define wmb() __asm__ __volatile__ ( "" : : : "memory")
#elif defined(__x86_64__)
#define mb()  __asm__ __volatile__ ( "mfence" : : : "memory")
#define rmb() __asm__ __volatile__ ( "lfence" : : : "memory")
#define wmb() __asm__ __volatile__ ( "" : : : "memory")
#elif defined(__ia64__)
/* FIXME */
#define mb()
#define rmb()
#define wmb()
#else
#error "Define barriers"
#endif

/*
 *  INITIALIZATION FUNCTIONS
 */ 

/**
 * This function opens a handle to the hypervisor interface.  This function can
 * be called multiple times within a single process.  Multiple processes can
 * have an open hypervisor interface at the same time.
 *
 * Each call to this function should have a corresponding call to
 * xc_interface_close().
 *
 * This function can fail if the caller does not have superuser permission or
 * if a Xen-enabled kernel is not currently running.
 *
 * @return a handle to the hypervisor interface or -1 on failure
 */
int xc_interface_open(void);

/**
 * This function closes an open hypervisor interface.
 *
 * This function can fail if the handle does not represent an open interface or
 * if there were problems closing the interface.
 *
 * @parm xc_handle a handle to an open hypervisor interface
 * @return 0 on success, -1 otherwise.
 */
int xc_interface_close(int xc_handle);

/*
 * DOMAIN DEBUGGING FUNCTIONS
 */

typedef struct xc_core_header {
    unsigned int xch_magic;
    unsigned int xch_nr_vcpus;
    unsigned int xch_nr_pages;
    unsigned int xch_ctxt_offset;
    unsigned int xch_index_offset;
    unsigned int xch_pages_offset;
} xc_core_header_t;


long xc_ptrace(
    int xc_handle,
    enum __ptrace_request request, 
    u32  domid,
    long addr, 
    long data);

long xc_ptrace_core(
    int xc_handle,
    enum __ptrace_request request, 
    u32 domid, 
    long addr, 
    long data);

int xc_waitdomain(
    int xc_handle,
    int domain, 
    int *status, 
    int options);

int xc_waitdomain_core(
    int xc_handle,
    int domain, 
    int *status, 
    int options);

/*
 * DOMAIN MANAGEMENT FUNCTIONS
 */

typedef struct {
    u32           domid;
    u32           ssidref;
    unsigned int  dying:1, crashed:1, shutdown:1, 
                  paused:1, blocked:1, running:1;
    unsigned int  shutdown_reason; /* only meaningful if shutdown==1 */
    unsigned long nr_pages;
    unsigned long shared_info_frame;
    u64           cpu_time;
    unsigned long max_memkb;
    unsigned int  vcpus;
    s32           vcpu_to_cpu[MAX_VIRT_CPUS];
    cpumap_t      cpumap[MAX_VIRT_CPUS];
} xc_dominfo_t;

typedef dom0_getdomaininfo_t xc_domaininfo_t;
int xc_domain_create(int xc_handle, 
                     u32 ssidref,
                     u32 *pdomid);


int xc_domain_dumpcore(int xc_handle, 
                       u32 domid,
                       const char *corename);


/**
 * This function pauses a domain. A paused domain still exists in memory
 * however it does not receive any timeslices from the hypervisor.
 *
 * @parm xc_handle a handle to an open hypervisor interface
 * @parm domid the domain id to pause
 * @return 0 on success, -1 on failure.
 */
int xc_domain_pause(int xc_handle, 
                    u32 domid);
/**
 * This function unpauses a domain.  The domain should have been previously
 * paused.
 *
 * @parm xc_handle a handle to an open hypervisor interface
 * @parm domid the domain id to unpause
 * return 0 on success, -1 on failure
 */
int xc_domain_unpause(int xc_handle, 
                      u32 domid);

/**
 * This function will destroy a domain.  Destroying a domain removes the domain
 * completely from memory.  This function should be called after sending the
 * domain a SHUTDOWN control message to free up the domain resources.
 *
 * @parm xc_handle a handle to an open hypervisor interface
 * @parm domid the domain id to destroy
 * @return 0 on success, -1 on failure
 */
int xc_domain_destroy(int xc_handle, 
                      u32 domid);
int xc_domain_pincpu(int xc_handle,
                     u32 domid,
                     int vcpu,
                     cpumap_t *cpumap);
/**
 * This function will return information about one or more domains. It is
 * designed to iterate over the list of domains. If a single domain is
 * requested, this function will return the next domain in the list - if
 * one exists. It is, therefore, important in this case to make sure the
 * domain requested was the one returned.
 *
 * @parm xc_handle a handle to an open hypervisor interface
 * @parm first_domid the first domain to enumerate information from.  Domains
 *                   are currently enumerate in order of creation.
 * @parm max_doms the number of elements in info
 * @parm info an array of max_doms size that will contain the information for
 *            the enumerated domains.
 * @return the number of domains enumerated or -1 on error
 */
int xc_domain_getinfo(int xc_handle,
                      u32 first_domid, 
                      unsigned int max_doms,
                      xc_dominfo_t *info);

/**
 * This function will return information about one or more domains, using a
 * single hypercall.  The domain information will be stored into the supplied
 * array of xc_domaininfo_t structures.
 *
 * @parm xc_handle a handle to an open hypervisor interface
 * @parm first_domain the first domain to enumerate information from.
 *                    Domains are currently enumerate in order of creation.
 * @parm max_domains the number of elements in info
 * @parm info an array of max_doms size that will contain the information for
 *            the enumerated domains.
 * @return the number of domains enumerated or -1 on error
 */
int xc_domain_getinfolist(int xc_handle,
                          u32 first_domain,
                          unsigned int max_domains,
                          xc_domaininfo_t *info);

/**
 * This function returns information about one domain.  This information is
 * more detailed than the information from xc_domain_getinfo().
 *
 * @parm xc_handle a handle to an open hypervisor interface
 * @parm domid the domain to get information from
 * @parm info a pointer to an xc_domaininfo_t to store the domain information
 * @parm ctxt a pointer to a structure to store the execution context of the
 *            domain
 * @return 0 on success, -1 on failure
 */
int xc_domain_get_vcpu_context(int xc_handle,
                               u32 domid,
                               u32 vcpu,
                               vcpu_guest_context_t *ctxt);

int xc_domain_setcpuweight(int xc_handle,
                           u32 domid,
                           float weight);
long long xc_domain_get_cpu_usage(int xc_handle,
                                  domid_t domid,
                                  int vcpu);


typedef dom0_shadow_control_stats_t xc_shadow_control_stats_t;
int xc_shadow_control(int xc_handle,
                      u32 domid, 
                      unsigned int sop,
                      unsigned long *dirty_bitmap,
                      unsigned long pages,
                      xc_shadow_control_stats_t *stats);

int xc_bvtsched_global_set(int xc_handle,
                           unsigned long ctx_allow);

int xc_bvtsched_domain_set(int xc_handle,
                           u32 domid,
                           u32 mcuadv,
                           int warpback,
                           s32 warpvalue,
                           long long warpl,
                           long long warpu);

int xc_bvtsched_global_get(int xc_handle,
                           unsigned long *ctx_allow);

int xc_bvtsched_domain_get(int xc_handle,
                           u32 domid,
                           u32 *mcuadv,
                           int *warpback,
                           s32 *warpvalue,
                           long long *warpl,
                           long long *warpu);

int xc_sedf_domain_set(int xc_handle,
                          u32 domid,
                          u64 period, u64 slice, u64 latency, u16 extratime, u16 weight);

int xc_sedf_domain_get(int xc_handle,
                          u32 domid,
                          u64* period, u64 *slice, u64 *latency, u16 *extratime, u16* weight);

typedef evtchn_status_t xc_evtchn_status_t;

/*
 * EVENT CHANNEL FUNCTIONS
 */

/**
 * This function allocates an unbound port.  Ports are named endpoints used for
 * interdomain communication.  This function is most useful in opening a
 * well-known port within a domain to receive events on.
 *
 * @parm xc_handle a handle to an open hypervisor interface
 * @parm dom the ID of the local domain (the 'allocatee')
 * @parm remote_dom the ID of the domain who will later bind
 * @return allocated port (in @dom) on success, -1 on failure
 */
int xc_evtchn_alloc_unbound(int xc_handle,
                            u32 dom,
                            u32 remote_dom);

int xc_evtchn_status(int xc_handle,
                     u32 dom, /* may be DOMID_SELF */
                     int port,
                     xc_evtchn_status_t *status);

int xc_physdev_pci_access_modify(int xc_handle,
                                 u32 domid,
                                 int bus,
                                 int dev,
                                 int func,
                                 int enable);

int xc_readconsolering(int xc_handle,
                       char **pbuffer,
                       unsigned int *pnr_chars, 
                       int clear);

typedef dom0_physinfo_t xc_physinfo_t;
int xc_physinfo(int xc_handle,
                xc_physinfo_t *info);

int xc_sched_id(int xc_handle,
                int *sched_id);

int xc_domain_setmaxmem(int xc_handle,
                        u32 domid, 
                        unsigned int max_memkb);

int xc_domain_memory_increase_reservation(int xc_handle,
                                          u32 domid, 
                                          unsigned long nr_extents,
                                          unsigned int extent_order,
                                          unsigned int address_bits,
					  unsigned long *extent_start);

int xc_domain_memory_decrease_reservation(int xc_handle,
                                          u32 domid, 
                                          unsigned long nr_extents,
                                          unsigned int extent_order,
					  unsigned long *extent_start);

unsigned long xc_make_page_below_4G(int xc_handle, u32 domid, 
				    unsigned long mfn);

typedef dom0_perfc_desc_t xc_perfc_desc_t;
/* IMPORTANT: The caller is responsible for mlock()'ing the @desc array. */
int xc_perfc_control(int xc_handle,
                     u32 op,
                     xc_perfc_desc_t *desc);

/* read/write msr */
long long xc_msr_read(int xc_handle, int cpu_mask, int msr);
int xc_msr_write(int xc_handle, int cpu_mask, int msr, unsigned int low,
                  unsigned int high);

/**
 * Memory maps a range within one domain to a local address range.  Mappings
 * should be unmapped with munmap and should follow the same rules as mmap
 * regarding page alignment.  Returns NULL on failure.
 *
 * In Linux, the ring queue for the control channel is accessible by mapping
 * the shared_info_frame (from xc_domain_getinfo()) + 2048.  The structure
 * stored there is of type control_if_t.
 *
 * @parm xc_handle a handle on an open hypervisor interface
 * @parm dom the domain to map memory from
 * @parm size the amount of memory to map (in multiples of page size)
 * @parm prot same flag as in mmap().
 * @parm mfn the frame address to map.
 */
void *xc_map_foreign_range(int xc_handle, u32 dom,
                            int size, int prot,
                            unsigned long mfn );

void *xc_map_foreign_batch(int xc_handle, u32 dom, int prot,
                           unsigned long *arr, int num );

int xc_get_pfn_list(int xc_handle, u32 domid, unsigned long *pfn_buf, 
                    unsigned long max_pfns);

int xc_ia64_get_pfn_list(int xc_handle, u32 domid, unsigned long *pfn_buf, 
                    unsigned int start_page, unsigned int nr_pages);

long xc_get_max_pages(int xc_handle, u32 domid);

int xc_mmuext_op(int xc_handle, struct mmuext_op *op, unsigned int nr_ops,
		 domid_t dom);

int xc_memory_op(int xc_handle, int cmd, void *arg);

int xc_get_pfn_type_batch(int xc_handle, u32 dom, int num, unsigned long *arr);


/*\
 *  GRANT TABLE FUNCTIONS
\*/ 

/**
 * This function opens a handle to the more restricted grant table hypervisor
 * interface. This may be used where the standard interface is not
 * available because the domain is not privileged.
 * This function can  be called multiple times within a single process.
 * Multiple processes can have an open hypervisor interface at the same time.
 *
 * Each call to this function should have a corresponding call to
 * xc_grant_interface_close().
 *
 * This function can fail if a Xen-enabled kernel is not currently running.
 *
 * @return a handle to the hypervisor grant table interface or -1 on failure
 */
int xc_grant_interface_open(void);

/**
 * This function closes an open grant table hypervisor interface.
 *
 * This function can fail if the handle does not represent an open interface or
 * if there were problems closing the interface.
 *
 * @parm xc_handle a handle to an open grant table hypervisor interface
 * @return 0 on success, -1 otherwise.
 */
int xc_grant_interface_close(int xc_handle);

int xc_gnttab_map_grant_ref(int  xc_handle,
                            u64  host_virt_addr,
                            u32  dom,
                            u16  ref,
                            u16  flags,
                            s16 *handle,
                            u64 *dev_bus_addr);

int xc_gnttab_unmap_grant_ref(int  xc_handle,
                              u64  host_virt_addr,
                              u64  dev_bus_addr,
                              u16  handle,
                              s16 *status);

int xc_gnttab_setup_table(int        xc_handle,
                          u32        dom,
                          u16        nr_frames,
                          s16       *status,
                          unsigned long **frame_list);

/* Grant debug builds only: */
int xc_gnttab_dump_table(int        xc_handle,
                         u32        dom,
                         s16       *status);

/* Get current total pages allocated to a domain. */
long xc_get_tot_pages(int xc_handle, u32 domid);

/* Execute a privileged dom0 operation. */
int xc_dom0_op(int xc_handle, dom0_op_t *op);

int xc_version(int xc_handle, int cmd, void *arg);

/* Initializes the store (for dom0)
   remote_port should be the remote end of a bound interdomain channel between
   the store and dom0.

   This function returns a shared frame that should be passed to
   xs_introduce_domain
 */
long xc_init_store(int xc_handle, int remote_port);

/*
 * MMU updates.
 */
#define MAX_MMU_UPDATES 1024
struct xc_mmu {
    mmu_update_t updates[MAX_MMU_UPDATES];
    int          idx;
    domid_t      subject;
};
typedef struct xc_mmu xc_mmu_t;
xc_mmu_t *xc_init_mmu_updates(int xc_handle, domid_t dom);
int xc_add_mmu_update(int xc_handle, xc_mmu_t *mmu, 
                   unsigned long long ptr, unsigned long long val);
int xc_finish_mmu_updates(int xc_handle, xc_mmu_t *mmu);

#endif
