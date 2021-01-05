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

#define X86_HVM_NR_SPECIAL_PAGES    8
#define X86_HVM_END_SPECIAL_REGION  0xff000u
#define XG_MAX_MODULES 2

/* --- typedefs and structs ---------------------------------------- */

typedef uint64_t xen_vaddr_t;
typedef uint64_t xen_paddr_t;

#define PRIpfn PRI_xen_pfn

struct xc_dom_seg {
    xen_vaddr_t vstart;
    xen_vaddr_t vend;
    xen_pfn_t pfn;
    xen_pfn_t pages;
};

struct xc_hvm_firmware_module {
    uint8_t  *data;
    uint32_t  length;
    uint64_t  guest_addr_out;
};

struct xc_dom_mem {
    struct xc_dom_mem *next;
    void *ptr;
    enum {
        XC_DOM_MEM_TYPE_MALLOC_INTERNAL,
        XC_DOM_MEM_TYPE_MALLOC_EXTERNAL,
        XC_DOM_MEM_TYPE_MMAP,
    } type;
    size_t len;
    unsigned char memory[0];
};

struct xc_dom_phys {
    struct xc_dom_phys *next;
    void *ptr;
    xen_pfn_t first;
    xen_pfn_t count;
};

struct xc_dom_module {
    void *blob;
    size_t size;
    void *cmdline;
    /* If seg.vstart is non zero then the module will be loaded at that
     * address, otherwise it will automatically placed.
     *
     * If automatic placement is used and the module is gzip
     * compressed then it will be decompressed as it is loaded. If the
     * module has been explicitly placed then it is loaded as is
     * otherwise decompressing risks undoing the manual placement.
     */
    struct xc_dom_seg seg;
};

struct xc_dom_image {
    /* files */
    void *kernel_blob;
    size_t kernel_size;
    unsigned int num_modules;
    struct xc_dom_module modules[XG_MAX_MODULES];
    void *devicetree_blob;
    size_t devicetree_size;

    size_t max_kernel_size;
    size_t max_module_size;
    size_t max_devicetree_size;

    /* arguments and parameters */
    char *cmdline;
    size_t cmdline_size;
    uint32_t f_requested[XENFEAT_NR_SUBMAPS];

    /* info from (elf) kernel image */
    struct elf_dom_parms *parms;
    char *guest_type;

    /* memory layout */
    struct xc_dom_seg kernel_seg;
    struct xc_dom_seg p2m_seg;
    struct xc_dom_seg pgtables_seg;
    struct xc_dom_seg devicetree_seg;
    struct xc_dom_seg start_info_seg;
    xen_pfn_t start_info_pfn;
    xen_pfn_t console_pfn;
    xen_pfn_t xenstore_pfn;
    xen_pfn_t shared_info_pfn;
    xen_pfn_t bootstack_pfn;
    xen_pfn_t pfn_alloc_end;
    xen_vaddr_t virt_alloc_end;
    xen_vaddr_t bsd_symtab_start;

    /*
     * initrd parameters as specified in start_info page
     * Depending on capabilities of the booted kernel this may be a virtual
     * address or a pfn. Type is neutral and large enough to hold a virtual
     * address of a 64 bit kernel even with 32 bit toolstack.
     */
    uint64_t initrd_start;
    uint64_t initrd_len;

    unsigned int alloc_bootstack;
    xen_vaddr_t virt_pgtab_end;

    /* other state info */
    uint32_t f_active[XENFEAT_NR_SUBMAPS];

    /*
     * pv_p2m is specific to x86 PV guests, and maps GFNs to MFNs.  It is
     * eventually copied into guest context.
     */
    xen_pfn_t *pv_p2m;

    /* physical memory
     *
     * An x86 PV guest has one or more blocks of physical RAM,
     * consisting of total_pages starting at 0. The start address and
     * size of each block is controlled by vNUMA structures.
     *
     * An ARM guest has GUEST_RAM_BANKS regions of RAM, with
     * rambank_size[i] pages in each. The lowest RAM address
     * (corresponding to the base of the p2m arrays above) is stored
     * in rambase_pfn.
     */
    xen_pfn_t rambase_pfn;
    xen_pfn_t total_pages;
    xen_pfn_t p2m_size;         /* number of pfns covered by p2m */
    struct xc_dom_phys *phys_pages;
#if defined (__arm__) || defined(__aarch64__)
    xen_pfn_t rambank_size[GUEST_RAM_BANKS];
#endif

    /* malloc memory pool */
    struct xc_dom_mem *memblocks;

    /* memory footprint stats */
    size_t alloc_malloc;
    size_t alloc_mem_map;
    size_t alloc_file_map;
    size_t alloc_domU_map;

    /* misc xen domain config stuff */
    unsigned long flags;
    unsigned int console_evtchn;
    unsigned int xenstore_evtchn;
    uint32_t console_domid;
    uint32_t xenstore_domid;
    xen_pfn_t shared_info_mfn;

    xc_interface *xch;
    uint32_t guest_domid;
    int claim_enabled; /* 0 by default, 1 enables it */

    int xen_version;
    xen_capabilities_info_t xen_caps;

    /* kernel loader, arch hooks */
    struct xc_dom_loader *kernel_loader;
    void *private_loader;

    /* vNUMA information */
    xen_vmemrange_t *vmemranges;
    unsigned int nr_vmemranges;
    unsigned int *vnode_to_pnode;
    unsigned int nr_vnodes;

    /* domain type/architecture specific data */
    void *arch_private;

    /* kernel loader */
    struct xc_dom_arch *arch_hooks;
    /* allocate up to pfn_alloc_end */
    int (*allocate) (struct xc_dom_image * dom);

    /* Container type (HVM or PV). */
    enum {
        XC_DOM_PV_CONTAINER,
        XC_DOM_HVM_CONTAINER,
    } container_type;

    /* HVM specific fields. */
    xen_pfn_t target_pages;
    xen_paddr_t mmio_start;
    xen_paddr_t mmio_size;
    xen_paddr_t lowmem_end;
    xen_paddr_t highmem_end;
    xen_pfn_t vga_hole_size;

    /* If unset disables the setup of the IOREQ pages. */
    bool device_model;

    /* BIOS/Firmware passed to HVMLOADER */
    struct xc_hvm_firmware_module system_firmware_module;

    /* Extra ACPI tables */
#define MAX_ACPI_MODULES        4
    struct xc_hvm_firmware_module acpi_modules[MAX_ACPI_MODULES];

    /* Extra SMBIOS structures passed to HVMLOADER */
    struct xc_hvm_firmware_module smbios_module;

#if defined(__i386__) || defined(__x86_64__)
    struct e820entry *e820;
    unsigned int e820_entries;
#endif

    xen_pfn_t vuart_gfn;

    /* Number of vCPUs */
    unsigned int max_vcpus;
};

/* --- arch specific hooks ----------------------------------------- */

struct xc_dom_arch {
    int (*alloc_magic_pages) (struct xc_dom_image * dom);

    /* pagetable setup - x86 PV only */
    int (*alloc_pgtables) (struct xc_dom_image * dom);
    int (*alloc_p2m_list) (struct xc_dom_image * dom);
    int (*setup_pgtables) (struct xc_dom_image * dom);

    /* arch-specific data structs setup */
    /* in Mini-OS environment start_info might be a macro, avoid collision. */
#undef start_info
    int (*start_info) (struct xc_dom_image * dom);
    int (*shared_info) (struct xc_dom_image * dom, void *shared_info);
    int (*vcpu) (struct xc_dom_image * dom);
    int (*bootearly) (struct xc_dom_image * dom);
    int (*bootlate) (struct xc_dom_image * dom);

    /* arch-specific memory initialization. */
    int (*meminit) (struct xc_dom_image * dom);

    char *guest_type;
    char *native_protocol;
    int page_shift;
    int sizeof_pfn;
    int p2m_base_supported;
    int arch_private_size;

    struct xc_dom_arch *next;
};
void xc_dom_register_arch_hooks(struct xc_dom_arch *hooks);

#define XC_DOM_PAGE_SHIFT(dom)  ((dom)->arch_hooks->page_shift)
#define XC_DOM_PAGE_SIZE(dom)   (1LL << (dom)->arch_hooks->page_shift)

/* --- main functions ---------------------------------------------- */

struct xc_dom_image *xc_dom_allocate(xc_interface *xch,
                                     const char *cmdline, const char *features);
void xc_dom_release_phys(struct xc_dom_image *dom);
void xc_dom_release(struct xc_dom_image *dom);
int xc_dom_rambase_init(struct xc_dom_image *dom, uint64_t rambase);
int xc_dom_mem_init(struct xc_dom_image *dom, unsigned int mem_mb);

/* Set this larger if you have enormous modules/kernels. Note that
 * you should trust all kernels not to be maliciously large (e.g. to
 * exhaust all dom0 memory) if you do this (see CVE-2012-4544 /
 * XSA-25). You can also set the default independently for
 * modules/kernels in xc_dom_allocate() or call
 * xc_dom_{kernel,module}_max_size.
 */
#ifndef XC_DOM_DECOMPRESS_MAX
#define XC_DOM_DECOMPRESS_MAX (1024*1024*1024) /* 1GB */
#endif

int xc_dom_kernel_check_size(struct xc_dom_image *dom, size_t sz);
int xc_dom_kernel_max_size(struct xc_dom_image *dom, size_t sz);

int xc_dom_module_max_size(struct xc_dom_image *dom, size_t sz);

int xc_dom_devicetree_max_size(struct xc_dom_image *dom, size_t sz);

size_t xc_dom_check_gzip(xc_interface *xch,
                     void *blob, size_t ziplen);
int xc_dom_do_gunzip(xc_interface *xch,
                     void *src, size_t srclen, void *dst, size_t dstlen);
int xc_dom_try_gunzip(struct xc_dom_image *dom, void **blob, size_t * size);

int xc_dom_kernel_file(struct xc_dom_image *dom, const char *filename);
int xc_dom_module_file(struct xc_dom_image *dom, const char *filename,
                       const char *cmdline);
int xc_dom_kernel_mem(struct xc_dom_image *dom, const void *mem,
                      size_t memsize);
int xc_dom_module_mem(struct xc_dom_image *dom, const void *mem,
                       size_t memsize, const char *cmdline);
int xc_dom_devicetree_file(struct xc_dom_image *dom, const char *filename);
int xc_dom_devicetree_mem(struct xc_dom_image *dom, const void *mem,
                          size_t memsize);

int xc_dom_parse_image(struct xc_dom_image *dom);
int xc_dom_set_arch_hooks(struct xc_dom_image *dom);
int xc_dom_build_image(struct xc_dom_image *dom);

int xc_dom_boot_xen_init(struct xc_dom_image *dom, xc_interface *xch,
                         uint32_t domid);
int xc_dom_boot_mem_init(struct xc_dom_image *dom);
void *xc_dom_boot_domU_map(struct xc_dom_image *dom, xen_pfn_t pfn,
                           xen_pfn_t count);
int xc_dom_boot_image(struct xc_dom_image *dom);
int xc_dom_compat_check(struct xc_dom_image *dom);
int xc_dom_gnttab_init(struct xc_dom_image *dom);
int xc_dom_gnttab_seed(xc_interface *xch, uint32_t guest_domid,
                       bool is_hvm,
                       xen_pfn_t console_gfn,
                       xen_pfn_t xenstore_gfn,
                       uint32_t console_domid,
                       uint32_t xenstore_domid);
bool xc_dom_translated(const struct xc_dom_image *dom);

/* --- debugging bits ---------------------------------------------- */

int xc_dom_loginit(xc_interface *xch);

void xc_dom_printf(xc_interface *xch, const char *fmt, ...)
     __attribute__ ((format(printf, 2, 3)));
void xc_dom_panic_func(xc_interface *xch,
                      const char *file, int line, xc_error_code err,
                      const char *fmt, ...)
    __attribute__ ((format(printf, 5, 6)));

#define xc_dom_panic(xch, err, fmt, args...) \
    xc_dom_panic_func(xch, __FILE__, __LINE__, err, fmt, ## args)
#define xc_dom_trace(mark) \
    xc_dom_printf("%s:%d: trace %s\n", __FILE__, __LINE__, mark)

void xc_dom_log_memory_footprint(struct xc_dom_image *dom);

/* --- simple memory pool ------------------------------------------ */

void *xc_dom_malloc(struct xc_dom_image *dom, size_t size);
int xc_dom_register_external(struct xc_dom_image *dom, void *ptr, size_t size);
void *xc_dom_malloc_page_aligned(struct xc_dom_image *dom, size_t size);
void *xc_dom_malloc_filemap(struct xc_dom_image *dom,
                            const char *filename, size_t * size,
                            const size_t max_size);
char *xc_dom_strdup(struct xc_dom_image *dom, const char *str);

/* --- alloc memory pool ------------------------------------------- */

xen_pfn_t xc_dom_alloc_page(struct xc_dom_image *dom, char *name);
int xc_dom_alloc_segment(struct xc_dom_image *dom,
                         struct xc_dom_seg *seg, char *name,
                         xen_vaddr_t start, xen_vaddr_t size);

/* --- misc bits --------------------------------------------------- */

void *xc_dom_pfn_to_ptr(struct xc_dom_image *dom, xen_pfn_t first,
                        xen_pfn_t count);
void *xc_dom_pfn_to_ptr_retcount(struct xc_dom_image *dom, xen_pfn_t first,
                                 xen_pfn_t count, xen_pfn_t *count_out);
void xc_dom_unmap_one(struct xc_dom_image *dom, xen_pfn_t pfn);
void xc_dom_unmap_all(struct xc_dom_image *dom);
void *xc_dom_vaddr_to_ptr(struct xc_dom_image *dom,
                          xen_vaddr_t vaddr, size_t *safe_region_out);
uint64_t xc_dom_virt_base(struct xc_dom_image *dom);
uint64_t xc_dom_virt_entry(struct xc_dom_image *dom);
uint64_t xc_dom_virt_hypercall(struct xc_dom_image *dom);
char *xc_dom_guest_os(struct xc_dom_image *dom);
bool xc_dom_feature_get(struct xc_dom_image *dom, unsigned int nr);

static inline void *xc_dom_seg_to_ptr_pages(struct xc_dom_image *dom,
                                      struct xc_dom_seg *seg,
                                      xen_pfn_t *pages_out)
{
    void *retval;

    retval = xc_dom_pfn_to_ptr(dom, seg->pfn, seg->pages);

    *pages_out = retval ? seg->pages : 0;
    return retval;
}

static inline void *xc_dom_seg_to_ptr(struct xc_dom_image *dom,
                                      struct xc_dom_seg *seg)
{
    xen_pfn_t dummy;

    return xc_dom_seg_to_ptr_pages(dom, seg, &dummy);
}

static inline xen_pfn_t xc_dom_p2m(struct xc_dom_image *dom, xen_pfn_t pfn)
{
    if ( xc_dom_translated(dom) )
        return pfn;

    /* x86 PV only now. */
    if ( pfn >= dom->total_pages )
        return INVALID_MFN;

    return dom->pv_p2m[pfn];
}

/*
 * User not using xc_suspend_* / xc_await_suspent may not want to
 * include the full libxenevtchn API here.
 */
struct xenevtchn_handle;

/* For save's precopy_policy(). */
struct precopy_stats
{
    unsigned int iteration;
    unsigned long total_written;
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
