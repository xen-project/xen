/*
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

#ifndef _XC_DOM_H
#define _XC_DOM_H

#include <xen/libelf/libelf.h>
#include <xenguest.h>

#define INVALID_PFN ((xen_pfn_t)-1)
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
    struct elf_dom_parms parms;
    char *guest_type;

    /* memory layout */
    struct xc_dom_seg kernel_seg;
    struct xc_dom_seg p2m_seg;
    struct xc_dom_seg pgtables_seg;
    struct xc_dom_seg devicetree_seg;
    struct xc_dom_seg start_info_seg; /* HVMlite only */
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
     * p2m_host maps guest physical addresses an offset from
     * rambase_pfn (see below) into gfns.
     *
     * For a pure PV guest this means that it maps GPFNs into MFNs for
     * a hybrid guest this means that it maps GPFNs to GPFNS.
     *
     * Note that the input is offset by rambase.
     */
    xen_pfn_t *p2m_host;
    void *p2m_guest;

    /* physical memory
     *
     * An x86 PV guest has one or more blocks of physical RAM,
     * consisting of total_pages starting at rambase_pfn. The start
     * address and size of each block is controlled by vNUMA
     * structures.
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
    domid_t console_domid;
    domid_t xenstore_domid;
    xen_pfn_t shared_info_mfn;
    int pvh_enabled;

    xc_interface *xch;
    domid_t guest_domid;
    int claim_enabled; /* 0 by default, 1 enables it */
    int shadow_enabled;

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
};

/* --- pluggable kernel loader ------------------------------------- */

struct xc_dom_loader {
    char *name;
    /* Sadly the error returns from these functions are not consistent: */
    elf_negerrnoval (*probe) (struct xc_dom_image * dom);
    elf_negerrnoval (*parser) (struct xc_dom_image * dom);
    elf_errorstatus (*loader) (struct xc_dom_image * dom);

    struct xc_dom_loader *next;
};

#define __init __attribute__ ((constructor))
void xc_dom_register_loader(struct xc_dom_loader *loader);

/* --- arch specific hooks ----------------------------------------- */

struct xc_dom_arch {
    /* pagetable setup */
    int (*alloc_magic_pages) (struct xc_dom_image * dom);
    int (*alloc_pgtables) (struct xc_dom_image * dom);
    int (*alloc_p2m_list) (struct xc_dom_image * dom);
    int (*setup_pgtables) (struct xc_dom_image * dom);

    /* arch-specific data structs setup */
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

int xc_dom_module_check_size(struct xc_dom_image *dom, size_t sz);
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
int xc_dom_update_guest_p2m(struct xc_dom_image *dom);

int xc_dom_boot_xen_init(struct xc_dom_image *dom, xc_interface *xch,
                     domid_t domid);
int xc_dom_boot_mem_init(struct xc_dom_image *dom);
void *xc_dom_boot_domU_map(struct xc_dom_image *dom, xen_pfn_t pfn,
                           xen_pfn_t count);
int xc_dom_boot_image(struct xc_dom_image *dom);
int xc_dom_compat_check(struct xc_dom_image *dom);
int xc_dom_gnttab_init(struct xc_dom_image *dom);
int xc_dom_gnttab_hvm_seed(xc_interface *xch, domid_t domid,
                           xen_pfn_t console_gmfn,
                           xen_pfn_t xenstore_gmfn,
                           domid_t console_domid,
                           domid_t xenstore_domid);
int xc_dom_gnttab_seed(xc_interface *xch, domid_t domid,
                       xen_pfn_t console_gmfn,
                       xen_pfn_t xenstore_gmfn,
                       domid_t console_domid,
                       domid_t xenstore_domid);
int xc_dom_feature_translated(struct xc_dom_image *dom);

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

static inline void *xc_dom_vaddr_to_ptr(struct xc_dom_image *dom,
                                        xen_vaddr_t vaddr,
                                        size_t *safe_region_out)
{
    unsigned int page_size = XC_DOM_PAGE_SIZE(dom);
    xen_pfn_t page = (vaddr - dom->parms.virt_base) / page_size;
    unsigned int offset = (vaddr - dom->parms.virt_base) % page_size;
    xen_pfn_t safe_region_count;
    void *ptr;

    *safe_region_out = 0;
    ptr = xc_dom_pfn_to_ptr_retcount(dom, page, 0, &safe_region_count);
    if ( ptr == NULL )
        return ptr;
    *safe_region_out = (safe_region_count << XC_DOM_PAGE_SHIFT(dom)) - offset;
    return ptr + offset;
}

static inline xen_pfn_t xc_dom_p2m(struct xc_dom_image *dom, xen_pfn_t pfn)
{
    if ( dom->shadow_enabled || xc_dom_feature_translated(dom) )
        return pfn;
    if (pfn < dom->rambase_pfn || pfn >= dom->rambase_pfn + dom->total_pages)
        return INVALID_MFN;
    return dom->p2m_host[pfn - dom->rambase_pfn];
}

#endif /* _XC_DOM_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
