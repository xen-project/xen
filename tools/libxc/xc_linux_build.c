/******************************************************************************
 * xc_linux_build.c
 */

#include <stddef.h>
#include "xg_private.h"
#include "xc_private.h"
#include <xenctrl.h>

#include "xc_elf.h"
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <zlib.h>

/* Handy for printing out '0' prepended values at native pointer size */
#define _p(a) ((void *) ((ulong)a))

#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)
#if defined(__i386__)
#define L3_PROT (_PAGE_PRESENT)
#elif defined(__x86_64__)
#define L3_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)
#define L4_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)
#endif

#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)
#define round_pgdown(_p)  ((_p)&PAGE_MASK)

struct initrd_info {
    enum { INITRD_none, INITRD_file, INITRD_mem } type;
    /*
     * .len must be filled in by the user for type==INITRD_mem. It is
     * filled in by load_initrd() for INITRD_file and unused for
     * INITRD_none.
     */
    unsigned long len;
    union {
        gzFile file_handle;
        char *mem_addr;
    } u;
};

static const char *feature_names[XENFEAT_NR_SUBMAPS*32] = {
    [XENFEAT_writable_page_tables]       = "writable_page_tables",
    [XENFEAT_writable_descriptor_tables] = "writable_descriptor_tables",
    [XENFEAT_auto_translated_physmap]    = "auto_translated_physmap",
    [XENFEAT_supervisor_mode_kernel]     = "supervisor_mode_kernel",
    [XENFEAT_pae_pgdir_above_4gb]        = "pae_pgdir_above_4gb"
};

static inline void set_feature_bit (int nr, uint32_t *addr)
{
    addr[nr>>5] |= (1<<(nr&31));
}

static inline int test_feature_bit(int nr, uint32_t *addr)
{
    return !!(addr[nr>>5] & (1<<(nr&31)));
}

static int parse_features(
    const char *feats,
    uint32_t supported[XENFEAT_NR_SUBMAPS],
    uint32_t required[XENFEAT_NR_SUBMAPS])
{
    const char *end, *p;
    int i, req;

    if ( (end = strchr(feats, ',')) == NULL )
        end = feats + strlen(feats);

    while ( feats < end )
    {
        p = strchr(feats, '|');
        if ( (p == NULL) || (p > end) )
            p = end;

        req = (*feats == '!');
        if ( req )
            feats++;

        for ( i = 0; i < XENFEAT_NR_SUBMAPS*32; i++ )
        {
            if ( feature_names[i] == NULL )
                continue;

            if ( strncmp(feature_names[i], feats, p-feats) == 0 )
            {
                set_feature_bit(i, supported);
                if ( required && req )
                    set_feature_bit(i, required);
                break;
            }
        }

        if ( i == XENFEAT_NR_SUBMAPS*32 )
        {
            ERROR("Unknown feature \"%.*s\".", (int)(p-feats), feats);
            if ( req )
            {
                ERROR("Kernel requires an unknown hypervisor feature.");
                return -EINVAL;
            }
        }

        feats = p;
        if ( *feats == '|' )
            feats++;
    }

    return -EINVAL;
}

static int probeimageformat(const char *image,
                            unsigned long image_size,
                            struct load_funcs *load_funcs)
{
    if ( probe_elf(image, image_size, load_funcs) &&
         probe_bin(image, image_size, load_funcs) )
    {
        xc_set_error(XC_INVALID_KERNEL, "Not a valid ELF or raw kernel image");
        return -EINVAL;
    }

    return 0;
}

static int load_initrd(int xc_handle, domid_t dom,
                struct initrd_info *initrd,
                unsigned long physbase,
                xen_pfn_t *phys_to_mach)
{
    char page[PAGE_SIZE];
    unsigned long pfn_start, pfn;

    if ( initrd->type == INITRD_none )
        return 0;

    pfn_start = physbase >> PAGE_SHIFT;

    if ( initrd->type == INITRD_mem )
    {
        unsigned long nr_pages  = (initrd->len + PAGE_SIZE - 1) >> PAGE_SHIFT;

        for ( pfn = pfn_start; pfn < (pfn_start + nr_pages); pfn++ )
        {
            xc_copy_to_domain_page(
                xc_handle, dom, phys_to_mach[pfn],
                &initrd->u.mem_addr[(pfn - pfn_start) << PAGE_SHIFT]);
        }
    }
    else
    {
        int readlen;

        pfn = pfn_start;
        initrd->len = 0;

        /* gzread returns 0 on EOF */
        while ( (readlen = gzread(initrd->u.file_handle, page, PAGE_SIZE)) )
        {
            if ( readlen < 0 )
            {
                PERROR("Error reading initrd image, could not");
                return -EINVAL;
            }

            initrd->len += readlen;
            xc_copy_to_domain_page(xc_handle, dom, phys_to_mach[pfn++], page);
        }
    }

    return 0;
}

#define alloc_pt(ltab, vltab)                                           \
do {                                                                    \
    ltab = ppt_alloc++;                                                 \
    ltab = (uint64_t)page_array[ltab] << PAGE_SHIFT;                    \
    if ( vltab != NULL )                                                \
        munmap(vltab, PAGE_SIZE);                                       \
    if ( (vltab = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,       \
                                       PROT_READ|PROT_WRITE,            \
                                       ltab >> PAGE_SHIFT)) == NULL )   \
        goto error_out;                                                 \
    memset(vltab, 0x0, PAGE_SIZE);                                      \
} while ( 0 )

#if defined(__i386__)

static int setup_pg_tables(int xc_handle, uint32_t dom,
                           vcpu_guest_context_t *ctxt,
                           unsigned long dsi_v_start,
                           unsigned long v_end,
                           xen_pfn_t *page_array,
                           unsigned long vpt_start,
                           unsigned long vpt_end,
                           unsigned shadow_mode_enabled)
{
    l1_pgentry_t *vl1tab=NULL, *vl1e=NULL;
    l2_pgentry_t *vl2tab=NULL, *vl2e=NULL;
    unsigned long l1tab = 0;
    unsigned long l2tab = 0;
    unsigned long ppt_alloc;
    unsigned long count;

    ppt_alloc = (vpt_start - dsi_v_start) >> PAGE_SHIFT;
    alloc_pt(l2tab, vl2tab);
    vl2e = &vl2tab[l2_table_offset(dsi_v_start)];
    ctxt->ctrlreg[3] = xen_pfn_to_cr3(l2tab >> PAGE_SHIFT);

    for ( count = 0; count < ((v_end - dsi_v_start) >> PAGE_SHIFT); count++ )
    {
        if ( ((unsigned long)vl1e & (PAGE_SIZE-1)) == 0 )
        {
            alloc_pt(l1tab, vl1tab);
            vl1e = &vl1tab[l1_table_offset(dsi_v_start + (count<<PAGE_SHIFT))];
            *vl2e++ = l1tab | L2_PROT;
        }

        *vl1e = (page_array[count] << PAGE_SHIFT) | L1_PROT;

        if ( !shadow_mode_enabled )
            if ( (count >= ((vpt_start-dsi_v_start)>>PAGE_SHIFT)) &&
                 (count <  ((vpt_end  -dsi_v_start)>>PAGE_SHIFT)) )
                *vl1e &= ~_PAGE_RW;

        vl1e++;
    }
    munmap(vl1tab, PAGE_SIZE);
    munmap(vl2tab, PAGE_SIZE);
    return 0;

 error_out:
    if (vl1tab)
        munmap(vl1tab, PAGE_SIZE);
    if (vl2tab)
        munmap(vl2tab, PAGE_SIZE);
    return -1;
}

static int setup_pg_tables_pae(int xc_handle, uint32_t dom,
                               vcpu_guest_context_t *ctxt,
                               unsigned long dsi_v_start,
                               unsigned long v_end,
                               xen_pfn_t *page_array,
                               unsigned long vpt_start,
                               unsigned long vpt_end,
                               unsigned shadow_mode_enabled,
                               unsigned pae_mode)
{
    l1_pgentry_64_t *vl1tab = NULL, *vl1e = NULL;
    l2_pgentry_64_t *vl2tab = NULL, *vl2e = NULL;
    l3_pgentry_64_t *vl3tab = NULL, *vl3e = NULL;
    uint64_t l1tab, l2tab, l3tab;
    unsigned long ppt_alloc, count, nmfn;

    /* First allocate page for page dir. */
    ppt_alloc = (vpt_start - dsi_v_start) >> PAGE_SHIFT;

    if ( pae_mode == PAEKERN_extended_cr3 )
    {
        ctxt->vm_assist |= (1UL << VMASST_TYPE_pae_extended_cr3);
    }
    else if ( page_array[ppt_alloc] > 0xfffff )
    {
        nmfn = xc_make_page_below_4G(xc_handle, dom, page_array[ppt_alloc]);
        if ( nmfn == 0 )
        {
            DPRINTF("Couldn't get a page below 4GB :-(\n");
            goto error_out;
        }
        page_array[ppt_alloc] = nmfn;
    }

    alloc_pt(l3tab, vl3tab);
    vl3e = &vl3tab[l3_table_offset_pae(dsi_v_start)];
    ctxt->ctrlreg[3] = xen_pfn_to_cr3(l3tab >> PAGE_SHIFT);

    for ( count = 0; count < ((v_end - dsi_v_start) >> PAGE_SHIFT); count++)
    {
        if ( !((unsigned long)vl1e & (PAGE_SIZE-1)) )
        {
            if ( !((unsigned long)vl2e & (PAGE_SIZE-1)) )
            {
                alloc_pt(l2tab, vl2tab);
                vl2e = &vl2tab[l2_table_offset_pae(
                    dsi_v_start + (count << PAGE_SHIFT))];
                *vl3e++ = l2tab | L3_PROT;
            }

            alloc_pt(l1tab, vl1tab);
            vl1e = &vl1tab[l1_table_offset_pae(
                dsi_v_start + (count << PAGE_SHIFT))];
            *vl2e++ = l1tab | L2_PROT;

        }

        *vl1e = ((uint64_t)page_array[count] << PAGE_SHIFT) | L1_PROT;

        if ( !shadow_mode_enabled )
            if ( (count >= ((vpt_start-dsi_v_start)>>PAGE_SHIFT)) &&
                 (count <  ((vpt_end  -dsi_v_start)>>PAGE_SHIFT)) )
                *vl1e &= ~_PAGE_RW;

        vl1e++;
    }

    /* Xen requires a mid-level pgdir mapping 0xC0000000 region. */
    if ( (vl3tab[3] & _PAGE_PRESENT) == 0 )
    {
        alloc_pt(l2tab, vl2tab);
        vl3tab[3] = l2tab | L3_PROT;
    }

    munmap(vl1tab, PAGE_SIZE);
    munmap(vl2tab, PAGE_SIZE);
    munmap(vl3tab, PAGE_SIZE);
    return 0;

 error_out:
    if (vl1tab)
        munmap(vl1tab, PAGE_SIZE);
    if (vl2tab)
        munmap(vl2tab, PAGE_SIZE);
    if (vl3tab)
        munmap(vl3tab, PAGE_SIZE);
    return -1;
}

#endif

#if defined(__x86_64__)

static int setup_pg_tables_64(int xc_handle, uint32_t dom,
                              vcpu_guest_context_t *ctxt,
                              unsigned long dsi_v_start,
                              unsigned long v_end,
                              xen_pfn_t *page_array,
                              unsigned long vpt_start,
                              unsigned long vpt_end,
                              int shadow_mode_enabled)
{
    l1_pgentry_t *vl1tab=NULL, *vl1e=NULL;
    l2_pgentry_t *vl2tab=NULL, *vl2e=NULL;
    l3_pgentry_t *vl3tab=NULL, *vl3e=NULL;
    l4_pgentry_t *vl4tab=NULL, *vl4e=NULL;
    unsigned long l2tab = 0;
    unsigned long l1tab = 0;
    unsigned long l3tab = 0;
    unsigned long l4tab = 0;
    unsigned long ppt_alloc;
    unsigned long count;

    /* First allocate page for page dir. */
    ppt_alloc = (vpt_start - dsi_v_start) >> PAGE_SHIFT;
    alloc_pt(l4tab, vl4tab);
    vl4e = &vl4tab[l4_table_offset(dsi_v_start)];
    ctxt->ctrlreg[3] = xen_pfn_to_cr3(l4tab >> PAGE_SHIFT);

    for ( count = 0; count < ((v_end-dsi_v_start)>>PAGE_SHIFT); count++)
    {
        if ( !((unsigned long)vl1e & (PAGE_SIZE-1)) )
        {
            alloc_pt(l1tab, vl1tab);

            if ( !((unsigned long)vl2e & (PAGE_SIZE-1)) )
            {
                alloc_pt(l2tab, vl2tab);
                if ( !((unsigned long)vl3e & (PAGE_SIZE-1)) )
                {
                    alloc_pt(l3tab, vl3tab);
                    vl3e = &vl3tab[l3_table_offset(dsi_v_start + (count<<PAGE_SHIFT))];
                    *vl4e++ = l3tab | L4_PROT;
                }
                vl2e = &vl2tab[l2_table_offset(dsi_v_start + (count<<PAGE_SHIFT))];
                *vl3e++ = l2tab | L3_PROT;
            }
            vl1e = &vl1tab[l1_table_offset(dsi_v_start + (count<<PAGE_SHIFT))];
            *vl2e++ = l1tab | L2_PROT;
        }

        *vl1e = (page_array[count] << PAGE_SHIFT) | L1_PROT;

        if ( !shadow_mode_enabled )
            if ( (count >= ((vpt_start-dsi_v_start)>>PAGE_SHIFT)) &&
                 (count <  ((vpt_end  -dsi_v_start)>>PAGE_SHIFT)) )
                *vl1e &= ~_PAGE_RW;

        vl1e++;
    }

    munmap(vl1tab, PAGE_SIZE);
    munmap(vl2tab, PAGE_SIZE);
    munmap(vl3tab, PAGE_SIZE);
    munmap(vl4tab, PAGE_SIZE);
    return 0;

 error_out:
    if (vl1tab)
        munmap(vl1tab, PAGE_SIZE);
    if (vl2tab)
        munmap(vl2tab, PAGE_SIZE);
    if (vl3tab)
        munmap(vl3tab, PAGE_SIZE);
    if (vl4tab)
        munmap(vl4tab, PAGE_SIZE);
    return -1;
}
#endif

#ifdef __ia64__
static int setup_guest(int xc_handle,
                       uint32_t dom,
                       const char *image, unsigned long image_size,
                       struct initrd_info *initrd,
                       unsigned long nr_pages,
                       unsigned long *pvsi, unsigned long *pvke,
                       unsigned long *pvss, vcpu_guest_context_t *ctxt,
                       const char *cmdline,
                       unsigned long shared_info_frame,
                       unsigned long flags,
                       unsigned int store_evtchn, unsigned long *store_mfn,
                       unsigned int console_evtchn, unsigned long *console_mfn,
                       uint32_t required_features[XENFEAT_NR_SUBMAPS])
{
    xen_pfn_t *page_array = NULL;
    struct load_funcs load_funcs;
    struct domain_setup_info dsi;
    unsigned long vinitrd_start;
    unsigned long vinitrd_end;
    unsigned long v_end;
    unsigned long start_page, pgnr;
    start_info_t *start_info;
    unsigned long start_info_mpa;
    struct xen_ia64_boot_param *bp;
    shared_info_t *shared_info;
    int i;
    DECLARE_DOMCTL;
    int rc;

    rc = probeimageformat(image, image_size, &load_funcs);
    if ( rc != 0 )
        goto error_out;

    memset(&dsi, 0, sizeof(struct domain_setup_info));

    rc = (load_funcs.parseimage)(image, image_size, &dsi);
    if ( rc != 0 )
        goto error_out;

    if ( (page_array = malloc(nr_pages * sizeof(xen_pfn_t))) == NULL )
    {
        PERROR("Could not allocate memory");
        goto error_out;
    }
    for ( i = 0; i < nr_pages; i++ )
        page_array[i] = i;
    if ( xc_domain_memory_populate_physmap(xc_handle, dom, nr_pages,
                                           0, 0, page_array) )
    {
        PERROR("Could not allocate memory for PV guest.\n");
        goto error_out;
    }

    dsi.v_start    = round_pgdown(dsi.v_start);
    vinitrd_start  = round_pgup(dsi.v_end);
    start_info_mpa = (nr_pages - 3) << PAGE_SHIFT;
    *pvke          = dsi.v_kernentry;

    /* Build firmware.  */
    memset(&domctl.u.arch_setup, 0, sizeof(domctl.u.arch_setup));
    domctl.u.arch_setup.flags = 0;
    domctl.u.arch_setup.bp = start_info_mpa + sizeof (start_info_t);
    domctl.u.arch_setup.maxmem = (nr_pages - 3) << PAGE_SHIFT;
    domctl.cmd = XEN_DOMCTL_arch_setup;
    domctl.domain = (domid_t)dom;
    if ( xc_domctl(xc_handle, &domctl) )
        goto error_out;

    start_page = dsi.v_start >> PAGE_SHIFT;
    /* in order to get initrd->len, we need to load initrd image at first */
    if ( load_initrd(xc_handle, dom, initrd,
                     vinitrd_start - dsi.v_start, page_array + start_page) )
        goto error_out;

    vinitrd_end    = vinitrd_start + initrd->len;
    v_end          = round_pgup(vinitrd_end);
    pgnr = (v_end - dsi.v_start) >> PAGE_SHIFT;
    if ( pgnr > nr_pages )
    {
        PERROR("too small memory is specified. "
               "At least %ld kb is necessary.\n",
               pgnr << (PAGE_SHIFT - 10));
    }

    IPRINTF("VIRTUAL MEMORY ARRANGEMENT:\n"
           " Loaded kernel: %p->%p\n"
           " Init. ramdisk: %p->%p\n"
           " TOTAL:         %p->%p\n",
           _p(dsi.v_kernstart), _p(dsi.v_kernend),
           _p(vinitrd_start),   _p(vinitrd_end),
           _p(dsi.v_start),     _p(v_end));
    IPRINTF(" ENTRY ADDRESS: %p\n", _p(dsi.v_kernentry));

    (load_funcs.loadimage)(image, image_size, xc_handle, dom,
                           page_array + start_page, &dsi);

    *store_mfn = page_array[nr_pages - 2]; //XXX
    *console_mfn = page_array[nr_pages - 1]; //XXX
    IPRINTF("start_info: 0x%lx at 0x%lx, "
           "store_mfn: 0x%lx at 0x%lx, "
           "console_mfn: 0x%lx at 0x%lx\n",
           page_array[nr_pages - 3], nr_pages - 3,
           *store_mfn,    nr_pages - 2,
           *console_mfn,  nr_pages - 1);

    start_info = xc_map_foreign_range(
        xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE,
        page_array[nr_pages - 3]);
    if ( start_info == NULL )
        goto error_out;

    memset(start_info, 0, sizeof(*start_info));
    rc = xc_version(xc_handle, XENVER_version, NULL);
    sprintf(start_info->magic, "xen-%i.%i-ia64", rc >> 16, rc & (0xFFFF));
    start_info->flags        = flags;
    start_info->store_mfn    = nr_pages - 2;
    start_info->store_evtchn = store_evtchn;
    start_info->console.domU.mfn   = nr_pages - 1;
    start_info->console.domU.evtchn = console_evtchn;
    start_info->nr_pages       = nr_pages; // FIXME?: nr_pages - 2 ????

    bp = (struct xen_ia64_boot_param *)(start_info + 1);
    bp->command_line = start_info_mpa + offsetof(start_info_t, cmd_line);
    if ( cmdline != NULL )
    {
        strncpy((char *)start_info->cmd_line, cmdline, MAX_GUEST_CMDLINE);
        start_info->cmd_line[MAX_GUEST_CMDLINE - 1] = 0;
    }
    if ( initrd->len != 0 )
    {
        bp->initrd_start    = vinitrd_start;
        bp->initrd_size     = initrd->len;
    }
    ctxt->user_regs.r28 = start_info_mpa + sizeof (start_info_t);
    munmap(start_info, PAGE_SIZE);

    /*
     * shared_info is assiged into guest pseudo physical address space
     * by XEN_DOMCTL_arch_setup. shared_info_frame is stale value until that.
     * So passed shared_info_frame is stale. obtain the right value here.
     */
    domctl.cmd = XEN_DOMCTL_getdomaininfo;
    domctl.domain = (domid_t)dom;
    if ( (xc_domctl(xc_handle, &domctl) < 0) ||
         ((uint16_t)domctl.domain != dom) )
    {
        PERROR("Could not get info on domain");
        goto error_out;
    }
    shared_info_frame = domctl.u.getdomaininfo.shared_info_frame;

    /* shared_info page starts its life empty. */
    shared_info = xc_map_foreign_range(
        xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE, shared_info_frame);
    printf("shared_info = %p frame=%lx\n",
           shared_info, shared_info_frame);
    //memset(shared_info, 0, PAGE_SIZE);
    /* Mask all upcalls... */
    for ( i = 0; i < MAX_VIRT_CPUS; i++ )
        shared_info->vcpu_info[i].evtchn_upcall_mask = 1;
    shared_info->arch.start_info_pfn = nr_pages - 3;

    munmap(shared_info, PAGE_SIZE);
    free(page_array);
    return 0;

 error_out:
    free(page_array);
    return -1;
}
#else /* x86 */

/* Check if the platform supports the guest kernel format */
static int compat_check(int xc_handle, struct domain_setup_info *dsi)
{
    xen_capabilities_info_t xen_caps = "";

    if (xc_version(xc_handle, XENVER_capabilities, &xen_caps) != 0) {
        xc_set_error(XC_INVALID_KERNEL,
                     "Cannot determine host capabilities.");
        return 0;
    }

#ifndef __x86_64__//temp
    if (strstr(xen_caps, "xen-3.0-x86_32p")) {
        if (dsi->pae_kernel == PAEKERN_bimodal) {
            dsi->pae_kernel = PAEKERN_extended_cr3;
        } else if (dsi->pae_kernel == PAEKERN_no) {
            xc_set_error(XC_INVALID_KERNEL,
                         "Non PAE-kernel on PAE host.");
            return 0;
        }
    } else {
        if (dsi->pae_kernel == PAEKERN_bimodal) {
            dsi->pae_kernel = PAEKERN_no;
        } else if (dsi->pae_kernel != PAEKERN_no) {
            xc_set_error(XC_INVALID_KERNEL,
                         "PAE-kernel on non-PAE host.");
            return 0;
        }
    }
#endif

    return 1;
}

static inline int increment_ulong(unsigned long *pval, unsigned long inc)
{
    if ( inc >= -*pval )
    {
        ERROR("Value wrapped to zero: image too large?");
        return 0;
    }
    *pval += inc;
    return 1;
}

static int setup_guest(int xc_handle,
                       uint32_t dom,
                       const char *image, unsigned long image_size,
                       struct initrd_info *initrd,
                       unsigned long nr_pages,
                       unsigned long *pvsi, unsigned long *pvke,
                       unsigned long *pvss, vcpu_guest_context_t *ctxt,
                       const char *cmdline,
                       unsigned long shared_info_frame,
                       unsigned long flags,
                       unsigned int store_evtchn, unsigned long *store_mfn,
                       unsigned int console_evtchn, unsigned long *console_mfn,
                       uint32_t required_features[XENFEAT_NR_SUBMAPS])
{
    xen_pfn_t *page_array = NULL;
    unsigned long count, i;
    unsigned long long hypercall_page;
    int hypercall_page_defined;
    start_info_t *start_info;
    shared_info_t *shared_info;
    const char *p;
    DECLARE_DOMCTL;
    int rc;

    unsigned long nr_pt_pages;
    unsigned long physmap_pfn;
    xen_pfn_t *physmap, *physmap_e;

    struct load_funcs load_funcs;
    struct domain_setup_info dsi;
    unsigned long vinitrd_start;
    unsigned long vphysmap_start;
    unsigned long vstartinfo_start;
    unsigned long vstoreinfo_start;
    unsigned long vconsole_start;
    unsigned long vsharedinfo_start = 0; /* XXX gcc */
    unsigned long vstack_start;
    unsigned long vstack_end;
    unsigned long vpt_start;
    unsigned long vpt_end;
    unsigned long v_end;
    unsigned long guest_store_mfn, guest_console_mfn, guest_shared_info_mfn;
    unsigned long shadow_mode_enabled;
    uint32_t supported_features[XENFEAT_NR_SUBMAPS] = { 0, };

    rc = probeimageformat(image, image_size, &load_funcs);
    if ( rc != 0 )
        goto error_out;

    memset(&dsi, 0, sizeof(struct domain_setup_info));

    rc = (load_funcs.parseimage)(image, image_size, &dsi);
    if ( rc != 0 )
        goto error_out;

    if ( (dsi.v_start & (PAGE_SIZE-1)) != 0 )
    {
        PERROR("Guest OS must load to a page boundary.");
        goto error_out;
    }

    if ( !compat_check(xc_handle, &dsi) )
        goto error_out;

    /* Parse and validate kernel features. */
    if ( (p = xen_elfnote_string(&dsi, XEN_ELFNOTE_FEATURES)) != NULL )
    {
        if ( !parse_features(p, supported_features, required_features) )
        {
            ERROR("Failed to parse guest kernel features.");
            goto error_out;
        }

        IPRINTF("Supported features  = { %08x }.\n", supported_features[0]);
        IPRINTF("Required features   = { %08x }.\n", required_features[0]);
    }

    for ( i = 0; i < XENFEAT_NR_SUBMAPS; i++ )
    {
        if ( (supported_features[i] & required_features[i]) !=
             required_features[i] )
        {
            ERROR("Guest kernel does not support a required feature.");
            goto error_out;
        }
    }

    shadow_mode_enabled = test_feature_bit(XENFEAT_auto_translated_physmap,
                                           required_features);

    if ( (page_array = malloc(nr_pages * sizeof(unsigned long))) == NULL )
    {
        PERROR("Could not allocate memory");
        goto error_out;
    }

    for ( i = 0; i < nr_pages; i++ )
        page_array[i] = i;

    if ( xc_domain_memory_populate_physmap(xc_handle, dom, nr_pages,
                                           0, 0, page_array) )
    {
        PERROR("Could not allocate memory for PV guest.\n");
        goto error_out;
    }


    if ( shadow_mode_enabled )
    {
        /*
         * Enable shadow translate mode. This must happen after
         * populate physmap because the p2m reservation is based on
         * the domain's current memory allocation.
         */
        if ( xc_shadow_control(xc_handle, dom,
                           XEN_DOMCTL_SHADOW_OP_ENABLE_TRANSLATE,
                           NULL, 0, NULL, 0, NULL) < 0 )
        {
            PERROR("Could not enable translation mode");
            goto error_out;
        }

        /* Reinitialise the gpfn->gmfn array. */
        for ( i = 0; i < nr_pages; i++ )
            page_array[i] = i;
    }

    rc = (load_funcs.loadimage)(image, image_size,
                           xc_handle, dom, page_array,
                           &dsi);
    if ( rc != 0 )
        goto error_out;

    /*
     * Why do we need this? The number of page-table frames depends on the
     * size of the bootstrap address space. But the size of the address space
     * depends on the number of page-table frames (since each one is mapped
     * read-only). We have a pair of simultaneous equations in two unknowns,
     * which we solve by exhaustive search.
     */
    v_end = round_pgup(dsi.v_end);
    if ( v_end == 0 )
    {
        ERROR("End of mapped kernel image too close to end of memory");
        goto error_out;
    }

    vinitrd_start = v_end;
    if ( load_initrd(xc_handle, dom, initrd,
                     vinitrd_start - dsi.v_start, page_array) )
        goto error_out;
    if ( !increment_ulong(&v_end, round_pgup(initrd->len)) )
        goto error_out;

    vphysmap_start = v_end;
    if ( !increment_ulong(&v_end, round_pgup(nr_pages * sizeof(long))) )
        goto error_out;
    vstartinfo_start = v_end;
    if ( !increment_ulong(&v_end, PAGE_SIZE) )
        goto error_out;
    vstoreinfo_start = v_end;
    if ( !increment_ulong(&v_end, PAGE_SIZE) )
        goto error_out;
    vconsole_start = v_end;
    if ( !increment_ulong(&v_end, PAGE_SIZE) )
        goto error_out;
    if ( shadow_mode_enabled ) {
        vsharedinfo_start = v_end;
        if ( !increment_ulong(&v_end, PAGE_SIZE) )
            goto error_out;
    }
    vpt_start = v_end;

    for ( nr_pt_pages = 2; ; nr_pt_pages++ )
    {
        /* vpt_end = vpt_staret + (nr_pt_pages * PAGE_SIZE); */
        vpt_end = vpt_start;
        if ( !increment_ulong(&vpt_end, nr_pt_pages * PAGE_SIZE) )
            goto error_out;

        vstack_start = vpt_end;
        /* vstack_end = vstack_start + PAGE_SIZE; */
        vstack_end = vstack_start;
        if ( !increment_ulong(&vstack_end, PAGE_SIZE) )
            goto error_out;

        /* v_end = (vstack_end + (1UL<<22)-1) & ~((1UL<<22)-1); */
        v_end = vstack_end;
        if ( !increment_ulong(&v_end, (1UL<<22)-1) )
            goto error_out;
        v_end &= ~((1UL<<22)-1);

        if ( (v_end - vstack_end) < (512UL << 10) )
        {
            /* Add extra 4MB to get >= 512kB padding. */
            if ( !increment_ulong(&v_end, 1UL << 22) )
                goto error_out;
        }

#define NR(_l,_h,_s)                                                    \
    (((((unsigned long)(_h) + ((1UL<<(_s))-1)) & ~((1UL<<(_s))-1)) -    \
    ((unsigned long)(_l) & ~((1UL<<(_s))-1))) >> (_s))
#if defined(__i386__)
        if ( dsi.pae_kernel != PAEKERN_no )
        {
            if ( (1 + /* # L3 */
                  NR(dsi.v_start, v_end, L3_PAGETABLE_SHIFT_PAE) + /* # L2 */
                  NR(dsi.v_start, v_end, L2_PAGETABLE_SHIFT_PAE) + /* # L1 */
                  /* Include a fourth mid-level page directory for Xen. */
                  (v_end <= (3 << L3_PAGETABLE_SHIFT_PAE)))
                  <= nr_pt_pages )
                break;
        }
        else
        {
            if ( (1 + /* # L2 */
                  NR(dsi.v_start, v_end, L2_PAGETABLE_SHIFT)) /* # L1 */
                 <= nr_pt_pages )
                break;
        }
#elif defined(__x86_64__)
        if ( (1 + /* # L4 */
              NR(dsi.v_start, v_end, L4_PAGETABLE_SHIFT) + /* # L3 */
              NR(dsi.v_start, v_end, L3_PAGETABLE_SHIFT) + /* # L2 */
              NR(dsi.v_start, v_end, L2_PAGETABLE_SHIFT))  /* # L1 */
             <= nr_pt_pages )
            break;
#endif
    }

    IPRINTF("VIRTUAL MEMORY ARRANGEMENT:\n");
    IPRINTF(" Loaded kernel:    %p->%p\n", _p(dsi.v_kernstart),
           _p(dsi.v_kernend));
    if ( initrd->len )
        IPRINTF(" Initial ramdisk:  %p->%p\n", _p(vinitrd_start),
               _p(vinitrd_start + initrd->len));
    IPRINTF(" Phys-Mach map:    %p\n", _p(vphysmap_start));
    IPRINTF(" Start info:       %p\n", _p(vstartinfo_start));
    IPRINTF(" Store page:       %p\n", _p(vstoreinfo_start));
    IPRINTF(" Console page:     %p\n", _p(vconsole_start));
    if ( shadow_mode_enabled )
        IPRINTF(" Shared Info page: %p\n", _p(vsharedinfo_start));
    IPRINTF(" Page tables:      %p\n", _p(vpt_start));
    IPRINTF(" Boot stack:       %p\n", _p(vstack_start));
    IPRINTF(" TOTAL:            %p->%p\n", _p(dsi.v_start), _p(v_end));
    IPRINTF(" ENTRY ADDRESS:    %p\n", _p(dsi.v_kernentry));

    if ( ((v_end - dsi.v_start)>>PAGE_SHIFT) > nr_pages )
    {
        PERROR("Initial guest OS requires too much space\n"
               "(%pMB is greater than %luMB limit)\n",
               _p((v_end-dsi.v_start)>>20), nr_pages>>(20-PAGE_SHIFT));
        goto error_out;
    }

#if defined(__i386__)
    if ( dsi.pae_kernel != PAEKERN_no )
        rc = setup_pg_tables_pae(xc_handle, dom, ctxt,
                                 dsi.v_start, v_end,
                                 page_array, vpt_start, vpt_end,
                                 shadow_mode_enabled, dsi.pae_kernel);
    else
        rc = setup_pg_tables(xc_handle, dom, ctxt,
                             dsi.v_start, v_end,
                             page_array, vpt_start, vpt_end,
                             shadow_mode_enabled);
#endif
#if defined(__x86_64__)
    rc = setup_pg_tables_64(xc_handle, dom, ctxt,
                            dsi.v_start, v_end,
                            page_array, vpt_start, vpt_end,
                            shadow_mode_enabled);
#endif
    if ( rc != 0 )
        goto error_out;

    /*
     * Pin down l2tab addr as page dir page - causes hypervisor to provide
     * correct protection for the page
     */
    if ( !shadow_mode_enabled )
    {
#if defined(__i386__)
        if ( dsi.pae_kernel != PAEKERN_no )
        {
            if ( pin_table(xc_handle, MMUEXT_PIN_L3_TABLE,
                           xen_cr3_to_pfn(ctxt->ctrlreg[3]), dom) )
                goto error_out;
        }
        else
        {
            if ( pin_table(xc_handle, MMUEXT_PIN_L2_TABLE,
                           xen_cr3_to_pfn(ctxt->ctrlreg[3]), dom) )
                goto error_out;
        }
#elif defined(__x86_64__)
        /*
         * Pin down l4tab addr as page dir page - causes hypervisor to  provide
         * correct protection for the page
         */
        if ( pin_table(xc_handle, MMUEXT_PIN_L4_TABLE,
                       xen_cr3_to_pfn(ctxt->ctrlreg[3]), dom) )
            goto error_out;
#endif
    }

    /* Write the phys->machine table entries (machine->phys already done). */
    physmap_pfn = (vphysmap_start - dsi.v_start) >> PAGE_SHIFT;
    physmap = physmap_e = xc_map_foreign_range(
        xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE,
        page_array[physmap_pfn++]);
    for ( count = 0; count < nr_pages; count++ )
    {
        *physmap_e++ = page_array[count];
        if ( ((unsigned long)physmap_e & (PAGE_SIZE-1)) == 0 )
        {
            munmap(physmap, PAGE_SIZE);
            physmap = physmap_e = xc_map_foreign_range(
                xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE,
                page_array[physmap_pfn++]);
        }
    }
    munmap(physmap, PAGE_SIZE);

    if ( shadow_mode_enabled )
    {
        struct xen_add_to_physmap xatp;

        guest_shared_info_mfn = (vsharedinfo_start-dsi.v_start) >> PAGE_SHIFT;

        /* Map shared info frame into guest physmap. */
        xatp.domid = dom;
        xatp.space = XENMAPSPACE_shared_info;
        xatp.idx   = 0;
        xatp.gpfn  = guest_shared_info_mfn;
        rc = xc_memory_op(xc_handle, XENMEM_add_to_physmap, &xatp);
        if ( rc != 0 )
        {
            PERROR("Cannot map shared info pfn");
            goto error_out;
        }

        /* Map grant table frames into guest physmap. */
        for ( i = 0; ; i++ )
        {
            xatp.domid = dom;
            xatp.space = XENMAPSPACE_grant_table;
            xatp.idx   = i;
            xatp.gpfn  = nr_pages + i;
            rc = xc_memory_op(xc_handle, XENMEM_add_to_physmap, &xatp);
            if ( rc != 0 )
            {
                if ( errno == EINVAL )
                    break; /* done all grant tables */
                PERROR("Cannot map grant table pfn");
                goto error_out;
            }
        }
    }
    else
    {
        guest_shared_info_mfn = shared_info_frame;
    }

    *store_mfn = page_array[(vstoreinfo_start-dsi.v_start) >> PAGE_SHIFT];
    *console_mfn = page_array[(vconsole_start-dsi.v_start) >> PAGE_SHIFT];
    if ( xc_clear_domain_page(xc_handle, dom, *store_mfn) ||
         xc_clear_domain_page(xc_handle, dom, *console_mfn) )
        goto error_out;
    if ( shadow_mode_enabled )
    {
        guest_store_mfn = (vstoreinfo_start-dsi.v_start) >> PAGE_SHIFT;
        guest_console_mfn = (vconsole_start-dsi.v_start) >> PAGE_SHIFT;
    }
    else
    {
        guest_store_mfn = *store_mfn;
        guest_console_mfn = *console_mfn;
    }

    start_info = xc_map_foreign_range(
        xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE,
        page_array[(vstartinfo_start-dsi.v_start)>>PAGE_SHIFT]);
    /*shared_info, start_info */
    memset(start_info, 0, sizeof(*start_info));
    rc = xc_version(xc_handle, XENVER_version, NULL);
    sprintf(start_info->magic, "xen-%i.%i-x86_%d%s",
            rc >> 16, rc & (0xFFFF), (unsigned int)sizeof(long)*8,
            (dsi.pae_kernel != PAEKERN_no) ? "p" : "");
    start_info->nr_pages     = nr_pages;
    start_info->shared_info  = guest_shared_info_mfn << PAGE_SHIFT;
    start_info->flags        = flags;
    start_info->pt_base      = vpt_start;
    start_info->nr_pt_frames = nr_pt_pages;
    start_info->mfn_list     = vphysmap_start;
    start_info->store_mfn    = guest_store_mfn;
    start_info->store_evtchn = store_evtchn;
    start_info->console.domU.mfn   = guest_console_mfn;
    start_info->console.domU.evtchn = console_evtchn;
    if ( initrd->len != 0 )
    {
        start_info->mod_start    = vinitrd_start;
        start_info->mod_len      = initrd->len;
    }
    if ( cmdline != NULL )
    {
        strncpy((char *)start_info->cmd_line, cmdline, MAX_GUEST_CMDLINE);
        start_info->cmd_line[MAX_GUEST_CMDLINE-1] = '\0';
    }
    munmap(start_info, PAGE_SIZE);

    /* shared_info page starts its life empty. */
    shared_info = xc_map_foreign_range(
        xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE, shared_info_frame);
    memset(shared_info, 0, PAGE_SIZE);
    /* Mask all upcalls... */
    for ( i = 0; i < MAX_VIRT_CPUS; i++ )
        shared_info->vcpu_info[i].evtchn_upcall_mask = 1;

    munmap(shared_info, PAGE_SIZE);

    hypercall_page = xen_elfnote_numeric(&dsi, XEN_ELFNOTE_HYPERCALL_PAGE,
                                         &hypercall_page_defined);
    if ( hypercall_page_defined )
    {
        unsigned long long pfn = (hypercall_page - dsi.v_start) >> PAGE_SHIFT;
        if ( pfn >= nr_pages )
            goto error_out;
        domctl.domain = (domid_t)dom;
        domctl.u.hypercall_init.gmfn = page_array[pfn];
        domctl.cmd = XEN_DOMCTL_hypercall_init;
        if ( xc_domctl(xc_handle, &domctl) )
            goto error_out;
    }

    free(page_array);

    *pvsi = vstartinfo_start;
    *pvss = vstack_start;
    *pvke = dsi.v_kernentry;

    return 0;

 error_out:
    free(page_array);
    return -1;
}
#endif

static int xc_linux_build_internal(int xc_handle,
                                   uint32_t domid,
                                   unsigned int mem_mb,
                                   const char *image,
                                   unsigned long image_size,
                                   struct initrd_info *initrd,
                                   const char *cmdline,
                                   const char *features,
                                   unsigned long flags,
                                   unsigned int store_evtchn,
                                   unsigned long *store_mfn,
                                   unsigned int console_evtchn,
                                   unsigned long *console_mfn)
{
    struct xen_domctl launch_domctl;
    DECLARE_DOMCTL;
    int rc;
    struct vcpu_guest_context st_ctxt, *ctxt = &st_ctxt;
    unsigned long vstartinfo_start, vkern_entry, vstack_start;
    uint32_t      features_bitmap[XENFEAT_NR_SUBMAPS] = { 0, };

    if ( features != NULL )
    {
        if ( !parse_features(features, features_bitmap, NULL) )
        {
            PERROR("Failed to parse configured features\n");
            goto error_out;
        }
    }

    memset(ctxt, 0, sizeof(*ctxt));

    if ( lock_pages(ctxt, sizeof(*ctxt) ) )
    {
        PERROR("%s: ctxt lock failed", __func__);
        return 1;
    }

    domctl.cmd = XEN_DOMCTL_getdomaininfo;
    domctl.domain = (domid_t)domid;
    if ( (xc_domctl(xc_handle, &domctl) < 0) ||
         ((uint16_t)domctl.domain != domid) )
    {
        PERROR("Could not get info on domain");
        goto error_out;
    }

    if ( setup_guest(xc_handle, domid, image, image_size,
                     initrd,
                     mem_mb << (20 - PAGE_SHIFT),
                     &vstartinfo_start, &vkern_entry,
                     &vstack_start, ctxt, cmdline,
                     domctl.u.getdomaininfo.shared_info_frame,
                     flags, store_evtchn, store_mfn,
                     console_evtchn, console_mfn,
                     features_bitmap) < 0 )
    {
        goto error_out;
    }

#ifdef __ia64__
    /* based on new_thread in xen/arch/ia64/domain.c */
    ctxt->user_regs.cr_iip = vkern_entry;
    ctxt->user_regs.cr_ifs = 1UL << 63;
    ctxt->user_regs.ar_fpsr = xc_ia64_fpsr_default();
#else /* x86 */
    /*
     * Initial register values:
     *  DS,ES,FS,GS = FLAT_KERNEL_DS
     *       CS:EIP = FLAT_KERNEL_CS:start_pc
     *       SS:ESP = FLAT_KERNEL_DS:start_stack
     *          ESI = start_info
     *  [EAX,EBX,ECX,EDX,EDI,EBP are zero]
     *       EFLAGS = IF | 2 (bit 1 is reserved and should always be 1)
     */
    ctxt->user_regs.ds = FLAT_KERNEL_DS;
    ctxt->user_regs.es = FLAT_KERNEL_DS;
    ctxt->user_regs.fs = FLAT_KERNEL_DS;
    ctxt->user_regs.gs = FLAT_KERNEL_DS;
    ctxt->user_regs.ss = FLAT_KERNEL_SS;
    ctxt->user_regs.cs = FLAT_KERNEL_CS;
    ctxt->user_regs.eip = vkern_entry;
    ctxt->user_regs.esp = vstack_start + PAGE_SIZE;
    ctxt->user_regs.esi = vstartinfo_start;
    ctxt->user_regs.eflags = 1 << 9; /* Interrupt Enable */

    ctxt->flags = VGCF_IN_KERNEL;

    ctxt->kernel_ss = ctxt->user_regs.ss;
    ctxt->kernel_sp = ctxt->user_regs.esp;
#endif /* x86 */

    memset(&launch_domctl, 0, sizeof(launch_domctl));

    launch_domctl.domain = (domid_t)domid;
    launch_domctl.u.vcpucontext.vcpu   = 0;
    set_xen_guest_handle(launch_domctl.u.vcpucontext.ctxt, ctxt);

    launch_domctl.cmd = XEN_DOMCTL_setvcpucontext;
    rc = xc_domctl(xc_handle, &launch_domctl);

    return rc;

 error_out:
    return -1;
}

int xc_linux_build_mem(int xc_handle,
                       uint32_t domid,
                       unsigned int mem_mb,
                       const char *image_buffer,
                       unsigned long image_size,
                       const char *initrd,
                       unsigned long initrd_len,
                       const char *cmdline,
                       const char *features,
                       unsigned long flags,
                       unsigned int store_evtchn,
                       unsigned long *store_mfn,
                       unsigned int console_evtchn,
                       unsigned long *console_mfn)
{
    int            sts;
    char          *img_buf;
    unsigned long  img_len;
    struct initrd_info initrd_info = { .type = INITRD_none };

    /* A kernel buffer is required */
    if ( (image_buffer == NULL) || (image_size == 0) )
    {
        ERROR("kernel image buffer not present");
        return -1;
    }

    /* If it's gzipped, inflate it;  otherwise, use as is */
    /* xc_inflate_buffer may return the same buffer pointer if */
    /* the buffer is already inflated */
    img_buf = xc_inflate_buffer(image_buffer, image_size, &img_len);
    if ( img_buf == NULL )
    {
        ERROR("unable to inflate kernel image buffer");
        return -1;
    }

    /* RAM disks are optional; if we get one, inflate it */
    if ( initrd != NULL )
    {
        initrd_info.type = INITRD_mem;
        initrd_info.u.mem_addr = xc_inflate_buffer(
            initrd, initrd_len, &initrd_info.len);
        if ( initrd_info.u.mem_addr == NULL )
        {
            ERROR("unable to inflate ram disk buffer");
            sts = -1;
            goto out;
        }
    }

    sts = xc_linux_build_internal(xc_handle, domid, mem_mb, img_buf, img_len,
                                  &initrd_info, cmdline, features, flags,
                                  store_evtchn, store_mfn,
                                  console_evtchn, console_mfn);

 out:
    /* The inflation routines may pass back the same buffer so be */
    /* sure that we have a buffer and that it's not the one passed in. */
    /* Don't unnecessarily annoy/surprise/confound the caller */
    if ( (img_buf != NULL) && (img_buf != image_buffer) )
        free(img_buf);
    if ( (initrd_info.u.mem_addr != NULL) &&
         (initrd_info.u.mem_addr != initrd) )
        free(initrd_info.u.mem_addr);

    return sts;
}

int xc_linux_build(int xc_handle,
                   uint32_t domid,
                   unsigned int mem_mb,
                   const char *image_name,
                   const char *initrd_name,
                   const char *cmdline,
                   const char *features,
                   unsigned long flags,
                   unsigned int store_evtchn,
                   unsigned long *store_mfn,
                   unsigned int console_evtchn,
                   unsigned long *console_mfn)
{
    char *image = NULL;
    unsigned long image_size;
    struct initrd_info initrd_info = { .type = INITRD_none };
    int fd = -1, sts = -1;

    if ( (image_name == NULL) ||
         ((image = xc_read_image(image_name, &image_size)) == NULL ))
        return -1;

    if ( (initrd_name != NULL) && (strlen(initrd_name) != 0) )
    {
        initrd_info.type = INITRD_file;

        if ( (fd = open(initrd_name, O_RDONLY)) < 0 )
        {
            PERROR("Could not open the initial ramdisk image");
            goto error_out;
        }

        if ( (initrd_info.u.file_handle = gzdopen(fd, "rb")) == NULL )
        {
            PERROR("Could not allocate decompression state for initrd");
            goto error_out;
        }
    }

    sts = xc_linux_build_internal(xc_handle, domid, mem_mb, image, image_size,
                                  &initrd_info, cmdline, features, flags,
                                  store_evtchn, store_mfn,
                                  console_evtchn, console_mfn);

 error_out:
    free(image);
    if ( initrd_info.type == INITRD_file && initrd_info.u.file_handle )
        gzclose(initrd_info.u.file_handle);
    else if ( fd >= 0 )
        close(fd);

    return sts;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
