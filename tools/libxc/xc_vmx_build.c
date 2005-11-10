/******************************************************************************
 * xc_vmx_build.c
 */

#include <stddef.h>
#include "xg_private.h"
#define ELFSIZE 32
#include "xc_elf.h"
#include <stdlib.h>
#include <unistd.h>
#include <zlib.h>
#include <xen/io/ioreq.h>

#define VMX_LOADER_ENTR_ADDR  0x00100000

#define L1_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_USER)
#define L2_PROT (_PAGE_PRESENT|_PAGE_RW|_PAGE_ACCESSED|_PAGE_DIRTY|_PAGE_USER)
#ifdef __x86_64__
#define L3_PROT (_PAGE_PRESENT)
#endif

#define E820MAX	128

#define E820_RAM          1
#define E820_RESERVED     2
#define E820_ACPI         3
#define E820_NVS          4
#define E820_IO          16
#define E820_SHARED_PAGE 17
#define E820_XENSTORE    18

#define E820_MAP_PAGE       0x00090000
#define E820_MAP_NR_OFFSET  0x000001E8
#define E820_MAP_OFFSET     0x000002D0

#define VCPU_NR_PAGE        0x0009F000
#define VCPU_NR_OFFSET      0x00000800

struct e820entry {
    uint64_t addr;
    uint64_t size;
    uint32_t type;
} __attribute__((packed));

#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)
#define round_pgdown(_p)  ((_p)&PAGE_MASK)

static int
parseelfimage(
    char *elfbase, unsigned long elfsize, struct domain_setup_info *dsi);
static int
loadelfimage(
    char *elfbase, int xch, uint32_t dom, unsigned long *parray,
    struct domain_setup_info *dsi);

static unsigned char build_e820map(void *e820_page, unsigned long mem_size)
{
    struct e820entry *e820entry =
        (struct e820entry *)(((unsigned char *)e820_page) + E820_MAP_OFFSET);
    unsigned char nr_map = 0;

    /* XXX: Doesn't work for > 4GB yet */
    e820entry[nr_map].addr = 0x0;
    e820entry[nr_map].size = 0x9F800;
    e820entry[nr_map].type = E820_RAM;
    nr_map++;

    e820entry[nr_map].addr = 0x9F800;
    e820entry[nr_map].size = 0x800;
    e820entry[nr_map].type = E820_RESERVED;
    nr_map++;

    e820entry[nr_map].addr = 0xA0000;
    e820entry[nr_map].size = 0x20000;
    e820entry[nr_map].type = E820_IO;
    nr_map++;

    e820entry[nr_map].addr = 0xF0000;
    e820entry[nr_map].size = 0x10000;
    e820entry[nr_map].type = E820_RESERVED;
    nr_map++;

#define STATIC_PAGES    2       /* for ioreq_t and store_mfn */
    /* Most of the ram goes here */
    e820entry[nr_map].addr = 0x100000;
    e820entry[nr_map].size = mem_size - 0x100000 - STATIC_PAGES*PAGE_SIZE;
    e820entry[nr_map].type = E820_RAM;
    nr_map++;

    /* Statically allocated special pages */

    /* Shared ioreq_t page */
    e820entry[nr_map].addr = mem_size - PAGE_SIZE;
    e820entry[nr_map].size = PAGE_SIZE;
    e820entry[nr_map].type = E820_SHARED_PAGE;
    nr_map++;

    /* For xenstore */
    e820entry[nr_map].addr = mem_size - 2*PAGE_SIZE;
    e820entry[nr_map].size = PAGE_SIZE;
    e820entry[nr_map].type = E820_XENSTORE;
    nr_map++;

    e820entry[nr_map].addr = mem_size;
    e820entry[nr_map].size = 0x3 * PAGE_SIZE;
    e820entry[nr_map].type = E820_NVS;
    nr_map++;

    e820entry[nr_map].addr = mem_size + 0x3 * PAGE_SIZE;
    e820entry[nr_map].size = 0xA * PAGE_SIZE;
    e820entry[nr_map].type = E820_ACPI;
    nr_map++;

    e820entry[nr_map].addr = 0xFEC00000;
    e820entry[nr_map].size = 0x1400000;
    e820entry[nr_map].type = E820_IO;
    nr_map++;

    return (*(((unsigned char *)e820_page) + E820_MAP_NR_OFFSET) = nr_map);
}

/*
 * Use E820 reserved memory 0x9F800 to pass number of vcpus to vmxloader
 * vmxloader will use it to config ACPI MADT table
 */
#define VCPU_MAGIC      0x76637075  /* "vcpu" */
static int set_vcpu_nr(int xc_handle, uint32_t dom,
                        unsigned long *pfn_list, unsigned int vcpus)
{
    char         *va_map;
    unsigned int *va_vcpus;

    va_map = xc_map_foreign_range(xc_handle, dom,
                                  PAGE_SIZE, PROT_READ|PROT_WRITE,
                                  pfn_list[VCPU_NR_PAGE >> PAGE_SHIFT]);
    if ( va_map == NULL )
        return -1;

    va_vcpus = (unsigned int *)(va_map + VCPU_NR_OFFSET);
    va_vcpus[0] = VCPU_MAGIC;
    va_vcpus[1] = vcpus;

    munmap(va_map, PAGE_SIZE);

    return 0;
}

#ifdef __i386__
static int zap_mmio_range(int xc_handle, uint32_t dom,
                          l2_pgentry_32_t *vl2tab,
                          unsigned long mmio_range_start,
                          unsigned long mmio_range_size)
{
    unsigned long mmio_addr;
    unsigned long mmio_range_end = mmio_range_start + mmio_range_size;
    unsigned long vl2e;
    l1_pgentry_32_t *vl1tab;

    mmio_addr = mmio_range_start & PAGE_MASK;
    for (; mmio_addr < mmio_range_end; mmio_addr += PAGE_SIZE) {
        vl2e = vl2tab[l2_table_offset(mmio_addr)];
        if (vl2e == 0)
            continue;
        vl1tab = xc_map_foreign_range(
            xc_handle, dom, PAGE_SIZE,
            PROT_READ|PROT_WRITE, vl2e >> PAGE_SHIFT);
        if ( vl1tab == 0 )
        {
            PERROR("Failed zap MMIO range");
            return -1;
        }
        vl1tab[l1_table_offset(mmio_addr)] = 0;
        munmap(vl1tab, PAGE_SIZE);
    }
    return 0;
}

static int zap_mmio_ranges(int xc_handle, uint32_t dom, unsigned long l2tab,
                           unsigned char e820_map_nr, unsigned char *e820map)
{
    unsigned int i;
    struct e820entry *e820entry = (struct e820entry *)e820map;

    l2_pgentry_32_t *vl2tab = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                                   PROT_READ|PROT_WRITE,
                                                   l2tab >> PAGE_SHIFT);
    if ( vl2tab == 0 )
        return -1;

    for ( i = 0; i < e820_map_nr; i++ )
    {
        if ( (e820entry[i].type == E820_IO) &&
             (zap_mmio_range(xc_handle, dom, vl2tab,
                             e820entry[i].addr, e820entry[i].size) == -1))
            return -1;
    }

    munmap(vl2tab, PAGE_SIZE);
    return 0;
}
#else
static int zap_mmio_range(int xc_handle, uint32_t dom,
                          l3_pgentry_t *vl3tab,
                          unsigned long mmio_range_start,
                          unsigned long mmio_range_size)
{
    unsigned long mmio_addr;
    unsigned long mmio_range_end = mmio_range_start + mmio_range_size;
    unsigned long vl2e = 0;
    unsigned long vl3e;
    l1_pgentry_t *vl1tab;
    l2_pgentry_t *vl2tab;

    mmio_addr = mmio_range_start & PAGE_MASK;
    for ( ; mmio_addr < mmio_range_end; mmio_addr += PAGE_SIZE )
    {
        vl3e = vl3tab[l3_table_offset(mmio_addr)];
        if ( vl3e == 0 )
            continue;

        vl2tab = xc_map_foreign_range(
            xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE, vl3e>>PAGE_SHIFT);
        if ( vl2tab == NULL )
        {
            PERROR("Failed zap MMIO range");
            return -1;
        }

        vl2e = vl2tab[l2_table_offset(mmio_addr)];
        if ( vl2e == 0 )
        {
            munmap(vl2tab, PAGE_SIZE);
            continue;
        }

        vl1tab = xc_map_foreign_range(
            xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE, vl2e>>PAGE_SHIFT);
        if ( vl1tab == NULL )
        {
            PERROR("Failed zap MMIO range");
            munmap(vl2tab, PAGE_SIZE);
            return -1;
        }

        vl1tab[l1_table_offset(mmio_addr)] = 0;
        munmap(vl2tab, PAGE_SIZE);
        munmap(vl1tab, PAGE_SIZE);
    }
    return 0;
}

static int zap_mmio_ranges(int xc_handle, uint32_t dom, unsigned long l3tab,
                           unsigned char e820_map_nr, unsigned char *e820map)
{
    unsigned int i;
    struct e820entry *e820entry = (struct e820entry *)e820map;

    l3_pgentry_t *vl3tab = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                                PROT_READ|PROT_WRITE,
                                                l3tab >> PAGE_SHIFT);
    if (vl3tab == 0)
        return -1;
    for ( i = 0; i < e820_map_nr; i++ ) {
        if ( (e820entry[i].type == E820_IO) &&
             (zap_mmio_range(xc_handle, dom, vl3tab,
                             e820entry[i].addr, e820entry[i].size) == -1) )
            return -1;
    }
    munmap(vl3tab, PAGE_SIZE);
    return 0;
}

#endif

static int setup_guest(int xc_handle,
                       uint32_t dom, int memsize,
                       char *image, unsigned long image_size,
                       unsigned long nr_pages,
                       vcpu_guest_context_t *ctxt,
                       unsigned long shared_info_frame,
                       unsigned int control_evtchn,
                       unsigned int lapic,
                       unsigned int vcpus,
                       unsigned int store_evtchn,
                       unsigned long *store_mfn)
{
    l1_pgentry_t *vl1tab=NULL, *vl1e=NULL;
    l2_pgentry_t *vl2tab=NULL, *vl2e=NULL;
    unsigned long *page_array = NULL;
#ifdef __x86_64__
    l3_pgentry_t *vl3tab=NULL, *vl3e=NULL;
    unsigned long l3tab;
#endif
    unsigned long l2tab;
    unsigned long l1tab;
    unsigned long count, i;
    shared_info_t *shared_info;
    void *e820_page;
    unsigned char e820_map_nr;
    xc_mmu_t *mmu = NULL;
    int rc;

    unsigned long nr_pt_pages;
    unsigned long ppt_alloc;

    struct domain_setup_info dsi;
    unsigned long vpt_start;
    unsigned long vpt_end;
    unsigned long v_end;

    unsigned long shared_page_frame = 0;
    shared_iopage_t *sp;

    memset(&dsi, 0, sizeof(struct domain_setup_info));

    if ( (rc = parseelfimage(image, image_size, &dsi)) != 0 )
        goto error_out;

    if ( (dsi.v_start & (PAGE_SIZE-1)) != 0 )
    {
        PERROR("Guest OS must load to a page boundary.\n");
        goto error_out;
    }

    /* memsize is in megabytes */
    v_end              = memsize << 20;

#ifdef __i386__
    nr_pt_pages = 1 + ((memsize + 3) >> 2);
#else
    nr_pt_pages = 5 + ((memsize + 1) >> 1);
#endif
    vpt_start   = v_end;
    vpt_end     = vpt_start + (nr_pt_pages * PAGE_SIZE);

    printf("VIRTUAL MEMORY ARRANGEMENT:\n"
           " Loaded VMX loader: %08lx->%08lx\n"
           " Page tables:   %08lx->%08lx\n"
           " TOTAL:         %08lx->%08lx\n",
           dsi.v_kernstart, dsi.v_kernend,
           vpt_start, vpt_end,
           dsi.v_start, v_end);
    printf(" ENTRY ADDRESS: %08lx\n", dsi.v_kernentry);

    if ( (v_end - dsi.v_start) > (nr_pages * PAGE_SIZE) )
    {
        ERROR("Initial guest OS requires too much space\n"
               "(%luMB is greater than %luMB limit)\n",
               (v_end-dsi.v_start)>>20, (nr_pages<<PAGE_SHIFT)>>20);
        goto error_out;
    }

    if ( (page_array = malloc(nr_pages * sizeof(unsigned long))) == NULL )
    {
        PERROR("Could not allocate memory");
        goto error_out;
    }

    if ( xc_get_pfn_list(xc_handle, dom, page_array, nr_pages) != nr_pages )
    {
        PERROR("Could not get the page frame list");
        goto error_out;
    }

    loadelfimage(image, xc_handle, dom, page_array, &dsi);

    if ( (mmu = xc_init_mmu_updates(xc_handle, dom)) == NULL )
        goto error_out;

    /* First allocate page for page dir or pdpt */
    ppt_alloc = vpt_start >> PAGE_SHIFT;
    if ( page_array[ppt_alloc] > 0xfffff )
    {
        unsigned long nmfn;
        nmfn = xc_make_page_below_4G( xc_handle, dom, page_array[ppt_alloc] );
        if ( nmfn == 0 )
        {
            fprintf(stderr, "Couldn't get a page below 4GB :-(\n");
            goto error_out;
        }
        page_array[ppt_alloc] = nmfn;
    }

#ifdef __i386__
    l2tab = page_array[ppt_alloc++] << PAGE_SHIFT;
    ctxt->ctrlreg[3] = l2tab;

    if ( (vl2tab = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                        PROT_READ|PROT_WRITE,
                                        l2tab >> PAGE_SHIFT)) == NULL )
        goto error_out;
    memset(vl2tab, 0, PAGE_SIZE);
    vl2e = &vl2tab[l2_table_offset(0)];
    for ( count = 0; count < (v_end >> PAGE_SHIFT); count++ )
    {
        if ( ((unsigned long)vl1e & (PAGE_SIZE-1)) == 0 )
        {
            l1tab = page_array[ppt_alloc++] << PAGE_SHIFT;
            if ( vl1tab != NULL )
                munmap(vl1tab, PAGE_SIZE);
            if ( (vl1tab = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                                PROT_READ|PROT_WRITE,
                                                l1tab >> PAGE_SHIFT)) == NULL )
            {
                munmap(vl2tab, PAGE_SIZE);
                goto error_out;
            }
            memset(vl1tab, 0, PAGE_SIZE);
            vl1e = &vl1tab[l1_table_offset(count << PAGE_SHIFT)];
            *vl2e++ = l1tab | L2_PROT;
        }

        *vl1e = (page_array[count] << PAGE_SHIFT) | L1_PROT;
        vl1e++;
    }
    munmap(vl1tab, PAGE_SIZE);
    munmap(vl2tab, PAGE_SIZE);
#else
    l3tab = page_array[ppt_alloc++] << PAGE_SHIFT;
    ctxt->ctrlreg[3] = l3tab;

    if ( (vl3tab = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                        PROT_READ|PROT_WRITE,
                                        l3tab >> PAGE_SHIFT)) == NULL )
        goto error_out;
    memset(vl3tab, 0, PAGE_SIZE);

    /* Fill in every PDPT entry. */
    for ( i = 0; i < L3_PAGETABLE_ENTRIES_PAE; i++ )
    {
        l2tab = page_array[ppt_alloc++] << PAGE_SHIFT;
        if ( (vl2tab = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                            PROT_READ|PROT_WRITE,
                                            l2tab >> PAGE_SHIFT)) == NULL )
            goto error_out;
        memset(vl2tab, 0, PAGE_SIZE);
        munmap(vl2tab, PAGE_SIZE);
        vl3tab[i] = l2tab | L3_PROT;
    }

    vl3e = &vl3tab[l3_table_offset(0)];
    for ( count = 0; count < (v_end >> PAGE_SHIFT); count++ )
    {
        if (!(count & (1 << (L3_PAGETABLE_SHIFT - L1_PAGETABLE_SHIFT)))){
            l2tab = vl3tab[count >> (L3_PAGETABLE_SHIFT - L1_PAGETABLE_SHIFT)]
                & PAGE_MASK;

            if (vl2tab != NULL)
                munmap(vl2tab, PAGE_SIZE);

            if ( (vl2tab = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                                PROT_READ|PROT_WRITE,
                                                l2tab >> PAGE_SHIFT)) == NULL )
                goto error_out;

            vl2e = &vl2tab[l2_table_offset(count << PAGE_SHIFT)];
        }
        if ( ((unsigned long)vl1e & (PAGE_SIZE-1)) == 0 )
        {
            l1tab = page_array[ppt_alloc++] << PAGE_SHIFT;
            if ( vl1tab != NULL )
                munmap(vl1tab, PAGE_SIZE);
            if ( (vl1tab = xc_map_foreign_range(xc_handle, dom, PAGE_SIZE,
                                                PROT_READ|PROT_WRITE,
                                                l1tab >> PAGE_SHIFT)) == NULL )
            {
                munmap(vl2tab, PAGE_SIZE);
                goto error_out;
            }
            memset(vl1tab, 0, PAGE_SIZE);
            vl1e = &vl1tab[l1_table_offset(count << PAGE_SHIFT)];
            *vl2e++ = l1tab | L2_PROT;
        }

        *vl1e = (page_array[count] << PAGE_SHIFT) | L1_PROT;
        vl1e++;
    }

    munmap(vl1tab, PAGE_SIZE);
    munmap(vl2tab, PAGE_SIZE);
    munmap(vl3tab, PAGE_SIZE);
#endif
    /* Write the machine->phys table entries. */
    for ( count = 0; count < nr_pages; count++ )
    {
        if ( xc_add_mmu_update(xc_handle, mmu,
                               (page_array[count] << PAGE_SHIFT) |
                               MMU_MACHPHYS_UPDATE, count) )
            goto error_out;
    }

    if (set_vcpu_nr(xc_handle, dom, page_array, vcpus)) {
        fprintf(stderr, "Couldn't set vcpu number for VMX guest.\n");
        goto error_out;
    }

    *store_mfn = page_array[(v_end-2) >> PAGE_SHIFT];
    shared_page_frame = (v_end - PAGE_SIZE) >> PAGE_SHIFT;

    if ((e820_page = xc_map_foreign_range(
        xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE,
        page_array[E820_MAP_PAGE >> PAGE_SHIFT])) == 0)
        goto error_out;
    memset(e820_page, 0, PAGE_SIZE);
    e820_map_nr = build_e820map(e820_page, v_end);
#if defined (__i386__)
    if (zap_mmio_ranges(xc_handle, dom, l2tab, e820_map_nr,
                        ((unsigned char *)e820_page) + E820_MAP_OFFSET) == -1)
#else
    if (zap_mmio_ranges(xc_handle, dom, l3tab, e820_map_nr,
                        ((unsigned char *)e820_page) + E820_MAP_OFFSET) == -1)
#endif
        goto error_out;
    munmap(e820_page, PAGE_SIZE);

    /* shared_info page starts its life empty. */
    if ((shared_info = xc_map_foreign_range(
        xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE,
        shared_info_frame)) == 0)
        goto error_out;
    memset(shared_info, 0, sizeof(shared_info_t));
    /* Mask all upcalls... */
    for ( i = 0; i < MAX_VIRT_CPUS; i++ )
        shared_info->vcpu_data[i].evtchn_upcall_mask = 1;

    munmap(shared_info, PAGE_SIZE);

    /* Populate the event channel port in the shared page */
    if ((sp = (shared_iopage_t *) xc_map_foreign_range(
        xc_handle, dom, PAGE_SIZE, PROT_READ|PROT_WRITE,
        page_array[shared_page_frame])) == 0)
        goto error_out;
    memset(sp, 0, PAGE_SIZE);
    sp->sp_global.eport = control_evtchn;
    munmap(sp, PAGE_SIZE);

    /* Send the page update requests down to the hypervisor. */
    if ( xc_finish_mmu_updates(xc_handle, mmu) )
        goto error_out;

    free(mmu);
    free(page_array);

    /*
     * Initial register values:
     */
    ctxt->user_regs.ds = 0;
    ctxt->user_regs.es = 0;
    ctxt->user_regs.fs = 0;
    ctxt->user_regs.gs = 0;
    ctxt->user_regs.ss = 0;
    ctxt->user_regs.cs = 0;
    ctxt->user_regs.eip = dsi.v_kernentry;
    ctxt->user_regs.edx = 0;
    ctxt->user_regs.eax = 0;
    ctxt->user_regs.esp = 0;
    ctxt->user_regs.ebx = 0; /* startup_32 expects this to be 0 to signal boot cpu */
    ctxt->user_regs.ecx = lapic;
    ctxt->user_regs.esi = 0;
    ctxt->user_regs.edi = 0;
    ctxt->user_regs.ebp = 0;

    ctxt->user_regs.eflags = 0;

    return 0;

 error_out:
    if ( mmu != NULL )
        free(mmu);
    if ( page_array != NULL )
        free(page_array);
    return -1;
}

#define VMX_FEATURE_FLAG 0x20

static int vmx_identify(void)
{
    int eax, ecx;

    __asm__ __volatile__ (
#if defined(__i386__)
                          "push %%ebx; cpuid; pop %%ebx"
#elif defined(__x86_64__)
                          "push %%rbx; cpuid; pop %%rbx"
#endif
                          : "=a" (eax), "=c" (ecx)
                          : "0" (1)
                          : "dx");

    if (!(ecx & VMX_FEATURE_FLAG)) {
        return -1;
    }

    return 0;
}

int xc_vmx_build(int xc_handle,
                 uint32_t domid,
                 int memsize,
                 const char *image_name,
                 unsigned int control_evtchn,
                 unsigned int lapic,
                 unsigned int vcpus,
                 unsigned int store_evtchn,
                 unsigned long *store_mfn)
{
    dom0_op_t launch_op, op;
    int rc, i;
    vcpu_guest_context_t st_ctxt, *ctxt = &st_ctxt;
    unsigned long nr_pages;
    char         *image = NULL;
    unsigned long image_size;

    if ( vmx_identify() < 0 )
    {
        PERROR("CPU doesn't support VMX Extensions");
        goto error_out;
    }

    if ( (nr_pages = xc_get_tot_pages(xc_handle, domid)) < 0 )
    {
        PERROR("Could not find total pages for domain");
        goto error_out;
    }

    if ( (image = xc_read_kernel_image(image_name, &image_size)) == NULL )
        goto error_out;

    if ( mlock(&st_ctxt, sizeof(st_ctxt) ) )
    {
        PERROR("%s: ctxt mlock failed", __func__);
        return 1;
    }

    op.cmd = DOM0_GETDOMAININFO;
    op.u.getdomaininfo.domain = (domid_t)domid;
    if ( (xc_dom0_op(xc_handle, &op) < 0) ||
         ((uint16_t)op.u.getdomaininfo.domain != domid) )
    {
        PERROR("Could not get info on domain");
        goto error_out;
    }

    if ( xc_domain_get_vcpu_context(xc_handle, domid, 0, ctxt) )
    {
        PERROR("Could not get vcpu context");
        goto error_out;
    }

    if ( !(op.u.getdomaininfo.flags & DOMFLAGS_PAUSED) ||
         (ctxt->ctrlreg[3] != 0) )
    {
        ERROR("Domain is already constructed");
        goto error_out;
    }

    if ( setup_guest(xc_handle, domid, memsize, image, image_size, nr_pages,
                     ctxt, op.u.getdomaininfo.shared_info_frame, control_evtchn,
                     lapic, vcpus, store_evtchn, store_mfn) < 0)
    {
        ERROR("Error constructing guest OS");
        goto error_out;
    }

    if ( image != NULL )
        free(image);

    ctxt->flags = VGCF_VMX_GUEST;
    /* FPU is set up to default initial state. */
    memset(&ctxt->fpu_ctxt, 0, sizeof(ctxt->fpu_ctxt));

    /* Virtual IDT is empty at start-of-day. */
    for ( i = 0; i < 256; i++ )
    {
        ctxt->trap_ctxt[i].vector = i;
        ctxt->trap_ctxt[i].cs     = FLAT_KERNEL_CS;
    }

    /* No LDT. */
    ctxt->ldt_ents = 0;

    /* Use the default Xen-provided GDT. */
    ctxt->gdt_ents = 0;

    /* No debugging. */
    memset(ctxt->debugreg, 0, sizeof(ctxt->debugreg));

    /* No callback handlers. */
#if defined(__i386__)
    ctxt->event_callback_cs     = FLAT_KERNEL_CS;
    ctxt->event_callback_eip    = 0;
    ctxt->failsafe_callback_cs  = FLAT_KERNEL_CS;
    ctxt->failsafe_callback_eip = 0;
#elif defined(__x86_64__)
    ctxt->event_callback_eip    = 0;
    ctxt->failsafe_callback_eip = 0;
    ctxt->syscall_callback_eip  = 0;
#endif

    memset( &launch_op, 0, sizeof(launch_op) );

    launch_op.u.setdomaininfo.domain = (domid_t)domid;
    launch_op.u.setdomaininfo.vcpu   = 0;
    launch_op.u.setdomaininfo.ctxt   = ctxt;

    launch_op.cmd = DOM0_SETDOMAININFO;
    rc = xc_dom0_op(xc_handle, &launch_op);

    return rc;

 error_out:
    if ( image != NULL )
        free(image);

    return -1;
}

static inline int is_loadable_phdr(Elf32_Phdr *phdr)
{
    return ((phdr->p_type == PT_LOAD) &&
            ((phdr->p_flags & (PF_W|PF_X)) != 0));
}

static int parseelfimage(char *elfbase,
                         unsigned long elfsize,
                         struct domain_setup_info *dsi)
{
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elfbase;
    Elf32_Phdr *phdr;
    Elf32_Shdr *shdr;
    unsigned long kernstart = ~0UL, kernend=0UL;
    char *shstrtab;
    int h;

    if ( !IS_ELF(*ehdr) )
    {
        ERROR("Kernel image does not have an ELF header.");
        return -EINVAL;
    }

    if ( (ehdr->e_phoff + (ehdr->e_phnum * ehdr->e_phentsize)) > elfsize )
    {
        ERROR("ELF program headers extend beyond end of image.");
        return -EINVAL;
    }

    if ( (ehdr->e_shoff + (ehdr->e_shnum * ehdr->e_shentsize)) > elfsize )
    {
        ERROR("ELF section headers extend beyond end of image.");
        return -EINVAL;
    }

    /* Find the section-header strings table. */
    if ( ehdr->e_shstrndx == SHN_UNDEF )
    {
        ERROR("ELF image has no section-header strings table (shstrtab).");
        return -EINVAL;
    }
    shdr = (Elf32_Shdr *)(elfbase + ehdr->e_shoff +
                          (ehdr->e_shstrndx*ehdr->e_shentsize));
    shstrtab = elfbase + shdr->sh_offset;

    for ( h = 0; h < ehdr->e_phnum; h++ )
    {
        phdr = (Elf32_Phdr *)(elfbase + ehdr->e_phoff + (h*ehdr->e_phentsize));
        if ( !is_loadable_phdr(phdr) )
            continue;
        if ( phdr->p_paddr < kernstart )
            kernstart = phdr->p_paddr;
        if ( (phdr->p_paddr + phdr->p_memsz) > kernend )
            kernend = phdr->p_paddr + phdr->p_memsz;
    }

    if ( (kernstart > kernend) ||
         (ehdr->e_entry < kernstart) ||
         (ehdr->e_entry > kernend) )
    {
        ERROR("Malformed ELF image.");
        return -EINVAL;
    }

    dsi->v_start = 0x00000000;

    dsi->v_kernstart = kernstart;
    dsi->v_kernend   = kernend;
    dsi->v_kernentry = VMX_LOADER_ENTR_ADDR;

    dsi->v_end       = dsi->v_kernend;

    return 0;
}

static int
loadelfimage(
    char *elfbase, int xch, uint32_t dom, unsigned long *parray,
    struct domain_setup_info *dsi)
{
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elfbase;
    Elf32_Phdr *phdr;
    int h;

    char         *va;
    unsigned long pa, done, chunksz;

    for ( h = 0; h < ehdr->e_phnum; h++ )
    {
        phdr = (Elf32_Phdr *)(elfbase + ehdr->e_phoff + (h*ehdr->e_phentsize));
        if ( !is_loadable_phdr(phdr) )
            continue;

        for ( done = 0; done < phdr->p_filesz; done += chunksz )
        {
            pa = (phdr->p_paddr + done) - dsi->v_start;
            if ((va = xc_map_foreign_range(
                xch, dom, PAGE_SIZE, PROT_WRITE,
                parray[pa >> PAGE_SHIFT])) == 0)
                return -1;
            chunksz = phdr->p_filesz - done;
            if ( chunksz > (PAGE_SIZE - (pa & (PAGE_SIZE-1))) )
                chunksz = PAGE_SIZE - (pa & (PAGE_SIZE-1));
            memcpy(va + (pa & (PAGE_SIZE-1)),
                   elfbase + phdr->p_offset + done, chunksz);
            munmap(va, PAGE_SIZE);
        }

        for ( ; done < phdr->p_memsz; done += chunksz )
        {
            pa = (phdr->p_paddr + done) - dsi->v_start;
            if ((va = xc_map_foreign_range(
                xch, dom, PAGE_SIZE, PROT_WRITE,
                parray[pa >> PAGE_SHIFT])) == 0)
                return -1;
            chunksz = phdr->p_memsz - done;
            if ( chunksz > (PAGE_SIZE - (pa & (PAGE_SIZE-1))) )
                chunksz = PAGE_SIZE - (pa & (PAGE_SIZE-1));
            memset(va + (pa & (PAGE_SIZE-1)), 0, chunksz);
            munmap(va, PAGE_SIZE);
        }
    }

    return 0;
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
