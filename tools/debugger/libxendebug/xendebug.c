/*
 * xendebug.c
 *
 * alex ho
 * http://www.cl.cam.ac.uk/netos/pdb
 *
 * xendebug_memory_page adapted from xc_ptrace.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <xenctrl.h>
#include "list.h"

#if defined(__i386__)
#define L1_PAGETABLE_SHIFT       12
#define L2_PAGETABLE_SHIFT       22
#elif defined(__x86_64__)
#define L1_PAGETABLE_SHIFT      12
#define L2_PAGETABLE_SHIFT      21
#define L3_PAGETABLE_SHIFT      30
#define L4_PAGETABLE_SHIFT      39
#endif

#define PAGE_SHIFT L1_PAGETABLE_SHIFT
#define PAGE_SIZE  (1UL<<PAGE_SHIFT)
#define PAGE_MASK  (~(PAGE_SIZE - 1))

/* from xen/include/asm-x86/processor.h */
#define X86_EFLAGS_TF	0x00000100 /* Trap Flag */

typedef int boolean;
#define true 1
#define false 0


typedef struct bwcpoint                           /* break/watch/catch point */
{
    struct list_head list;
    unsigned long address;
    uint32_t domain;
    uint8_t old_value;                             /* old value for software bkpt */
} bwcpoint_t, *bwcpoint_p;

static bwcpoint_t bwcpoint_list;



typedef struct domain_context                 /* local cache of domain state */
{
    struct list_head     list;
    uint32_t                  domid;
    boolean              valid[MAX_VIRT_CPUS];
    vcpu_guest_context_t context[MAX_VIRT_CPUS];

    long            total_pages;
    unsigned long  *page_array;

    unsigned long   cr3_phys[MAX_VIRT_CPUS];
    unsigned long  *cr3_virt[MAX_VIRT_CPUS];
    unsigned long   pde_phys[MAX_VIRT_CPUS];     
    unsigned long  *pde_virt[MAX_VIRT_CPUS];
    unsigned long   page_phys[MAX_VIRT_CPUS];     
    unsigned long  *page_virt[MAX_VIRT_CPUS];
    int             page_perm[MAX_VIRT_CPUS];
} domain_context_t, *domain_context_p;

static domain_context_t domain_context_list;

/* initialization */

static boolean xendebug_initialized = false;

static __inline__ void
xendebug_initialize()
{
    if ( !xendebug_initialized )
    {
        memset((void *) &domain_context_list, 0, sizeof(domain_context_t));
        INIT_LIST_HEAD(&domain_context_list.list);

        memset((void *) &bwcpoint_list, 0, sizeof(bwcpoint_t));
        INIT_LIST_HEAD(&bwcpoint_list.list);

        xendebug_initialized = true;
    }
}

/**************/

static domain_context_p
xendebug_domain_context_search (uint32_t domid)
{
    struct list_head *entry;
    domain_context_p  ctxt;

    list_for_each(entry, &domain_context_list.list)
    {
        ctxt = list_entry(entry, domain_context_t, list);
        if ( domid == ctxt->domid )
            return ctxt;
    }
    return (domain_context_p)NULL;
}

static __inline__ domain_context_p
xendebug_get_context (int xc_handle, uint32_t domid, uint32_t vcpu)
{
    int rc;
    domain_context_p ctxt;

    xendebug_initialize();

    if ( (ctxt = xendebug_domain_context_search(domid)) == NULL)
        return NULL;

    if ( !ctxt->valid[vcpu] )
    {
        if ( (rc = xc_vcpu_getcontext(xc_handle, domid, vcpu, 
                                      &ctxt->context[vcpu])) )
            return NULL;

        ctxt->valid[vcpu] = true;
    }

    return ctxt;
}

static __inline__ int
xendebug_set_context (int xc_handle, domain_context_p ctxt, uint32_t vcpu)
{
    dom0_op_t op;
    int rc;

    if ( !ctxt->valid[vcpu] )
        return -EINVAL;

    op.interface_version = DOM0_INTERFACE_VERSION;
    op.cmd = DOM0_SETVCPUCONTEXT;
    op.u.setvcpucontext.domain = ctxt->domid;
    op.u.setvcpucontext.vcpu = vcpu;
    op.u.setvcpucontext.ctxt = &ctxt->context[vcpu];

    if ( (rc = mlock(&ctxt->context[vcpu], sizeof(vcpu_guest_context_t))) )
        return rc;

    rc = xc_dom0_op(xc_handle, &op);
    (void) munlock(&ctxt->context[vcpu], sizeof(vcpu_guest_context_t));

    return rc;
}

/**************/

int
xendebug_attach(int xc_handle,
                uint32_t domid,
                uint32_t vcpu)
{
    domain_context_p ctxt;

    xendebug_initialize();

    if ( (ctxt = malloc(sizeof(domain_context_t))) == NULL )
        return -1;
    memset(ctxt, 0, sizeof(domain_context_t));
    
    ctxt->domid = domid;
    list_add(&ctxt->list, &domain_context_list.list);

    return xc_domain_pause(xc_handle, domid);
}

int
xendebug_detach(int xc_handle,
                uint32_t domid,
                uint32_t vcpu)
{
    domain_context_p ctxt;
    
    xendebug_initialize();

    if ( (ctxt = xendebug_domain_context_search (domid)) == NULL)
        return -EINVAL;

    list_del(&ctxt->list);

    if ( ctxt->page_array ) free(ctxt->page_array);

    free(ctxt);

    return xc_domain_unpause(xc_handle, domid);
}

int
xendebug_read_registers(int xc_handle,
                        uint32_t domid,
                        uint32_t vcpu,
                        cpu_user_regs_t **regs)
{
    domain_context_p ctxt;
    int rc = -1;

    xendebug_initialize();

    ctxt = xendebug_get_context(xc_handle, domid, vcpu);
    if (ctxt)
    {
        *regs = &ctxt->context[vcpu].user_regs;
        rc = 0;
    }

    return rc;
}

int
xendebug_read_fpregisters (int xc_handle,
                           uint32_t domid,
                           uint32_t vcpu,
                           char **regs)
{
    domain_context_p ctxt;
    int rc = -1;

    xendebug_initialize();

    ctxt = xendebug_get_context(xc_handle, domid, vcpu);
    if (ctxt)
    {
        *regs = ctxt->context[vcpu].fpu_ctxt.x;
        rc = 0;
    }

    return rc;
}

int
xendebug_write_registers(int xc_handle,
                         uint32_t domid,
                         uint32_t vcpu,
                         cpu_user_regs_t *regs)
{
    domain_context_p ctxt;
    int rc = -1;

    xendebug_initialize();

    ctxt = xendebug_get_context(xc_handle, domid, vcpu);
    if (ctxt)
    {
        memcpy(&ctxt->context[vcpu].user_regs, regs, sizeof(cpu_user_regs_t));
        rc = xendebug_set_context(xc_handle, ctxt, vcpu);
    }
    
    return rc;
}

int
xendebug_step(int xc_handle,
              uint32_t domid,
              uint32_t vcpu)
{
    domain_context_p ctxt;
    int rc;

    xendebug_initialize();

    ctxt = xendebug_get_context(xc_handle, domid, vcpu);
    if (!ctxt) return -EINVAL;

    ctxt->context[vcpu].user_regs.eflags |= X86_EFLAGS_TF;

    if ( (rc = xendebug_set_context(xc_handle, ctxt, vcpu)) )
        return rc;

    ctxt->valid[vcpu] = false;
    return xc_domain_unpause(xc_handle, domid);
}

int
xendebug_continue(int xc_handle,
                  uint32_t domid,
                  uint32_t vcpu)
{
    domain_context_p ctxt;
    int rc;

    xendebug_initialize();

    ctxt = xendebug_get_context(xc_handle, domid, vcpu);
    if (!ctxt) return -EINVAL;

    if ( ctxt->context[vcpu].user_regs.eflags & X86_EFLAGS_TF )
    {
        ctxt->context[vcpu].user_regs.eflags &= ~X86_EFLAGS_TF;
        if ( (rc = xendebug_set_context(xc_handle, ctxt, vcpu)) )
            return rc;
    }
    ctxt->valid[vcpu] = false;
    return xc_domain_unpause(xc_handle, domid);
}

/*************************************************/

#define vtopdi(va) ((va) >> L2_PAGETABLE_SHIFT)
#define vtopti(va) (((va) >> PAGE_SHIFT) & 0x3ff)

/* access to one page */
static int
xendebug_memory_page (domain_context_p ctxt, int xc_handle, uint32_t vcpu,
                      int protection, unsigned long address, int length, uint8_t *buffer)
{
    vcpu_guest_context_t *vcpu_ctxt = &ctxt->context[vcpu];
    unsigned long pde, page;
    unsigned long va = (unsigned long)address;
    void *ptr;
    long pages;

    pages = xc_get_tot_pages(xc_handle, ctxt->domid);

    if ( ctxt->total_pages != pages )
    {
        if ( ctxt->total_pages > 0 ) free( ctxt->page_array );
        ctxt->total_pages = pages;

        ctxt->page_array = malloc(pages * sizeof(unsigned long));
        if ( ctxt->page_array == NULL )
        {
            printf("Could not allocate memory\n");
            return 0;
        }

        if ( xc_get_pfn_list(xc_handle, ctxt->domid, ctxt->page_array,pages) !=
                pages )
        {
            printf("Could not get the page frame list\n");
            return 0;
        }
    }

    if ( vcpu_ctxt->ctrlreg[3] != ctxt->cr3_phys[vcpu]) 
    {
        ctxt->cr3_phys[vcpu] = vcpu_ctxt->ctrlreg[3];
        if ( ctxt->cr3_virt[vcpu] )
            munmap(ctxt->cr3_virt[vcpu], PAGE_SIZE);
        ctxt->cr3_virt[vcpu] = xc_map_foreign_range(xc_handle, ctxt->domid,
                    PAGE_SIZE, PROT_READ, ctxt->cr3_phys[vcpu] >> PAGE_SHIFT);
        if ( ctxt->cr3_virt[vcpu] == NULL )
            return 0;
    } 


    if ( (pde = ctxt->cr3_virt[vcpu][vtopdi(va)]) == 0) /* logical address */
        return 0;
    if (ctxt->context[vcpu].flags & VGCF_VMX_GUEST)
        pde = ctxt->page_array[pde >> PAGE_SHIFT] << PAGE_SHIFT;
    if (pde != ctxt->pde_phys[vcpu]) 
    {
        ctxt->pde_phys[vcpu] = pde;
        if ( ctxt->pde_virt[vcpu])
            munmap(ctxt->pde_virt[vcpu], PAGE_SIZE);
        ctxt->pde_virt[vcpu] = xc_map_foreign_range(xc_handle, ctxt->domid,
                    PAGE_SIZE, PROT_READ, ctxt->pde_phys[vcpu] >> PAGE_SHIFT);
        if ( ctxt->pde_virt[vcpu] == NULL )
            return 0;
    }

    if ((page = ctxt->pde_virt[vcpu][vtopti(va)]) == 0) /* logical address */
        return 0;
    if (ctxt->context[vcpu].flags & VGCF_VMX_GUEST)
        page = ctxt->page_array[page >> PAGE_SHIFT] << PAGE_SHIFT;
    if (page != ctxt->page_phys[vcpu] || protection != ctxt->page_perm[vcpu]) 
    {
        ctxt->page_phys[vcpu] = page;
        if (ctxt->page_virt[vcpu])
            munmap(ctxt->page_virt[vcpu], PAGE_SIZE);
        ctxt->page_virt[vcpu] = xc_map_foreign_range(xc_handle, ctxt->domid, 
                  PAGE_SIZE, protection, ctxt->page_phys[vcpu] >> PAGE_SHIFT);
        if ( ctxt->page_virt[vcpu] == NULL )
        {
            printf("cr3 %lx pde %lx page %lx pti %lx\n", 
                   vcpu_ctxt->ctrlreg[3], pde, page, vtopti(va));
            ctxt->page_phys[vcpu] = 0;
            return 0;
        }
        ctxt->page_perm[vcpu] = protection;
    }	

    ptr = (void *)( (unsigned long)ctxt->page_virt[vcpu] |
                    (va & ~PAGE_MASK) );

    if ( protection & PROT_WRITE )
    {
        memcpy(ptr, buffer, length);
    }
    else
    {
        memcpy(buffer, ptr, length);
    }

    return length;
}

/* divide a memory operation into accesses to individual pages */
static int
xendebug_memory_op (domain_context_p ctxt, int xc_handle, uint32_t vcpu,
                    int protection, unsigned long address, int length, uint8_t *buffer)
{
    int      remain;              /* number of bytes to touch past this page */
    int      bytes   = 0;

    while ( (remain = (address + length - 1) - (address | (PAGE_SIZE-1))) > 0)
    {
        bytes += xendebug_memory_page(ctxt, xc_handle, vcpu, protection,
                                      address, length - remain, buffer);
        buffer += (length - remain);
        length = remain;
        address = (address | (PAGE_SIZE - 1)) + 1;
    }

    bytes += xendebug_memory_page(ctxt, xc_handle, vcpu, protection,
                                  address, length, buffer);

    return bytes;
}

int
xendebug_read_memory(int xc_handle,
                     uint32_t domid,
                     uint32_t vcpu,
                     unsigned long address,
                     uint32_t length,
                     uint8_t *data)
{
    domain_context_p ctxt;

    xendebug_initialize();

    ctxt = xendebug_get_context(xc_handle, domid, vcpu);

    xendebug_memory_op(ctxt, xc_handle, vcpu, PROT_READ, 
                       address, length, data);

    return 0;
}

int
xendebug_write_memory(int xc_handle,
                      uint32_t domid,
                      uint32_t vcpu,
                      unsigned long address,
                      uint32_t length,
                      uint8_t *data)
{
    domain_context_p ctxt;

    xendebug_initialize();

    ctxt = xendebug_get_context(xc_handle, domid, vcpu);
    xendebug_memory_op(ctxt, xc_handle, vcpu, PROT_READ | PROT_WRITE,

                       address, length, data);

    return 0;
}

int
xendebug_insert_memory_breakpoint(int xc_handle,
                                  uint32_t domid,
                                  uint32_t vcpu,
                                  unsigned long address,
                                  uint32_t length)
{
    bwcpoint_p bkpt;
    uint8_t breakpoint_opcode = 0xcc;

    printf("insert breakpoint %d:%lx %d\n",
            domid, address, length);

    xendebug_initialize();

    bkpt = malloc(sizeof(bwcpoint_t));
    if ( bkpt == NULL )
    {
        printf("error: breakpoint length should be 1\n");
        return -1;
    }

    if ( length != 1 )
    {
        printf("error: breakpoint length should be 1\n");
        free(bkpt);
        return -1;
    }

    bkpt->address = address;
    bkpt->domain  = domid;

    xendebug_read_memory(xc_handle, domid, vcpu, address, 1,
                         &bkpt->old_value);

    xendebug_write_memory(xc_handle, domid, vcpu, address, 1, 
                          &breakpoint_opcode);
    
    list_add(&bkpt->list, &bwcpoint_list.list);

    printf("breakpoint_set %d:%lx 0x%x\n",
           domid, address, bkpt->old_value);

    return 0;
}

int
xendebug_remove_memory_breakpoint(int xc_handle,
                                  uint32_t domid,
                                  uint32_t vcpu,
                                  unsigned long address,
                                  uint32_t length)
{
    bwcpoint_p bkpt = NULL;

    printf ("remove breakpoint %d:%lx\n",
            domid, address);

    struct list_head *entry;
    list_for_each(entry, &bwcpoint_list.list)
    {
        bkpt = list_entry(entry, bwcpoint_t, list);
        if ( domid == bkpt->domain && address == bkpt->address )
            break;
    }
    
    if (bkpt == &bwcpoint_list || bkpt == NULL)
    {
        printf ("error: no breakpoint found\n");
        return -1;
    }

    list_del(&bkpt->list);

    xendebug_write_memory(xc_handle, domid, vcpu, address, 1, 
                          &bkpt->old_value);

    free(bkpt);
    return 0;
}

int
xendebug_query_domain_stop(int xc_handle, int *dom_list, int dom_list_size)
{
    xc_dominfo_t *info;
    uint32_t first_dom = 0;
    int max_doms = 1024;
    int nr_doms, loop;
    int count = 0;

    if ( (info = malloc(max_doms * sizeof(xc_dominfo_t))) == NULL )
        return -ENOMEM;

    nr_doms = xc_domain_getinfo(xc_handle, first_dom, max_doms, info);

    for (loop = 0; loop < nr_doms; loop++)
    {
        printf ("domid: %d", info[loop].domid);
        printf (" %c%c%c%c%c%c",
                info[loop].dying ? 'D' : '-',
                info[loop].crashed ? 'C' : '-',
                info[loop].shutdown ? 'S' : '-',
                info[loop].paused ? 'P' : '-',
                info[loop].blocked ? 'B' : '-',
                info[loop].running ? 'R' : '-');
        printf (" pages: %ld, vcpus %d", 
                info[loop].nr_pages, info[loop].vcpus);
        printf ("\n");

        if ( info[loop].paused && count < dom_list_size)
        {
            dom_list[count++] = info[loop].domid;
        }
    }

    free(info);

    return count;
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
