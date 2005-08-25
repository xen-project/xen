/******************************************************************************
 * blktap_userdev.c
 * 
 * XenLinux virtual block-device tap.
 * Control interface between the driver and a character device.
 * 
 * Copyright (c) 2004, Andrew Warfield
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/gfp.h>
#include <linux/poll.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm-xen/xen-public/io/blkif.h> /* for control ring. */
#ifdef CONFIG_XEN_BLKDEV_GRANT
#include <asm-xen/xen-public/grant_table.h>
#endif

#include "blktap.h"


unsigned long blktap_mode = BLKTAP_MODE_PASSTHROUGH;

/* Only one process may open /dev/xen/blktap at any time. */
static unsigned long blktap_dev_inuse;
unsigned long blktap_ring_ok; /* make this ring->state */

/* for poll: */
static wait_queue_head_t blktap_wait;

/* Rings up to user space. */
static blkif_front_ring_t blktap_ufe_ring;
static blkif_back_ring_t  blktap_ube_ring;
static ctrl_front_ring_t  blktap_uctrl_ring;

/* local prototypes */
static int blktap_read_fe_ring(void);
static int blktap_read_be_ring(void);


/* -------[ mmap region ]--------------------------------------------- */
/*
 * We use a big chunk of address space to map in-flight requests into,
 * and export this region up to user-space.  See the comments in blkback
 * about this -- the two must be kept in sync if the tap is used as a 
 * passthrough.
 */

#define MAX_PENDING_REQS 64

/* immediately before the mmap area, we have a bunch of pages reserved
 * for shared memory rings.
 */
#define RING_PAGES 3 /* Ctrl, Front, and Back */ 

/* Where things are inside the device mapping. */
struct vm_area_struct *blktap_vma = NULL;
unsigned long mmap_vstart;  /* Kernel pages for mapping in data. */
unsigned long rings_vstart; /* start of mmaped vma               */
unsigned long user_vstart;  /* start of user mappings            */

#define MMAP_PAGES_PER_REQUEST \
    (BLKIF_MAX_SEGMENTS_PER_REQUEST + 1)
#define MMAP_PAGES             \
    (MAX_PENDING_REQS * MMAP_PAGES_PER_REQUEST)
#define MMAP_VADDR(_start, _req,_seg)                \
    ( _start +                                       \
     ((_req) * MMAP_PAGES_PER_REQUEST * PAGE_SIZE) + \
     ((_seg) * PAGE_SIZE))

/* -------[ grant handles ]------------------------------------------- */

#ifdef CONFIG_XEN_BLKDEV_GRANT
/* When using grant tables to map a frame for device access then the
 * handle returned must be used to unmap the frame. This is needed to
 * drop the ref count on the frame.
 */
struct grant_handle_pair
{
    u16  kernel;
    u16  user;
};
static struct grant_handle_pair pending_grant_handles[MMAP_PAGES];
#define pending_handle(_idx, _i) \
    (pending_grant_handles[((_idx) * BLKIF_MAX_SEGMENTS_PER_REQUEST) + (_i)])
#define BLKTAP_INVALID_HANDLE(_g) \
    (((_g->kernel) == 0xFFFF) && ((_g->user) == 0xFFFF))
#define BLKTAP_INVALIDATE_HANDLE(_g) do {       \
    (_g)->kernel = 0xFFFF; (_g)->user = 0xFFFF; \
    } while(0)
    
#endif


/* -------[ blktap vm ops ]------------------------------------------- */

static struct page *blktap_nopage(struct vm_area_struct *vma,
                                             unsigned long address,
                                             int *type)
{
    /*
     * if the page has not been mapped in by the driver then generate
     * a SIGBUS to the domain.
     */

    force_sig(SIGBUS, current);

    return 0;
}

struct vm_operations_struct blktap_vm_ops = {
    nopage:   blktap_nopage,
};

/* -------[ blktap file ops ]----------------------------------------- */

static int blktap_open(struct inode *inode, struct file *filp)
{
    blkif_sring_t *sring;
    ctrl_sring_t *csring;
    
    if ( test_and_set_bit(0, &blktap_dev_inuse) )
        return -EBUSY;
    
    /* Allocate the ctrl ring. */
    csring = (ctrl_sring_t *)get_zeroed_page(GFP_KERNEL);
    if (csring == NULL)
        goto fail_nomem;

    SetPageReserved(virt_to_page(csring));
    
    SHARED_RING_INIT(csring);
    FRONT_RING_INIT(&blktap_uctrl_ring, csring, PAGE_SIZE);

    /* Allocate the fe ring. */
    sring = (blkif_sring_t *)get_zeroed_page(GFP_KERNEL);
    if (sring == NULL)
        goto fail_free_ctrl;

    SetPageReserved(virt_to_page(sring));
    
    SHARED_RING_INIT(sring);
    FRONT_RING_INIT(&blktap_ufe_ring, sring, PAGE_SIZE);

    /* Allocate the be ring. */
    sring = (blkif_sring_t *)get_zeroed_page(GFP_KERNEL);
    if (sring == NULL)
        goto fail_free_fe;

    SetPageReserved(virt_to_page(sring));
    
    SHARED_RING_INIT(sring);
    BACK_RING_INIT(&blktap_ube_ring, sring, PAGE_SIZE);

    DPRINTK(KERN_ALERT "blktap open.\n");

    return 0;
    
 fail_free_ctrl:
    free_page( (unsigned long) blktap_uctrl_ring.sring);

 fail_free_fe:
    free_page( (unsigned long) blktap_ufe_ring.sring);

 fail_nomem:
    return -ENOMEM;
}

static int blktap_release(struct inode *inode, struct file *filp)
{
    blktap_dev_inuse = 0;
    blktap_ring_ok = 0;

    DPRINTK(KERN_ALERT "blktap closed.\n");

    /* Free the ring page. */
    ClearPageReserved(virt_to_page(blktap_uctrl_ring.sring));
    free_page((unsigned long) blktap_uctrl_ring.sring);

    ClearPageReserved(virt_to_page(blktap_ufe_ring.sring));
    free_page((unsigned long) blktap_ufe_ring.sring);

    ClearPageReserved(virt_to_page(blktap_ube_ring.sring));
    free_page((unsigned long) blktap_ube_ring.sring);

    /* Clear any active mappings and free foreign map table */
    if (blktap_vma != NULL) {
        zap_page_range(blktap_vma, blktap_vma->vm_start, 
                       blktap_vma->vm_end - blktap_vma->vm_start, NULL);
        blktap_vma = NULL;
    }

    return 0;
}

/* Note on mmap:
 * We need to map pages to user space in a way that will allow the block
 * subsystem set up direct IO to them.  This couldn't be done before, because
 * there isn't really a sane way to make a user virtual address down to a 
 * physical address when the page belongs to another domain.
 *
 * My first approach was to map the page in to kernel memory, add an entry
 * for it in the physical frame list (using alloc_lomem_region as in blkback)
 * and then attempt to map that page up to user space.  This is disallowed
 * by xen though, which realizes that we don't really own the machine frame
 * underlying the physical page.
 *
 * The new approach is to provide explicit support for this in xen linux.
 * The VMA now has a flag, VM_FOREIGN, to indicate that it contains pages
 * mapped from other vms.  vma->vm_private_data is set up as a mapping 
 * from pages to actual page structs.  There is a new clause in get_user_pages
 * that does the right thing for this sort of mapping.
 * 
 * blktap_mmap sets up this mapping.  Most of the real work is done in
 * blktap_write_fe_ring below.
 */
static int blktap_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int size;
    struct page **map;
    int i;

    DPRINTK(KERN_ALERT "blktap mmap (%lx, %lx)\n",
           vma->vm_start, vma->vm_end);

    vma->vm_flags |= VM_RESERVED;
    vma->vm_ops = &blktap_vm_ops;

    size = vma->vm_end - vma->vm_start;
    if ( size != ( (MMAP_PAGES + RING_PAGES) << PAGE_SHIFT ) ) {
        printk(KERN_INFO 
               "blktap: you _must_ map exactly %d pages!\n",
               MMAP_PAGES + RING_PAGES);
        return -EAGAIN;
    }

    size >>= PAGE_SHIFT;
    DPRINTK(KERN_INFO "blktap: 2 rings + %d pages.\n", size-1);
    
    rings_vstart = vma->vm_start;
    user_vstart  = rings_vstart + (RING_PAGES << PAGE_SHIFT);
    
    /* Map the ring pages to the start of the region and reserve it. */

    /* not sure if I really need to do this... */
    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

    DPRINTK("Mapping ctrl_ring page %lx.\n", __pa(blktap_uctrl_ring.sring));
    if (remap_pfn_range(vma, vma->vm_start, 
                         __pa(blktap_uctrl_ring.sring) >> PAGE_SHIFT, 
                         PAGE_SIZE, vma->vm_page_prot)) 
        goto fail;


    DPRINTK("Mapping be_ring page %lx.\n", __pa(blktap_ube_ring.sring));
    if (remap_pfn_range(vma, vma->vm_start + PAGE_SIZE, 
                         __pa(blktap_ube_ring.sring) >> PAGE_SHIFT, 
                         PAGE_SIZE, vma->vm_page_prot)) 
        goto fail;

    DPRINTK("Mapping fe_ring page %lx.\n", __pa(blktap_ufe_ring.sring));
    if (remap_pfn_range(vma, vma->vm_start + ( 2 * PAGE_SIZE ), 
                         __pa(blktap_ufe_ring.sring) >> PAGE_SHIFT, 
                         PAGE_SIZE, vma->vm_page_prot)) 
        goto fail;

    /* Mark this VM as containing foreign pages, and set up mappings. */
    map = kmalloc(((vma->vm_end - vma->vm_start) >> PAGE_SHIFT)
                  * sizeof(struct page_struct*),
                  GFP_KERNEL);
    if (map == NULL) goto fail;

    for (i=0; i<((vma->vm_end - vma->vm_start) >> PAGE_SHIFT); i++)
        map[i] = NULL;
    
    vma->vm_private_data = map;
    vma->vm_flags |= VM_FOREIGN;

    blktap_vma = vma;
    blktap_ring_ok = 1;

    return 0;
 fail:
    /* Clear any active mappings. */
    zap_page_range(vma, vma->vm_start, 
                   vma->vm_end - vma->vm_start, NULL);

    return -ENOMEM;
}

static int blktap_ioctl(struct inode *inode, struct file *filp,
                        unsigned int cmd, unsigned long arg)
{
    switch(cmd) {
    case BLKTAP_IOCTL_KICK_FE: /* There are fe messages to process. */
        return blktap_read_fe_ring();

    case BLKTAP_IOCTL_KICK_BE: /* There are be messages to process. */
        return blktap_read_be_ring();

    case BLKTAP_IOCTL_SETMODE:
        if (BLKTAP_MODE_VALID(arg)) {
            blktap_mode = arg;
            /* XXX: may need to flush rings here. */
            printk(KERN_INFO "blktap: set mode to %lx\n", arg);
            return 0;
        }
    case BLKTAP_IOCTL_PRINT_IDXS:
        {
            print_be_ring_idxs();
            print_fe_ring_idxs();
            WPRINTK("User Rings: \n-----------\n");
            WPRINTK("UF: rsp_cons: %2d, req_prod_prv: %2d "
                            "| req_prod: %2d, rsp_prod: %2d\n",
                            blktap_ufe_ring.rsp_cons,
                            blktap_ufe_ring.req_prod_pvt,
                            blktap_ufe_ring.sring->req_prod,
                            blktap_ufe_ring.sring->rsp_prod);
            WPRINTK("UB: req_cons: %2d, rsp_prod_prv: %2d "
                            "| req_prod: %2d, rsp_prod: %2d\n",
                            blktap_ube_ring.req_cons,
                            blktap_ube_ring.rsp_prod_pvt,
                            blktap_ube_ring.sring->req_prod,
                            blktap_ube_ring.sring->rsp_prod);
            
        }
    }
    return -ENOIOCTLCMD;
}

static unsigned int blktap_poll(struct file *file, poll_table *wait)
{
        poll_wait(file, &blktap_wait, wait);

        if ( RING_HAS_UNPUSHED_REQUESTS(&blktap_uctrl_ring) ||
             RING_HAS_UNPUSHED_REQUESTS(&blktap_ufe_ring)   ||
             RING_HAS_UNPUSHED_RESPONSES(&blktap_ube_ring) ) {

            flush_tlb_all();

            RING_PUSH_REQUESTS(&blktap_uctrl_ring);
            RING_PUSH_REQUESTS(&blktap_ufe_ring);
            RING_PUSH_RESPONSES(&blktap_ube_ring);
            return POLLIN | POLLRDNORM;
        }

        return 0;
}

void blktap_kick_user(void)
{
    /* blktap_ring->req_prod = blktap_req_prod; */
    wake_up_interruptible(&blktap_wait);
}

static struct file_operations blktap_fops = {
    owner:    THIS_MODULE,
    poll:     blktap_poll,
    ioctl:    blktap_ioctl,
    open:     blktap_open,
    release:  blktap_release,
    mmap:     blktap_mmap,
};
    
/*-----[ Data to/from user space ]----------------------------------------*/

static void fast_flush_area(int idx, int nr_pages)
{
#ifdef CONFIG_XEN_BLKDEV_GRANT
    struct gnttab_unmap_grant_ref unmap[BLKIF_MAX_SEGMENTS_PER_REQUEST*2];
    unsigned int i, op = 0;
    struct grant_handle_pair *handle;
    unsigned long ptep;

    for (i=0; i<nr_pages; i++)
    {
        handle = &pending_handle(idx, i);
        if (!BLKTAP_INVALID_HANDLE(handle))
        {

            unmap[op].host_addr = MMAP_VADDR(mmap_vstart, idx, i);
            unmap[op].dev_bus_addr = 0;
            unmap[op].handle = handle->kernel;
            op++;

            if (create_lookup_pte_addr(blktap_vma->vm_mm,
                                       MMAP_VADDR(user_vstart, idx, i), 
                                       &ptep) !=0) {
                DPRINTK("Couldn't get a pte addr!\n");
                return;
            }
            unmap[op].host_addr    = ptep;
            unmap[op].dev_bus_addr = 0;
            unmap[op].handle       = handle->user;
            op++;
            
            BLKTAP_INVALIDATE_HANDLE(handle);
        }
    }
    if ( unlikely(HYPERVISOR_grant_table_op(
        GNTTABOP_unmap_grant_ref, unmap, op)))
        BUG();
#else
    multicall_entry_t mcl[BLKIF_MAX_SEGMENTS_PER_REQUEST];
    int               i;

    for ( i = 0; i < nr_pages; i++ )
    {
        MULTI_update_va_mapping(mcl+i, MMAP_VADDR(mmap_vstart, idx, i),
                                __pte(0), 0);
    }

    mcl[nr_pages-1].args[MULTI_UVMFLAGS_INDEX] = UVMF_TLB_FLUSH|UVMF_ALL;
    if ( unlikely(HYPERVISOR_multicall(mcl, nr_pages) != 0) )
        BUG();
#endif
}


int blktap_write_fe_ring(blkif_request_t *req)
{
    blkif_request_t *target;
    int i, ret = 0;
#ifdef CONFIG_XEN_BLKDEV_GRANT
    struct gnttab_map_grant_ref map[BLKIF_MAX_SEGMENTS_PER_REQUEST*2];
    int op;
#else
    unsigned long remap_prot;
    multicall_entry_t mcl[BLKIF_MAX_SEGMENTS_PER_REQUEST+1];
    mmu_update_t mmu[BLKIF_MAX_SEGMENTS_PER_REQUEST];
#endif

    /*
     * This is called to pass a request from the real frontend domain's
     * blkif ring to the character device.
     */

    if ( ! blktap_ring_ok ) {
        DPRINTK("blktap: ufe_ring not ready for a request!\n");
        return 0;
    }

    if ( RING_FULL(&blktap_ufe_ring) ) {
        PRINTK("blktap: fe_ring is full, can't add.\n");
        return 0;
    }

    flush_cache_all(); /* a noop on intel... */

    target = RING_GET_REQUEST(&blktap_ufe_ring, blktap_ufe_ring.req_prod_pvt);
    memcpy(target, req, sizeof(*req));

    /* Map the foreign pages directly in to the application */
#ifdef CONFIG_XEN_BLKDEV_GRANT
    op = 0;
    for (i=0; i<target->nr_segments; i++) {

        unsigned long uvaddr;
        unsigned long kvaddr;
        unsigned long ptep;

        uvaddr = MMAP_VADDR(user_vstart, ID_TO_IDX(req->id), i);
        kvaddr = MMAP_VADDR(mmap_vstart, ID_TO_IDX(req->id), i);

        /* Map the remote page to kernel. */
        map[op].host_addr = kvaddr;
        map[op].dom   = ID_TO_DOM(req->id);
        map[op].ref   = blkif_gref_from_fas(target->frame_and_sects[i]);
        map[op].flags = GNTMAP_host_map;
        /* This needs a bit more thought in terms of interposition: 
         * If we want to be able to modify pages during write using 
         * grant table mappings, the guest will either need to allow 
         * it, or we'll need to incur a copy. */
        if (req->operation == BLKIF_OP_WRITE)
            map[op].flags |= GNTMAP_readonly;
        op++;

        /* Now map it to user. */
        ret = create_lookup_pte_addr(blktap_vma->vm_mm, uvaddr, &ptep);
        if (ret)
        {
            DPRINTK("Couldn't get a pte addr!\n");
            goto fail;
        }

        map[op].host_addr = ptep;
        map[op].dom       = ID_TO_DOM(req->id);
        map[op].ref       = blkif_gref_from_fas(target->frame_and_sects[i]);
        map[op].flags     = GNTMAP_host_map | GNTMAP_application_map
                            | GNTMAP_contains_pte;
        /* Above interposition comment applies here as well. */
        if (req->operation == BLKIF_OP_WRITE)
            map[op].flags |= GNTMAP_readonly;
        op++;
    }

    if ( unlikely(HYPERVISOR_grant_table_op(
            GNTTABOP_map_grant_ref, map, op)))
        BUG();

    op = 0;
    for (i=0; i<(target->nr_segments*2); i+=2) {
        unsigned long uvaddr;
        unsigned long kvaddr;
        unsigned long offset;
        int cancel = 0;

        uvaddr = MMAP_VADDR(user_vstart, ID_TO_IDX(req->id), i/2);
        kvaddr = MMAP_VADDR(mmap_vstart, ID_TO_IDX(req->id), i/2);

        if ( unlikely(map[i].handle < 0) ) {
            DPRINTK("Error on kernel grant mapping (%d)\n", map[i].handle);
            ret = map[i].handle;
            cancel = 1;
        }

        if ( unlikely(map[i+1].handle < 0) ) {
            DPRINTK("Error on user grant mapping (%d)\n", map[i+1].handle);
            ret = map[i+1].handle;
            cancel = 1;
        }

        if (cancel) 
            goto fail;

        /* Set the necessary mappings in p2m and in the VM_FOREIGN 
         * vm_area_struct to allow user vaddr -> struct page lookups
         * to work.  This is needed for direct IO to foreign pages. */
        phys_to_machine_mapping[__pa(kvaddr) >> PAGE_SHIFT] =
            FOREIGN_FRAME(map[i].dev_bus_addr >> PAGE_SHIFT);

        offset = (uvaddr - blktap_vma->vm_start) >> PAGE_SHIFT;
        ((struct page **)blktap_vma->vm_private_data)[offset] =
            pfn_to_page(__pa(kvaddr) >> PAGE_SHIFT);

        /* Save handles for unmapping later. */
        pending_handle(ID_TO_IDX(req->id), i/2).kernel = map[i].handle;
        pending_handle(ID_TO_IDX(req->id), i/2).user   = map[i+1].handle;
    }
    
#else

    remap_prot = _PAGE_PRESENT|_PAGE_DIRTY|_PAGE_ACCESSED|_PAGE_RW;

    for (i=0; i<target->nr_segments; i++) {
        unsigned long buf;
        unsigned long uvaddr;
        unsigned long kvaddr;
        unsigned long offset;
        unsigned long ptep;

        buf   = target->frame_and_sects[i] & PAGE_MASK;
        uvaddr = MMAP_VADDR(user_vstart, ID_TO_IDX(req->id), i);
        kvaddr = MMAP_VADDR(mmap_vstart, ID_TO_IDX(req->id), i);

        MULTI_update_va_mapping_otherdomain(
            mcl+i, 
            kvaddr, 
            pfn_pte_ma(buf >> PAGE_SHIFT, __pgprot(remap_prot)),
            0,
            ID_TO_DOM(req->id));

        phys_to_machine_mapping[__pa(kvaddr)>>PAGE_SHIFT] =
            FOREIGN_FRAME(buf >> PAGE_SHIFT);

        ret = create_lookup_pte_addr(blktap_vma->vm_mm, uvaddr, &ptep);
        if (ret)
        { 
            DPRINTK("error getting pte\n");
            goto fail;
        }

        mmu[i].ptr = ptep;
        mmu[i].val = (target->frame_and_sects[i] & PAGE_MASK)
            | pgprot_val(blktap_vma->vm_page_prot);

        offset = (uvaddr - blktap_vma->vm_start) >> PAGE_SHIFT;
        ((struct page **)blktap_vma->vm_private_data)[offset] =
            pfn_to_page(__pa(kvaddr) >> PAGE_SHIFT);
    }
    
    /* Add the mmu_update call. */
    mcl[i].op = __HYPERVISOR_mmu_update;
    mcl[i].args[0] = (unsigned long)mmu;
    mcl[i].args[1] = target->nr_segments;
    mcl[i].args[2] = 0;
    mcl[i].args[3] = ID_TO_DOM(req->id);

    BUG_ON(HYPERVISOR_multicall(mcl, target->nr_segments+1) != 0);

    /* Make sure it all worked. */
    for ( i = 0; i < target->nr_segments; i++ )
    {
        if ( unlikely(mcl[i].result != 0) )
        {
            DPRINTK("invalid buffer -- could not remap it\n");
            ret = mcl[i].result;
            goto fail;
        }
    }
    if ( unlikely(mcl[i].result != 0) )
    {
        DPRINTK("direct remapping of pages to /dev/blktap failed.\n");
        ret = mcl[i].result;
        goto fail;
    }
#endif /* CONFIG_XEN_BLKDEV_GRANT */

    /* Mark mapped pages as reserved: */
    for ( i = 0; i < target->nr_segments; i++ )
    {
        unsigned long kvaddr;

        kvaddr = MMAP_VADDR(mmap_vstart, ID_TO_IDX(req->id), i);
        SetPageReserved(pfn_to_page(__pa(kvaddr) >> PAGE_SHIFT));
    }


    blktap_ufe_ring.req_prod_pvt++;
    
    return 0;

 fail:
    fast_flush_area(ID_TO_IDX(req->id), target->nr_segments);
    return ret;
}

int blktap_write_be_ring(blkif_response_t *rsp)
{
    blkif_response_t *target;

    /*
     * This is called to pass a request from the real backend domain's
     * blkif ring to the character device.
     */

    if ( ! blktap_ring_ok ) {
        DPRINTK("blktap: be_ring not ready for a request!\n");
        return 0;
    }

    /* No test for fullness in the response direction. */

    target = RING_GET_RESPONSE(&blktap_ube_ring,
            blktap_ube_ring.rsp_prod_pvt);
    memcpy(target, rsp, sizeof(*rsp));

    /* no mapping -- pages were mapped in blktap_write_fe_ring() */

    blktap_ube_ring.rsp_prod_pvt++;
    
    return 0;
}

static int blktap_read_fe_ring(void)
{
    /* This is called to read responses from the UFE ring. */

    RING_IDX i, j, rp;
    blkif_response_t *resp_s;
    blkif_t *blkif;
    active_req_t *ar;

    DPRINTK("blktap_read_fe_ring()\n");

    /* if we are forwarding from UFERring to FERing */
    if (blktap_mode & BLKTAP_MODE_INTERCEPT_FE) {

        /* for each outstanding message on the UFEring  */
        rp = blktap_ufe_ring.sring->rsp_prod;
        rmb();
        
        for ( i = blktap_ufe_ring.rsp_cons; i != rp; i++ )
        {
            resp_s = RING_GET_RESPONSE(&blktap_ufe_ring, i);
            
            DPRINTK("resp->fe_ring\n");
            ar = lookup_active_req(ID_TO_IDX(resp_s->id));
            blkif = ar->blkif;
            for (j = 0; j < ar->nr_pages; j++) {
                unsigned long vaddr;
                struct page **map = blktap_vma->vm_private_data;
                int offset; 

                vaddr  = MMAP_VADDR(user_vstart, ID_TO_IDX(resp_s->id), j);
                offset = (vaddr - blktap_vma->vm_start) >> PAGE_SHIFT;

                ClearPageReserved(virt_to_page(vaddr));
                map[offset] = NULL;
            }

            fast_flush_area(ID_TO_IDX(resp_s->id), ar->nr_pages);
            zap_page_range(blktap_vma, 
                    MMAP_VADDR(user_vstart, ID_TO_IDX(resp_s->id), 0), 
                    ar->nr_pages << PAGE_SHIFT, NULL);
            write_resp_to_fe_ring(blkif, resp_s);
            blktap_ufe_ring.rsp_cons = i + 1;
            kick_fe_domain(blkif);
        }
    }
    return 0;
}

static int blktap_read_be_ring(void)
{
    /* This is called to read requests from the UBE ring. */

    RING_IDX i, rp;
    blkif_request_t *req_s;

    DPRINTK("blktap_read_be_ring()\n");

    /* if we are forwarding from UFERring to FERing */
    if (blktap_mode & BLKTAP_MODE_INTERCEPT_BE) {

        /* for each outstanding message on the UFEring  */
        rp = blktap_ube_ring.sring->req_prod;
        rmb();
        for ( i = blktap_ube_ring.req_cons; i != rp; i++ )
        {
            req_s = RING_GET_REQUEST(&blktap_ube_ring, i);

            DPRINTK("req->be_ring\n");
            write_req_to_be_ring(req_s);
            kick_be_domain();
        }
        
        blktap_ube_ring.req_cons = i;
    }

    return 0;
}

int blktap_write_ctrl_ring(ctrl_msg_t *msg)
{
    ctrl_msg_t *target;

    if ( ! blktap_ring_ok ) {
        DPRINTK("blktap: be_ring not ready for a request!\n");
        return 0;
    }

    /* No test for fullness in the response direction. */

    target = RING_GET_REQUEST(&blktap_uctrl_ring,
            blktap_uctrl_ring.req_prod_pvt);
    memcpy(target, msg, sizeof(*msg));

    blktap_uctrl_ring.req_prod_pvt++;
    
    /* currently treat the ring as unidirectional. */
    blktap_uctrl_ring.rsp_cons = blktap_uctrl_ring.sring->rsp_prod;
    
    return 0;
       
}

/* -------[ blktap module setup ]------------------------------------- */

static struct miscdevice blktap_miscdev = {
    .minor        = BLKTAP_MINOR,
    .name         = "blktap",
    .fops         = &blktap_fops,
    .devfs_name   = "misc/blktap",
};

int blktap_init(void)
{
    int err, i, j;
    struct page *page;

    page = balloon_alloc_empty_page_range(MMAP_PAGES);
    BUG_ON(page == NULL);
    mmap_vstart = (unsigned long)pfn_to_kaddr(page_to_pfn(page));

#ifdef CONFIG_XEN_BLKDEV_GRANT
    for (i=0; i<MAX_PENDING_REQS ; i++)
        for (j=0; j<BLKIF_MAX_SEGMENTS_PER_REQUEST; j++)
            BLKTAP_INVALIDATE_HANDLE(&pending_handle(i, j));
#endif

    err = misc_register(&blktap_miscdev);
    if ( err != 0 )
    {
        printk(KERN_ALERT "Couldn't register /dev/misc/blktap (%d)\n", err);
        return err;
    }

    init_waitqueue_head(&blktap_wait);


    return 0;
}
