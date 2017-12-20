/******************************************************************************
 * hvm/emulate.c
 * 
 * HVM instruction emulation. Used for MMIO and VMX real mode.
 * 
 * Copyright (c) 2008, Citrix Systems, Inc.
 * 
 * Authors:
 *    Keir Fraser <keir@xen.org>
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/paging.h>
#include <xen/trace.h>
#include <asm/event.h>
#include <asm/xstate.h>
#include <asm/hvm/emulate.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/ioreq.h>
#include <asm/hvm/trace.h>
#include <asm/hvm/support.h>
#include <asm/hvm/svm/svm.h>
#include <asm/vm_event.h>

static void hvmtrace_io_assist(const ioreq_t *p)
{
    unsigned int size, event;
    unsigned char buffer[12];

    if ( likely(!tb_init_done) )
        return;

    if ( p->type == IOREQ_TYPE_COPY )
        event = p->dir ? TRC_HVM_IOMEM_READ : TRC_HVM_IOMEM_WRITE;
    else
        event = p->dir ? TRC_HVM_IOPORT_READ : TRC_HVM_IOPORT_WRITE;

    *(uint64_t *)buffer = p->addr;
    size = (p->addr != (u32)p->addr) ? 8 : 4;
    if ( size == 8 )
        event |= TRC_64_FLAG;

    if ( !p->data_is_ptr )
    {
        *(uint32_t *)&buffer[size] = p->data;
        size += 4;
    }

    trace_var(event, 0/*!cycles*/, size, buffer);
}

static int null_read(const struct hvm_io_handler *io_handler,
                     uint64_t addr,
                     uint32_t size,
                     uint64_t *data)
{
    *data = ~0ul;
    return X86EMUL_OKAY;
}

static int null_write(const struct hvm_io_handler *handler,
                      uint64_t addr,
                      uint32_t size,
                      uint64_t data)
{
    return X86EMUL_OKAY;
}

static int set_context_data(void *buffer, unsigned int size)
{
    struct vcpu *curr = current;

    if ( curr->arch.vm_event )
    {
        unsigned int safe_size =
            min(size, curr->arch.vm_event->emul.read.size);

        memcpy(buffer, curr->arch.vm_event->emul.read.data, safe_size);
        memset(buffer + safe_size, 0, size - safe_size);
        return X86EMUL_OKAY;
    }

    return X86EMUL_UNHANDLEABLE;
}

static const struct hvm_io_ops null_ops = {
    .read = null_read,
    .write = null_write
};

static const struct hvm_io_handler null_handler = {
    .ops = &null_ops
};

static int hvmemul_do_io(
    bool_t is_mmio, paddr_t addr, unsigned long *reps, unsigned int size,
    uint8_t dir, bool_t df, bool_t data_is_addr, uintptr_t data)
{
    struct vcpu *curr = current;
    struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;
    ioreq_t p = {
        .type = is_mmio ? IOREQ_TYPE_COPY : IOREQ_TYPE_PIO,
        .addr = addr,
        .size = size,
        .count = *reps,
        .dir = dir,
        .df = df,
        .data = data_is_addr ? data : 0,
        .data_is_ptr = data_is_addr, /* ioreq_t field name is misleading */
        .state = STATE_IOREQ_READY,
    };
    void *p_data = (void *)data;
    int rc;

    /*
     * Weird-sized accesses have undefined behaviour: we discard writes
     * and read all-ones.
     */
    if ( unlikely((size > sizeof(long)) || (size & (size - 1))) )
    {
        gdprintk(XENLOG_WARNING, "bad mmio size %d\n", size);
        return X86EMUL_UNHANDLEABLE;
    }

    switch ( vio->io_req.state )
    {
    case STATE_IOREQ_NONE:
        break;
    case STATE_IORESP_READY:
        vio->io_req.state = STATE_IOREQ_NONE;
        p = vio->io_req;

        /* Verify the emulation request has been correctly re-issued */
        if ( (p.type != (is_mmio ? IOREQ_TYPE_COPY : IOREQ_TYPE_PIO)) ||
             (p.addr != addr) ||
             (p.size != size) ||
             (p.count > *reps) ||
             (p.dir != dir) ||
             (p.df != df) ||
             (p.data_is_ptr != data_is_addr) )
            domain_crash(curr->domain);

        if ( data_is_addr )
            return X86EMUL_UNHANDLEABLE;

        *reps = p.count;
        goto finish_access;
    default:
        return X86EMUL_UNHANDLEABLE;
    }

    if ( dir == IOREQ_WRITE )
    {
        if ( !data_is_addr )
            memcpy(&p.data, p_data, size);

        hvmtrace_io_assist(&p);
    }

    vio->io_req = p;

    rc = hvm_io_intercept(&p);

    /*
     * p.count may have got reduced (see hvm_process_io_intercept()) - inform
     * our callers and mirror this into latched state.
     */
    ASSERT(p.count <= *reps);
    *reps = vio->io_req.count = p.count;

    switch ( rc )
    {
    case X86EMUL_OKAY:
        vio->io_req.state = STATE_IOREQ_NONE;
        break;
    case X86EMUL_UNHANDLEABLE:
    {
        struct hvm_ioreq_server *s =
            hvm_select_ioreq_server(curr->domain, &p);

        /* If there is no suitable backing DM, just ignore accesses */
        if ( !s )
        {
            rc = hvm_process_io_intercept(&null_handler, &p);
            vio->io_req.state = STATE_IOREQ_NONE;
        }
        else
        {
            rc = hvm_send_ioreq(s, &p, 0);
            if ( rc != X86EMUL_RETRY || curr->domain->is_shutting_down )
                vio->io_req.state = STATE_IOREQ_NONE;
            else if ( data_is_addr )
                rc = X86EMUL_OKAY;
        }
        break;
    }
    default:
        BUG();
    }

    if ( rc != X86EMUL_OKAY )
        return rc;

 finish_access:
    if ( dir == IOREQ_READ )
    {
        hvmtrace_io_assist(&p);

        if ( !data_is_addr )
            memcpy(p_data, &p.data, size);
    }

    return X86EMUL_OKAY;
}

static int hvmemul_do_io_buffer(
    bool_t is_mmio, paddr_t addr, unsigned long *reps, unsigned int size,
    uint8_t dir, bool_t df, void *buffer)
{
    int rc;

    BUG_ON(buffer == NULL);

    rc = hvmemul_do_io(is_mmio, addr, reps, size, dir, df, 0,
                       (uintptr_t)buffer);
    if ( rc == X86EMUL_UNHANDLEABLE && dir == IOREQ_READ )
        memset(buffer, 0xff, size);

    return rc;
}

static int hvmemul_acquire_page(unsigned long gmfn, struct page_info **page)
{
    struct domain *curr_d = current->domain;
    p2m_type_t p2mt;

    *page = get_page_from_gfn(curr_d, gmfn, &p2mt, P2M_UNSHARE);

    if ( *page == NULL )
        return X86EMUL_UNHANDLEABLE;

    if ( p2m_is_paging(p2mt) )
    {
        put_page(*page);
        p2m_mem_paging_populate(curr_d, gmfn);
        return X86EMUL_RETRY;
    }

    if ( p2m_is_shared(p2mt) )
    {
        put_page(*page);
        return X86EMUL_RETRY;
    }

    /* This code should not be reached if the gmfn is not RAM */
    if ( p2m_is_mmio(p2mt) )
    {
        domain_crash(curr_d);

        put_page(*page);
        return X86EMUL_UNHANDLEABLE;
    }

    return X86EMUL_OKAY;
}

static inline void hvmemul_release_page(struct page_info *page)
{
    put_page(page);
}

static int hvmemul_do_io_addr(
    bool_t is_mmio, paddr_t addr, unsigned long *reps,
    unsigned int size, uint8_t dir, bool_t df, paddr_t ram_gpa)
{
    struct vcpu *v = current;
    unsigned long ram_gmfn = paddr_to_pfn(ram_gpa);
    unsigned int page_off = ram_gpa & (PAGE_SIZE - 1);
    struct page_info *ram_page[2];
    unsigned int nr_pages = 0;
    unsigned long count;
    int rc;

    rc = hvmemul_acquire_page(ram_gmfn, &ram_page[nr_pages]);
    if ( rc != X86EMUL_OKAY )
        goto out;

    nr_pages++;

    /* Detemine how many reps will fit within this page */
    count = min_t(unsigned long,
                  *reps,
                  df ?
                  ((page_off + size - 1) & ~PAGE_MASK) / size :
                  (PAGE_SIZE - page_off) / size);

    if ( count == 0 )
    {
        /*
         * This access must span two pages, so grab a reference to
         * the next page and do a single rep.
         * It is safe to assume multiple pages are physically
         * contiguous at this point as hvmemul_linear_to_phys() will
         * ensure this is the case.
         */
        rc = hvmemul_acquire_page(df ? ram_gmfn - 1 : ram_gmfn + 1,
                                  &ram_page[nr_pages]);
        if ( rc != X86EMUL_OKAY )
            goto out;

        nr_pages++;
        count = 1;
    }

    rc = hvmemul_do_io(is_mmio, addr, &count, size, dir, df, 1,
                       ram_gpa);

    if ( rc == X86EMUL_OKAY )
        v->arch.hvm_vcpu.hvm_io.mmio_retry = (count < *reps);

    *reps = count;

 out:
    while ( nr_pages )
        hvmemul_release_page(ram_page[--nr_pages]);

    return rc;
}

/*
 * Perform I/O between <port> and <buffer>. <dir> indicates the
 * direction: IOREQ_READ means a read from <port> to <buffer> and
 * IOREQ_WRITE means a write from <buffer> to <port>. Each access has
 * width <size>.
 */
int hvmemul_do_pio_buffer(uint16_t port,
                          unsigned int size,
                          uint8_t dir,
                          void *buffer)
{
    unsigned long one_rep = 1;

    return hvmemul_do_io_buffer(0, port, &one_rep, size, dir, 0, buffer);
}

/*
 * Perform I/O between <port> and guest RAM starting at <ram_addr>.
 * <dir> indicates the direction: IOREQ_READ means a read from <port> to
 * RAM and IOREQ_WRITE means a write from RAM to <port>. Each access has
 * width <size> and up to *<reps> accesses will be performed. If
 * X86EMUL_OKAY is returned then <reps> will be updated with the number
 * of accesses actually performed.
 * Each access will be done to/from successive RAM addresses, increasing
 * if <df> is 0 or decreasing if <df> is 1.
 */
static int hvmemul_do_pio_addr(uint16_t port,
                               unsigned long *reps,
                               unsigned int size,
                               uint8_t dir,
                               bool_t df,
                               paddr_t ram_addr)
{
    return hvmemul_do_io_addr(0, port, reps, size, dir, df, ram_addr);
}

/*
 * Perform I/O between MMIO space starting at <mmio_gpa> and <buffer>.
 * <dir> indicates the direction: IOREQ_READ means a read from MMIO to
 * <buffer> and IOREQ_WRITE means a write from <buffer> to MMIO. Each
 * access has width <size> and up to *<reps> accesses will be performed.
 * If X86EMUL_OKAY is returned then <reps> will be updated with the number
 * of accesses actually performed.
 * Each access will be done to/from successive MMIO addresses, increasing
 * if <df> is 0 or decreasing if <df> is 1.
 *
 * NOTE: If *<reps> is greater than 1, each access will use the
 *       <buffer> pointer; there is no implicit interation over a
 *       block of memory starting at <buffer>.
 */
static int hvmemul_do_mmio_buffer(paddr_t mmio_gpa,
                                  unsigned long *reps,
                                  unsigned int size,
                                  uint8_t dir,
                                  bool_t df,
                                  void *buffer)
{
    return hvmemul_do_io_buffer(1, mmio_gpa, reps, size, dir, df, buffer);
}

/*
 * Perform I/O between MMIO space starting at <mmio_gpa> and guest RAM
 * starting at <ram_gpa>. <dir> indicates the direction: IOREQ_READ
 * means a read from MMIO to RAM and IOREQ_WRITE means a write from RAM
 * to MMIO. Each access has width <size> and up to *<reps> accesses will
 * be performed. If X86EMUL_OKAY is returned then <reps> will be updated
 * with the number of accesses actually performed.
 * Each access will be done to/from successive RAM *and* MMIO addresses,
 * increasing if <df> is 0 or decreasing if <df> is 1.
 */
static int hvmemul_do_mmio_addr(paddr_t mmio_gpa,
                                unsigned long *reps,
                                unsigned int size,
                                uint8_t dir,
                                bool_t df,
                                paddr_t ram_gpa)
{
    return hvmemul_do_io_addr(1, mmio_gpa, reps, size, dir, df, ram_gpa);
}

/*
 * Convert addr from linear to physical form, valid over the range
 * [addr, addr + *reps * bytes_per_rep]. *reps is adjusted according to
 * the valid computed range. It is always >0 when X86EMUL_OKAY is returned.
 * @pfec indicates the access checks to be performed during page-table walks.
 */
static int hvmemul_linear_to_phys(
    unsigned long addr,
    paddr_t *paddr,
    unsigned int bytes_per_rep,
    unsigned long *reps,
    uint32_t pfec,
    struct hvm_emulate_ctxt *hvmemul_ctxt)
{
    struct vcpu *curr = current;
    unsigned long pfn, npfn, done, todo, i, offset = addr & ~PAGE_MASK;
    int reverse;

    /*
     * Clip repetitions to a sensible maximum. This avoids extensive looping in
     * this function while still amortising the cost of I/O trap-and-emulate.
     */
    *reps = min_t(unsigned long, *reps, 4096);

    /* With no paging it's easy: linear == physical. */
    if ( !(curr->arch.hvm_vcpu.guest_cr[0] & X86_CR0_PG) )
    {
        *paddr = addr;
        return X86EMUL_OKAY;
    }

    /* Reverse mode if this is a backwards multi-iteration string operation. */
    reverse = (hvmemul_ctxt->ctxt.regs->eflags & X86_EFLAGS_DF) && (*reps > 1);

    if ( reverse && ((PAGE_SIZE - offset) < bytes_per_rep) )
    {
        /* Do page-straddling first iteration forwards via recursion. */
        paddr_t _paddr;
        unsigned long one_rep = 1;
        int rc = hvmemul_linear_to_phys(
            addr, &_paddr, bytes_per_rep, &one_rep, pfec, hvmemul_ctxt);
        if ( rc != X86EMUL_OKAY )
            return rc;
        pfn = _paddr >> PAGE_SHIFT;
    }
    else if ( (pfn = paging_gva_to_gfn(curr, addr, &pfec)) == gfn_x(INVALID_GFN) )
    {
        if ( pfec & (PFEC_page_paged | PFEC_page_shared) )
            return X86EMUL_RETRY;
        hvm_inject_page_fault(pfec, addr);
        return X86EMUL_EXCEPTION;
    }

    done = reverse ? bytes_per_rep + offset : PAGE_SIZE - offset;
    todo = *reps * bytes_per_rep;
    for ( i = 1; done < todo; i++ )
    {
        /* Get the next PFN in the range. */
        addr += reverse ? -PAGE_SIZE : PAGE_SIZE;
        npfn = paging_gva_to_gfn(curr, addr, &pfec);

        /* Is it contiguous with the preceding PFNs? If not then we're done. */
        if ( (npfn == gfn_x(INVALID_GFN)) ||
             (npfn != (pfn + (reverse ? -i : i))) )
        {
            if ( pfec & (PFEC_page_paged | PFEC_page_shared) )
                return X86EMUL_RETRY;
            done /= bytes_per_rep;
            if ( done == 0 )
            {
                ASSERT(!reverse);
                if ( npfn != gfn_x(INVALID_GFN) )
                    return X86EMUL_UNHANDLEABLE;
                hvm_inject_page_fault(pfec, addr & PAGE_MASK);
                return X86EMUL_EXCEPTION;
            }
            *reps = done;
            break;
        }

        done += PAGE_SIZE;
    }

    *paddr = ((paddr_t)pfn << PAGE_SHIFT) | offset;
    return X86EMUL_OKAY;
}
    

static int hvmemul_virtual_to_linear(
    enum x86_segment seg,
    unsigned long offset,
    unsigned int bytes_per_rep,
    unsigned long *reps,
    enum hvm_access_type access_type,
    struct hvm_emulate_ctxt *hvmemul_ctxt,
    unsigned long *paddr)
{
    struct segment_register *reg;
    int okay;
    unsigned long max_reps = 4096;

    if ( seg == x86_seg_none )
    {
        *paddr = offset;
        return X86EMUL_OKAY;
    }

    /*
     * If introspection has been enabled for this domain, and we're emulating
     * becase a vm_reply asked us to (i.e. not doing regular IO) reps should
     * be at most 1, since optimization might otherwise cause a single
     * vm_event being triggered for repeated writes to a whole page.
     */
    if ( unlikely(current->domain->arch.mem_access_emulate_each_rep) &&
         current->arch.vm_event->emulate_flags != 0 )
       max_reps = 1;

    /*
     * Clip repetitions to avoid overflow when multiplying by @bytes_per_rep.
     * The chosen maximum is very conservative but it's what we use in
     * hvmemul_linear_to_phys() so there is no point in using a larger value.
     */
    *reps = min_t(unsigned long, *reps, max_reps);

    reg = hvmemul_get_seg_reg(seg, hvmemul_ctxt);
    if ( IS_ERR(reg) )
        return -PTR_ERR(reg);

    if ( (hvmemul_ctxt->ctxt.regs->eflags & X86_EFLAGS_DF) && (*reps > 1) )
    {
        /*
         * x86_emulate() clips the repetition count to ensure we don't wrap
         * the effective-address index register. Hence this assertion holds.
         */
        ASSERT(offset >= ((*reps - 1) * bytes_per_rep));
        okay = hvm_virtual_to_linear_addr(
            seg, reg, offset - (*reps - 1) * bytes_per_rep,
            *reps * bytes_per_rep, access_type,
            hvmemul_ctxt->ctxt.addr_size, paddr);
        *paddr += (*reps - 1) * bytes_per_rep;
        if ( hvmemul_ctxt->ctxt.addr_size != 64 )
            *paddr = (uint32_t)*paddr;
    }
    else
    {
        okay = hvm_virtual_to_linear_addr(
            seg, reg, offset, *reps * bytes_per_rep, access_type,
            hvmemul_ctxt->ctxt.addr_size, paddr);
    }

    if ( okay )
        return X86EMUL_OKAY;

    /* If this is a string operation, emulate each iteration separately. */
    if ( *reps != 1 )
        return X86EMUL_UNHANDLEABLE;

    /* This is a singleton operation: fail it with an exception. */
    hvmemul_ctxt->exn_pending = 1;
    hvmemul_ctxt->trap.vector =
        (seg == x86_seg_ss) ? TRAP_stack_error : TRAP_gp_fault;
    hvmemul_ctxt->trap.type = X86_EVENTTYPE_HW_EXCEPTION;
    hvmemul_ctxt->trap.error_code = 0;
    hvmemul_ctxt->trap.insn_len = 0;
    return X86EMUL_EXCEPTION;
}

static int hvmemul_phys_mmio_access(
    struct hvm_mmio_cache *cache, paddr_t gpa, unsigned int size, uint8_t dir,
    uint8_t *buffer, unsigned int offset)
{
    unsigned long one_rep = 1;
    unsigned int chunk;
    int rc = X86EMUL_OKAY;

    /* Accesses must fall within a page. */
    BUG_ON((gpa & ~PAGE_MASK) + size > PAGE_SIZE);

    /*
     * hvmemul_do_io() cannot handle non-power-of-2 accesses or
     * accesses larger than sizeof(long), so choose the highest power
     * of 2 not exceeding sizeof(long) as the 'chunk' size.
     */
    ASSERT(size != 0);
    chunk = 1u << (fls(size) - 1);
    if ( chunk > sizeof (long) )
        chunk = sizeof (long);

    for ( ;; )
    {
        /* Have we already done this chunk? */
        if ( offset < cache->size )
        {
            ASSERT((offset + chunk) <= cache->size);

            if ( dir == IOREQ_READ )
                memcpy(&buffer[offset], &cache->buffer[offset], chunk);
            else if ( memcmp(&buffer[offset], &cache->buffer[offset], chunk) != 0 )
                domain_crash(current->domain);
        }
        else
        {
            ASSERT(offset == cache->size);

            rc = hvmemul_do_mmio_buffer(gpa, &one_rep, chunk, dir, 0,
                                        &buffer[offset]);
            if ( rc != X86EMUL_OKAY )
                break;

            /* Note that we have now done this chunk. */
            memcpy(&cache->buffer[offset], &buffer[offset], chunk);
            cache->size += chunk;
        }

        /* Advance to the next chunk. */
        gpa += chunk;
        offset += chunk;
        size -= chunk;

        if ( size == 0 )
            break;

        /*
         * If the chunk now exceeds the remaining size, choose the next
         * lowest power of 2 that will fit.
         */
        while ( chunk > size )
            chunk >>= 1;
    }

    return rc;
}

/*
 * Multi-cycle MMIO handling is based upon the assumption that emulation
 * of the same instruction will not access the same MMIO region more
 * than once. Hence we can deal with re-emulation (for secondary or
 * subsequent cycles) by looking up the result or previous I/O in a
 * cache indexed by linear MMIO address.
 */
static struct hvm_mmio_cache *hvmemul_find_mmio_cache(
    struct hvm_vcpu_io *vio, unsigned long gla, uint8_t dir)
{
    unsigned int i;
    struct hvm_mmio_cache *cache;

    for ( i = 0; i < vio->mmio_cache_count; i ++ )
    {
        cache = &vio->mmio_cache[i];

        if ( gla == cache->gla &&
             dir == cache->dir )
            return cache;
    }

    i = vio->mmio_cache_count++;
    if( i == ARRAY_SIZE(vio->mmio_cache) )
    {
        domain_crash(current->domain);
        return NULL;
    }

    cache = &vio->mmio_cache[i];
    memset(cache, 0, sizeof (*cache));

    cache->gla = gla;
    cache->dir = dir;

    return cache;
}

static void latch_linear_to_phys(struct hvm_vcpu_io *vio, unsigned long gla,
                                 unsigned long gpa, bool_t write)
{
    if ( vio->mmio_access.gla_valid )
        return;

    vio->mmio_gla = gla & PAGE_MASK;
    vio->mmio_gpfn = PFN_DOWN(gpa);
    vio->mmio_access = (struct npfec){ .gla_valid = 1,
                                       .read_access = 1,
                                       .write_access = write };
}

static int hvmemul_linear_mmio_access(
    unsigned long gla, unsigned int size, uint8_t dir, void *buffer,
    uint32_t pfec, struct hvm_emulate_ctxt *hvmemul_ctxt, bool_t known_gpfn)
{
    struct hvm_vcpu_io *vio = &current->arch.hvm_vcpu.hvm_io;
    unsigned long offset = gla & ~PAGE_MASK;
    struct hvm_mmio_cache *cache = hvmemul_find_mmio_cache(vio, gla, dir);
    unsigned int chunk, buffer_offset = 0;
    paddr_t gpa;
    unsigned long one_rep = 1;
    int rc;

    if ( cache == NULL )
        return X86EMUL_UNHANDLEABLE;

    chunk = min_t(unsigned int, size, PAGE_SIZE - offset);

    if ( known_gpfn )
        gpa = pfn_to_paddr(vio->mmio_gpfn) | offset;
    else
    {
        rc = hvmemul_linear_to_phys(gla, &gpa, chunk, &one_rep, pfec,
                                    hvmemul_ctxt);
        if ( rc != X86EMUL_OKAY )
            return rc;

        latch_linear_to_phys(vio, gla, gpa, dir == IOREQ_WRITE);
    }

    for ( ;; )
    {
        rc = hvmemul_phys_mmio_access(cache, gpa, chunk, dir, buffer, buffer_offset);
        if ( rc != X86EMUL_OKAY )
            break;

        gla += chunk;
        buffer_offset += chunk;
        size -= chunk;

        if ( size == 0 )
            break;

        chunk = min_t(unsigned int, size, PAGE_SIZE);
        rc = hvmemul_linear_to_phys(gla, &gpa, chunk, &one_rep, pfec,
                                    hvmemul_ctxt);
        if ( rc != X86EMUL_OKAY )
            return rc;
    }

    return rc;
}

static inline int hvmemul_linear_mmio_read(
    unsigned long gla, unsigned int size, void *buffer,
    uint32_t pfec, struct hvm_emulate_ctxt *hvmemul_ctxt,
    bool_t translate)
{
    return hvmemul_linear_mmio_access(gla, size, IOREQ_READ, buffer,
                                      pfec, hvmemul_ctxt, translate);
}

static inline int hvmemul_linear_mmio_write(
    unsigned long gla, unsigned int size, void *buffer,
    uint32_t pfec, struct hvm_emulate_ctxt *hvmemul_ctxt,
    bool_t translate)
{
    return hvmemul_linear_mmio_access(gla, size, IOREQ_WRITE, buffer,
                                      pfec, hvmemul_ctxt, translate);
}

static int __hvmemul_read(
    enum x86_segment seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    enum hvm_access_type access_type,
    struct hvm_emulate_ctxt *hvmemul_ctxt)
{
    struct vcpu *curr = current;
    unsigned long addr, reps = 1;
    uint32_t pfec = PFEC_page_present;
    struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;
    int rc;

    rc = hvmemul_virtual_to_linear(
        seg, offset, bytes, &reps, access_type, hvmemul_ctxt, &addr);
    if ( rc != X86EMUL_OKAY || !bytes )
        return rc;
    if ( ((access_type != hvm_access_insn_fetch
           ? vio->mmio_access.read_access
           : vio->mmio_access.insn_fetch)) &&
         (vio->mmio_gla == (addr & PAGE_MASK)) )
        return hvmemul_linear_mmio_read(addr, bytes, p_data, pfec, hvmemul_ctxt, 1);

    if ( (seg != x86_seg_none) &&
         (hvmemul_ctxt->seg_reg[x86_seg_ss].attr.fields.dpl == 3) )
        pfec |= PFEC_user_mode;

    rc = ((access_type == hvm_access_insn_fetch) ?
          hvm_fetch_from_guest_virt(p_data, addr, bytes, pfec) :
          hvm_copy_from_guest_virt(p_data, addr, bytes, pfec));

    switch ( rc )
    {
    case HVMCOPY_okay:
        break;
    case HVMCOPY_bad_gva_to_gfn:
        return X86EMUL_EXCEPTION;
    case HVMCOPY_bad_gfn_to_mfn:
        if ( access_type == hvm_access_insn_fetch )
            return X86EMUL_UNHANDLEABLE;

        return hvmemul_linear_mmio_read(addr, bytes, p_data, pfec, hvmemul_ctxt, 0);
    case HVMCOPY_gfn_paged_out:
    case HVMCOPY_gfn_shared:
        return X86EMUL_RETRY;
    default:
        return X86EMUL_UNHANDLEABLE;
    }

    return X86EMUL_OKAY;
}

static int hvmemul_read(
    enum x86_segment seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);

    if ( unlikely(hvmemul_ctxt->set_context) )
        return set_context_data(p_data, bytes);

    return __hvmemul_read(
        seg, offset, p_data, bytes, hvm_access_read,
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt));
}

int hvmemul_insn_fetch(
    enum x86_segment seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);
    /* Careful, as offset can wrap or truncate WRT insn_buf_eip. */
    uint8_t insn_off = offset - hvmemul_ctxt->insn_buf_eip;

    /*
     * Fall back if requested bytes are not in the prefetch cache.
     * But always perform the (fake) read when bytes == 0.
     */
    if ( !bytes ||
         unlikely((insn_off + bytes) > hvmemul_ctxt->insn_buf_bytes) )
    {
        int rc = __hvmemul_read(seg, offset, p_data, bytes,
                                hvm_access_insn_fetch, hvmemul_ctxt);

        if ( rc == X86EMUL_OKAY && bytes )
        {
            /*
             * Will we overflow insn_buf[]?  This shouldn't be able to happen,
             * which means something went wrong with instruction decoding...
             */
            if ( insn_off >= sizeof(hvmemul_ctxt->insn_buf) ||
                 insn_off + bytes > sizeof(hvmemul_ctxt->insn_buf) )
            {
                ASSERT_UNREACHABLE();
                return X86EMUL_UNHANDLEABLE;
            }

            memcpy(&hvmemul_ctxt->insn_buf[insn_off], p_data, bytes);
            hvmemul_ctxt->insn_buf_bytes = insn_off + bytes;
        }

        return rc;
    }

    /* Hit the cache. Simple memcpy. */
    memcpy(p_data, &hvmemul_ctxt->insn_buf[insn_off], bytes);
    return X86EMUL_OKAY;
}

static int hvmemul_write(
    enum x86_segment seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);
    struct vcpu *curr = current;
    unsigned long addr, reps = 1;
    uint32_t pfec = PFEC_page_present | PFEC_write_access;
    struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;
    int rc;

    rc = hvmemul_virtual_to_linear(
        seg, offset, bytes, &reps, hvm_access_write, hvmemul_ctxt, &addr);
    if ( rc != X86EMUL_OKAY || !bytes )
        return rc;

    if ( vio->mmio_access.write_access &&
         (vio->mmio_gla == (addr & PAGE_MASK)) )
        return hvmemul_linear_mmio_write(addr, bytes, p_data, pfec, hvmemul_ctxt, 1);

    if ( (seg != x86_seg_none) &&
         (hvmemul_ctxt->seg_reg[x86_seg_ss].attr.fields.dpl == 3) )
        pfec |= PFEC_user_mode;

    rc = hvm_copy_to_guest_virt(addr, p_data, bytes, pfec);

    switch ( rc )
    {
    case HVMCOPY_okay:
        break;
    case HVMCOPY_bad_gva_to_gfn:
        return X86EMUL_EXCEPTION;
    case HVMCOPY_bad_gfn_to_mfn:
        return hvmemul_linear_mmio_write(addr, bytes, p_data, pfec, hvmemul_ctxt, 0);
    case HVMCOPY_gfn_paged_out:
    case HVMCOPY_gfn_shared:
        return X86EMUL_RETRY;
    default:
        return X86EMUL_UNHANDLEABLE;
    }

    return X86EMUL_OKAY;
}

static int hvmemul_write_discard(
    enum x86_segment seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    /* Discarding the write. */
    return X86EMUL_OKAY;
}

static int hvmemul_rep_ins_discard(
    uint16_t src_port,
    enum x86_segment dst_seg,
    unsigned long dst_offset,
    unsigned int bytes_per_rep,
    unsigned long *reps,
    struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_OKAY;
}

static int hvmemul_rep_movs_discard(
   enum x86_segment src_seg,
   unsigned long src_offset,
   enum x86_segment dst_seg,
   unsigned long dst_offset,
   unsigned int bytes_per_rep,
   unsigned long *reps,
   struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_OKAY;
}

static int hvmemul_rep_stos_discard(
    void *p_data,
    enum x86_segment seg,
    unsigned long offset,
    unsigned int bytes_per_rep,
    unsigned long *reps,
    struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_OKAY;
}

static int hvmemul_rep_outs_discard(
    enum x86_segment src_seg,
    unsigned long src_offset,
    uint16_t dst_port,
    unsigned int bytes_per_rep,
    unsigned long *reps,
    struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_OKAY;
}

static int hvmemul_cmpxchg_discard(
    enum x86_segment seg,
    unsigned long offset,
    void *p_old,
    void *p_new,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_OKAY;
}

static int hvmemul_read_io_discard(
    unsigned int port,
    unsigned int bytes,
    unsigned long *val,
    struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_OKAY;
}

static int hvmemul_write_io_discard(
    unsigned int port,
    unsigned int bytes,
    unsigned long val,
    struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_OKAY;
}

static int hvmemul_write_msr_discard(
    unsigned int reg,
    uint64_t val,
    struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_OKAY;
}

static int hvmemul_wbinvd_discard(
    struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_OKAY;
}

static int hvmemul_cmpxchg(
    enum x86_segment seg,
    unsigned long offset,
    void *p_old,
    void *p_new,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    /* Fix this in case the guest is really relying on r-m-w atomicity. */
    return hvmemul_write(seg, offset, p_new, bytes, ctxt);
}

static int hvmemul_rep_ins(
    uint16_t src_port,
    enum x86_segment dst_seg,
    unsigned long dst_offset,
    unsigned int bytes_per_rep,
    unsigned long *reps,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);
    unsigned long addr;
    uint32_t pfec = PFEC_page_present | PFEC_write_access;
    paddr_t gpa;
    p2m_type_t p2mt;
    int rc;

    rc = hvmemul_virtual_to_linear(
        dst_seg, dst_offset, bytes_per_rep, reps, hvm_access_write,
        hvmemul_ctxt, &addr);
    if ( rc != X86EMUL_OKAY )
        return rc;

    if ( hvmemul_ctxt->seg_reg[x86_seg_ss].attr.fields.dpl == 3 )
        pfec |= PFEC_user_mode;

    rc = hvmemul_linear_to_phys(
        addr, &gpa, bytes_per_rep, reps, pfec, hvmemul_ctxt);
    if ( rc != X86EMUL_OKAY )
        return rc;

    (void) get_gfn_query_unlocked(current->domain, gpa >> PAGE_SHIFT, &p2mt);
    if ( p2mt == p2m_mmio_direct || p2mt == p2m_mmio_dm )
        return X86EMUL_UNHANDLEABLE;

    return hvmemul_do_pio_addr(src_port, reps, bytes_per_rep, IOREQ_READ,
                               !!(ctxt->regs->eflags & X86_EFLAGS_DF), gpa);
}

static int hvmemul_rep_outs_set_context(
    enum x86_segment src_seg,
    unsigned long src_offset,
    uint16_t dst_port,
    unsigned int bytes_per_rep,
    unsigned long *reps,
    struct x86_emulate_ctxt *ctxt)
{
    unsigned int bytes = *reps * bytes_per_rep;
    char *buf;
    int rc;

    buf = xmalloc_array(char, bytes);

    if ( buf == NULL )
        return X86EMUL_UNHANDLEABLE;

    rc = set_context_data(buf, bytes);

    if ( rc == X86EMUL_OKAY )
        rc = hvmemul_do_pio_buffer(dst_port, bytes, IOREQ_WRITE, buf);

    xfree(buf);

    return rc;
}

static int hvmemul_rep_outs(
    enum x86_segment src_seg,
    unsigned long src_offset,
    uint16_t dst_port,
    unsigned int bytes_per_rep,
    unsigned long *reps,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);
    unsigned long addr;
    uint32_t pfec = PFEC_page_present;
    paddr_t gpa;
    p2m_type_t p2mt;
    int rc;

    if ( unlikely(hvmemul_ctxt->set_context) )
        return hvmemul_rep_outs_set_context(src_seg, src_offset, dst_port,
                                            bytes_per_rep, reps, ctxt);

    rc = hvmemul_virtual_to_linear(
        src_seg, src_offset, bytes_per_rep, reps, hvm_access_read,
        hvmemul_ctxt, &addr);
    if ( rc != X86EMUL_OKAY )
        return rc;

    if ( hvmemul_ctxt->seg_reg[x86_seg_ss].attr.fields.dpl == 3 )
        pfec |= PFEC_user_mode;

    rc = hvmemul_linear_to_phys(
        addr, &gpa, bytes_per_rep, reps, pfec, hvmemul_ctxt);
    if ( rc != X86EMUL_OKAY )
        return rc;

    (void) get_gfn_query_unlocked(current->domain, gpa >> PAGE_SHIFT, &p2mt);
    if ( p2mt == p2m_mmio_direct || p2mt == p2m_mmio_dm )
        return X86EMUL_UNHANDLEABLE;

    return hvmemul_do_pio_addr(dst_port, reps, bytes_per_rep, IOREQ_WRITE,
                               !!(ctxt->regs->eflags & X86_EFLAGS_DF), gpa);
}

static int hvmemul_rep_movs(
   enum x86_segment src_seg,
   unsigned long src_offset,
   enum x86_segment dst_seg,
   unsigned long dst_offset,
   unsigned int bytes_per_rep,
   unsigned long *reps,
   struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);
    struct hvm_vcpu_io *vio = &current->arch.hvm_vcpu.hvm_io;
    unsigned long saddr, daddr, bytes;
    paddr_t sgpa, dgpa;
    uint32_t pfec = PFEC_page_present;
    p2m_type_t sp2mt, dp2mt;
    int rc, df = !!(ctxt->regs->eflags & X86_EFLAGS_DF);
    char *buf;

    rc = hvmemul_virtual_to_linear(
        src_seg, src_offset, bytes_per_rep, reps, hvm_access_read,
        hvmemul_ctxt, &saddr);
    if ( rc != X86EMUL_OKAY )
        return rc;

    rc = hvmemul_virtual_to_linear(
        dst_seg, dst_offset, bytes_per_rep, reps, hvm_access_write,
        hvmemul_ctxt, &daddr);
    if ( rc != X86EMUL_OKAY )
        return rc;

    if ( hvmemul_ctxt->seg_reg[x86_seg_ss].attr.fields.dpl == 3 )
        pfec |= PFEC_user_mode;

    if ( vio->mmio_access.read_access &&
         (vio->mmio_gla == (saddr & PAGE_MASK)) &&
         /*
          * Upon initial invocation don't truncate large batches just because
          * of a hit for the translation: Doing the guest page table walk is
          * cheaper than multiple round trips through the device model. Yet
          * when processing a response we can always re-use the translation.
          */
         (vio->io_req.state == STATE_IORESP_READY ||
          ((!df || *reps == 1) &&
           PAGE_SIZE - (saddr & ~PAGE_MASK) >= *reps * bytes_per_rep)) )
        sgpa = pfn_to_paddr(vio->mmio_gpfn) | (saddr & ~PAGE_MASK);
    else
    {
        rc = hvmemul_linear_to_phys(saddr, &sgpa, bytes_per_rep, reps, pfec,
                                    hvmemul_ctxt);
        if ( rc != X86EMUL_OKAY )
            return rc;
    }

    bytes = PAGE_SIZE - (daddr & ~PAGE_MASK);
    if ( vio->mmio_access.write_access &&
         (vio->mmio_gla == (daddr & PAGE_MASK)) &&
         /* See comment above. */
         (vio->io_req.state == STATE_IORESP_READY ||
          ((!df || *reps == 1) &&
           PAGE_SIZE - (daddr & ~PAGE_MASK) >= *reps * bytes_per_rep)) )
        dgpa = pfn_to_paddr(vio->mmio_gpfn) | (daddr & ~PAGE_MASK);
    else
    {
        rc = hvmemul_linear_to_phys(daddr, &dgpa, bytes_per_rep, reps,
                                    pfec | PFEC_write_access, hvmemul_ctxt);
        if ( rc != X86EMUL_OKAY )
            return rc;
    }

    /* Check for MMIO ops */
    (void) get_gfn_query_unlocked(current->domain, sgpa >> PAGE_SHIFT, &sp2mt);
    (void) get_gfn_query_unlocked(current->domain, dgpa >> PAGE_SHIFT, &dp2mt);

    if ( sp2mt == p2m_mmio_direct || dp2mt == p2m_mmio_direct ||
         (sp2mt == p2m_mmio_dm && dp2mt == p2m_mmio_dm) )
        return X86EMUL_UNHANDLEABLE;

    if ( sp2mt == p2m_mmio_dm )
    {
        latch_linear_to_phys(vio, saddr, sgpa, 0);
        return hvmemul_do_mmio_addr(
            sgpa, reps, bytes_per_rep, IOREQ_READ, df, dgpa);
    }

    if ( dp2mt == p2m_mmio_dm )
    {
        latch_linear_to_phys(vio, daddr, dgpa, 1);
        return hvmemul_do_mmio_addr(
            dgpa, reps, bytes_per_rep, IOREQ_WRITE, df, sgpa);
    }

    /* RAM-to-RAM copy: emulate as equivalent of memmove(dgpa, sgpa, bytes). */
    bytes = *reps * bytes_per_rep;

    /* Adjust source address for reverse copy. */
    if ( df )
        sgpa -= bytes - bytes_per_rep;

    /*
     * Will first iteration copy fall within source range? If not then entire
     * copy does not corrupt itself. If so, then this is more complex than
     * can be emulated by a source-to-buffer-to-destination block copy.
     */
    if ( ((dgpa + bytes_per_rep) > sgpa) && (dgpa < (sgpa + bytes)) )
        return X86EMUL_UNHANDLEABLE;

    /* Adjust destination address for reverse copy. */
    if ( df )
        dgpa -= bytes - bytes_per_rep;

    /* Allocate temporary buffer. Fall back to slow emulation if this fails. */
    buf = xmalloc_bytes(bytes);
    if ( buf == NULL )
        return X86EMUL_UNHANDLEABLE;

    if ( unlikely(hvmemul_ctxt->set_context) )
    {
        rc = set_context_data(buf, bytes);

        if ( rc != X86EMUL_OKAY)
        {
            xfree(buf);
            return rc;
        }

        rc = HVMCOPY_okay;
    }
    else
        /*
         * We do a modicum of checking here, just for paranoia's sake and to
         * definitely avoid copying an unitialised buffer into guest address
         * space.
         */
        rc = hvm_copy_from_guest_phys(buf, sgpa, bytes);

    if ( rc == HVMCOPY_okay )
        rc = hvm_copy_to_guest_phys(dgpa, buf, bytes);

    xfree(buf);

    if ( rc == HVMCOPY_gfn_paged_out )
        return X86EMUL_RETRY;
    if ( rc == HVMCOPY_gfn_shared )
        return X86EMUL_RETRY;
    if ( rc != HVMCOPY_okay )
    {
        gdprintk(XENLOG_WARNING, "Failed memory-to-memory REP MOVS: sgpa=%"
                 PRIpaddr" dgpa=%"PRIpaddr" reps=%lu bytes_per_rep=%u\n",
                 sgpa, dgpa, *reps, bytes_per_rep);
        return X86EMUL_UNHANDLEABLE;
    }

    return X86EMUL_OKAY;
}

static int hvmemul_rep_stos(
    void *p_data,
    enum x86_segment seg,
    unsigned long offset,
    unsigned int bytes_per_rep,
    unsigned long *reps,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);
    struct hvm_vcpu_io *vio = &current->arch.hvm_vcpu.hvm_io;
    unsigned long addr, bytes;
    paddr_t gpa;
    p2m_type_t p2mt;
    bool_t df = !!(ctxt->regs->eflags & X86_EFLAGS_DF);
    int rc = hvmemul_virtual_to_linear(seg, offset, bytes_per_rep, reps,
                                       hvm_access_write, hvmemul_ctxt, &addr);

    if ( rc != X86EMUL_OKAY )
        return rc;

    bytes = PAGE_SIZE - (addr & ~PAGE_MASK);
    if ( vio->mmio_access.write_access &&
         (vio->mmio_gla == (addr & PAGE_MASK)) &&
         /* See respective comment in MOVS processing. */
         (vio->io_req.state == STATE_IORESP_READY ||
          ((!df || *reps == 1) &&
           PAGE_SIZE - (addr & ~PAGE_MASK) >= *reps * bytes_per_rep)) )
        gpa = pfn_to_paddr(vio->mmio_gpfn) | (addr & ~PAGE_MASK);
    else
    {
        uint32_t pfec = PFEC_page_present | PFEC_write_access;

        if ( hvmemul_ctxt->seg_reg[x86_seg_ss].attr.fields.dpl == 3 )
            pfec |= PFEC_user_mode;

        rc = hvmemul_linear_to_phys(addr, &gpa, bytes_per_rep, reps, pfec,
                                    hvmemul_ctxt);
        if ( rc != X86EMUL_OKAY )
            return rc;
    }

    /* Check for MMIO op */
    (void)get_gfn_query_unlocked(current->domain, gpa >> PAGE_SHIFT, &p2mt);

    switch ( p2mt )
    {
        unsigned long bytes;
        void *buf;

    default:
        /* Allocate temporary buffer. */
        for ( ; ; )
        {
            bytes = *reps * bytes_per_rep;
            buf = xmalloc_bytes(bytes);
            if ( buf || *reps <= 1 )
                break;
            *reps >>= 1;
        }

        if ( !buf )
            buf = p_data;
        else
            switch ( bytes_per_rep )
            {
                unsigned long dummy;

#define CASE(bits, suffix)                                     \
            case (bits) / 8:                                   \
                asm ( "rep stos" #suffix                       \
                      : "=m" (*(char (*)[bytes])buf),          \
                        "=D" (dummy), "=c" (dummy)             \
                      : "a" (*(const uint##bits##_t *)p_data), \
                         "1" (buf), "2" (*reps) );             \
                break
            CASE(8, b);
            CASE(16, w);
            CASE(32, l);
            CASE(64, q);
#undef CASE

            default:
                ASSERT_UNREACHABLE();
                xfree(buf);
                return X86EMUL_UNHANDLEABLE;
            }

        /* Adjust address for reverse store. */
        if ( df )
            gpa -= bytes - bytes_per_rep;

        rc = hvm_copy_to_guest_phys(gpa, buf, bytes);

        if ( buf != p_data )
            xfree(buf);

        switch ( rc )
        {
        case HVMCOPY_gfn_paged_out:
        case HVMCOPY_gfn_shared:
            return X86EMUL_RETRY;
        case HVMCOPY_okay:
            return X86EMUL_OKAY;
        }

        gdprintk(XENLOG_WARNING,
                 "Failed REP STOS: gpa=%"PRIpaddr" reps=%lu bytes_per_rep=%u\n",
                 gpa, *reps, bytes_per_rep);
        /* fall through */
    case p2m_mmio_direct:
        return X86EMUL_UNHANDLEABLE;

    case p2m_mmio_dm:
        latch_linear_to_phys(vio, addr, gpa, 1);
        return hvmemul_do_mmio_buffer(gpa, reps, bytes_per_rep, IOREQ_WRITE, df,
                                      p_data);
    }
}

static int hvmemul_read_segment(
    enum x86_segment seg,
    struct segment_register *reg,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);
    struct segment_register *sreg = hvmemul_get_seg_reg(seg, hvmemul_ctxt);

    if ( IS_ERR(sreg) )
         return -PTR_ERR(sreg);

    memcpy(reg, sreg, sizeof(struct segment_register));
    return X86EMUL_OKAY;
}

static int hvmemul_write_segment(
    enum x86_segment seg,
    struct segment_register *reg,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);
    unsigned int idx = seg;

    if ( idx >= ARRAY_SIZE(hvmemul_ctxt->seg_reg) )
        return X86EMUL_UNHANDLEABLE;

    hvmemul_ctxt->seg_reg[idx] = *reg;
    __set_bit(idx, &hvmemul_ctxt->seg_reg_accessed);
    __set_bit(idx, &hvmemul_ctxt->seg_reg_dirty);

    return X86EMUL_OKAY;
}

static int hvmemul_read_io(
    unsigned int port,
    unsigned int bytes,
    unsigned long *val,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);

    *val = 0;

    if ( unlikely(hvmemul_ctxt->set_context) )
        return set_context_data(val, bytes);

    return hvmemul_do_pio_buffer(port, bytes, IOREQ_READ, val);
}

static int hvmemul_write_io(
    unsigned int port,
    unsigned int bytes,
    unsigned long val,
    struct x86_emulate_ctxt *ctxt)
{
    return hvmemul_do_pio_buffer(port, bytes, IOREQ_WRITE, &val);
}

static int hvmemul_read_cr(
    unsigned int reg,
    unsigned long *val,
    struct x86_emulate_ctxt *ctxt)
{
    switch ( reg )
    {
    case 0:
    case 2:
    case 3:
    case 4:
        *val = current->arch.hvm_vcpu.guest_cr[reg];
        HVMTRACE_LONG_2D(CR_READ, reg, TRC_PAR_LONG(*val));
        return X86EMUL_OKAY;
    default:
        break;
    }

    return X86EMUL_UNHANDLEABLE;
}

static int hvmemul_write_cr(
    unsigned int reg,
    unsigned long val,
    struct x86_emulate_ctxt *ctxt)
{
    HVMTRACE_LONG_2D(CR_WRITE, reg, TRC_PAR_LONG(val));
    switch ( reg )
    {
    case 0:
        return hvm_set_cr0(val, 1);
    case 2:
        current->arch.hvm_vcpu.guest_cr[2] = val;
        return X86EMUL_OKAY;
    case 3:
        return hvm_set_cr3(val, 1);
    case 4:
        return hvm_set_cr4(val, 1);
    default:
        break;
    }

    return X86EMUL_UNHANDLEABLE;
}

static int hvmemul_read_msr(
    unsigned int reg,
    uint64_t *val,
    struct x86_emulate_ctxt *ctxt)
{
    return hvm_msr_read_intercept(reg, val);
}

static int hvmemul_write_msr(
    unsigned int reg,
    uint64_t val,
    struct x86_emulate_ctxt *ctxt)
{
    return hvm_msr_write_intercept(reg, val, 1);
}

static int hvmemul_wbinvd(
    struct x86_emulate_ctxt *ctxt)
{
    hvm_funcs.wbinvd_intercept();
    return X86EMUL_OKAY;
}

int hvmemul_cpuid(
    unsigned int *eax,
    unsigned int *ebx,
    unsigned int *ecx,
    unsigned int *edx,
    struct x86_emulate_ctxt *ctxt)
{
    /*
     * x86_emulate uses this function to query CPU features for its own internal
     * use. Make sure we're actually emulating CPUID before emulating CPUID
     * faulting.
     */
    if ( ctxt->opcode == X86EMUL_OPC(0x0f, 0xa2) &&
         hvm_check_cpuid_faulting(current) )
        return X86EMUL_EXCEPTION;

    hvm_funcs.cpuid_intercept(eax, ebx, ecx, edx);
    return X86EMUL_OKAY;
}

static int hvmemul_inject_hw_exception(
    uint8_t vector,
    int32_t error_code,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);

    hvmemul_ctxt->exn_pending = 1;
    hvmemul_ctxt->trap.vector = vector;
    hvmemul_ctxt->trap.type = X86_EVENTTYPE_HW_EXCEPTION;
    hvmemul_ctxt->trap.error_code = error_code;
    hvmemul_ctxt->trap.insn_len = 0;

    return X86EMUL_OKAY;
}

static int hvmemul_inject_sw_interrupt(
    enum x86_swint_type type,
    uint8_t vector,
    uint8_t insn_len,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);

    switch ( type )
    {
    case x86_swint_icebp:
        hvmemul_ctxt->trap.type = X86_EVENTTYPE_PRI_SW_EXCEPTION;
        break;

    case x86_swint_int3:
    case x86_swint_into:
        hvmemul_ctxt->trap.type = X86_EVENTTYPE_SW_EXCEPTION;
        break;

    case x86_swint_int:
        hvmemul_ctxt->trap.type = X86_EVENTTYPE_SW_INTERRUPT;
        break;

    default:
        return X86EMUL_UNHANDLEABLE;
    }

    hvmemul_ctxt->exn_pending = 1;
    hvmemul_ctxt->trap.vector = vector;
    hvmemul_ctxt->trap.error_code = HVM_DELIVER_NO_ERROR_CODE;
    hvmemul_ctxt->trap.insn_len = insn_len;

    return X86EMUL_OKAY;
}

static int hvmemul_get_fpu(
    void (*exception_callback)(void *, struct cpu_user_regs *),
    void *exception_callback_arg,
    enum x86_emulate_fpu_type type,
    struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *curr = current;

    switch ( type )
    {
    case X86EMUL_FPU_fpu:
    case X86EMUL_FPU_wait:
    case X86EMUL_FPU_mmx:
    case X86EMUL_FPU_xmm:
        break;
    case X86EMUL_FPU_ymm:
        if ( !(curr->arch.xcr0 & XSTATE_SSE) ||
             !(curr->arch.xcr0 & XSTATE_YMM) )
            return X86EMUL_UNHANDLEABLE;
        break;
    default:
        return X86EMUL_UNHANDLEABLE;
    }

    if ( !curr->fpu_dirtied )
        hvm_funcs.fpu_dirty_intercept();

    curr->arch.hvm_vcpu.fpu_exception_callback = exception_callback;
    curr->arch.hvm_vcpu.fpu_exception_callback_arg = exception_callback_arg;

    return X86EMUL_OKAY;
}

static void hvmemul_put_fpu(
    struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *curr = current;
    curr->arch.hvm_vcpu.fpu_exception_callback = NULL;
}

static int hvmemul_invlpg(
    enum x86_segment seg,
    unsigned long offset,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);
    unsigned long addr, reps = 1;
    int rc;

    rc = hvmemul_virtual_to_linear(
        seg, offset, 1, &reps, hvm_access_none, hvmemul_ctxt, &addr);

    if ( rc == X86EMUL_EXCEPTION )
    {
        /*
         * `invlpg` takes segment bases into account, but is not subject to
         * faults from segment type/limit checks, and is specified as a NOP
         * when issued on non-canonical addresses.
         *
         * hvmemul_virtual_to_linear() raises exceptions for type/limit
         * violations, so squash them.
         */
        hvmemul_ctxt->exn_pending = 0;
        hvmemul_ctxt->trap = (struct hvm_trap){};
        rc = X86EMUL_OKAY;
    }

    if ( rc == X86EMUL_OKAY )
        paging_invlpg(current, addr);

    return rc;
}

static int hvmemul_vmfunc(
    struct x86_emulate_ctxt *ctxt)
{
    int rc;

    if ( !hvm_funcs.altp2m_vcpu_emulate_vmfunc )
        return X86EMUL_UNHANDLEABLE;
    rc = hvm_funcs.altp2m_vcpu_emulate_vmfunc(ctxt->regs);
    if ( rc == X86EMUL_EXCEPTION )
        hvmemul_inject_hw_exception(TRAP_invalid_op, HVM_DELIVER_NO_ERROR_CODE,
                                    ctxt);

    return rc;
}

static const struct x86_emulate_ops hvm_emulate_ops = {
    .read          = hvmemul_read,
    .insn_fetch    = hvmemul_insn_fetch,
    .write         = hvmemul_write,
    .cmpxchg       = hvmemul_cmpxchg,
    .rep_ins       = hvmemul_rep_ins,
    .rep_outs      = hvmemul_rep_outs,
    .rep_movs      = hvmemul_rep_movs,
    .rep_stos      = hvmemul_rep_stos,
    .read_segment  = hvmemul_read_segment,
    .write_segment = hvmemul_write_segment,
    .read_io       = hvmemul_read_io,
    .write_io      = hvmemul_write_io,
    .read_cr       = hvmemul_read_cr,
    .write_cr      = hvmemul_write_cr,
    .read_msr      = hvmemul_read_msr,
    .write_msr     = hvmemul_write_msr,
    .wbinvd        = hvmemul_wbinvd,
    .cpuid         = hvmemul_cpuid,
    .inject_hw_exception = hvmemul_inject_hw_exception,
    .inject_sw_interrupt = hvmemul_inject_sw_interrupt,
    .get_fpu       = hvmemul_get_fpu,
    .put_fpu       = hvmemul_put_fpu,
    .invlpg        = hvmemul_invlpg,
    .vmfunc        = hvmemul_vmfunc,
};

static const struct x86_emulate_ops hvm_emulate_ops_no_write = {
    .read          = hvmemul_read,
    .insn_fetch    = hvmemul_insn_fetch,
    .write         = hvmemul_write_discard,
    .cmpxchg       = hvmemul_cmpxchg_discard,
    .rep_ins       = hvmemul_rep_ins_discard,
    .rep_outs      = hvmemul_rep_outs_discard,
    .rep_movs      = hvmemul_rep_movs_discard,
    .rep_stos      = hvmemul_rep_stos_discard,
    .read_segment  = hvmemul_read_segment,
    .write_segment = hvmemul_write_segment,
    .read_io       = hvmemul_read_io_discard,
    .write_io      = hvmemul_write_io_discard,
    .read_cr       = hvmemul_read_cr,
    .write_cr      = hvmemul_write_cr,
    .read_msr      = hvmemul_read_msr,
    .write_msr     = hvmemul_write_msr_discard,
    .wbinvd        = hvmemul_wbinvd_discard,
    .cpuid         = hvmemul_cpuid,
    .inject_hw_exception = hvmemul_inject_hw_exception,
    .inject_sw_interrupt = hvmemul_inject_sw_interrupt,
    .get_fpu       = hvmemul_get_fpu,
    .put_fpu       = hvmemul_put_fpu,
    .invlpg        = hvmemul_invlpg,
    .vmfunc        = hvmemul_vmfunc,
};

static int _hvm_emulate_one(struct hvm_emulate_ctxt *hvmemul_ctxt,
    const struct x86_emulate_ops *ops)
{
    const struct cpu_user_regs *regs = hvmemul_ctxt->ctxt.regs;
    struct vcpu *curr = current;
    uint32_t new_intr_shadow;
    struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;
    int rc;

    hvm_emulate_init_per_insn(hvmemul_ctxt, vio->mmio_insn,
                              vio->mmio_insn_bytes);

    vio->mmio_retry = 0;

    if ( cpu_has_vmx )
        hvmemul_ctxt->ctxt.swint_emulate = x86_swint_emulate_none;
    else if ( cpu_has_svm_nrips )
        hvmemul_ctxt->ctxt.swint_emulate = x86_swint_emulate_icebp;
    else
        hvmemul_ctxt->ctxt.swint_emulate = x86_swint_emulate_all;

    switch ( rc = x86_emulate(&hvmemul_ctxt->ctxt, ops) )
    {
    case X86EMUL_OKAY:
        if ( vio->mmio_retry )
            rc = X86EMUL_RETRY;
        /* fall through */
    default:
        vio->mmio_cache_count = 0;
        vio->mmio_insn_bytes = 0;
        break;

    case X86EMUL_RETRY:
        BUILD_BUG_ON(sizeof(vio->mmio_insn) < sizeof(hvmemul_ctxt->insn_buf));
        vio->mmio_insn_bytes = hvmemul_ctxt->insn_buf_bytes;
        memcpy(vio->mmio_insn, hvmemul_ctxt->insn_buf, vio->mmio_insn_bytes);
        break;
    }

    if ( rc != X86EMUL_OKAY )
        return rc;

    new_intr_shadow = hvmemul_ctxt->intr_shadow;

    /* MOV-SS instruction toggles MOV-SS shadow, else we just clear it. */
    if ( hvmemul_ctxt->ctxt.retire.flags.mov_ss )
        new_intr_shadow ^= HVM_INTR_SHADOW_MOV_SS;
    else
        new_intr_shadow &= ~HVM_INTR_SHADOW_MOV_SS;

    /* STI instruction toggles STI shadow, else we just clear it. */
    if ( hvmemul_ctxt->ctxt.retire.flags.sti )
        new_intr_shadow ^= HVM_INTR_SHADOW_STI;
    else
        new_intr_shadow &= ~HVM_INTR_SHADOW_STI;

    if ( hvmemul_ctxt->intr_shadow != new_intr_shadow )
    {
        hvmemul_ctxt->intr_shadow = new_intr_shadow;
        hvm_funcs.set_interrupt_shadow(curr, new_intr_shadow);
    }

    if ( hvmemul_ctxt->ctxt.retire.flags.hlt &&
         !hvm_local_events_need_delivery(curr) )
    {
        hvm_hlt(regs->eflags);
    }

    return X86EMUL_OKAY;
}

int hvm_emulate_one(
    struct hvm_emulate_ctxt *hvmemul_ctxt)
{
    return _hvm_emulate_one(hvmemul_ctxt, &hvm_emulate_ops);
}

int hvm_emulate_one_no_write(
    struct hvm_emulate_ctxt *hvmemul_ctxt)
{
    return _hvm_emulate_one(hvmemul_ctxt, &hvm_emulate_ops_no_write);
}

int hvm_emulate_one_mmio(unsigned long mfn, unsigned long gla)
{
    static const struct x86_emulate_ops hvm_intercept_ops_mmcfg = {
        .read       = x86emul_unhandleable_rw,
        .insn_fetch = hvmemul_insn_fetch,
        .write      = mmcfg_intercept_write,
        .cpuid      = hvmemul_cpuid,
    };
    static const struct x86_emulate_ops hvm_ro_emulate_ops_mmio = {
        .read       = x86emul_unhandleable_rw,
        .insn_fetch = hvmemul_insn_fetch,
        .write      = mmio_ro_emulated_write,
        .cpuid      = hvmemul_cpuid,
    };
    struct mmio_ro_emulate_ctxt mmio_ro_ctxt = { .cr2 = gla };
    struct hvm_emulate_ctxt ctxt;
    const struct x86_emulate_ops *ops;
    unsigned int seg, bdf;
    int rc;

    if ( pci_ro_mmcfg_decode(mfn, &seg, &bdf) )
    {
        mmio_ro_ctxt.seg = seg;
        mmio_ro_ctxt.bdf = bdf;
        ops = &hvm_intercept_ops_mmcfg;
    }
    else
        ops = &hvm_ro_emulate_ops_mmio;

    hvm_emulate_init_once(&ctxt, guest_cpu_user_regs());
    ctxt.ctxt.data = &mmio_ro_ctxt;
    rc = _hvm_emulate_one(&ctxt, ops);
    switch ( rc )
    {
    case X86EMUL_UNHANDLEABLE:
        hvm_dump_emulation_state(XENLOG_G_WARNING "MMCFG", &ctxt);
        break;
    case X86EMUL_EXCEPTION:
        if ( ctxt.exn_pending )
            hvm_inject_trap(&ctxt.trap);
        /* fallthrough */
    default:
        hvm_emulate_writeback(&ctxt);
    }

    return rc;
}

void hvm_emulate_one_vm_event(enum emul_kind kind, unsigned int trapnr,
    unsigned int errcode)
{
    struct hvm_emulate_ctxt ctx = {{ 0 }};
    int rc;

    hvm_emulate_init_once(&ctx, guest_cpu_user_regs());

    switch ( kind )
    {
    case EMUL_KIND_NOWRITE:
        rc = hvm_emulate_one_no_write(&ctx);
        break;
    case EMUL_KIND_SET_CONTEXT_INSN: {
        struct vcpu *curr = current;
        struct hvm_vcpu_io *vio = &curr->arch.hvm_vcpu.hvm_io;

        BUILD_BUG_ON(sizeof(vio->mmio_insn) !=
                     sizeof(curr->arch.vm_event->emul.insn.data));
        ASSERT(!vio->mmio_insn_bytes);

        /*
         * Stash insn buffer into mmio buffer here instead of ctx
         * to avoid having to add more logic to hvm_emulate_one.
         */
        vio->mmio_insn_bytes = sizeof(vio->mmio_insn);
        memcpy(vio->mmio_insn, curr->arch.vm_event->emul.insn.data,
               vio->mmio_insn_bytes);
    }
    /* Fall-through */
    default:
        ctx.set_context = (kind == EMUL_KIND_SET_CONTEXT_DATA);
        rc = hvm_emulate_one(&ctx);
    }

    switch ( rc )
    {
    case X86EMUL_RETRY:
        /*
         * This function is called when handling an EPT-related vm_event
         * reply. As such, nothing else needs to be done here, since simply
         * returning makes the current instruction cause a page fault again,
         * consistent with X86EMUL_RETRY.
         */
        return;
    case X86EMUL_UNHANDLEABLE:
        hvm_dump_emulation_state(XENLOG_G_DEBUG "Mem event", &ctx);
        hvm_inject_hw_exception(trapnr, errcode);
        break;
    case X86EMUL_EXCEPTION:
        if ( ctx.exn_pending )
            hvm_inject_trap(&ctx.trap);
        break;
    }

    hvm_emulate_writeback(&ctx);
}

void hvm_emulate_init_once(
    struct hvm_emulate_ctxt *hvmemul_ctxt,
    struct cpu_user_regs *regs)
{
    hvmemul_ctxt->intr_shadow = hvm_funcs.get_interrupt_shadow(current);
    hvmemul_ctxt->ctxt.regs = regs;
    hvmemul_ctxt->ctxt.force_writeback = 1;
    hvmemul_ctxt->seg_reg_accessed = 0;
    hvmemul_ctxt->seg_reg_dirty = 0;
    hvmemul_ctxt->set_context = 0;
    hvmemul_get_seg_reg(x86_seg_cs, hvmemul_ctxt);
    hvmemul_get_seg_reg(x86_seg_ss, hvmemul_ctxt);
}

void hvm_emulate_init_per_insn(
    struct hvm_emulate_ctxt *hvmemul_ctxt,
    const unsigned char *insn_buf,
    unsigned int insn_bytes)
{
    struct vcpu *curr = current;
    unsigned int pfec = PFEC_page_present;
    unsigned long addr;

    if ( hvm_long_mode_enabled(curr) &&
         hvmemul_ctxt->seg_reg[x86_seg_cs].attr.fields.l )
        hvmemul_ctxt->ctxt.addr_size = hvmemul_ctxt->ctxt.sp_size = 64;
    else
    {
        hvmemul_ctxt->ctxt.addr_size =
            hvmemul_ctxt->seg_reg[x86_seg_cs].attr.fields.db ? 32 : 16;
        hvmemul_ctxt->ctxt.sp_size =
            hvmemul_ctxt->seg_reg[x86_seg_ss].attr.fields.db ? 32 : 16;
    }

    if ( hvmemul_ctxt->seg_reg[x86_seg_ss].attr.fields.dpl == 3 )
        pfec |= PFEC_user_mode;

    hvmemul_ctxt->insn_buf_eip = hvmemul_ctxt->ctxt.regs->eip;
    if ( !insn_bytes )
    {
        hvmemul_ctxt->insn_buf_bytes =
            hvm_get_insn_bytes(curr, hvmemul_ctxt->insn_buf) ?:
            (hvm_virtual_to_linear_addr(x86_seg_cs,
                                        &hvmemul_ctxt->seg_reg[x86_seg_cs],
                                        hvmemul_ctxt->insn_buf_eip,
                                        sizeof(hvmemul_ctxt->insn_buf),
                                        hvm_access_insn_fetch,
                                        hvmemul_ctxt->ctxt.addr_size,
                                        &addr) &&
             hvm_fetch_from_guest_virt_nofault(hvmemul_ctxt->insn_buf, addr,
                                               sizeof(hvmemul_ctxt->insn_buf),
                                               pfec) == HVMCOPY_okay) ?
            sizeof(hvmemul_ctxt->insn_buf) : 0;
    }
    else
    {
        hvmemul_ctxt->insn_buf_bytes = insn_bytes;
        memcpy(hvmemul_ctxt->insn_buf, insn_buf, insn_bytes);
    }

    hvmemul_ctxt->exn_pending = 0;
}

void hvm_emulate_writeback(
    struct hvm_emulate_ctxt *hvmemul_ctxt)
{
    enum x86_segment seg;

    seg = find_first_bit(&hvmemul_ctxt->seg_reg_dirty,
                         ARRAY_SIZE(hvmemul_ctxt->seg_reg));

    while ( seg < ARRAY_SIZE(hvmemul_ctxt->seg_reg) )
    {
        hvm_set_segment_register(current, seg, &hvmemul_ctxt->seg_reg[seg]);
        seg = find_next_bit(&hvmemul_ctxt->seg_reg_dirty,
                            ARRAY_SIZE(hvmemul_ctxt->seg_reg),
                            seg+1);
    }
}

/*
 * Callers which pass a known in-range x86_segment can rely on the return
 * pointer being valid.  Other callers must explicitly check for errors.
 */
struct segment_register *hvmemul_get_seg_reg(
    enum x86_segment seg,
    struct hvm_emulate_ctxt *hvmemul_ctxt)
{
    unsigned int idx = seg;

    if ( idx >= ARRAY_SIZE(hvmemul_ctxt->seg_reg) )
        return ERR_PTR(-X86EMUL_UNHANDLEABLE);

    if ( !__test_and_set_bit(idx, &hvmemul_ctxt->seg_reg_accessed) )
        hvm_get_segment_register(current, idx, &hvmemul_ctxt->seg_reg[idx]);
    return &hvmemul_ctxt->seg_reg[idx];
}

static const char *guest_x86_mode_to_str(int mode)
{
    switch ( mode )
    {
    case 0:  return "Real";
    case 1:  return "v86";
    case 2:  return "16bit";
    case 4:  return "32bit";
    case 8:  return "64bit";
    default: return "Unknown";
    }
}

void hvm_dump_emulation_state(const char *prefix,
                              struct hvm_emulate_ctxt *hvmemul_ctxt)
{
    struct vcpu *curr = current;
    const char *mode_str = guest_x86_mode_to_str(hvm_guest_x86_mode(curr));
    const struct segment_register *cs =
        hvmemul_get_seg_reg(x86_seg_cs, hvmemul_ctxt);

    printk("%s emulation failed: %pv %s @ %04x:%08lx -> %*ph\n",
           prefix, curr, mode_str, cs->sel, hvmemul_ctxt->insn_buf_eip,
           hvmemul_ctxt->insn_buf_bytes, hvmemul_ctxt->insn_buf);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
