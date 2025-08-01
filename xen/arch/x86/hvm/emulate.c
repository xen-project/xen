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

#include <xen/init.h>
#include <xen/iocap.h>
#include <xen/ioreq.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/paging.h>
#include <xen/trace.h>
#include <xen/vm_event.h>
#include <xen/xvmalloc.h>

#include <asm/altp2m.h>
#include <asm/event.h>
#include <asm/i387.h>
#include <asm/xstate.h>
#include <asm/hvm/emulate.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/monitor.h>
#include <asm/hvm/support.h>
#include <asm/iocap.h>
#include <asm/vm_event.h>

/*
 * We may read or write up to m512 or up to a tile row as a number of
 * device-model transactions.
 */
struct hvm_mmio_cache {
    unsigned long gla;     /* Start of original access (e.g. insn operand). */
    unsigned int skip;     /* Offset to start of MMIO */
    unsigned int size;     /* Amount of buffer[] actually used, incl @skip. */
    unsigned int space:31; /* Allocated size of buffer[]. */
    unsigned int dir:1;
    uint8_t buffer[] __aligned(sizeof(long));
};

struct hvmemul_cache
{
    /* The cache is disabled as long as num_ents > max_ents. */
    unsigned int num_ents;
    unsigned int max_ents;
    struct {
        paddr_t gpa:PADDR_BITS;
        unsigned int :BITS_PER_LONG - PADDR_BITS - 8;
        unsigned int size:8;
        unsigned long data;
    } ents[];
};

static void hvmtrace_io_assist(const ioreq_t *p)
{
    unsigned int size, event;
    unsigned char buffer[16];

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
        if ( size == 4 )
            *(uint32_t *)&buffer[size] = p->data;
        else
            *(uint64_t *)&buffer[size] = p->data;
        size *= 2;
    }

    trace(event, size, buffer);
}

static int cf_check null_read(
    const struct hvm_io_handler *io_handler, uint64_t addr, uint32_t size,
    uint64_t *data)
{
    *data = ~0UL;
    return X86EMUL_OKAY;
}

static int cf_check null_write(
    const struct hvm_io_handler *handler, uint64_t addr, uint32_t size,
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

static int cf_check ioreq_server_read(
    const struct hvm_io_handler *io_handler, uint64_t addr, uint32_t size,
    uint64_t *data)
{
    if ( hvm_copy_from_guest_phys(data, addr, size) != HVMTRANS_okay )
        return X86EMUL_UNHANDLEABLE;

    return X86EMUL_OKAY;
}

static const struct hvm_io_ops ioreq_server_ops = {
    .read = ioreq_server_read,
    .write = null_write
};

static const struct hvm_io_handler ioreq_server_handler = {
    .ops = &ioreq_server_ops
};

/*
 * Drop all records of in-flight emulation. This is needed whenever a vCPU's
 * register state may have changed behind the emulator's back.
 */
void hvmemul_cancel(struct vcpu *v)
{
    struct hvm_vcpu_io *hvio = &v->arch.hvm.hvm_io;

    v->io.req.state = STATE_IOREQ_NONE;
    v->io.completion = VIO_no_completion;
    hvio->mmio_cache_count = 0;
    hvio->mmio_insn_bytes = 0;
    hvio->mmio_access = (struct npfec){};
    hvio->mmio_retry = false;
    hvio->g2m_ioport = NULL;

    hvmemul_cache_disable(v);
}

bool __ro_after_init opt_dom0_pf_fixup;
static int hwdom_fixup_p2m(paddr_t addr)
{
    unsigned long gfn = paddr_to_pfn(addr);
    struct domain *currd = current->domain;
    p2m_type_t type;
    mfn_t mfn;
    int rc;

    ASSERT(is_hardware_domain(currd));
    ASSERT(!altp2m_active(currd));

    if ( !iomem_access_permitted(currd, gfn, gfn) )
        return -EPERM;

    /*
     * Fixups are only applied for MMIO holes, and rely on the hardware domain
     * having identity mappings for non RAM regions (gfn == mfn).
     *
     * Much like get_page_from_l1e() for PV Dom0 does, check that the page
     * accessed is actually an MMIO one: Either its MFN is out of range, or
     * it's owned by DOM_IO.
     */
    if ( mfn_valid(_mfn(gfn)) )
    {
        struct page_info *pg = mfn_to_page(_mfn(gfn));
        const struct domain *owner = page_get_owner_and_reference(pg);

        if ( owner )
            put_page(pg);
        if ( owner != dom_io )
            return -EPERM;
    }

    mfn = get_gfn(currd, gfn, &type);
    if ( !mfn_eq(mfn, INVALID_MFN) || !p2m_is_hole(type) )
        rc = mfn_eq(mfn, _mfn(gfn)) ? -EEXIST : -ENOTEMPTY;
    else
        rc = set_mmio_p2m_entry(currd, _gfn(gfn), _mfn(gfn), 0);
    put_gfn(currd, gfn);

    return rc;
}

static int hvmemul_do_io(
    bool is_mmio, paddr_t addr, unsigned long *reps, unsigned int size,
    uint8_t dir, bool df, bool data_is_addr, uintptr_t data)
{
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    struct vcpu_io *vio = &curr->io;
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

    switch ( vio->req.state )
    {
    case STATE_IOREQ_NONE:
        break;
    case STATE_IORESP_READY:
        vio->req.state = STATE_IOREQ_NONE;
        p = vio->req;

        /* Verify the emulation request has been correctly re-issued */
        if ( (p.type != (is_mmio ? IOREQ_TYPE_COPY : IOREQ_TYPE_PIO)) ||
             (p.addr != addr) ||
             (p.size != size) ||
             (p.count > *reps) ||
             (p.dir != dir) ||
             (p.df != df) ||
             (p.data_is_ptr != data_is_addr) ||
             (data_is_addr && (p.data != data)) )
            domain_crash(currd);

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

    /*
     * Make sure that we truncate rep MMIO at any GFN boundary. This is
     * necessary to ensure that the correct device model is targetted
     * or that we correctly handle a rep op spanning MMIO and RAM.
     */
    if ( unlikely(p.count > 1) && p.type == IOREQ_TYPE_COPY )
    {
        unsigned int off = p.addr & ~PAGE_MASK;
        unsigned int tail = PAGE_SIZE - off;

        if ( tail < p.size ) /* single rep spans GFN */
            p.count = 1;
        else
            p.count = min(p.count,
                          (p.df ? (off + p.size) : tail) / p.size);
    }
    ASSERT(p.count);

    vio->req = p;
    vio->suspended = false;

    rc = hvm_io_intercept(&p);

    /*
     * p.count may have got reduced (see hvm_process_io_intercept()) - inform
     * our callers and mirror this into latched state.
     */
    ASSERT(p.count <= *reps);
    *reps = vio->req.count = p.count;

    switch ( rc )
    {
    case X86EMUL_OKAY:
        vio->req.state = STATE_IOREQ_NONE;
        break;
    case X86EMUL_UNHANDLEABLE:
    {
        /*
         * Xen isn't emulating the instruction internally, so see if there's
         * an ioreq server that can handle it.
         *
         * Rules:
         * A> PIO or MMIO accesses run through ioreq_server_select() to
         * choose the ioreq server by range. If no server is found, the access
         * is ignored.
         *
         * B> p2m_ioreq_server accesses are handled by the designated
         * ioreq server for the domain, but there are some corner cases:
         *
         *   - If the domain ioreq server is NULL, it's likely we suffer from
         *   a race with an unmap operation on the ioreq server, so re-try the
         *   instruction.
         *
         *   - If the accesss is a read, this could be part of a
         *   read-modify-write instruction, emulate the read first.
         *
         * Note: Even when an ioreq server is found, its value could become
         * stale later, because it is possible that
         *
         *   - the PIO or MMIO address is removed from the rangeset of the
         *   ioreq server, before the event is delivered to the device model.
         *
         *   - the p2m_ioreq_server type is unmapped from the ioreq server,
         *   before the event is delivered to the device model.
         *
         * However, there's no cheap approach to avoid above situations in xen,
         * so the device model side needs to check the incoming ioreq event.
         */
        struct ioreq_server *s = NULL;
        p2m_type_t p2mt = p2m_invalid;

        if ( is_mmio )
        {
            unsigned long gmfn = paddr_to_pfn(addr);

            get_gfn_query_unlocked(currd, gmfn, &p2mt);

            if ( p2mt == p2m_ioreq_server )
            {
                unsigned int flags;

                s = p2m_get_ioreq_server(currd, &flags);

                if ( s == NULL )
                {
                    rc = X86EMUL_RETRY;
                    vio->req.state = STATE_IOREQ_NONE;
                    break;
                }

                /*
                 * This is part of a read-modify-write instruction.
                 * Emulate the read part so we have the value available.
                 */
                if ( dir == IOREQ_READ )
                {
                    rc = hvm_process_io_intercept(&ioreq_server_handler, &p);
                    vio->req.state = STATE_IOREQ_NONE;
                    break;
                }
            }
        }

        if ( !s )
            s = ioreq_server_select(currd, &p);

        /* If there is no suitable backing DM, just ignore accesses */
        if ( !s )
        {
            if ( is_mmio && is_hardware_domain(currd) &&
                 /*
                  * Do not attempt to fixup write accesses to r/o MMIO regions,
                  * they are expected to be terminated by the null handler
                  * below.
                  */
                 (dir == IOREQ_READ ||
                  !rangeset_contains_singleton(mmio_ro_ranges,
                                               PFN_DOWN(addr))) )
            {
                /*
                 * PVH dom0 is likely missing MMIO mappings on the p2m, due to
                 * the incomplete information Xen has about the memory layout.
                 *
                 * Either print a message to note dom0 attempted to access an
                 * unpopulated GPA, or try to fixup the p2m by creating an
                 * identity mapping for the faulting GPA.
                 */
                if ( opt_dom0_pf_fixup )
                {
                    int inner_rc = hwdom_fixup_p2m(addr);

                    if ( !inner_rc || inner_rc == -EEXIST )
                    {
                        if ( !inner_rc )
                            gdprintk(XENLOG_DEBUG,
                                     "fixup p2m mapping for page %lx added\n",
                                     paddr_to_pfn(addr));
                        else
                            gprintk(XENLOG_INFO,
                                    "fixup p2m mapping for page %lx already present\n",
                                    paddr_to_pfn(addr));

                        rc = X86EMUL_RETRY;
                        vio->req.state = STATE_IOREQ_NONE;
                        break;
                    }

                    gprintk(XENLOG_WARNING,
                            "unable to fixup memory %s %#lx size %u: %d\n",
                            dir ? "read from" : "write to", addr, size,
                            inner_rc);
                }
                else
                    gdprintk(XENLOG_DEBUG,
                             "unhandled memory %s %#lx size %u\n",
                             dir ? "read from" : "write to", addr, size);
            }
            rc = hvm_process_io_intercept(&null_handler, &p);
            vio->req.state = STATE_IOREQ_NONE;
        }
        else
        {
            rc = ioreq_send(s, &p, 0);
            if ( rc != X86EMUL_RETRY || vio->suspended )
                vio->req.state = STATE_IOREQ_NONE;
            else if ( !ioreq_needs_completion(&vio->req) )
                rc = X86EMUL_OKAY;
        }
        break;
    }
    case X86EMUL_UNIMPLEMENTED:
        ASSERT_UNREACHABLE();
        fallthrough;
    default:
        BUG();
    }

    ASSERT(rc != X86EMUL_UNIMPLEMENTED);

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
    bool is_mmio, paddr_t addr, unsigned long *reps, unsigned int size,
    uint8_t dir, bool df, void *buffer)
{
    int rc;

    BUG_ON(buffer == NULL);

    rc = hvmemul_do_io(is_mmio, addr, reps, size, dir, df, 0,
                       (uintptr_t)buffer);

    ASSERT(rc != X86EMUL_UNIMPLEMENTED);

    if ( rc == X86EMUL_UNHANDLEABLE && dir == IOREQ_READ )
        memset(buffer, 0xff, size);

    return rc;
}

static int hvmemul_acquire_page(unsigned long gmfn, struct page_info **page)
{
    struct domain *curr_d = current->domain;
    p2m_type_t p2mt;

    switch ( check_get_page_from_gfn(curr_d, _gfn(gmfn), false, &p2mt,
                                     page) )
    {
    case 0:
        break;

    case -EAGAIN:
        return X86EMUL_RETRY;

    default:
        ASSERT_UNREACHABLE();
        fallthrough;
    case -EINVAL:
        return X86EMUL_UNHANDLEABLE;
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
    bool is_mmio, paddr_t addr, unsigned long *reps,
    unsigned int size, uint8_t dir, bool df, paddr_t ram_gpa)
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

    ASSERT(rc != X86EMUL_UNIMPLEMENTED);

    if ( rc == X86EMUL_OKAY )
        v->arch.hvm.hvm_io.mmio_retry = (count < *reps);

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
                               bool df,
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
                                  bool df,
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
                                bool df,
                                paddr_t ram_gpa)
{
    return hvmemul_do_io_addr(1, mmio_gpa, reps, size, dir, df, ram_gpa);
}

/*
 * Map the frame(s) covering an individual linear access, for writeable
 * access.  May return NULL for MMIO, or ERR_PTR(~X86EMUL_*) for other errors
 * including ERR_PTR(~X86EMUL_OKAY) for write-discard mappings.
 *
 * In debug builds, map() checks that each slot in hvmemul_ctxt->mfn[] is
 * clean before use, and poisions unused slots with INVALID_MFN.
 */
static void *hvmemul_map_linear_addr(
    unsigned long linear, unsigned int bytes, uint32_t pfec,
    struct hvm_emulate_ctxt *hvmemul_ctxt)
{
    struct vcpu *curr = current;
    void *err, *mapping;
    unsigned int nr_frames = ((linear + bytes - !!bytes) >> PAGE_SHIFT) -
        (linear >> PAGE_SHIFT) + 1;
    unsigned int i;
    gfn_t gfn;

    /*
     * mfn points to the next free slot.  All used slots have a page reference
     * held on them.
     */
    mfn_t *mfn = &hvmemul_ctxt->mfn[0];

    /*
     * The maximum access size depends on the number of adjacent mfns[] which
     * can be vmap()'d, accouting for possible misalignment within the region.
     * The higher level emulation callers are responsible for ensuring that
     * mfns[] is large enough for the requested access size.
     */
    if ( nr_frames > ARRAY_SIZE(hvmemul_ctxt->mfn) )
    {
        ASSERT_UNREACHABLE();
        goto unhandleable;
    }

    for ( i = 0; i < nr_frames; i++ )
    {
        enum hvm_translation_result res;
        struct page_info *page;
        pagefault_info_t pfinfo;
        p2m_type_t p2mt;
        unsigned long addr = i ? (linear + (i << PAGE_SHIFT)) & PAGE_MASK : linear;

        if ( hvmemul_ctxt->ctxt.addr_size < 64 )
            addr = (uint32_t)addr;

        /* Error checking.  Confirm that the current slot is clean. */
        ASSERT(mfn_x(*mfn) == 0);

        res = hvm_translate_get_page(curr, addr, true, pfec,
                                     &pfinfo, &page, &gfn, &p2mt);

        switch ( res )
        {
        case HVMTRANS_okay:
            break;

        case HVMTRANS_bad_linear_to_gfn:
            ASSERT(pfinfo.linear == addr);
            x86_emul_pagefault(pfinfo.ec, pfinfo.linear, &hvmemul_ctxt->ctxt);
            err = ERR_PTR(~X86EMUL_EXCEPTION);
            goto out;

        case HVMTRANS_bad_gfn_to_mfn:
            err = NULL;
            goto out;

        case HVMTRANS_need_retry:
            /*
             * hvm_translate_get_page() does not currently return
             * HVMTRANS_need_retry.
             */
            ASSERT_UNREACHABLE();
            /* fall through */
        case HVMTRANS_gfn_paged_out:
        case HVMTRANS_gfn_shared:
            err = ERR_PTR(~X86EMUL_RETRY);
            goto out;

        default:
            goto unhandleable;
        }

        *mfn++ = page_to_mfn(page);

        if ( pfec & PFEC_write_access )
        {
            if ( p2m_is_discard_write(p2mt) )
            {
                err = ERR_PTR(~X86EMUL_OKAY);
                goto out;
            }

            if ( p2mt == p2m_ioreq_server )
            {
                err = NULL;
                goto out;
            }

            ASSERT(p2mt == p2m_ram_logdirty || !p2m_is_readonly(p2mt));
        }

        if ( unlikely(curr->arch.vm_event) &&
             curr->arch.vm_event->send_event &&
             hvm_monitor_check_p2m(addr, gfn, pfec, npfec_kind_with_gla) )
        {
            err = ERR_PTR(~X86EMUL_RETRY);
            goto out;
        }
    }

    /* Entire access within a single frame? */
    if ( nr_frames == 1 )
        mapping = map_domain_page(hvmemul_ctxt->mfn[0]);
    /* Multiple frames? Need to vmap(). */
    else if ( (mapping = vmap(hvmemul_ctxt->mfn,
                              nr_frames)) == NULL )
        goto unhandleable;

#ifndef NDEBUG /* Poision unused mfn[]s with INVALID_MFN. */
    while ( mfn < hvmemul_ctxt->mfn + ARRAY_SIZE(hvmemul_ctxt->mfn) )
    {
        ASSERT(mfn_x(*mfn) == 0);
        *mfn++ = INVALID_MFN;
    }
#endif
    return mapping + (linear & ~PAGE_MASK);

 unhandleable:
    err = ERR_PTR(~X86EMUL_UNHANDLEABLE);

 out:
    /* Drop all held references. */
    while ( mfn-- > hvmemul_ctxt->mfn )
    {
        put_page(mfn_to_page(*mfn));
#ifndef NDEBUG /* Clean slot for a subsequent map()'s error checking. */
        *mfn = _mfn(0);
#endif
    }

    return err;
}

static void hvmemul_unmap_linear_addr(
    void *mapping, unsigned long linear, unsigned int bytes,
    struct hvm_emulate_ctxt *hvmemul_ctxt)
{
    struct domain *currd = current->domain;
    unsigned int nr_frames = ((linear + bytes - !!bytes) >> PAGE_SHIFT) -
        (linear >> PAGE_SHIFT) + 1;
    unsigned int i;
    mfn_t *mfn = &hvmemul_ctxt->mfn[0];

    if ( nr_frames == 1 )
        unmap_domain_page(mapping);
    else
        vunmap(mapping);

    for ( i = 0; i < nr_frames; i++ )
    {
        ASSERT(mfn_x(*mfn) && mfn_valid(*mfn));
        paging_mark_dirty(currd, *mfn);
        put_page(mfn_to_page(*mfn));

        *mfn++ = _mfn(0); /* Clean slot for map()'s error checking. */
    }

#ifndef NDEBUG /* Check (and clean) all unused mfns. */
    while ( mfn < hvmemul_ctxt->mfn + ARRAY_SIZE(hvmemul_ctxt->mfn) )
    {
        ASSERT(mfn_eq(*mfn, INVALID_MFN));
        *mfn++ = _mfn(0);
    }
#endif
}

/*
 * Convert addr from linear to physical form, valid over the range
 * [addr, addr + *reps * bytes_per_rep). *reps is adjusted according to
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
    if ( !(curr->arch.hvm.guest_cr[0] & X86_CR0_PG) )
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
        {
            *reps = one_rep;
            return rc;
        }
        pfn = _paddr >> PAGE_SHIFT;
    }
    else if ( (pfn = paging_gva_to_gfn(curr, addr, &pfec)) == gfn_x(INVALID_GFN) )
    {
        if ( pfec & (PFEC_page_paged | PFEC_page_shared) )
            return X86EMUL_RETRY;
        *reps = 0;
        x86_emul_pagefault(pfec, addr, &hvmemul_ctxt->ctxt);
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
                *reps = 0;
                x86_emul_pagefault(pfec, addr & PAGE_MASK, &hvmemul_ctxt->ctxt);
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
    unsigned long *reps_p,
    enum hvm_access_type access_type,
    struct hvm_emulate_ctxt *hvmemul_ctxt,
    unsigned long *linear)
{
    struct segment_register *reg;
    int okay;
    unsigned long reps = 1;

    if ( seg == x86_seg_none || seg == x86_seg_sys )
    {
        *linear = offset;
        return X86EMUL_OKAY;
    }

    if ( reps_p )
    {
        unsigned long max_reps = 4096;

        /*
         * If introspection has been enabled for this domain, and we're
         * emulating because a vm_reply asked us to (i.e. not doing regular IO)
         * reps should be at most 1, since optimization might otherwise cause a
         * single vm_event being triggered for repeated writes to a whole page.
         */
        if ( unlikely(current->domain->arch.mem_access_emulate_each_rep) &&
             current->arch.vm_event->emulate_flags != 0 )
           max_reps = 1;

        /*
         * Clip repetitions to avoid overflow when multiplying by
         * @bytes_per_rep. The chosen maximum is very conservative but it's
         * what we use in hvmemul_linear_to_phys() so there is no point in
         * using a larger value.
         */
        reps = *reps_p = min_t(unsigned long, *reps_p, max_reps);
    }

    reg = hvmemul_get_seg_reg(seg, hvmemul_ctxt);
    if ( IS_ERR(reg) )
        return -PTR_ERR(reg);

    if ( (hvmemul_ctxt->ctxt.regs->eflags & X86_EFLAGS_DF) && (reps > 1) )
    {
        /*
         * x86_emulate() clips the repetition count to ensure we don't wrap
         * the effective-address index register. Hence this assertion holds.
         */
        ASSERT(offset >= ((reps - 1) * bytes_per_rep));
        okay = hvm_virtual_to_linear_addr(
            seg, reg, offset - (reps - 1) * bytes_per_rep,
            reps * bytes_per_rep, access_type,
            hvmemul_get_seg_reg(x86_seg_cs, hvmemul_ctxt), linear);
        *linear += (reps - 1) * bytes_per_rep;
        if ( hvmemul_ctxt->ctxt.addr_size != 64 )
            *linear = (uint32_t)*linear;
    }
    else
    {
        okay = hvm_virtual_to_linear_addr(
            seg, reg, offset, reps * bytes_per_rep, access_type,
            hvmemul_get_seg_reg(x86_seg_cs, hvmemul_ctxt), linear);
    }

    if ( okay )
        return X86EMUL_OKAY;

    if ( reps_p )
    {
        /* If this is a string operation, emulate each iteration separately. */
        if ( reps != 1 )
            return X86EMUL_UNHANDLEABLE;

        *reps_p = 0;
    }

    /*
     * Leave exception injection to the caller for non-user segments: We
     * neither know the exact error code to be used, nor can we easily
     * determine the kind of exception (#GP or #TS) in that case.
     */
    if ( is_x86_user_segment(seg) )
        x86_emul_hw_exception((seg == x86_seg_ss) ? X86_EXC_SS : X86_EXC_GP,
                              0, &hvmemul_ctxt->ctxt);

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
    if ( (gpa & ~PAGE_MASK) + size > PAGE_SIZE )
    {
        ASSERT_UNREACHABLE();
        return X86EMUL_UNHANDLEABLE;
    }

    /* Accesses must not overflow the cache's buffer. */
    if ( offset + size > cache->space )
    {
        ASSERT_UNREACHABLE();
        return X86EMUL_UNHANDLEABLE;
    }

    /* Accesses must not be to the unused leading space. */
    if ( offset < cache->skip )
    {
        ASSERT_UNREACHABLE();
        return X86EMUL_UNHANDLEABLE;
    }

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
 * of the same instruction will not access the exact same MMIO region
 * more than once in exactly the same way (if it does, the accesses will
 * be "folded"). Hence we can deal with re-emulation (for secondary or
 * subsequent cycles) by looking up the result of previous I/O in a cache
 * indexed by linear address and access type.
 */
static struct hvm_mmio_cache *hvmemul_find_mmio_cache(
    struct hvm_vcpu_io *hvio, unsigned long gla, uint8_t dir,
    unsigned int skip)
{
    unsigned int i;
    struct hvm_mmio_cache *cache;

    for ( i = 0; i < hvio->mmio_cache_count; i ++ )
    {
        cache = hvio->mmio_cache[i];

        if ( gla == cache->gla &&
             dir == cache->dir )
            return cache;
    }

    /*
     * Bail if a new entry shouldn't be allocated, relying on ->space having
     * the same value for all entries.
     */
    if ( skip >= hvio->mmio_cache[0]->space )
        return NULL;

    i = hvio->mmio_cache_count;
    if( i == ARRAY_SIZE(hvio->mmio_cache) )
        return NULL;

    ++hvio->mmio_cache_count;

    cache = hvio->mmio_cache[i];
    memset(cache->buffer, 0, cache->space);

    cache->gla = gla;
    cache->skip = skip;
    cache->size = skip;
    cache->dir = dir;

    return cache;
}

static void latch_linear_to_phys(struct hvm_vcpu_io *hvio, unsigned long gla,
                                 unsigned long gpa, bool write)
{
    if ( hvio->mmio_access.gla_valid )
        return;

    hvio->mmio_gla = gla & PAGE_MASK;
    hvio->mmio_gpfn = PFN_DOWN(gpa);
    hvio->mmio_access = (struct npfec){ .gla_valid = 1,
                                        .read_access = 1,
                                        .write_access = write };
}

static int hvmemul_linear_mmio_access(
    unsigned long gla, unsigned int size, uint8_t dir, void *buffer,
    uint32_t pfec, struct hvm_emulate_ctxt *hvmemul_ctxt,
    unsigned long start_gla, bool known_gpfn)
{
    struct hvm_vcpu_io *hvio = &current->arch.hvm.hvm_io;
    unsigned long offset = gla & ~PAGE_MASK;
    unsigned int buffer_offset = gla - start_gla;
    struct hvm_mmio_cache *cache = hvmemul_find_mmio_cache(hvio, start_gla,
                                                           dir, buffer_offset);
    paddr_t gpa;
    unsigned long one_rep = 1;
    int rc;

    if ( cache == NULL )
        return X86EMUL_UNHANDLEABLE;

    if ( size + offset > PAGE_SIZE )
    {
        ASSERT_UNREACHABLE();
        return X86EMUL_UNHANDLEABLE;
    }

    if ( known_gpfn )
        gpa = pfn_to_paddr(hvio->mmio_gpfn) | offset;
    else
    {
        rc = hvmemul_linear_to_phys(gla, &gpa, size, &one_rep, pfec,
                                    hvmemul_ctxt);
        if ( rc != X86EMUL_OKAY )
            return rc;

        latch_linear_to_phys(hvio, gla, gpa, dir == IOREQ_WRITE);
    }

    return hvmemul_phys_mmio_access(cache, gpa, size, dir, buffer,
                                    buffer_offset);
}

static inline int hvmemul_linear_mmio_read(
    unsigned long gla, unsigned int size, void *buffer,
    uint32_t pfec, struct hvm_emulate_ctxt *hvmemul_ctxt,
    unsigned long start_gla, bool translate)
{
    return hvmemul_linear_mmio_access(gla, size, IOREQ_READ, buffer, pfec,
                                      hvmemul_ctxt, start_gla, translate);
}

static inline int hvmemul_linear_mmio_write(
    unsigned long gla, unsigned int size, void *buffer,
    uint32_t pfec, struct hvm_emulate_ctxt *hvmemul_ctxt,
    unsigned long start_gla, bool translate)
{
    return hvmemul_linear_mmio_access(gla, size, IOREQ_WRITE, buffer, pfec,
                                      hvmemul_ctxt, start_gla, translate);
}

static bool known_gla(unsigned long addr, unsigned int bytes, uint32_t pfec)
{
    const struct hvm_vcpu_io *hvio = &current->arch.hvm.hvm_io;

    if ( pfec & PFEC_write_access )
    {
        if ( !hvio->mmio_access.write_access )
            return false;
    }
    else if ( pfec & PFEC_insn_fetch )
    {
        if ( !hvio->mmio_access.insn_fetch )
            return false;
    }
    else if ( !hvio->mmio_access.read_access )
            return false;

    return (hvio->mmio_gla == (addr & PAGE_MASK) &&
            (addr & ~PAGE_MASK) + bytes <= PAGE_SIZE);
}

static int linear_read(unsigned long addr, unsigned int bytes, void *p_data,
                       uint32_t pfec, struct hvm_emulate_ctxt *hvmemul_ctxt)
{
    pagefault_info_t pfinfo;
    struct hvm_vcpu_io *hvio = &current->arch.hvm.hvm_io;
    void *buffer = p_data;
    unsigned long start = addr;
    unsigned int offset = addr & ~PAGE_MASK;
    const struct hvm_mmio_cache *cache;
    int rc;

    if ( offset + bytes > PAGE_SIZE )
    {
        unsigned int part1 = PAGE_SIZE - offset;

        /* Split the access at the page boundary. */
        rc = linear_read(addr, part1, p_data, pfec, hvmemul_ctxt);
        if ( rc != X86EMUL_OKAY )
            return rc;

        addr += part1;
        bytes -= part1;
        p_data += part1;
    }

    rc = HVMTRANS_bad_gfn_to_mfn;

    /*
     * If there is an MMIO cache entry for the access then we must be re-issuing
     * an access that was previously handled as MMIO. Thus it is imperative that
     * we handle this access in the same way to guarantee completion and hence
     * clean up any interim state.
     *
     * Care must be taken, however, to correctly deal with crossing RAM/MMIO or
     * MMIO/RAM boundaries. While we want to use a single cache entry (tagged
     * by the starting linear address), we need to continue issuing (i.e. also
     * upon replay) the RAM access for anything that's ahead of or past MMIO,
     * i.e. in RAM.
     */
    cache = hvmemul_find_mmio_cache(hvio, start, IOREQ_READ, ~0);
    if ( !cache ||
         addr + bytes <= start + cache->skip ||
         addr >= start + cache->size )
        rc = hvm_copy_from_guest_linear(p_data, addr, bytes, pfec, &pfinfo);

    switch ( rc )
    {
    case HVMTRANS_okay:
        return X86EMUL_OKAY;

    case HVMTRANS_bad_linear_to_gfn:
        x86_emul_pagefault(pfinfo.ec, pfinfo.linear, &hvmemul_ctxt->ctxt);
        return X86EMUL_EXCEPTION;

    case HVMTRANS_bad_gfn_to_mfn:
        if ( pfec & PFEC_insn_fetch )
            return X86EMUL_UNHANDLEABLE;

        return hvmemul_linear_mmio_read(addr, bytes, buffer, pfec,
                                        hvmemul_ctxt, start,
                                        known_gla(addr, bytes, pfec));

    case HVMTRANS_gfn_paged_out:
    case HVMTRANS_gfn_shared:
    case HVMTRANS_need_retry:
        return X86EMUL_RETRY;
    }

    return X86EMUL_UNHANDLEABLE;
}

static int linear_write(unsigned long addr, unsigned int bytes, void *p_data,
                        uint32_t pfec, struct hvm_emulate_ctxt *hvmemul_ctxt)
{
    pagefault_info_t pfinfo;
    struct hvm_vcpu_io *hvio = &current->arch.hvm.hvm_io;
    void *buffer = p_data;
    unsigned long start = addr;
    unsigned int offset = addr & ~PAGE_MASK;
    const struct hvm_mmio_cache *cache;
    int rc;

    if ( offset + bytes > PAGE_SIZE )
    {
        unsigned int part1 = PAGE_SIZE - offset;

        /* Split the access at the page boundary. */
        rc = linear_write(addr, part1, p_data, pfec, hvmemul_ctxt);
        if ( rc != X86EMUL_OKAY )
            return rc;

        addr += part1;
        bytes -= part1;
        p_data += part1;
    }

    rc = HVMTRANS_bad_gfn_to_mfn;

    /* See commentary in linear_read(). */
    cache = hvmemul_find_mmio_cache(hvio, start, IOREQ_WRITE, ~0);
    if ( !cache ||
         addr + bytes <= start + cache->skip ||
         addr >= start + cache->size )
        rc = hvm_copy_to_guest_linear(addr, p_data, bytes, pfec, &pfinfo);

    switch ( rc )
    {
    case HVMTRANS_okay:
        return X86EMUL_OKAY;

    case HVMTRANS_bad_linear_to_gfn:
        x86_emul_pagefault(pfinfo.ec, pfinfo.linear, &hvmemul_ctxt->ctxt);
        return X86EMUL_EXCEPTION;

    case HVMTRANS_bad_gfn_to_mfn:
        return hvmemul_linear_mmio_write(addr, bytes, buffer, pfec,
                                         hvmemul_ctxt, start,
                                         known_gla(addr, bytes, pfec));

    case HVMTRANS_gfn_paged_out:
    case HVMTRANS_gfn_shared:
    case HVMTRANS_need_retry:
        return X86EMUL_RETRY;
    }

    return X86EMUL_UNHANDLEABLE;
}

static int __hvmemul_read(
    enum x86_segment seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    enum hvm_access_type access_type,
    struct hvm_emulate_ctxt *hvmemul_ctxt)
{
    unsigned long addr;
    uint32_t pfec = PFEC_page_present;
    int rc;

    if ( is_x86_system_segment(seg) )
        pfec |= PFEC_implicit;
    else if ( hvmemul_ctxt->seg_reg[x86_seg_ss].dpl == 3 )
        pfec |= PFEC_user_mode;
    if ( access_type == hvm_access_insn_fetch )
        pfec |= PFEC_insn_fetch;

    rc = hvmemul_virtual_to_linear(
        seg, offset, bytes, NULL, access_type, hvmemul_ctxt, &addr);
    if ( rc != X86EMUL_OKAY || !bytes )
        return rc;

    return linear_read(addr, bytes, p_data, pfec, hvmemul_ctxt);
}

static int cf_check hvmemul_read(
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

int cf_check hvmemul_insn_fetch(
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
        int rc = __hvmemul_read(x86_seg_cs, offset, p_data, bytes,
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

static int cf_check hvmemul_write(
    enum x86_segment seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);
    unsigned long addr;
    uint32_t pfec = PFEC_page_present | PFEC_write_access;
    int rc;
    void *mapping = NULL;

    if ( is_x86_system_segment(seg) )
        pfec |= PFEC_implicit;
    else if ( hvmemul_ctxt->seg_reg[x86_seg_ss].dpl == 3 )
        pfec |= PFEC_user_mode;

    rc = hvmemul_virtual_to_linear(
        seg, offset, bytes, NULL, hvm_access_write, hvmemul_ctxt, &addr);
    if ( rc != X86EMUL_OKAY || !bytes )
        return rc;

    if ( !known_gla(addr, bytes, pfec) )
    {
        mapping = hvmemul_map_linear_addr(addr, bytes, pfec, hvmemul_ctxt);
        if ( IS_ERR(mapping) )
             return ~PTR_ERR(mapping);
    }

    if ( !mapping )
        return linear_write(addr, bytes, p_data, pfec, hvmemul_ctxt);

    /* Where possible use single (and hence generally atomic) MOV insns. */
    switch ( bytes )
    {
    case 2: write_u16_atomic(mapping, *(uint16_t *)p_data); break;
    case 4: write_u32_atomic(mapping, *(uint32_t *)p_data); break;
    case 8: write_u64_atomic(mapping, *(uint64_t *)p_data); break;
    default: memcpy(mapping, p_data, bytes);                break;
    }

    hvmemul_unmap_linear_addr(mapping, addr, bytes, hvmemul_ctxt);

    return X86EMUL_OKAY;
}

static int cf_check hvmemul_rmw(
    enum x86_segment seg,
    unsigned long offset,
    unsigned int bytes,
    uint32_t *eflags,
    struct x86_emulate_state *state,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);
    unsigned long addr;
    uint32_t pfec = PFEC_page_present | PFEC_write_access;
    int rc;
    void *mapping = NULL;

    rc = hvmemul_virtual_to_linear(
        seg, offset, bytes, NULL, hvm_access_write, hvmemul_ctxt, &addr);
    if ( rc != X86EMUL_OKAY || !bytes )
        return rc;

    if ( is_x86_system_segment(seg) )
        pfec |= PFEC_implicit;
    else if ( hvmemul_ctxt->seg_reg[x86_seg_ss].dpl == 3 )
        pfec |= PFEC_user_mode;

    if ( !known_gla(addr, bytes, pfec) )
    {
        mapping = hvmemul_map_linear_addr(addr, bytes, pfec, hvmemul_ctxt);
        if ( IS_ERR(mapping) )
            return ~PTR_ERR(mapping);
    }

    if ( mapping )
    {
        rc = x86_emul_rmw(mapping, bytes, eflags, state, ctxt);
        hvmemul_unmap_linear_addr(mapping, addr, bytes, hvmemul_ctxt);
    }
    else
    {
        unsigned long data = 0;

        if ( bytes > sizeof(data) )
            return X86EMUL_UNHANDLEABLE;
        rc = linear_read(addr, bytes, &data, pfec, hvmemul_ctxt);
        if ( rc == X86EMUL_OKAY )
            rc = x86_emul_rmw(&data, bytes, eflags, state, ctxt);
        if ( rc == X86EMUL_OKAY )
            rc = linear_write(addr, bytes, &data, pfec, hvmemul_ctxt);
    }

    return rc;
}

static int cf_check hvmemul_blk(
    enum x86_segment seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    uint32_t *eflags,
    struct x86_emulate_state *state,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);
    unsigned long addr;
    uint32_t pfec = PFEC_page_present;
    int rc;
    void *mapping = NULL;

    rc = hvmemul_virtual_to_linear(
        seg, offset, bytes, NULL, hvm_access_write, hvmemul_ctxt, &addr);
    if ( rc != X86EMUL_OKAY || !bytes )
        return rc;

    if ( x86_insn_is_mem_write(state, ctxt) )
        pfec |= PFEC_write_access;

    if ( is_x86_system_segment(seg) )
        pfec |= PFEC_implicit;
    else if ( hvmemul_ctxt->seg_reg[x86_seg_ss].dpl == 3 )
        pfec |= PFEC_user_mode;

    mapping = hvmemul_map_linear_addr(addr, bytes, pfec, hvmemul_ctxt);
    if ( IS_ERR(mapping) )
        return ~PTR_ERR(mapping);
    if ( !mapping )
        return X86EMUL_UNHANDLEABLE;

    rc = x86_emul_blk(mapping, p_data, bytes, eflags, state, ctxt);
    hvmemul_unmap_linear_addr(mapping, addr, bytes, hvmemul_ctxt);

    return rc;
}

static int cf_check hvmemul_write_discard(
    enum x86_segment seg,
    unsigned long offset,
    void *p_data,
    unsigned int bytes,
    struct x86_emulate_ctxt *ctxt)
{
    /* Discarding the write. */
    return X86EMUL_OKAY;
}

static int cf_check hvmemul_rep_ins_discard(
    uint16_t src_port,
    enum x86_segment dst_seg,
    unsigned long dst_offset,
    unsigned int bytes_per_rep,
    unsigned long *reps,
    struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_OKAY;
}

static int cf_check hvmemul_rep_movs_discard(
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

static int cf_check hvmemul_rep_stos_discard(
    void *p_data,
    enum x86_segment seg,
    unsigned long offset,
    unsigned int bytes_per_rep,
    unsigned long *reps,
    struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_OKAY;
}

static int cf_check hvmemul_rep_outs_discard(
    enum x86_segment src_seg,
    unsigned long src_offset,
    uint16_t dst_port,
    unsigned int bytes_per_rep,
    unsigned long *reps,
    struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_OKAY;
}

static int cf_check hvmemul_cmpxchg_discard(
    enum x86_segment seg,
    unsigned long offset,
    void *p_old,
    void *p_new,
    unsigned int bytes,
    bool lock,
    struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_OKAY;
}

static int cf_check hvmemul_read_io_discard(
    unsigned int port,
    unsigned int bytes,
    unsigned long *val,
    struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_OKAY;
}

static int cf_check hvmemul_write_io_discard(
    unsigned int port,
    unsigned int bytes,
    unsigned long val,
    struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_OKAY;
}

static int cf_check hvmemul_write_msr_discard(
    unsigned int reg,
    uint64_t val,
    struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_OKAY;
}

static int cf_check hvmemul_cache_op_discard(
    enum x86emul_cache_op op,
    enum x86_segment seg,
    unsigned long offset,
    struct x86_emulate_ctxt *ctxt)
{
    return X86EMUL_OKAY;
}

static int cf_check hvmemul_cmpxchg(
    enum x86_segment seg,
    unsigned long offset,
    void *p_old,
    void *p_new,
    unsigned int bytes,
    bool lock,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);
    unsigned long addr;
    uint32_t pfec = PFEC_page_present | PFEC_write_access;
    int rc;
    void *mapping = NULL;

    rc = hvmemul_virtual_to_linear(
        seg, offset, bytes, NULL, hvm_access_write, hvmemul_ctxt, &addr);
    if ( rc != X86EMUL_OKAY )
        return rc;

    if ( is_x86_system_segment(seg) )
        pfec |= PFEC_implicit;
    else if ( hvmemul_ctxt->seg_reg[x86_seg_ss].dpl == 3 )
        pfec |= PFEC_user_mode;

    if ( !known_gla(addr, bytes, pfec) )
    {
        mapping = hvmemul_map_linear_addr(addr, bytes, pfec, hvmemul_ctxt);
        if ( IS_ERR(mapping) )
            return ~PTR_ERR(mapping);
    }

    if ( !mapping )
    {
        /* Fix this in case the guest is really relying on r-m-w atomicity. */
        return linear_write(addr, bytes, p_new, pfec, hvmemul_ctxt);
    }

    switch ( bytes )
    {
    case 1: case 2: case 4: case 8:
    {
        unsigned long old = 0, new = 0, cur;

        memcpy(&old, p_old, bytes);
        memcpy(&new, p_new, bytes);
        if ( lock )
            cur = __cmpxchg(mapping, old, new, bytes);
        else
            cur = cmpxchg_local_(mapping, old, new, bytes);
        if ( cur != old )
        {
            memcpy(p_old, &cur, bytes);
            rc = X86EMUL_CMPXCHG_FAILED;
        }
        break;
    }

    case 16:
        if ( cpu_has_cx16 )
        {
            __uint128_t *old = p_old, cur;

            if ( lock )
                cur = __cmpxchg16b(mapping, old, p_new);
            else
                cur = cmpxchg16b_local_(mapping, old, p_new);
            if ( cur != *old )
            {
                *old = cur;
                rc = X86EMUL_CMPXCHG_FAILED;
            }
        }
        else
            rc = X86EMUL_UNHANDLEABLE;
        break;

    default:
        ASSERT_UNREACHABLE();
        rc = X86EMUL_UNHANDLEABLE;
        break;
    }

    hvmemul_unmap_linear_addr(mapping, addr, bytes, hvmemul_ctxt);

    return rc;
}

static int cf_check hvmemul_validate(
    const struct x86_emulate_state *state,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);

    hvmemul_ctxt->is_mem_access = x86_insn_is_mem_access(state, ctxt);

    return !hvmemul_ctxt->validate || hvmemul_ctxt->validate(state, ctxt)
           ? X86EMUL_OKAY : X86EMUL_UNHANDLEABLE;
}

static int cf_check hvmemul_rep_ins(
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

    if ( hvmemul_ctxt->seg_reg[x86_seg_ss].dpl == 3 )
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
    uint16_t dst_port,
    unsigned int bytes_per_rep,
    unsigned long *reps)
{
    const struct arch_vm_event *ev = current->arch.vm_event;
    const uint8_t *ptr;
    unsigned int avail;
    unsigned long done;
    int rc = X86EMUL_OKAY;

    ASSERT(bytes_per_rep <= 4);
    if ( !ev )
        return X86EMUL_UNHANDLEABLE;

    ptr = ev->emul.read.data;
    avail = ev->emul.read.size;

    for ( done = 0; done < *reps; ++done )
    {
        unsigned int size = min(bytes_per_rep, avail);
        uint32_t data = 0;

        if ( done && hypercall_preempt_check() )
            break;

        memcpy(&data, ptr, size);
        avail -= size;
        ptr += size;

        rc = hvmemul_do_pio_buffer(dst_port, bytes_per_rep, IOREQ_WRITE, &data);
        if ( rc != X86EMUL_OKAY )
            break;
    }

    *reps = done;

    return rc;
}

static int cf_check hvmemul_rep_outs(
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
        return hvmemul_rep_outs_set_context(dst_port, bytes_per_rep, reps);

    rc = hvmemul_virtual_to_linear(
        src_seg, src_offset, bytes_per_rep, reps, hvm_access_read,
        hvmemul_ctxt, &addr);
    if ( rc != X86EMUL_OKAY )
        return rc;

    if ( hvmemul_ctxt->seg_reg[x86_seg_ss].dpl == 3 )
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

static int cf_check hvmemul_rep_movs(
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
    struct vcpu *curr = current;
    struct hvm_vcpu_io *hvio = &curr->arch.hvm.hvm_io;
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

    if ( hvmemul_ctxt->seg_reg[x86_seg_ss].dpl == 3 )
        pfec |= PFEC_user_mode;

    if ( hvio->mmio_access.read_access &&
         (hvio->mmio_gla == (saddr & PAGE_MASK)) &&
         /*
          * Upon initial invocation don't truncate large batches just because
          * of a hit for the translation: Doing the guest page table walk is
          * cheaper than multiple round trips through the device model. Yet
          * when processing a response we can always re-use the translation.
          */
         (curr->io.req.state == STATE_IORESP_READY ||
          ((!df || *reps == 1) &&
           PAGE_SIZE - (saddr & ~PAGE_MASK) >= *reps * bytes_per_rep)) )
        sgpa = pfn_to_paddr(hvio->mmio_gpfn) | (saddr & ~PAGE_MASK);
    else
    {
        rc = hvmemul_linear_to_phys(saddr, &sgpa, bytes_per_rep, reps, pfec,
                                    hvmemul_ctxt);
        if ( rc != X86EMUL_OKAY )
            return rc;
    }

    if ( hvio->mmio_access.write_access &&
         (hvio->mmio_gla == (daddr & PAGE_MASK)) &&
         /* See comment above. */
         (curr->io.req.state == STATE_IORESP_READY ||
          ((!df || *reps == 1) &&
           PAGE_SIZE - (daddr & ~PAGE_MASK) >= *reps * bytes_per_rep)) )
        dgpa = pfn_to_paddr(hvio->mmio_gpfn) | (daddr & ~PAGE_MASK);
    else
    {
        rc = hvmemul_linear_to_phys(daddr, &dgpa, bytes_per_rep, reps,
                                    pfec | PFEC_write_access, hvmemul_ctxt);
        if ( rc != X86EMUL_OKAY )
            return rc;
    }

    /* Check for MMIO ops */
    get_gfn_query_unlocked(curr->domain, sgpa >> PAGE_SHIFT, &sp2mt);
    get_gfn_query_unlocked(curr->domain, dgpa >> PAGE_SHIFT, &dp2mt);

    if ( sp2mt == p2m_mmio_direct || dp2mt == p2m_mmio_direct ||
         (sp2mt == p2m_mmio_dm && dp2mt == p2m_mmio_dm) )
        return X86EMUL_UNHANDLEABLE;

    if ( sp2mt == p2m_mmio_dm )
    {
        latch_linear_to_phys(hvio, saddr, sgpa, 0);
        return hvmemul_do_mmio_addr(
            sgpa, reps, bytes_per_rep, IOREQ_READ, df, dgpa);
    }

    if ( dp2mt == p2m_mmio_dm )
    {
        latch_linear_to_phys(hvio, daddr, dgpa, 1);
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
    buf = xvmalloc_array(char, bytes);
    if ( buf == NULL )
        return X86EMUL_UNHANDLEABLE;

    if ( unlikely(hvmemul_ctxt->set_context) )
    {
        rc = set_context_data(buf, bytes);

        if ( rc != X86EMUL_OKAY)
        {
            xvfree(buf);
            return rc;
        }

        rc = HVMTRANS_okay;
    }
    else
    {
        unsigned int token = hvmemul_cache_disable(curr);

        /*
         * We do a modicum of checking here, just for paranoia's sake and to
         * definitely avoid copying an unitialised buffer into guest address
         * space.
         */
        rc = hvm_copy_from_guest_phys(buf, sgpa, bytes);
        hvmemul_cache_restore(curr, token);
    }

    if ( rc == HVMTRANS_okay )
        rc = hvm_copy_to_guest_phys(dgpa, buf, bytes, curr);

    xvfree(buf);

    switch ( rc )
    {
    case HVMTRANS_need_retry:
        /*
         * hvm_copy_{from,to}_guest_phys() do not currently return
         * HVMTRANS_need_retry.
         */
        ASSERT_UNREACHABLE();
        /* fall through */
    case HVMTRANS_gfn_paged_out:
    case HVMTRANS_gfn_shared:
        return X86EMUL_RETRY;
    case HVMTRANS_okay:
        return X86EMUL_OKAY;
    }

    gdprintk(XENLOG_WARNING, "Failed memory-to-memory REP MOVS: sgpa=%"
             PRIpaddr" dgpa=%"PRIpaddr" reps=%lu bytes_per_rep=%u\n",
             sgpa, dgpa, *reps, bytes_per_rep);

    return X86EMUL_UNHANDLEABLE;
}

static int cf_check hvmemul_rep_stos(
    void *p_data,
    enum x86_segment seg,
    unsigned long offset,
    unsigned int bytes_per_rep,
    unsigned long *reps,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);
    struct vcpu *curr = current;
    struct hvm_vcpu_io *hvio = &curr->arch.hvm.hvm_io;
    unsigned long addr;
    paddr_t gpa;
    p2m_type_t p2mt;
    bool df = ctxt->regs->eflags & X86_EFLAGS_DF;
    int rc = hvmemul_virtual_to_linear(seg, offset, bytes_per_rep, reps,
                                       hvm_access_write, hvmemul_ctxt, &addr);

    if ( rc != X86EMUL_OKAY )
        return rc;

    if ( hvio->mmio_access.write_access &&
         (hvio->mmio_gla == (addr & PAGE_MASK)) &&
         /* See respective comment in MOVS processing. */
         (curr->io.req.state == STATE_IORESP_READY ||
          ((!df || *reps == 1) &&
           PAGE_SIZE - (addr & ~PAGE_MASK) >= *reps * bytes_per_rep)) )
        gpa = pfn_to_paddr(hvio->mmio_gpfn) | (addr & ~PAGE_MASK);
    else
    {
        uint32_t pfec = PFEC_page_present | PFEC_write_access;

        if ( hvmemul_ctxt->seg_reg[x86_seg_ss].dpl == 3 )
            pfec |= PFEC_user_mode;

        rc = hvmemul_linear_to_phys(addr, &gpa, bytes_per_rep, reps, pfec,
                                    hvmemul_ctxt);
        if ( rc != X86EMUL_OKAY )
            return rc;
    }

    /* Check for MMIO op */
    get_gfn_query_unlocked(curr->domain, gpa >> PAGE_SHIFT, &p2mt);

    switch ( p2mt )
    {
        unsigned long bytes;
        char *buf;

    default:
        /* Allocate temporary buffer. */
        for ( ; ; )
        {
            bytes = *reps * bytes_per_rep;
            buf = xvmalloc_array(char, bytes);
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
                      : "=m" (*buf),                           \
                        "=D" (dummy), "=c" (dummy)             \
                      : "a" (*(const uint##bits##_t *)p_data), \
                        "1" (buf), "2" (*reps) : "memory" );   \
                break
            CASE(8, b);
            CASE(16, w);
            CASE(32, l);
            CASE(64, q);
#undef CASE

            default:
                ASSERT_UNREACHABLE();
                xvfree(buf);
                return X86EMUL_UNHANDLEABLE;
            }

        /* Adjust address for reverse store. */
        if ( df )
            gpa -= bytes - bytes_per_rep;

        rc = hvm_copy_to_guest_phys(gpa, buf, bytes, curr);

        if ( buf != p_data )
            xvfree(buf);

        switch ( rc )
        {
        case HVMTRANS_need_retry:
            /*
             * hvm_copy_to_guest_phys() does not currently return
             * HVMTRANS_need_retry.
             */
            ASSERT_UNREACHABLE();
            /* fall through */
        case HVMTRANS_gfn_paged_out:
        case HVMTRANS_gfn_shared:
            return X86EMUL_RETRY;
        case HVMTRANS_okay:
            return X86EMUL_OKAY;
        }

        gdprintk(XENLOG_WARNING,
                 "Failed REP STOS: gpa=%"PRIpaddr" reps=%lu bytes_per_rep=%u\n",
                 gpa, *reps, bytes_per_rep);
        /* fall through */
    case p2m_mmio_direct:
        return X86EMUL_UNHANDLEABLE;

    case p2m_mmio_dm:
        latch_linear_to_phys(hvio, addr, gpa, 1);
        return hvmemul_do_mmio_buffer(gpa, reps, bytes_per_rep, IOREQ_WRITE, df,
                                      p_data);
    }
}

static int cf_check hvmemul_read_segment(
    enum x86_segment seg,
    struct segment_register *reg,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);
    struct segment_register *sreg = hvmemul_get_seg_reg(seg, hvmemul_ctxt);

    if ( IS_ERR(sreg) )
         return -PTR_ERR(sreg);

    *reg = *sreg;

    return X86EMUL_OKAY;
}

static int cf_check hvmemul_write_segment(
    enum x86_segment seg,
    const struct segment_register *reg,
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

static int cf_check hvmemul_read_io(
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

static int cf_check hvmemul_write_io(
    unsigned int port,
    unsigned int bytes,
    unsigned long val,
    struct x86_emulate_ctxt *ctxt)
{
    return hvmemul_do_pio_buffer(port, bytes, IOREQ_WRITE, &val);
}

static int cf_check hvmemul_read_cr(
    unsigned int reg,
    unsigned long *pval,
    struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *curr = current;
    unsigned long val;

    switch ( reg )
    {
    case 0:
    case 2:
    case 3:
    case 4:
        val = curr->arch.hvm.guest_cr[reg];
        break;

    case 8:
        val = (vlapic_get_reg(vcpu_vlapic(curr), APIC_TASKPRI) & 0xf0) >> 4;
        break;

    default:
        return X86EMUL_UNHANDLEABLE;
    }

    TRACE(TRC_HVM_CR_READ64, reg, val, val >> 32);

    *pval = val;

    return X86EMUL_OKAY;
}

static int cf_check hvmemul_write_cr(
    unsigned int reg,
    unsigned long val,
    struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *curr = current;
    int rc;

    TRACE(TRC_HVM_CR_WRITE64, reg, val, val >> 32);
    switch ( reg )
    {
    case 0:
        rc = hvm_set_cr0(val, true);
        break;

    case 2:
        curr->arch.hvm.guest_cr[2] = val;
        rc = X86EMUL_OKAY;
        break;

    case 3:
    {
        bool noflush = hvm_pcid_enabled(curr) && (val & X86_CR3_NOFLUSH);

        if ( noflush )
            val &= ~X86_CR3_NOFLUSH;
        rc = hvm_set_cr3(val, noflush, true);
        break;
    }

    case 4:
        rc = hvm_set_cr4(val, true);
        break;

    case 8:
        if ( val & ~X86_CR8_VALID_MASK )
        {
            rc = X86EMUL_EXCEPTION;
            break;
        }

        vlapic_set_reg(vcpu_vlapic(curr), APIC_TASKPRI, val << 4);
        rc = X86EMUL_OKAY;
        break;

    default:
        rc = X86EMUL_UNHANDLEABLE;
        break;
    }

    if ( rc == X86EMUL_EXCEPTION )
        x86_emul_hw_exception(X86_EXC_GP, 0, ctxt);

    return rc;
}

static int cf_check hvmemul_read_xcr(
    unsigned int reg,
    uint64_t *val,
    struct x86_emulate_ctxt *ctxt)
{
    int rc = x86emul_read_xcr(reg, val, ctxt);

    if ( rc == X86EMUL_OKAY )
        TRACE(TRC_HVM_XCR_READ64, reg, *val, *val >> 32);

    return rc;
}

static int cf_check hvmemul_write_xcr(
    unsigned int reg,
    uint64_t val,
    struct x86_emulate_ctxt *ctxt)
{
    TRACE(TRC_HVM_XCR_WRITE64, reg, val, val >> 32);

    return x86emul_write_xcr(reg, val, ctxt);
}

static int cf_check hvmemul_read_msr(
    unsigned int reg,
    uint64_t *val,
    struct x86_emulate_ctxt *ctxt)
{
    int rc = hvm_msr_read_intercept(reg, val);

    if ( rc == X86EMUL_EXCEPTION )
        x86_emul_hw_exception(X86_EXC_GP, 0, ctxt);

    return rc;
}

static int cf_check hvmemul_write_msr(
    unsigned int reg,
    uint64_t val,
    struct x86_emulate_ctxt *ctxt)
{
    int rc = hvm_msr_write_intercept(reg, val, true);

    if ( rc == X86EMUL_EXCEPTION )
        x86_emul_hw_exception(X86_EXC_GP, 0, ctxt);

    return rc;
}

static int cf_check hvmemul_cache_op(
    enum x86emul_cache_op op,
    enum x86_segment seg,
    unsigned long offset,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);
    uint32_t pfec = PFEC_page_present;

    if ( !cache_flush_permitted(current->domain) )
        return X86EMUL_OKAY;

    switch ( op )
    {
        unsigned long addr;
        int rc;
        void *mapping;

    case x86emul_clflush:
    case x86emul_clflushopt:
    case x86emul_clwb:
        ASSERT(!is_x86_system_segment(seg));

        rc = hvmemul_virtual_to_linear(seg, offset, 0, NULL,
                                       op != x86emul_clwb ? hvm_access_none
                                                          : hvm_access_read,
                                       hvmemul_ctxt, &addr);
        if ( rc != X86EMUL_OKAY )
            break;

        if ( hvmemul_ctxt->seg_reg[x86_seg_ss].dpl == 3 )
            pfec |= PFEC_user_mode;

        mapping = hvmemul_map_linear_addr(addr, 0, pfec, hvmemul_ctxt);
        if ( mapping == ERR_PTR(~X86EMUL_EXCEPTION) )
            return X86EMUL_EXCEPTION;
        if ( IS_ERR_OR_NULL(mapping) )
            break;

        if ( cpu_has_clflush )
        {
            if ( op == x86emul_clwb && cpu_has_clwb )
                clwb(mapping);
            else if ( op == x86emul_clflushopt && cpu_has_clflushopt )
                clflushopt(mapping);
            else
                clflush(mapping);

            hvmemul_unmap_linear_addr(mapping, addr, 0, hvmemul_ctxt);
            break;
        }

        hvmemul_unmap_linear_addr(mapping, addr, 0, hvmemul_ctxt);
        /* fall through */
    case x86emul_wbinvd:
    case x86emul_wbnoinvd:
        alternative_vcall(hvm_funcs.wbinvd_intercept);
        break;

    case x86emul_invd:
        /*
         * Deliberately ignored: We mustn't issue INVD, and issuing WBINVD
         * wouldn't match the request. And the only place we'd expect the insn
         * to be sensibly used is in (virtualization unaware) firmware.
         */
        break;
    }

    return X86EMUL_OKAY;
}

static int cf_check hvmemul_get_fpu(
    enum x86_emulate_fpu_type type,
    struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *curr = current;

    if ( !curr->fpu_dirtied )
        alternative_vcall(hvm_funcs.fpu_dirty_intercept);
    else if ( type == X86EMUL_FPU_fpu )
    {
        /* Has a fastpath for `current`, so there's no actual map */
        const struct xsave_struct *xsave_area = VCPU_MAP_XSAVE_AREA(curr);
        const fpusse_t *fpu_ctxt = &xsave_area->fpu_sse;

        /*
         * Latch current register state so that we can back out changes
         * if needed (namely when a memory write fails after register state
         * has already been updated).
         * NB: We don't really need the "enable" part of the called function
         * (->fpu_dirtied set implies CR0.TS clear), but the additional
         * overhead should be low enough to not warrant introduction of yet
         * another slightly different function. However, we need to undo the
         * ->fpu_dirtied clearing the function does as well as the possible
         * masking of all exceptions by FNSTENV.)
         */
        save_fpu_enable();
        curr->fpu_initialised = true;
        curr->fpu_dirtied = true;
        if ( (fpu_ctxt->fcw & 0x3f) != 0x3f )
        {
            uint16_t fcw;

            asm ( "fnstcw %0" : "=m" (fcw) );
            if ( (fcw & 0x3f) == 0x3f )
                asm ( "fldcw %0" :: "m" (fpu_ctxt->fcw) );
            else
                ASSERT(fcw == fpu_ctxt->fcw);
        }

        VCPU_UNMAP_XSAVE_AREA(curr, xsave_area);
    }

    return X86EMUL_OKAY;
}

static void cf_check hvmemul_put_fpu(
    struct x86_emulate_ctxt *ctxt,
    enum x86_emulate_fpu_type backout,
    const struct x86_emul_fpu_aux *aux)
{
    struct vcpu *curr = current;

    if ( aux )
    {
        /* Has a fastpath for `current`, so there's no actual map */
        struct xsave_struct *xsave_area = VCPU_MAP_XSAVE_AREA(curr);
        fpusse_t *fpu_ctxt = &xsave_area->fpu_sse;
        bool dval = aux->dval;
        int mode = hvm_guest_x86_mode(curr);

        ASSERT(backout == X86EMUL_FPU_none);
        /*
         * Latch current register state so that we can replace FIP/FDP/FOP
         * (which have values resulting from our own invocation of the FPU
         * instruction during emulation).
         * NB: See also the comment in hvmemul_get_fpu(); we don't need to
         * set ->fpu_dirtied here as it is going to be cleared below, and
         * we also don't need to reload FCW as we're forcing full state to
         * be reloaded anyway.
         */
        save_fpu_enable();

        if ( boot_cpu_has(X86_FEATURE_FDP_EXCP_ONLY) &&
             !(fpu_ctxt->fsw & ~fpu_ctxt->fcw & 0x003f) )
            dval = false;

        switch ( mode )
        {
        case X86_MODE_64BIT:
            fpu_ctxt->fip.addr = aux->ip;
            if ( dval )
                fpu_ctxt->fdp.addr = aux->dp;
            fpu_ctxt->x[FPU_WORD_SIZE_OFFSET] = 8;
            break;

        case X86_MODE_32BIT:
        case X86_MODE_16BIT:
            fpu_ctxt->fip.offs = aux->ip;
            fpu_ctxt->fip.sel  = aux->cs;
            if ( dval )
            {
                fpu_ctxt->fdp.offs = aux->dp;
                fpu_ctxt->fdp.sel  = aux->ds;
            }
            fpu_ctxt->x[FPU_WORD_SIZE_OFFSET] = mode;
            break;

        case X86_MODE_REAL:
        case X86_MODE_VM86:
            fpu_ctxt->fip.addr = aux->ip | (aux->cs << 4);
            if ( dval )
                fpu_ctxt->fdp.addr = aux->dp | (aux->ds << 4);
            fpu_ctxt->x[FPU_WORD_SIZE_OFFSET] = 2;
            break;

        default:
            ASSERT_UNREACHABLE();
            return;
        }

        fpu_ctxt->fop = aux->op;

        VCPU_UNMAP_XSAVE_AREA(curr, xsave_area);

        /* Re-use backout code below. */
        backout = X86EMUL_FPU_fpu;
    }

    if ( backout == X86EMUL_FPU_fpu )
    {
        /*
         * To back out changes to the register file
         * - in fully eager mode, restore original state immediately,
         * - in lazy mode, simply adjust state such that upon next FPU insn
         *   use by the guest we'll reload the state saved (or freshly loaded)
         *   by hvmemul_get_fpu().
         */
        if ( curr->arch.fully_eager_fpu )
            vcpu_restore_fpu_nonlazy(curr, false);
        else
        {
            curr->fpu_dirtied = false;
            stts();
            alternative_vcall(hvm_funcs.fpu_leave, curr);
        }
    }
}

static int cf_check hvmemul_tlb_op(
    enum x86emul_tlb_op op,
    unsigned long addr,
    unsigned long aux,
    struct x86_emulate_ctxt *ctxt)
{
    struct hvm_emulate_ctxt *hvmemul_ctxt =
        container_of(ctxt, struct hvm_emulate_ctxt, ctxt);
    int rc = X86EMUL_OKAY;

    switch ( op )
    {
    case x86emul_invlpg:
        rc = hvmemul_virtual_to_linear(aux, addr, 1, NULL, hvm_access_none,
                                       hvmemul_ctxt, &addr);

        if ( rc == X86EMUL_EXCEPTION )
        {
            /*
             * `invlpg` takes segment bases into account, but is not subject
             * to faults from segment type/limit checks, and is specified as
             * a NOP when issued on non-canonical addresses.
             *
             * hvmemul_virtual_to_linear() raises exceptions for type/limit
             * violations, so squash them.
             */
            x86_emul_reset_event(ctxt);
            rc = X86EMUL_OKAY;
        }

        if ( rc == X86EMUL_OKAY )
            paging_invlpg(current, addr);
        break;

    case x86emul_invpcid:
        if ( x86emul_invpcid_type(aux) != X86_INVPCID_INDIV_ADDR )
        {
            hvm_asid_flush_vcpu(current);
            break;
        }
        aux = x86emul_invpcid_pcid(aux);
        /* fall through */
    case x86emul_invlpga:
        /* TODO: Support ASIDs/PCIDs. */
        if ( !aux )
            paging_invlpg(current, addr);
        else
        {
            x86_emul_hw_exception(X86_EXC_UD, X86_EVENT_NO_EC, ctxt);
            rc = X86EMUL_EXCEPTION;
        }
        break;
    }

    return rc;
}

static int cf_check hvmemul_vmfunc(
    struct x86_emulate_ctxt *ctxt)
{
    int rc;

    if ( !hvm_funcs.altp2m_vcpu_emulate_vmfunc )
        return X86EMUL_UNHANDLEABLE;
    rc = alternative_call(hvm_funcs.altp2m_vcpu_emulate_vmfunc, ctxt->regs);
    if ( rc == X86EMUL_EXCEPTION )
        x86_emul_hw_exception(X86_EXC_UD, X86_EVENT_NO_EC, ctxt);

    return rc;
}

static const struct x86_emulate_ops hvm_emulate_ops = {
    .read          = hvmemul_read,
    .insn_fetch    = hvmemul_insn_fetch,
    .write         = hvmemul_write,
    .rmw           = hvmemul_rmw,
    .cmpxchg       = hvmemul_cmpxchg,
    .blk           = hvmemul_blk,
    .validate      = hvmemul_validate,
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
    .read_xcr      = hvmemul_read_xcr,
    .write_xcr     = hvmemul_write_xcr,
    .read_msr      = hvmemul_read_msr,
    .write_msr     = hvmemul_write_msr,
    .cache_op      = hvmemul_cache_op,
    .tlb_op        = hvmemul_tlb_op,
    .cpuid         = x86emul_cpuid,
    .get_fpu       = hvmemul_get_fpu,
    .put_fpu       = hvmemul_put_fpu,
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
    .read_xcr      = hvmemul_read_xcr,
    .write_xcr     = hvmemul_write_xcr,
    .read_msr      = hvmemul_read_msr,
    .write_msr     = hvmemul_write_msr_discard,
    .cache_op      = hvmemul_cache_op_discard,
    .tlb_op        = hvmemul_tlb_op,
    .cpuid         = x86emul_cpuid,
    .get_fpu       = hvmemul_get_fpu,
    .put_fpu       = hvmemul_put_fpu,
    .vmfunc        = hvmemul_vmfunc,
};

/*
 * Note that passing VIO_no_completion into this function serves as kind
 * of (but not fully) an "auto select completion" indicator.  When there's
 * no completion needed, the passed in value will be ignored in any case.
 */
static int _hvm_emulate_one(struct hvm_emulate_ctxt *hvmemul_ctxt,
    const struct x86_emulate_ops *ops,
    enum vio_completion completion)
{
    const struct cpu_user_regs *regs = hvmemul_ctxt->ctxt.regs;
    struct vcpu *curr = current;
    uint32_t new_intr_shadow;
    struct hvm_vcpu_io *hvio = &curr->arch.hvm.hvm_io;
    int rc;

    /*
     * Enable caching if it's currently disabled, but leave the cache
     * untouched if it's already enabled, for re-execution to consume
     * entries populated by an earlier pass.
     */
    if ( hvio->cache->num_ents > hvio->cache->max_ents )
    {
        ASSERT(curr->io.req.state == STATE_IOREQ_NONE);
        hvio->cache->num_ents = 0;
    }
    else
        ASSERT(curr->io.req.state == STATE_IORESP_READY);

    hvm_emulate_init_per_insn(hvmemul_ctxt, hvio->mmio_insn,
                              hvio->mmio_insn_bytes);

    hvio->mmio_retry = 0;

    rc = x86_emulate(&hvmemul_ctxt->ctxt, ops);
    if ( rc == X86EMUL_OKAY && hvio->mmio_retry )
        rc = X86EMUL_RETRY;

    if ( !ioreq_needs_completion(&curr->io.req) )
        completion = VIO_no_completion;
    else if ( completion == VIO_no_completion )
        completion = (curr->io.req.type != IOREQ_TYPE_PIO ||
                      hvmemul_ctxt->is_mem_access) ? VIO_mmio_completion
                                                   : VIO_pio_completion;

    switch ( curr->io.completion = completion )
    {
    case VIO_no_completion:
    case VIO_pio_completion:
        hvio->mmio_cache_count = 0;
        hvio->mmio_insn_bytes = 0;
        hvio->mmio_access = (struct npfec){};
        hvmemul_cache_disable(curr);
        break;

    case VIO_mmio_completion:
    case VIO_realmode_completion:
        BUILD_BUG_ON(sizeof(hvio->mmio_insn) < sizeof(hvmemul_ctxt->insn_buf));
        hvio->mmio_insn_bytes = hvmemul_ctxt->insn_buf_bytes;
        memcpy(hvio->mmio_insn, hvmemul_ctxt->insn_buf, hvio->mmio_insn_bytes);
        break;

    default:
        ASSERT_UNREACHABLE();
        return X86EMUL_UNHANDLEABLE;
    }

    if ( hvmemul_ctxt->ctxt.retire.singlestep )
        hvm_inject_hw_exception(X86_EXC_DB, X86_EVENT_NO_EC);

    new_intr_shadow = hvmemul_ctxt->intr_shadow;

    /* MOV-SS instruction toggles MOV-SS shadow, else we just clear it. */
    if ( hvmemul_ctxt->ctxt.retire.mov_ss )
        new_intr_shadow ^= HVM_INTR_SHADOW_MOV_SS;
    else if ( rc != X86EMUL_RETRY )
        new_intr_shadow &= ~HVM_INTR_SHADOW_MOV_SS;

    /* STI instruction toggles STI shadow, else we just clear it. */
    if ( hvmemul_ctxt->ctxt.retire.sti )
        new_intr_shadow ^= HVM_INTR_SHADOW_STI;
    else if ( rc != X86EMUL_RETRY )
        new_intr_shadow &= ~HVM_INTR_SHADOW_STI;

    /* IRET, if valid in the given context, clears NMI blocking. */
    if ( hvmemul_ctxt->ctxt.retire.unblock_nmi )
        new_intr_shadow &= ~HVM_INTR_SHADOW_NMI;

    if ( hvmemul_ctxt->intr_shadow != new_intr_shadow )
    {
        hvmemul_ctxt->intr_shadow = new_intr_shadow;
        alternative_vcall(hvm_funcs.set_interrupt_shadow,
                          curr, new_intr_shadow);
    }

    if ( hvmemul_ctxt->ctxt.retire.hlt &&
         !hvm_local_events_need_delivery(curr) )
    {
        hvm_hlt(regs->eflags);
    }

    return rc;
}

int hvm_emulate_one(
    struct hvm_emulate_ctxt *hvmemul_ctxt,
    enum vio_completion completion)
{
    return _hvm_emulate_one(hvmemul_ctxt, &hvm_emulate_ops, completion);
}

void hvm_emulate_one_vm_event(enum emul_kind kind, unsigned int trapnr,
    unsigned int errcode)
{
    struct hvm_emulate_ctxt ctx = {};
    int rc;

    hvm_emulate_init_once(&ctx, NULL, guest_cpu_user_regs());

    switch ( kind )
    {
    case EMUL_KIND_NOWRITE:
        rc = _hvm_emulate_one(&ctx, &hvm_emulate_ops_no_write,
                              VIO_no_completion);
        break;
    case EMUL_KIND_SET_CONTEXT_INSN: {
        struct vcpu *curr = current;
        struct hvm_vcpu_io *hvio = &curr->arch.hvm.hvm_io;

        BUILD_BUG_ON(sizeof(hvio->mmio_insn) !=
                     sizeof(curr->arch.vm_event->emul.insn.data));
        ASSERT(!hvio->mmio_insn_bytes);

        /*
         * Stash insn buffer into mmio buffer here instead of ctx
         * to avoid having to add more logic to hvm_emulate_one.
         */
        hvio->mmio_insn_bytes = sizeof(hvio->mmio_insn);
        memcpy(hvio->mmio_insn, curr->arch.vm_event->emul.insn.data,
               hvio->mmio_insn_bytes);
    }
        fallthrough;
    default:
        ctx.set_context = (kind == EMUL_KIND_SET_CONTEXT_DATA);
        rc = hvm_emulate_one(&ctx, VIO_no_completion);
        break;
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
    case X86EMUL_UNIMPLEMENTED:
        if ( hvm_monitor_emul_unimplemented() )
            return;
        fallthrough;
    case X86EMUL_UNHANDLEABLE:
        hvm_dump_emulation_state(XENLOG_G_DEBUG, "Mem event", &ctx, rc);
        hvm_inject_hw_exception(trapnr, errcode);
        break;
    case X86EMUL_EXCEPTION:
        hvm_inject_event(&ctx.ctxt.event);
        break;
    }

    hvm_emulate_writeback(&ctx);
}

void hvm_emulate_init_once(
    struct hvm_emulate_ctxt *hvmemul_ctxt,
    hvm_emulate_validate_t *validate,
    struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;

    memset(hvmemul_ctxt, 0, sizeof(*hvmemul_ctxt));

    hvmemul_ctxt->intr_shadow =
        alternative_call(hvm_funcs.get_interrupt_shadow, curr);
    hvmemul_get_seg_reg(x86_seg_cs, hvmemul_ctxt);
    hvmemul_get_seg_reg(x86_seg_ss, hvmemul_ctxt);

    hvmemul_ctxt->validate = validate;
    hvmemul_ctxt->ctxt.regs = regs;
    hvmemul_ctxt->ctxt.cpu_policy = curr->domain->arch.cpu_policy;
    hvmemul_ctxt->ctxt.force_writeback = true;
}

void hvm_emulate_init_per_insn(
    struct hvm_emulate_ctxt *hvmemul_ctxt,
    const unsigned char *insn_buf,
    unsigned int insn_bytes)
{
    struct vcpu *curr = current;

    hvmemul_ctxt->ctxt.lma = hvm_long_mode_active(curr);

    if ( hvmemul_ctxt->ctxt.lma &&
         hvmemul_ctxt->seg_reg[x86_seg_cs].l )
        hvmemul_ctxt->ctxt.addr_size = hvmemul_ctxt->ctxt.sp_size = 64;
    else
    {
        hvmemul_ctxt->ctxt.addr_size =
            hvmemul_ctxt->seg_reg[x86_seg_cs].db ? 32 : 16;
        hvmemul_ctxt->ctxt.sp_size =
            hvmemul_ctxt->seg_reg[x86_seg_ss].db ? 32 : 16;
    }

    hvmemul_ctxt->insn_buf_eip = hvmemul_ctxt->ctxt.regs->rip;

    if ( insn_bytes )
    {
        hvmemul_ctxt->insn_buf_bytes = insn_bytes;
        memcpy(hvmemul_ctxt->insn_buf, insn_buf, insn_bytes);
    }
    else if ( !(hvmemul_ctxt->insn_buf_bytes =
                hvm_get_insn_bytes(curr, hvmemul_ctxt->insn_buf)) )
    {
        unsigned int pfec = PFEC_page_present | PFEC_insn_fetch;
        unsigned long addr;

        if ( hvmemul_ctxt->seg_reg[x86_seg_ss].dpl == 3 )
            pfec |= PFEC_user_mode;

        hvmemul_ctxt->insn_buf_bytes =
            (hvm_virtual_to_linear_addr(x86_seg_cs,
                                        &hvmemul_ctxt->seg_reg[x86_seg_cs],
                                        hvmemul_ctxt->insn_buf_eip,
                                        sizeof(hvmemul_ctxt->insn_buf),
                                        hvm_access_insn_fetch,
                                        &hvmemul_ctxt->seg_reg[x86_seg_cs],
                                        &addr) &&
             hvm_copy_from_guest_linear(hvmemul_ctxt->insn_buf, addr,
                                        sizeof(hvmemul_ctxt->insn_buf),
                                        pfec, NULL) == HVMTRANS_okay) ?
            sizeof(hvmemul_ctxt->insn_buf) : 0;
    }

    hvmemul_ctxt->is_mem_access = false;
}

void hvm_emulate_writeback(
    struct hvm_emulate_ctxt *hvmemul_ctxt)
{
    struct vcpu *curr = current;
    unsigned int dirty = hvmemul_ctxt->seg_reg_dirty;

    for_each_set_bit ( seg, dirty )
        hvm_set_segment_register(curr, seg, &hvmemul_ctxt->seg_reg[seg]);
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
    case X86_MODE_REAL:   return "Real";
    case X86_MODE_VM86:   return "vm86";
    case X86_MODE_16BIT:  return "16bit";
    case X86_MODE_32BIT:  return "32bit";
    case X86_MODE_64BIT:  return "64bit";
    default: return "Unknown";
    }
}

void hvm_dump_emulation_state(const char *loglvl, const char *prefix,
                              struct hvm_emulate_ctxt *hvmemul_ctxt, int rc)
{
    struct vcpu *curr = current;
    const char *mode_str = guest_x86_mode_to_str(hvm_guest_x86_mode(curr));
    const struct segment_register *cs =
        hvmemul_get_seg_reg(x86_seg_cs, hvmemul_ctxt);

    printk("%s%s emulation failed (%d): %pv %s @ %04x:%08lx -> %*ph\n",
           loglvl, prefix, rc, curr, mode_str, cs->sel,
           hvmemul_ctxt->insn_buf_eip, hvmemul_ctxt->insn_buf_bytes,
           hvmemul_ctxt->insn_buf);
}

int hvmemul_cache_init(struct vcpu *v)
{
    /*
     * AVX512F scatter/gather insns can access up to 16 independent linear
     * addresses, up to 8 bytes size. Each such linear range can span a page
     * boundary, i.e. may require two page walks.
     */
    unsigned int nents = 16 * 2 * (CONFIG_PAGING_LEVELS + 1);
    unsigned int i, max_bytes = 64;
    struct hvmemul_cache *cache;

    /*
     * Account for each insn byte individually, both for simplicity and to
     * leave some slack space.
     */
    nents += MAX_INST_LEN * (CONFIG_PAGING_LEVELS + 1);

    cache = xvmalloc_flex_struct(struct hvmemul_cache, ents, nents);
    if ( !cache )
        return -ENOMEM;

    /* Cache is disabled initially. */
    cache->num_ents = nents + 1;
    cache->max_ents = nents;

    v->arch.hvm.hvm_io.cache = cache;

    for ( i = 0; i < ARRAY_SIZE(v->arch.hvm.hvm_io.mmio_cache); ++i )
    {
        v->arch.hvm.hvm_io.mmio_cache[i] =
            xvmalloc_flex_struct(struct hvm_mmio_cache, buffer, max_bytes);
        if ( !v->arch.hvm.hvm_io.mmio_cache[i] )
            return -ENOMEM;
        v->arch.hvm.hvm_io.mmio_cache[i]->space = max_bytes;
    }

    return 0;
}

unsigned int hvmemul_cache_disable(struct vcpu *v)
{
    struct hvmemul_cache *cache = v->arch.hvm.hvm_io.cache;
    unsigned int token = cache->num_ents;

    cache->num_ents = cache->max_ents + 1;

    return token;
}

void hvmemul_cache_restore(struct vcpu *v, unsigned int token)
{
    struct hvmemul_cache *cache = v->arch.hvm.hvm_io.cache;

    ASSERT(cache->num_ents > cache->max_ents);
    cache->num_ents = token;
}

bool hvmemul_read_cache(const struct vcpu *v, paddr_t gpa,
                        void *buffer, unsigned int size)
{
    const struct hvmemul_cache *cache = v->arch.hvm.hvm_io.cache;
    unsigned int i;

    /* Cache unavailable? */
    if ( !is_hvm_vcpu(v) || cache->num_ents > cache->max_ents )
        return false;

    while ( size > sizeof(cache->ents->data) )
    {
        i = gpa & (sizeof(cache->ents->data) - 1)
            ? -gpa & (sizeof(cache->ents->data) - 1)
            : sizeof(cache->ents->data);
        if ( !hvmemul_read_cache(v, gpa, buffer, i) )
            return false;
        gpa += i;
        buffer += i;
        size -= i;
    }

    for ( i = 0; i < cache->num_ents; ++i )
        if ( cache->ents[i].gpa == gpa && cache->ents[i].size == size )
        {
            memcpy(buffer, &cache->ents[i].data, size);
            return true;
        }

    return false;
}

void hvmemul_write_cache(const struct vcpu *v, paddr_t gpa,
                         const void *buffer, unsigned int size)
{
    struct hvmemul_cache *cache = v->arch.hvm.hvm_io.cache;
    unsigned int i;

    /* Cache unavailable? */
    if ( !is_hvm_vcpu(v) || cache->num_ents > cache->max_ents )
        return;

    while ( size > sizeof(cache->ents->data) )
    {
        i = gpa & (sizeof(cache->ents->data) - 1)
            ? -gpa & (sizeof(cache->ents->data) - 1)
            : sizeof(cache->ents->data);
        hvmemul_write_cache(v, gpa, buffer, i);
        gpa += i;
        buffer += i;
        size -= i;
    }

    for ( i = 0; i < cache->num_ents; ++i )
        if ( cache->ents[i].gpa == gpa && cache->ents[i].size == size )
        {
            memcpy(&cache->ents[i].data, buffer, size);
            return;
        }

    if ( unlikely(i >= cache->max_ents) )
    {
        domain_crash(v->domain);
        return;
    }

    cache->ents[i].gpa  = gpa;
    cache->ents[i].size = size;

    memcpy(&cache->ents[i].data, buffer, size);

    cache->num_ents = i + 1;
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
