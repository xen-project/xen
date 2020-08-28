/******************************************************************************
 * tools/xenpaging/xenpaging.h
 *
 * Xen domain paging.
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Patrick Colp)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef __XEN_PAGING2_H__
#define __XEN_PAGING2_H__

#include <malloc.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <xenevtchn.h>
#define XC_WANT_COMPAT_MAP_FOREIGN_API
#include <xenctrl.h>
// #include <xc_private.h>
#include <xen/event_channel.h>
#include <xen/vm_event.h>

#define XENPAGING_PAGEIN_QUEUE_SIZE 64

struct vm_event {
    domid_t domain_id;
    xenevtchn_handle *xce_handle;
    int port;
    vm_event_back_ring_t back_ring;
    uint32_t evtchn_port;
    void *ring_page;
};

struct xenpaging {
    xc_interface *xc_handle;
    xentoollog_logger *logger;
    struct xs_handle *xs_handle;

    unsigned long *bitmap;

    unsigned long *slot_to_gfn;
    int *gfn_to_slot;

    void *paging_buffer;

    struct vm_event vm_event;
    int fd;
    /* number of pages for which data structures were allocated */
    int max_pages;
    int num_paged_out;
    int target_tot_pages;
    int policy_mru_size;
    int use_poll_timeout;
    int debug;
    int stack_count;
    int *free_slot_stack;
    unsigned long pagein_queue[XENPAGING_PAGEIN_QUEUE_SIZE];
};

#define DPRINTF(msg, args...) xtl_log(paging->logger, XTL_DETAIL, 0,      \
                                      "paging", msg, ## args)
#define ERROR(msg, args...)   xtl_log(paging->logger, XTL_ERROR, -1,      \
                                      "paging", msg, ## args)
#define PERROR(msg, args...)  xtl_log(paging->logger, XTL_ERROR, -1,      \
                                      "paging", msg "(%d = %s)", ## args, \
                                      errno, strerror(errno))

extern void create_page_in_thread(struct xenpaging *paging);
extern void page_in_trigger(void);

#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#define ORDER_LONG (sizeof(unsigned long) == 4 ? 5 : 6)

#define BITMAP_ENTRY(_nr,_bmap) ((_bmap))[(_nr) / 8]
#define BITMAP_SHIFT(_nr) ((_nr) % 8)

static inline int bitmap_size(int nr_bits)
{
    return (nr_bits + 7) / 8;
}

static inline void *bitmap_alloc(int nr_bits)
{
    return calloc(1, bitmap_size(nr_bits));
}

static inline void bitmap_clear(void *addr, int nr_bits)
{
    memset(addr, 0, bitmap_size(nr_bits));
}

static inline int test_bit(int nr, const void *_addr)
{
    const char *addr = _addr;
    return (BITMAP_ENTRY(nr, addr) >> BITMAP_SHIFT(nr)) & 1;
}

static inline void clear_bit(int nr, void *_addr)
{
    char *addr = _addr;
    BITMAP_ENTRY(nr, addr) &= ~(1UL << BITMAP_SHIFT(nr));
}

static inline void set_bit(int nr, void *_addr)
{
    char *addr = _addr;
    BITMAP_ENTRY(nr, addr) |= (1UL << BITMAP_SHIFT(nr));
}

static inline int test_and_clear_bit(int nr, void *addr)
{
    int oldbit = test_bit(nr, addr);
    clear_bit(nr, addr);
    return oldbit;
}

static inline int test_and_set_bit(int nr, void *addr)
{
    int oldbit = test_bit(nr, addr);
    set_bit(nr, addr);
    return oldbit;
}

#endif // __XEN_PAGING_H__


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
