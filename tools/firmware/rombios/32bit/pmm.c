/*
 *  pmm.c - POST(Power On Self Test) Memory Manager
 *  according to the specification described in
 *  http://www.phoenix.com/NR/rdonlyres/873A00CF-33AC-4775-B77E-08E7B9754993/0/specspmm101.pdf
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 *  Copyright (C) 2009 FUJITSU LIMITED
 *
 *  Author: Kouya Shimura <kouya@jp.fujitsu.com>
 */

/*
 * Algorithm:
 *
 * This is not a fast storage allocator but simple one.  There is no
 * segregated management by block size and it does nothing special for
 * avoiding the fragmentation.
 *
 * The allocation algorithm is a first-fit. All memory blocks are
 * managed by linear single linked list in order of the address.
 * (i.e. There is no backward pointer) It searches the first available
 * equal or larger block from the head (lowest address) of memory
 * heap. The larger block is splitted into two blocks unless one side
 * becomes too small.
 * 
 * For de-allocation, the specified block is just marked as available
 * and it does nothing else. Thus, the fragmentation will occur. The
 * collection of continuous available blocks are done on the search
 * phase of another block allocation.
 *
 * The following is an abstract of this algorithm. The actual code
 * looks complicated on account of alignment and checking the handle.
 *
 *     static memblk_t *
 *     alloc(heap_t *heap, uint32_t size)
 *     {
 *         static memblk_t *mb;
 *         for_each_memblk(heap, mb) // search memory blocks
 *             if (memblk_is_avail(mb))
 *             {
 *                 collect_avail_memblks(heap, mb);
 *                 if (size <= memblk_bufsize(mb))
 *                 {
 *                     split_memblk(mb, size);
 *                     set_inuse(mb);
 *                     return mb;
 *                 }
 *             }
 *         return NULL;
 *     }
 */

#include <stdint.h>
#include <stddef.h>
#include "config.h"
#include "e820.h"
#include "util.h"

#define DEBUG_PMM 0

#define __stringify(a) #a
#define stringify(a) __stringify(a)

#define ASSERT(_expr, _action)                                  \
    if (!(_expr)) {                                             \
        printf("ASSERTION FAIL: %s %s:%d %s()\n",               \
               stringify(_expr), __FILE__, __LINE__, __func__); \
        _action;                                                \
    } else

#if DEBUG_PMM
# define PMM_DEBUG(format, p...) printf("PMM " format, ##p)
#else
# define PMM_DEBUG(format, p...)
#endif

struct pmmAllocArgs {
    uint16_t function;
    uint32_t length;
    uint32_t handle;
    uint16_t flags;
} __attribute__ ((packed));

struct pmmFindArgs {
    uint16_t function;
    uint32_t handle;
} __attribute__ ((packed));

struct pmmDeallocateArgs {
    uint16_t function;
    uint32_t buffer;
} __attribute__ ((packed));

#define PMM_FUNCTION_ALLOCATE   0
#define PMM_FUNCTION_FIND       1         
#define PMM_FUNCTION_DEALLOC    2

#define PARAGRAPH_LENGTH        16  // unit of length

#define PMM_HANDLE_ANONYMOUS    0xffffffff

#define PMM_FLAGS_MEMORY_TYPE_MASK      0x0003
#define PMM_FLAGS_MEMORY_INVALID        0
#define PMM_FLAGS_MEMORY_CONVENTIONAL   1  // 0 to 1MB
#define PMM_FLAGS_MEMORY_EXTENDED       2  // 1MB to 4GB
#define PMM_FLAGS_MEMORY_ANY            3  // whichever is available
#define PMM_FLAGS_ALIGINMENT            0x0004

/* Error code */
#define PMM_ENOMEM      (0)     // Out of memory, duplicate handle
#define PMM_EINVAL      (-1)    // Invalid argument

#define ALIGN_UP(addr, size)    (((addr)+((size)-1))&(~((size)-1)))
#define ALIGN_DOWN(addr, size)  ((addr)&(~((size)-1)))

typedef struct memblk {
    uint32_t magic;      // inuse or available
    struct memblk *next; // points the very next of this memblk
    uint32_t handle;     // identifier of this block
    uint32_t __fill;     // for 16byte alignment, not used
    uint8_t buffer[0];
} memblk_t;

typedef struct heap {
    memblk_t *head;     // start address of heap
    memblk_t *end;      // end address of heap
} heap_t;

#define HEAP_NOT_INITIALIZED    (memblk_t *)-1
#define HEAP_ALIGNMENT          16

/*
 * PMM handles two memory heaps, the caller chooses either.
 *
 * - conventional memroy (below 1MB)
 *    In HVM, the area is fixed. 0x00010000-0x0007FFFF
 *    (LOWHEAP_SIZE bytes from LOWHEAP_PHYSICAL_ADDRESS)
 *
 * - extended memory (start at 1MB, below 4GB)
 *    In HVM, the area starts at memory address 0x00100000.
 *    The end address is variable. We read low RAM address from e820 table.
 *
 * The following struct must be located in the data segment since bss
 * in 32bitbios doesn't be relocated.
 */
static struct {
    heap_t heap;     // conventional memory
    heap_t ext_heap; // extended memory
} pmm_data = { {HEAP_NOT_INITIALIZED, NULL}, {NULL, NULL} };

/* These values are private use, not a spec in PMM */
#define MEMBLK_MAGIC_INUSE   0x2A4D4D50  // 'PMM*'
#define MEMBLK_MAGIC_AVAIL   0x5F4D4D50  // 'PMM_'

#define memblk_is_inuse(_mb)  ((_mb)->magic == MEMBLK_MAGIC_INUSE)
#define memblk_is_avail(_mb)  ((_mb)->magic == MEMBLK_MAGIC_AVAIL)

static void set_inuse(memblk_t *mb, uint32_t handle)
{
    mb->magic = MEMBLK_MAGIC_INUSE;
    mb->handle = handle;
}

static void set_avail(memblk_t *mb)
{
    mb->magic = MEMBLK_MAGIC_AVAIL;
    mb->handle = PMM_HANDLE_ANONYMOUS;
}

#define MEMBLK_HEADER_SIZE   ((int)(&((memblk_t *)0)->buffer))
#define MIN_MEMBLK_SIZE      (MEMBLK_HEADER_SIZE + PARAGRAPH_LENGTH)

#define memblk_size(_mb)     ((void *)((_mb)->next) - (void *)(_mb))
#define memblk_buffer(_mb)   ((uint32_t)(&(_mb)->buffer))
#define memblk_bufsize(_mb)  (memblk_size(_mb) - MEMBLK_HEADER_SIZE)

#define buffer_memblk(_buf)  (memblk_t *)((_buf) - MEMBLK_HEADER_SIZE)

#define memblk_loop_mbondition(_h, _mb) \
    (((_mb) < (_h)->end) && (/* avoid infinite loop */ (_mb) < (_mb)->next))

#define for_each_memblk(_h, _mb)                \
    for ((_mb) = (_h)->head;                    \
         memblk_loop_mbondition(_h, _mb);       \
         (_mb) = (_mb)->next)

#define for_remain_memblk(_h, _mb)              \
    for (;                                      \
         memblk_loop_mbondition(_h, _mb);       \
         (_mb) = (_mb)->next)

/*
 *                                       <-size->
 *    +==================+======+       +========+========+======+
 *    |      avail       |      |       | avail  | avail  |      |
 *    |      memblk      |memblk|...    | memblk | memblk |memblk|...
 *    +==================+======+   =>  +========+========+======+
 *    ^ |                ^ |    ^         |      ^ |      ^ |    ^
 *    | |next            | |next|         |next  | |next  | |next|
 *    | \________________/ \____/         \______/ \______/ \____/
 *    |                                          ^
 *    |                                          |
 *    mb                                         +- sb(return value)
 */
static memblk_t *
split_memblk(memblk_t *mb, uint32_t size)
{
    memblk_t *sb = (void *)memblk_buffer(mb) + size;

    /* Only split if the remaining fragment is big enough. */
    if ( (memblk_bufsize(mb) - size) < MIN_MEMBLK_SIZE)
        return mb;

    sb->next = mb->next;
    set_avail(sb);

    mb->next = sb;
    return sb;
}

/*
 *    +======+======+======+======+       +=================+======+
 *    |avail |avail |avail |inuse |       |      avail      |inuse |   
 *    |memblk|memblk|memblk|memblk|...    |      memblk     |memblk|...
 *    +======+======+======+======+   =>  +=================+======+
 *    ^ |    ^ |    ^ |    ^ |    ^         |               ^ |    ^
 *    | |next| |next| |next| |next|         |next           | |next|
 *    | \____/ \____/ \____/ \____/         \_______________/ \____/
 *    |
 *    mb
 */
static void
collect_avail_memblks(heap_t *heap, memblk_t *mb)
{
    memblk_t *nb = mb->next;

    for_remain_memblk ( heap, nb )
        if ( memblk_is_inuse(nb) )
            break;
    mb->next = nb;
}

static void
pmm_init_heap(heap_t *heap, uint32_t from_addr, uint32_t to_addr)
{
    memblk_t *mb = (memblk_t *)ALIGN_UP(from_addr, HEAP_ALIGNMENT);

    mb->next = (memblk_t *)ALIGN_DOWN(to_addr, HEAP_ALIGNMENT);
    set_avail(mb);

    heap->head = mb;
    heap->end = mb->next;
}

static void
pmm_initalize(void)
{
    int i, e820_nr = *E820_NR;
    struct e820entry *e820 = E820;

    /* Extended memory: RAM below 4GB, 0x100000-0xXXXXXXXX */
    for ( i = 0; i < e820_nr; i++ )
    {
        if ( (e820[i].type == E820_RAM) && (e820[i].addr >= 0x00100000) )
        {
            pmm_init_heap(&pmm_data.ext_heap, e820[i].addr, 
                          e820[i].addr + e820[i].size);
            break;
        }
    }

    /* convectional memory: RAM below 1MB, 0x10000-0x7FFFF */
    pmm_init_heap(&pmm_data.heap,
		  LOWHEAP_PHYSICAL_ADDRESS,
		  LOWHEAP_PHYSICAL_ADDRESS+LOWHEAP_SIZE);
}

static uint32_t
pmm_max_avail_length(heap_t *heap)
{
    memblk_t *mb;
    uint32_t size, max = 0;

    for_each_memblk ( heap, mb )
    {
        if ( !memblk_is_avail(mb) )
            continue;
        collect_avail_memblks(heap, mb);
        size = memblk_bufsize(mb);
        if ( size > max )
            max = size;
    }

    return (max / PARAGRAPH_LENGTH);
}

static memblk_t *
first_fit(heap_t *heap, uint32_t size, uint32_t handle, uint32_t flags)
{
    memblk_t *mb;
    int32_t align = 0;

    if ( flags & PMM_FLAGS_ALIGINMENT )
        align = ((size ^ (size - 1)) >> 1) + 1;

    for_each_memblk ( heap, mb )
    {
        if ( memblk_is_avail(mb) )
        {
            collect_avail_memblks(heap, mb);

            if ( align )
            {
                uint32_t addr = memblk_buffer(mb);
                uint32_t offset = ALIGN_UP(addr, align) - addr;

                if ( offset > 0 )
                {
                    ASSERT(offset >= MEMBLK_HEADER_SIZE, continue);

                    if ( (offset + size) > memblk_bufsize(mb) )
                        continue;

                    mb = split_memblk(mb, offset - MEMBLK_HEADER_SIZE);
                    return mb;
                }
            }

            if ( size <= memblk_bufsize(mb) )
                return mb;
        }
        else
        {
            ASSERT(memblk_is_inuse(mb), return NULL);

            /* Duplication check for handle. */
            if ( (handle != PMM_HANDLE_ANONYMOUS) && (mb->handle == handle) )
                return NULL;
        }
    }

    return NULL;
}

static memblk_t *
pmm_find_handle(heap_t *heap, uint32_t handle)
{
    memblk_t *mb;

    if ( handle == PMM_HANDLE_ANONYMOUS )
        return NULL;

    for_each_memblk ( heap, mb )
        if ( mb->handle == handle )
            return mb;

    return NULL;
}

/*
 * allocate a memory block of the specified type and size, and returns
 * the address of the memory block.
 *
 * A client-specified identifier to be associated with the allocated
 * memory block. A handle of 0xFFFFFFFF indicates that no identifier
 * should be associated with the block. Such a memory block is known
 * as an "anonymous" memory block and cannot be found using the
 * pmmFind function. If a specified handle for a requested memory
 * block is already used in a currently allocated memory block, the
 * error value of 0x00000000 is returned
 *
 * If length is 0x00000000, no memory is allocated and the value
 * returned is the size of the largest memory block available for the
 * memory type specified in the flags parameter. The alignment bit in
 * the flags register is ignored when calculating the largest memory
 * block available.
 *
 * If a specified handle for a requested memory block is already used
 * in a currently allocated memory block, the error value of
 * 0x00000000 is returned.
 * 
 * A return value of 0x00000000 indicates that an error occurred and
 * no memory has been allocated. 
 */
static uint32_t
pmmAllocate(uint32_t length, uint32_t handle, uint16_t flags)
{
    heap_t *heap;
    memblk_t *mb;
    uint32_t size;

    switch ( flags & PMM_FLAGS_MEMORY_TYPE_MASK )
    {
    case PMM_FLAGS_MEMORY_CONVENTIONAL:
        heap = &pmm_data.heap;
        break;

    case PMM_FLAGS_MEMORY_EXTENDED:
    case PMM_FLAGS_MEMORY_ANY: /* XXX: ignore conventional memory for now */
        heap = &pmm_data.ext_heap;
        break;

    default:
        return PMM_EINVAL;
    }

    /* return the largest memory block available */
    if ( length == 0 )
        return pmm_max_avail_length(heap);

    size = length * PARAGRAPH_LENGTH;
    mb = first_fit(heap, size, handle, flags);

    if ( mb == NULL )
        return PMM_ENOMEM;

    /* duplication check for handle */
    if ( handle != PMM_HANDLE_ANONYMOUS )
    {
        memblk_t *nb = mb->next;

        for_remain_memblk(heap, nb)
            if (nb->handle == handle)
                return PMM_ENOMEM;
    }

    split_memblk(mb, size);
    set_inuse(mb, handle);

    return memblk_buffer(mb);
}

/*
 * returns the address of the memory block associated with the
 * specified handle.  
 *
 * A return value of 0x00000000 indicates that the handle does not
 * correspond to a currently allocated memory block.
 */
static uint32_t
pmmFind(uint32_t handle)
{
    memblk_t *mb;

    if ( handle == PMM_HANDLE_ANONYMOUS )
        return 0;

    mb = pmm_find_handle(&pmm_data.heap, handle);
    if ( mb == NULL )
        mb = pmm_find_handle(&pmm_data.ext_heap, handle);

    return mb ? memblk_buffer(mb) : 0;
}

/* 
 * frees the specified memory block that was previously allocated by
 * pmmAllocate.
 *
 * If the memory block was deallocated correctly, the return value is
 * 0x00000000. If there was an error, the return value is non-zero.
 */
static uint32_t
pmmDeallocate(uint32_t buffer)
{
    memblk_t *mb = buffer_memblk(buffer);

    if ( !memblk_is_inuse(mb) )
        return PMM_EINVAL;

    set_avail(mb);
    return 0;
}


union pmm_args {
    uint16_t function;
    struct pmmAllocArgs alloc;
    struct pmmFindArgs find;
    struct pmmDeallocateArgs dealloc;
} __attribute__ ((packed));

/*
 * entry function of all PMM services.
 *
 * Values returned to the caller are placed in the DX:AX register
 * pair. The flags and all registers, other than DX and AX, are
 * preserved across calls to PMM services.
 */
uint32_t
pmm(void *argp)
{
    union pmm_args *ap = argp;
    uint32_t ret = PMM_EINVAL;

    if ( pmm_data.heap.head == HEAP_NOT_INITIALIZED )
        pmm_initalize();

    switch ( ap->function )
    {
    case PMM_FUNCTION_ALLOCATE:
        ret = pmmAllocate(ap->alloc.length, ap->alloc.handle, ap->alloc.flags);
        PMM_DEBUG("Alloc length=%x handle=%x flags=%x ret=%x\n", 
                  ap->alloc.length, ap->alloc.handle, ap->alloc.flags, ret);
        break;

    case PMM_FUNCTION_FIND:
        ret = pmmFind(ap->find.handle);
        PMM_DEBUG("Find handle=%x ret=%x\n", ap->find.handle, ret);
        break;

    case PMM_FUNCTION_DEALLOC:
        ret = pmmDeallocate(ap->dealloc.buffer);
        PMM_DEBUG("Dealloc buffer=%x ret=%x\n", ap->dealloc.buffer, ret);
        break;

    default:
        PMM_DEBUG("Invalid function:%d\n", ap->function);
        break;
    }

    return ret;
}
