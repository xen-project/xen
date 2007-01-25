#ifndef XG_PRIVATE_H
#define XG_PRIVATE_H

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "xenctrl.h"
#include "xenguest.h"
#include "xc_private.h"

#include <xen/sys/privcmd.h>
#include <xen/memory.h>
#include <xen/elfnote.h>

#ifndef ELFSIZE
#include <limits.h>
#if UINT_MAX == ULONG_MAX
#define ELFSIZE 32
#else
#define ELFSIZE 64
#endif
#endif

char *xc_read_image(const char *filename, unsigned long *size);
char *xc_inflate_buffer(const char *in_buf,
                        unsigned long in_size,
                        unsigned long *out_size);

unsigned long csum_page (void * page);

#define _PAGE_PRESENT   0x001
#define _PAGE_RW        0x002
#define _PAGE_USER      0x004
#define _PAGE_PWT       0x008
#define _PAGE_PCD       0x010
#define _PAGE_ACCESSED  0x020
#define _PAGE_DIRTY     0x040
#define _PAGE_PAT       0x080
#define _PAGE_PSE       0x080
#define _PAGE_GLOBAL    0x100

#define L1_PAGETABLE_SHIFT_I386       12
#define L2_PAGETABLE_SHIFT_I386       22
#define L1_PAGETABLE_ENTRIES_I386   1024
#define L2_PAGETABLE_ENTRIES_I386   1024

#define L1_PAGETABLE_SHIFT_PAE        12
#define L2_PAGETABLE_SHIFT_PAE        21
#define L3_PAGETABLE_SHIFT_PAE        30
#define L1_PAGETABLE_ENTRIES_PAE     512
#define L2_PAGETABLE_ENTRIES_PAE     512
#define L3_PAGETABLE_ENTRIES_PAE       4

#define L1_PAGETABLE_SHIFT_X86_64     12
#define L2_PAGETABLE_SHIFT_X86_64     21
#define L3_PAGETABLE_SHIFT_X86_64     30
#define L4_PAGETABLE_SHIFT_X86_64     39
#define L1_PAGETABLE_ENTRIES_X86_64  512
#define L2_PAGETABLE_ENTRIES_X86_64  512
#define L3_PAGETABLE_ENTRIES_X86_64  512
#define L4_PAGETABLE_ENTRIES_X86_64  512

#if defined(__i386__)
#define L1_PAGETABLE_SHIFT     L1_PAGETABLE_SHIFT_I386
#define L2_PAGETABLE_SHIFT     L2_PAGETABLE_SHIFT_I386
#define L1_PAGETABLE_ENTRIES   L1_PAGETABLE_ENTRIES_I386
#define L2_PAGETABLE_ENTRIES   L2_PAGETABLE_ENTRIES_I386
#elif defined(__x86_64__)
#define L1_PAGETABLE_SHIFT     L1_PAGETABLE_SHIFT_X86_64
#define L2_PAGETABLE_SHIFT     L2_PAGETABLE_SHIFT_X86_64
#define L3_PAGETABLE_SHIFT     L3_PAGETABLE_SHIFT_X86_64
#define L4_PAGETABLE_SHIFT     L4_PAGETABLE_SHIFT_X86_64
#define L1_PAGETABLE_ENTRIES   L1_PAGETABLE_ENTRIES_X86_64
#define L2_PAGETABLE_ENTRIES   L2_PAGETABLE_ENTRIES_X86_64
#define L3_PAGETABLE_ENTRIES   L3_PAGETABLE_ENTRIES_X86_64
#define L4_PAGETABLE_ENTRIES   L4_PAGETABLE_ENTRIES_X86_64
#endif

typedef uint32_t l1_pgentry_32_t;
typedef uint32_t l2_pgentry_32_t;
typedef uint64_t l1_pgentry_64_t;
typedef uint64_t l2_pgentry_64_t;
typedef uint64_t l3_pgentry_64_t;
typedef uint64_t l4_pgentry_64_t;

#if defined(__i386__)
typedef l1_pgentry_32_t l1_pgentry_t;
typedef l2_pgentry_32_t l2_pgentry_t;
#elif defined(__x86_64__)
typedef l1_pgentry_64_t l1_pgentry_t;
typedef l2_pgentry_64_t l2_pgentry_t;
typedef l3_pgentry_64_t l3_pgentry_t;
typedef l4_pgentry_64_t l4_pgentry_t;
#endif

#define l1_table_offset_i386(_a) \
  (((_a) >> L1_PAGETABLE_SHIFT_I386) & (L1_PAGETABLE_ENTRIES_I386 - 1))
#define l2_table_offset_i386(_a) \
  (((_a) >> L2_PAGETABLE_SHIFT_I386) & (L2_PAGETABLE_ENTRIES_I386 - 1))

#define l1_table_offset_pae(_a) \
  (((_a) >> L1_PAGETABLE_SHIFT_PAE) & (L1_PAGETABLE_ENTRIES_PAE - 1))
#define l2_table_offset_pae(_a) \
  (((_a) >> L2_PAGETABLE_SHIFT_PAE) & (L2_PAGETABLE_ENTRIES_PAE - 1))
#define l3_table_offset_pae(_a) \
  (((_a) >> L3_PAGETABLE_SHIFT_PAE) & (L3_PAGETABLE_ENTRIES_PAE - 1))

#define l1_table_offset_x86_64(_a) \
  (((_a) >> L1_PAGETABLE_SHIFT_X86_64) & (L1_PAGETABLE_ENTRIES_X86_64 - 1))
#define l2_table_offset_x86_64(_a) \
  (((_a) >> L2_PAGETABLE_SHIFT_X86_64) & (L2_PAGETABLE_ENTRIES_X86_64 - 1))
#define l3_table_offset_x86_64(_a) \
  (((_a) >> L3_PAGETABLE_SHIFT_X86_64) & (L3_PAGETABLE_ENTRIES_X86_64 - 1))
#define l4_table_offset_x86_64(_a) \
  (((_a) >> L4_PAGETABLE_SHIFT_X86_64) & (L4_PAGETABLE_ENTRIES_X86_64 - 1))

#if defined(__i386__)
#define l1_table_offset(_a) l1_table_offset_i386(_a)
#define l2_table_offset(_a) l2_table_offset_i386(_a)
#elif defined(__x86_64__)
#define l1_table_offset(_a) l1_table_offset_x86_64(_a)
#define l2_table_offset(_a) l2_table_offset_x86_64(_a)
#define l3_table_offset(_a) l3_table_offset_x86_64(_a)
#define l4_table_offset(_a) l4_table_offset_x86_64(_a)
#endif

#define PAGE_SHIFT_X86          12
#define PAGE_SIZE_X86           (1UL << PAGE_SHIFT_X86)
#define PAGE_MASK_X86           (~(PAGE_SIZE_X86-1))

#define PAGE_SHIFT_IA64         14
#define PAGE_SIZE_IA64          (1UL << PAGE_SHIFT_IA64)
#define PAGE_MASK_IA64          (~(PAGE_SIZE_IA64-1))

struct domain_setup_info
{
    uint64_t v_start;
    uint64_t v_end;
    uint64_t v_kernstart;
    uint64_t v_kernend;
    uint64_t v_kernentry;

    uint64_t elf_paddr_offset;

#define PAEKERN_no           0
#define PAEKERN_yes          1
#define PAEKERN_extended_cr3 2
#define PAEKERN_bimodal      3
    unsigned int  pae_kernel;

    unsigned int  load_symtab;
    unsigned long symtab_addr;
    unsigned long symtab_len;

    /*
     * Only one of __elfnote_* or __xen_guest_string will be
     * non-NULL.
     *
     * You should use the xen_elfnote_* accessors below in order to
     * pickup the correct one and retain backwards compatibility.
     */
    const void *__elfnote_section, *__elfnote_section_end;
    const char *__xen_guest_string;
};

typedef int (*parseimagefunc)(const char *image, unsigned long image_size,
                              struct domain_setup_info *dsi);
typedef int (*loadimagefunc)(const char *image, unsigned long image_size,
                             int xch,
                             uint32_t dom, xen_pfn_t *parray,
                             struct domain_setup_info *dsi);

/*
 * If an ELF note of the given type is found then the value contained
 * in the note is returned and *defined is set to non-zero. If no such
 * note is found then *defined is set to 0 and 0 is returned.
 */
extern unsigned long long xen_elfnote_numeric(const struct domain_setup_info *dsi,
					      int type, int *defined);

/*
 * If an ELF note of the given type is found then the string contained
 * in the value is returned, otherwise NULL is returned.
 */
extern const char * xen_elfnote_string(const struct domain_setup_info *dsi,
				       int type);

struct load_funcs
{
    parseimagefunc parseimage;
    loadimagefunc loadimage;
};

#define mfn_mapper_queue_size 128

typedef struct mfn_mapper {
    int xc_handle;
    int size;
    int prot;
    int error;
    int max_queue_size;
    void * addr;
    privcmd_mmap_t ioctl;

} mfn_mapper_t;

int xc_copy_to_domain_page(int xc_handle, uint32_t domid,
                            unsigned long dst_pfn, const char *src_page);

void xc_map_memcpy(unsigned long dst, const char *src, unsigned long size,
                   int xch, uint32_t dom, xen_pfn_t *parray,
                   unsigned long vstart);

int pin_table(int xc_handle, unsigned int type, unsigned long mfn,
              domid_t dom);

/* image loading */
int probe_elf(const char *image, unsigned long image_size,
              struct load_funcs *funcs);
int probe_bin(const char *image, unsigned long image_size,
              struct load_funcs *funcs);

#endif /* XG_PRIVATE_H */
