#ifndef XG_PRIVATE_H
#define XG_PRIVATE_H

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "xenctrl.h"

#include <xen/linux/privcmd.h>

char *xc_read_kernel_image(const char *filename, unsigned long *size);
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

#if defined(__i386__)
#define L1_PAGETABLE_SHIFT       12
#define L2_PAGETABLE_SHIFT       22
#define L1_PAGETABLE_SHIFT_PAE   12
#define L2_PAGETABLE_SHIFT_PAE   21
#define L3_PAGETABLE_SHIFT_PAE   30
#elif defined(__x86_64__)
#define L1_PAGETABLE_SHIFT      12
#define L2_PAGETABLE_SHIFT      21
#define L3_PAGETABLE_SHIFT      30
#define L4_PAGETABLE_SHIFT      39
#endif

#if defined(__i386__) 
#define ENTRIES_PER_L1_PAGETABLE 1024
#define ENTRIES_PER_L2_PAGETABLE 1024
#define L1_PAGETABLE_ENTRIES_PAE  512
#define L2_PAGETABLE_ENTRIES_PAE  512
#define L3_PAGETABLE_ENTRIES_PAE    4
#elif defined(__x86_64__)
#define L1_PAGETABLE_ENTRIES    512
#define L2_PAGETABLE_ENTRIES    512
#define L3_PAGETABLE_ENTRIES    512
#define L4_PAGETABLE_ENTRIES    512
#endif
 
#define PAGE_SHIFT              XC_PAGE_SHIFT
#define PAGE_SIZE               (1UL << PAGE_SHIFT)
#define PAGE_MASK               (~(PAGE_SIZE-1))

typedef u32 l1_pgentry_32_t;
typedef u32 l2_pgentry_32_t;
typedef u64 l1_pgentry_64_t;
typedef u64 l2_pgentry_64_t;
typedef u64 l3_pgentry_64_t;
typedef unsigned long l1_pgentry_t;
typedef unsigned long l2_pgentry_t;
#if defined(__x86_64__)
typedef unsigned long l3_pgentry_t;
typedef unsigned long l4_pgentry_t;
#endif

#if defined(__i386__)
#define l1_table_offset(_a) \
          (((_a) >> L1_PAGETABLE_SHIFT) & (ENTRIES_PER_L1_PAGETABLE - 1))
#define l2_table_offset(_a) \
          ((_a) >> L2_PAGETABLE_SHIFT)
#define l1_table_offset_pae(_a) \
  (((_a) >> L1_PAGETABLE_SHIFT_PAE) & (L1_PAGETABLE_ENTRIES_PAE - 1))
#define l2_table_offset_pae(_a) \
  (((_a) >> L2_PAGETABLE_SHIFT_PAE) & (L2_PAGETABLE_ENTRIES_PAE - 1))
#define l3_table_offset_pae(_a) \
	(((_a) >> L3_PAGETABLE_SHIFT_PAE) & (L3_PAGETABLE_ENTRIES_PAE - 1))
#elif defined(__x86_64__)
#define l1_table_offset(_a) \
  (((_a) >> L1_PAGETABLE_SHIFT) & (L1_PAGETABLE_ENTRIES - 1))
#define l2_table_offset(_a) \
  (((_a) >> L2_PAGETABLE_SHIFT) & (L2_PAGETABLE_ENTRIES - 1))
#define l3_table_offset(_a) \
	(((_a) >> L3_PAGETABLE_SHIFT) & (L3_PAGETABLE_ENTRIES - 1))
#define l4_table_offset(_a) \
	(((_a) >> L4_PAGETABLE_SHIFT) & (L4_PAGETABLE_ENTRIES - 1))
#endif

#define ERROR(_m, _a...)                                \
do {                                                    \
    int __saved_errno = errno;                          \
    fprintf(stderr, "ERROR: " _m "\n" , ## _a );        \
    errno = __saved_errno;                              \
} while (0)


#define PERROR(_m, _a...)                                       \
do {                                                            \
    int __saved_errno = errno;                                  \
    fprintf(stderr, "ERROR: " _m " (%d = %s)\n" , ## _a ,       \
            __saved_errno, strerror(__saved_errno));            \
    errno = __saved_errno;                                      \
} while (0)


struct domain_setup_info
{
    unsigned long v_start;
    unsigned long v_end;
    unsigned long v_kernstart;
    unsigned long v_kernend;
    unsigned long v_kernentry;

    unsigned int  load_symtab;
    unsigned int  pae_kernel;
    unsigned long symtab_addr;
    unsigned long symtab_len;
};

typedef int (*parseimagefunc)(char *image, unsigned long image_size,
			      struct domain_setup_info *dsi);
typedef int (*loadimagefunc)(char *image, unsigned long image_size, int xch,
			     u32 dom, unsigned long *parray,
			     struct domain_setup_info *dsi);

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

unsigned long xc_get_m2p_start_mfn (int xc_handle);

int xc_copy_to_domain_page(int xc_handle, u32 domid,
                            unsigned long dst_pfn, void *src_page);

unsigned long xc_get_filesz(int fd);

void xc_map_memcpy(unsigned long dst, char *src, unsigned long size,
                   int xch, u32 dom, unsigned long *parray,
                   unsigned long vstart);

int pin_table(int xc_handle, unsigned int type, unsigned long mfn,
	      domid_t dom);

/* image loading */
int probe_elf(char *image, unsigned long image_size, struct load_funcs *funcs);
int probe_bin(char *image, unsigned long image_size, struct load_funcs *funcs);
int probe_aout9(char *image, unsigned long image_size, struct load_funcs *funcs);

#endif

