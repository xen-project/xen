
#ifndef __NetBSDRump_PRIVCMD_H__
#define __NetBSDRump_PRIVCMD_H__

typedef struct privcmd_hypercall
{
    unsigned long op;
    unsigned long arg[5];
    long retval;
} privcmd_hypercall_t;

typedef struct privcmd_mmap_entry {
    unsigned long va;
    unsigned long mfn;
    unsigned long npages;
} privcmd_mmap_entry_t; 

typedef struct privcmd_mmap {
    int num;
    domid_t dom; /* target domain */
    privcmd_mmap_entry_t *entry;
} privcmd_mmap_t; 

typedef struct privcmd_mmapbatch {
    int num;     /* number of pages to populate */
    domid_t dom; /* target domain */
    unsigned long addr;  /* virtual address */
    unsigned long *arr; /* array of mfns - top nibble set on err */
} privcmd_mmapbatch_t; 

#endif
