/* IOCTLs used when access /proc/xeno/dom0_cmd. */
#ifndef __DOM0_H__
#define __DOM0_H__

#define IOCTL_DOM0_CREATEDOMAIN _IOC(_IOC_READ, 'x', 0, sizeof(struct dom0_createdomain_args))
#define IOCTL_DOM0_MAPDOMMEM _IOC(_IOC_READ, 'x', 1, sizeof(struct dom0_mapdommem_args))
#define IOCTL_DOM0_UNMAPDOMMEM _IOC(_IOC_READ, 'x', 2, sizeof(struct dom0_unmapdommem_args))
#define IOCTL_DOM0_DOPGUPDATES _IOC(_IOC_READ, 'x', 3, sizeof(struct dom0_dopgupdates_args))

struct dom0_createdomain_args
{
    unsigned int kb_mem;
    const char *name;
};

struct dom0_mapdommem_args
{
    unsigned int domain;
    unsigned start_pfn;
    unsigned tot_pages;  
};

struct dom0_unmapdommem_args
{
    unsigned long vaddr;
    unsigned long start_pfn;
    unsigned long tot_pages;
};

struct dom0_dopgupdates_args
{
    unsigned long pgt_update_arr;
    unsigned long num_pgt_updates;
};

#endif __DOM0_H__ /* __DOM0_H__ */
