/******************************************************************************
 * proc_cmd.h
 * 
 * Interface to /proc/cmd and /proc/xen/privcmd.
 */

#ifndef __PROC_CMD_H__
#define __PROC_CMD_H__

typedef struct privcmd_hypercall
{
    unsigned long op;
    unsigned long arg[5];
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

typedef struct privcmd_blkmsg
{
    unsigned long op;
    void         *buf;
    int           buf_size;
} privcmd_blkmsg_t;

/*
 * @cmd: IOCTL_PRIVCMD_HYPERCALL
 * @arg: &privcmd_hypercall_t
 * Return: Value returned from execution of the specified hypercall.
 */
#define IOCTL_PRIVCMD_HYPERCALL         \
    _IOC(_IOC_NONE, 'P', 0, sizeof(privcmd_hypercall_t))

/*
 * @cmd: IOCTL_PRIVCMD_INITDOMAIN_EVTCHN
 * @arg: n/a
 * Return: Port associated with domain-controller end of control event channel
 *         for the initial domain.
 */
#define IOCTL_PRIVCMD_INITDOMAIN_EVTCHN \
    _IOC(_IOC_NONE, 'P', 1, 0)
#define IOCTL_PRIVCMD_MMAP             \
    _IOC(_IOC_NONE, 'P', 2, sizeof(privcmd_mmap_t))

#endif /* __PROC_CMD_H__ */
