/******************************************************************************
 * proc_cmd.h
 * 
 * Interface to /proc/cmd and /proc/xeno/privcmd.
 */

#ifndef __PROC_CMD_H__
#define __PROC_CMD_H__

typedef struct privcmd_hypercall
{
    unsigned long op;
    unsigned long arg[5];
} privcmd_hypercall_t;

typedef struct privcmd_blkmsg
{
    unsigned long op;
    void         *buf;
    int           buf_size;
} privcmd_blkmsg_t;

#define IOCTL_PRIVCMD_HYPERCALL        \
    _IOC(_IOC_NONE, 'P', 0, sizeof(privcmd_hypercall_t))
#define IOCTL_PRIVCMD_BLKMSG           \
    _IOC(_IOC_NONE, 'P', 1, sizeof(privcmd_blkmsg_t))

#endif /* __PROC_CMD_H__ */
