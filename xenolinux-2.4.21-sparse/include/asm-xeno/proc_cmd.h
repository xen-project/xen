/******************************************************************************
 * proc_cmd.h
 * 
 * Interface to /proc/cmd and /proc/xeno/privcmd.
 */

#ifndef __PROC_CMD_H__
#define __PROC_CMD_H__

#define IOCTL_PRIVCMD_HYPERCALL        0
#define IOCTL_PRIVCMD_BLKMSG           1
#define IOCTL_PRIVCMD_LINDEV_TO_XENDEV 2
#define IOCTL_PRIVCMD_XENDEV_TO_LINDEV 3

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

#endif /* __PROC_CMD_H__ */
