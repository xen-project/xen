/* evtchn.c
 *
 * Interfaces to event channel driver.
 *
 * Most of this is directly based on the original xu interface to python 
 * written by Keir Fraser.
 *
 * (c) 2004, Andrew Warfield
 *
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h> /* XOPEN drops makedev, this gets it back. */
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "xcs.h"

static int evtchn_fd = -1;

/* NB. The following should be kept in sync with the kernel's evtchn driver. */
#define EVTCHN_DEV_NAME  "/dev/xen/evtchn"
#define EVTCHN_DEV_MAJOR 10
#define EVTCHN_DEV_MINOR 201
/* /dev/xen/evtchn ioctls: */
/* EVTCHN_RESET: Clear and reinit the event buffer. Clear error condition. */
#define EVTCHN_RESET  _IO('E', 1)
/* EVTCHN_BIND: Bind to teh specified event-channel port. */
#define EVTCHN_BIND   _IO('E', 2)
/* EVTCHN_UNBIND: Unbind from the specified event-channel port. */
#define EVTCHN_UNBIND _IO('E', 3)

int evtchn_read()
{
    u16 v;
    int bytes;

    while ( (bytes = read(evtchn_fd, &v, sizeof(v))) == -1 )
    {
        if ( errno == EINTR )
            continue;
        /* EAGAIN was cased to return 'None' in the python version... */
        return -errno;
    }
    
    if ( bytes == sizeof(v) )
        return v;
    
    /* bad return */
    return -1;
}

void evtchn_unmask(u16 idx)
{
    (void)write(evtchn_fd, &idx, sizeof(idx));
}

int evtchn_bind(int idx)
{
    if ( ioctl(evtchn_fd, EVTCHN_BIND, idx) != 0 )
        return -errno;
    
    return 0;
}

int evtchn_unbind(int idx)
{
    if ( ioctl(evtchn_fd, EVTCHN_UNBIND, idx) != 0 )
        return -errno;

    return 0;
}

int evtchn_open(void)
{
    struct stat st;
    
    /* Make sure any existing device file links to correct device. */
    if ( (lstat(EVTCHN_DEV_NAME, &st) != 0) ||
         !S_ISCHR(st.st_mode) ||
         (st.st_rdev != makedev(EVTCHN_DEV_MAJOR, EVTCHN_DEV_MINOR)) )
        (void)unlink(EVTCHN_DEV_NAME);

 reopen:
    evtchn_fd = open(EVTCHN_DEV_NAME, O_NONBLOCK|O_RDWR); 
    if ( evtchn_fd == -1 )
    {
        if ( (errno == ENOENT) &&
             ((mkdir("/dev/xen", 0755) == 0) || (errno == EEXIST)) &&
             (mknod(EVTCHN_DEV_NAME, S_IFCHR|0600, 
                    makedev(EVTCHN_DEV_MAJOR,EVTCHN_DEV_MINOR)) == 0) )
            goto reopen;
        return -errno;
    }
    /*set_cloexec(evtchn_fd); -- no longer required*/
printf("Eventchan_fd is %d\n", evtchn_fd);
    return evtchn_fd;
}

void evtchn_close()
{
    (void)close(evtchn_fd);
    evtchn_fd = -1;
}

