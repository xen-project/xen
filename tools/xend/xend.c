/******************************************************************************
 * xend.c
 * 
 * The grand Xen daemon. For now it's just a virtual-console concentrator.
 * 
 * Copyright (c) 2004, K A Fraser
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <xc.h>

/* NB. The following should be kept in sync with the kernel's evtchn driver. */
#define EVTCHN_DEV_NAME  "/dev/xen/evtchn"
#define EVTCHN_DEV_MAJOR 10
#define EVTCHN_DEV_MINOR 200
#define PORT_NORMAL     0x0000   /* A standard event notification.      */ 
#define PORT_DISCONNECT 0x8000   /* A port-disconnect notification.     */
#define PORTIDX_MASK    0x7fff   /* Strip subtype to obtain port index. */
#define EVTCHN_RESET _IO('E', 1) /* Clear notification buffer. Clear errors. */

/* Error macros. */
#define ERROR(_f, _a...)     \
    fprintf ( stderr, "ERROR: " _f "\n" , ## _a );
#define SYS_ERROR(_f, _a...) \
    fprintf ( stderr, "ERROR: " _f " [errno=%d (%s)]\n" , \
              ## _a , errno , strerror(errno) );
#define HINT(_f, _a...)      \
    fprintf ( stderr, "Hint: " _f "\n" , ## _a );
#define ROOT_HINT() HINT("You must execute this daemon as root.")
#define DOM0_HINT() HINT("You must execute this daemon " \
                         "on a privileged Xenolinux instance (e.g., DOM0).")

/* The following is to be shared with guest kernels. */
typedef struct {
    u8 cmd_type;     /* echoed in response */
    u8 cmd_subtype;  /* echoed in response */
    u8 id;           /* echoed in response */
    u8 length;       /* number of bytes in 'msg' */
    unsigned char msg[60]; /* command-specific message data */
} control_msg_t;
#define CONTROL_RING_SIZE 8
typedef unsigned int CONTROL_RING_IDX;
#define MASK_CONTROL_IDX(_i) ((_i)&(CONTROL_RING_SIZE-1))
typedef struct {
    control_msg_t tx_ring[CONTROL_RING_SIZE]; /* guest -> DOM0 */
    control_msg_t rx_ring[CONTROL_RING_SIZE]; /* DOM0 -> guest */
    CONTROL_RING_IDX tx_req_prod, tx_resp_prod;
    CONTROL_RING_IDX rx_req_prod, rx_resp_prod;
} control_comms_t;
#define CMD_CONSOLE      0
#define CMD_CONSOLE_DATA 0

#define PAGE_SHIFT 12
#define PAGE_SIZE  (1<<PAGE_SHIFT)

typedef struct {
    u64              dom;
    control_comms_t *comms;
    CONTROL_RING_IDX tx_req_cons, tx_resp_prod;
    CONTROL_RING_IDX rx_req_cons, rx_resp_prod;
} portinfo_t;

static portinfo_t portinfo[1024];    

static control_comms_t *map_comms(int fd, unsigned long pfn)
{
    char *vaddr = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE,
                       MAP_SHARED, fd, pfn << PAGE_SHIFT);
    if ( vaddr == MAP_FAILED )
        return NULL;
    return (control_comms_t *)(vaddr + 2048);
}

static void unmap_comms(int fd, control_comms_t *c)
{
    char *vaddr = (char *)c - 2048;
    (void)munmap(vaddr, PAGE_SIZE);
}

#define PORT_CHUNK 4
int main(int argc, char **argv)
{
    int fd, memfd, xch, chunk;
    unsigned int bytes, i, port, portid, status;
    u64 domid;
    u16 buf[PORT_CHUNK];

    if ( (fd = open(EVTCHN_DEV_NAME, O_RDWR)) == -1 )
    {
        SYS_ERROR("Could not open '%s'", EVTCHN_DEV_NAME);
        ROOT_HINT();
        HINT("On a non-devfs system you must run 'mknod %s c %d %d'.",
             EVTCHN_DEV_NAME, EVTCHN_DEV_MAJOR, EVTCHN_DEV_MINOR);
        exit(1);
    }

    if ( (memfd = open("/dev/mem", O_RDWR)) == -1 )
    {
        SYS_ERROR("Could not open '/dev/mem'");
        ROOT_HINT();
        exit(1);
    }

    if ( (xch = xc_interface_open()) == -1 )
    {
        SYS_ERROR("Could not open Xen control interface");
        ROOT_HINT();
        DOM0_HINT();
        exit(1);
    }

    while ( (bytes = read(fd, buf, sizeof(buf))) == -1 )
    {
        if ( errno == EINTR )
            continue;
        SYS_ERROR("Unexpected error reading '%s'.", EVTCHN_DEV_NAME);
        exit(1);
    }

    if ( (bytes == 0) || ((bytes & 1) != 0) )
    {
        ERROR("Short or bad read length (%d bytes) from '%s'.",
              bytes, EVTCHN_DEV_NAME);
        exit(1);
    }

    chunk = bytes / 2;
    for ( i = 0; i < chunk; i++ )
    {
        port = buf[i] & PORTIDX_MASK;
        if ( buf[i] & PORT_DISCONNECT )
        {
            if ( portinfo[port].comms == NULL )
                continue;
            unmap_comms(memfd, portinfo[port].comms);
            portinfo[port].comms = NULL;
            (void)write(fd, &buf[i], sizeof(u16));
            (void)xc_evtchn_close(xch, DOMID_SELF, port);
        }
        else
        {
            if ( portinfo[port].comms == NULL )
            {
                xc_dominfo_t info;
                xc_evtchn_status(xch, DOMID_SELF, port, 
                                 &domid, &portid, &status);

                if ( (status == EVTCHNSTAT_closed) ||
                     ((status == EVTCHNSTAT_disconnected) && (portid == 0)) )
                {
                    /* Cleanup sanity: we'll be the grim reaper. */
                    (void)write(fd, &buf[i], sizeof(u16)); /* PORT_NORMAL */
                    buf[i] |= PORT_DISCONNECT;
                    (void)write(fd, &buf[i], sizeof(u16)); /* PORT_DISCON */
                    continue;
                }

                /* We only deal with initial ports (id == 0). */
                if ( portid != 0 )
                    continue;

                xc_domain_getinfo(xch, domid, 1, &info);
                portinfo[port].comms = 
                    map_comms(memfd, info.shared_info_frame);
                portinfo[port].dom = domid;
                portinfo[port].tx_req_cons  = 0;
                portinfo[port].tx_resp_prod = 0;
                portinfo[port].rx_req_cons  = 0;
                portinfo[port].rx_resp_prod = 0;
            }

            do {
                xc_evtchn_send(xch, port);
                write(fd, &buf[i], sizeof(u16));
            } while ( 0 );
        }
    }

    (void)xc_interface_close(xch);
    (void)close(memfd);
    (void)close(fd);

    return 0;
}
