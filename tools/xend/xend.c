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
#include <sys/poll.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <xc.h>
#include <asm-xeno/control_if.h>

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

#if 0
#define DPRINTF(_f, _a...)  \
    fprintf ( stdout, _f "\n" , ## _a );
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

/* Per-port Tx/Rx buffering. */
#define CONBUFSZ 65536
#define MASK_CONBUF_IDX(_i) ((_i)&(CONBUFSZ-1))

struct portinfo;
typedef struct portinfo {
    u64              dom;
    control_if_t    *interface;
    CONTROL_RING_IDX tx_req_cons, tx_resp_prod;
    CONTROL_RING_IDX rx_req_prod, rx_resp_cons;
    char            *tx_buf, *rx_buf;
    unsigned int     txp, txc, rxp, rxc;
#define CONSTAT_CLOSED    0
#define CONSTAT_LISTENING 1
#define CONSTAT_CONNECTED 2
    int              con_fd, con_status;
    struct portinfo **pprev, *next; /* links to other active ports */
} portinfo_t;

#define PORT(_pinfo) ((_pinfo)-portinfo)
#define TX_EMPTY(_pinfo) ((_pinfo)->txp == (_pinfo)->txc)
#define TX_FULL(_pinfo)  (((_pinfo)->txp - (_pinfo)->txc) == CONBUFSZ)
#define RX_EMPTY(_pinfo) ((_pinfo)->rxp == (_pinfo)->rxc)
#define RX_FULL(_pinfo)  (((_pinfo)->rxp - (_pinfo)->rxc) == CONBUFSZ)

static portinfo_t *active_head;   /* linked list of active ports */
static portinfo_t portinfo[1024]; /* array of all ports */    
static int xc_fd, evt_fd, mem_fd;

#define PAGE_SIZE           4096 /* size of a machine page frame            */
#define BATCH_SIZE           512 /* maximum notifications to read at a time */

static int make_consock_listener(portinfo_t *pinfo);
static int make_consock_connected(portinfo_t *pinfo);
static void make_consock_closed(portinfo_t *pinfo);
static void do_consock_read(portinfo_t *pinfo);
static void do_consock_write(portinfo_t *pinfo);
static int process_evtchn_reads(portinfo_t *pinfo);
static int process_evtchn_writes(portinfo_t *pinfo);

static control_if_t *map_control_interface(int fd, unsigned long pfn)
{
    char *vaddr = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE,
                       MAP_SHARED, fd, pfn * PAGE_SIZE);
    if ( vaddr == MAP_FAILED )
        return NULL;
    return (control_if_t *)(vaddr + 2048);
}

static void unmap_control_interface(int fd, control_if_t *c)
{
    char *vaddr = (char *)c - 2048;
    (void)munmap(vaddr, PAGE_SIZE);
}

/* Returns TRUE if the channel is open on exit. */
static int handle_channel_exception(unsigned int port)
{
    xc_dominfo_t info;
    unsigned int remote_port, status;
    u64          remote_dom;
    u16          wbuf;
    portinfo_t  *pinfo = &portinfo[port];

    if ( xc_evtchn_status(xc_fd, DOMID_SELF, port, 
                          &remote_dom, &remote_port, &status) != 0 )
    {
        SYS_ERROR("Unexpected failure when obtaining port-%d status.", port);
        exit(1);
    }
    
    if ( status != EVTCHNSTAT_connected )
    {
        DPRINTF("Port %d not connected: cleaning up.", port);
        if ( pinfo->interface != NULL )
        {
            unmap_control_interface(mem_fd, pinfo->interface);
            pinfo->interface = NULL;
            *(pinfo->pprev) = pinfo->next;
            if ( pinfo->next != NULL )
                pinfo->next->pprev = pinfo->pprev;
            make_consock_closed(pinfo);
            free(pinfo->tx_buf);
            free(pinfo->rx_buf);
            memset(pinfo, 0, sizeof(*pinfo));
        }
        /* Cleanup sanity: we'll be the grim reaper. */
        wbuf = port | PORT_NORMAL;
        (void)write(evt_fd, &wbuf, sizeof(wbuf));
        wbuf = port | PORT_DISCONNECT;
        (void)write(evt_fd, &wbuf, sizeof(wbuf));
        if ( status == EVTCHNSTAT_disconnected )
            (void)xc_evtchn_close(xc_fd, DOMID_SELF, port);
        return 0;
    }

    /* We only deal with initial ports (id == 0). */
    if ( remote_port != 0 )
        return 0;

    if ( pinfo->interface == NULL )
    {
        DPRINTF("New control interface for DOM%llu on port %d.", 
                remote_dom, port);
        if ( xc_domain_getinfo(xc_fd, remote_dom, 1, &info) != 1 )
        {
            SYS_ERROR("Failed to obtain DOM%llu status.", remote_dom);
            exit(1);
        }
        memset(pinfo, 0, sizeof(*pinfo));
        pinfo->interface = 
            map_control_interface(mem_fd, info.shared_info_frame);
        pinfo->tx_buf = malloc(CONBUFSZ);
        pinfo->rx_buf = malloc(CONBUFSZ);
        pinfo->dom = remote_dom;
        pinfo->con_status = CONSTAT_CLOSED;
        if ( !make_consock_listener(pinfo) )
        {
            ERROR("Could not start console %d in listener status.",
                  PORT(pinfo));
            exit(1);
        }
        pinfo->pprev = &active_head;
        if ( (pinfo->next = active_head) != NULL )
            pinfo->next->pprev = &pinfo->next;
        active_head = pinfo;
    }

    return 1;
}

static void process_channel(unsigned int port)
{
    portinfo_t      *pinfo = &portinfo[port];
    u16              wbuf = port;

    /* Acknowledge the notification. */
    (void)write(evt_fd, &wbuf, sizeof(wbuf));

    /* Process requests; send notification if we updated either ring. */
    if ( process_evtchn_reads(pinfo) || process_evtchn_writes(pinfo) )
        (void)xc_evtchn_send(xc_fd, port);
}

int main(int argc, char **argv)
{
    struct pollfd polls[1025]; /* one per port, plus /dev/xeno/evtchn */
    portinfo_t *pinfo;
    unsigned int batch, bytes, i, port, fd_idx;
    u16 buf[BATCH_SIZE];

    /* Ignore writes to disconnected sockets. We clear up later. */
    (void)signal(SIGPIPE, SIG_IGN);
    
    if ( (evt_fd = open(EVTCHN_DEV_NAME, O_NONBLOCK|O_RDWR)) == -1 )
    {
        SYS_ERROR("Could not open '%s'", EVTCHN_DEV_NAME);
        ROOT_HINT();
        HINT("On a non-devfs system you must run 'mknod %s c %d %d'.",
             EVTCHN_DEV_NAME, EVTCHN_DEV_MAJOR, EVTCHN_DEV_MINOR);
        exit(1);
    }

    if ( (mem_fd = open("/dev/mem", O_RDWR)) == -1 )
    {
        SYS_ERROR("Could not open '/dev/mem'");
        ROOT_HINT();
        exit(1);
    }

    if ( (xc_fd = xc_interface_open()) == -1 )
    {
        SYS_ERROR("Could not open Xen control interface");
        ROOT_HINT();
        DOM0_HINT();
        exit(1);
    }

    for ( ; ; )
    {
        polls[0].fd     = evt_fd;
        polls[0].events = POLLIN;

        fd_idx = 1;
        for ( pinfo = active_head; pinfo != NULL; pinfo = pinfo->next )
        {
            switch ( pinfo->con_status )
            {
            case CONSTAT_LISTENING:
                polls[fd_idx].fd     = pinfo->con_fd;
                polls[fd_idx].events = POLLIN;
                fd_idx++;
                break;
            case CONSTAT_CONNECTED:
                polls[fd_idx].fd     = pinfo->con_fd;
                polls[fd_idx].events = POLLIN | (RX_EMPTY(pinfo)?0:POLLOUT);
                fd_idx++;
                break;
            }
        }

        while ( poll(polls, fd_idx, -1) == -1 )
        {
            if ( errno == EINTR )
                continue;
            SYS_ERROR("Unexpected error from poll().");
            exit(1);
        }

        fd_idx = 1;
        for ( pinfo = active_head; pinfo != NULL; pinfo = pinfo->next )
        {
            switch ( pinfo->con_status )
            {
            case CONSTAT_LISTENING:
                if ( ((polls[fd_idx].revents & POLLIN) != 0) )
                    (void)make_consock_connected(pinfo);
                break;
            case CONSTAT_CONNECTED:
                if ( ((polls[fd_idx].revents & POLLOUT) != 0) )
                    do_consock_write(pinfo);
                if ( ((polls[fd_idx].revents & POLLIN) != 0) )
                    do_consock_read(pinfo);
                break;
            }
            fd_idx++;
        }

        while ( (bytes = read(evt_fd, buf, sizeof(buf))) == -1 )
        {
            if ( errno == EINTR )
                continue;
            if ( errno == EAGAIN )
            {
                bytes = 0;
                break;
            }
            SYS_ERROR("Unexpected error while reading '%s'.", EVTCHN_DEV_NAME);
            exit(1);
        }
        
        if ( bytes == 0 )
            continue;

        if ( (bytes & 1) != 0 )
        {
            ERROR("Bad read length (%d bytes) from '%s'.",
                  bytes, EVTCHN_DEV_NAME);
            exit(1);
        }
        
        batch = bytes / sizeof(u16);
        for ( i = 0; i < batch; i++ )
        {
            port = buf[i] & PORTIDX_MASK;
            
            if ( buf[i] & PORT_DISCONNECT )
            {
                DPRINTF("Disconnect on port %d.", port);
                (void)handle_channel_exception(port);
                continue;
            }
            
            if ( portinfo[port].interface == NULL )
            {
                DPRINTF("Unexpected notification on port %d.", port);
                if ( !handle_channel_exception(port) )
                    continue;
            }
            
            process_channel(port);
        }
    }

    (void)xc_interface_close(xc_fd);
    (void)close(mem_fd);
    (void)close(evt_fd);

    return 0;
}


/* Returns non-zero if console is listening on exit. */
static int make_consock_listener(portinfo_t *pinfo)
{
    int reuseaddr_flag = 1;
    struct linger linger;
    int tcp_port = 9600 + PORT(pinfo);
    int fd, flags;
    struct sockaddr_in sa;

    if ( pinfo->con_status == CONSTAT_LISTENING )
        return 1;

    if ( pinfo->con_status == CONSTAT_CONNECTED )
    {
        (void)close(pinfo->con_fd);
        pinfo->con_status = CONSTAT_CLOSED;
    }

    if ( (fd = socket(AF_INET, SOCK_STREAM, 0)) == -1 )
    {
        SYS_ERROR("Could not create TCP socket.");
        return 0;
    }

    linger.l_onoff = 0;
    if ( (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, 
                     &reuseaddr_flag, sizeof(int)) != 0) ||
         (setsockopt(fd, SOL_SOCKET, SO_LINGER, 
                     &linger, sizeof(linger)) != 0) )
    {
        SYS_ERROR("Could not enable immediate reuse of socket port.");
        close(fd);
        return 0;
    }

    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port        = htons(tcp_port);
    if ( bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 )
    {
        SYS_ERROR("Unable to bind to console port %d.", tcp_port);
        close(fd);
        return 0;
    }

    if ( listen(fd, 5) != 0 )
    {
        SYS_ERROR("Unable to listen on console port %d.", tcp_port);
        close(fd);
        return 0;
    }

    if ( ((flags = fcntl(fd, F_GETFL, 0)) < 0) ||
         (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) )
    {
        SYS_ERROR("Unable to set non-blocking status for console listener.");
        close(fd);
        return 0;
    }

    pinfo->con_fd     = fd;
    pinfo->con_status = CONSTAT_LISTENING;
    return 1;
}

/* Returns non-zero if console is connected on exit. */
static int make_consock_connected(portinfo_t *pinfo)
{
    int fd, flags, sa_len;
    struct linger linger;
    struct sockaddr_in sa;

    if ( pinfo->con_status == CONSTAT_CONNECTED )
        return 1;

    if ( pinfo->con_status == CONSTAT_CLOSED )
        return 0;

    if ( (fd = accept(pinfo->con_fd, (struct sockaddr *)&sa, &sa_len)) == -1 )
        return 0;

    linger.l_onoff = 0;
    if ( setsockopt(fd, SOL_SOCKET, SO_LINGER, 
                    &linger, sizeof(linger)) != 0 )
    {
        SYS_ERROR("Could not enable immediate socket death.");
        close(fd);
        return 0;
    }

    if ( ((flags = fcntl(fd, F_GETFL, 0)) < 0) ||
         (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) )
    {
        SYS_ERROR("Unable to set non-blocking status on socket.");
        close(fd);
        return 0;
    }

    (void)close(pinfo->con_fd);

    pinfo->con_fd     = fd;
    pinfo->con_status = CONSTAT_CONNECTED;
    return 1;
}


static void make_consock_closed(portinfo_t *pinfo)
{
    if ( pinfo->con_status != CONSTAT_CLOSED )
        (void)close(pinfo->con_fd);
    pinfo->con_status = CONSTAT_CLOSED;
}


static void do_consock_read(portinfo_t *pinfo)
{
    char buf[1024];
    int  idx, bytes, rc, was_empty = TX_EMPTY(pinfo);

    while ( (rc = read(pinfo->con_fd, &buf, sizeof(buf))) > 0 )
    {
        idx = 0;
        while ( (rc != 0) && !TX_FULL(pinfo) )
        {
            bytes = rc;
            /* Clip copy to ring-buffer wrap. */
            if ( bytes > (CONBUFSZ - MASK_CONBUF_IDX(pinfo->txp)) )
                bytes = CONBUFSZ - MASK_CONBUF_IDX(pinfo->txp);
            /* Clip copy to ring-buffer overflow. */
            if ( bytes > (CONBUFSZ - (pinfo->txp - pinfo->txc)) )
                bytes = CONBUFSZ - (pinfo->txp - pinfo->txc);
            memcpy(&pinfo->tx_buf[MASK_CONBUF_IDX(pinfo->txp)],
                   &buf[idx], bytes);
            pinfo->txp += bytes;
            idx        += bytes;
            rc         -= bytes;
        }
    }

    if ( (rc == 0) || (errno != EAGAIN) )
    {
        DPRINTF("Console client has disconnected.");
        if ( !make_consock_listener(pinfo) )
        {
            ERROR("Could not revert console %d to listener status.",
                  PORT(pinfo));
            exit(1);
        }
    }

    if ( was_empty && !TX_EMPTY(pinfo) )
    {
        /* There is now data to transmit to guest. Kickstart the pipeline. */
        if ( process_evtchn_writes(pinfo) )
            (void)xc_evtchn_send(xc_fd, PORT(pinfo));
    }
}

static void do_consock_write(portinfo_t *pinfo)
{
    int bytes, rc;

    while ( !RX_EMPTY(pinfo) )
    {
        /* Clip transfer to ring-buffer wrap. */
        bytes = CONBUFSZ - MASK_CONBUF_IDX(pinfo->rxc);
        /* Clip transfer to ring-buffer overflow. */
        if ( bytes > (pinfo->rxp - pinfo->rxc) )
            bytes = pinfo->rxp - pinfo->rxc;
        rc = write(pinfo->con_fd, 
                   &pinfo->rx_buf[MASK_CONBUF_IDX(pinfo->rxc)], 
                   bytes);
        if ( rc <= 0 )
            return; /* Nothing to do. Errors cleaned up in reader code. */
        pinfo->rxc += rc;
    }
}

static int process_evtchn_reads(portinfo_t *pinfo)
{
    CONTROL_RING_IDX c;
    control_if_t    *cif = pinfo->interface;
    control_msg_t   *cmsg;
    unsigned int     clen, idx, len, bytes;

    for ( c = pinfo->tx_req_cons; 
          (c != cif->tx_req_prod) && 
              ((c-pinfo->tx_resp_prod) != CONTROL_RING_SIZE);
          c++ )
    {
        cmsg = &cif->tx_ring[MASK_CONTROL_IDX(c)];

        if ( (clen = cmsg->length) > sizeof(cmsg->msg) )
            clen = sizeof(cmsg->msg);

        if ( (cmsg->cmd_type == CMD_CONSOLE) &&
             (cmsg->cmd_subtype == CMD_CONSOLE_DATA) )
        {
            idx = 0;
            len = cmsg->length;
            while ( (len != 0) && !RX_FULL(pinfo) )
            {
                bytes = len;
                /* Clip copy to ring-buffer wrap. */
                if ( bytes > (CONBUFSZ - MASK_CONBUF_IDX(pinfo->rxp)) )
                    bytes = CONBUFSZ - MASK_CONBUF_IDX(pinfo->rxp);
                /* Clip copy to ring-buffer overflow. */
                if ( bytes > (CONBUFSZ - (pinfo->rxp - pinfo->rxc)) )
                    bytes = CONBUFSZ - (pinfo->rxp - pinfo->rxc);
                memcpy(&pinfo->rx_buf[MASK_CONBUF_IDX(pinfo->rxp)],
                       &cmsg->msg[idx], bytes);
                pinfo->rxp += bytes;
                idx += bytes;
                len -= bytes;
            }
        }

        /* Prepare response. No payload; msg type and id same as request. */
        cmsg->length = 0;
    }

    if ( c != pinfo->tx_req_cons )
    {
        /* Update private indexes. */
        pinfo->tx_resp_prod = c;
        pinfo->tx_req_cons  = c;
        /* Queue responses and send a notification to the guest OS. */
        cif->tx_resp_prod   = c;
        return 1;
    }

    return 0;
}

static int process_evtchn_writes(portinfo_t *pinfo)
{
    CONTROL_RING_IDX p, rx_resp_prod;
    control_if_t    *cif = pinfo->interface;
    control_msg_t   *cmsg;
    unsigned int     bytes;

    /* Validate the rx-response producer, an dupdate our consumer if okay. */
    rx_resp_prod = cif->rx_resp_prod;
    if ( (pinfo->rx_resp_cons != rx_resp_prod) &&
         ((pinfo->rx_req_prod - rx_resp_prod) <= CONTROL_RING_SIZE) &&
         ((rx_resp_prod - pinfo->rx_resp_cons) <= CONTROL_RING_SIZE) )
        pinfo->rx_resp_cons = cif->rx_resp_prod;

    for ( p = pinfo->rx_req_prod;
          (p-pinfo->rx_resp_cons) != CONTROL_RING_SIZE;
          p++ )
    {
        if ( TX_EMPTY(pinfo) )
            break;
        cmsg = &cif->rx_ring[MASK_CONTROL_IDX(p)];
        bytes = sizeof(cmsg->msg);
        /* Clip transfer to ring-buffer wrap. */
        if ( bytes > (CONBUFSZ - MASK_CONBUF_IDX(pinfo->txc)) )
            bytes = CONBUFSZ - MASK_CONBUF_IDX(pinfo->txc);
        /* Clip transfer to ring-buffer overflow. */
        if ( bytes > (pinfo->txp - pinfo->txc) )
            bytes = pinfo->txp - pinfo->txc;
        cmsg->cmd_type    = CMD_CONSOLE;
        cmsg->cmd_subtype = CMD_CONSOLE_DATA;
        cmsg->id          = 0xaa;
        cmsg->length      = bytes;
        memcpy(&cmsg->msg[0], 
               &pinfo->tx_buf[MASK_CONBUF_IDX(pinfo->txc)], 
               bytes);
        pinfo->txc += bytes;
    }

    if ( p != pinfo->rx_req_prod )
    {
        pinfo->rx_req_prod  = p;
        cif->rx_req_prod    = p;
        return 1;
    }

    return 0;
}
