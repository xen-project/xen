/*
 * blktaplib.c
 * 
 * userspace interface routines for the blktap driver.
 *
 * (threadsafe(r) version) 
 *
 * (c) 2004 Andrew Warfield.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <err.h>
#include <errno.h>
#include <sys/types.h>
#include <linux/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

                                                                     
#define __COMPILING_BLKTAP_LIB
#include "blktaplib.h"

#if 0
#define DPRINTF(_f, _a...) printf ( _f , ## _a )
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif
#define DEBUG_RING_IDXS 1

#define POLLRDNORM     0x040 

#define BLKTAP_IOCTL_KICK 1

void got_sig_bus();
void got_sig_int();

/* in kernel these are opposite, but we are a consumer now. */
blkif_back_ring_t  fe_ring; /* slightly counterintuitive ;) */
blkif_front_ring_t be_ring; 
ctrl_back_ring_t   ctrl_ring;

unsigned long mmap_vstart = 0;
char *blktap_mem;
int fd = 0;

#define BLKTAP_RING_PAGES       3 /* Ctrl, Back, Front */
/*#define BLKTAP_MMAP_PAGES       ((11 + 1) * 64)*/
#define BLKTAP_MMAP_PAGES \
    ((BLKIF_MAX_SEGMENTS_PER_REQUEST + 1) * BLKIF_RING_SIZE)
#define BLKTAP_MMAP_REGION_SIZE (BLKTAP_RING_PAGES + BLKTAP_MMAP_PAGES)
    
int bad_count = 0;
void bad(void)
{
    bad_count ++;
    if (bad_count > 50) exit(0);
}
/*-----[ ID Manipulation from tap driver code ]--------------------------*/

#define ACTIVE_RING_IDX unsigned short

inline unsigned long MAKE_ID(domid_t fe_dom, ACTIVE_RING_IDX idx)
{
    return ( (fe_dom << 16) | idx );
}

inline unsigned int ID_TO_IDX(unsigned long id) 
{ 
        return ( id & 0x0000ffff );
}

inline domid_t ID_TO_DOM(unsigned long id) { return (id >> 16); }
/*
static int (*request_hook)(blkif_request_t *req) = NULL;
static int (*response_hook)(blkif_response_t *req) = NULL;
*/

/*-----[ Request/Response hook chains.]----------------------------------*/

#define HOOK_NAME_MAX 50
        
typedef struct ctrl_hook_st {
    char name[HOOK_NAME_MAX];
    int (*func)(control_msg_t *);
    struct ctrl_hook_st *next;
} ctrl_hook_t;
        
typedef struct request_hook_st {
    char name[HOOK_NAME_MAX];
    int (*func)(blkif_request_t *);
    struct request_hook_st *next;
} request_hook_t;

typedef struct response_hook_st {
    char name[HOOK_NAME_MAX];
    int (*func)(blkif_response_t *);
    struct response_hook_st *next;
} response_hook_t;

static ctrl_hook_t *ctrl_hook_chain = NULL;
static request_hook_t *request_hook_chain = NULL;
static response_hook_t *response_hook_chain = NULL;

void blktap_register_ctrl_hook(char *name, int (*ch)(control_msg_t *)) 
{
    ctrl_hook_t *ch_ent, **c;
    
    ch_ent = (ctrl_hook_t *)malloc(sizeof(ctrl_hook_t));
    if (!ch_ent) { printf("couldn't allocate a new hook\n"); exit(-1); }
    
    ch_ent->func  = ch;
    ch_ent->next = NULL;
    strncpy(ch_ent->name, name, HOOK_NAME_MAX);
    ch_ent->name[HOOK_NAME_MAX-1] = '\0';
    
    c = &ctrl_hook_chain;
    while (*c != NULL) {
        c = &(*c)->next;
    }
    *c = ch_ent;
}

void blktap_register_request_hook(char *name, int (*rh)(blkif_request_t *)) 
{
    request_hook_t *rh_ent, **c;
    
    rh_ent = (request_hook_t *)malloc(sizeof(request_hook_t));
    if (!rh_ent) { printf("couldn't allocate a new hook\n"); exit(-1); }
    
    rh_ent->func  = rh;
    rh_ent->next = NULL;
    strncpy(rh_ent->name, name, HOOK_NAME_MAX);
    
    c = &request_hook_chain;
    while (*c != NULL) {
        c = &(*c)->next;
    }
    *c = rh_ent;
}

void blktap_register_response_hook(char *name, int (*rh)(blkif_response_t *)) 
{
    response_hook_t *rh_ent, **c;
    
    rh_ent = (response_hook_t *)malloc(sizeof(response_hook_t));
    if (!rh_ent) { printf("couldn't allocate a new hook\n"); exit(-1); }
    
    rh_ent->func  = rh;
    rh_ent->next = NULL;
    strncpy(rh_ent->name, name, HOOK_NAME_MAX);
    
    c = &response_hook_chain;
    while (*c != NULL) {
        c = &(*c)->next;
    }
    *c = rh_ent;
}

void print_hooks(void)
{
    request_hook_t  *req_hook;
    response_hook_t *rsp_hook;
    ctrl_hook_t     *ctrl_hook;
    
    printf("Control Hooks:\n");
    ctrl_hook = ctrl_hook_chain;
    while (ctrl_hook != NULL)
    {
        printf("  [0x%p] %s\n", ctrl_hook->func, ctrl_hook->name);
        ctrl_hook = ctrl_hook->next;
    }
    
    printf("Request Hooks:\n");
    req_hook = request_hook_chain;
    while (req_hook != NULL)
    {
        printf("  [0x%p] %s\n", req_hook->func, req_hook->name);
        req_hook = req_hook->next;
    }
    
    printf("Response Hooks:\n");
    rsp_hook = response_hook_chain;
    while (rsp_hook != NULL)
    {
        printf("  [0x%p] %s\n", rsp_hook->func, rsp_hook->name);
        rsp_hook = rsp_hook->next;
    }
}
        
/*-----[ Data to/from Backend (server) VM ]------------------------------*/



inline int write_req_to_be_ring(blkif_request_t *req)
{
    blkif_request_t *req_d;
    static pthread_mutex_t be_prod_mutex = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&be_prod_mutex);
    req_d = RING_GET_REQUEST(&be_ring, be_ring.req_prod_pvt);
    memcpy(req_d, req, sizeof(blkif_request_t));
    wmb();
    be_ring.req_prod_pvt++;
    pthread_mutex_unlock(&be_prod_mutex);
    
    return 0;
}

inline int write_rsp_to_fe_ring(blkif_response_t *rsp)
{
    blkif_response_t *rsp_d;
    static pthread_mutex_t fe_prod_mutex = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&fe_prod_mutex);
    rsp_d = RING_GET_RESPONSE(&fe_ring, fe_ring.rsp_prod_pvt);
    memcpy(rsp_d, rsp, sizeof(blkif_response_t));
    wmb();
    fe_ring.rsp_prod_pvt++;
    pthread_mutex_unlock(&fe_prod_mutex);

    return 0;
}

static void apply_rsp_hooks(blkif_response_t *rsp)
{
    response_hook_t  *rsp_hook;
    
    rsp_hook = response_hook_chain;
    while (rsp_hook != NULL)
    {
        switch(rsp_hook->func(rsp))
        {
        case BLKTAP_PASS:
            break;
        default:
            printf("Only PASS is supported for resp hooks!\n");
        }
        rsp_hook = rsp_hook->next;
    }
}

static pthread_mutex_t push_mutex = PTHREAD_MUTEX_INITIALIZER;

void blktap_inject_response(blkif_response_t *rsp)
{
    
    apply_rsp_hooks(rsp);
    
    write_rsp_to_fe_ring(rsp);
    
    pthread_mutex_lock(&push_mutex);
    
    RING_PUSH_RESPONSES(&fe_ring);
    ioctl(fd, BLKTAP_IOCTL_KICK_FE);
    
    pthread_mutex_unlock(&push_mutex);
}

/*-----[ Polling fd listeners ]------------------------------------------*/

#define MAX_POLLFDS 64

typedef struct {
    int (*func)(int fd);
    struct pollfd *pfd;
    int fd;
    short events;
    int active;
} pollhook_t;

static struct pollfd  pfd[MAX_POLLFDS+1];
static pollhook_t     pollhooks[MAX_POLLFDS];
static unsigned int   ph_freelist[MAX_POLLFDS];
static unsigned int   ph_cons, ph_prod;
#define nr_pollhooks() (MAX_POLLFDS - (ph_prod - ph_cons))
#define PH_IDX(x) (x % MAX_POLLFDS)

int blktap_attach_poll(int fd, short events, int (*func)(int fd))
{
    pollhook_t *ph;
    
    if (nr_pollhooks() == MAX_POLLFDS) {
        printf("Too many pollhooks!\n");
        return -1;
    }
    
    ph = &pollhooks[ph_freelist[PH_IDX(ph_cons++)]];
    
    ph->func        = func;
    ph->fd          = fd;
    ph->events      = events;
    ph->active      = 1;
    
    printf("Added fd %d at ph index %d, now %d phs.\n", fd, ph_cons-1, 
            nr_pollhooks());
    
    return 0;
}

void blktap_detach_poll(int fd)
{
    int i;
    
    for (i=0; i<MAX_POLLFDS; i++)
        if ((pollhooks[i].active) && (pollhooks[i].pfd->fd == fd)) {
            ph_freelist[PH_IDX(ph_prod++)] = i;
            pollhooks[i].pfd->fd = -1;
            pollhooks[i].active = 0;
            break;
        }
        
    printf("Removed fd %d at ph index %d, now %d phs.\n", fd, i, 
            nr_pollhooks());
}

void pollhook_init(void)
{
    int i;
    
    for (i=0; i < MAX_POLLFDS; i++) {
        ph_freelist[i] = (i+1) % MAX_POLLFDS;
        pollhooks[i].active = 0;
    }
    
    ph_cons = 0;
    ph_prod = MAX_POLLFDS;
}

void __attribute__ ((constructor)) blktaplib_init(void)
{
    printf("[[ C O N S T R U C T O R ]]\n");
    pollhook_init();
}

/*-----[ The main listen loop ]------------------------------------------*/

int blktap_listen(void)
{
    int               notify_be, notify_fe, tap_pfd;
    
    /* comms rings: */
    blkif_request_t  *req;
    blkif_response_t *rsp;
    control_msg_t    *msg;
    blkif_sring_t    *sring;
    ctrl_sring_t     *csring;
    RING_IDX          rp, i, pfd_count; 
    
    /* pending rings */
    blkif_request_t req_pending[BLKIF_RING_SIZE];
    blkif_response_t rsp_pending[BLKIF_RING_SIZE];
    
    /* handler hooks: */
    request_hook_t   *req_hook;
    response_hook_t  *rsp_hook;
    ctrl_hook_t      *ctrl_hook;
    
    signal (SIGBUS, got_sig_bus);
    signal (SIGINT, got_sig_int);
    
    print_hooks();
    
    fd = open("/dev/blktap", O_RDWR);
    if (fd == -1) {
        printf("open failed! (%d)\n", errno);
        goto open_failed;
    }

    blktap_mem = mmap(0, PAGE_SIZE * BLKTAP_MMAP_REGION_SIZE, 
             PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if ((int)blktap_mem == -1) {
        printf("mmap failed! (%d)\n", errno);
        goto mmap_failed;
    }

    /* assign the rings to the mapped memory */
    csring = (ctrl_sring_t *)blktap_mem;
    BACK_RING_INIT(&ctrl_ring, csring, CONTROL_RING_MEM);
    
    sring = (blkif_sring_t *)((unsigned long)blktap_mem + PAGE_SIZE);
    FRONT_RING_INIT(&be_ring, sring, PAGE_SIZE);
    
    sring = (blkif_sring_t *)((unsigned long)blktap_mem + (2 *PAGE_SIZE));
    BACK_RING_INIT(&fe_ring, sring, PAGE_SIZE);

    mmap_vstart = (unsigned long)blktap_mem + (BLKTAP_RING_PAGES << PAGE_SHIFT);
    
    printf("fe_ring mapped at: %p\n", fe_ring.sring);
    printf("be_ring mapped at: %p\n", be_ring.sring);

    ioctl(fd, BLKTAP_IOCTL_SETMODE, BLKTAP_MODE_INTERPOSE );

    while(1) {
        int ret;
        
        /* build the poll list */
        
        DPRINTF("Building poll list.\n");
        
        pfd_count = 0;
        for ( i=0; i < MAX_POLLFDS; i++ ) {
            pollhook_t *ph = &pollhooks[i];
            
            if (ph->active) {
                pfd[pfd_count].fd     = ph->fd;
                pfd[pfd_count].events = ph->events;
                ph->pfd               = &pfd[pfd_count];
                pfd_count++;
            }
        }

        tap_pfd = pfd_count;
        pfd[tap_pfd].fd = fd;
        pfd[tap_pfd].events = POLLIN;

        DPRINTF("poll() %d fds.\n", pfd_count);
        
        if ( (ret = (poll(pfd, pfd_count+1, 10000)) == 0) ) {
            if (DEBUG_RING_IDXS)
                ioctl(fd, BLKTAP_IOCTL_PRINT_IDXS);
            continue;
        }

        DPRINTF("poll returned %d\n", ret);

        for (i=0; i < MAX_POLLFDS; i++) {
            if ( (pollhooks[i].active ) && (pollhooks[i].pfd->revents ) )
                pollhooks[i].func(pollhooks[i].pfd->fd);
        }
        
        if (pfd[tap_pfd].revents) {
            
            /* empty the control ring */
            rp = ctrl_ring.sring->req_prod;
            rmb();
            for (i = ctrl_ring.req_cons; i < rp; i++)
            {
                msg = RING_GET_REQUEST(&ctrl_ring, i);

                ctrl_hook = ctrl_hook_chain;
                while (ctrl_hook != NULL)
                {
                    DPRINTF("CTRL_HOOK: %s\n", ctrl_hook->name);
                    /* We currently don't respond to ctrl messages. */
                    ctrl_hook->func(msg);
                    ctrl_hook = ctrl_hook->next;
                }
            }
            /* Using this as a unidirectional ring. */
            ctrl_ring.req_cons = ctrl_ring.rsp_prod_pvt = i;
pthread_mutex_lock(&push_mutex);
            RING_PUSH_RESPONSES(&ctrl_ring);
pthread_mutex_unlock(&push_mutex);
            
            /* empty the fe_ring */
            notify_fe = 0;
            notify_be = RING_HAS_UNCONSUMED_REQUESTS(&fe_ring);
            rp = fe_ring.sring->req_prod;
            rmb();
            for (i = fe_ring.req_cons; i != rp; i++)
            {
                int done = 0; /* stop forwarding this request */

                req = RING_GET_REQUEST(&fe_ring, i);
                memcpy(&req_pending[ID_TO_IDX(req->id)], req, sizeof(*req));
                req = &req_pending[ID_TO_IDX(req->id)];

                DPRINTF("copying an fe request\n");

                req_hook = request_hook_chain;
                while (req_hook != NULL)
                {
                    DPRINTF("REQ_HOOK: %s\n", req_hook->name);
                    switch(req_hook->func(req))
                    {
                    case BLKTAP_RESPOND:
                        apply_rsp_hooks((blkif_response_t *)req);
                        write_rsp_to_fe_ring((blkif_response_t *)req);
                        notify_fe = 1;
                        done = 1;
                        break;
                    case BLKTAP_STOLEN:
                        done = 1;
                        break;
                    case BLKTAP_PASS:
                        break;
                    default:
                        printf("Unknown request hook return value!\n");
                    }
                    if (done) break;
                    req_hook = req_hook->next;
                }

                if (done == 0) write_req_to_be_ring(req);

            }
            fe_ring.req_cons = i;

            /* empty the be_ring */
            notify_fe |= RING_HAS_UNCONSUMED_RESPONSES(&be_ring);
            rp = be_ring.sring->rsp_prod;
            rmb();
            for (i = be_ring.rsp_cons; i != rp; i++)
            {

                rsp = RING_GET_RESPONSE(&be_ring, i);
                memcpy(&rsp_pending[ID_TO_IDX(rsp->id)], rsp, sizeof(*rsp));
                rsp = &rsp_pending[ID_TO_IDX(rsp->id)];

                DPRINTF("copying a be request\n");

                apply_rsp_hooks(rsp);
                write_rsp_to_fe_ring(rsp);
            }
            be_ring.rsp_cons = i;

            /* notify the domains */

            if (notify_be) {
                DPRINTF("notifying be\n");
pthread_mutex_lock(&push_mutex);
                RING_PUSH_REQUESTS(&be_ring);
                ioctl(fd, BLKTAP_IOCTL_KICK_BE);
pthread_mutex_unlock(&push_mutex);
            }

            if (notify_fe) {
                DPRINTF("notifying fe\n");
pthread_mutex_lock(&push_mutex);
                RING_PUSH_RESPONSES(&fe_ring);
                ioctl(fd, BLKTAP_IOCTL_KICK_FE);
pthread_mutex_unlock(&push_mutex);
            }
        }        
    }


    munmap(blktap_mem, PAGE_SIZE);

 mmap_failed:
    close(fd);

 open_failed:
    return 0;
}

void got_sig_bus() {
    printf("Attempted to access a page that isn't.\n");
    exit(-1);
}

void got_sig_int() {
    printf("quitting -- returning to passthrough mode.\n");
    if (fd > 0) ioctl(fd, BLKTAP_IOCTL_SETMODE, BLKTAP_MODE_PASSTHROUGH );
    exit(0);
} 
