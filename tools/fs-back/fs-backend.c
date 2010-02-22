#undef NDEBUG
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <malloc.h>
#include <xenctrl.h>
#include <aio.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <xen/io/ring.h>
#include <xc_private.h>
#include <err.h>
#include "sys-queue.h"
#include "fs-backend.h"
#include "fs-debug.h"

struct xs_handle *xsh = NULL;
static struct fs_export *fs_exports = NULL;
static int export_id = 0;
static int mount_id = 0;
static int pipefds[2];
static LIST_HEAD(mount_requests_head, fs_mount) mount_requests_head;

static void free_mount_request(struct fs_mount *mount);

static void dispatch_response(struct fs_request *request)
{
    int i;
    struct fs_op *op;

    for(i=0;;i++)
    {
        op = fsops[i];
        /* We should dispatch a response before reaching the end of the array */
        assert(op != NULL);
        if(op->type == request->req_shadow.type)
        {
            FS_DEBUG("Found op for type=%d\n", op->type);
            /* There needs to be a response handler */
            assert(op->response_handler != NULL);
            op->response_handler(request->mount, request);
            break;
        }
    }

    request->active = 0;
    add_id_to_freelist(request->id, request->mount->freelist);
}

static void handle_aio_event(struct fs_request *request)
{
    int ret, notify;

    FS_DEBUG("handle_aio_event: mount %s request %d\n", request->mount->frontend, request->id);
    if (request->active < 0) {
        request->mount->nr_entries++;
        if (!request->mount->nr_entries)
            free_mount_request(request->mount);
        return;
    }

    ret = aio_error(&request->aiocb);
    if(ret != EINPROGRESS && ret != ECANCELED)
        dispatch_response(request);

    RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&request->mount->ring, notify);
    FS_DEBUG("Pushed responces and notify=%d\n", notify);
    if(notify)
        xc_evtchn_notify(request->mount->evth, request->mount->local_evtchn);
}

static void allocate_request_array(struct fs_mount *mount)
{
    int i, nr_entries = mount->nr_entries;
    struct fs_request *requests;
    unsigned short *freelist;
    
    requests = malloc(sizeof(struct fs_request) *nr_entries);
    freelist = malloc(sizeof(unsigned short) * (nr_entries + 1)); 
    memset(requests, 0, sizeof(struct fs_request) * nr_entries);
    memset(freelist, 0, sizeof(unsigned short) * (nr_entries + 1));
    for(i=0; i< nr_entries; i++)
    {
        requests[i].active = 0; 
        requests[i].mount = mount; 
        add_id_to_freelist(i, freelist);
    }
    mount->requests = requests;
    mount->freelist = freelist;
}


static void handle_mount(struct fs_mount *mount)
{
    int more, notify;
    int nr_consumed=0;
    RING_IDX cons, rp;
    struct fsif_request *req;

moretodo:
    rp = mount->ring.sring->req_prod;
    xen_rmb(); /* Ensure we see queued requests up to 'rp'. */

    while ((cons = mount->ring.req_cons) != rp)
    {
        int i;
        struct fs_op *op;

        FS_DEBUG("Got a request at %d (of %d)\n", 
                cons, RING_SIZE(&mount->ring));
        req = RING_GET_REQUEST(&mount->ring, cons);
        FS_DEBUG("Request type=%d\n", req->type); 
        for(i=0;;i++)
        {
            op = fsops[i];
            if(op == NULL)
            {
                /* We've reached the end of the array, no appropirate
                 * handler found. Warn, ignore and continue. */
                FS_DEBUG("WARN: Unknown request type: %d\n", req->type);
                mount->ring.req_cons++; 
                break;
            }
            if(op->type == req->type)
            {
                /* There needs to be a dispatch handler */
                assert(op->dispatch_handler != NULL);
                op->dispatch_handler(mount, req);
                break;
            }
        }

        nr_consumed++;
    }
    FS_DEBUG("Backend consumed: %d requests\n", nr_consumed);
    RING_FINAL_CHECK_FOR_REQUESTS(&mount->ring, more);
    if(more) goto moretodo;

    RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&mount->ring, notify);
    FS_DEBUG("Pushed responces and notify=%d\n", notify);
    if(notify)
        xc_evtchn_notify(mount->evth, mount->local_evtchn);
}

void terminate_mount_request(struct fs_mount *mount)
{
    int count = 0, i;

    FS_DEBUG("terminate_mount_request %s\n", mount->frontend);
    xenbus_write_backend_state(mount, STATE_CLOSING);

    for(i=0; i<mount->nr_entries; i++)
        if(mount->requests[i].active) {
            mount->requests[i].active = -1;
            aio_cancel(mount->requests[i].aiocb.aio_fildes, &mount->requests[i].aiocb);
            count--;
        }
    mount->nr_entries = count;

    /* wait for the frontend to shut down but don't wait more than 3
     * seconds */
    i = 0;
    while (!xenbus_frontend_state_changed(mount, STATE_CLOSING) && i < 3) {
        sleep(1);
        i++;
    }
    xenbus_write_backend_state(mount, STATE_CLOSED);

    xc_gnttab_munmap(mount->gnth, mount->ring.sring, mount->shared_ring_size);
    xc_gnttab_close(mount->gnth);
    xc_evtchn_unbind(mount->evth, mount->local_evtchn);
    xc_evtchn_close(mount->evth);

    if (!count)
        free_mount_request(mount);
}

static void free_mount_request(struct fs_mount *mount) {
    FS_DEBUG("free_mount_request %s\n", mount->frontend);
    xenbus_free_backend_node(mount);
    free(mount->frontend);
    free(mount->requests);
    free(mount->freelist);
    LIST_REMOVE (mount, entries);
    free(mount);
}

static void handle_connection(int frontend_dom_id, int export_id, char *frontend)
{
    struct fs_mount *mount;
    struct fs_export *export;
    struct fsif_sring *sring = NULL;
    uint32_t dom_ids[MAX_RING_SIZE];
    int i;

    FS_DEBUG("Handling connection from dom=%d, for export=%d\n", 
            frontend_dom_id, export_id);
    /* Try to find the export on the list */
    export = fs_exports;
    while(export)
    {
        if(export->export_id == export_id)
            break;
        export = export->next;
    }
    if(!export)
    {
        FS_DEBUG("Could not find the export (the id is unknown).\n");
        return;
    }

    mount = (struct fs_mount*)malloc(sizeof(struct fs_mount));
    memset(mount, 0, sizeof(struct fs_mount));
    mount->dom_id = frontend_dom_id;
    mount->export = export;
    mount->mount_id = mount_id++;
    if (xenbus_read_mount_request(mount, frontend) < 0)
        goto error;
    FS_DEBUG("Frontend found at: %s (gref=%d, evtchn=%d)\n", 
            mount->frontend, mount->grefs[0], mount->remote_evtchn);
    if (!xenbus_write_backend_node(mount)) {
        FS_DEBUG("ERROR: failed to write backend node on xenbus\n");
        goto error;
    }
    mount->evth = -1;
    mount->evth = xc_evtchn_open(); 
    if (mount->evth < 0) {
        FS_DEBUG("ERROR: Couldn't open evtchn!\n");
        goto error;
    }
    mount->local_evtchn = -1;
    mount->local_evtchn = xc_evtchn_bind_interdomain(mount->evth, 
                                                     mount->dom_id, 
                                                     mount->remote_evtchn);
    if (mount->local_evtchn < 0) {
        FS_DEBUG("ERROR: Couldn't bind evtchn!\n");
        goto error;
    }
    mount->gnth = -1;
    mount->gnth = xc_gnttab_open(); 
    if (mount->gnth < 0) {
        FS_DEBUG("ERROR: Couldn't open gnttab!\n");
        goto error;
    }
    for(i=0; i<mount->shared_ring_size; i++)
        dom_ids[i] = mount->dom_id;
    sring = xc_gnttab_map_grant_refs(mount->gnth,
                                     mount->shared_ring_size,
                                     dom_ids,
                                     mount->grefs,
                                     PROT_READ | PROT_WRITE);

    if (!sring) {
        FS_DEBUG("ERROR: Couldn't amp grant refs!\n");
        goto error;
    }

    BACK_RING_INIT(&mount->ring, sring, mount->shared_ring_size * XC_PAGE_SIZE);
    mount->nr_entries = mount->ring.nr_ents; 
    for (i = 0; i < MAX_FDS; i++)
        mount->fds[i] = -1;

    LIST_INSERT_HEAD(&mount_requests_head, mount, entries);
    if (!xenbus_watch_frontend_state(mount)) {
        FS_DEBUG("ERROR: failed to watch frontend state on xenbus\n");
        goto error;
    }
    if (!xenbus_write_backend_state(mount, STATE_READY)) {
        FS_DEBUG("ERROR: failed to write backend state to xenbus\n");
        goto error;
    }

    allocate_request_array(mount);

    return;

error:
    xenbus_write_backend_state(mount, STATE_CLOSED);
    if (sring)
        xc_gnttab_munmap(mount->gnth, mount->ring.sring, mount->shared_ring_size);
    if (mount->gnth > 0)
        xc_gnttab_close(mount->gnth);
    if (mount->local_evtchn > 0)
        xc_evtchn_unbind(mount->evth, mount->local_evtchn);
    if (mount->evth > 0)
        xc_evtchn_close(mount->evth);
}

static void await_connections(void)
{
    int fd, max_fd, ret, dom_id, export_id; 
    fd_set fds;
    char **watch_paths;
    unsigned int len;
    char d;
    struct fs_mount *pointer;

    LIST_INIT (&mount_requests_head);

    assert(xsh != NULL);
    if ((fd = xenbus_get_watch_fd()) == -1)
	    err(1, "xenbus_get_watch_fd: could not setup watch");
    /* Infinite watch loop */
    do {
	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	FD_SET(pipefds[0], &fds);
        max_fd = fd > pipefds[0] ? fd : pipefds[0];
        LIST_FOREACH(pointer, &mount_requests_head, entries) {
            int tfd = xc_evtchn_fd(pointer->evth);
            FD_SET(tfd, &fds);
            if (tfd > max_fd) max_fd = tfd;
        }
        ret = select(max_fd+1, &fds, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno == EINTR) continue;
            /* try to recover */
            else if (errno == EBADF) {
                struct timeval timeout;
                memset(&timeout, 0x00, sizeof(timeout));
                FD_ZERO(&fds);
                FD_SET(fd, &fds);
                FD_SET(pipefds[0], &fds);
                max_fd = fd > pipefds[0] ? fd : pipefds[0];
                ret = select(max_fd + 1, &fds, NULL, NULL, &timeout);
                if (ret < 0)
                    err(1, "select: unrecoverable error occurred: %d\n", errno);

                /* trying to find the bogus fd among the open event channels */
                LIST_FOREACH(pointer, &mount_requests_head, entries) {
                    int tfd = xc_evtchn_fd(pointer->evth);
                    memset(&timeout, 0x00, sizeof(timeout));
                    FD_ZERO(&fds);
                    FD_SET(tfd, &fds);
                    ret = select(tfd + 1, &fds, NULL, NULL, &timeout);
                    if (ret < 0) {
                        FS_DEBUG("fd %d is bogus, closing the related connection\n", tfd);
                        pointer->evth = fd;
                        terminate_mount_request(pointer);
                        continue;
                    }
                }
                continue;
            } else
                err(1, "select: unrecoverable error occurred: %d\n", errno);
        }
        if (FD_ISSET(fd, &fds)) {
            watch_paths = xs_read_watch(xsh, &len);
            if (!strcmp(watch_paths[XS_WATCH_TOKEN], "conn-watch")) {
                dom_id = -1;
                export_id = -1;
                d = 0;
                FS_DEBUG("Path changed %s\n", watch_paths[0]);
                sscanf(watch_paths[XS_WATCH_PATH], WATCH_NODE"/%d/%d/fronten%c", 
                        &dom_id, &export_id, &d);
                if((dom_id >= 0) && (export_id >= 0) && d == 'd') {
                    char *frontend = xs_read(xsh, XBT_NULL, watch_paths[XS_WATCH_PATH], NULL);
                    if (frontend) {
                        char *p, *wp = strdup(watch_paths[XS_WATCH_PATH]);
                        handle_connection(dom_id, export_id, frontend);
                        xs_rm(xsh, XBT_NULL, wp);
                        p = strrchr(wp, '/');
                        if (p) {
                            *p = '\0';
                            p = strrchr(wp, '/');
                            if (p) {
                                *p = '\0';
                                xs_rm(xsh, XBT_NULL, wp);
                            }
                        }
                        free(wp);
                    }
                }
            } else if (!strcmp(watch_paths[XS_WATCH_TOKEN], "frontend-state")) {
                LIST_FOREACH(pointer, &mount_requests_head, entries) {
                    if (!strncmp(pointer->frontend, watch_paths[XS_WATCH_PATH], strlen(pointer->frontend))) {
                        char *state = xenbus_read_frontend_state(pointer);
                        if (!state || strcmp(state, STATE_READY)) {
                            xenbus_unwatch_frontend_state(pointer);
                            terminate_mount_request(pointer);
                        }
                        free(state);
                        break;
                    }
                }
            } else {
                FS_DEBUG("xenstore watch event unrecognized\n");
            }
            FS_DEBUG("Awaiting next connection.\n");
            /* TODO - we need to figure out what to free */
            free(watch_paths);
        }
        if (FD_ISSET(pipefds[0], &fds)) {
            struct fs_request *request;
            if (read_exact(pipefds[0], &request, sizeof(struct fs_request *)) < 0)
                err(1, "read request failed\n");
            handle_aio_event(request); 
        }
        LIST_FOREACH(pointer, &mount_requests_head, entries) {
            if (FD_ISSET(xc_evtchn_fd(pointer->evth), &fds)) {
                evtchn_port_t port;
                port = xc_evtchn_pending(pointer->evth);
                if (port != -1) {
                    handle_mount(pointer);
                    xc_evtchn_unmask(pointer->evth, port);
                }
            }
        }
    } while (1);
}

static struct fs_export* create_export(char *name, char *export_path)
{
    struct fs_export *curr_export, **last_export;

    /* Create export structure */
    curr_export = (struct fs_export *)malloc(sizeof(struct fs_export));
    curr_export->name = name;
    curr_export->export_path = export_path;
    curr_export->export_id = export_id++;
    /* Thread it onto the list */
    curr_export->next = NULL;
    last_export = &fs_exports;
    while(*last_export)
        last_export = &((*last_export)->next);
    *last_export = curr_export;

    return curr_export;
}

static void aio_signal_handler(int signo, siginfo_t *info, void *context)
{
    struct fs_request *request = (struct fs_request*) info->si_value.sival_ptr;
    int saved_errno = errno;
    if (write_exact(pipefds[1], &request, sizeof(struct fs_request *)) < 0)
        err(1, "write request filed\n");
    errno = saved_errno;
}

int main(void)
{
    struct fs_export *export;
    struct sigaction act;
    sigset_t enable;

    sigemptyset(&enable);
    sigaddset(&enable, SIGUSR2);
    pthread_sigmask(SIG_UNBLOCK, &enable, NULL);

    sigfillset(&act.sa_mask);
    act.sa_flags = SA_SIGINFO; /* do not restart syscalls to interrupt select(); use sa_sigaction */
    act.sa_sigaction = aio_signal_handler;
    sigaction(SIGUSR2, &act, NULL);

    /* Open the connection to XenStore first */
    xsh = xs_domain_open();
    assert(xsh != NULL);
    xs_rm(xsh, XBT_NULL, ROOT_NODE);
    /* Create watch node */
    xenbus_create_request_node();
    
    /* Create & register the default export */
    export = create_export("default", "/var/lib/xen");
    xenbus_register_export(export);

    if (socketpair(PF_UNIX,SOCK_STREAM, 0, pipefds) == -1)
        err(1, "failed to create pipe\n");

    await_connections();
    /* Close the connection to XenStore when we are finished with everything */
    xs_daemon_close(xsh);
#if 0
    int xc_handle;
    char *shared_page;
    int prot = PROT_READ | PROT_WRITE;
  
    xc_handle = xc_gnttab_open();
    printf("Main fn.\n");

    shared_page = xc_gnttab_map_grant_ref(xc_handle,
                                           7,
                                           2047,
                                           prot);
    
    shared_page[20] = '\0';
    printf("Current content of the page = %s\n", shared_page);
    sprintf(shared_page, "%s", "Haha dirty page now! Very bad page.");
    xc_gnttab_munmap(xc_handle, shared_page, 1);
    xc_gnttab_close(xc_handle);
    unrelated next line, saved for later convinience    
    xc_evtchn_notify(mount->evth, mount->local_evtchn);
#endif
}
