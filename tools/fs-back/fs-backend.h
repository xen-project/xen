#ifndef __LIB_FS_BACKEND__
#define __LIB_FS_BACKEND__

#include <aio.h>
#include <xs.h>
#include <xen/grant_table.h>
#include <xen/event_channel.h>
#include <xen/io/ring.h>
#include <xen/io/fsif.h>
#include "sys-queue.h"

#define ROOT_NODE           "backend/vfs"
#define EXPORTS_SUBNODE     "exports"
#define EXPORTS_NODE        ROOT_NODE"/"EXPORTS_SUBNODE
#define WATCH_NODE          EXPORTS_NODE"/requests"
#define MAX_FDS             16
#define MAX_RING_SIZE       16

struct fs_export
{
    int export_id;
    char *export_path;
    char *name;
    struct fs_export *next; 
};

struct fs_request
{
    struct fs_mount *mount;
    int id;
    int active;
    void *page;                         /* Pointer to mapped grant */
    int count;
    struct fsif_request req_shadow;
    struct aiocb aiocb; 
};


struct fs_mount
{
    struct fs_export *export;
    int dom_id;
    char *frontend;
    int mount_id;                     /* = backend id */
    grant_ref_t grefs[MAX_RING_SIZE];
    evtchn_port_t remote_evtchn;
    int evth;                         /* Handle to the event channel */
    evtchn_port_t local_evtchn;
    int gnth;
    int shared_ring_size;             /* in pages */
    struct fsif_back_ring ring;
    int nr_entries;
    struct fs_request *requests;
    unsigned short *freelist;
    int fds[MAX_FDS];
    LIST_ENTRY(fs_mount) entries;
};

void terminate_mount_request(struct fs_mount *mount);

/* Handle to XenStore driver */
extern struct xs_handle *xsh;

bool xenbus_create_request_node(void);
int xenbus_register_export(struct fs_export *export);
int xenbus_get_watch_fd(void);
int xenbus_read_mount_request(struct fs_mount *mount, char *frontend);
bool xenbus_write_backend_node(struct fs_mount *mount);
bool xenbus_write_backend_state(struct fs_mount *mount, const char *state);
void xenbus_free_backend_node(struct fs_mount *mount);
int xenbus_frontend_state_changed(struct fs_mount *mount, const char *oldstate);
bool xenbus_watch_frontend_state(struct fs_mount *mount);
bool xenbus_unwatch_frontend_state(struct fs_mount *mount);
char* xenbus_read_frontend_state(struct fs_mount *mount);

/* File operations, implemented in fs-ops.c */
struct fs_op
{
    int type;       /* Type of request (from fsif.h) this handlers 
                       are responsible for */
    void (*dispatch_handler)(struct fs_mount *mount, struct fsif_request *req);
    void (*response_handler)(struct fs_mount *mount, struct fs_request *req);
};

/* This NULL terminated array of all file requests handlers */
extern struct fs_op *fsops[];

static inline void add_id_to_freelist(unsigned int id,unsigned short* freelist)
{
    freelist[id + 1] = freelist[0];
    freelist[0]  = id;
}

static inline unsigned short get_id_from_freelist(unsigned short* freelist)
{
    unsigned int id = freelist[0];
    freelist[0] = freelist[id + 1];
    return id;
}

#endif /* __LIB_FS_BACKEND__ */
