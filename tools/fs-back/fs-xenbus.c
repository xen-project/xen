#undef NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <sys/select.h>
#include <xenctrl.h>
#include <xs.h>
#include <xen/io/fsif.h>
#include "fs-backend.h"
#include "fs-debug.h"


static bool xenbus_printf(struct xs_handle *xsh,
                          xs_transaction_t xbt,
                          char* node,
                          char* path,
                          char* fmt,
                          ...)
{
    char fullpath[1024];
    char val[1024];
    va_list args;
    
    va_start(args, fmt);
    snprintf(fullpath, sizeof(fullpath), "%s/%s", node, path);
    vsnprintf(val, sizeof(val), fmt, args);
    va_end(args);
    FS_DEBUG("xenbus_printf (%s) <= %s.\n", fullpath, val);    

    return xs_write(xsh, xbt, fullpath, val, strlen(val));
}

bool xenbus_create_request_node(void)
{
    bool ret;
    struct xs_permissions perms;
    
    assert(xsh != NULL);
    xs_rm(xsh, XBT_NULL, WATCH_NODE);
    ret = xs_mkdir(xsh, XBT_NULL, WATCH_NODE); 
    if (!ret)
        return false;

    perms.id = 0;
    perms.perms = XS_PERM_WRITE;
    ret = xs_set_permissions(xsh, XBT_NULL, WATCH_NODE, &perms, 1);

    return ret;
}

int xenbus_register_export(struct fs_export *export)
{
    xs_transaction_t xst = 0;
    char node[1024];
    struct xs_permissions perms;

    assert(xsh != NULL);
    if(xsh == NULL)
    {
        FS_DEBUG("Could not open connection to xenbus deamon.\n");
        goto error_exit;
    }
    FS_DEBUG("Connection to the xenbus deamon opened successfully.\n");

    /* Start transaction */
    xst = xs_transaction_start(xsh);
    if(xst == 0)
    {
        FS_DEBUG("Could not start a transaction.\n");
        goto error_exit;
    }
    FS_DEBUG("XS transaction is %d\n", xst); 
 
    /* Create node string */
    snprintf(node, sizeof(node), "%s/%d", EXPORTS_NODE, export->export_id); 
    /* Remove old export (if exists) */ 
    xs_rm(xsh, xst, node);

    if(!xenbus_printf(xsh, xst, node, "name", "%s", export->name))
    {
        FS_DEBUG("Could not write the export node.\n");
        goto error_exit;
    }

    /* People need to be able to read our export */
    perms.id = 0;
    perms.perms = XS_PERM_READ;
    if(!xs_set_permissions(xsh, xst, EXPORTS_NODE, &perms, 1))
    {
        FS_DEBUG("Could not set permissions on the export node.\n");
        goto error_exit;
    }

    xs_transaction_end(xsh, xst, 0);
    return 0; 

error_exit:    
    if(xst != 0)
        xs_transaction_end(xsh, xst, 1);
    return -1;
}

int xenbus_get_watch_fd(void)
{
    int res;
    assert(xsh != NULL);
    res = xs_watch(xsh, WATCH_NODE, "conn-watch");
    if (!res) {
        FS_DEBUG("ERROR: xs_watch %s failed ret=%d errno=%d\n",
                 WATCH_NODE, res, errno);
        return -1;
    }
    return xs_fileno(xsh); 
}

int xenbus_read_mount_request(struct fs_mount *mount, char *frontend)
{
    char node[1024];
    char *s;
    int i;

    assert(xsh != NULL);
#if 0
    snprintf(node, sizeof(node), WATCH_NODE"/%d/%d/frontend", 
                           mount->dom_id, mount->export->export_id);
    frontend = xs_read(xsh, XBT_NULL, node, NULL);
#endif
    mount->frontend = frontend;
    snprintf(node, sizeof(node), "%s/state", frontend);
    s = xs_read(xsh, XBT_NULL, node, NULL);
    if (strcmp(s, STATE_READY) != 0) {
        FS_DEBUG("ERROR: frontend not read\n");
        goto error;
    }
    free(s);
    snprintf(node, sizeof(node), "%s/ring-size", frontend);
    s = xs_read(xsh, XBT_NULL, node, NULL);
    mount->shared_ring_size = atoi(s);
    if (mount->shared_ring_size > MAX_RING_SIZE) {
        FS_DEBUG("ERROR: shared_ring_size (%d) > MAX_RING_SIZE\n", mount->shared_ring_size);
        goto error;
    }
    free(s);
    for(i=0; i<mount->shared_ring_size; i++)
    {
        snprintf(node, sizeof(node), "%s/ring-ref-%d", frontend, i);
        s = xs_read(xsh, XBT_NULL, node, NULL);
        mount->grefs[i] = atoi(s);
        free(s);
    }
    snprintf(node, sizeof(node), "%s/event-channel", frontend);
    s = xs_read(xsh, XBT_NULL, node, NULL);
    mount->remote_evtchn = atoi(s);
    free(s);
    return 0;

error:
    free(s);
    return -1;
}

/* Small utility function to figure out our domain id */
static int get_self_id(void)
{
    char *dom_id;
    int ret; 
                
    assert(xsh != NULL);
    dom_id = xs_read(xsh, XBT_NULL, "domid", NULL);
    sscanf(dom_id, "%d", &ret); 
    free(dom_id);
                        
    return ret;                                  
} 


bool xenbus_write_backend_node(struct fs_mount *mount)
{
    char node[1024], backend_node[1024];
    int self_id;

    assert(xsh != NULL);
    self_id = get_self_id();
    FS_DEBUG("Our own dom_id=%d\n", self_id);
    snprintf(node, sizeof(node), "%s/backend", mount->frontend);
    snprintf(backend_node, sizeof(backend_node), "/local/domain/%d/"ROOT_NODE"/%d",
                                self_id, mount->mount_id);
    xs_write(xsh, XBT_NULL, node, backend_node, strlen(backend_node));

    snprintf(node, sizeof(node), ROOT_NODE"/%d/state", mount->mount_id);
    return xs_write(xsh, XBT_NULL, node, STATE_INITIALISED, strlen(STATE_INITIALISED));
}

bool xenbus_write_backend_state(struct fs_mount *mount, const char *state)
{
    char node[1024];
    int self_id;

    assert(xsh != NULL);
    self_id = get_self_id();
    snprintf(node, sizeof(node), ROOT_NODE"/%d/state", mount->mount_id);
    return xs_write(xsh, XBT_NULL, node, state, strlen(state));
}

void xenbus_free_backend_node(struct fs_mount *mount)
{
    char node[1024];
    int self_id;

    assert(xsh != NULL);
    self_id = get_self_id();
    snprintf(node, sizeof(node), ROOT_NODE"/%d", mount->mount_id);
    xs_rm(xsh, XBT_NULL, node);
}

bool xenbus_watch_frontend_state(struct fs_mount *mount)
{
    char statepath[1024];

    assert(xsh != NULL);
    snprintf(statepath, sizeof(statepath), "%s/state", mount->frontend);
    return xs_watch(xsh, statepath, "frontend-state");
}

bool xenbus_unwatch_frontend_state(struct fs_mount *mount)
{
    char statepath[1024];

    assert(xsh != NULL);
    snprintf(statepath, sizeof(statepath), "%s/state", mount->frontend);
    return xs_unwatch(xsh, statepath, "frontend-state");
}

int xenbus_frontend_state_changed(struct fs_mount *mount, const char *oldstate)
{
    unsigned int len;
    char statepath[1024];
    char *state = NULL;

    assert(xsh != NULL);
    snprintf(statepath, sizeof(statepath), "%s/state", mount->frontend);
    state = xs_read(xsh, XBT_NULL, statepath, &len);
    if (state && len > 0) {
        if (strcmp(state, oldstate)) {
            free(state);
            return 1;
        } else {
            free(state);
            return 0;
        }
    } else
        return 1;
}

char* xenbus_read_frontend_state(struct fs_mount *mount)
{
    unsigned int len;
    char statepath[1024];

    assert(xsh != NULL);
    snprintf(statepath, sizeof(statepath), "%s/state", mount->frontend);
    return xs_read(xsh, XBT_NULL, statepath, &len);
}

