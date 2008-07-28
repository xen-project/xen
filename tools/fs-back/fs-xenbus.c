#undef NDEBUG
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <xenctrl.h>
#include <xs.h>
#include <xen/io/fsif.h>
#include "fs-backend.h"


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
    printf("xenbus_printf (%s) <= %s.\n", fullpath, val);    

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
        printf("Could not open connection to xenbus deamon.\n");
        goto error_exit;
    }
    printf("Connection to the xenbus deamon opened successfully.\n");

    /* Start transaction */
    xst = xs_transaction_start(xsh);
    if(xst == 0)
    {
        printf("Could not start a transaction.\n");
        goto error_exit;
    }
    printf("XS transaction is %d\n", xst); 
 
    /* Create node string */
    snprintf(node, sizeof(node), "%s/%d", EXPORTS_NODE, export->export_id); 
    /* Remove old export (if exists) */ 
    xs_rm(xsh, xst, node);

    if(!xenbus_printf(xsh, xst, node, "name", "%s", export->name))
    {
        printf("Could not write the export node.\n");
        goto error_exit;
    }

    /* People need to be able to read our export */
    perms.id = 0;
    perms.perms = XS_PERM_READ;
    if(!xs_set_permissions(xsh, xst, EXPORTS_NODE, &perms, 1))
    {
        printf("Could not set permissions on the export node.\n");
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
    assert(res);
    return xs_fileno(xsh); 
}

void xenbus_read_mount_request(struct fs_mount *mount, char *frontend)
{
    char node[1024];
    char *s;

    assert(xsh != NULL);
#if 0
    snprintf(node, sizeof(node), WATCH_NODE"/%d/%d/frontend", 
                           mount->dom_id, mount->export->export_id);
    frontend = xs_read(xsh, XBT_NULL, node, NULL);
#endif
    mount->frontend = frontend;
    snprintf(node, sizeof(node), "%s/state", frontend);
    s = xs_read(xsh, XBT_NULL, node, NULL);
    assert(strcmp(s, STATE_READY) == 0);
    free(s);
    snprintf(node, sizeof(node), "%s/ring-ref", frontend);
    s = xs_read(xsh, XBT_NULL, node, NULL);
    mount->gref = atoi(s);
    free(s);
    snprintf(node, sizeof(node), "%s/event-channel", frontend);
    s = xs_read(xsh, XBT_NULL, node, NULL);
    mount->remote_evtchn = atoi(s);
    free(s);
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


void xenbus_write_backend_node(struct fs_mount *mount)
{
    char node[1024], backend_node[1024];
    int self_id;

    assert(xsh != NULL);
    self_id = get_self_id();
    printf("Our own dom_id=%d\n", self_id);
    snprintf(node, sizeof(node), "%s/backend", mount->frontend);
    snprintf(backend_node, sizeof(backend_node), "/local/domain/%d/"ROOT_NODE"/%d",
                                self_id, mount->mount_id);
    xs_write(xsh, XBT_NULL, node, backend_node, strlen(backend_node));

    snprintf(node, sizeof(node), ROOT_NODE"/%d/state", mount->mount_id);
    xs_write(xsh, XBT_NULL, node, STATE_INITIALISED, strlen(STATE_INITIALISED));
}

void xenbus_write_backend_ready(struct fs_mount *mount)
{
    char node[1024];
    int self_id;

    assert(xsh != NULL);
    self_id = get_self_id();
    snprintf(node, sizeof(node), ROOT_NODE"/%d/state", mount->mount_id);
    xs_write(xsh, XBT_NULL, node, STATE_READY, strlen(STATE_READY));
}

