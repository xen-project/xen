#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "xc.h"
#include "xc_io.h"

#include "sxpr.h"
#include "sxpr_parser.h"
#include "file_stream.h"
#include "fd_stream.h"

#include "xen_domain.h"
#include "xfrd.h"

#define MODULE_NAME "XFRD"
#define DEBUG 1
#undef DEBUG
#include "debug.h"

int domain_suspend(void *data, u32 dom){
    int err = 0;
    Conn *xend = data;

    dprintf("> dom=%lu data=%p\n", dom, data);
    err = xfr_vm_suspend(xend, dom);
    dprintf("< err=%d\n", err);
    return err;
}

int domain_configure(void *data, u32 dom, char *vmconfig, int vmconfig_n){
    return xen_domain_configure(dom, vmconfig, vmconfig_n);
}

static int xc_handle = 0;

int xcinit(void){
    if(xc_handle <= 0){
        xc_handle = xc_interface_open();
    }
    dprintf("< xc_handle=%d\n", xc_handle);
    return xc_handle;
}

void xcfini(void){
    if(xc_handle > 0){
        xc_interface_close(xc_handle);
        xc_handle = 0;
    }
}

/** Write domain state.
 *
 * At some point during this the domain is suspended, and then there's no way back.
 * Even if something later goes wrong we can't restart the domain.
 */
int xen_domain_snd(Conn *xend, IOStream *io,
                   uint32_t dom,
                   char *vmconfig, int vmconfig_n,
                   int live, int resource){
    int err = 0;
    XcIOContext _ioctxt = {}, *ioctxt = &_ioctxt;
    ioctxt->domain = dom;
    ioctxt->io = io;
    ioctxt->info = iostdout;
    ioctxt->err = iostderr;
    ioctxt->data = xend;
    ioctxt->suspend = domain_suspend;
    ioctxt->vmconfig = vmconfig;
    ioctxt->vmconfig_n = vmconfig_n;
    if(live){
        ioctxt->flags |= XCFLAGS_LIVE;
    }
    ioctxt->resource = resource;
    err = xc_linux_save(xcinit(), ioctxt);
    dprintf("< err=%d\n", err);
    return err;
}

/** Receive domain state.
 * Create a new domain and store the received state into it.
 */
int xen_domain_rcv(IOStream *io,
                   uint32_t *dom,
                   char **vmconfig, int *vmconfig_n,
                   int *configured){
    int err = 0;
    XcIOContext _ioctxt = {}, *ioctxt = &_ioctxt;
    dprintf(">\n");
    ioctxt->io = io;
    ioctxt->info = iostdout;
    ioctxt->err = iostderr;
    ioctxt->configure = domain_configure;
    if ( !*configured )
        ioctxt->flags |= XCFLAGS_CONFIGURE;

    err = xc_linux_restore(xcinit(), ioctxt);
    *dom = ioctxt->domain;
    *vmconfig = ioctxt->vmconfig;
    *vmconfig_n = ioctxt->vmconfig_n;
    *configured = (ioctxt->flags & XCFLAGS_CONFIGURE);
    dprintf("< err=%d\n", err);
    return err;
}

typedef struct xend {
    int fd;
    IOStream *io;
    Parser *parser;
    int seeneof;
} Xend;

char *xend_server_addr(void){
    char * val = getenv("XEND_EVENT_ADDR");
    return (val ? val : "/var/lib/xend/event-socket");
}

/** Open a unix-domain socket to the xend server.
 */
int xend_open_fd(void){
    struct sockaddr_un addr_un = { .sun_family = AF_UNIX };
    struct sockaddr *addr = (struct sockaddr*)&addr_un;
    int addr_n = sizeof(addr_un);
    int err = 0;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(fd < 0){
        err = -errno;
        perror("socket");
        goto exit;
    }
    strcpy(addr_un.sun_path, xend_server_addr());
    if(connect(fd, addr, addr_n) < 0){
        err = -errno;
        perror("connect");
        goto exit;
    }
  exit:
    if(err && (fd >= 0)){
        close(fd);
    }
    
    return (err ? err : fd);
}

/** Close a connection to the server.
 *
  * @param xend connection
*/
void xend_close(Xend *xend){
    if(!xend) return;
    close(xend->fd);
    Parser_free(xend->parser);
}

/** Open a connection to the server.
 *
 * @param xend result parameter for the connection
 * @return 0 on success, negative error code otherwise
 */
int xend_open(Xend **xend){
    int err = 0;
    Xend *val = ALLOCATE(Xend);

    val->fd = xend_open_fd();

    if(val->fd < 0){
        err = val->fd;
        goto exit;
    }
    val->io = fd_stream_new(val->fd);
    val->parser = Parser_new();
  exit:
    if(err) xend_close(val);
    *xend = (err ? NULL : val);
    return err;
}

/** Read a response from a server connection.
 */
int xend_read_resp(Xend *xend, Sxpr *resp){
    int err = 0;
    Sxpr val = ONONE;
    char buf[1024];
    int buf_n = sizeof(buf), n;

    for( ; ; ){
        if(Parser_ready(xend->parser)){
            val = Parser_get_val(xend->parser);
            goto exit;
        }
        if(xend->seeneof){
            err = -EIO;
            goto exit;
        }
        memset(buf, 0, buf_n);
        n = IOStream_read(xend->io, buf, 100);
        if(n <= 0){
            xend->seeneof = 1;
            err = Parser_input_eof(xend->parser);
        } else {
            err = Parser_input(xend->parser, buf, n);
        }
    }
  exit:
    *resp = (err < 0 ? ONONE : val);
    return err;
}

/** Read a response from a server connection and decode the value.
 *
 * @param xend server connection
 * @param resp result parameter for the response value
 * @return 0 on success, negative error code otherwise
 */
int xend_read(Xend *xend, Sxpr *resp){
    int err = 0;
    Sxpr val = ONONE;

    dprintf(">\n");
    for( ; ; ){
        err = xend_read_resp(xend, &val);
        if(err < 0) goto exit;
        
        if(sxpr_is(sxpr_name(val), "event")){
            // We don't care about events, try again.
            err = 0;
            continue;
        } else if(sxpr_is(sxpr_name(val), "err")){
            eprintf("> "); objprint(iostderr, val, 0); fprintf(stderr, "\n");
            err = -EINVAL;
            break;
        } else {
            err = 0;
            val = sxpr_child0(val, ONULL);
            break;
        }
    }
#ifdef DEBUG
    dprintf("> OK ");
    objprint(iostdout, val, 0);
    printf("\n");
#endif
  exit:
    if(resp){
        *resp = (err < 0 ? ONONE : val);
    }
    dprintf("> err=%d\n", err);
    return err;
}

/** Send a request to the server and return the result value in resp.
 *
 * @param xend server connection
 * @param resp result parameter for the response value
 * @param format request format followed by args to print
 * @return 0 on success, negative error code otherwise
 */
int xend_call(Xend *xend, Sxpr *resp, char *format, ...){
    va_list args;
    int err;
    
    dprintf("> ");
    va_start(args, format);
#ifdef DEBUG
    vprintf(format, args); printf("\n");
#endif
    err = IOStream_vprint(xend->io, format, args);
    va_end(args);
    if(err < 0) goto exit;
    IOStream_flush(xend->io);
    err = xend_read(xend, resp);
  exit:
    dprintf("> err=%d\n", err);
    return (err < 0 ? err : 0);
}

/** Get xend to list domains.
 * We use this to force xend to refresh its domain list.
 *
 * @return 0 on success, error code otherwise
 */
int xen_domain_ls(void){
    int err = 0;
    Xend *xend = NULL;
    err = xend_open(&xend);
    if(err) goto exit;
    err = xend_call(xend, NULL, "(domain.ls)");
  exit:
    xend_close(xend);
    return err;
}

/** Get xend to configure a new domain.
 *
 * @param dom domain id
 * @param vmconfig configuration string
 * @param vmconfig_n length of vmconfig
 * @return 0 on success, error code otherwise
 */
int xen_domain_configure(uint32_t dom, char *vmconfig, int vmconfig_n){
    int err = 0;
    Xend *xend = NULL;
    dprintf("> dom=%u\n", dom);
    // List domains so that xend will update its domain list and notice the new domain.
    xen_domain_ls();
    // Now configure it.
    err = xend_open(&xend);
    if(err) goto exit;
    err = xend_call(xend, NULL, "(domain.configure (dom %d) (config %*s))",
                    dom, vmconfig_n, vmconfig);
  exit:
    dprintf("< err=%d\n", err);
    xend_close(xend);
    return err;
}

/** Get xend to unpause a domain.
 *
 * @param dom domain id
 * @return 0 on success, error code otherwise
 */
int xen_domain_unpause(uint32_t dom){
    int err = 0;
    Xend *xend = NULL;
    err = xend_open(&xend);
    if(err) goto exit;
    err = xend_call(xend, NULL, "(domain.unpause (dom %d))", dom);
  exit:
    xend_close(xend);
    return err;
}
