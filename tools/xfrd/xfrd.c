/** @file
 * XFRD - Domain Transfer Daemon for Xen.
 *
 * The xfrd is forked by xend to transfer a vm to a remote system.
 *
 * The vm is suspended, then its state and memory are transferred to the remote system.
 * The remote system attempts to create a vm and copy the transferred state and memory into it,
 * finally resuming the vm. If all is OK the vm ends up running on the remote
 * system and is removed from the originating system. If the transfer does not complete
 * successfully the originating system attempts to resume the vm.
 * The children exit when the transfer completes.
 *
 * @author Mike Wray <mike.wray@hpl.hp.com>
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <signal.h>
#include <sys/wait.h>
#include <sys/select.h>

#include "allocate.h"
#include "file_stream.h"
#include "string_stream.h"
#include "lzi_stream.h"
#include "gzip_stream.h"
#include "sys_net.h"
#include "sys_string.h"

//#include "xdr.h"
#include "enum.h"
#include "xfrd.h"

#include "xen_domain.h"

#include "connection.h"
#include "select.h"

#define MODULE_NAME "XFRD"
#define DEBUG 1
#undef DEBUG
#include "debug.h"

/*
sender:
        xend connects to xfrd and writes migrate message
        xend writes domain config to xfrd

        xfrd forks

        xfrd connects to peer
        xfrd sends hello, reads response
        xfrd sends domain
        xfrd reads response
        reports progress/status to xend

        xend reads xfrd for progress/status, disconnects
        If ok, destroys domain.
        If not ok, unpauses domain.

receiver:
        xfrd accepts connection on inbound port
        xfrd forks and accepts connection
        xfrd receives hello, writes response
        xfrd receives domain
        xfrd connects to xend, configures new domain
        xfrd writes status back to peer, child exits


        (xfr.hello <major> <minor>)
        (xfr.err <code> <reason>)

        xend->xfrd (xfr.migrate  <domain> <vmconfig> <host> <port> <live>)
                   (xfr.save <domain> <vmconfig> <file>)
        xfrd->xend (xfr.suspend <domain>)
        xfrd->xend (xfr.progress <percent> <rate: kb/s>)
        xfrd->xend (xfr.err <code> <reason>) | (xfr.ok <domain>)
        xfrd->xfrd (xfr.xfr <domain>)
        xfrd->xfrd (xfr.err <code>) | (xfr.ok <domain>)

        xfrd->xend (xfr.configure <domain> <vmconfig>)
 */

Sxpr oxfr_configure; // (xfr.configure <vmid> <vmconfig>)
Sxpr oxfr_err;       // (xfr.err <code>)
Sxpr oxfr_hello;     // (xfr.hello <major> <minor>)
Sxpr oxfr_migrate;   // (xfr.migrate <vmid> <vmconfig> <host> <port> <live>)
Sxpr oxfr_migrate_ok;// (xfr.migrate.ok <value>)
Sxpr oxfr_progress;  // (xfr.progress <percent> <rate: kb/s>)
Sxpr oxfr_save;      // (xfr.save <vmid> <vmconfig> <file>)
Sxpr oxfr_save_ok;   // (xfr.save.ok)
Sxpr oxfr_vm_destroy;// (xfr.vm.destroy <vmid>)
Sxpr oxfr_vm_suspend;// (xfr.vm.suspend <vmid>)
Sxpr oxfr_xfr;       // (xfr.xfr <vmid>)
Sxpr oxfr_xfr_ok;    // (xfr.xfr.ok <vmid>)

void xfr_init(void){
    oxfr_configure      = intern("xfr.configure");
    oxfr_err            = intern("xfr.err");
    oxfr_hello          = intern("xfr.hello");
    oxfr_migrate        = intern("xfr.migrate");
    oxfr_migrate_ok     = intern("xfr.migrate.ok");
    oxfr_progress       = intern("xfr.progress");
    oxfr_save           = intern("xfr.save");
    oxfr_save_ok        = intern("xfr.save.ok");
    oxfr_vm_destroy     = intern("xfr.vm.destroy");
    oxfr_vm_suspend     = intern("xfr.vm.suspend");
    oxfr_xfr            = intern("xfr.xfr");
    oxfr_xfr_ok         = intern("xfr.xfr.ok");
}

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define PROGRAM      "xfrd"

#define OPT_PORT     'P'
#define KEY_PORT     "port"
#define DOC_PORT     "<port>\n\txfr port (as a number or service name)"

#define OPT_COMPRESS 'Z'
#define KEY_COMPRESS "compress"
#define DOC_COMPRESS "\n\tuse compression for migration"

#define OPT_HELP     'h'
#define KEY_HELP     "help"
#define DOC_HELP     "\n\tprint help"

#define OPT_VERSION  'v'
#define KEY_VERSION  "version"
#define DOC_VERSION  "\n\tprint version"

#define OPT_VERBOSE  'V'
#define KEY_VERBOSE  "verbose"
#define DOC_VERBOSE  "\n\tverbose flag"

/** Print a usage message.
 * Prints to stdout if err is zero, and exits with 0.
 * Prints to stderr if err is non-zero, and exits with 1.
 */
void usage(int err){
    FILE *out = (err ? stderr : stdout);

    fprintf(out, "Usage: %s [options]\n", PROGRAM);
    fprintf(out, "-%c, --%s %s\n", OPT_PORT,     KEY_PORT,     DOC_PORT);
    fprintf(out, "-%c, --%s %s\n", OPT_COMPRESS, KEY_COMPRESS, DOC_COMPRESS);
    fprintf(out, "-%c, --%s %s\n", OPT_VERBOSE,  KEY_VERBOSE,  DOC_VERBOSE);
    fprintf(out, "-%c, --%s %s\n", OPT_VERSION,  KEY_VERSION,  DOC_VERSION);
    fprintf(out, "-%c, --%s %s\n", OPT_HELP,     KEY_HELP,     DOC_HELP);
    exit(err ? 1 : 0);
}

/** Short options. Options followed by ':' take an argument. */
static char *short_opts = (char[]){
    OPT_PORT,     ':',
    OPT_COMPRESS,
    OPT_HELP,
    OPT_VERSION,
    OPT_VERBOSE,
    0 };

/** Long options. */
static struct option const long_opts[] = {
    { KEY_PORT,     required_argument, NULL, OPT_PORT     },
    { KEY_COMPRESS, no_argument,       NULL, OPT_COMPRESS },
    { KEY_HELP,     no_argument,       NULL, OPT_HELP     },
    { KEY_VERSION,  no_argument,       NULL, OPT_VERSION  },
    { KEY_VERBOSE,  no_argument,       NULL, OPT_VERBOSE  },
    { NULL,         0,                 NULL, 0            }
};

typedef struct Args {
    int bufsize;
    unsigned long port;
    int verbose;
    int compress;
} Args;

/** Transfer states. */
enum {
    XFR_INIT,
    XFR_HELLO,
    XFR_STATE,
    XFR_RUN,
    XFR_FAIL,
    XFR_DONE,
    XFR_MAX
};

/** Initialize an array element for a constant to its string name. */
#define VALDEF(val) { val, #val }

/** Names for the transfer states. */
static EnumDef xfr_states[] = {
    VALDEF(XFR_INIT),
    VALDEF(XFR_HELLO),
    VALDEF(XFR_STATE),
    VALDEF(XFR_RUN),
    VALDEF(XFR_FAIL),
    VALDEF(XFR_DONE),
    { 0, NULL }
};
    

/** State machine for transfer. */
typedef struct XfrState {
    /** Current state. */
    int state;
    /** Error codes for the states. */
    int state_err[XFR_MAX];
    /** First error. */
    int err;
    /** State when first error happened. */
    int err_state;

    uint32_t vmid;
    char* vmconfig;
    int vmconfig_n;
    unsigned long xfr_port;
    char *xfr_host;
    uint32_t vmid_new;
    int live;
} XfrState;

/** Get the name of a transfer state.
 *
 * @param s state
 * @return name
 */
char * xfr_state_name(int s){
    return enum_val_to_name(s, xfr_states);
}

/** Set the state of a transfer.
 *
 * @param s transfer
 * @param state state
 * @return state
 */
int XfrState_set_state(XfrState *s, int state){
    s->state = state;
    return s->state;
}

/** Get the state of a transfer.
 *
 * @param s transfer
 * @return state
 */
int XfrState_get_state(XfrState *s){
    return s->state;
}

/** Set an error in the current state.
 * Does nothing if an error is already set.
 *
 * @param s transfer
 * @param err error
 * @return error
 */
int XfrState_set_err(XfrState *s, int err){
    if(!s->state_err[s->state]){
        s->state_err[s->state] = err;
    }
    if(!s->err){
        s->err = err;
        s->err_state = s->state;
    }
    return err;
}

/** Get the error in the current state.
 *
 * @param s transfer
 * @return error
 */
int XfrState_get_err(XfrState *s){
    return s->state_err[s->state];
}

/** Get the first error of a transfer.
 *
 * @param s transfer
 * @return error
 */
int XfrState_first_err(XfrState *s){
    return s->err;
}

/** Get the state a transfer was in when it had its first error.
 *
 * @param s transfer
 * @return error state
 */
int XfrState_first_err_state(XfrState *s){
    return s->err_state;
}

/** Xfrd arguments. */
static Args _args = {};

/** Xfrd arguments. */
static Args *args = &_args;

/** Set xfrd default arguments.
 *
 * @param args arguments to set
 */
void set_defaults(Args *args){
    args->compress = FALSE;
    args->bufsize = 128 * 1024;
    args->port = htons(XFRD_PORT);
}

int stringof(Sxpr exp, char **s){
    int err = 0;
    //dprintf(">\n"); objprint(iostdout, exp, PRINT_TYPE); IOStream_print(iostdout, "\n");
    if(ATOMP(exp)){
        *s = atom_name(exp);
    } else if(STRINGP(exp)){
        *s = string_string(exp);
    } else {
        err = -EINVAL;
        *s = NULL;
    }
    //dprintf("< err=%d s=%s\n", err, *s);
    return err;
}

int intof(Sxpr exp, int *v){
    int err = 0;
    char *s;
    unsigned long l;
    //dprintf(">\n"); objprint(iostdout, exp, 0); IOStream_print(iostdout, "\n");
    if(INTP(exp)){
        *v = OBJ_INT(exp);
    } else {
        err = stringof(exp, &s);
        if(err) goto exit;
        err = convert_atoul(s, &l);
        *v = (int)l;
    }
 exit:
    //dprintf("< err=%d v=%d\n", err, *v);
    return err;
}

int addrof(Sxpr exp, uint32_t *v){
    char *h;
    unsigned long a;
    int err = 0;
    //dprintf(">\n"); objprint(iostdout, exp, 0); IOStream_print(iostdout, "\n");
    err = stringof(exp, &h);
    if(err) goto exit;
    if(get_host_address(h, &a)){
        err = -EINVAL;
        goto exit;
    }
    *v = a;
  exit:
    //dprintf("< err=%d v=%x\n", err, *v);
    return err;
}

int portof(Sxpr exp, uint16_t *v){
    char *s;
    int err = 0;
    //dprintf(">\n"); objprint(iostdout, exp, 0); IOStream_print(iostdout, "\n");
    if(INTP(exp)){
        *v = get_ul(exp);
        *v = htons(*v);
    } else {
        unsigned long p;
        err = stringof(exp, &s);
        if(err) goto exit;
        err = convert_service_to_port(s, &p);
        if(err){
            err = -EINVAL;
            goto exit;
        }
        *v = p;
    }
  exit:
    //dprintf("< err=%d v=%u\n", err, *v);
    return err;
}

static inline struct in_addr inaddr(uint32_t addr){
    return (struct in_addr){ .s_addr = addr };
}

time_t stats(time_t t0, uint64_t offset, uint64_t memory, float *percent, float *rate){
    time_t t1 = time(NULL);
    *percent = (offset * 100.0f) / memory;
    t1 = time(NULL) - t0;
    *rate = (t1 ?  offset/(t1 * 1024.0f) : 0.0f);
    return t1;
}

/** Notify success or error.
 *
 * @param conn connection
 * @param errcode error code
 * @return 0 on success, error code otherwise
 */
int xfr_error(Conn *conn, int errcode){
    int err = 0;

    if(!conn->out) return -ENOTCONN;
    if(errcode <0) errcode = -errcode;
    err = IOStream_print(conn->out, "(%s %d)",
                         atom_name(oxfr_err), errcode);
    return (err < 0 ? err : 0);
}

/** Read a response message - error or ok.
 *
 * @param conn connection
 * @return 0 on success, error code otherwise
 */
int xfr_response(Conn *conn){
    int err;
    Sxpr sxpr;

    dprintf(">\n");
    if(!conn->out) return -ENOTCONN;
    err = Conn_sxpr(conn, &sxpr);
    if(err) goto exit;
    if(sxpr_elementp(sxpr, oxfr_err)){
        int errcode;
        err = intof(sxpr_childN(sxpr, 0, ONONE), &errcode);
        if(err) goto exit;
        err = errcode;
    }
  exit:
    dprintf("< err=%d\n", err);
    return err;
}

/** Get the initial hello message and check the protocol version.
 * It is an error to receive anything other than a hello message
 * with the correct protocol version.
 *
 * @param conn connection
 * @return 0 on success, error code otherwise
 */
int xfr_hello(Conn *conn){
    int err;
    uint32_t major = XFR_PROTO_MAJOR, minor = XFR_PROTO_MINOR;
    uint32_t hello_major, hello_minor;
    Sxpr sxpr;
    if(!conn->in) return -ENOTCONN;
    dprintf(">\n");
    err = Conn_sxpr(conn, &sxpr);
    if(err) goto exit;
    if(!sxpr_elementp(sxpr, oxfr_hello)){
        wprintf("> sxpr_elementp test failed\n");
        err = -EINVAL;
        goto exit;
    }
    err = intof(sxpr_childN(sxpr, 0, ONONE), &hello_major);
    if(err) goto exit;
    err = intof(sxpr_childN(sxpr, 1, ONONE), &hello_minor);
    if(err) goto exit;
    if(hello_major != major || hello_minor != minor){
        eprintf("> Wanted protocol version %d.%d, got %d.%d",
                major, minor, hello_major, hello_minor);
        err = -EINVAL;
        goto exit;
    }
  exit:
    xfr_error(conn, err);
    if(err){
        eprintf("> Hello failed: %d\n", err);
    }
    dprintf("< err=%d\n", err);
    return err;
}

/** Send the initial hello message.
 *
 * @param conn connection
 * @param msg  message
 * @return 0 on success, error code otherwise
 */
int xfr_send_hello(Conn *conn){
    int err = 0;
    dprintf(">\n");

    err = IOStream_print(conn->out, "(%s %d %d)",
                         atom_name(oxfr_hello),
                         XFR_PROTO_MAJOR,
                         XFR_PROTO_MINOR);
    if(err < 0) goto exit;
    IOStream_flush(conn->out);
    err = xfr_response(conn);
  exit:
    dprintf("< err=%d\n", err);
    return err;
}

int xfr_send_xfr(Conn *conn, uint32_t vmid){
    int err;

    err = IOStream_print(conn->out, "(%s %d)",
                         atom_name(oxfr_xfr), vmid);
    return (err < 0 ? err : 0);
}

int xfr_send_xfr_ok(Conn *conn, uint32_t vmid){
    int err = 0;

    err = IOStream_print(conn->out, "(%s %d)",
                         atom_name(oxfr_xfr_ok), vmid);
    return (err < 0 ? err : 0);
}

int xfr_send_migrate_ok(Conn *conn, uint32_t vmid){
    int err = 0;

    err = IOStream_print(conn->out, "(%s %d)",
                         atom_name(oxfr_migrate_ok), vmid);
    return (err < 0 ? err : 0);
}

int xfr_send_save_ok(Conn *conn){
    int err = 0;

    err = IOStream_print(conn->out, "(%s)",
                         atom_name(oxfr_save_ok));
    return (err < 0 ? err : 0);
}

int xfr_send_suspend(Conn *conn, uint32_t vmid){
    int err = 0;

    err = IOStream_print(conn->out, "(%s %d)",
                         atom_name(oxfr_vm_suspend), vmid);
    return (err < 0 ? err : 0);
}

/** Suspend a vm on behalf of save/migrate.
 */
int xfr_vm_suspend(Conn *xend, uint32_t vmid){
    int err = 0;
    dprintf("> vmid=%u\n", vmid);
    err = xfr_send_suspend(xend, vmid);
    if(err) goto exit;
    IOStream_flush(xend->out);
    err = xfr_response(xend);
  exit:
    dprintf("< err=%d\n", err);
    return err;
}

int xfr_send_destroy(Conn *conn, uint32_t vmid){
    int err = 0;

    err = IOStream_print(conn->out, "(%s %d)",
                         atom_name(oxfr_vm_destroy), vmid);
    return (err < 0 ? err : 0);
}

/** Destroy a vm on behalf of save/migrate.
 */
int xfr_vm_destroy(Conn *xend, uint32_t vmid){
    int err = 0;
    dprintf("> vmid=%u\n", vmid);
    err = xfr_send_destroy(xend, vmid);
    if(err) goto exit;
    IOStream_flush(xend->out);
    err = xfr_response(xend);
  exit:
    dprintf("< err=%d\n", err);
    return err;
}

/** Get vm state. Send transfer message.
 *
 * @param peer connection
 * @param msg  message
 * @return 0 on success, error code otherwise
 */
int xfr_send_state(XfrState *state, Conn *xend, Conn *peer){
    int err = 0;
    Sxpr sxpr;
    
    dprintf(">\n");
    XfrState_set_state(state, XFR_STATE);
    // Send xfr message and the domain state.
    err = xfr_send_xfr(peer, state->vmid);
    if(err) goto exit;
    dprintf(">*** Sending domain %u\n", state->vmid);
    err = xen_domain_snd(xend, peer->out,
                         state->vmid,
                         state->vmconfig, state->vmconfig_n,
                         state->live);
    dprintf(">*** Sent domain %u\n", state->vmid);
    if(err) goto exit;
    // Sending the domain suspends it, and there's no way back.
    // So destroy it now. If anything goes wrong now it's too late.
    dprintf(">*** Destroying domain %u\n", state->vmid);
    err = xfr_vm_destroy(xend, state->vmid);
    if(err) goto exit;
    err = xfr_error(peer, err);
    if(err) goto exit;
    IOStream_flush(peer->out);
    // Read the response from the peer.
    err = Conn_sxpr(peer, &sxpr);
    if(err) goto exit;
    if(sxpr_elementp(sxpr, oxfr_err)){
        // Error.
        int errcode;
        err = intof(sxpr_childN(sxpr, 0, ONONE), &errcode);
        if(!err) err = errcode;
    } else if(sxpr_elementp(sxpr, oxfr_xfr_ok)){
        // Ok - get the new domain id.
        err = intof(sxpr_childN(sxpr, 0, ONONE), &state->vmid_new);
        xfr_error(peer, err);
    } else {
        // Anything else is invalid. But it may be too late.
        err = -EINVAL;
        xfr_error(peer, err);
    }
  exit:
    XfrState_set_err(state, err);
    dprintf("< err=%d\n", err);
    return err;
}

/** Finish the transfer.
 */
int xfr_send_done(XfrState *state, Conn *xend){
    int err = 0;
    int first_err = 0;

    first_err = XfrState_first_err(state);
    if(first_err){
        XfrState_set_state(state, XFR_FAIL);
    } else {
        XfrState_set_state(state, XFR_DONE);
    }
    if(first_err){
        err = xfr_error(xend, first_err);
    } else {
        // Report new domain id to xend.
        err = xfr_send_migrate_ok(xend, state->vmid_new);
    }  

    XfrState_set_err(state, err);
    if(XfrState_first_err(state)){
        int s, serr;

        wprintf("> Transfer errors:\n");
        for(s = 0; s < XFR_MAX; s++){
            serr = state->state_err[s];
            if(!serr) continue;
            wprintf("> state=%-12s err=%d\n", xfr_state_name(s), serr);
        }
    } else {
        wprintf("> Transfer OK\n");
    }
    dprintf("< err=%d\n", err);
    return err;
}

/** Migrate a vm to another node.
 *
 * @param xend connection
 * @return 0 on success, error code otherwise
 */
int xfr_send(Args *args, XfrState *state, Conn *xend, uint32_t addr, uint32_t port){
    int err = 0;
    Conn _peer = {}, *peer = &_peer;
    int flags = 0;
    struct in_addr xfr_addr;
    uint16_t xfr_port;
    time_t t0 = time(NULL), t1;

    dprintf(">\n");
    flags |= CONN_NOBUFFER;
    if(args->compress){
        flags |= CONN_WRITE_COMPRESS;
    }
    xfr_addr.s_addr = addr;
    xfr_port = port;
    if(!xfr_port) xfr_port = htons(XFRD_PORT);
    dprintf("> Xfr vmid=%u\n", state->vmid);
    dprintf("> Xfr xfr_addr=%s:%d\n", inet_ntoa(xfr_addr), ntohs(xfr_port));
    err = Conn_connect(peer, flags, xfr_addr, xfr_port);
    if(err) goto exit;
    XfrState_set_state(state, XFR_HELLO);
    // Send hello message.
    err = xfr_send_hello(peer);
    if(err) goto exit;
    printf("\n");
    // Send vm state.
    err = xfr_send_state(state, xend, peer);
    if(err) goto exit;
    if(args->compress){
        IOStream *zio = peer->out;
        int plain_bytes = lzi_stream_plain_bytes(zio);
        int comp_bytes = lzi_stream_comp_bytes(zio);
        float ratio = lzi_stream_ratio(zio);
        iprintf("> Compression: plain %d bytes, compressed %d bytes, ratio %3.2f\n",
                plain_bytes, comp_bytes, ratio);
    }
  exit:
    dprintf("> err=%d\n", err);
    if(err && !XfrState_get_err(state)){
        XfrState_set_err(state, err);
    }
    Conn_close(peer);
    if(!err){
        t1 = time(NULL) - t0;
        iprintf("> Transfer complete in %lu seconds\n", t1);
    }
    dprintf("> done err=%d, notifying xend...\n", err);
    xfr_send_done(state, xend);
    dprintf("< err=%d\n", err);
    return err;
}

/** Save a vm to file.
 */
int xfr_save(Args *args, XfrState *state, Conn *xend, char *file){
    int err = 0;
    int compress = 0;
    IOStream *io = NULL;

    dprintf("> file=%s\n", file);
    if(compress){
        io = gzip_stream_fopen(file, "wb1");
    } else {
        io = file_stream_fopen(file, "wb");
    }
    if(!io){
        eprintf("> Failed to open %s\n", file);
        err = -EINVAL;
        goto exit;
    }
    err = xen_domain_snd(xend, io,
                         state->vmid,
                         state->vmconfig, state->vmconfig_n,
                         0);
    if(err){
        err = xfr_error(xend, err);
    } else {
        err = xfr_send_save_ok(xend);
    }
  exit:
    if(io){
        IOStream_close(io);
        IOStream_free(io);
    }
    if(err){
        unlink(file);
    }
    dprintf("< err=%d\n", err);
    return err;
}

/** Accept the transfer of a vm from another node.
 *
 * @param peer connection
 * @param msg  message
 * @return 0 on success, error code otherwise
 */
int xfr_recv(Args *args, XfrState *state, Conn *peer){
    int err = 0;
    time_t t0 = time(NULL), t1;
    Sxpr sxpr;

    dprintf(">\n");
    err = xen_domain_rcv(peer->in, &state->vmid_new, &state->vmconfig, &state->vmconfig_n);
    if(err) goto exit;
    // Read from the peer. This is just so we wait before configuring.
    // When migrating to the same host the peer must destroy the domain
    // before we configure the new one.
    err = Conn_sxpr(peer, &sxpr);
    if(err) goto exit;
    err = xen_domain_configure(state->vmid_new, state->vmconfig, state->vmconfig_n);
    if(err) goto exit;
    err = xen_domain_unpause(state->vmid_new);
    if(err) goto exit;
    // Report new domain id to peer.
    err = xfr_send_xfr_ok(peer, state->vmid_new);
    if(err) goto exit;
    // Get the final ok.
    err = xfr_response(peer);
  exit:
    if(!err){
        t1 = time(NULL) - t0;
        iprintf("> Transfer complete in %lu seconds\n", t1);
    }
    if(err){
        xfr_error(peer, err);
    }
    dprintf("< err=%d\n", err);
    return err;
}

/** Listen for a hello followed by a service request.
 * The request can be from the local xend or from xfrd on another node.
 *
 * @param peersock socket
 * @param peer_in peer address
 * @return 0 on success, error code otherwise
 */
int xfrd_service(Args *args, int peersock, struct sockaddr_in peer_in){
    int err = 0;
    Sxpr sxpr;
    Conn _conn = {}, *conn = &_conn;
    int flags = CONN_NOBUFFER;

    dprintf(">\n");
    err = Conn_init(conn, flags, peersock, peer_in);
    if(err) goto exit;
    //dprintf(">xfr_hello... \n");
    err = xfr_hello(conn);
    if(err) goto exit;
    //dprintf("> sxpr...\n");
    err = Conn_sxpr(conn, &sxpr);
    if(err) goto exit;
    //dprintf("> sxpr=\n");
    //objprint(iostdout, sxpr, PRINT_TYPE); IOStream_print(iostdout, "\n");
    if(sxpr_elementp(sxpr, oxfr_migrate)){
        // Migrate message from xend.
        uint32_t addr;
        uint16_t port;
        XfrState _state = {}, *state = &_state;
        int n = 0;

        dprintf("> xfr.migrate\n");
        err = intof(sxpr_childN(sxpr, n++, ONONE), &state->vmid);
        if(err) goto exit;
        err = stringof(sxpr_childN(sxpr, n++, ONONE), &state->vmconfig);
        if(err) goto exit;
        state->vmconfig_n = strlen(state->vmconfig);
        err = addrof(sxpr_childN(sxpr, n++, ONONE), &addr);
        if(err) goto exit;
        err = portof(sxpr_childN(sxpr, n++, ONONE), &port);
        if(err) goto exit;
        err = intof(sxpr_childN(sxpr, n++, ONONE), &state->live);
        if(err) goto exit;
        err = xfr_send(args, state, conn, addr, port);

    } else if(sxpr_elementp(sxpr, oxfr_save)){
        // Save message from xend.
        char *file;
        XfrState _state = {}, *state = &_state;
        int n = 0;

        dprintf("> xfr.save\n");
        err = intof(sxpr_childN(sxpr, n++, ONONE), &state->vmid);
        if(err) goto exit;
        err = stringof(sxpr_childN(sxpr, n++, ONONE), &state->vmconfig);
        if(err) goto exit;
        state->vmconfig_n = strlen(state->vmconfig);
        err = stringof(sxpr_childN(sxpr, n++, ONONE), &file);
        if(err) goto exit;
        err = xfr_save(args, state, conn, file);

    } else if(sxpr_elementp(sxpr, oxfr_xfr)){
        // Xfr message from peer xfrd.
        XfrState _state = {}, *state = &_state;
        int n = 0;

        dprintf("> xfr.xfr\n");
        err = intof(sxpr_childN(sxpr, n++, ONONE), &state->vmid);
        if(err) goto exit;
        err = xfr_recv(args, state, conn);

    } else{
        // Anything else is invalid.
        err = -EINVAL;
        eprintf("> Invalid message: ");
        objprint(iostderr, sxpr, 0);
        IOStream_print(iostderr, "\n");
        xfr_error(conn, err);
    }
  exit:
    Conn_close(conn);
    dprintf("< err=%d\n", err);
    return err;
}

/** Accept an incoming connection.
 *
 * @param sock tcp socket
 * @return 0 on success, error code otherwise
 */
int xfrd_accept(Args *args, int sock){
    struct sockaddr_in peer_in;
    struct sockaddr *peer = (struct sockaddr *)&peer_in;
    socklen_t peer_n = sizeof(peer_in);
    int peersock;
    pid_t pid;
    int err = 0;
    
    dprintf("> sock=%d\n", sock);
    dprintf("> accept...\n");
    peersock = accept(sock, peer, &peer_n);
    dprintf("> accept=%d\n", peersock);
    if(peersock < 0){
        perror("accept");
        err = -errno;
        goto exit;
    }
    iprintf("> Accepted connection from %s:%d on %d\n",
            inet_ntoa(peer_in.sin_addr), htons(peer_in.sin_port), sock);
    pid = fork();
    if(pid > 0){
        // Parent, fork succeeded.
        iprintf("> Forked child pid=%d\n", pid);
        close(peersock);
    } else if (pid < 0){
        // Parent, fork failed.
        perror("fork");
        close(peersock);
    } else {
        // Child.
        iprintf("> Xfr service for %s:%d\n",
                inet_ntoa(peer_in.sin_addr), htons(peer_in.sin_port));
        err = xfrd_service(args, peersock, peer_in);
        iprintf("> Xfr service err=%d\n", err);
        shutdown(peersock, 2);
        exit(err ? 1 : 0);
    }
  exit:
    dprintf("< err=%d\n", err);
    return err;
}

/** Socket select loop.
 * Accepts connections on the tcp socket.
 *
 * @param listen_sock tcp listen socket
 * @return 0 on success, error code otherwise
 */
int xfrd_select(Args *args, int listen_sock){
    int err = 0;
    SelectSet set = {};
    dprintf("> socks: %d\n", listen_sock);
    while(1){
        SelectSet_zero(&set);
        SelectSet_add_read(&set, listen_sock);
        err = SelectSet_select(&set, NULL);
        if(err < 0){
            if(errno == EINTR) continue;
            perror("select");
            goto exit;
        }
        if(FD_ISSET(listen_sock, &set.rd)){
            xfrd_accept(args, listen_sock);
        }
    }
  exit:
    dprintf("< err=%d\n", err);
    return err;
}

/** Create a socket.
 *
 * @param args program arguments
 * @param socktype socket type
 * @param reuse whether to set SO_REUSEADDR
 * @param val return value for the socket
 * @return 0 on success, error code otherwise
 */
int create_socket(Args *args, int socktype, int reuse, int *val){
    int err = 0;
    int sock = 0;
    struct sockaddr_in addr_in;
    struct sockaddr *addr = (struct sockaddr *)&addr_in;
    socklen_t addr_n = sizeof(addr_in);

    dprintf(">\n");
    // Create socket and bind it.
    sock = socket(AF_INET, socktype, 0);
    if(sock < 0){
        err = -errno;
        goto exit;
    }
    addr_in.sin_family = AF_INET;
    addr_in.sin_addr.s_addr = INADDR_ANY;
    addr_in.sin_port = args->port;
    dprintf("> port=%d\n", ntohs(addr_in.sin_port));
    if(reuse){
        // Set socket option to reuse address.
        int val = 1;
        err = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
        if(err < 0){
            err = -errno;
            perror("setsockopt");
            goto exit;
        }
    }
    err = bind(sock, addr, addr_n);
    if(err < 0){
        err = -errno;
        perror("bind");
        goto exit;
    }
  exit:
    *val = (err ? -1 : sock);
    dprintf("< err=%d\n", err);
    return err;
}

/** Create the tcp listen socket.
 *
 * @param args program arguments
 * @param val return value for the socket
 * @return 0 on success, error code otherwise
 */
int xfrd_listen_socket(Args *args, int *val){
    int err = 0;
    int sock;
    dprintf(">\n");
    err = create_socket(args, SOCK_STREAM, 1, &sock);
    if(err) goto exit;
    dprintf("> listen...\n");
    err = listen(sock, 5);
    if(err < 0){
        err = -errno;
        perror("listen");
        goto exit;
    }
  exit:
    *val = (err ? -1 : sock);
    if(err) close(sock);
    dprintf("< err=%d\n", err);
    return err;
}

/** Type for signal handling functions. */
typedef void SignalAction(int code, siginfo_t *info, void *data);

/** Handle SIGCHLD by getting child exit status.
 * This prevents child processes being defunct.
 *
 * @param code signal code
 * @param info signal info
 * @param data
 */
void sigaction_SIGCHLD(int code, siginfo_t *info, void *data){
    int status;
    pid_t pid;
    //dprintf("> child_exit=%d waiting...\n", child_exit);
    pid = wait(&status);
    dprintf("> child pid=%d status=%d\n", pid, status);
}

/** Handle SIGPIPE.
 *
 * @param code signal code
 * @param info signal info
 * @param data
 */
void sigaction_SIGPIPE(int code, siginfo_t *info, void *data){
    dprintf("> SIGPIPE\n");
    //fflush(stdout);
    //fflush(stderr);
    //exit(1);
}

/** Handle SIGALRM.
 *
 * @param code signal code
 * @param info signal info
 * @param data
 */
void sigaction_SIGALRM(int code, siginfo_t *info, void *data){
    dprintf("> SIGALRM\n");
}

/** Install a handler for a signal.
 *
 * @param signum signal
 * @param action handler
 * @return 0 on success, error code otherwise
 */
int catch_signal(int signum, SignalAction *action){
    int err = 0;
    struct sigaction sig = {};
    sig.sa_sigaction = action;
    sig.sa_flags = SA_SIGINFO;
    err = sigaction(signum, &sig, NULL);
    if(err){
        perror("sigaction");
    }
    return err;
}    

/** Transfer daemon main program.
 *
 * @param args program arguments
 * @return 0 on success, error code otherwise
 */
int xfrd_main(Args *args){
    int err = 0;
    int listen_sock;

    dprintf(">\n");
    catch_signal(SIGCHLD,sigaction_SIGCHLD);
    catch_signal(SIGPIPE,sigaction_SIGPIPE);
    catch_signal(SIGALRM,sigaction_SIGALRM); 
    err  = xfrd_listen_socket(args, &listen_sock);
    if(err) goto exit;
    err = xfrd_select(args, listen_sock);
  exit:
    close(listen_sock);
    dprintf("< err=%d\n", err);
    return err;
}

/** Parse command-line arguments and call the xfrd main program.
 *
 * @param arg argument count
 * @param argv arguments
 * @return 0 on success, 1 otherwise
 */
int main(int argc, char *argv[]){
    int err = 0;
    int key = 0;
    int long_index = 0;
    static const char * LOGFILE = "/var/log/xfrd.log";

    freopen(LOGFILE, "w+", stdout);
    fclose(stderr);
    stderr = stdout;
    dprintf(">\n");
    set_defaults(args);
    while(1){
	key = getopt_long(argc, argv, short_opts, long_opts, &long_index);
	if(key == -1) break;
	switch(key){
        case OPT_PORT:
            err = !convert_service_to_port(optarg, &args->port);
            if(err) goto exit;
            break;
        case OPT_COMPRESS:
            args->compress = TRUE;
            break;
	case OPT_HELP:
	    usage(0);
	    break;
	case OPT_VERBOSE:
	    args->verbose = TRUE;
	    break;
	case OPT_VERSION:
            printf("> Version %d.%d\n", XFR_PROTO_MAJOR, XFR_PROTO_MINOR);
            exit(0);
	    break;
	default:
	    usage(EINVAL);
	    break;
	}
    }
    xfr_init();
    err = xfrd_main(args);
  exit:
    if(err && key > 0){
        fprintf(stderr, "Error in arg %c\n", key);
    }
    return (err ? 1 : 0);
}

