/* 
 ****************************************************************************
 * (C) 2006 - Cambridge University
 ****************************************************************************
 *
 *        File: mm.c
 *      Author: Steven Smith (sos22@cam.ac.uk) 
 *     Changes: Grzegorz Milos (gm281@cam.ac.uk)
 *              
 *        Date: Mar 2006, chages Aug 2005
 * 
 * Environment: Xen Minimal OS
 * Description: Minimal implementation of xenbus
 *
 ****************************************************************************
 **/
#include <os.h>
#include <mm.h>
#include <traps.h>
#include <lib.h>
#include <xenbus.h>
#include <events.h>
#include <errno.h>
#include <sched.h>
#include <wait.h>
#include <xen/io/xs_wire.h>
#include <spinlock.h>
#include <xmalloc.h>

#define BUG_ON(x) do { \
    if (x) {printk("BUG at %s:%d\n", __FILE__, __LINE__); BUG(); } \
} while (0)

#define min(x,y) ({                       \
        typeof(x) tmpx = (x);                 \
        typeof(y) tmpy = (y);                 \
        tmpx < tmpy ? tmpx : tmpy;            \
        })

#ifdef XENBUS_DEBUG
#define DEBUG(_f, _a...) \
    printk("MINI_OS(file=xenbus.c, line=%d) " _f , __LINE__, ## _a)
#else
#define DEBUG(_f, _a...)    ((void)0)
#endif


static struct xenstore_domain_interface *xenstore_buf;
static DECLARE_WAIT_QUEUE_HEAD(xb_waitq);
struct xenbus_req_info 
{
    int in_use:1;
    struct wait_queue_head waitq;
    void *reply;
};

#define NR_REQS 32
static struct xenbus_req_info req_info[NR_REQS];

static void memcpy_from_ring(const void *Ring,
        void *Dest,
        int off,
        int len)
{
    int c1, c2;
    const char *ring = Ring;
    char *dest = Dest;
    c1 = min(len, XENSTORE_RING_SIZE - off);
    c2 = len - c1;
    memcpy(dest, ring + off, c1);
    memcpy(dest + c1, ring, c2);
}

static void xenbus_thread_func(void *ign)
{
    struct xsd_sockmsg msg;
    unsigned prod;

    for (;;) 
    {
        wait_event(xb_waitq, prod != xenstore_buf->rsp_prod);
        while (1) 
        {
            prod = xenstore_buf->rsp_prod;
            DEBUG("Rsp_cons %d, rsp_prod %d.\n", xenstore_buf->rsp_cons,
                    xenstore_buf->rsp_prod);
            if (xenstore_buf->rsp_prod - xenstore_buf->rsp_cons < sizeof(msg))
                break;
            rmb();
            memcpy_from_ring(xenstore_buf->rsp,
                    &msg,
                    MASK_XENSTORE_IDX(xenstore_buf->rsp_cons),
                    sizeof(msg));
            DEBUG("Msg len %d, %d avail, id %d.\n",
                    msg.len + sizeof(msg),
                    xenstore_buf->rsp_prod - xenstore_buf->rsp_cons,
                    msg.req_id);
            if (xenstore_buf->rsp_prod - xenstore_buf->rsp_cons <
                    sizeof(msg) + msg.len)
                break;

            DEBUG("Message is good.\n");
            req_info[msg.req_id].reply = malloc(sizeof(msg) + msg.len);
            memcpy_from_ring(xenstore_buf->rsp,
                    req_info[msg.req_id].reply,
                    MASK_XENSTORE_IDX(xenstore_buf->rsp_cons),
                    msg.len + sizeof(msg));
            wake_up(&req_info[msg.req_id].waitq);
            xenstore_buf->rsp_cons += msg.len + sizeof(msg);
        }
    }
}

static void xenbus_evtchn_handler(int port, struct pt_regs *regs)
{
    wake_up(&xb_waitq);
}

static int nr_live_reqs;
static spinlock_t req_lock = SPIN_LOCK_UNLOCKED;
static DECLARE_WAIT_QUEUE_HEAD(req_wq);

/* Release a xenbus identifier */
static void release_xenbus_id(int id)
{
    BUG_ON(!req_info[id].in_use);
    spin_lock(&req_lock);
    nr_live_reqs--;
    if (nr_live_reqs == NR_REQS - 1)
        wake_up(&req_wq);
    spin_unlock(&req_lock);
}

/* Allocate an identifier for a xenbus request.  Blocks if none are
   available. */
static int allocate_xenbus_id(void)
{
    static int probe;
    int o_probe;

    while (1) 
    {
        spin_lock(&req_lock);
        if (nr_live_reqs < NR_REQS)
            break;
        spin_unlock(&req_lock);
        wait_event(req_wq, (nr_live_reqs < NR_REQS));
    }

    o_probe = probe;
    for (;;) 
    {
        if (!req_info[o_probe].in_use)
            break;
        o_probe = (o_probe + 1) % NR_REQS;
        BUG_ON(o_probe == probe);
    }
    nr_live_reqs++;
    req_info[o_probe].in_use = 1;
    probe = o_probe + 1;
    spin_unlock(&req_lock);
    init_waitqueue_head(&req_info[o_probe].waitq);
    return o_probe;
}

/* Initialise xenbus. */
void init_xenbus(void)
{
    int err;
    DEBUG("init_xenbus called.\n");
    xenstore_buf = mfn_to_virt(start_info.store_mfn);
    create_thread("xenstore", xenbus_thread_func, NULL);
    DEBUG("buf at %p.\n", xenstore_buf);
    err = bind_evtchn(start_info.store_evtchn,
            xenbus_evtchn_handler);
    DEBUG("xenbus on irq %d\n", err);
}

struct write_req {
    const void *data;
    unsigned len;
};

/* Send data to xenbus.  This can block.  All of the requests are seen
   by xenbus as if sent atomically.  The header is added
   automatically, using type %type, req_id %req_id, and trans_id
   %trans_id. */
static void xb_write(int type, int req_id, int trans_id,
        const struct write_req *req, int nr_reqs)
{
    XENSTORE_RING_IDX prod;
    int r;
    int len = 0;
    const struct write_req *cur_req;
    int req_off;
    int total_off;
    int this_chunk;
    struct xsd_sockmsg m = {.type = type, .req_id = req_id,
        .tx_id = trans_id };
    struct write_req header_req = { &m, sizeof(m) };

    for (r = 0; r < nr_reqs; r++)
        len += req[r].len;
    m.len = len;
    len += sizeof(m);

    cur_req = &header_req;

    BUG_ON(len > XENSTORE_RING_SIZE);
    /* Wait for the ring to drain to the point where we can send the
       message. */
    prod = xenstore_buf->req_prod;
    if (prod + len - xenstore_buf->req_cons > XENSTORE_RING_SIZE) 
    {
        /* Wait for there to be space on the ring */
        DEBUG("prod %d, len %d, cons %d, size %d; waiting.\n",
                prod, len, xenstore_buf->req_cons, XENSTORE_RING_SIZE);
        wait_event(xb_waitq,
                xenstore_buf->req_prod + len - xenstore_buf->req_cons <=
                XENSTORE_RING_SIZE);
        DEBUG("Back from wait.\n");
        prod = xenstore_buf->req_prod;
    }

    /* We're now guaranteed to be able to send the message without
       overflowing the ring.  Do so. */
    total_off = 0;
    req_off = 0;
    while (total_off < len) 
    {
        this_chunk = min(cur_req->len - req_off,
                XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(prod));
        memcpy((char *)xenstore_buf->req + MASK_XENSTORE_IDX(prod),
                (char *)cur_req->data + req_off, this_chunk);
        prod += this_chunk;
        req_off += this_chunk;
        total_off += this_chunk;
        if (req_off == cur_req->len) 
        {
            req_off = 0;
            if (cur_req == &header_req)
                cur_req = req;
            else
                cur_req++;
        }
    }

    DEBUG("Complete main loop of xb_write.\n");
    BUG_ON(req_off != 0);
    BUG_ON(total_off != len);
    BUG_ON(prod > xenstore_buf->req_cons + XENSTORE_RING_SIZE);

    /* Remote must see entire message before updating indexes */
    wmb();

    xenstore_buf->req_prod += len;

    /* Send evtchn to notify remote */
    notify_remote_via_evtchn(start_info.store_evtchn);
}

/* Send a mesasge to xenbus, in the same fashion as xb_write, and
   block waiting for a reply.  The reply is malloced and should be
   freed by the caller. */
static void *xenbus_msg_reply(int type,
        int trans,
        struct write_req *io,
        int nr_reqs)
{
    int id;
    DEFINE_WAIT(w);
    void *rep;
    struct xsd_sockmsg *repmsg;

    id = allocate_xenbus_id();
    add_waiter(w, req_info[id].waitq);

    xb_write(type, id, trans, io, nr_reqs);

    schedule();
    wake(current);

    rep = req_info[id].reply;
    repmsg = rep;
    BUG_ON(repmsg->req_id != id);
    release_xenbus_id(id);

    return rep;
}

/* Send a debug message to xenbus.  Can block. */
static void xenbus_debug_msg(const char *msg)
{
    int len = strlen(msg);
    struct write_req req[] = {
        { "print", sizeof("print") },
        { msg, len },
        { "", 1 }};
    void *reply;
    struct xsd_sockmsg *repmsg;

    reply = xenbus_msg_reply(XS_DEBUG, 0, req, 3);
    repmsg = reply;
    DEBUG("Got a reply, type %d, id %d, len %d.\n",
            repmsg->type, repmsg->req_id, repmsg->len);
}

/* List the contents of a directory.  Returns a malloc()ed array of
   pointers to malloc()ed strings.  The array is NULL terminated.  May
   block. */
static char **xenbus_ls(const char *pre)
{
    void *reply;
    struct xsd_sockmsg *repmsg;
    struct write_req req[] = { { pre, strlen(pre)+1 } };
    int nr_elems, x, i;
    char **res;

    repmsg = xenbus_msg_reply(XS_DIRECTORY, 0, req, 1);
    reply = repmsg + 1;
    for (x = nr_elems = 0; x < repmsg->len; x++)
        nr_elems += (((char *)reply)[x] == 0);
    res = malloc(sizeof(res[0]) * (nr_elems + 1));
    for (x = i = 0; i < nr_elems; i++) {
        int l = strlen((char *)reply + x);
        res[i] = malloc(l + 1);
        memcpy(res[i], (char *)reply + x, l + 1);
        x += l + 1;
    }
    res[i] = NULL;
    free(repmsg);
    return res;
}

static char *xenbus_read(const char *path)
{
    struct write_req req[] = { {path, strlen(path) + 1}};
    struct xsd_sockmsg *rep;
    char *res;
    rep = xenbus_msg_reply(XS_READ, 0, req, 1);
    res = malloc(rep->len + 1);
    memcpy(res, rep + 1, rep->len);
    res[rep->len] = 0;
    free(rep);
    return res;
}

static void do_ls_test(const char *pre)
{
    char **dirs;
    int x;

    DEBUG("ls %s...\n", pre);
    dirs = xenbus_ls(pre);
    for (x = 0; dirs[x]; x++) 
    {
        DEBUG("ls %s[%d] -> %s\n", pre, x, dirs[x]);
        free(dirs[x]);
    }
    free(dirs);
}

static void do_read_test(const char *path)
{
    char *res;
    DEBUG("Read %s...\n", path);
    res = xenbus_read(path);
    DEBUG("Read %s -> %s.\n", path, res);
    free(res);
}

/* Simple testing thing */
void test_xenbus(void)
{
    DEBUG("Doing xenbus test.\n");
    xenbus_debug_msg("Testing xenbus...\n");

    DEBUG("Doing ls test.\n");
    do_ls_test("device");
    do_ls_test("device/vif");
    do_ls_test("device/vif/0");

    DEBUG("Doing read test.\n");
    do_read_test("device/vif/0/mac");
    do_read_test("device/vif/0/backend");
    printk("Xenbus initialised.\n");
}
