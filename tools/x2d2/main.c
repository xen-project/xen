#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <asm/page.h>
#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <netinet/in.h>
#include <printf.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "minixend.h"

#define MINIXEND_PORT 5123

#define mb() asm volatile ("" ::: "memory")

static void send_control_message(int type, int subtype, int id,
				 int size, void *payload,
				 struct domain *target);

struct list_head
head_domain = LIST_HEAD(&head_domain);

static struct list_head
head_connection = LIST_HEAD(&head_connection);

struct list_head
head_console = LIST_HEAD(&head_console);

#define foreach_open_connection(d)                                          \
foreach_item(d, &head_connection, struct open_connection, connection_list)

/* Not modified after initial start up */
static struct domain *
dom0;
unsigned
xc_handle;
static int
listen_fd;
int
evtchn_fd;

static struct list_head
head_event_receiver = LIST_HEAD(&head_event_receiver);

struct event_receiver {
	struct list_head list;
	int id;
	pthread_cond_t cond;
};

/* We're protected by the dom0 mutex in here */
static struct event_receiver *
allocate_event_receiver(struct domain *d)
{
	static int next_message_id;
	struct event_receiver *work;

	assert(d == dom0);
	work = xmalloc(sizeof(*work));
	work->id = next_message_id++;
	pthread_cond_init(&work->cond, NULL);

	list_insert_after(&work->list, &head_event_receiver);

	return work;
}

static struct event_receiver *
find_event_receiver(int id)
{
	struct event_receiver *work;
	foreach_item(work, &head_event_receiver, struct event_receiver, list)
		if (work->id == id)
			return work;
	return NULL;
}

static void
release_event_receiver(struct event_receiver *w)
{
	list_remove(&w->list);
	pthread_cond_destroy(&w->cond);
	free(w);
}

/* Send a message to dom0, and then block awaiting a reply. */
/* Make sure we don't hold any domain mutexs */
static void
send_dom0_message_block(control_msg_t *msg)
{
	CONTROL_RING_IDX c;
	struct event_receiver *er;
	control_msg_t buf;

	PRINTF(0, "sending message to dom0 and blocking for reply.\n");
	pthread_mutex_lock(&dom0->mux);
	PRINTF(0, "got dom0 lock.\n");
	er = allocate_event_receiver(dom0);
	PRINTF(0, "allocated evetn receiver.\n");
	msg->id = er->id;
	PRINTF(1, "sending message with id %d\n", msg->id);
	send_control_message(msg->type, msg->subtype,
			     msg->id, msg->length, msg->msg, dom0);
	xc_evtchn_send(xc_handle, dom0->control_evtchn);

	PRINTF(0, "waiting for reply\n");
	pthread_cond_wait(&er->cond, &dom0->mux);
	PRINTF(0, "got reply\n");

	c = dom0->rx_resp_cons % CONTROL_RING_SIZE;
	memcpy(&buf, &dom0->ctrl_if->rx_ring[c], sizeof(buf));
	assert(msg->id == buf.id);
	assert(msg->type == buf.type);
	assert(msg->subtype == buf.subtype);
	memcpy(msg, &buf, sizeof(*msg));
	dom0->rx_resp_cons++;

	release_event_receiver(er);

	pthread_mutex_unlock(&dom0->mux);

	PRINTF(1, "got reply to message with id %d\n", msg->id);
}

/* Allocate an interdomain event channel.  event_ports[0] is the
   local event port number, event_ports[1] the remote */
int
allocate_event_channel(struct domain *d, int event_ports[2])
{
	return xc_evtchn_bind_interdomain(xc_handle, DOMID_SELF,
					  d->domid, event_ports,
					  event_ports+1);
}

static void
accept_new_connection(void)
{
	int fd;
	struct open_connection *oc;

	fd = accept(listen_fd, NULL, NULL);
	if (fd < 0)
		return;
	oc = xmalloc(sizeof(*oc));
	oc->fd = fd;
	oc->state = OC_STATE_CONNECTED;
	oc->buf_used = 0;
	oc->buf_allocated = 16;
	oc->buf = xmalloc(oc->buf_allocated);
	list_insert_after(&oc->connection_list, &head_connection);
}

static void
closedown_connection(struct open_connection *oc)
{
	close(oc->fd);
	assert(oc->buf);
	free(oc->buf);
	free(oc);
}

#if 0
/* Hackl for the benefit of domain replay */
static unsigned
report_work(u32 *ptr, u32 val, unsigned dom, int do_direct)
{
	if (!do_direct) {
		int rc;
		asm("int $0x80" : "=a" (rc)
		    : "0" (264), "b" (ptr), "c" (val), "d" (dom));
		if (rc < 0) {
			errno = -rc;
			rc = -1;
		}
		return rc;
	} else {
		*ptr = val;
		return 0;
	}
}
#else
static unsigned
report_work(u32 *ptr, u32 val, unsigned dom, int do_direct)
{
	*ptr = val;
	return 0;
}
#endif

static void
send_control_reply(const control_msg_t *msg, struct domain *d)
{
	CONTROL_RING_IDX c;

	PRINTF(3,"Control reply, type %d:%d, length %d.\n",
	       msg->type, msg->subtype, msg->length);
	c = d->ctrl_if->tx_resp_prod % CONTROL_RING_SIZE;
	memcpy(&d->ctrl_if->tx_ring[c], msg, sizeof(*msg));
	report_work(&d->ctrl_if->tx_resp_prod,
		    d->ctrl_if->tx_resp_prod + 1,
		    d->domid,
		    0);
	PRINTF(4,"tx_resp_prod %ld.\n", d->ctrl_if->tx_resp_prod);
	assert(!d->plugged);
}

static void
send_trivial_control_reply(const control_msg_t *msg, struct domain *d)
{
	control_msg_t rep;

	memset(&rep, 0, sizeof(rep));
	rep.type = msg->type;
	rep.subtype = msg->subtype;
	rep.id = msg->id;
	send_control_reply(&rep, d);
}

static void
process_console_control_message(control_msg_t *m, struct domain *d)
{
	int off;
	int r;

	if (m->subtype != CMSG_CONSOLE_DATA) {
		warnx("unknown console message subtype %d",
		      m->subtype);
		return;
	}

	if (m->length > 60) {
		warnx("truncating message from domain %d (was length %d)",
		      d->domid, m->length);
		m->length = 60;
	}
	PRINTF(1, "DOM%d: %.*s\n", d->domid, m->length, m->msg);
	send_trivial_control_reply(m, d);

	if (d->cc) {
		PRINTF(5, "Have a console connection.\n");
		if (d->cc->state == CC_STATE_CONNECTED) {
			PRINTF(5, "Console is connected, sending directly.\n");
			for (off = 0; off < m->length; off += r) {
				r = write(d->cc->fd, m->msg + off,
					  m->length - off);
				if (r <= 0) {
					d->cc->state = CC_STATE_ERROR;
					break;
				}
			}
		} else {
			PRINTF(5, "Console not connected, buffering.\n");
			if (d->cc->buf_allocated == 0) {
				d->cc->buf_allocated = 60;
				d->cc->buf = xmalloc(d->cc->buf_allocated);
				d->cc->buf_used = 0;
			} else if (d->cc->buf_allocated <
				   d->cc->buf_used + m->length) {
				d->cc->buf_allocated += 60;
				d->cc->buf = xrealloc(d->cc->buf,
						      d->cc->buf_allocated);
			}
			assert(d->cc->buf_allocated >=
			       d->cc->buf_used + m->length);
			memcpy(d->cc->buf + d->cc->buf_used,
			       m->msg,
			       m->length);
			d->cc->buf_used += m->length;
		}
	}
}

static void
process_blkif_fe_message(control_msg_t *m, struct domain *d)
{
	switch (m->subtype) {
	default:
		warnx("unknown blkif front end message subtype %d",
		      m->subtype);
	}
}

static void
send_control_message(int type, int subtype, int id,
		     int size, void *payload, struct domain *target)
{
	control_msg_t msg;
	CONTROL_RING_IDX c;

	msg.type = type;
	msg.subtype = subtype;
	msg.id = id;
	msg.length = size;
	memcpy(msg.msg, payload, size);

	c = target->ctrl_if->rx_req_prod % CONTROL_RING_SIZE;
	memcpy(&target->ctrl_if->rx_ring[c], &msg, sizeof(msg));
	report_work(&target->ctrl_if->rx_req_prod,
		    target->ctrl_if->rx_req_prod + 1,
		    target->domid,
		    0);
	assert(!target->plugged);
}

/* Procedure for bringing a new netif front end up:

   -- Front end sends us NETIF_FE_DRIVER_STATUS_CHANGED
   -- We send back end NETIF_BE_CREATE, wait for a reply
   -- Back end creates a new netif for us, replies
   -- We send front end a NETIF_FE_DRIVER_STATUS_CHANGED message saying
      how many interfaces we've created for it
   -- We send front end a NETIF_FE_INTERFACE_STATUS_CHANGED for each
      netif created
   -- Front end sends us a NETIF_FE_INTERFACE_CONNECT for each netif
*/
static void
handle_netif_fe_driver_status_changed(control_msg_t *m,
				      netif_fe_driver_status_changed_t *sh,
				      struct domain *d)
{
	netif_fe_interface_status_changed_t if_s;
	control_msg_t be_msg;
	netif_be_create_t *be = (void *)be_msg.msg;
	int r;

	switch (sh->status) {
	case NETIF_DRIVER_STATUS_UP:
		/* Tell the back end about the new interface coming
		 * up. */
		if (d->created_netif_backend) {
			PRINTF(10, "Front end came up twice in dom %d -> reporting no interfaces this time around.\n", d->domid);
			sh->nr_interfaces = 0;
			send_control_reply(m, d);
			send_control_message(CMSG_NETIF_FE,
					     CMSG_NETIF_FE_DRIVER_STATUS_CHANGED,
					     1,
					     sizeof(*sh),
					     sh,
					     d);
			return;
		}
		be_msg.type = CMSG_NETIF_BE;
		be_msg.subtype = CMSG_NETIF_BE_CREATE;
		be_msg.id = d->domid;
		be_msg.length = sizeof(*be);
		be->domid = d->domid;
		be->netif_handle = 0;
		memcpy(be->mac, d->netif_mac, 6);

		PRINTF(2,"Telling back end about new front end.\n");
		pthread_mutex_unlock(&d->mux);
		send_dom0_message_block(&be_msg);
		pthread_mutex_lock(&d->mux);
		PRINTF(3,"Done.\n");

		if (be->status != NETIF_BE_STATUS_OKAY) {
			/* Uh oh... can't bring back end
			 * up. */
			sh->nr_interfaces = 0;
			send_control_reply(m, d);
			send_control_message(CMSG_NETIF_FE,
					     CMSG_NETIF_FE_DRIVER_STATUS_CHANGED,
					     1,
					     sizeof(*sh),
					     sh,
					     d);
			return;
		}
		d->created_netif_backend = 1;

		r = our_system("/etc/xen/vif-bridge up domain=%s mac=%.02x:%.02x:%.02x:%.02x:%.02x:%.02x vif=vif%d.0 bridge=xen-br0",
			       d->name,
			       d->netif_mac[0],
			       d->netif_mac[1],
			       d->netif_mac[2],
			       d->netif_mac[3],
			       d->netif_mac[4],
			       d->netif_mac[5],
			       d->domid);
		if (r != 0)
			warn("error %d running vif-bridge script", r);

		/* Tell domain how many interfaces it has to deal
		 * with. */
		sh->nr_interfaces = 1;
		send_control_reply(m, d);
		send_control_message(CMSG_NETIF_FE,
				     CMSG_NETIF_FE_DRIVER_STATUS_CHANGED,
				     1,
				     sizeof(*sh),
				     sh,
				     d);

		PRINTF(2,"Telling front end about its interfaces.\n");
		if_s.handle = 0;
		if_s.status = NETIF_INTERFACE_STATUS_DISCONNECTED;
		send_control_message(CMSG_NETIF_FE,
				     CMSG_NETIF_FE_INTERFACE_STATUS_CHANGED,
				     1,
				     sizeof(if_s),
				     &if_s,
				     d);
		PRINTF(3,"Done.\n");

		break;
	default:
		warnx("unknown netif status %ld", sh->status);
		break;
	}
}

static void
handle_netif_fe_interface_connect(control_msg_t *m,
				  netif_fe_interface_connect_t *ic,
				  struct domain *d)
{
	control_msg_t be_msg;
	netif_be_connect_t *bmsg = (void *)be_msg.msg;
	netif_fe_interface_status_changed_t fmsg = {0};
	int evtchn_ports[2];
	int r;

	PRINTF(4, "front end sent us an interface connect message.\n");
	send_trivial_control_reply(m, d);

	r = xc_evtchn_bind_interdomain(xc_handle,
				       dom0->domid,
				       d->domid,
				       &evtchn_ports[0],
				       &evtchn_ports[1]);
	if (r < 0)
		err(1, "allocating network event channel");

	be_msg.type = CMSG_NETIF_BE;
	be_msg.subtype = CMSG_NETIF_BE_CONNECT;
	be_msg.id = 0;
	be_msg.length = sizeof(*bmsg);
	bmsg->domid = d->domid;
	bmsg->netif_handle = ic->handle;
	bmsg->tx_shmem_frame = ic->tx_shmem_frame;
	bmsg->rx_shmem_frame = ic->rx_shmem_frame;
	bmsg->evtchn = evtchn_ports[0];

	pthread_mutex_unlock(&d->mux);
	send_dom0_message_block(&be_msg);
	pthread_mutex_lock(&d->mux);

	if (bmsg->status != NETIF_BE_STATUS_OKAY) {
		PRINTF(2, "error connected backend netif: %ld\n",
		       bmsg->status);
		abort(); /* Need to handle this */
	} else {
		PRINTF(3, "connect backend netif\n");

		/* Tell the domain that we've connected it up. */
		fmsg.handle = ic->handle;
		fmsg.status = NETIF_INTERFACE_STATUS_CONNECTED;
		fmsg.evtchn = evtchn_ports[1];
		memcpy(fmsg.mac, d->netif_mac, 6);

		send_control_message(CMSG_NETIF_FE,
				     CMSG_NETIF_FE_INTERFACE_STATUS_CHANGED,
				     0,
				     sizeof(fmsg),
				     &fmsg,
				     d);
	}
}

static void
process_netif_fe_message(control_msg_t *m, struct domain *d)
{
	switch (m->subtype) {
	case CMSG_NETIF_FE_DRIVER_STATUS_CHANGED:
	{
		netif_fe_driver_status_changed_t *sh =
			(netif_fe_driver_status_changed_t *)m->msg;
		handle_netif_fe_driver_status_changed(m, sh, d);
		break;
	}
	case CMSG_NETIF_FE_INTERFACE_CONNECT:
	{
		netif_fe_interface_connect_t *ic =
			(netif_fe_interface_connect_t *)m->msg;
		handle_netif_fe_interface_connect(m, ic, d);
		break;
	}
	default:
		warnx("unknown netif front end message subtype %d",
		      m->subtype);
	}
}

static void
process_pdb_be_driver_status_changed_message(control_msg_t *msg,
					     pdb_be_driver_status_changed_t*pe,
					     struct domain *d)
{
	pdb_be_connected_t conn;
	pdb_fe_new_be_t new_be;
	int assist_channel[2];
	int event_channel[2];
	int r;

	switch (pe->status) {
	case PDB_DRIVER_STATUS_UP:
		PRINTF(4, "creating event channel for PDB device\n");
		r = allocate_event_channel(d, assist_channel);
		r |= allocate_event_channel(d, event_channel);
		if (r < 0)
			abort(); /* XXX need to handle this */

		send_trivial_control_reply(msg, d);

		PRINTF(4, "informing front end of event channel\n");
		conn.assist_port = assist_channel[1];
		conn.event_port = event_channel[1];
		send_control_message(CMSG_PDB_BE,
				     CMSG_PDB_BE_INTERFACE_CONNECTED,
				     0,
				     sizeof(conn),
				     &conn,
				     d);

		PRINTF(4, "informing back end of front end\n");
		new_be.domain = d->domid;
		new_be.assist_evtchn = assist_channel[0];
		new_be.event_evtchn = event_channel[0];
		new_be.assist_frame = pe->assist_page;
		new_be.event_frame = pe->event_page;
		send_control_message(CMSG_PDB_FE,
				     CMSG_PDB_FE_NEW_BE,
				     0,
				     sizeof(new_be),
				     &new_be,
				     dom0);
		break;
	default:
		warnx("unknown pdb status %d", pe->status);
	}
}

static void
process_pdb_be_message(control_msg_t *msg, struct domain *d)
{
	switch (msg->subtype) {
	case CMSG_PDB_BE_DRIVER_STATUS_CHANGED:
	{
		pdb_be_driver_status_changed_t *pe =
			(pdb_be_driver_status_changed_t *)msg->msg;
		process_pdb_be_driver_status_changed_message(msg, pe, d);
		break;
	}
	default:
		warnx("unknown pdb back end message subtype %d",
		      msg->subtype);
	}
}

static void
process_control_message(control_msg_t *msg, struct domain *d)
{
	control_msg_t m;

	/* Don't want a malicous domain messing us about, so copy the
	   control mesasge into a local buffer. */
	memcpy(&m, msg, sizeof(m));
	switch (m.type) {
	case CMSG_CONSOLE:
		process_console_control_message(&m, d);
		break;
	case CMSG_BLKIF_FE:
		process_blkif_fe_message(&m, d);
		break;
	case CMSG_NETIF_FE:
		process_netif_fe_message(&m, d);
		break;
	case CMSG_PDB_BE:
		process_pdb_be_message(&m, d);
		break;
	default:
		warnx("unknown control message type %d", m.type);
	}
}

static void
domain_did_control_event(struct domain *d)
{
	CONTROL_RING_IDX c;

	/* Pick up and process control ring messages. */
	while (d->tx_req_cons != d->ctrl_if->tx_req_prod) {
		c = d->tx_req_cons % CONTROL_RING_SIZE;
		process_control_message(&d->ctrl_if->tx_ring[c], d);
		d->tx_req_cons++;
		assert(d->tx_req_cons <= d->ctrl_if->tx_req_prod);
		PRINTF(5, "req_cons %ld, req_prod %ld.\n",
		       d->tx_req_cons, d->ctrl_if->tx_req_prod);
	}

	/* Take any replies off, and discard them. */
	if (d->rx_resp_cons != d->ctrl_if->rx_resp_prod)
		PRINTF(1, "discard %ld events\n",
		       d->ctrl_if->rx_resp_prod -
		       d->rx_resp_cons);
	d->rx_resp_cons = d->ctrl_if->rx_resp_prod;
}

/* This is the main function for domain control threads */
void *
domain_thread_func(void *D)
{
	struct domain *d = D;
	int r;
	CONTROL_RING_IDX old_resp_prod, old_req_prod;

	pthread_mutex_lock(&d->mux);
	for (;;) {
		pthread_cond_wait(&d->cond, &d->mux);

		old_resp_prod = d->ctrl_if->tx_resp_prod;
		old_req_prod = d->ctrl_if->rx_req_prod;

		domain_did_control_event(d);
		if (d->cc && d->cc->in_buf_used != 0 && d->plugged == 0) {
			r = d->cc->in_buf_used;
			if (r > 60)
				r = 60;
			PRINTF(1, "Sending to domain: %.*s\n",
			       r, d->cc->in_buf);
			send_control_message(CMSG_CONSOLE,
					     CMSG_CONSOLE_DATA,
					     0,
					     r,
					     d->cc->in_buf,
					     d);
			memmove(d->cc->in_buf, d->cc->in_buf + r,
				d->cc->in_buf_used - r);
			d->cc->in_buf_used -= r;
		}

		if (d->ctrl_if->tx_resp_prod != old_resp_prod ||
		    d->ctrl_if->rx_req_prod != old_req_prod)
			xc_evtchn_send(xc_handle, d->control_evtchn);
	}
}

/* This is the only thing you can do with a domain structure if you're
   not in the thread which controls that domain.  Domain 0 is
   special. */
void
signal_domain(struct domain *d)
{
	CONTROL_RING_IDX c;
	int id;
	struct event_receiver *evt;

	pthread_mutex_lock(&d->mux);
	if (d == dom0) {
		/* Take events off of dom0's control ring, and send
		   them to the event receivers. */
		while (d->tx_req_cons != d->ctrl_if->tx_req_prod) {
			c = d->tx_req_cons % CONTROL_RING_SIZE;
			id = d->ctrl_if->tx_ring[c].id;
			evt = find_event_receiver(id);
			if (evt != NULL) {
				PRINTF(1, "delivering event id %d\n", evt->id);
				pthread_cond_broadcast(&evt->cond);
				pthread_mutex_unlock(&d->mux);
				pthread_yield();
				pthread_mutex_lock(&d->mux);
			} else {
				warnx("unexpected message id %d discarded",
				      id);
				d->tx_req_cons++;
			}
		}
		while (d->rx_resp_cons != d->ctrl_if->rx_resp_prod) {
			c = d->rx_resp_cons % CONTROL_RING_SIZE;
			id = d->ctrl_if->rx_ring[c].id;
			evt = find_event_receiver(id);
			if (evt != NULL) {
				PRINTF(1, "delivering event rep id %d\n", evt->id);
				pthread_cond_broadcast(&evt->cond);
				pthread_mutex_unlock(&d->mux);
				pthread_yield();
				pthread_mutex_lock(&d->mux);
			} else {
				warnx("unexpected message reply id %d discarded",
				      id);
				d->rx_resp_cons++;
			}
		}
	} else {
		if (d->plugged) {
			d->event_pending = 1;
		} else {
			pthread_cond_broadcast(&d->cond);
		}
	}
	pthread_mutex_unlock(&d->mux);
}

static void
handle_evtchn_event(void)
{
	short port;
	struct domain *d;

	read(evtchn_fd, &port, sizeof(short));
	write(evtchn_fd, &port, sizeof(short));
	foreach_domain (d) {
		if (d->control_evtchn == port) {
			signal_domain(d);
			return;
		}
	}
	warnx("got an event on an unknown port %d", port);
}

void *
map_domain_mem(struct domain *d, unsigned long mfn)
{
	return xc_map_foreign_range(xc_handle, d->domid,
				    PAGE_SIZE, PROT_READ | PROT_WRITE,
				    mfn);
}

static void
handle_console_event(struct console_connection *cc)
{
	int r;
	int fd;

	switch (cc->state) {
	case CC_STATE_ERROR:
		/* Errors shouldn't get here. */
		abort();
	case CC_STATE_PENDING:
		fd = accept(cc->fd, NULL, NULL);
		if (fd >= 0) {
			PRINTF(3, "Accepted console connection for domain %d",
			       cc->dom->domid);
			close(cc->fd);
			cc->fd = fd;
			cc->state = CC_STATE_CONNECTED;
			while (cc->buf_used != 0) {
				r = write(cc->fd,
					  cc->buf,
					  cc->buf_used);
				if (r <= 0) {
					cc->state = CC_STATE_ERROR;
					break;
				}
				memmove(cc->buf,
					cc->buf + r,
					cc->buf_used - r);
				cc->buf_used -= r;
			}
			free(cc->buf);
			cc->buf = NULL;
			cc->buf_allocated = 0;
		} else {
			PRINTF(1, "error %s accepting console", strerror(errno));
		}
		pthread_mutex_unlock(&cc->dom->mux);
		break;
	case CC_STATE_CONNECTED:
		if (cc->in_buf_allocated == 0) {
			assert(cc->in_buf_used == 0);
			cc->in_buf_allocated = 128;
			cc->in_buf = xmalloc(cc->in_buf_allocated);
		}
		if (cc->in_buf_used == cc->in_buf_allocated) {
			cc->in_buf_allocated *= 2;
			cc->in_buf = xrealloc(cc->in_buf, cc->in_buf_allocated);
		}
		r = read(cc->fd, cc->in_buf + cc->in_buf_used,
			 cc->in_buf_allocated - cc->in_buf_used);
		if (r <= 0) {
			cc->state = CC_STATE_ERROR;
		} else {
			cc->in_buf_used += r;
		}
		pthread_mutex_unlock(&cc->dom->mux);
		signal_domain(cc->dom);
		break;
	}
}

static void
handle_connection_event(struct open_connection *oc)
{
	int r;

	/* We know that some amount of data is ready and waiting for
	   us.  Slurp it in. */
	if (oc->buf_used == oc->buf_allocated) {
		oc->buf_allocated *= 2;
		oc->buf = xrealloc(oc->buf, oc->buf_allocated);
	}
	r = read(oc->fd, oc->buf + oc->buf_used,
		 oc->buf_allocated - oc->buf_used);
	if (r < 0) {
		warn("reading command from remote");
		oc->state = OC_STATE_ERROR;
	} else if (r == 0) {
		warnx("reading command from remote");
		oc->state = OC_STATE_ERROR;
	} else {
		oc->buf_used += r;
		if (strchr(oc->buf, '\n'))
			oc->state = OC_STATE_COMMAND_PENDING;
	}
}

static void
get_and_process_event(void)
{
	fd_set read_fds, except_fds;
	struct open_connection *oc;
	struct console_connection *cc;
	int max_fd = listen_fd;
	int r;
	struct list_head *li, *temp_li;

	FD_ZERO(&read_fds);
	FD_ZERO(&except_fds);
	FD_SET(listen_fd, &read_fds);
	FD_SET(evtchn_fd, &read_fds);
	if (evtchn_fd > max_fd)
		max_fd = evtchn_fd;
	foreach_open_connection(oc) {
		FD_SET(oc->fd, &read_fds);
		FD_SET(oc->fd, &except_fds);
		if (oc->fd > max_fd)
			max_fd = oc->fd;
	}
	foreach_console_connection(cc) {
		FD_SET(cc->fd, &read_fds);
		FD_SET(cc->fd, &except_fds);
		if (cc->fd > max_fd)
			max_fd = cc->fd;
	}

	r = select(max_fd + 1, &read_fds, NULL, &except_fds, NULL);
	if (r < 0)
		err(1, "select");
	if (FD_ISSET(listen_fd, &read_fds)) {
		accept_new_connection();
	} else if (FD_ISSET(evtchn_fd, &read_fds))
		handle_evtchn_event();


	foreach_open_connection(oc) {
		if (FD_ISSET(oc->fd, &read_fds))
			handle_connection_event(oc);
		if (FD_ISSET(oc->fd, &except_fds))
			oc->state = OC_STATE_ERROR;
	}
	list_foreach_safe(&head_console, li, temp_li) {
		cc = list_item(li, struct console_connection, list);
		if (FD_ISSET(cc->fd, &read_fds))
			handle_console_event(cc);
		if (FD_ISSET(cc->fd, &except_fds) ||
		    cc->state == CC_STATE_ERROR) {
			PRINTF(1, "Cleaning up console connection");
			cc->dom->cc = NULL;
			list_remove(&cc->list);
			close(cc->fd);
			if (cc->buf_allocated != 0)
				free(cc->buf);
			if (cc->in_buf_allocated != 0)
				free(cc->in_buf);
			free(cc);
		}
	}

	/* Run pending stuff on the open connections. */
	list_foreach_safe(&head_connection, li, temp_li) {
		oc = list_item(li, struct open_connection, connection_list);
		switch (oc->state) {
		case OC_STATE_ERROR:
			list_remove(&oc->connection_list);
			closedown_connection(oc);
			break;
		case OC_STATE_COMMAND_PENDING:
			process_command(oc);
			break;
		case OC_STATE_CONNECTED:
			/* Don't need to do anything */
			break;
		}
	}
}

static int
start_listening(void)
{
	int sock;
	struct sockaddr_in inaddr;

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		err(1, "creating socket");
	memset(&inaddr, 0, sizeof(inaddr));
	inaddr.sin_family = AF_INET;
	inaddr.sin_port = htons(MINIXEND_PORT);

	if (bind(sock, (struct sockaddr *)&inaddr, sizeof(inaddr)) < 0)
		err(1, "binding to port %d", MINIXEND_PORT);
	if (listen(sock, 5) < 0)
		err(1, "listening for connections");

	return sock;
}

static struct domain *
find_dom0(void)
{
	int r;
	xc_dominfo_t info;
	struct domain *work;

	r = xc_domain_getinfo(xc_handle, 0, 1, &info);
	if (r < 0)
		err(1, "getting domain 0 information");
	work = xmalloc(sizeof(*work));
	work->control_evtchn = 2;
	if (ioctl(evtchn_fd, EVTCHN_BIND, 2) < 0)
		err(1, "binding to domain 0 control event channel");

	work->domid = 0;
	work->name = xstrdup("dom0");
	work->mem_kb = info.max_memkb;
	work->state = DOM_STATE_RUNNING;
	work->shared_info_mfn = info.shared_info_frame;

	work->shared_info = map_domain_mem(work, info.shared_info_frame);
	work->ctrl_if = (control_if_t *)((unsigned)work->shared_info + 2048);
	work->tx_req_cons = work->ctrl_if->tx_req_prod;
	work->rx_resp_cons = work->ctrl_if->rx_resp_prod;

	pthread_mutex_init(&work->mux, NULL);
	pthread_cond_init(&work->cond, NULL);

	list_insert_after(&work->domain_list, &head_domain);

	return work;
}

int
main(int argc, char *argv[])
{
	int r;

	r = our_system("/etc/xen/network start antispoof=no");
	if (r < 0)
		err(1, "running /etc/xen/network");
	if (!WIFEXITED(r)) {
		if (WIFSIGNALED(r)) {
			errx(1, "/etc/xen/network killed by signal %d",
			     WTERMSIG(r));
		}
		errx(1, "/etc/xen/network terminated abnormally");
	}
	if (WEXITSTATUS(r) != 0)
		errx(1, "/etc/xen/network returned error status %d",
		     WEXITSTATUS(r));

	xc_handle = xc_interface_open();

	listen_fd = start_listening();

	evtchn_fd = open("/dev/xen/evtchn", O_RDWR);
	if (evtchn_fd < 0)
		err(1, "openning /dev/xen/evtchn");

	dom0 = find_dom0();

	while (1) {
		get_and_process_event();

		PRINTF(5, "Dom0 ring state:\n");
		PRINTF(5, "RX: req_prod %ld, resp_prod %ld, resp_cons %ld\n",
		       dom0->ctrl_if->rx_req_prod,
		       dom0->ctrl_if->rx_resp_prod,
		       dom0->rx_resp_cons);
		PRINTF(5, "TX: req_prod %ld, resp_prod %ld, req_cons %ld\n",
		       dom0->ctrl_if->tx_req_prod,
		       dom0->ctrl_if->tx_resp_prod,
		       dom0->tx_req_cons);
	}

	return 0;
}

