#ifndef MINIXEND_H__
#define MINIXEND_H__

#include <sys/types.h>
#include <xc.h>

struct list_head {
	struct list_head *next, **pprev;
};

struct open_connection {
	struct list_head connection_list;
	int fd;
	enum {
		OC_STATE_CONNECTED,
		OC_STATE_ERROR,
		OC_STATE_COMMAND_PENDING
	} state;

	/* Buffer of stuff coming from the remote until we get a whole
	   command */
	int buf_used;
	int buf_allocated;
	char *buf;
};

struct console_connection;

/* Only ever accessed from the domain's controlling thread, unless
   it's dom0, in which case we perform a moderately complex dance to
   avoid needing any sort of locking at all. */
struct domain {
	struct list_head domain_list;
	int control_evtchn; /* the local port for the doain control
			       interface event channel. */
	int domid;
	char *name;
	int mem_kb;
	enum {
		DOM_STATE_CREATED, /* created but not built */
		DOM_STATE_PAUSED,  /* built but not started or paused */
		DOM_STATE_RUNNING, /* running normally */
		DOM_STATE_DEAD     /* dead; either destroyed, crashed,
				      or exitted. */
	} state;

	unsigned long shared_info_mfn;
	shared_info_t *shared_info;
	control_if_t *ctrl_if;
	CONTROL_RING_IDX tx_req_cons;
	CONTROL_RING_IDX rx_resp_cons;

	unsigned created_netif_backend:1;
	unsigned plugged:1;
	unsigned event_pending:1; /* True if an event arrived while
				     the domain was plugged. */

	struct console_connection *cc;

	char netif_mac[6];

	/* Used for two purposes: waking up domain threads when
	   necessary, and synchronising access to dom0, which doesn't
	   have a domain thread. */
	pthread_mutex_t mux;
	pthread_cond_t cond;

	pthread_t thread;
};

struct console_connection {
	struct list_head list;
	int fd;
	struct domain *dom;

	enum {
		CC_STATE_PENDING,
		CC_STATE_CONNECTED,
		CC_STATE_ERROR
	} state;

	unsigned buf_allocated;
	unsigned buf_used;
	char *buf;

	unsigned in_buf_allocated;
	unsigned in_buf_used;
	char *in_buf;
};


void *domain_thread_func(void *d);
void process_command(struct open_connection *oc);

void *xmalloc(size_t s);
void *xrealloc(void *x, size_t s);
char *xstrdup(const char *s);

int allocate_event_channel(struct domain *d, int event_ports[2]);
void *map_domain_mem(struct domain *d, unsigned long mfn);
void signal_domain(struct domain *d);
int our_system(const char *fmt, ...);

extern unsigned xc_handle;
#define EVTCHN_BIND _IO('E', 2)
extern int evtchn_fd;

#define list_item(head, type, field)                                        \
((type *)((unsigned)(head) - offsetof(type, field)))

#define foreach_item(iter, head, type, field)                               \
for ((iter) = list_item((head)->next, type, field);                         \
     (iter) != list_item((head), type, field);                              \
     (iter) = list_item((iter)->field.next, type, field))

#define list_insert_after(what, head)                                       \
do {                                                                        \
	(what)->next = (head)->next;                                        \
	(what)->pprev = &(head)->next;                                      \
	(head)->next->pprev = &(what)->next;                                \
	(head)->next = what;                                                \
} while (0)

#define list_remove(head)                                                   \
(head)->next->pprev = (head)->pprev;                                        \
*(head)->pprev = (head)->next;

#define list_foreach_safe(head, li, temp)                                   \
for ((li) = (head)->next, (temp) = (li)->next;                              \
     (li) != (head);                                                        \
     (li) = (temp), (temp) = (li)->next)

#define LIST_HEAD(x) { (x), &(x)->next }


extern struct list_head head_domain;
extern struct list_head head_console;

#define foreach_domain(d)                                                   \
foreach_item(d, &head_domain, struct domain, domain_list)
#define foreach_console_connection(cc)                                      \
foreach_item(cc, &head_console, struct console_connection, list)


#define CURRENT_LOG_LEVEL 0

#define PRINTF(level, ...)                                         \
do {                                                               \
	if ((level) >= CURRENT_LOG_LEVEL)                          \
		printf(__VA_ARGS__);                               \
} while (0)


#endif /* MINIXEND_H__ */
