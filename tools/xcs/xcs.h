/* xcs.h
 *
 * public interfaces for the control interface switch (xcs).
 *
 * (c) 2004, Andrew Warfield
 *
 */


#ifndef __XCS_H__
#define __XCS_H__

#include <pthread.h>
#include <xc.h>
#include <xen/xen.h>
#include <xen/io/domain_controller.h>
#include <xen/linux/privcmd.h>
#include <sys/time.h>
#include "xcs_proto.h"

/* ------[ Debug macros ]--------------------------------------------------*/

#if 0
#define DPRINTF(_f, _a...) printf ( _f , ## _a )
#else
#define DPRINTF(_f, _a...) ((void)0)
#endif

/* ------[ XCS-specific defines and types ]--------------------------------*/

#define MAX_DOMS            1024
#define XCS_SESSION_TIMEOUT   10 /* (secs) disconnected session gc timeout */
#define XCS_UFD_TIMEOUT        5 /* how long can connections be unbound?   */
#define XCS_GC_INTERVAL        5 /* How often to run gc handlers.          */


/* ------[ Other required defines ]----------------------------------------*/

/* Size of a machine page frame. */
#define PAGE_SIZE 4096

#if defined(__i386__)
#define rmb() __asm__ __volatile__ ( "lock; addl $0,0(%%esp)" : : : "memory" )
#define wmb() __asm__ __volatile__ ( "" : : : "memory" )
#else
#error "Define barriers"
#endif

#ifndef timersub /* XOPEN and __BSD don't cooperate well... */
#define timersub(a, b, result)                                                \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;                          \
    if ((result)->tv_usec < 0) {                                              \
      --(result)->tv_sec;                                                     \
      (result)->tv_usec += 1000000;                                           \
    }                                                                         \
  } while (0)
#endif /*timersub*/

/* ------[ Bindings Interface ]--------------------------------------------*/

/*forward declare connection_t */
typedef struct connection_st connection_t;

typedef struct {
    int    port;
    u16    type;
} binding_key_t;

typedef struct binding_key_ent_st {
    binding_key_t              key;
    struct binding_key_ent_st *next;
} binding_key_ent_t;

#define BINDING_KEYS_EQUAL(_k1, _k2) \
    (((_k1)->port == (_k2)->port) && ((_k1)->type == (_k2)->type))

int  xcs_bind(connection_t *con, int port, u16 type);
int  xcs_unbind(connection_t *con, int port, u16 type);
void xcs_lookup(int port, u16 type, void (*f)(connection_t *, void *), 
        void *arg);
void init_bindings(void);

/* ------[ Connection Interface ]------------------------------------------*/

struct connection_st {
    unsigned long      id;              /* Unique session id             */
    int                ctrl_fd;         /* TCP descriptors               */
    int                data_fd;         /*                               */
    binding_key_ent_t *bindings;        /* List of bindings              */
    connection_t      *next;            /* Linked list of connections    */
    struct timeval     disconnect_time; /*  "            "               */
}; /* previously typedefed as connection_t */


extern connection_t *connection_list;

connection_t *get_con_by_session(unsigned long session_id);
connection_t *connection_new();
void connection_free(connection_t *con);
int  connection_add_binding(connection_t *con, binding_key_t *key);
int  connection_remove_binding(connection_t *con, binding_key_t *key);
int  connection_has_binding(connection_t *con, binding_key_t *key);
void gc_connection_list(void);

/* ------[ Control Channel Interfaces ]------------------------------------*/
 
typedef struct {
    int               connected;
    int               ref_count;
    int               type;
    u32               remote_dom;
    int               local_port;
    int               remote_port;
    control_if_t     *interface;
    ctrl_back_ring_t  tx_ring;
    ctrl_front_ring_t rx_ring;
    int               virq;
} control_channel_t;

/* cc types that we care about */
#define CC_TYPE_INTERDOMAIN  0
#define CC_TYPE_VIRQ         1

control_channel_t 
     *ctrl_chan_new(u32 dom, int local_port, int remote_port);
void  ctrl_chan_free(control_channel_t *cc);
int   ctrl_chan_init(void);
int   ctrl_chan_notify(control_channel_t *cc);
int   ctrl_chan_read_request(control_channel_t *cc, xcs_control_msg_t *);
int   ctrl_chan_write_request(control_channel_t *cc, 
                            xcs_control_msg_t *smsg);
int   ctrl_chan_read_response(control_channel_t *cc, xcs_control_msg_t *);
int   ctrl_chan_write_response(control_channel_t *cc, 
                             xcs_control_msg_t *smsg);
int   ctrl_chan_request_to_read(control_channel_t *cc);
int   ctrl_chan_space_to_write_request(control_channel_t *cc);
int   ctrl_chan_response_to_read(control_channel_t *cc);
int   ctrl_chan_space_to_write_response(control_channel_t *cc);
int   ctrl_chan_connect(control_channel_t *cc);
void  ctrl_chan_disconnect(control_channel_t *cc);
int   ctrl_chan_bind_virq(int virq, int *port);

/* ------[ Event notification interfaces ]---------------------------------*/


int   evtchn_open(void);
void  evtchn_close();
int   evtchn_bind(int idx);
int   evtchn_unbind(int idx);
void  evtchn_unmask(u16 idx);
int   evtchn_read();

#endif /* __XCS_H__ */
