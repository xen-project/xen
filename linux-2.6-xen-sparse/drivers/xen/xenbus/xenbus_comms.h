/* Private include for xenbus communications. */
#ifndef _XENBUS_COMMS_H
#define _XENBUS_COMMS_H
int xs_init(void);
int xb_init_comms(void **in, void **out);

/* Low level routines. */
struct ringbuf_head;
int xb_write(struct ringbuf_head *out, const void *data, unsigned len);
int xb_read(struct ringbuf_head *in, void *data, unsigned len);
int xs_input_avail(struct ringbuf_head *in);
extern wait_queue_head_t xb_waitq;

#endif /* _XENBUS_COMMS_H */
