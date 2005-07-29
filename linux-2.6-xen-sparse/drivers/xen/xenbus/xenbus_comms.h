/* Private include for xenbus communications. */
#ifndef _XENBUS_COMMS_H
#define _XENBUS_COMMS_H
int xs_init(void);
int xb_init_comms(void);

/* Low level routines. */
int xb_write(const void *data, unsigned len);
int xb_read(void *data, unsigned len);
int xs_input_avail(void);
extern wait_queue_head_t xb_waitq;

#endif /* _XENBUS_COMMS_H */
