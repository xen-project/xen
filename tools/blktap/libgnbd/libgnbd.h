/* libgnbd.h
 *
 * gnbd client library
 *
 * Copyright (c) 2005, Christian Limpach
 */
     
#define GNBD_LOGIN_DONE		0x10001
#define GNBD_REQUEST_DONE	0x10002
#define GNBD_CONTINUE		0x10003
#define GNBD_CONTINUE_WRITE	0x10004

struct gnbd_handle;
int gnbd_close(struct gnbd_handle *);
int gnbd_fd(struct gnbd_handle *);
unsigned long gnbd_finished_request(struct gnbd_handle *);
int gnbd_kill_gserv(struct gnbd_handle *);
int gnbd_login(struct gnbd_handle *);
int gnbd_read(struct gnbd_handle *, uint64_t, ssize_t, unsigned char *,
    unsigned long);
int gnbd_write(struct gnbd_handle *, uint64_t, ssize_t, unsigned char *,
    unsigned long);
int gnbd_reply(struct gnbd_handle *);
uint64_t gnbd_sectors(struct gnbd_handle *);
struct gnbd_handle *gnbd_setup(char *, unsigned int, char *, char *);
