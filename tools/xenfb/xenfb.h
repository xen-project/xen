#ifndef _XENFB_H_
#define _XENFB_H_

#include <stdbool.h>
#include <sys/types.h>

struct xenfb
{
	void *pixels;

	int row_stride;
	int depth;
	int width;
	int height;
	int abs_pointer_wanted;

	void *user_data;

	void (*update)(struct xenfb *xenfb, int x, int y, int width, int height);
};

struct xenfb *xenfb_new(void);
void xenfb_delete(struct xenfb *xenfb);
void xenfb_teardown(struct xenfb *xenfb);

int xenfb_attach_dom(struct xenfb *xenfb, int domid);

int xenfb_dispatch_store(struct xenfb *xenfb_pub);
int xenfb_dispatch_channel(struct xenfb *xenfb_pub);
int xenfb_select_fds(struct xenfb *xenfb, fd_set *readfds);
int xenfb_poll(struct xenfb *xenfb, fd_set *readfds);
int xenfb_get_store_fd(struct xenfb *xenfb_pub);
int xenfb_get_channel_fd(struct xenfb *xenfb_pub);

int xenfb_send_key(struct xenfb *xenfb, bool down, int keycode);
int xenfb_send_motion(struct xenfb *xenfb, int rel_x, int rel_y);
int xenfb_send_position(struct xenfb *xenfb, int abs_x, int abs_y);

#endif
