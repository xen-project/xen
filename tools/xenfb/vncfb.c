#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <malloc.h>
#include <rfb/rfb.h>
#include <rfb/keysym.h>
#include <linux/input.h>
#include <xs.h>
#include "xenfb.h"

static int xk2linux[0x10000] = {
	[XK_a] = KEY_A,
	[XK_b] = KEY_B,
	[XK_c] = KEY_C,
	[XK_d] = KEY_D,
	[XK_e] = KEY_E,
	[XK_f] = KEY_F,
	[XK_g] = KEY_G,
	[XK_h] = KEY_H,
	[XK_i] = KEY_I,
	[XK_j] = KEY_J,
	[XK_k] = KEY_K,
	[XK_l] = KEY_L,
	[XK_m] = KEY_M,
	[XK_n] = KEY_N,
	[XK_o] = KEY_O,
	[XK_p] = KEY_P,
	[XK_q] = KEY_Q,
	[XK_r] = KEY_R,
	[XK_s] = KEY_S,
	[XK_t] = KEY_T,
	[XK_u] = KEY_U,
	[XK_v] = KEY_V,
	[XK_w] = KEY_W,
	[XK_x] = KEY_X,
	[XK_y] = KEY_Y,
	[XK_z] = KEY_Z,
	[XK_A] = KEY_A,
	[XK_B] = KEY_B,
	[XK_C] = KEY_C,
	[XK_D] = KEY_D,
	[XK_E] = KEY_E,
	[XK_F] = KEY_F,
	[XK_G] = KEY_G,
	[XK_H] = KEY_H,
	[XK_I] = KEY_I,
	[XK_J] = KEY_J,
	[XK_K] = KEY_K,
	[XK_L] = KEY_L,
	[XK_M] = KEY_M,
	[XK_N] = KEY_N,
	[XK_O] = KEY_O,
	[XK_P] = KEY_P,
	[XK_Q] = KEY_Q,
	[XK_R] = KEY_R,
	[XK_S] = KEY_S,
	[XK_T] = KEY_T,
	[XK_U] = KEY_U,
	[XK_V] = KEY_V,
	[XK_W] = KEY_W,
	[XK_X] = KEY_X,
	[XK_Y] = KEY_Y,
	[XK_Z] = KEY_Z,
	[XK_0] = KEY_0,
	[XK_1] = KEY_1,
	[XK_2] = KEY_2,
	[XK_3] = KEY_3,
	[XK_4] = KEY_4,
	[XK_5] = KEY_5,
	[XK_6] = KEY_6,
	[XK_7] = KEY_7,
	[XK_8] = KEY_8,
	[XK_9] = KEY_9,
	[XK_Return] = KEY_ENTER,
	[XK_BackSpace] = KEY_BACKSPACE,
	[XK_Tab] = KEY_TAB,
	[XK_Pause] = KEY_PAUSE,
	[XK_Delete] = KEY_DELETE,
	[XK_slash] = KEY_SLASH,
	[XK_minus] = KEY_MINUS,
	[XK_equal] = KEY_EQUAL,
	[XK_Escape] = KEY_ESC,
	[XK_braceleft] = KEY_LEFTBRACE,
	[XK_braceright] = KEY_RIGHTBRACE,
	[XK_bracketleft] = KEY_LEFTMETA,
	[XK_bracketright] = KEY_RIGHTMETA,
	[XK_Control_L] = KEY_LEFTCTRL,
	[XK_Control_R] = KEY_RIGHTCTRL,
	[XK_Shift_L] = KEY_LEFTSHIFT,
	[XK_Shift_R] = KEY_RIGHTSHIFT,
	[XK_Alt_L] = KEY_LEFTALT,
	[XK_Alt_R] = KEY_RIGHTALT,
	[XK_semicolon] = KEY_SEMICOLON, 
	[XK_apostrophe] = KEY_APOSTROPHE,
	[XK_grave] = KEY_GRAVE,
	[XK_backslash] = KEY_BACKSLASH,
	[XK_comma] = KEY_COMMA,
	[XK_period] = KEY_DOT,
	[XK_space] = KEY_SPACE,
	[XK_Caps_Lock] = KEY_CAPSLOCK,
	[XK_Num_Lock] = KEY_NUMLOCK,
	[XK_Scroll_Lock] = KEY_SCROLLLOCK,
	[XK_Sys_Req] = KEY_SYSRQ,
	[XK_Linefeed] = KEY_LINEFEED,
	[XK_Home] = KEY_HOME,
	[XK_Pause] = KEY_PAUSE,
	[XK_F1] = KEY_F1,
	[XK_F2] = KEY_F2,
	[XK_F3] = KEY_F3,
	[XK_F4] = KEY_F4,
	[XK_F5] = KEY_F5,
	[XK_F6] = KEY_F6,
	[XK_F7] = KEY_F7,
	[XK_F8] = KEY_F8,
	[XK_F9] = KEY_F9,
	[XK_F10] = KEY_F10,
	[XK_F11] = KEY_F11,
	[XK_F12] = KEY_F12,
	[XK_Up] = KEY_UP,
	[XK_Page_Up] = KEY_PAGEUP,
	[XK_Left] = KEY_LEFT,
	[XK_Right] = KEY_RIGHT,
	[XK_End] = KEY_END,
	[XK_Down] = KEY_DOWN,
	[XK_Page_Down] = KEY_PAGEDOWN,
	[XK_Insert] = KEY_INSERT, 
	[XK_colon] = KEY_SEMICOLON,
	[XK_quotedbl] = KEY_APOSTROPHE,
	[XK_less] = KEY_COMMA,
	[XK_greater] = KEY_DOT,
	[XK_question] = KEY_SLASH,
	[XK_bar] = KEY_BACKSLASH,
	[XK_asciitilde] = KEY_GRAVE,
	[XK_exclam] = KEY_1,
	[XK_at] = KEY_2,
	[XK_numbersign] = KEY_3,
	[XK_dollar] = KEY_4,
	[XK_percent] = KEY_5,
	[XK_asciicircum] = KEY_6,
	[XK_ampersand] = KEY_7,
	[XK_asterisk] = KEY_8,
	[XK_parenleft] = KEY_9,
	[XK_parenright] = KEY_0,
	[XK_underscore] = KEY_MINUS,
	[XK_plus] = KEY_EQUAL,
};

static int btnmap[] = {
	BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, BTN_FORWARD, BTN_BACK
};

static void on_kbd_event(rfbBool down, rfbKeySym keycode, rfbClientPtr cl)
{
	/*
	 * We need to map to the key's Linux input layer keycode.
	 * Unfortunately, we don't get the key here, only the
	 * rfbKeySym, which is what the key is mapped to.  Mapping
	 * back to the key is impossible in general, even when you
	 * know the keymap.  For instance, the standard German keymap
	 * maps both KEY_COMMA and KEY_102ND to XK_less.  We simply
	 * assume standard US layout.  This sucks.
	 */
	rfbScreenInfoPtr server = cl->screen;
	struct xenfb *xenfb = server->screenData;
	if (keycode >= sizeof(xk2linux) / sizeof(*xk2linux))
		return;
	if (xk2linux[keycode] == 0)
		return;
	if (xenfb_send_key(xenfb, down, xk2linux[keycode]) < 0)
		fprintf(stderr, "Key %d %s lost (%s)\n",
			xk2linux[keycode], down ? "down" : "up",
			strerror(errno));
}

static void on_ptr_event(int buttonMask, int x, int y, rfbClientPtr cl)
{
	/* initial pointer state: at (0,0), buttons up */
	static int last_x, last_y, last_button;
	rfbScreenInfoPtr server = cl->screen;
	struct xenfb *xenfb = server->screenData;
	int i, last_down, down, ret;

	for (i = 0; i < 8; i++) {
		last_down = last_button & (1 << i);
		down = buttonMask & (1 << i);
		if (down == last_down)
			continue;
		if (i >= sizeof(btnmap) / sizeof(*btnmap))
			break;
		if (btnmap[i] == 0)
			break;
		if (xenfb_send_key(xenfb, down != 0, btnmap[i]) < 0)
			fprintf(stderr, "Button %d %s lost (%s)\n",
				i, down ? "down" : "up", strerror(errno));
	}

	if (x != last_x || y != last_y) {
		if (xenfb->abs_pointer_wanted) 
			ret = xenfb_send_position(xenfb, x, y);
		else
			ret = xenfb_send_motion(xenfb, x - last_x, y - last_y);
		if (ret < 0)
			fprintf(stderr, "Pointer to %d,%d lost (%s)\n",
				x, y, strerror(errno));
	}

	last_button = buttonMask;
	last_x = x;
	last_y = y;
}

static void xenstore_write_vncport(struct xs_handle *xsh, int port, int domid)
{
	char *buf, *path;
	char portstr[10];

	path = xs_get_domain_path(xsh, domid);
	if (path == NULL) {
		fprintf(stderr, "Can't get domain path (%s)\n",
			strerror(errno));
		goto out;
	}

	if (asprintf(&buf, "%s/console/vnc-port", path) == -1) {
		fprintf(stderr, "Can't make vncport path\n");
		goto out;
	}

	if (snprintf(portstr, sizeof(portstr), "%d", port) == -1) {
		fprintf(stderr, "Can't make vncport value\n");
		goto out;
	}

	if (!xs_write(xsh, XBT_NULL, buf, portstr, strlen(portstr)))
		fprintf(stderr, "Can't set vncport (%s)\n",
			strerror(errno));

 out:
	free(buf);
}


static int xenstore_read_vncpasswd(struct xs_handle *xsh, int domid, char *pwbuf, int pwbuflen)
{
	char buf[256], *path, *uuid = NULL, *passwd = NULL;
	unsigned int len, rc = 0;

	if (xsh == NULL) {
		return -1;
	}

	path = xs_get_domain_path(xsh, domid);
	if (path == NULL) {
		fprintf(stderr, "xs_get_domain_path() error\n");
		return -1;
	}

	snprintf(buf, 256, "%s/vm", path);
	uuid = xs_read(xsh, XBT_NULL, buf, &len);
	if (uuid == NULL) {
		fprintf(stderr, "xs_read(): uuid get error\n");
		free(path);
		return -1;
	}

	snprintf(buf, 256, "%s/vncpasswd", uuid);
	passwd = xs_read(xsh, XBT_NULL, buf, &len);
	if (passwd == NULL) {
		free(uuid);
		free(path);
		return rc;
	}

	strncpy(pwbuf, passwd, pwbuflen-1);
	pwbuf[pwbuflen-1] = '\0';

	fprintf(stderr, "Got a VNC password read from XenStore\n");

	passwd[0] = '\0';
	snprintf(buf, 256, "%s/vncpasswd", uuid);
	if (xs_write(xsh, XBT_NULL, buf, passwd, len) == 0) {
		fprintf(stderr, "xs_write() vncpasswd failed\n");
		rc = -1;
	}

	free(passwd);
	free(uuid);
	free(path);

	return rc;
}

static void vnc_update(struct xenfb *xenfb, int x, int y, int w, int h)
{
	rfbScreenInfoPtr server = xenfb->user_data;
	rfbMarkRectAsModified(server, x, y, x + w, y + h);
}

static struct option options[] = {
	{ "domid", 1, NULL, 'd' },
	{ "vncport", 1, NULL, 'p' },
	{ "title", 1, NULL, 't' },
	{ "unused", 0, NULL, 'u' },
	{ "listen", 1, NULL, 'l' },
	{ NULL }
};

int main(int argc, char **argv)
{
	rfbScreenInfoPtr server;
	char *fake_argv[7] = { "vncfb", "-rfbport", "5901", 
                               "-desktop", "xen-vncfb", 
                               "-listen", "127.0.0.1" };
	int fake_argc = sizeof(fake_argv) / sizeof(fake_argv[0]);
	int domid = -1, port = -1;
	char *title = NULL;
	char *listen = NULL;
	bool unused = false;
	int opt;
	struct xenfb *xenfb;
	fd_set readfds;
	int nfds;
	char portstr[10];
	char *endp;
	int r;
	struct xs_handle *xsh;
	char vncpasswd[1024];

	vncpasswd[0] = '\0';

	while ((opt = getopt_long(argc, argv, "d:p:t:u", options,
				  NULL)) != -1) {
		switch (opt) {
                case 'd':
			errno = 0;
			domid = strtol(optarg, &endp, 10);
			if (endp == optarg || *endp || errno) {
				fprintf(stderr, "Invalid domain id specified\n");
				exit(1);
			}
			break;
                case 'p':
			errno = 0;
			port = strtol(optarg, &endp, 10);
			if (endp == optarg || *endp || errno) {
				fprintf(stderr, "Invalid port specified\n");
				exit(1);
			}
			break;
                case 't':
			title = strdup(optarg);
			break;
                case 'u':
			unused = true;
			break;
                case 'l':
			listen = strdup(optarg);
			break;
		case '?':
			exit(1);
                }
        }
        if (optind != argc) {
		fprintf(stderr, "Invalid options!\n");
		exit(1);
        }
        if (domid <= 0) {
		fprintf(stderr, "Domain ID must be specified!\n");
		exit(1);
        }
            
        if (port <= 0)
		port = 5900 + domid;
	if (snprintf(portstr, sizeof(portstr), "%d", port) == -1) {
		fprintf(stderr, "Invalid port specified\n");
		exit(1);
        }
            
	fake_argv[2] = portstr;

        if (title != NULL)
		fake_argv[4] = title;

        if (listen != NULL)
		fake_argv[6] = listen;

	signal(SIGPIPE, SIG_IGN);

	xenfb = xenfb_new();
	if (xenfb == NULL) {
		fprintf(stderr, "Could not create framebuffer (%s)\n",
			strerror(errno));
		exit(1);
	}

	if (xenfb_attach_dom(xenfb, domid) < 0) {
		fprintf(stderr, "Could not connect to domain (%s)\n",
			strerror(errno));
		exit(1);
	}

	xsh = xs_daemon_open();
	if (xsh == NULL) {
	        fprintf(stderr, "cannot open connection to xenstore\n");
		exit(1);
	}


	if (xenstore_read_vncpasswd(xsh, domid, vncpasswd, sizeof(vncpasswd)/sizeof(char)) < 0) {
		fprintf(stderr, "cannot read VNC password from xenstore\n");
		exit(1);
	}
	  

	server = rfbGetScreen(&fake_argc, fake_argv, 
			      xenfb->width, xenfb->height,
			      8, 3, xenfb->depth / 8);
	if (server == NULL) {
		fprintf(stderr, "Could not create VNC server\n");
		exit(1);
	}

	xenfb->user_data = server;
	xenfb->update = vnc_update;

        if (unused)
		server->autoPort = true;

	if (vncpasswd[0]) {
		char **passwds = malloc(sizeof(char**)*2);
		if (!passwds) {
			fprintf(stderr, "cannot allocate memory (%s)\n", strerror(errno));
			exit(1);
		}
		fprintf(stderr, "Registered password\n");
		passwds[0] = vncpasswd;
		passwds[1] = NULL;

		server->authPasswdData = passwds;
		server->passwordCheck = rfbCheckPasswordByList;
	} else {
		fprintf(stderr, "Running with no password\n");
	}
	server->serverFormat.redShift = 16;
	server->serverFormat.greenShift = 8;
	server->serverFormat.blueShift = 0;
	server->kbdAddEvent = on_kbd_event;
	server->ptrAddEvent = on_ptr_event;
	server->frameBuffer = xenfb->pixels;
	server->screenData = xenfb;
	server->cursor = NULL;
	rfbInitServer(server);

	rfbRunEventLoop(server, -1, true);

        xenstore_write_vncport(xsh, server->port, domid);

	for (;;) {
		FD_ZERO(&readfds);
		nfds = xenfb_select_fds(xenfb, &readfds);

		if (select(nfds, &readfds, NULL, NULL, NULL) < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr,
				"Can't select() on event channel (%s)\n",
				strerror(errno));
			break;
		}

		r = xenfb_poll(xenfb, &readfds);
		if (r == -2)
		    xenfb_teardown(xenfb);
		if (r < 0)
		    break;
	}

	rfbScreenCleanup(server);
	xenfb_delete(xenfb);

	return 0;
}
