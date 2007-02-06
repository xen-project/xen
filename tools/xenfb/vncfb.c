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

/* Grab key translation support routines from qemu directory. */
#define qemu_mallocz(size) calloc(1, (size))
static const char *bios_dir = "/usr/share/xen/qemu";
#include "vnc_keysym.h"
#include "keymaps.c"

static unsigned char atkbd_set2_keycode[512] = {

	  0, 67, 65, 63, 61, 59, 60, 88,  0, 68, 66, 64, 62, 15, 41,117,
	  0, 56, 42, 93, 29, 16,  2,  0,  0,  0, 44, 31, 30, 17,  3,  0,
	  0, 46, 45, 32, 18,  5,  4, 95,  0, 57, 47, 33, 20, 19,  6,183,
	  0, 49, 48, 35, 34, 21,  7,184,  0,  0, 50, 36, 22,  8,  9,185,
	  0, 51, 37, 23, 24, 11, 10,  0,  0, 52, 53, 38, 39, 25, 12,  0,
	  0, 89, 40,  0, 26, 13,  0,  0, 58, 54, 28, 27,  0, 43,  0, 85,
	  0, 86, 91, 90, 92,  0, 14, 94,  0, 79,124, 75, 71,121,  0,  0,
	 82, 83, 80, 76, 77, 72,  1, 69, 87, 78, 81, 74, 55, 73, 70, 99,

	  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
	217,100,255,  0, 97,165,  0,  0,156,  0,  0,  0,  0,  0,  0,125,
	173,114,  0,113,  0,  0,  0,126,128,  0,  0,140,  0,  0,  0,127,
	159,  0,115,  0,164,  0,  0,116,158,  0,150,166,  0,  0,  0,142,
	157,  0,  0,  0,  0,  0,  0,  0,155,  0, 98,  0,  0,163,  0,  0,
	226,  0,  0,  0,  0,  0,  0,  0,  0,255, 96,  0,  0,  0,143,  0,
	  0,  0,  0,  0,  0,  0,  0,  0,  0,107,  0,105,102,  0,  0,112,
	110,111,108,112,106,103,  0,119,  0,118,109,  0, 99,104,119,  0,

};

static unsigned char atkbd_unxlate_table[128] = {

	  0,118, 22, 30, 38, 37, 46, 54, 61, 62, 70, 69, 78, 85,102, 13,
	 21, 29, 36, 45, 44, 53, 60, 67, 68, 77, 84, 91, 90, 20, 28, 27,
	 35, 43, 52, 51, 59, 66, 75, 76, 82, 14, 18, 93, 26, 34, 33, 42,
	 50, 49, 58, 65, 73, 74, 89,124, 17, 41, 88,  5,  6,  4, 12,  3,
	 11,  2, 10,  1,  9,119,126,108,117,125,123,107,115,116,121,105,
	114,122,112,113,127, 96, 97,120,  7, 15, 23, 31, 39, 47, 55, 63,
	 71, 79, 86, 94,  8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 87,111,
	 19, 25, 57, 81, 83, 92, 95, 98, 99,100,101,103,104,106,109,110

};

unsigned char keycode_table[512];

static void *kbd_layout;

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

	if( keycode >= 'A' && keycode <= 'Z' )
		keycode += 'a' - 'A';

	int scancode = keycode_table[keysym2scancode(kbd_layout, keycode)];
	if (scancode == 0)
		return;
	if (xenfb_send_key(xenfb, down, scancode) < 0)
		fprintf(stderr, "Key %d %s lost (%s)\n",
			scancode, down ? "down" : "up",
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
	{ "keymap", 1, NULL, 'k' },
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
	char *keymap = NULL;
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
	int i;

	vncpasswd[0] = '\0';

	while ((opt = getopt_long(argc, argv, "d:p:t:uk:", options,
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
                case 'k':
			keymap = strdup(optarg);
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

	if (keymap == NULL){
		keymap = "en-us";
	}

	kbd_layout = init_keyboard_layout(keymap);
	if( !kbd_layout ){
		fprintf(stderr, "Invalid keyboard_layout\n");
		exit(1);
        }

	for (i = 0; i < 128; i++) {
		keycode_table[i] = atkbd_set2_keycode[atkbd_unxlate_table[i]];
		keycode_table[i | 0x80] = 
			atkbd_set2_keycode[atkbd_unxlate_table[i] | 0x80];
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


	if (xenstore_read_vncpasswd(xsh, domid, vncpasswd,
				    sizeof(vncpasswd)/sizeof(char)) < 0) {
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
			fprintf(stderr, "cannot allocate memory (%s)\n",
				strerror(errno));
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
