#include <SDL.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/select.h>
#include <stdlib.h>
#include <linux/input.h>
#include <getopt.h>
#include <string.h>
#include "xenfb.h"

struct SDLFBData
{
	SDL_Surface *dst;
	SDL_Surface *src;
};

/*
 * Map from scancode to Linux input layer keycode.  Scancodes are
 * hardware-specific.  This map assumes a standard AT or PS/2
 * keyboard.
 *
 * Why use scancodes?  We can't use key symbols, because they don't
 * identify keys --- they're what keys are mapped to.  The standard
 * German keymap, for instance, maps both KEY_COMMA and KEY_102ND to
 * SDLK_LESS.
 */
static int keymap[256] = {
	[9] = KEY_ESC,
	[10] = KEY_1,
	[11] = KEY_2,
	[12] = KEY_3,
	[13] = KEY_4,
	[14] = KEY_5,
	[15] = KEY_6,
	[16] = KEY_7,
	[17] = KEY_8,
	[18] = KEY_9,
	[19] = KEY_0,
	[20] = KEY_MINUS,
	[21] = KEY_EQUAL,
	[22] = KEY_BACKSPACE,
	[23] = KEY_TAB,
	[24] = KEY_Q,
	[25] = KEY_W,
	[26] = KEY_E,
	[27] = KEY_R,
	[28] = KEY_T,
	[29] = KEY_Y,
	[30] = KEY_U,
	[31] = KEY_I,
	[32] = KEY_O,
	[33] = KEY_P,
	[34] = KEY_LEFTBRACE,
	[35] = KEY_RIGHTBRACE,
	[36] = KEY_ENTER,
	[37] = KEY_LEFTCTRL,
	[38] = KEY_A,
	[39] = KEY_S,
	[40] = KEY_D,
	[41] = KEY_F,
	[42] = KEY_G,
	[43] = KEY_H,
	[44] = KEY_J,
	[45] = KEY_K,
	[46] = KEY_L,
	[47] = KEY_SEMICOLON,
	[48] = KEY_APOSTROPHE,
	[49] = KEY_GRAVE,
	[50] = KEY_LEFTSHIFT,
	[51] = KEY_BACKSLASH,
	[52] = KEY_Z,
	[53] = KEY_X,
	[54] = KEY_C,
	[55] = KEY_V,
	[56] = KEY_B,
	[57] = KEY_N,
	[58] = KEY_M,
	[59] = KEY_COMMA,
	[60] = KEY_DOT,
	[61] = KEY_SLASH,
	[62] = KEY_RIGHTSHIFT,
	[63] = KEY_KPASTERISK,
	[64] = KEY_LEFTALT,
	[65] = KEY_SPACE,
	[66] = KEY_CAPSLOCK,
	[67] = KEY_F1,
	[68] = KEY_F2,
	[69] = KEY_F3,
	[70] = KEY_F4,
	[71] = KEY_F5,
	[72] = KEY_F6,
	[73] = KEY_F7,
	[74] = KEY_F8,
	[75] = KEY_F9,
	[76] = KEY_F10,
	[77] = KEY_NUMLOCK,
	[78] = KEY_SCROLLLOCK,
	[79] = KEY_KP7,
	[80] = KEY_KP8,
	[81] = KEY_KP9,
	[82] = KEY_KPMINUS,
	[83] = KEY_KP4,
	[84] = KEY_KP5,
	[85] = KEY_KP6,
	[86] = KEY_KPPLUS,
	[87] = KEY_KP1,
	[88] = KEY_KP2,
	[89] = KEY_KP3,
	[90] = KEY_KP0,
	[91] = KEY_KPDOT,
	[94] = KEY_102ND,	/* FIXME is this correct? */
	[95] = KEY_F11,
	[96] = KEY_F12,
	[108] = KEY_KPENTER,
	[109] = KEY_RIGHTCTRL,
	[112] = KEY_KPSLASH,
	[111] = KEY_SYSRQ,
	[113] = KEY_RIGHTALT,
	[97] = KEY_HOME,
	[98] = KEY_UP,
	[99] = KEY_PAGEUP,
	[100] = KEY_LEFT,
	[102] = KEY_RIGHT,
	[103] = KEY_END,
	[104] = KEY_DOWN,
	[105] = KEY_PAGEDOWN,
	[106] = KEY_INSERT,
	[107] = KEY_DELETE,
	[110] = KEY_PAUSE,
	[115] = KEY_LEFTMETA,
	[116] = KEY_RIGHTMETA,
	[117] = KEY_MENU,
};

static int btnmap[] = {
	[SDL_BUTTON_LEFT] = BTN_LEFT,
	[SDL_BUTTON_MIDDLE] = BTN_MIDDLE,
	[SDL_BUTTON_RIGHT] = BTN_RIGHT,
	/* FIXME not 100% sure about these: */
	[SDL_BUTTON_WHEELUP] = BTN_FORWARD,
	[SDL_BUTTON_WHEELDOWN] BTN_BACK
};

static void sdl_update(struct xenfb *xenfb, int x, int y, int width, int height)
{
	struct SDLFBData *data = xenfb->user_data;
	SDL_Rect r = { x, y, width, height };
	SDL_BlitSurface(data->src, &r, data->dst, &r);
	SDL_UpdateRect(data->dst, x, y, width, height);
}

static int sdl_on_event(struct xenfb *xenfb, SDL_Event *event)
{
	int x, y, ret;

	switch (event->type) {
	case SDL_KEYDOWN:
	case SDL_KEYUP:
		if (keymap[event->key.keysym.scancode] == 0)
			break;
		ret = xenfb_send_key(xenfb,
				     event->type == SDL_KEYDOWN,
				     keymap[event->key.keysym.scancode]);
		if (ret < 0)
			fprintf(stderr, "Key %d %s lost (%s)\n",
				keymap[event->key.keysym.scancode],
				event->type == SDL_KEYDOWN ? "down" : "up",
				strerror(errno));
		break;
	case SDL_MOUSEMOTION:
		if (xenfb->abs_pointer_wanted) {
			SDL_GetMouseState(&x, &y);
			ret = xenfb_send_position(xenfb, x, y);
		} else {
			SDL_GetRelativeMouseState(&x, &y);
			ret = xenfb_send_motion(xenfb, x, y);
		}
		if (ret < 0)
			fprintf(stderr, "Pointer to %d,%d lost (%s)\n",
				x, y, strerror(errno));
		break;
	case SDL_MOUSEBUTTONDOWN:
	case SDL_MOUSEBUTTONUP:
		if (event->button.button >= sizeof(btnmap) / sizeof(*btnmap))
			break;
		if (btnmap[event->button.button] == 0)
			break;
		ret = xenfb_send_key(xenfb,
				     event->type == SDL_MOUSEBUTTONDOWN,
				     btnmap[event->button.button]);
		if (ret < 0)
			fprintf(stderr, "Button %d %s lost (%s)\n",
				btnmap[event->button.button] - BTN_MOUSE,
				event->type == SDL_MOUSEBUTTONDOWN ? "down" : "up",
				strerror(errno));
		break;
	case SDL_QUIT:
		return 0;
	}

	return 1;
}

static struct option options[] = {
	{ "domid", 1, NULL, 'd' },
	{ "title", 1, NULL, 't' },
};

int main(int argc, char **argv)
{
	struct xenfb *xenfb;
	int domid = -1;
        char * title = NULL;
	fd_set readfds;
	int nfds;
	struct SDLFBData data;
	SDL_Rect r;
	struct timeval tv;
	SDL_Event event;
	int do_quit = 0;
	int opt;
	char *endp;

	while ((opt = getopt_long(argc, argv, "d:t:", options,
				  NULL)) != -1) {
		switch (opt) {
                case 'd':
			domid = strtol(optarg, &endp, 10);
			if (endp == optarg || *endp) {
				fprintf(stderr, "Invalid domain id specified\n");
				exit(1);
			}
			break;
                case 't':
			title = strdup(optarg);
			break;
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

	if (SDL_Init(SDL_INIT_VIDEO) < 0) {
		fprintf(stderr, "Could not initialize SDL\n");
		exit(1);
	}

	data.dst = SDL_SetVideoMode(xenfb->width, xenfb->height, xenfb->depth,
				    SDL_SWSURFACE);
	if (!data.dst) {
		fprintf(stderr, "SDL_SetVideoMode failed\n");
		exit(1);
	}

	data.src = SDL_CreateRGBSurfaceFrom(xenfb->pixels,
					    xenfb->width, xenfb->height,
					    xenfb->depth, xenfb->row_stride,
					    0xFF0000, 0xFF00, 0xFF, 0);

	if (!data.src) {
		fprintf(stderr, "SDL_CreateRGBSurfaceFrom failed\n");
		exit(1);
	}

        if (title == NULL)
		title = strdup("xen-sdlfb");
        SDL_WM_SetCaption(title, title);

	r.x = r.y = 0;
	r.w = xenfb->width;
	r.h = xenfb->height;
	SDL_BlitSurface(data.src, &r, data.dst, &r);
	SDL_UpdateRect(data.dst, 0, 0, xenfb->width, xenfb->height);

	xenfb->update = sdl_update;
	xenfb->user_data = &data;

	SDL_ShowCursor(0);

	/*
	 * We need to wait for fds becoming ready or SDL events to
	 * arrive.  We time out the select after 10ms to poll for SDL
	 * events.  Clunky, but works.  Could avoid the clunkiness
	 * with a separate thread.
	 */
	for (;;) {
		FD_ZERO(&readfds);
		nfds = xenfb_select_fds(xenfb, &readfds);
		tv = (struct timeval){0, 10000};

		if (select(nfds, &readfds, NULL, NULL, &tv) < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr,
				"Can't select() on event channel (%s)\n",
				strerror(errno));
			break;
		}

		while (SDL_PollEvent(&event)) {
			if (!sdl_on_event(xenfb, &event))
				do_quit = 1;
		}

                if (do_quit)
			break;

		xenfb_poll(xenfb, &readfds);
	}

	xenfb_delete(xenfb);

	SDL_Quit();

	return 0;
}
