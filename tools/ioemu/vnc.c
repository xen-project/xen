/*
 * QEMU VNC display driver (uses LibVNCServer, based on QEMU SDL driver)
 * 
 * Copyright (c) 2003,2004 Fabrice Bellard, Matthew Mastracci,
 * Johannes E. Schindelin
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 *
 * reverse connection setup copied from x11vnc.c
 * Copyright (c) 2002-2005 Karl J. Runge <runge@karlrunge.com>
 * All rights reserved.
 * based on:
 *       the originial x11vnc.c in libvncserver (Johannes E. Schindelin)
 *       x0rfbserver, the original native X vnc server (Jens Wagner)
 *       krfb, the KDE desktopsharing project (Tim Jansen)
 */
#include "vl.h"

#include <rfb/rfb.h>

/* keyboard stuff */
#include <rfb/keysym.h>
#include "keysym_adapter_vnc.h"
#include "keyboard_rdesktop.c"


#ifndef _WIN32
#include <signal.h>
#endif

static rfbScreenInfoPtr screen;
static DisplayState* ds_sdl=0;
static void* kbd_layout=0; // TODO: move into rfbClient

/* mouse stuff */

typedef struct mouse_magic_t {
	/* When calibrating, mouse_calibration contains a copy of the 
	 * current frame buffer. After a simulated mouse movement, the
	 * update function only gets (0,y1,width,y2) as bounding box 
	 * of the changed region, so we refine that with the help of
	 * this copy, and then update the copy. */
	char* calibration;
	/* Mouse handling using VNC used to be wrong, because if moving the
	 * mouse very fast, the pointer got even faster. The reason for this:
	 * when the mouse sends a delta of at least 4 (Windows: 3) pixels, 
	 * it is treated as if it were double the amount. I call this the
	 * sonic wall. */
	int sonic_wall_x;
	int sonic_wall_y;
	/* Unfortunately, Windows and X behave differently, when the sonic
	 * wall was reached in one axis, but not the other: Windows treats
	 * them independently. I call this orthogonal. */
	char sonic_wall_is_orthogonal;
	/* last_dy contains the last delta sent on the y axis. We don't
	 * use the x axis (see mouse_calibration). */
	//static int last_dy=0;
} mouse_magic_t;

mouse_magic_t* init_mouse_magic() {
	mouse_magic_t* ret=(mouse_magic_t*)malloc(sizeof(mouse_magic_t));

	ret->calibration=0;
#ifdef EXPECT_WINDOWS_GUEST
	ret->sonic_wall_x=3;
	ret->sonic_wall_y=3;
	ret->sonic_wall_is_orthogonal=1;
#else
	ret->sonic_wall_x=4;
	ret->sonic_wall_y=4;
	ret->sonic_wall_is_orthogonal=0;
#endif
	return ret;
}

static void vnc_save(QEMUFile* f,void* opaque)
{
	mouse_magic_t* s=(mouse_magic_t*)opaque;

	qemu_put_be32s(f, &s->sonic_wall_x);
	qemu_put_be32s(f, &s->sonic_wall_y);
	qemu_put_8s(f, &s->sonic_wall_is_orthogonal);
}

static int vnc_load(QEMUFile* f,void* opaque,int version_id)
{
	mouse_magic_t* s=(mouse_magic_t*)opaque;

	if (version_id != 1)
		return -EINVAL;

	qemu_get_be32s(f, &s->sonic_wall_x);
	qemu_get_be32s(f, &s->sonic_wall_y);
	qemu_get_8s(f, &s->sonic_wall_is_orthogonal);

	return 0;
}

static mouse_magic_t* mouse_magic;

typedef struct {
	int x,y,w,h;
} rectangle_t;
/* In order to calibrate the mouse, we have to know about the bounding boxes
 * of the last changes. */
static rectangle_t last_update, before_update;
static int updates_since_mouse=0;

static int mouse_x,mouse_y;
static int new_mouse_x,new_mouse_y,new_mouse_z,new_mouse_buttons;

static void init_mouse(int initial_x,int initial_y) {
	mouse_x=new_mouse_x=initial_x;
	mouse_y=new_mouse_y=initial_y;
	new_mouse_z=new_mouse_buttons=0;
	mouse_magic->calibration = 0;
}

static void mouse_refresh() {
	int dx=0,dy=0,dz=new_mouse_z;
	static int counter=1;

	counter++;
	if(!mouse_magic->calibration && counter>=2) { counter=0; return; }

	dx=new_mouse_x-mouse_x;
	dy=new_mouse_y-mouse_y;

	if(mouse_magic->sonic_wall_is_orthogonal) {
		if(abs(dx)>=mouse_magic->sonic_wall_x) { dx/=2; mouse_x+=dx; }
		if(abs(dy)>=mouse_magic->sonic_wall_y) { dy/=2; mouse_y+=dy; }
	} else {
		if(abs(dx)>=mouse_magic->sonic_wall_x || abs(dy)>=mouse_magic->sonic_wall_y) {
			dx/=2; mouse_x+=dx;
			dy/=2; mouse_y+=dy;
		}
	}
	//fprintf(stderr,"sending mouse event %d,%d\n",dx,dy);
	kbd_mouse_event(dx,dy,dz,new_mouse_buttons);
	mouse_x+=dx;
	mouse_y+=dy;
		
	updates_since_mouse=0;
}

static int calibration_step=0;
//static int calibration_count=0;

static void mouse_find_bounding_box_of_difference(int* x,int* y,int* w,int* h) {
	int i,j,X=*x,Y=*y,W=*w,H=*h;
	int bpp=screen->depth/8;

	*x=screen->width; *w=-*x;
	*y=screen->height; *h=-*y;
	for(i=X;i<X+W;i++)
		for(j=Y;j<Y+H;j++) {
			int offset=i*bpp+j*screen->paddedWidthInBytes;
			if(memcmp(mouse_magic->calibration+offset,screen->frameBuffer+offset,bpp)) {
				if(i<((*x))) { (*w)+=(*x)-i; (*x)=i; }
				if(i>(*x)+(*w)) (*w)=i-(*x);
				if(j<(*y)) { (*h)+=(*y)-j; (*y)=j; }
				if(j>(*y)+(*h)) (*h)=j-(*y); 
			}
		}
	if(h>0)
		memcpy(mouse_magic->calibration+Y*screen->paddedWidthInBytes,
				screen->frameBuffer+Y*screen->paddedWidthInBytes,
				H*screen->paddedWidthInBytes);
}

static void start_mouse_calibration() {
	int size = screen->height*screen->paddedWidthInBytes;
	free(mouse_magic->calibration);
	mouse_magic->calibration = malloc(size);
	memcpy(mouse_magic->calibration, screen->frameBuffer, size);
	calibration_step=0;
	// calibration_count=-1;
	//calibration_count=1000; updates_since_mouse=1;
	fprintf(stderr,"Starting mouse calibration:\n");
}

static void stop_mouse_calibration() {
	free(mouse_magic->calibration);
	mouse_magic->calibration = 0;
}

static void mouse_calibration_update(int x,int y,int w,int h) {
	mouse_find_bounding_box_of_difference(&x,&y,&w,&h);
	if(w<=0 || h<=0)
		return;
	last_update.x=x;
	last_update.y=y;
	last_update.w=w;
	last_update.h=h;
	updates_since_mouse++;
}

static void mouse_calibration_refresh() {
	static rectangle_t cursor;
	static int x,y;
	static int idle_counter;

	if(calibration_step==0)
		idle_counter=0;
	else {
		if(updates_since_mouse==0) {
			idle_counter++;
			if(idle_counter>5) {
				fprintf(stderr, "Calibration failed: no update for 5 cycles\n");
				stop_mouse_calibration();
			}
			return;
		}
		if(updates_since_mouse!=1) {
			fprintf(stderr,"Calibration failed: updates=%d\n",updates_since_mouse);
			stop_mouse_calibration();
			return;
		}
	}
	
	if(calibration_step==0) {
		x=0; y=1;
		kbd_mouse_event(0,-1,0,0);
		calibration_step++;
	} else if(calibration_step==1) {
		// find out the initial position of the cursor
		cursor=last_update;
		cursor.h--;
		calibration_step++;
		mouse_magic->sonic_wall_y=-1;
		last_update=cursor;
		x=0; y=2;
		goto move_calibrate;
	} else if(calibration_step==2) {
		// find out the sonic_wall
		if(last_update.y==before_update.y-2*y) {
			mouse_magic->sonic_wall_y=y;
			// test orthogonality
			calibration_step++;
			x=mouse_magic->sonic_wall_y+1; y=1;
			goto move_calibrate;
		} else if(last_update.y<=2) {
			if(y<6)
				fprintf(stderr,"Calibration failed: not enough head room!\n");
			else
				fprintf(stderr,"Calibration finished.\n");
			mouse_magic->sonic_wall_x=mouse_magic->sonic_wall_y=32768;
			goto stop_calibration;
		} else if(last_update.y!=before_update.y-y) {
			fprintf(stderr,"Calibration failed: delta=%d (expected: %d)\n",last_update.y-before_update.y,-y);
			goto stop_calibration;
		} else {
			y++;
move_calibrate:
			kbd_mouse_event(-x,-y,0,0);
			before_update=last_update;
		}
	} else if(calibration_step==3) {
		if(last_update.y==before_update.y-2)
			mouse_magic->sonic_wall_is_orthogonal=0;
		else if(last_update.y==before_update.y-1)
			mouse_magic->sonic_wall_is_orthogonal=-1;
		else
			fprintf(stderr,"Calibration failed: no clue of orthogonal.\n");
		mouse_magic->sonic_wall_x=mouse_magic->sonic_wall_y;
		if(last_update.x==before_update.x-mouse_magic->sonic_wall_x)
			mouse_magic->sonic_wall_x++;
		else if(last_update.x!=before_update.x-x*2)
			fprintf(stderr,"Calibration failed: could not determine horizontal sonic wall x\n");
		fprintf(stderr,"Calibration finished\n");
stop_calibration:
		mouse_x=last_update.x;
		mouse_y=last_update.y;
		stop_mouse_calibration();
	}
	updates_since_mouse=0;
}

/* end of mouse stuff */

static void vnc_update(DisplayState *ds, int x, int y, int w, int h)
{
	if(ds_sdl)
		ds_sdl->dpy_update(ds_sdl,x,y,w,h);
	if(0) fprintf(stderr,"updating x=%d y=%d w=%d h=%d\n", x, y, w, h);
	rfbMarkRectAsModified(screen,x,y,x+w,y+h);
	if(mouse_magic->calibration) {
		mouse_calibration_update(x,y,w,h);
	}
}

#include <SDL/SDL_video.h>
extern SDL_PixelFormat* sdl_get_format();

static void vnc_resize(DisplayState *ds, int w, int h)
{
	int depth = screen->bitsPerPixel;
	rfbClientIteratorPtr iter;
	rfbClientPtr cl;

	if(w==screen->width && h==screen->height)
		return;

	if(ds_sdl) {
		SDL_PixelFormat* sdl_format;
		ds_sdl->dpy_resize(ds_sdl,w,h);
		ds->data = ds_sdl->data;
		ds->linesize = screen->paddedWidthInBytes = ds_sdl->linesize;
		screen->serverFormat.bitsPerPixel = screen->serverFormat.depth
			= screen->bitsPerPixel = depth = ds->depth = ds_sdl->depth;
		w = ds->width = ds_sdl->width;
		h = ds->height = ds_sdl->height;
		sdl_format=sdl_get_format();
		if(sdl_format->palette==0) {
			screen->serverFormat.trueColour=TRUE;
			screen->serverFormat.redShift=sdl_format->Rshift;
			screen->serverFormat.greenShift=sdl_format->Gshift;
			screen->serverFormat.blueShift=sdl_format->Bshift;
			screen->serverFormat.redMax=sdl_format->Rmask>>screen->serverFormat.redShift;
			screen->serverFormat.greenMax=sdl_format->Gmask>>screen->serverFormat.greenShift;
			screen->serverFormat.blueMax=sdl_format->Bmask>>screen->serverFormat.blueShift;
		} else {
			rfbColourMap* cmap=&(screen->colourMap);
			int i;
			screen->serverFormat.trueColour=FALSE;
			cmap->is16=FALSE;
			cmap->count=sdl_format->palette->ncolors;
			if(cmap->data.bytes==0)
				cmap->data.bytes=malloc(256*3);
			for(i=0;i<cmap->count;i++) {
				cmap->data.bytes[3*i+0]=sdl_format->palette->colors[i].r;
				cmap->data.bytes[3*i+1]=sdl_format->palette->colors[i].g;
				cmap->data.bytes[3*i+2]=sdl_format->palette->colors[i].b;
			}
		}
	} else {
		ds->data = (unsigned char*)realloc(ds->data, w*h*depth/8);
		ds->linesize = screen->paddedWidthInBytes = w*2;
		ds->width = w;
		ds->height = h;
		ds->depth = depth;
		screen->paddedWidthInBytes = w*depth/8;
	}
	screen->frameBuffer = ds->data;

	screen->width = w;
	screen->height = h;

	iter=rfbGetClientIterator(screen);
	while((cl=rfbClientIteratorNext(iter)))
		if(cl->useNewFBSize)
			cl->newFBSizePending = TRUE;
		else
			rfbLog("Warning: Client %s does not support NewFBSize!\n",cl->host);
	rfbReleaseClientIterator(iter);

	if(mouse_magic->calibration) {
		fprintf(stderr,"Warning: mouse calibration interrupted by video mode change\n");
		stop_mouse_calibration();
	}
	init_mouse(w/2,h/2);
}

static void vnc_process_key(rfbBool down, rfbKeySym keySym, rfbClientPtr cl)
{
	static int magic=0; // Ctrl+Alt starts calibration

	if(is_active_console(vga_console)) {
		WORD keycode=keysym2scancode(kbd_layout, keySym);
		if(keycode>=0x80)
			keycode=(keycode<<8)^0x80e0;
		while(keycode!=0) {
			kbd_put_keycode((keycode&0xff)|(down?0:0x80));
			keycode>>=8;
		}
	} else if(down) {
            int qemu_keysym = 0;
            if (keySym <= 128) { /* normal ascii */
                qemu_keysym = keySym;
            } else {
                switch(keySym) {
                    case XK_Up: qemu_keysym = QEMU_KEY_UP; break;
                    case XK_Down: qemu_keysym = QEMU_KEY_DOWN; break;
                    case XK_Left: qemu_keysym = QEMU_KEY_LEFT; break;
                    case XK_Right: qemu_keysym = QEMU_KEY_RIGHT; break;
                    case XK_Home: qemu_keysym = QEMU_KEY_HOME; break;
                    case XK_End: qemu_keysym = QEMU_KEY_END; break;
                    case XK_Page_Up: qemu_keysym = QEMU_KEY_PAGEUP; break;
                    case XK_Page_Down: qemu_keysym = QEMU_KEY_PAGEDOWN; break;
                    case XK_BackSpace: qemu_keysym = QEMU_KEY_BACKSPACE; break;
                    case XK_Delete: qemu_keysym = QEMU_KEY_DELETE; break;
                    case XK_Return:
                    case XK_Linefeed: qemu_keysym = keySym; break;
                    default: break;
                }
            }
            if (qemu_keysym != 0)
                kbd_put_keysym(qemu_keysym);
	}
	if(down) {
		if(keySym==XK_Control_L)
			magic|=1;
		else if(keySym==XK_Alt_L)
			magic|=2;
	} else {
		if((magic&3)==3) {
			switch(keySym) {
				case XK_Control_L:
					magic&=~1;
					break;
				case XK_Alt_L:
					magic&=~2;
					break;
				case XK_m:
					magic=0;
					start_mouse_calibration();
					break;
				case XK_1 ... XK_9:
					magic=0;
					fprintf(stderr,"switch to %d\n",keySym-XK_1);
					console_select(keySym - XK_1);
					if (is_active_console(vga_console)) {
						/* tell the vga console to redisplay itself */
						vga_invalidate_display();
						vnc_update(0,0,0,screen->width,screen->height);
					}
					break;
			}
		}
	}
}

static void vnc_process_mouse(int buttonMask, int x, int y, rfbClientPtr cl)
{
	new_mouse_x=x; new_mouse_y=y; new_mouse_buttons=0;
	if(buttonMask&1) new_mouse_buttons|=MOUSE_EVENT_LBUTTON;
	if(buttonMask&2) new_mouse_buttons|=MOUSE_EVENT_MBUTTON;
	if(buttonMask&4) new_mouse_buttons|=MOUSE_EVENT_RBUTTON;
	if(buttonMask&8) new_mouse_z--;
	if(buttonMask&16) new_mouse_z++;
}

	static void vnc_refresh(DisplayState *ds) {
		if(ds_sdl)
			ds_sdl->dpy_refresh(ds_sdl);
		else
			vga_update_display();
		rfbProcessEvents(screen,0);
		if(mouse_magic->calibration) {
			mouse_calibration_refresh();
		} else {
			mouse_refresh();
		}
	}

static void vnc_cleanup(void) 
{
	rfbScreenCleanup(screen);
}


void vnc_display_init(DisplayState *ds, int useAlsoSDL,
                      long port, const char* connect)
{
    int   len, rport = 5500;
    char  host[1024];
    char *p;
    rfbClientPtr cl;
    
	if(!keyboard_layout) {
		fprintf(stderr, "No keyboard language specified\n");
		exit(1);
	}

	kbd_layout=init_keyboard_layout(keyboard_layout);
	if(!kbd_layout) {
		fprintf(stderr, "Could not initialize keyboard\n");
		exit(1);
	}


	mouse_magic=init_mouse_magic();
	register_savevm("vnc", 0, 1, vnc_save, vnc_load, mouse_magic);

	rfbLog=rfbErr=term_printf;
	screen=rfbGetScreen(0,0,0,0,5,3,2);
	if(screen==0) {
		fprintf(stderr, "Could not initialize VNC - exiting\n");
		exit(1);
	}


	screen->serverFormat.redShift = 11;
	screen->serverFormat.greenShift = 5;
	screen->serverFormat.blueShift = 0;
	screen->serverFormat.redMax = 31;
	screen->serverFormat.greenMax = 63;
	screen->serverFormat.blueMax = 31;

    if (port != 0) 
        screen->port = port;
    else
        screen->autoPort = TRUE;

	if(useAlsoSDL) {
		ds_sdl=(DisplayState*)malloc(sizeof(DisplayState));
		sdl_display_init(ds_sdl,0);
		screen->frameBuffer = ds_sdl->data;
	} else
		screen->frameBuffer = malloc(640*400*2);

	screen->desktopName = domain_name;
	screen->cursor = 0;
	screen->kbdAddEvent = vnc_process_key;
	screen->ptrAddEvent = vnc_process_mouse;
	rfbInitServer(screen);

	vnc_resize(ds,640,400);

	ds->dpy_update = vnc_update;
	ds->dpy_resize = vnc_resize;
	ds->dpy_refresh = vnc_refresh;

    /* deal with reverse connections */
    if ( connect == NULL || (len = strlen(connect)) < 1) {
        return;
    }
    if ( len > 1024 ) {
        fprintf(stderr, "vnc reverse connect name too long\n");
		exit(1);
    }
    strncpy(host, connect, len);
    host[len] = '\0';
    /* extract port, if any */
    if ((p = strchr(host, ':')) != NULL) {
        rport = atoi(p+1);
        *p = '\0';
    }
    cl = rfbReverseConnection(screen, host, rport);
    if (cl == NULL) {
        fprintf(stderr, "reverse_connect: %s failed\n", connect);
    } else {
        fprintf(stderr, "reverse_connect: %s/%s OK\n", connect, cl->host);
    }

	atexit(vnc_cleanup);



}

