/*
 * QEMU SDL display driver
 * 
 * Copyright (c) 2003 Fabrice Bellard
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
 */
#include "vl.h"

#include <SDL.h>

#ifndef _WIN32
#include <signal.h>
#endif

#ifdef CONFIG_OPENGL
#include <SDL_opengl.h>
#endif

static SDL_Surface *screen;
static SDL_Surface *shared = NULL;
static int gui_grab; /* if true, all keyboard/mouse events are grabbed */
static int last_vm_running;
static int gui_saved_grab;
static int gui_fullscreen;
static int gui_key_modifier_pressed;
static int gui_keysym;
static int gui_fullscreen_initial_grab;
static int gui_grab_code = KMOD_LALT | KMOD_LCTRL;
static uint8_t modifiers_state[256];
static int width, height;
static SDL_Cursor *sdl_cursor_normal;
static SDL_Cursor *sdl_cursor_hidden;
static int absolute_enabled = 0;
static int opengl_enabled;

#ifdef CONFIG_OPENGL
static GLint tex_format;
static GLint tex_type;
static GLuint texture_ref = 0;
static GLint gl_format;

static void opengl_setdata(DisplayState *ds, void *pixels)
{
    glEnable(GL_TEXTURE_RECTANGLE_ARB);
    glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_REPLACE);
    glClearColor(0, 0, 0, 0);
    glDisable(GL_BLEND);
    glDisable(GL_LIGHTING);
    glDisable(GL_DEPTH_TEST);
    glDepthMask(GL_FALSE);
    glDisable(GL_CULL_FACE);
    glViewport( 0, 0, screen->w, screen->h);
    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();
    glOrtho(0, screen->w, screen->h, 0, -1,1);
    glMatrixMode(GL_MODELVIEW);
    glLoadIdentity();
    glClear(GL_COLOR_BUFFER_BIT);
    ds->data = pixels;

    if (texture_ref) {
        glDeleteTextures(1, &texture_ref);
        texture_ref = 0;
    }

    glGenTextures(1, &texture_ref);
    glBindTexture(GL_TEXTURE_RECTANGLE_ARB, texture_ref);
    glPixelStorei(GL_UNPACK_LSB_FIRST, 1);
    switch (ds->depth) {
        case 8:
            tex_format = GL_RGB;
            tex_type = GL_UNSIGNED_BYTE_3_3_2;
            glPixelStorei (GL_UNPACK_ALIGNMENT, 1);
            break;
        case 16:
            tex_format = GL_RGB;
            tex_type = GL_UNSIGNED_SHORT_5_6_5;
            glPixelStorei (GL_UNPACK_ALIGNMENT, 2);
            break;
        case 24:
            tex_format = GL_BGR;
            tex_type = GL_UNSIGNED_BYTE;
            glPixelStorei (GL_UNPACK_ALIGNMENT, 1);
            break;
        case 32:
            if (!ds->bgr) {
                tex_format = GL_BGRA;
                tex_type = GL_UNSIGNED_BYTE;
            } else {
                tex_format = GL_RGBA;
                tex_type = GL_UNSIGNED_BYTE;                
            }
            glPixelStorei (GL_UNPACK_ALIGNMENT, 4);
            break;
    }   
    glPixelStorei(GL_UNPACK_ROW_LENGTH, (ds->linesize * 8) / ds->depth);
    glTexImage2D(GL_TEXTURE_RECTANGLE_ARB, 0, gl_format, ds->width, ds->height, 0, tex_format, tex_type, pixels);
    glTexParameterf(GL_TEXTURE_RECTANGLE_ARB, GL_TEXTURE_PRIORITY, 1.0);
    glTexParameteri(GL_TEXTURE_RECTANGLE_ARB, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_RECTANGLE_ARB, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_RECTANGLE_ARB, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_RECTANGLE_ARB, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glBindTexture(GL_TEXTURE_RECTANGLE_ARB, 0);
}

static void opengl_update(DisplayState *ds, int x, int y, int w, int h)
{  
    int bpp = ds->depth / 8;
    GLvoid *pixels = ds->data + y * ds->linesize + x * bpp;
    glBindTexture(GL_TEXTURE_RECTANGLE_ARB, texture_ref);
    glPixelStorei(GL_UNPACK_ROW_LENGTH, ds->linesize / bpp);
    glTexSubImage2D(GL_TEXTURE_RECTANGLE_ARB, 0, x, y, w, h, tex_format, tex_type, pixels);
    glBegin(GL_QUADS);
        glTexCoord2d(0, 0);
        glVertex2d(0, 0);
        glTexCoord2d(ds->width, 0);
        glVertex2d(screen->w, 0);
        glTexCoord2d(ds->width, ds->height);
        glVertex2d(screen->w, screen->h);
        glTexCoord2d(0, ds->height);
        glVertex2d(0, screen->h);
    glEnd();
    glBindTexture(GL_TEXTURE_RECTANGLE_ARB, 0);
    SDL_GL_SwapBuffers();
}
#endif

static void sdl_update(DisplayState *ds, int x, int y, int w, int h)
{
    //    printf("updating x=%d y=%d w=%d h=%d\n", x, y, w, h);
    if (shared) {
        SDL_Rect rec;
        rec.x = x;
        rec.y = y;
        rec.w = w;
        rec.h = h;
        SDL_BlitSurface(shared, &rec, screen, &rec);
    }
    SDL_Flip(screen);
}

static void sdl_setdata(DisplayState *ds, void *pixels)
{
    uint32_t rmask, gmask, bmask, amask = 0;
    switch (ds->depth) {
        case 8:
            rmask = 0x000000E0;
            gmask = 0x0000001C;
            bmask = 0x00000003;
            break;
        case 16:
            rmask = 0x0000F800;
            gmask = 0x000007E0;
            bmask = 0x0000001F;
            break;
        case 24:
            rmask = 0x00FF0000;
            gmask = 0x0000FF00;
            bmask = 0x000000FF;
            break;
        case 32:
            rmask = 0x00FF0000;
            gmask = 0x0000FF00;
            bmask = 0x000000FF;
            break;
        default:
            return;
    }
    shared = SDL_CreateRGBSurfaceFrom(pixels, width, height, ds->depth, ds->linesize, rmask , gmask, bmask, amask);
    ds->data = pixels;
}

static void sdl_resize(DisplayState *ds, int w, int h, int linesize)
{
    int flags;

    //    printf("resizing to %d %d\n", w, h);

#ifdef CONFIG_OPENGL
    if (ds->shared_buf && opengl_enabled)
        flags = SDL_OPENGL|SDL_RESIZABLE;
    else
#endif
        flags = SDL_HWSURFACE|SDL_ASYNCBLIT|SDL_HWACCEL|SDL_DOUBLEBUF|SDL_HWPALETTE;

    if (gui_fullscreen) {
        flags |= SDL_FULLSCREEN;
        flags &= ~SDL_RESIZABLE;
    }
    
    width = w;
    height = h;

 again:
    screen = SDL_SetVideoMode(w, h, 0, flags);

    if (!screen) {
        fprintf(stderr, "Could not open SDL display: %s\n", SDL_GetError());
        if (opengl_enabled) {
            /* Fallback to SDL */
            opengl_enabled = 0;
            ds->dpy_update = sdl_update;
            ds->dpy_setdata = sdl_setdata;
            sdl_resize(ds, w, h, linesize);
            return;
        }
        exit(1);
    }

    if (!opengl_enabled) {
        if (!screen->pixels && (flags & SDL_HWSURFACE) && (flags & SDL_FULLSCREEN)) {
            flags &= ~SDL_HWSURFACE;
            goto again;
        }

        if (!screen->pixels) {
            fprintf(stderr, "Could not open SDL display: %s\n", SDL_GetError());
            exit(1);
        }
    }

    ds->width = w;
    ds->height = h;
    if (!ds->shared_buf) {
        ds->depth = screen->format->BitsPerPixel;
        if (ds->depth == 32 && screen->format->Rshift == 0) {
            ds->bgr = 1;
        } else {
            ds->bgr = 0;
        }
        ds->data = screen->pixels;
        ds->linesize = screen->pitch;
    } else {
        ds->linesize = linesize;
#ifdef CONFIG_OPENGL
        switch(screen->format->BitsPerPixel) {
        case 8:
            gl_format = GL_RGB;
            break;
        case 16:
            gl_format = GL_RGB;
            break;
        case 24:
            gl_format = GL_RGB;
            break;
        case 32:
            if (!screen->format->Rshift)
                gl_format = GL_BGRA;
            else
                gl_format = GL_RGBA;
            break;
        };
#endif
    }
}

static void sdl_colourdepth(DisplayState *ds, int depth)
{
    if (!depth || !ds->depth) return;
    ds->shared_buf = 1;
    ds->depth = depth;
    ds->linesize = width * depth / 8;
#ifdef CONFIG_OPENGL
    if (opengl_enabled) {
        ds->dpy_update = opengl_update;
        ds->dpy_setdata = opengl_setdata;
    }
#endif
}

/* generic keyboard conversion */

#include "sdl_keysym.h"
#include "keymaps.c"

static kbd_layout_t *kbd_layout = NULL;

static uint8_t sdl_keyevent_to_keycode_generic(const SDL_KeyboardEvent *ev)
{
    int keysym;
    /* workaround for X11+SDL bug with AltGR */
    keysym = ev->keysym.sym;
    if (keysym == 0 && ev->keysym.scancode == 113)
        keysym = SDLK_MODE;
    /* For Japanese key '\' and '|' */
    if (keysym == 92 && ev->keysym.scancode == 133) {
        keysym = 0xa5;
    }
    return keysym2scancode(kbd_layout, keysym);
}

/* specific keyboard conversions from scan codes */

#if defined(_WIN32)

static uint8_t sdl_keyevent_to_keycode(const SDL_KeyboardEvent *ev)
{
    return ev->keysym.scancode;
}

#else

static uint8_t sdl_keyevent_to_keycode(const SDL_KeyboardEvent *ev)
{
    int keycode;

    keycode = ev->keysym.scancode;

    if (keycode < 9) {
        keycode = 0;
    } else if (keycode < 97) {
        keycode -= 8; /* just an offset */
    } else if (keycode < 212) {
        /* use conversion table */
        keycode = _translate_keycode(keycode - 97);
    } else {
        keycode = 0;
    }
    return keycode;
}

#endif

static void reset_keys(void)
{
    int i;
    for(i = 0; i < 256; i++) {
        if (modifiers_state[i]) {
            if (i & 0x80)
                kbd_put_keycode(0xe0);
            kbd_put_keycode(i | 0x80);
            modifiers_state[i] = 0;
        }
    }
}

static void sdl_process_key(SDL_KeyboardEvent *ev)
{
    int keycode, v;

    if (ev->keysym.sym == SDLK_PAUSE) {
        /* specific case */
        v = 0;
        if (ev->type == SDL_KEYUP)
            v |= 0x80;
        kbd_put_keycode(0xe1);
        kbd_put_keycode(0x1d | v);
        kbd_put_keycode(0x45 | v);
        return;
    }

    if (kbd_layout) {
        keycode = sdl_keyevent_to_keycode_generic(ev);
    } else {
        keycode = sdl_keyevent_to_keycode(ev);
    }

    switch(keycode) {
    case 0x00:
        /* sent when leaving window: reset the modifiers state */
        reset_keys();
        return;
    case 0x2a:                          /* Left Shift */
    case 0x36:                          /* Right Shift */
    case 0x1d:                          /* Left CTRL */
    case 0x9d:                          /* Right CTRL */
    case 0x38:                          /* Left ALT */
    case 0xb8:                         /* Right ALT */
        if (ev->type == SDL_KEYUP)
            modifiers_state[keycode] = 0;
        else
            modifiers_state[keycode] = 1;
        break;
    case 0x45: /* num lock */
    case 0x3a: /* caps lock */
        /* SDL does not send the key up event, so we generate it */
        kbd_put_keycode(keycode);
        kbd_put_keycode(keycode | 0x80);
        return;
    }

    /* now send the key code */
    if (keycode & 0x80)
        kbd_put_keycode(0xe0);
    if (ev->type == SDL_KEYUP)
        kbd_put_keycode(keycode | 0x80);
    else
        kbd_put_keycode(keycode & 0x7f);
}

static void sdl_update_caption(void)
{
    char buf[1024];
    strcpy(buf, domain_name);
    if (!vm_running) {
        strcat(buf, " [Stopped]");
    }
    if (gui_grab) {
        strcat(buf, " - Press Ctrl-Alt to exit grab");
    }
    SDL_WM_SetCaption(buf, domain_name);
}

static void sdl_hide_cursor(void)
{
    if (kbd_mouse_is_absolute()) {
        SDL_ShowCursor(1);
        SDL_SetCursor(sdl_cursor_hidden);
    } else {
        SDL_ShowCursor(0);
    }
}

static void sdl_show_cursor(void)
{
    if (!kbd_mouse_is_absolute()) {
        SDL_ShowCursor(1);
        SDL_SetCursor(sdl_cursor_normal);
    }
}

static void sdl_grab_start(void)
{
    sdl_hide_cursor();
    SDL_WM_GrabInput(SDL_GRAB_ON);
    /* dummy read to avoid moving the mouse */
    SDL_GetRelativeMouseState(NULL, NULL);
    gui_grab = 1;
    sdl_update_caption();
}

static void sdl_grab_end(void)
{
    SDL_WM_GrabInput(SDL_GRAB_OFF);
    sdl_show_cursor();
    gui_grab = 0;
    sdl_update_caption();
}

static void sdl_send_mouse_event(int dx, int dy, int dz, int state)
{
    int buttons = 0;
    if (state & SDL_BUTTON(SDL_BUTTON_LEFT))
        buttons |= MOUSE_EVENT_LBUTTON;
    if (state & SDL_BUTTON(SDL_BUTTON_RIGHT))
        buttons |= MOUSE_EVENT_RBUTTON;
    if (state & SDL_BUTTON(SDL_BUTTON_MIDDLE))
        buttons |= MOUSE_EVENT_MBUTTON;

    if (kbd_mouse_is_absolute()) {
	if (!absolute_enabled) {
	    sdl_hide_cursor();
	    if (gui_grab) {
		sdl_grab_end();
	    }
	    absolute_enabled = 1;
	}

	SDL_GetMouseState(&dx, &dy);
        dx = dx * 0x7FFF / (screen->w - 1);
        dy = dy * 0x7FFF / (screen->h - 1);
    } else if (absolute_enabled) {
	sdl_show_cursor();
	absolute_enabled = 0;
    }

    kbd_mouse_event(dx, dy, dz, buttons);
}

static void toggle_full_screen(DisplayState *ds)
{
    gui_fullscreen = !gui_fullscreen;
    sdl_resize(ds, ds->width, ds->height, ds->linesize);
    ds->dpy_setdata(ds, ds->data);
    if (gui_fullscreen) {
        gui_saved_grab = gui_grab;
        sdl_grab_start();
    } else {
        if (!gui_saved_grab)
            sdl_grab_end();
    }
    vga_hw_invalidate();
    vga_hw_update();
}

static void sdl_refresh(DisplayState *ds)
{
    SDL_Event ev1, *ev = &ev1;
    int mod_state;
                     
    if (last_vm_running != vm_running) {
        last_vm_running = vm_running;
        sdl_update_caption();
    }

    vga_hw_update();

    while (SDL_PollEvent(ev)) {
        switch (ev->type) {
        case SDL_VIDEOEXPOSE:
            ds->dpy_update(ds, 0, 0, ds->width, ds->height);
            break;
        case SDL_KEYDOWN:
        case SDL_KEYUP:
            if (ev->type == SDL_KEYDOWN) {
                mod_state = (SDL_GetModState() & gui_grab_code) ==
                    gui_grab_code;
                gui_key_modifier_pressed = mod_state;
                if (gui_key_modifier_pressed) {
                    int keycode;
                    keycode = sdl_keyevent_to_keycode(&ev->key);
                    switch(keycode) {
                    case 0x21: /* 'f' key on US keyboard */
                        toggle_full_screen(ds);
                        gui_keysym = 1;
                        break;
                    case 0x02 ... 0x0a: /* '1' to '9' keys */ 
                        /* Reset the modifiers sent to the current console */
                        reset_keys();
                        console_select(keycode - 0x02);
                        if (!is_graphic_console()) {
                            /* display grab if going to a text console */
                            if (gui_grab)
                                sdl_grab_end();
                        }
                        gui_keysym = 1;
                        break;
                    default:
                        break;
                    }
                } else if (!is_graphic_console()) {
                    int keysym;
                    keysym = 0;
                    if (ev->key.keysym.mod & (KMOD_LCTRL | KMOD_RCTRL)) {
                        switch(ev->key.keysym.sym) {
                        case SDLK_UP: keysym = QEMU_KEY_CTRL_UP; break;
                        case SDLK_DOWN: keysym = QEMU_KEY_CTRL_DOWN; break;
                        case SDLK_LEFT: keysym = QEMU_KEY_CTRL_LEFT; break;
                        case SDLK_RIGHT: keysym = QEMU_KEY_CTRL_RIGHT; break;
                        case SDLK_HOME: keysym = QEMU_KEY_CTRL_HOME; break;
                        case SDLK_END: keysym = QEMU_KEY_CTRL_END; break;
                        case SDLK_PAGEUP: keysym = QEMU_KEY_CTRL_PAGEUP; break;
                        case SDLK_PAGEDOWN: keysym = QEMU_KEY_CTRL_PAGEDOWN; break;
                        default: break;
                        }
                    } else {
                        switch(ev->key.keysym.sym) {
                        case SDLK_UP: keysym = QEMU_KEY_UP; break;
                        case SDLK_DOWN: keysym = QEMU_KEY_DOWN; break;
                        case SDLK_LEFT: keysym = QEMU_KEY_LEFT; break;
                        case SDLK_RIGHT: keysym = QEMU_KEY_RIGHT; break;
                        case SDLK_HOME: keysym = QEMU_KEY_HOME; break;
                        case SDLK_END: keysym = QEMU_KEY_END; break;
                        case SDLK_PAGEUP: keysym = QEMU_KEY_PAGEUP; break;
                        case SDLK_PAGEDOWN: keysym = QEMU_KEY_PAGEDOWN; break;
                        case SDLK_BACKSPACE: keysym = QEMU_KEY_BACKSPACE; break;                        case SDLK_DELETE: keysym = QEMU_KEY_DELETE; break;
                        default: break;
                        }
                    }
                    if (keysym) {
                        kbd_put_keysym(keysym);
                    } else if (ev->key.keysym.unicode != 0) {
                        kbd_put_keysym(ev->key.keysym.unicode);
                    }
                }
            } else if (ev->type == SDL_KEYUP) {
                mod_state = (ev->key.keysym.mod & gui_grab_code);
                if (!mod_state) {
                    if (gui_key_modifier_pressed) {
                        gui_key_modifier_pressed = 0;
                        if (gui_keysym == 0) {
                            /* exit/enter grab if pressing Ctrl-Alt */
                            if (!gui_grab) {
                                /* if the application is not active,
                                   do not try to enter grab state. It
                                   prevents
                                   'SDL_WM_GrabInput(SDL_GRAB_ON)'
                                   from blocking all the application
                                   (SDL bug). */
                                if (SDL_GetAppState() & SDL_APPACTIVE)
                                    sdl_grab_start();
                            } else {
                                sdl_grab_end();
                            }
                            /* SDL does not send back all the
                               modifiers key, so we must correct it */
                            reset_keys();
                            break;
                        }
                        gui_keysym = 0;
                    }
                }
            }
            if (is_graphic_console() && !gui_keysym) 
                sdl_process_key(&ev->key);
            break;
        case SDL_QUIT:
            if (!no_quit) {
               qemu_system_shutdown_request();
            }
            break;
        case SDL_MOUSEMOTION:
            if (gui_grab || kbd_mouse_is_absolute() ||
                absolute_enabled) {
                int dx, dy, state;
                state = SDL_GetRelativeMouseState(&dx, &dy);
                sdl_send_mouse_event(dx, dy, 0, state);
            }
            break;
        case SDL_MOUSEBUTTONUP:
            if (gui_grab || kbd_mouse_is_absolute()) {
                int dx, dy, state;
                state = SDL_GetRelativeMouseState(&dx, &dy);
                sdl_send_mouse_event(dx, dy, 0, state);
            }
            break;
        case SDL_MOUSEBUTTONDOWN:
            {
                SDL_MouseButtonEvent *bev = &ev->button;
                if (!gui_grab && !kbd_mouse_is_absolute()) {
                    if (ev->type == SDL_MOUSEBUTTONDOWN &&
                        (bev->state & SDL_BUTTON_LMASK)) {
                        /* start grabbing all events */
                        sdl_grab_start();
                    }
                } else {
                    int dx, dy, dz, state;
                    dz = 0;
                    state = SDL_GetRelativeMouseState(&dx, &dy);
#ifdef SDL_BUTTON_WHEELUP
                    if (bev->button == SDL_BUTTON_WHEELUP) {
                        dz = -1;
                    } else if (bev->button == SDL_BUTTON_WHEELDOWN) {
                        dz = 1;
                    } else {
                        state = bev->button | state;
                    }
#endif               
                    sdl_send_mouse_event(dx, dy, dz, state);
                }
            }
            break;
        case SDL_ACTIVEEVENT:
            if (gui_grab && ev->active.state == SDL_APPINPUTFOCUS &&
                !ev->active.gain && !gui_fullscreen_initial_grab) {
                sdl_grab_end();
            }
	    if (ev->active.state & SDL_APPACTIVE) {
		if (ev->active.gain) {
		    /* Back to default interval */
		    ds->gui_timer_interval = 0;
		} else {
		    /* Sleeping interval */
		    ds->gui_timer_interval = 500;
		}
	    }
            break;
#ifdef CONFIG_OPENGL
        case SDL_VIDEORESIZE:
        {
            if (ds->shared_buf && opengl_enabled) {
                SDL_ResizeEvent *rev = &ev->resize;
                screen = SDL_SetVideoMode(rev->w, rev->h, 0, SDL_OPENGL|SDL_RESIZABLE);
                opengl_setdata(ds, ds->data);
                opengl_update(ds, 0, 0, ds->width, ds->height);
            }
            break;
        }
#endif
        default:
            break;
        }
    }
}

static void sdl_cleanup(void) 
{
#ifdef CONFIG_OPENGL
    if (texture_ref) glDeleteTextures(1, &texture_ref);
#endif
    SDL_Quit();
}

void sdl_display_init(DisplayState *ds, int full_screen, int opengl)
{
    int flags;
    uint8_t data = 0;
    opengl_enabled = opengl;

#if defined(__APPLE__)
    /* always use generic keymaps */
    if (!keyboard_layout)
        keyboard_layout = "en-us";
#endif
    if(keyboard_layout) {
        kbd_layout = init_keyboard_layout(keyboard_layout);
        if (!kbd_layout)
            exit(1);
    }

    flags = SDL_INIT_VIDEO | SDL_INIT_NOPARACHUTE;
    if (SDL_Init (flags)) {
        fprintf(stderr, "Could not initialize SDL - exiting\n");
        exit(1);
    }
#ifndef _WIN32
    /* NOTE: we still want Ctrl-C to work, so we undo the SDL redirections */
    signal(SIGINT, SIG_DFL);
    signal(SIGQUIT, SIG_DFL);
#endif

    ds->dpy_update = sdl_update;
    ds->dpy_resize = sdl_resize;
    ds->dpy_refresh = sdl_refresh;
    ds->dpy_colourdepth = sdl_colourdepth;
    ds->dpy_setdata = sdl_setdata;

    sdl_resize(ds, 640, 400, 640 * 4);
    sdl_update_caption();
    SDL_EnableKeyRepeat(250, 50);
    SDL_EnableUNICODE(1);
    gui_grab = 0;

    sdl_cursor_hidden = SDL_CreateCursor(&data, &data, 8, 1, 0, 0);
    sdl_cursor_normal = SDL_GetCursor();

    atexit(sdl_cleanup);
    if (full_screen) {
        gui_fullscreen = 1;
        gui_fullscreen_initial_grab = 1;
        sdl_grab_start();
    }
}
