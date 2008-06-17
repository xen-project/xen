#include <stdint.h>
#include <xen/io/fbif.h>
#include <xen/io/kbdif.h>
#include <semaphore.h>
#include <sched.h>
#include <fbfront.h>

#include <hw/xenfb.h>

#include "vl.h"

typedef struct XenFBState {
    struct semaphore kbd_sem;
    struct kbdfront_dev *kbd_dev;
    struct fbfront_dev *fb_dev;
    void *vga_vram, *nonshared_vram;
    DisplayState *ds;
} XenFBState;

XenFBState *xs;

static char *kbd_path, *fb_path;

static unsigned char linux2scancode[KEY_MAX + 1];

int xenfb_connect_vkbd(const char *path)
{
    kbd_path = strdup(path);
    return 0;
}

int xenfb_connect_vfb(const char *path)
{
    fb_path = strdup(path);
    return 0;
}

static void xenfb_pv_update(DisplayState *ds, int x, int y, int w, int h)
{
    XenFBState *xs = ds->opaque;
    struct fbfront_dev *fb_dev = xs->fb_dev;
    if (!fb_dev)
        return;
    fbfront_update(fb_dev, x, y, w, h);
}

static void xenfb_pv_resize_shared(DisplayState *ds, int w, int h, int depth, int linesize, void *pixels)
{
    XenFBState *xs = ds->opaque;
    struct fbfront_dev *fb_dev = xs->fb_dev;
    int offset;

    fprintf(stderr,"resize to %dx%d@%d, %d required\n", w, h, depth, linesize);
    ds->width = w;
    ds->height = h;
    if (!depth) {
        ds->shared_buf = 0;
        ds->depth = 32;
    } else {
        ds->shared_buf = 1;
        ds->depth = depth;
    }
    if (!linesize)
        ds->shared_buf = 0;
    if (!ds->shared_buf)
        linesize = w * 4;
    ds->linesize = linesize;
    if (!fb_dev)
        return;
    if (ds->shared_buf) {
        offset = pixels - xs->vga_vram;
        ds->data = pixels;
        fbfront_resize(fb_dev, ds->width, ds->height, ds->linesize, ds->depth, offset);
    } else {
        ds->data = xs->nonshared_vram;
        fbfront_resize(fb_dev, w, h, linesize, ds->depth, VGA_RAM_SIZE);
    }
}

static void xenfb_pv_resize(DisplayState *ds, int w, int h)
{
    xenfb_pv_resize_shared(ds, w, h, 0, 0, NULL);
}

static void xenfb_pv_setdata(DisplayState *ds, void *pixels)
{
    XenFBState *xs = ds->opaque;
    struct fbfront_dev *fb_dev = xs->fb_dev;
    int offset = pixels - xs->vga_vram;
    ds->data = pixels;
    if (!fb_dev)
        return;
    fbfront_resize(fb_dev, ds->width, ds->height, ds->linesize, ds->depth, offset);
}

static void xenfb_pv_refresh(DisplayState *ds)
{
    vga_hw_update();
}

static void xenfb_fb_handler(void *opaque)
{
#define FB_NUM_BATCH 4
    union xenfb_in_event buf[FB_NUM_BATCH];
    int n, i;
    XenFBState *xs = opaque;
    DisplayState *ds = xs->ds;

    n = fbfront_receive(xs->fb_dev, buf, FB_NUM_BATCH);
    for (i = 0; i < n; i++) {
        switch (buf[i].type) {
        case XENFB_TYPE_REFRESH_PERIOD:
            if (buf[i].refresh_period.period == XENFB_NO_REFRESH) {
                /* Sleeping interval */
                ds->idle = 1;
                ds->gui_timer_interval = 500;
            } else {
                /* Set interval */
                ds->idle = 0;
                ds->gui_timer_interval = buf[i].refresh_period.period;
            }
        default:
            /* ignore unknown events */
            break;
        }
    }
}

static void xenfb_kbd_handler(void *opaque)
{
#define KBD_NUM_BATCH 64
    union xenkbd_in_event buf[KBD_NUM_BATCH];
    int n, i;
    XenFBState *xs = opaque;
    DisplayState *s = xs->ds;
    static int buttons;
    static int x, y;

    n = kbdfront_receive(xs->kbd_dev, buf, KBD_NUM_BATCH);
    for (i = 0; i < n; i++) {
        switch (buf[i].type) {

            case XENKBD_TYPE_MOTION:
                fprintf(stderr, "FB backend sent us relative mouse motion event!\n");
                break;

            case XENKBD_TYPE_POS:
            {
                int new_x = buf[i].pos.abs_x;
                int new_y = buf[i].pos.abs_y;
                if (new_x >= s->width)
                    new_x = s->width - 1;
                if (new_y >= s->height)
                    new_y = s->height - 1;
                if (kbd_mouse_is_absolute()) {
                    kbd_mouse_event(
                            new_x * 0x7FFF / (s->width - 1),
                            new_y * 0x7FFF / (s->height - 1),
                            buf[i].pos.rel_z,
                            buttons);
                } else {
                    kbd_mouse_event(
                            new_x - x,
                            new_y - y,
                            buf[i].pos.rel_z,
                            buttons);
                }
                x = new_x;
                y = new_y;
                break;
            }

            case XENKBD_TYPE_KEY:
            {
                int keycode = buf[i].key.keycode;
                int button = 0;

                if (keycode == BTN_LEFT)
                    button = MOUSE_EVENT_LBUTTON;
                else if (keycode == BTN_RIGHT)
                    button = MOUSE_EVENT_RBUTTON;
                else if (keycode == BTN_MIDDLE)
                    button = MOUSE_EVENT_MBUTTON;

                if (button) {
                    if (buf[i].key.pressed)
                        buttons |=  button;
                    else
                        buttons &= ~button;
                    if (kbd_mouse_is_absolute())
                        kbd_mouse_event(
                                x * 0x7FFF / (s->width - 1),
                                y * 0x7FFF / (s->height - 1),
                                0,
                                buttons);
                    else
                        kbd_mouse_event(0, 0, 0, buttons);
                } else {
                    int scancode = linux2scancode[keycode];
                    if (!scancode) {
                        fprintf(stderr, "Can't convert keycode %x to scancode\n", keycode);
                        break;
                    }
                    if (scancode & 0x80) {
                        kbd_put_keycode(0xe0);
                        scancode &= 0x7f;
                    }
                    if (!buf[i].key.pressed)
                        scancode |= 0x80;
                    kbd_put_keycode(scancode);
                }
                break;
            }
        }
    }
}

static void kbdfront_thread(void *p)
{
    int scancode, keycode;
    XenFBState *xs = p;
    xs->kbd_dev = init_kbdfront(kbd_path, 1);
    if (!xs->kbd_dev) {
        fprintf(stderr,"can't open keyboard\n");
        exit(1);
    }
    up(&xs->kbd_sem);
    for (scancode = 0; scancode < 128; scancode++) {
        keycode = atkbd_set2_keycode[atkbd_unxlate_table[scancode]];
        linux2scancode[keycode] = scancode;
        keycode = atkbd_set2_keycode[atkbd_unxlate_table[scancode] | 0x80];
        linux2scancode[keycode] = scancode | 0x80;
    }
}

int xenfb_pv_display_init(DisplayState *ds)
{
    if (!fb_path || !kbd_path)
        return -1;

    xs = qemu_mallocz(sizeof(XenFBState));
    if (!xs)
        return -1;

    init_SEMAPHORE(&xs->kbd_sem, 0);
    xs->ds = ds;

    create_thread("kbdfront", kbdfront_thread, (void*) xs);

    ds->data = xs->nonshared_vram = qemu_memalign(PAGE_SIZE, VGA_RAM_SIZE);
    memset(ds->data, 0, VGA_RAM_SIZE);
    ds->opaque = xs;
    ds->depth = 32;
    ds->bgr = 0;
    ds->width = 640;
    ds->height = 400;
    ds->linesize = 640 * 4;
    ds->dpy_update = xenfb_pv_update;
    ds->dpy_resize = xenfb_pv_resize;
    ds->dpy_resize_shared = xenfb_pv_resize_shared;
    ds->dpy_setdata = xenfb_pv_setdata;
    ds->dpy_refresh = xenfb_pv_refresh;
    return 0;
}

int xenfb_pv_display_start(void *data)
{
    DisplayState *ds;
    struct fbfront_dev *fb_dev;
    int kbd_fd, fb_fd;
    int offset = 0;
    unsigned long *mfns;
    int n = VGA_RAM_SIZE / PAGE_SIZE;
    int i;

    if (!fb_path || !kbd_path)
        return 0;

    ds = xs->ds;
    xs->vga_vram = data;
    mfns = malloc(2 * n * sizeof(*mfns));
    for (i = 0; i < n; i++)
        mfns[i] = virtual_to_mfn(xs->vga_vram + i * PAGE_SIZE);
    for (i = 0; i < n; i++)
        mfns[n + i] = virtual_to_mfn(xs->nonshared_vram + i * PAGE_SIZE);

    fb_dev = init_fbfront(fb_path, mfns, ds->width, ds->height, ds->depth, ds->linesize, 2 * n);
    free(mfns);
    if (!fb_dev) {
        fprintf(stderr,"can't open frame buffer\n");
        exit(1);
    }
    free(fb_path);

    if (ds->shared_buf) {
        offset = (void*) ds->data - xs->vga_vram;
    } else {
        offset = VGA_RAM_SIZE;
        ds->data = xs->nonshared_vram;
    }
    if (offset)
        fbfront_resize(fb_dev, ds->width, ds->height, ds->linesize, ds->depth, offset);

    down(&xs->kbd_sem);
    free(kbd_path);

    kbd_fd = kbdfront_open(xs->kbd_dev);
    qemu_set_fd_handler(kbd_fd, xenfb_kbd_handler, NULL, xs);

    fb_fd = fbfront_open(fb_dev);
    qemu_set_fd_handler(fb_fd, xenfb_fb_handler, NULL, xs);

    xs->fb_dev = fb_dev;
    return 0;
}
