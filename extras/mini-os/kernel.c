/******************************************************************************
 * kernel.c
 * 
 * Assorted crap goes here, including the initial C entry point, jumped at
 * from head.S.
 * 
 * Copyright (c) 2002-2003, K A Fraser & R Neugebauer
 * Copyright (c) 2005, Grzegorz Milos, Intel Research Cambridge
 * Copyright (c) 2006, Robert Kaiser, FH Wiesbaden
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 * DEALINGS IN THE SOFTWARE.
 */

#include <os.h>
#include <hypervisor.h>
#include <mm.h>
#include <events.h>
#include <time.h>
#include <types.h>
#include <lib.h>
#include <sched.h>
#include <xenbus.h>
#include <gnttab.h>
#include <netfront.h>
#include <blkfront.h>
#include <fbfront.h>
#include <fs.h>
#include <xmalloc.h>
#include <fcntl.h>
#include <xen/features.h>
#include <xen/version.h>


u8 xen_features[XENFEAT_NR_SUBMAPS * 32];

void setup_xen_features(void)
{
    xen_feature_info_t fi;
    int i, j;

    for (i = 0; i < XENFEAT_NR_SUBMAPS; i++) 
    {
        fi.submap_idx = i;
        if (HYPERVISOR_xen_version(XENVER_get_features, &fi) < 0)
            break;
        
        for (j=0; j<32; j++)
            xen_features[i*32+j] = !!(fi.submap & 1<<j);
    }
}

void test_xenbus(void);

static void xenbus_tester(void *p)
{
    printk("Xenbus tests disabled, because of a Xend bug.\n");
    /* test_xenbus(); */
}

static void periodic_thread(void *p)
{
    struct timeval tv;
    printk("Periodic thread started.\n");
    for(;;)
    {
        gettimeofday(&tv, NULL);
        printk("T(s=%ld us=%ld)\n", tv.tv_sec, tv.tv_usec);
        msleep(1000);
    }
}

static void netfront_thread(void *p)
{
    init_netfront(NULL, NULL, NULL, NULL);
}

static struct blkfront_dev *blk_dev;
static struct blkfront_info blk_info;
static uint64_t blk_size_read;
static uint64_t blk_size_write;

struct blk_req {
    struct blkfront_aiocb aiocb;
    int rand_value;
    struct blk_req *next;
};

#ifdef BLKTEST_WRITE
static struct blk_req *blk_to_read;
#endif

static struct blk_req *blk_alloc_req(uint64_t sector)
{
    struct blk_req *req = xmalloc(struct blk_req);
    req->aiocb.aio_dev = blk_dev;
    req->aiocb.aio_buf = _xmalloc(blk_info.sector_size, blk_info.sector_size);
    req->aiocb.aio_nbytes = blk_info.sector_size;
    req->aiocb.aio_offset = sector * blk_info.sector_size;
    req->aiocb.data = req;
    req->next = NULL;
    return req;
}

static void blk_read_completed(struct blkfront_aiocb *aiocb, int ret)
{
    struct blk_req *req = aiocb->data;
    if (ret)
        printk("got error code %d when reading at offset %ld\n", ret, aiocb->aio_offset);
    else
        blk_size_read += blk_info.sector_size;
    free(aiocb->aio_buf);
    free(req);
}

static void blk_read_sector(uint64_t sector)
{
    struct blk_req *req;

    req = blk_alloc_req(sector);
    req->aiocb.aio_cb = blk_read_completed;

    blkfront_aio_read(&req->aiocb);
}

#ifdef BLKTEST_WRITE
static void blk_write_read_completed(struct blkfront_aiocb *aiocb, int ret)
{
    struct blk_req *req = aiocb->data;
    int rand_value;
    int i;
    int *buf;

    if (ret) {
        printk("got error code %d when reading back at offset %ld\n", ret, aiocb->aio_offset);
        free(aiocb->aio_buf);
        free(req);
        return;
    }
    blk_size_read += blk_info.sector_size;
    buf = (int*) aiocb->aio_buf;
    rand_value = req->rand_value;
    for (i = 0; i < blk_info.sector_size / sizeof(int); i++) {
        if (buf[i] != rand_value) {
            printk("bogus data at offset %ld\n", aiocb->aio_offset + i);
            break;
        }
        rand_value *= RAND_MIX;
    }
    free(aiocb->aio_buf);
    free(req);
}

static void blk_write_completed(struct blkfront_aiocb *aiocb, int ret)
{
    struct blk_req *req = aiocb->data;
    if (ret) {
        printk("got error code %d when writing at offset %ld\n", ret, aiocb->aio_offset);
        free(aiocb->aio_buf);
        free(req);
        return;
    }
    blk_size_write += blk_info.sector_size;
    /* Push write check */
    req->next = blk_to_read;
    blk_to_read = req;
}

static void blk_write_sector(uint64_t sector)
{
    struct blk_req *req;
    int rand_value;
    int i;
    int *buf;

    req = blk_alloc_req(sector);
    req->aiocb.aio_cb = blk_write_completed;
    req->rand_value = rand_value = rand();

    buf = (int*) req->aiocb.aio_buf;
    for (i = 0; i < blk_info.sector_size / sizeof(int); i++) {
        buf[i] = rand_value;
        rand_value *= RAND_MIX;
    }

    blkfront_aio_write(&req->aiocb);
}
#endif

static void blkfront_thread(void *p)
{
    time_t lasttime = 0;

    blk_dev = init_blkfront(NULL, &blk_info);
    if (!blk_dev)
        return;

    if (blk_info.info & VDISK_CDROM)
        printk("Block device is a CDROM\n");
    if (blk_info.info & VDISK_REMOVABLE)
        printk("Block device is removable\n");
    if (blk_info.info & VDISK_READONLY)
        printk("Block device is read-only\n");

#ifdef BLKTEST_WRITE
    if (blk_info.mode == O_RDWR) {
        blk_write_sector(0);
        blk_write_sector(blk_info.sectors-1);
    } else
#endif
    {
        blk_read_sector(0);
        blk_read_sector(blk_info.sectors-1);
    }

    while (1) {
        uint64_t sector = rand() % blk_info.sectors;
        struct timeval tv;
#ifdef BLKTEST_WRITE
        if (blk_info.mode == O_RDWR)
            blk_write_sector(sector);
        else
#endif
            blk_read_sector(sector);
        blkfront_aio_poll(blk_dev);
        gettimeofday(&tv, NULL);
        if (tv.tv_sec > lasttime + 10) {
            printk("%llu read, %llu write\n", blk_size_read, blk_size_write);
            lasttime = tv.tv_sec;
        }

#ifdef BLKTEST_WRITE
        while (blk_to_read) {
            struct blk_req *req = blk_to_read;
            blk_to_read = blk_to_read->next;
            req->aiocb.aio_cb = blk_write_read_completed;
            blkfront_aio_read(&req->aiocb);
        }
#endif
    }
}

#define WIDTH 800
#define HEIGHT 600
#define DEPTH 32

static uint32_t *fb;
static struct fbfront_dev *fb_dev;
static struct semaphore fbfront_sem = __SEMAPHORE_INITIALIZER(fbfront_sem, 0);

static void fbfront_drawvert(int x, int y1, int y2, uint32_t color)
{
    int y;
    if (x < 0)
        return;
    if (x >= WIDTH)
        return;
    if (y1 < 0)
        y1 = 0;
    if (y2 >= HEIGHT)
        y2 = HEIGHT-1;
    for (y = y1; y <= y2; y++)
        fb[x + y*WIDTH] ^= color;
}

static void fbfront_drawhoriz(int x1, int x2, int y, uint32_t color)
{
    int x;
    if (y < 0)
        return;
    if (y >= HEIGHT)
        return;
    if (x1 < 0)
        x1 = 0;
    if (x2 >= WIDTH)
        x2 = WIDTH-1;
    for (x = x1; x <= x2; x++)
        fb[x + y*WIDTH] ^= color;
}

static void fbfront_thread(void *p)
{
    size_t line_length = WIDTH * (DEPTH / 8);
    size_t memsize = HEIGHT * line_length;

    fb = _xmalloc(memsize, PAGE_SIZE);
    fb_dev = init_fbfront(NULL, fb, WIDTH, HEIGHT, DEPTH, line_length, memsize);
    if (!fb_dev) {
        xfree(fb);
        return;
    }
    up(&fbfront_sem);
}

static void clip_cursor(int *x, int *y)
{
    if (*x < 0)
        *x = 0;
    if (*x >= WIDTH)
        *x = WIDTH - 1;
    if (*y < 0)
        *y = 0;
    if (*y >= HEIGHT)
        *y = HEIGHT - 1;
}

static void refresh_cursor(int new_x, int new_y)
{
    static int old_x = -1, old_y = -1;
    if (old_x != -1 && old_y != -1) {
        fbfront_drawvert(old_x, old_y + 1, old_y + 8, 0xffffffff);
        fbfront_drawhoriz(old_x + 1, old_x + 8, old_y, 0xffffffff);
        fbfront_update(fb_dev, old_x, old_y, 9, 9);
    }
    old_x = new_x;
    old_y = new_y;
    fbfront_drawvert(new_x, new_y + 1, new_y + 8, 0xffffffff);
    fbfront_drawhoriz(new_x + 1, new_x + 8, new_y, 0xffffffff);
    fbfront_update(fb_dev, new_x, new_y, 9, 9);
}

static void kbdfront_thread(void *p)
{
    struct kbdfront_dev *kbd_dev;
    DEFINE_WAIT(w);
    int x = WIDTH / 2, y = HEIGHT / 2, z = 0;

    kbd_dev = init_kbdfront(NULL, 1);
    if (!kbd_dev)
        return;

    down(&fbfront_sem);
    refresh_cursor(x, y);
    while (1) {
        union xenkbd_in_event event;

        add_waiter(w, kbdfront_queue);

        if (kbdfront_receive(kbd_dev, &event, 1) == 0)
            schedule();
        else switch(event.type) {
            case XENKBD_TYPE_MOTION:
                printk("motion x:%d y:%d z:%d\n",
                        event.motion.rel_x,
                        event.motion.rel_y,
                        event.motion.rel_z);
                x += event.motion.rel_x;
                y += event.motion.rel_y;
                z += event.motion.rel_z;
                clip_cursor(&x, &y);
                refresh_cursor(x, y);
                break;
            case XENKBD_TYPE_POS:
                printk("pos x:%d y:%d dz:%d\n",
                        event.pos.abs_x,
                        event.pos.abs_y,
                        event.pos.rel_z);
                x = event.pos.abs_x;
                y = event.pos.abs_y;
                z = event.pos.rel_z;
                clip_cursor(&x, &y);
                refresh_cursor(x, y);
                break;
            case XENKBD_TYPE_KEY:
                printk("key %d %s\n",
                        event.key.keycode,
                        event.key.pressed ? "pressed" : "released");
                if (event.key.keycode == BTN_LEFT) {
                    printk("mouse %s at (%d,%d,%d)\n",
                            event.key.pressed ? "clic" : "release", x, y, z);
                    if (event.key.pressed) {
                        uint32_t color = rand();
                        fbfront_drawvert(x - 16, y - 16, y + 15, color);
                        fbfront_drawhoriz(x - 16, x + 15, y + 16, color);
                        fbfront_drawvert(x + 16, y - 15, y + 16, color);
                        fbfront_drawhoriz(x - 15, x + 16, y - 16, color);
                        fbfront_update(fb_dev, x - 16, y - 16, 33, 33);
                    }
                } else if (event.key.keycode == KEY_Q) {
                    struct sched_shutdown sched_shutdown = { .reason = SHUTDOWN_poweroff };
                    HYPERVISOR_sched_op(SCHEDOP_shutdown, &sched_shutdown);
                    do_exit();
                }
                break;
        }
    }
}

static void fs_thread(void *p)
{
    init_fs_frontend();
}

/* This should be overridden by the application we are linked against. */
__attribute__((weak)) int app_main(start_info_t *si)
{
    printk("Dummy main: start_info=%p\n", si);
    create_thread("xenbus_tester", xenbus_tester, si);
    create_thread("periodic_thread", periodic_thread, si);
    create_thread("netfront", netfront_thread, si);
    create_thread("blkfront", blkfront_thread, si);
    create_thread("fbfront", fbfront_thread, si);
    create_thread("kbdfront", kbdfront_thread, si);
    create_thread("fs-frontend", fs_thread, si);
    return 0;
}

/*
 * INITIAL C ENTRY POINT.
 */
void start_kernel(start_info_t *si)
{
    static char hello[] = "Bootstrapping...\n";

    (void)HYPERVISOR_console_io(CONSOLEIO_write, strlen(hello), hello);

    arch_init(si);

    trap_init();

    /* print out some useful information  */
    printk("Xen Minimal OS!\n");
    printk("start_info:   %p\n",    si);
    printk("  nr_pages:   %lu",     si->nr_pages);
    printk("  shared_inf: %08lx\n", si->shared_info);
    printk("  pt_base:    %p",      (void *)si->pt_base); 
    printk("  mod_start:  0x%lx\n", si->mod_start);
    printk("  mod_len:    %lu\n",   si->mod_len); 
    printk("  flags:      0x%x\n",  (unsigned int)si->flags);
    printk("  cmd_line:   %s\n",  
           si->cmd_line ? (const char *)si->cmd_line : "NULL");

    /* Set up events. */
    init_events();
    
    /* ENABLE EVENT DELIVERY. This is disabled at start of day. */
    __sti();

    arch_print_info();

    setup_xen_features();

    /* Init memory management. */
    init_mm();

    /* Init time and timers. */
    init_time();

    /* Init the console driver. */
    init_console();

    /* Init grant tables */
    init_gnttab();
    
    /* Init scheduler. */
    init_sched();
 
    /* Init XenBus */
    init_xenbus();

    /* Call (possibly overridden) app_main() */
    app_main(&start_info);

    /* Everything initialised, start idle thread */
    run_idle_thread();
}


/*
 * do_exit: This is called whenever an IRET fails in entry.S.
 * This will generally be because an application has got itself into
 * a really bad state (probably a bad CS or SS). It must be killed.
 * Of course, minimal OS doesn't have applications :-)
 */

void do_exit(void)
{
    printk("Do_exit called!\n");
    for( ;; )
    {
        struct sched_shutdown sched_shutdown = { .reason = SHUTDOWN_crash };
        HYPERVISOR_sched_op(SCHEDOP_shutdown, &sched_shutdown);
    }
}
