/*
 * linux/drivers/video/xenfb.c -- Xen para-virtual frame buffer device
 *
 * Copyright (C) 2005-2006 Anthony Liguori <aliguori@us.ibm.com>
 * Copyright (C) 2006 Red Hat, Inc., Markus Armbruster <armbru@redhat.com>
 *
 *  Based on linux/drivers/video/q40fb.c
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License. See the file COPYING in the main directory of this archive for
 *  more details.
 */

/*
 * TODO:
 *
 * Switch to grant tables when they become capable of dealing with the
 * frame buffer.
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fb.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <asm/hypervisor.h>
#include <xen/evtchn.h>
#include <xen/interface/io/fbif.h>
#include <xen/interface/io/protocols.h>
#include <xen/xenbus.h>
#include <linux/kthread.h>

struct xenfb_mapping
{
	struct list_head	link;
	struct vm_area_struct	*vma;
	atomic_t		map_refs;
	int			faults;
	struct xenfb_info	*info;
};

struct xenfb_info
{
	struct task_struct	*kthread;
	wait_queue_head_t	wq;

	unsigned char		*fb;
	struct fb_info		*fb_info;
	struct timer_list	refresh;
	int			dirty;
	int			x1, y1, x2, y2;	/* dirty rectangle,
						   protected by dirty_lock */
	spinlock_t		dirty_lock;
	struct mutex		mm_lock;
	int			nr_pages;
	struct page		**pages;
	struct list_head	mappings; /* protected by mm_lock */

	int			irq;
	struct xenfb_page	*page;
	unsigned long 		*mfns;
	int			update_wanted; /* XENFB_TYPE_UPDATE wanted */

	struct xenbus_device	*xbdev;
};

/*
 * How the locks work together
 *
 * There are two locks: spinlock dirty_lock protecting the dirty
 * rectangle, and mutex mm_lock protecting mappings.
 *
 * The problem is that dirty rectangle and mappings aren't
 * independent: the dirty rectangle must cover all faulted pages in
 * mappings.  We need to prove that our locking maintains this
 * invariant.
 *
 * There are several kinds of critical regions:
 *
 * 1. Holding only dirty_lock: xenfb_refresh().  May run in
 *    interrupts.  Extends the dirty rectangle.  Trivially preserves
 *    invariant.
 *
 * 2. Holding only mm_lock: xenfb_mmap() and xenfb_vm_close().  Touch
 *    only mappings.  The former creates unfaulted pages.  Preserves
 *    invariant.  The latter removes pages.  Preserves invariant.
 *
 * 3. Holding both locks: xenfb_vm_nopage().  Extends the dirty
 *    rectangle and updates mappings consistently.  Preserves
 *    invariant.
 *
 * 4. The ugliest one: xenfb_update_screen().  Clear the dirty
 *    rectangle and update mappings consistently.
 *
 *    We can't simply hold both locks, because zap_page_range() cannot
 *    be called with a spinlock held.
 *
 *    Therefore, we first clear the dirty rectangle with both locks
 *    held.  Then we unlock dirty_lock and update the mappings.
 *    Critical regions that hold only dirty_lock may interfere with
 *    that.  This can only be region 1: xenfb_refresh().  But that
 *    just extends the dirty rectangle, which can't harm the
 *    invariant.
 *
 * But FIXME: the invariant is too weak.  It misses that the fault
 * record in mappings must be consistent with the mapping of pages in
 * the associated address space!  do_no_page() updates the PTE after
 * xenfb_vm_nopage() returns, i.e. outside the critical region.  This
 * allows the following race:
 *
 * X writes to some address in the Xen frame buffer
 * Fault - call do_no_page()
 *     call xenfb_vm_nopage()
 *         grab mm_lock
 *         map->faults++;
 *         release mm_lock
 *     return back to do_no_page()
 * (preempted, or SMP)
 * Xen worker thread runs.
 *      grab mm_lock
 *      look at mappings
 *          find this mapping, zaps its pages (but page not in pte yet)
 *          clear map->faults
 *      releases mm_lock
 * (back to X process)
 *     put page in X's pte
 *
 * Oh well, we wont be updating the writes to this page anytime soon.
 */

static int xenfb_fps = 20;
static unsigned long xenfb_mem_len = XENFB_WIDTH * XENFB_HEIGHT * XENFB_DEPTH / 8;

static int xenfb_remove(struct xenbus_device *);
static void xenfb_init_shared_page(struct xenfb_info *);
static int xenfb_connect_backend(struct xenbus_device *, struct xenfb_info *);
static void xenfb_disconnect_backend(struct xenfb_info *);

static void xenfb_do_update(struct xenfb_info *info,
			    int x, int y, int w, int h)
{
	union xenfb_out_event event;
	__u32 prod;

	event.type = XENFB_TYPE_UPDATE;
	event.update.x = x;
	event.update.y = y;
	event.update.width = w;
	event.update.height = h;

	prod = info->page->out_prod;
	/* caller ensures !xenfb_queue_full() */
	mb();			/* ensure ring space available */
	XENFB_OUT_RING_REF(info->page, prod) = event;
	wmb();			/* ensure ring contents visible */
	info->page->out_prod = prod + 1;

	notify_remote_via_irq(info->irq);
}

static int xenfb_queue_full(struct xenfb_info *info)
{
	__u32 cons, prod;

	prod = info->page->out_prod;
	cons = info->page->out_cons;
	return prod - cons == XENFB_OUT_RING_LEN;
}

static void xenfb_update_screen(struct xenfb_info *info)
{
	unsigned long flags;
	int y1, y2, x1, x2;
	struct xenfb_mapping *map;

	if (!info->update_wanted)
		return;
	if (xenfb_queue_full(info))
		return;

	mutex_lock(&info->mm_lock);

	spin_lock_irqsave(&info->dirty_lock, flags);
	y1 = info->y1;
	y2 = info->y2;
	x1 = info->x1;
	x2 = info->x2;
	info->x1 = info->y1 = INT_MAX;
	info->x2 = info->y2 = 0;
	spin_unlock_irqrestore(&info->dirty_lock, flags);

	list_for_each_entry(map, &info->mappings, link) {
		if (!map->faults)
			continue;
		zap_page_range(map->vma, map->vma->vm_start,
			       map->vma->vm_end - map->vma->vm_start, NULL);
		map->faults = 0;
	}

	mutex_unlock(&info->mm_lock);

	xenfb_do_update(info, x1, y1, x2 - x1, y2 - y1);
}

static int xenfb_thread(void *data)
{
	struct xenfb_info *info = data;

	while (!kthread_should_stop()) {
		if (info->dirty) {
			info->dirty = 0;
			xenfb_update_screen(info);
		}
		wait_event_interruptible(info->wq,
			kthread_should_stop() || info->dirty);
		try_to_freeze();
	}
	return 0;
}

static int xenfb_setcolreg(unsigned regno, unsigned red, unsigned green,
			   unsigned blue, unsigned transp,
			   struct fb_info *info)
{
	u32 v;

	if (regno > info->cmap.len)
		return 1;

	red   >>= (16 - info->var.red.length);
	green >>= (16 - info->var.green.length);
	blue  >>= (16 - info->var.blue.length);

	v = (red << info->var.red.offset) |
	    (green << info->var.green.offset) |
	    (blue << info->var.blue.offset);

	/* FIXME is this sane?  check against xxxfb_setcolreg()!  */
	switch (info->var.bits_per_pixel) {
	case 16:
	case 24:
	case 32:
		((u32 *)info->pseudo_palette)[regno] = v;
		break;
	}
	
	return 0;
}

static void xenfb_timer(unsigned long data)
{
	struct xenfb_info *info = (struct xenfb_info *)data;
	info->dirty = 1;
	wake_up(&info->wq);
}

static void __xenfb_refresh(struct xenfb_info *info,
			    int x1, int y1, int w, int h)
{
	int y2, x2;

	y2 = y1 + h;
	x2 = x1 + w;

	if (info->y1 > y1)
		info->y1 = y1;
	if (info->y2 < y2)
		info->y2 = y2;
	if (info->x1 > x1)
		info->x1 = x1;
	if (info->x2 < x2)
		info->x2 = x2;

	if (timer_pending(&info->refresh))
		return;

	mod_timer(&info->refresh, jiffies + HZ/xenfb_fps);
}

static void xenfb_refresh(struct xenfb_info *info,
			  int x1, int y1, int w, int h)
{
	unsigned long flags;

	spin_lock_irqsave(&info->dirty_lock, flags);
	__xenfb_refresh(info, x1, y1, w, h);
	spin_unlock_irqrestore(&info->dirty_lock, flags);
}

static void xenfb_fillrect(struct fb_info *p, const struct fb_fillrect *rect)
{
	struct xenfb_info *info = p->par;

	cfb_fillrect(p, rect);
	xenfb_refresh(info, rect->dx, rect->dy, rect->width, rect->height);
}

static void xenfb_imageblit(struct fb_info *p, const struct fb_image *image)
{
	struct xenfb_info *info = p->par;

	cfb_imageblit(p, image);
	xenfb_refresh(info, image->dx, image->dy, image->width, image->height);
}

static void xenfb_copyarea(struct fb_info *p, const struct fb_copyarea *area)
{
	struct xenfb_info *info = p->par;

	cfb_copyarea(p, area);
	xenfb_refresh(info, area->dx, area->dy, area->width, area->height);
}

static void xenfb_vm_open(struct vm_area_struct *vma)
{
	struct xenfb_mapping *map = vma->vm_private_data;
	atomic_inc(&map->map_refs);
}

static void xenfb_vm_close(struct vm_area_struct *vma)
{
	struct xenfb_mapping *map = vma->vm_private_data;
	struct xenfb_info *info = map->info;

	mutex_lock(&info->mm_lock);
	if (atomic_dec_and_test(&map->map_refs)) {
		list_del(&map->link);
		kfree(map);
	}
	mutex_unlock(&info->mm_lock);
}

static struct page *xenfb_vm_nopage(struct vm_area_struct *vma,
				    unsigned long vaddr, int *type)
{
	struct xenfb_mapping *map = vma->vm_private_data;
	struct xenfb_info *info = map->info;
	int pgnr = (vaddr - vma->vm_start) >> PAGE_SHIFT;
	unsigned long flags;
	struct page *page;
	int y1, y2;

	if (pgnr >= info->nr_pages)
		return NOPAGE_SIGBUS;

	mutex_lock(&info->mm_lock);
	spin_lock_irqsave(&info->dirty_lock, flags);
	page = info->pages[pgnr];
	get_page(page);
	map->faults++;

	y1 = pgnr * PAGE_SIZE / info->fb_info->fix.line_length;
	y2 = (pgnr * PAGE_SIZE + PAGE_SIZE - 1) / info->fb_info->fix.line_length;
	if (y2 > info->fb_info->var.yres)
		y2 = info->fb_info->var.yres;
	__xenfb_refresh(info, 0, y1, info->fb_info->var.xres, y2 - y1);
	spin_unlock_irqrestore(&info->dirty_lock, flags);
	mutex_unlock(&info->mm_lock);

	if (type)
		*type = VM_FAULT_MINOR;

	return page;
}

static struct vm_operations_struct xenfb_vm_ops = {
	.open	= xenfb_vm_open,
	.close	= xenfb_vm_close,
	.nopage	= xenfb_vm_nopage,
};

static int xenfb_mmap(struct fb_info *fb_info, struct vm_area_struct *vma)
{
	struct xenfb_info *info = fb_info->par;
	struct xenfb_mapping *map;
	int map_pages;

	if (!(vma->vm_flags & VM_WRITE))
		return -EINVAL;
	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;
	if (vma->vm_pgoff != 0)
		return -EINVAL;

	map_pages = (vma->vm_end - vma->vm_start + PAGE_SIZE-1) >> PAGE_SHIFT;
	if (map_pages > info->nr_pages)
		return -EINVAL;

	map = kzalloc(sizeof(*map), GFP_KERNEL);
	if (map == NULL)
		return -ENOMEM;

	map->vma = vma;
	map->faults = 0;
	map->info = info;
	atomic_set(&map->map_refs, 1);

	mutex_lock(&info->mm_lock);
	list_add(&map->link, &info->mappings);
	mutex_unlock(&info->mm_lock);

	vma->vm_ops = &xenfb_vm_ops;
	vma->vm_flags |= (VM_DONTEXPAND | VM_RESERVED);
	vma->vm_private_data = map;

	return 0;
}

static struct fb_ops xenfb_fb_ops = {
	.owner		= THIS_MODULE,
	.fb_setcolreg	= xenfb_setcolreg,
	.fb_fillrect	= xenfb_fillrect,
	.fb_copyarea	= xenfb_copyarea,
	.fb_imageblit	= xenfb_imageblit,
	.fb_mmap	= xenfb_mmap,
};

static irqreturn_t xenfb_event_handler(int rq, void *dev_id,
				       struct pt_regs *regs)
{
	/*
	 * No in events recognized, simply ignore them all.
	 * If you need to recognize some, see xenbkd's input_handler()
	 * for how to do that.
	 */
	struct xenfb_info *info = dev_id;
	struct xenfb_page *page = info->page;

	if (page->in_cons != page->in_prod) {
		info->page->in_cons = info->page->in_prod;
		notify_remote_via_irq(info->irq);
	}
	return IRQ_HANDLED;
}

static unsigned long vmalloc_to_mfn(void *address)
{
	return pfn_to_mfn(vmalloc_to_pfn(address));
}

static int __devinit xenfb_probe(struct xenbus_device *dev,
				 const struct xenbus_device_id *id)
{
	struct xenfb_info *info;
	struct fb_info *fb_info;
	int ret;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (info == NULL) {
		xenbus_dev_fatal(dev, -ENOMEM, "allocating info structure");
		return -ENOMEM;
	}
	dev->dev.driver_data = info;
	info->xbdev = dev;
	info->irq = -1;
	info->x1 = info->y1 = INT_MAX;
	spin_lock_init(&info->dirty_lock);
	mutex_init(&info->mm_lock);
	init_waitqueue_head(&info->wq);
	init_timer(&info->refresh);
	info->refresh.function = xenfb_timer;
	info->refresh.data = (unsigned long)info;
	INIT_LIST_HEAD(&info->mappings);

	info->fb = vmalloc(xenfb_mem_len);
	if (info->fb == NULL)
		goto error_nomem;
	memset(info->fb, 0, xenfb_mem_len);

	info->nr_pages = (xenfb_mem_len + PAGE_SIZE - 1) >> PAGE_SHIFT;

	info->pages = kmalloc(sizeof(struct page *) * info->nr_pages,
			      GFP_KERNEL);
	if (info->pages == NULL)
		goto error_nomem;

	info->mfns = vmalloc(sizeof(unsigned long) * info->nr_pages);
	if (!info->mfns)
		goto error_nomem;

	/* set up shared page */
	info->page = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!info->page)
		goto error_nomem;

	xenfb_init_shared_page(info);

	fb_info = framebuffer_alloc(sizeof(u32) * 256, NULL);
				/* see fishy hackery below */
	if (fb_info == NULL)
		goto error_nomem;

	/* FIXME fishy hackery */
	fb_info->pseudo_palette = fb_info->par;
	fb_info->par = info;
	/* /FIXME */
	fb_info->screen_base = info->fb;

	fb_info->fbops = &xenfb_fb_ops;
	fb_info->var.xres_virtual = fb_info->var.xres = info->page->width;
	fb_info->var.yres_virtual = fb_info->var.yres = info->page->height;
	fb_info->var.bits_per_pixel = info->page->depth;

	fb_info->var.red = (struct fb_bitfield){16, 8, 0};
	fb_info->var.green = (struct fb_bitfield){8, 8, 0};
	fb_info->var.blue = (struct fb_bitfield){0, 8, 0};

	fb_info->var.activate = FB_ACTIVATE_NOW;
	fb_info->var.height = -1;
	fb_info->var.width = -1;
	fb_info->var.vmode = FB_VMODE_NONINTERLACED;

	fb_info->fix.visual = FB_VISUAL_TRUECOLOR;
	fb_info->fix.line_length = info->page->line_length;
	fb_info->fix.smem_start = 0;
	fb_info->fix.smem_len = xenfb_mem_len;
	strcpy(fb_info->fix.id, "xen");
	fb_info->fix.type = FB_TYPE_PACKED_PIXELS;
	fb_info->fix.accel = FB_ACCEL_NONE;

	fb_info->flags = FBINFO_FLAG_DEFAULT;

	ret = fb_alloc_cmap(&fb_info->cmap, 256, 0);
	if (ret < 0) {
		framebuffer_release(fb_info);
		xenbus_dev_fatal(dev, ret, "fb_alloc_cmap");
		goto error;
	}

	ret = register_framebuffer(fb_info);
	if (ret) {
		fb_dealloc_cmap(&info->fb_info->cmap);
		framebuffer_release(fb_info);
		xenbus_dev_fatal(dev, ret, "register_framebuffer");
		goto error;
	}
	info->fb_info = fb_info;

	/* FIXME should this be delayed until backend XenbusStateConnected? */
	info->kthread = kthread_run(xenfb_thread, info, "xenfb thread");
	if (IS_ERR(info->kthread)) {
		ret = PTR_ERR(info->kthread);
		info->kthread = NULL;
		xenbus_dev_fatal(dev, ret, "register_framebuffer");
		goto error;
	}

	ret = xenfb_connect_backend(dev, info);
	if (ret < 0)
		goto error;

	return 0;

 error_nomem:
	ret = -ENOMEM;
	xenbus_dev_fatal(dev, ret, "allocating device memory");
 error:
	xenfb_remove(dev);
	return ret;
}

static int xenfb_resume(struct xenbus_device *dev)
{
	struct xenfb_info *info = dev->dev.driver_data;

	xenfb_disconnect_backend(info);
	xenfb_init_shared_page(info);
	return xenfb_connect_backend(dev, info);
}

static int xenfb_remove(struct xenbus_device *dev)
{
	struct xenfb_info *info = dev->dev.driver_data;

	del_timer(&info->refresh);
	if (info->kthread)
		kthread_stop(info->kthread);
	xenfb_disconnect_backend(info);
	if (info->fb_info) {
		unregister_framebuffer(info->fb_info);
		fb_dealloc_cmap(&info->fb_info->cmap);
		framebuffer_release(info->fb_info);
	}
	free_page((unsigned long)info->page);
	vfree(info->mfns);
	kfree(info->pages);
	vfree(info->fb);
	kfree(info);

	return 0;
}

static void xenfb_init_shared_page(struct xenfb_info *info)
{
	int i;

	for (i = 0; i < info->nr_pages; i++)
		info->pages[i] = vmalloc_to_page(info->fb + i * PAGE_SIZE);

	for (i = 0; i < info->nr_pages; i++)
		info->mfns[i] = vmalloc_to_mfn(info->fb + i * PAGE_SIZE);

	info->page->pd[0] = vmalloc_to_mfn(info->mfns);
	info->page->pd[1] = 0;
	info->page->width = XENFB_WIDTH;
	info->page->height = XENFB_HEIGHT;
	info->page->depth = XENFB_DEPTH;
	info->page->line_length = (info->page->depth / 8) * info->page->width;
	info->page->mem_length = xenfb_mem_len;
	info->page->in_cons = info->page->in_prod = 0;
	info->page->out_cons = info->page->out_prod = 0;
}

static int xenfb_connect_backend(struct xenbus_device *dev,
				 struct xenfb_info *info)
{
	int ret;
	struct xenbus_transaction xbt;

	ret = bind_listening_port_to_irqhandler(
		dev->otherend_id, xenfb_event_handler, 0, "xenfb", info);
	if (ret < 0) {
		xenbus_dev_fatal(dev, ret,
				 "bind_listening_port_to_irqhandler");
		return ret;
	}
	info->irq = ret;

 again:
	ret = xenbus_transaction_start(&xbt);
	if (ret) {
		xenbus_dev_fatal(dev, ret, "starting transaction");
		return ret;
	}
	ret = xenbus_printf(xbt, dev->nodename, "page-ref", "%lu",
			    virt_to_mfn(info->page));
	if (ret)
		goto error_xenbus;
	ret = xenbus_printf(xbt, dev->nodename, "event-channel", "%u",
			    irq_to_evtchn_port(info->irq));
	if (ret)
		goto error_xenbus;
	ret = xenbus_printf(xbt, dev->nodename, "protocol", "%s",
			    XEN_IO_PROTO_ABI_NATIVE);
	if (ret)
		goto error_xenbus;
	ret = xenbus_printf(xbt, dev->nodename, "feature-update", "1");
	if (ret)
		goto error_xenbus;
	ret = xenbus_transaction_end(xbt, 0);
	if (ret) {
		if (ret == -EAGAIN)
			goto again;
		xenbus_dev_fatal(dev, ret, "completing transaction");
		return ret;
	}

	xenbus_switch_state(dev, XenbusStateInitialised);
	return 0;

 error_xenbus:
	xenbus_transaction_end(xbt, 1);
	xenbus_dev_fatal(dev, ret, "writing xenstore");
	return ret;
}

static void xenfb_disconnect_backend(struct xenfb_info *info)
{
	if (info->irq >= 0)
		unbind_from_irqhandler(info->irq, info);
	info->irq = -1;
}

static void xenfb_backend_changed(struct xenbus_device *dev,
				  enum xenbus_state backend_state)
{
	struct xenfb_info *info = dev->dev.driver_data;
	int val;

	switch (backend_state) {
	case XenbusStateInitialising:
	case XenbusStateInitialised:
	case XenbusStateUnknown:
	case XenbusStateClosed:
		break;

	case XenbusStateInitWait:
	InitWait:
		xenbus_switch_state(dev, XenbusStateConnected);
		break;

	case XenbusStateConnected:
		/*
		 * Work around xenbus race condition: If backend goes
		 * through InitWait to Connected fast enough, we can
		 * get Connected twice here.
		 */
		if (dev->state != XenbusStateConnected)
			goto InitWait; /* no InitWait seen yet, fudge it */

		if (xenbus_scanf(XBT_NIL, info->xbdev->otherend,
				 "request-update", "%d", &val) < 0)
			val = 0;
		if (val)
			info->update_wanted = 1;
		break;

	case XenbusStateClosing:
		// FIXME is this safe in any dev->state?
		xenbus_frontend_closed(dev);
		break;
	}
}

static struct xenbus_device_id xenfb_ids[] = {
	{ "vfb" },
	{ "" }
};

static struct xenbus_driver xenfb = {
	.name = "vfb",
	.owner = THIS_MODULE,
	.ids = xenfb_ids,
	.probe = xenfb_probe,
	.remove = xenfb_remove,
	.resume = xenfb_resume,
	.otherend_changed = xenfb_backend_changed,
};

static int __init xenfb_init(void)
{
	if (!is_running_on_xen())
		return -ENODEV;

	/* Nothing to do if running in dom0. */
	if (is_initial_xendomain())
		return -ENODEV;

	return xenbus_register_frontend(&xenfb);
}

static void __exit xenfb_cleanup(void)
{
	return xenbus_unregister_driver(&xenfb);
}

module_init(xenfb_init);
module_exit(xenfb_cleanup);

MODULE_LICENSE("GPL");
