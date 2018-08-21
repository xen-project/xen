/******************************************************************************
 * gntdev.h
 * 
 * Interface to /dev/xen/gntdev.
 * 
 * Copyright (c) 2007, D G Murray
 * Copyright (c) 2018, Oleksandr Andrushchenko, EPAM Systems Inc.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef __LINUX_PUBLIC_GNTDEV_H__
#define __LINUX_PUBLIC_GNTDEV_H__

struct ioctl_gntdev_grant_ref {
	/* The domain ID of the grant to be mapped. */
	uint32_t domid;
	/* The grant reference of the grant to be mapped. */
	uint32_t ref;
};

/*
 * Inserts the grant references into the mapping table of an instance
 * of gntdev. N.B. This does not perform the mapping, which is deferred
 * until mmap() is called with @index as the offset.
 */
#define IOCTL_GNTDEV_MAP_GRANT_REF \
_IOC(_IOC_NONE, 'G', 0, sizeof(struct ioctl_gntdev_map_grant_ref))
struct ioctl_gntdev_map_grant_ref {
	/* IN parameters */
	/* The number of grants to be mapped. */
	uint32_t count;
	uint32_t pad;
	/* OUT parameters */
	/* The offset to be used on a subsequent call to mmap(). */
	uint64_t index;
	/* Variable IN parameter. */
	/* Array of grant references, of size @count. */
	struct ioctl_gntdev_grant_ref refs[1];
};

/*
 * Removes the grant references from the mapping table of an instance of
 * of gntdev. N.B. munmap() must be called on the relevant virtual address(es)
 * before this ioctl is called, or an error will result.
 */
#define IOCTL_GNTDEV_UNMAP_GRANT_REF \
_IOC(_IOC_NONE, 'G', 1, sizeof(struct ioctl_gntdev_unmap_grant_ref))
struct ioctl_gntdev_unmap_grant_ref {
	/* IN parameters */
	/* The offset was returned by the corresponding map operation. */
	uint64_t index;
	/* The number of pages to be unmapped. */
	uint32_t count;
	uint32_t pad;
};

/*
 * Returns the offset in the driver's address space that corresponds
 * to @vaddr. This can be used to perform a munmap(), followed by an
 * UNMAP_GRANT_REF ioctl, where no state about the offset is retained by
 * the caller. The number of pages that were allocated at the same time as
 * @vaddr is returned in @count.
 *
 * N.B. Where more than one page has been mapped into a contiguous range, the
 *      supplied @vaddr must correspond to the start of the range; otherwise
 *      an error will result. It is only possible to munmap() the entire
 *      contiguously-allocated range at once, and not any subrange thereof.
 */
#define IOCTL_GNTDEV_GET_OFFSET_FOR_VADDR \
_IOC(_IOC_NONE, 'G', 2, sizeof(struct ioctl_gntdev_get_offset_for_vaddr))
struct ioctl_gntdev_get_offset_for_vaddr {
	/* IN parameters */
	/* The virtual address of the first mapped page in a range. */
	uint64_t vaddr;
	/* OUT parameters */
	/* The offset that was used in the initial mmap() operation. */
	uint64_t offset;
	/* The number of pages mapped in the VM area that begins at @vaddr. */
	uint32_t count;
	uint32_t pad;
};

/*
 * Sets the maximum number of grants that may mapped at once by this gntdev
 * instance.
 *
 * N.B. This must be called before any other ioctl is performed on the device.
 */
#define IOCTL_GNTDEV_SET_MAX_GRANTS \
_IOC(_IOC_NONE, 'G', 3, sizeof(struct ioctl_gntdev_set_max_grants))
struct ioctl_gntdev_set_max_grants {
	/* IN parameter */
	/* The maximum number of grants that may be mapped at once. */
	uint32_t count;
};

/*
 * Sets up an unmap notification within the page, so that the other side can do
 * cleanup if this side crashes. Required to implement cross-domain robust
 * mutexes or close notification on communication channels.
 *
 * Each mapped page only supports one notification; multiple calls referring to
 * the same page overwrite the previous notification. You must clear the
 * notification prior to the IOCTL_GNTALLOC_DEALLOC_GREF if you do not want it
 * to occur.
 */
#define IOCTL_GNTDEV_SET_UNMAP_NOTIFY \
_IOC(_IOC_NONE, 'G', 7, sizeof(struct ioctl_gntdev_unmap_notify))
struct ioctl_gntdev_unmap_notify {
	/* IN parameters */
	/* Offset in the file descriptor for a byte within the page. This offset
	 * is the result of the IOCTL_GNTDEV_MAP_GRANT_REF and is the same as
	 * is used with mmap(). If using UNMAP_NOTIFY_CLEAR_BYTE, this is the byte
	 * within the page to be cleared.
	 */
	uint64_t index;
	/* Action(s) to take on unmap */
	uint32_t action;
	/* Event channel to notify */
	uint32_t event_channel_port;
};

/* Clear (set to zero) the byte specified by index */
#define UNMAP_NOTIFY_CLEAR_BYTE 0x1
/* Send an interrupt on the indicated event channel */
#define UNMAP_NOTIFY_SEND_EVENT 0x2

struct ioctl_gntdev_grant_copy_segment {
    union {
        void *virt;
        struct {
            uint32_t ref;
            uint16_t offset;
            uint16_t domid;
        } foreign;
    } source, dest;
    uint16_t len;
    uint16_t flags;
    int16_t status;
};

#define IOCTL_GNTDEV_GRANT_COPY \
_IOC(_IOC_NONE, 'G', 8, sizeof(struct ioctl_gntdev_grant_copy))
struct ioctl_gntdev_grant_copy {
    unsigned int count;
    struct ioctl_gntdev_grant_copy_segment *segments;
};

/*
 * Flags to be used while requesting memory mapping's backing storage
 * to be allocated with DMA API.
 */

/*
 * The buffer is backed with memory allocated with dma_alloc_wc.
 */
#define GNTDEV_DMA_FLAG_WC		(1 << 0)

/*
 * The buffer is backed with memory allocated with dma_alloc_coherent.
 */
#define GNTDEV_DMA_FLAG_COHERENT	(1 << 1)

/*
 * Create a dma-buf [1] from grant references @refs of count @count provided
 * by the foreign domain @domid with flags @flags.
 *
 * By default dma-buf is backed by system memory pages, but by providing
 * one of the GNTDEV_DMA_FLAG_XXX flags it can also be created as
 * a DMA write-combine or coherent buffer, e.g. allocated with dma_alloc_wc/
 * dma_alloc_coherent.
 *
 * Returns 0 if dma-buf was successfully created and the corresponding
 * dma-buf's file descriptor is returned in @fd.
 *
 * [1] https://elixir.bootlin.com/linux/latest/source/Documentation/driver-api/dma-buf.rst
 */

#define IOCTL_GNTDEV_DMABUF_EXP_FROM_REFS \
    _IOC(_IOC_NONE, 'G', 9, \
         sizeof(struct ioctl_gntdev_dmabuf_exp_from_refs))
struct ioctl_gntdev_dmabuf_exp_from_refs {
    /* IN parameters. */
    /* Specific options for this dma-buf: see GNTDEV_DMABUF_FLAG_XXX. */
    uint32_t flags;
    /* Number of grant references in @refs array. */
    uint32_t count;
    /* OUT parameters. */
    /* File descriptor of the dma-buf. */
    uint32_t fd;
    /* The domain ID of the grant references to be mapped. */
    uint32_t domid;
    /* Variable IN parameter. */
    /* Array of grant references of size @count. */
    uint32_t refs[1];
};

/*
 * This will block until the dma-buf with the file descriptor @fd is
 * released. This is only valid for buffers created with
 * IOCTL_GNTDEV_DMABUF_EXP_FROM_REFS.
 *
 * If withing @wait_to_ms milliseconds the buffer is not released
 * then -ETIMEDOUT error is returned.
 * If the buffer with file descriptor @fd does not exist or has already
 * been released, then -ENOENT is returned. For valid file descriptors
 * this must not be treated as error.
 */
#define IOCTL_GNTDEV_DMABUF_EXP_WAIT_RELEASED \
    _IOC(_IOC_NONE, 'G', 10, \
         sizeof(struct ioctl_gntdev_dmabuf_exp_wait_released))
struct ioctl_gntdev_dmabuf_exp_wait_released {
    /* IN parameters */
    uint32_t fd;
    uint32_t wait_to_ms;
};

/*
 * Import a dma-buf with file descriptor @fd and export granted references
 * to the pages of that dma-buf into array @refs of size @count.
 */
#define IOCTL_GNTDEV_DMABUF_IMP_TO_REFS \
    _IOC(_IOC_NONE, 'G', 11, \
         sizeof(struct ioctl_gntdev_dmabuf_imp_to_refs))
struct ioctl_gntdev_dmabuf_imp_to_refs {
    /* IN parameters. */
    /* File descriptor of the dma-buf. */
    uint32_t fd;
    /* Number of grant references in @refs array. */
    uint32_t count;
    /* The domain ID for which references to be granted. */
    uint32_t domid;
    /* Reserved - must be zero. */
    uint32_t reserved;
    /* OUT parameters. */
    /* Array of grant references of size @count. */
    uint32_t refs[1];
};

/*
 * This will close all references to an imported buffer, so it can be
 * released by the owner. This is only valid for buffers created with
 * IOCTL_GNTDEV_DMABUF_IMP_TO_REFS.
 */
#define IOCTL_GNTDEV_DMABUF_IMP_RELEASE \
    _IOC(_IOC_NONE, 'G', 12, \
         sizeof(struct ioctl_gntdev_dmabuf_imp_release))
struct ioctl_gntdev_dmabuf_imp_release {
    /* IN parameters */
    uint32_t fd;
    uint32_t reserved;
};

#endif /* __LINUX_PUBLIC_GNTDEV_H__ */
