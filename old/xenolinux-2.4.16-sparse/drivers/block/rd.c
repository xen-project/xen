/*
 * ramdisk.c - Multiple RAM disk driver - gzip-loading version - v. 0.8 beta.
 * 
 * (C) Chad Page, Theodore Ts'o, et. al, 1995. 
 *
 * This RAM disk is designed to have filesystems created on it and mounted
 * just like a regular floppy disk.  
 *  
 * It also does something suggested by Linus: use the buffer cache as the
 * RAM disk data.  This makes it possible to dynamically allocate the RAM disk
 * buffer - with some consequences I have to deal with as I write this. 
 * 
 * This code is based on the original ramdisk.c, written mostly by
 * Theodore Ts'o (TYT) in 1991.  The code was largely rewritten by
 * Chad Page to use the buffer cache to store the RAM disk data in
 * 1995; Theodore then took over the driver again, and cleaned it up
 * for inclusion in the mainline kernel.
 *
 * The original CRAMDISK code was written by Richard Lyons, and
 * adapted by Chad Page to use the new RAM disk interface.  Theodore
 * Ts'o rewrote it so that both the compressed RAM disk loader and the
 * kernel decompressor uses the same inflate.c codebase.  The RAM disk
 * loader now also loads into a dynamic (buffer cache based) RAM disk,
 * not the old static RAM disk.  Support for the old static RAM disk has
 * been completely removed.
 *
 * Loadable module support added by Tom Dyas.
 *
 * Further cleanups by Chad Page (page0588@sundance.sjsu.edu):
 *	Cosmetic changes in #ifdef MODULE, code movement, etc.
 * 	When the RAM disk module is removed, free the protected buffers
 * 	Default RAM disk size changed to 2.88 MB
 *
 *  Added initrd: Werner Almesberger & Hans Lermen, Feb '96
 *
 * 4/25/96 : Made RAM disk size a parameter (default is now 4 MB) 
 *		- Chad Page
 *
 * Add support for fs images split across >1 disk, Paul Gortmaker, Mar '98
 *
 * Make block size and block size shift for RAM disks a global macro
 * and set blk_size for -ENOSPC,     Werner Fink <werner@suse.de>, Apr '99
 */

#include <linux/config.h>
#include <linux/sched.h>
#include <linux/minix_fs.h>
#include <linux/ext2_fs.h>
#include <linux/romfs_fs.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/hdreg.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/ioctl.h>
#include <linux/fd.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/devfs_fs_kernel.h>
#include <linux/smp_lock.h>

#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/byteorder.h>

extern void wait_for_keypress(void);

/*
 * 35 has been officially registered as the RAMDISK major number, but
 * so is the original MAJOR number of 1.  We're using 1 in
 * include/linux/major.h for now
 */
#define MAJOR_NR RAMDISK_MAJOR
#include <linux/blk.h>
#include <linux/blkpg.h>

/* The RAM disk size is now a parameter */
#define NUM_RAMDISKS 16		/* This cannot be overridden (yet) */ 

#ifndef MODULE
/* We don't have to load RAM disks or gunzip them in a module. */
#define RD_LOADER
#define BUILD_CRAMDISK

void rd_load(void);
static int crd_load(struct file *fp, struct file *outfp);

#ifdef CONFIG_BLK_DEV_INITRD
static int initrd_users;
#endif
#endif

/* Various static variables go here.  Most are used only in the RAM disk code.
 */

static unsigned long rd_length[NUM_RAMDISKS];	/* Size of RAM disks in bytes   */
static int rd_hardsec[NUM_RAMDISKS];		/* Size of real blocks in bytes */
static int rd_blocksizes[NUM_RAMDISKS];		/* Size of 1024 byte blocks :)  */
static int rd_kbsize[NUM_RAMDISKS];		/* Size in blocks of 1024 bytes */
static devfs_handle_t devfs_handle;
static struct block_device *rd_bdev[NUM_RAMDISKS];/* Protected device data */

/*
 * Parameters for the boot-loading of the RAM disk.  These are set by
 * init/main.c (from arguments to the kernel command line) or from the
 * architecture-specific setup routine (from the stored boot sector
 * information). 
 */
int rd_size = CONFIG_BLK_DEV_RAM_SIZE;		/* Size of the RAM disks */
/*
 * It would be very desiderable to have a soft-blocksize (that in the case
 * of the ramdisk driver is also the hardblocksize ;) of PAGE_SIZE because
 * doing that we'll achieve a far better MM footprint. Using a rd_blocksize of
 * BLOCK_SIZE in the worst case we'll make PAGE_SIZE/BLOCK_SIZE buffer-pages
 * unfreeable. With a rd_blocksize of PAGE_SIZE instead we are sure that only
 * 1 page will be protected. Depending on the size of the ramdisk you
 * may want to change the ramdisk blocksize to achieve a better or worse MM
 * behaviour. The default is still BLOCK_SIZE (needed by rd_load_image that
 * supposes the filesystem in the image uses a BLOCK_SIZE blocksize).
 */
int rd_blocksize = BLOCK_SIZE;			/* blocksize of the RAM disks */

#ifndef MODULE

int rd_doload;			/* 1 = load RAM disk, 0 = don't load */
int rd_prompt = 1;		/* 1 = prompt for RAM disk, 0 = don't prompt */
int rd_image_start;		/* starting block # of image */
#ifdef CONFIG_BLK_DEV_INITRD
unsigned long initrd_start, initrd_end;
int mount_initrd = 1;		/* zero if initrd should not be mounted */
int initrd_below_start_ok;

static int __init no_initrd(char *str)
{
	mount_initrd = 0;
	return 1;
}

__setup("noinitrd", no_initrd);

#endif

static int __init ramdisk_start_setup(char *str)
{
	rd_image_start = simple_strtol(str,NULL,0);
	return 1;
}

static int __init load_ramdisk(char *str)
{
	rd_doload = simple_strtol(str,NULL,0) & 3;
	return 1;
}

static int __init prompt_ramdisk(char *str)
{
	rd_prompt = simple_strtol(str,NULL,0) & 1;
	return 1;
}

static int __init ramdisk_size(char *str)
{
	rd_size = simple_strtol(str,NULL,0);
	return 1;
}

static int __init ramdisk_size2(char *str)
{
	return ramdisk_size(str);
}

static int __init ramdisk_blocksize(char *str)
{
	rd_blocksize = simple_strtol(str,NULL,0);
	return 1;
}

__setup("ramdisk_start=", ramdisk_start_setup);
__setup("load_ramdisk=", load_ramdisk);
__setup("prompt_ramdisk=", prompt_ramdisk);
__setup("ramdisk=", ramdisk_size);
__setup("ramdisk_size=", ramdisk_size2);
__setup("ramdisk_blocksize=", ramdisk_blocksize);

#endif

/*
 * Copyright (C) 2000 Linus Torvalds.
 *               2000 Transmeta Corp.
 * aops copied from ramfs.
 */
static int ramdisk_readpage(struct file *file, struct page * page)
{
	if (!Page_Uptodate(page)) {
		memset(kmap(page), 0, PAGE_CACHE_SIZE);
		kunmap(page);
		flush_dcache_page(page);
		SetPageUptodate(page);
	}
	UnlockPage(page);
	return 0;
}

static int ramdisk_prepare_write(struct file *file, struct page *page, unsigned offset, unsigned to)
{
	if (!Page_Uptodate(page)) {
		void *addr = page_address(page);
		memset(addr, 0, PAGE_CACHE_SIZE);
		flush_dcache_page(page);
		SetPageUptodate(page);
	}
	SetPageDirty(page);
	return 0;
}

static int ramdisk_commit_write(struct file *file, struct page *page, unsigned offset, unsigned to)
{
	return 0;
}

static struct address_space_operations ramdisk_aops = {
	readpage: ramdisk_readpage,
	writepage: fail_writepage,
	prepare_write: ramdisk_prepare_write,
	commit_write: ramdisk_commit_write,
};

static int rd_blkdev_pagecache_IO(int rw, struct buffer_head * sbh, int minor)
{
	struct address_space * mapping;
	unsigned long index;
	int offset, size, err;

	err = -EIO;
	err = 0;
	mapping = rd_bdev[minor]->bd_inode->i_mapping;

	index = sbh->b_rsector >> (PAGE_CACHE_SHIFT - 9);
	offset = (sbh->b_rsector << 9) & ~PAGE_CACHE_MASK;
	size = sbh->b_size;

	do {
		int count;
		struct page ** hash;
		struct page * page;
		char * src, * dst;
		int unlock = 0;

		count = PAGE_CACHE_SIZE - offset;
		if (count > size)
			count = size;
		size -= count;

		hash = page_hash(mapping, index);
		page = __find_get_page(mapping, index, hash);
		if (!page) {
			page = grab_cache_page(mapping, index);
			err = -ENOMEM;
			if (!page)
				goto out;
			err = 0;

			if (!Page_Uptodate(page)) {
				memset(kmap(page), 0, PAGE_CACHE_SIZE);
				kunmap(page);
				SetPageUptodate(page);
			}

			unlock = 1;
		}

		index++;

		if (rw == READ) {
			src = kmap(page);
			src += offset;
			dst = bh_kmap(sbh);
		} else {
			dst = kmap(page);
			dst += offset;
			src = bh_kmap(sbh);
		}
		offset = 0;

		memcpy(dst, src, count);

		kunmap(page);
		bh_kunmap(sbh);

		if (rw == READ) {
			flush_dcache_page(page);
		} else {
			SetPageDirty(page);
		}
		if (unlock)
			UnlockPage(page);
		__free_page(page);
	} while (size);

 out:
	return err;
}

/*
 *  Basically, my strategy here is to set up a buffer-head which can't be
 *  deleted, and make that my Ramdisk.  If the request is outside of the
 *  allocated size, we must get rid of it...
 *
 * 19-JAN-1998  Richard Gooch <rgooch@atnf.csiro.au>  Added devfs support
 *
 */
static int rd_make_request(request_queue_t * q, int rw, struct buffer_head *sbh)
{
	unsigned int minor;
	unsigned long offset, len;

	minor = MINOR(sbh->b_rdev);

	if (minor >= NUM_RAMDISKS)
		goto fail;

	
	offset = sbh->b_rsector << 9;
	len = sbh->b_size;

	if ((offset + len) > rd_length[minor])
		goto fail;

	if (rw==READA)
		rw=READ;
	if ((rw != READ) && (rw != WRITE)) {
		printk(KERN_INFO "RAMDISK: bad command: %d\n", rw);
		goto fail;
	}

	if (rd_blkdev_pagecache_IO(rw, sbh, minor))
		goto fail;

	sbh->b_end_io(sbh,1);
	return 0;
 fail:
	sbh->b_end_io(sbh,0);
	return 0;
} 

static int rd_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
	int error = -EINVAL;
	unsigned int minor;

	if (!inode || !inode->i_rdev) 	
		goto out;

	minor = MINOR(inode->i_rdev);

	switch (cmd) {
		case BLKFLSBUF:
			if (!capable(CAP_SYS_ADMIN))
				return -EACCES;
			/* special: we want to release the ramdisk memory,
			   it's not like with the other blockdevices where
			   this ioctl only flushes away the buffer cache. */
			error = -EBUSY;
			down(&inode->i_bdev->bd_sem);
			if (inode->i_bdev->bd_openers <= 2) {
				truncate_inode_pages(inode->i_mapping, 0);
				error = 0;
			}
			up(&inode->i_bdev->bd_sem);
			break;
         	case BLKGETSIZE:   /* Return device size */
			if (!arg)
				break;
			error = put_user(rd_kbsize[minor] << 1, (unsigned long *) arg);
			break;
         	case BLKGETSIZE64:
			error = put_user((u64)rd_kbsize[minor]<<10, (u64*)arg);
			break;
		case BLKROSET:
		case BLKROGET:
		case BLKSSZGET:
			error = blk_ioctl(inode->i_rdev, cmd, arg);
	};
out:
	return error;
}


#ifdef CONFIG_BLK_DEV_INITRD

static ssize_t initrd_read(struct file *file, char *buf,
			   size_t count, loff_t *ppos)
{
	int left;

	left = initrd_end - initrd_start - *ppos;
	if (count > left) count = left;
	if (count == 0) return 0;
	copy_to_user(buf, (char *)initrd_start + *ppos, count);
	*ppos += count;
	return count;
}


static int initrd_release(struct inode *inode,struct file *file)
{
	extern void free_initrd_mem(unsigned long, unsigned long);

	lock_kernel();
	if (!--initrd_users) {
		free_initrd_mem(initrd_start, initrd_end);
		initrd_start = 0;
	}
	unlock_kernel();
	blkdev_put(inode->i_bdev, BDEV_FILE);
	return 0;
}


static struct file_operations initrd_fops = {
	read:		initrd_read,
	release:	initrd_release,
};

#endif


static int rd_open(struct inode * inode, struct file * filp)
{
	int unit = DEVICE_NR(inode->i_rdev);

#ifdef CONFIG_BLK_DEV_INITRD
	if (unit == INITRD_MINOR) {
		if (!initrd_start) return -ENODEV;
		initrd_users++;
		filp->f_op = &initrd_fops;
		return 0;
	}
#endif

	if (unit >= NUM_RAMDISKS)
		return -ENXIO;

	/*
	 * Immunize device against invalidate_buffers() and prune_icache().
	 */
	if (rd_bdev[unit] == NULL) {
		rd_bdev[unit] = bdget(kdev_t_to_nr(inode->i_rdev));
		rd_bdev[unit]->bd_openers++;
		rd_bdev[unit]->bd_inode->i_mapping->a_ops = &ramdisk_aops;
	}

	return 0;
}

static struct block_device_operations rd_bd_op = {
	owner:		THIS_MODULE,
	open:		rd_open,
	ioctl:		rd_ioctl,
};

#ifdef MODULE
/* Before freeing the module, invalidate all of the protected buffers! */
static void __exit rd_cleanup (void)
{
	int i;

	for (i = 0 ; i < NUM_RAMDISKS; i++) {
		struct block_device *bdev = rd_bdev[i];
		rd_bdev[i] = NULL;
		if (bdev)
			blkdev_put(bdev, BDEV_FILE);
		destroy_buffers(MKDEV(MAJOR_NR, i));
	}

	devfs_unregister (devfs_handle);
	unregister_blkdev( MAJOR_NR, "ramdisk" );
	hardsect_size[MAJOR_NR] = NULL;
	blksize_size[MAJOR_NR] = NULL;
	blk_size[MAJOR_NR] = NULL;
}
#endif

/* This is the registration and initialization section of the RAM disk driver */
int __init rd_init (void)
{
	int		i;

	if (rd_blocksize > PAGE_SIZE || rd_blocksize < 512 ||
	    (rd_blocksize & (rd_blocksize-1)))
	{
		printk("RAMDISK: wrong blocksize %d, reverting to defaults\n",
		       rd_blocksize);
		rd_blocksize = BLOCK_SIZE;
	}

	if (register_blkdev(MAJOR_NR, "ramdisk", &rd_bd_op)) {
		printk("RAMDISK: Could not get major %d", MAJOR_NR);
		return -EIO;
	}

	blk_queue_make_request(BLK_DEFAULT_QUEUE(MAJOR_NR), &rd_make_request);

	for (i = 0; i < NUM_RAMDISKS; i++) {
		/* rd_size is given in kB */
		rd_length[i] = rd_size << 10;
		rd_hardsec[i] = rd_blocksize;
		rd_blocksizes[i] = rd_blocksize;
		rd_kbsize[i] = rd_size;
	}
	devfs_handle = devfs_mk_dir (NULL, "rd", NULL);
	devfs_register_series (devfs_handle, "%u", NUM_RAMDISKS,
			       DEVFS_FL_DEFAULT, MAJOR_NR, 0,
			       S_IFBLK | S_IRUSR | S_IWUSR,
			       &rd_bd_op, NULL);

	for (i = 0; i < NUM_RAMDISKS; i++)
		register_disk(NULL, MKDEV(MAJOR_NR,i), 1, &rd_bd_op, rd_size<<1);

#ifdef CONFIG_BLK_DEV_INITRD
	/* We ought to separate initrd operations here */
	register_disk(NULL, MKDEV(MAJOR_NR,INITRD_MINOR), 1, &rd_bd_op, rd_size<<1);
#endif

	hardsect_size[MAJOR_NR] = rd_hardsec;		/* Size of the RAM disk blocks */
	blksize_size[MAJOR_NR] = rd_blocksizes;		/* Avoid set_blocksize() check */
	blk_size[MAJOR_NR] = rd_kbsize;			/* Size of the RAM disk in kB  */

		/* rd_size is given in kB */
	printk("RAMDISK driver initialized: "
	       "%d RAM disks of %dK size %d blocksize\n",
	       NUM_RAMDISKS, rd_size, rd_blocksize);

	return 0;
}

#ifdef MODULE
module_init(rd_init);
module_exit(rd_cleanup);
#endif

/* loadable module support */
MODULE_PARM     (rd_size, "1i");
MODULE_PARM_DESC(rd_size, "Size of each RAM disk in kbytes.");
MODULE_PARM     (rd_blocksize, "i");
MODULE_PARM_DESC(rd_blocksize, "Blocksize of each RAM disk in bytes.");

MODULE_LICENSE("GPL");

/* End of non-loading portions of the RAM disk driver */

#ifdef RD_LOADER 
/*
 * This routine tries to find a RAM disk image to load, and returns the
 * number of blocks to read for a non-compressed image, 0 if the image
 * is a compressed image, and -1 if an image with the right magic
 * numbers could not be found.
 *
 * We currently check for the following magic numbers:
 * 	minix
 * 	ext2
 *	romfs
 * 	gzip
 */
static int __init 
identify_ramdisk_image(kdev_t device, struct file *fp, int start_block)
{
	const int size = 512;
	struct minix_super_block *minixsb;
	struct ext2_super_block *ext2sb;
	struct romfs_super_block *romfsb;
	int nblocks = -1;
	unsigned char *buf;

	buf = kmalloc(size, GFP_KERNEL);
	if (buf == 0)
		return -1;

	minixsb = (struct minix_super_block *) buf;
	ext2sb = (struct ext2_super_block *) buf;
	romfsb = (struct romfs_super_block *) buf;
	memset(buf, 0xe5, size);

	/*
	 * Read block 0 to test for gzipped kernel
	 */
	if (fp->f_op->llseek)
		fp->f_op->llseek(fp, start_block * BLOCK_SIZE, 0);
	fp->f_pos = start_block * BLOCK_SIZE;
	
	fp->f_op->read(fp, buf, size, &fp->f_pos);

	/*
	 * If it matches the gzip magic numbers, return -1
	 */
	if (buf[0] == 037 && ((buf[1] == 0213) || (buf[1] == 0236))) {
		printk(KERN_NOTICE
		       "RAMDISK: Compressed image found at block %d\n",
		       start_block);
		nblocks = 0;
		goto done;
	}

	/* romfs is at block zero too */
	if (romfsb->word0 == ROMSB_WORD0 &&
	    romfsb->word1 == ROMSB_WORD1) {
		printk(KERN_NOTICE
		       "RAMDISK: romfs filesystem found at block %d\n",
		       start_block);
		nblocks = (ntohl(romfsb->size)+BLOCK_SIZE-1)>>BLOCK_SIZE_BITS;
		goto done;
	}

	/*
	 * Read block 1 to test for minix and ext2 superblock
	 */
	if (fp->f_op->llseek)
		fp->f_op->llseek(fp, (start_block+1) * BLOCK_SIZE, 0);
	fp->f_pos = (start_block+1) * BLOCK_SIZE;

	fp->f_op->read(fp, buf, size, &fp->f_pos);
		
	/* Try minix */
	if (minixsb->s_magic == MINIX_SUPER_MAGIC ||
	    minixsb->s_magic == MINIX_SUPER_MAGIC2) {
		printk(KERN_NOTICE
		       "RAMDISK: Minix filesystem found at block %d\n",
		       start_block);
		nblocks = minixsb->s_nzones << minixsb->s_log_zone_size;
		goto done;
	}

	/* Try ext2 */
	if (ext2sb->s_magic == cpu_to_le16(EXT2_SUPER_MAGIC)) {
		printk(KERN_NOTICE
		       "RAMDISK: ext2 filesystem found at block %d\n",
		       start_block);
		nblocks = le32_to_cpu(ext2sb->s_blocks_count);
		goto done;
	}

	printk(KERN_NOTICE
	       "RAMDISK: Couldn't find valid RAM disk image starting at %d.\n",
	       start_block);
	
done:
	if (fp->f_op->llseek)
		fp->f_op->llseek(fp, start_block * BLOCK_SIZE, 0);
	fp->f_pos = start_block * BLOCK_SIZE;	

	kfree(buf);
	return nblocks;
}

/*
 * This routine loads in the RAM disk image.
 */
static void __init rd_load_image(kdev_t device, int offset, int unit)
{
 	struct inode *inode, *out_inode;
	struct file infile, outfile;
	struct dentry in_dentry, out_dentry;
	mm_segment_t fs;
	kdev_t ram_device;
	int nblocks, i;
	char *buf;
	unsigned short rotate = 0;
	unsigned short devblocks = 0;
#if !defined(CONFIG_ARCH_S390) && !defined(CONFIG_PPC_ISERIES) && !defined(CONFIG_XENO)
	char rotator[4] = { '|' , '/' , '-' , '\\' };
#endif
	ram_device = MKDEV(MAJOR_NR, unit);

	if ((inode = get_empty_inode()) == NULL)
		return;
	memset(&infile, 0, sizeof(infile));
	memset(&in_dentry, 0, sizeof(in_dentry));
	infile.f_mode = 1; /* read only */
	infile.f_dentry = &in_dentry;
	in_dentry.d_inode = inode;
	infile.f_op = &def_blk_fops;
	init_special_inode(inode, S_IFBLK | S_IRUSR, kdev_t_to_nr(device));

	if ((out_inode = get_empty_inode()) == NULL)
		goto free_inode;
	memset(&outfile, 0, sizeof(outfile));
	memset(&out_dentry, 0, sizeof(out_dentry));
	outfile.f_mode = 3; /* read/write */
	outfile.f_dentry = &out_dentry;
	out_dentry.d_inode = out_inode;
	outfile.f_op = &def_blk_fops;
	init_special_inode(out_inode, S_IFBLK | S_IRUSR | S_IWUSR, kdev_t_to_nr(ram_device));

	if (blkdev_open(inode, &infile) != 0) {
		iput(out_inode);
		goto free_inode;
	}
	if (blkdev_open(out_inode, &outfile) != 0)
		goto free_inodes;

	fs = get_fs();
	set_fs(KERNEL_DS);
	
	nblocks = identify_ramdisk_image(device, &infile, offset);
	if (nblocks < 0)
		goto done;

	if (nblocks == 0) {
#ifdef BUILD_CRAMDISK
		if (crd_load(&infile, &outfile) == 0)
			goto successful_load;
#else
		printk(KERN_NOTICE
		       "RAMDISK: Kernel does not support compressed "
		       "RAM disk images\n");
#endif
		goto done;
	}

	/*
	 * NOTE NOTE: nblocks suppose that the blocksize is BLOCK_SIZE, so
	 * rd_load_image will work only with filesystem BLOCK_SIZE wide!
	 * So make sure to use 1k blocksize while generating ext2fs
	 * ramdisk-images.
	 */
	if (nblocks > (rd_length[unit] >> BLOCK_SIZE_BITS)) {
		printk("RAMDISK: image too big! (%d/%ld blocks)\n",
		       nblocks, rd_length[unit] >> BLOCK_SIZE_BITS);
		goto done;
	}
		
	/*
	 * OK, time to copy in the data
	 */
	buf = kmalloc(BLOCK_SIZE, GFP_KERNEL);
	if (buf == 0) {
		printk(KERN_ERR "RAMDISK: could not allocate buffer\n");
		goto done;
	}

	if (blk_size[MAJOR(device)])
		devblocks = blk_size[MAJOR(device)][MINOR(device)];

#ifdef CONFIG_BLK_DEV_INITRD
	if (MAJOR(device) == MAJOR_NR && MINOR(device) == INITRD_MINOR)
		devblocks = nblocks;
#endif

	if (devblocks == 0) {
		printk(KERN_ERR "RAMDISK: could not determine device size\n");
		goto done;
	}

	printk(KERN_NOTICE "RAMDISK: Loading %d blocks [%d disk%s] into ram disk... ", 
		nblocks, ((nblocks-1)/devblocks)+1, nblocks>devblocks ? "s" : "");
	for (i=0; i < nblocks; i++) {
		if (i && (i % devblocks == 0)) {
			printk("done disk #%d.\n", i/devblocks);
			rotate = 0;
			if (infile.f_op->release(inode, &infile) != 0) {
				printk("Error closing the disk.\n");
				goto noclose_input;
			}
			printk("Please insert disk #%d and press ENTER\n", i/devblocks+1);
			wait_for_keypress();
			if (blkdev_open(inode, &infile) != 0)  {
				printk("Error opening disk.\n");
				goto noclose_input;
			}
			infile.f_pos = 0;
			printk("Loading disk #%d... ", i/devblocks+1);
		}
		infile.f_op->read(&infile, buf, BLOCK_SIZE, &infile.f_pos);
		outfile.f_op->write(&outfile, buf, BLOCK_SIZE, &outfile.f_pos);
#if !defined(CONFIG_ARCH_S390) && !defined(CONFIG_PPC_ISERIES) && !defined(CONFIG_XENO)
		if (!(i % 16)) {
			printk("%c\b", rotator[rotate & 0x3]);
			rotate++;
		}
#endif
	}
	printk("done.\n");
	kfree(buf);

successful_load:
	ROOT_DEV = MKDEV(MAJOR_NR, unit);
	if (ROOT_DEVICE_NAME != NULL) strcpy (ROOT_DEVICE_NAME, "rd/0");

done:
	infile.f_op->release(inode, &infile);
noclose_input:
	blkdev_close(out_inode, &outfile);
	iput(inode);
	iput(out_inode);
	set_fs(fs);
	return;
free_inodes: /* free inodes on error */ 
	iput(out_inode);
	infile.f_op->release(inode, &infile);
free_inode:
	iput(inode);
}

#ifdef CONFIG_MAC_FLOPPY
int swim3_fd_eject(int devnum);
#endif

static void __init rd_load_disk(int n)
{

	if (rd_doload == 0)
		return;

	if (MAJOR(ROOT_DEV) != FLOPPY_MAJOR
#ifdef CONFIG_BLK_DEV_INITRD
		&& MAJOR(real_root_dev) != FLOPPY_MAJOR
#endif
	)
		return;

	if (rd_prompt) {
#ifdef CONFIG_BLK_DEV_FD
		floppy_eject();
#endif
#ifdef CONFIG_MAC_FLOPPY
		if(MAJOR(ROOT_DEV) == FLOPPY_MAJOR)
			swim3_fd_eject(MINOR(ROOT_DEV));
		else if(MAJOR(real_root_dev) == FLOPPY_MAJOR)
			swim3_fd_eject(MINOR(real_root_dev));
#endif
		printk(KERN_NOTICE
		       "VFS: Insert root floppy disk to be loaded into RAM disk and press ENTER\n");
		wait_for_keypress();
	}

	rd_load_image(ROOT_DEV,rd_image_start, n);

}

void __init rd_load(void)
{
	rd_load_disk(0);
}

void __init rd_load_secondary(void)
{
	rd_load_disk(1);
}

#ifdef CONFIG_BLK_DEV_INITRD
void __init initrd_load(void)
{
	rd_load_image(MKDEV(MAJOR_NR, INITRD_MINOR),rd_image_start,0);
}
#endif

#endif /* RD_LOADER */

#ifdef BUILD_CRAMDISK

/*
 * gzip declarations
 */

#define OF(args)  args

#ifndef memzero
#define memzero(s, n)     memset ((s), 0, (n))
#endif

typedef unsigned char  uch;
typedef unsigned short ush;
typedef unsigned long  ulg;

#define INBUFSIZ 4096
#define WSIZE 0x8000    /* window size--must be a power of two, and */
			/*  at least 32K for zip's deflate method */

static uch *inbuf;
static uch *window;

static unsigned insize;  /* valid bytes in inbuf */
static unsigned inptr;   /* index of next byte to be processed in inbuf */
static unsigned outcnt;  /* bytes in output buffer */
static int exit_code;
static long bytes_out;
static struct file *crd_infp, *crd_outfp;

#define get_byte()  (inptr < insize ? inbuf[inptr++] : fill_inbuf())
		
/* Diagnostic functions (stubbed out) */
#define Assert(cond,msg)
#define Trace(x)
#define Tracev(x)
#define Tracevv(x)
#define Tracec(c,x)
#define Tracecv(c,x)

#define STATIC static

static int  fill_inbuf(void);
static void flush_window(void);
static void *malloc(int size);
static void free(void *where);
static void error(char *m);
static void gzip_mark(void **);
static void gzip_release(void **);

#include "../../lib/inflate.c"

static void __init *malloc(int size)
{
	return kmalloc(size, GFP_KERNEL);
}

static void __init free(void *where)
{
	kfree(where);
}

static void __init gzip_mark(void **ptr)
{
}

static void __init gzip_release(void **ptr)
{
}


/* ===========================================================================
 * Fill the input buffer. This is called only when the buffer is empty
 * and at least one byte is really needed.
 */
static int __init fill_inbuf(void)
{
	if (exit_code) return -1;
	
	insize = crd_infp->f_op->read(crd_infp, inbuf, INBUFSIZ,
				      &crd_infp->f_pos);
	if (insize == 0) return -1;

	inptr = 1;

	return inbuf[0];
}

/* ===========================================================================
 * Write the output window window[0..outcnt-1] and update crc and bytes_out.
 * (Used for the decompressed data only.)
 */
static void __init flush_window(void)
{
    ulg c = crc;         /* temporary variable */
    unsigned n;
    uch *in, ch;
    
    crd_outfp->f_op->write(crd_outfp, window, outcnt, &crd_outfp->f_pos);
    in = window;
    for (n = 0; n < outcnt; n++) {
	    ch = *in++;
	    c = crc_32_tab[((int)c ^ ch) & 0xff] ^ (c >> 8);
    }
    crc = c;
    bytes_out += (ulg)outcnt;
    outcnt = 0;
}

static void __init error(char *x)
{
	printk(KERN_ERR "%s", x);
	exit_code = 1;
}

static int __init 
crd_load(struct file * fp, struct file *outfp)
{
	int result;

	insize = 0;		/* valid bytes in inbuf */
	inptr = 0;		/* index of next byte to be processed in inbuf */
	outcnt = 0;		/* bytes in output buffer */
	exit_code = 0;
	bytes_out = 0;
	crc = (ulg)0xffffffffL; /* shift register contents */

	crd_infp = fp;
	crd_outfp = outfp;
	inbuf = kmalloc(INBUFSIZ, GFP_KERNEL);
	if (inbuf == 0) {
		printk(KERN_ERR "RAMDISK: Couldn't allocate gzip buffer\n");
		return -1;
	}
	window = kmalloc(WSIZE, GFP_KERNEL);
	if (window == 0) {
		printk(KERN_ERR "RAMDISK: Couldn't allocate gzip window\n");
		kfree(inbuf);
		return -1;
	}
	makecrc();
	result = gunzip();
	kfree(inbuf);
	kfree(window);
	return result;
}

#endif  /* BUILD_CRAMDISK */

