void grok_partitions(struct gendisk *dev, int drive, unsigned minors, long size)
{
	int i;
	int first_minor	= drive << dev->minor_shift;
	int end_minor	= first_minor + dev->max_p;

	if(!dev->sizes)
		blk_size[dev->major] = NULL;

	dev->part[first_minor].nr_sects = size;
#ifdef DEVFS_MUST_DIE
	/* No such device or no minors to use for partitions */
	if ( !size && dev->flags && (dev->flags[drive] & GENHD_FL_REMOVABLE) )
		devfs_register_partitions (dev, first_minor, 0);
#endif

	if (!size || minors == 1)
		return;

	if (dev->sizes) {
		dev->sizes[first_minor] = size >> (BLOCK_SIZE_BITS - 9);
		for (i = first_minor + 1; i < end_minor; i++)
			dev->sizes[i] = 0;
	}
	blk_size[dev->major] = dev->sizes;
#if 0
	/* XXX SMH: don't actually check partition details yet */
	check_partition(dev, MKDEV(dev->major, first_minor), 1 + first_minor);
#endif

 	/*
 	 * We need to set the sizes array before we will be able to access
 	 * any of the partitions on this device.
 	 */
	if (dev->sizes != NULL) {	/* optional safeguard in ll_rw_blk.c */
		for (i = first_minor; i < end_minor; i++)
			dev->sizes[i] = dev->part[i].nr_sects >> (BLOCK_SIZE_BITS - 9);
	}
}
