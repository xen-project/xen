/*
 * Extended boot option ROM support.
 *
 * Copyright IBM, Corp. 2007
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "vl.h"

/* Extended Boot ROM suport */

union extboot_cmd
{
    uint16_t type;
    struct {
	uint16_t type;
	uint16_t cylinders;
	uint16_t heads;
	uint16_t sectors;
    } query_geometry;
    struct {
	uint16_t type;
	uint16_t nb_sectors;
	uint16_t segment;
	uint16_t offset;
	uint64_t sector;
    } xfer;
};

static void get_translated_chs(BlockDriverState *bs, int *c, int *h, int *s)
{
    bdrv_get_geometry_hint(bs, c, h, s);

    if (*c <= 1024) {
	*c >>= 0;
	*h <<= 0;
    } else if (*c <= 2048) {
	*c >>= 1;
	*h <<= 1;
    } else if (*c <= 4096) {
	*c >>= 2;
	*h <<= 2;
    } else if (*c <= 8192) {
	*c >>= 3;
	*h <<= 3;
    } else {
	*c >>= 4;
	*h <<= 4;
    }

    /* what is the correct algorithm for this?? */
    if (*h == 256) {
	*h = 255;
	*c = *c + 1;
    }
}

static uint32_t extboot_read(void *opaque, uint32_t addr)
{
    int *pcmd = opaque;
    return *pcmd;
}

static void extboot_write_cmd(void *opaque, uint32_t addr, uint32_t value)
{
    union extboot_cmd *cmd = (void *)(phys_ram_base + ((value & 0xFFFF) << 4));
    BlockDriverState *bs = opaque;
    int cylinders, heads, sectors, err;

    get_translated_chs(bs, &cylinders, &heads, &sectors);

    if (cmd->type == 0x01 || cmd->type == 0x02) {
	target_ulong pa = cmd->xfer.segment * 16 + cmd->xfer.segment;

	/* possible buffer overflow */
	if ((pa + cmd->xfer.nb_sectors * 512) > phys_ram_size)
	    return;
    }

    switch (cmd->type) {
    case 0x00:
	cmd->query_geometry.cylinders = cylinders;
	cmd->query_geometry.heads = heads;
	cmd->query_geometry.sectors = sectors;
	cpu_physical_memory_set_dirty((value & 0xFFFF) << 4);
	break;
    case 0x01:
	err = bdrv_read(bs, cmd->xfer.sector, phys_ram_base +
			cmd->xfer.segment * 16 + cmd->xfer.offset,
			cmd->xfer.nb_sectors);
	if (err)
	    printf("Read failed\n");
	break;
    case 0x02:
	err = bdrv_write(bs, cmd->xfer.sector, phys_ram_base +
			 cmd->xfer.segment * 16 + cmd->xfer.offset,
			 cmd->xfer.nb_sectors);
	if (err)
	    printf("Write failed\n");

	cpu_physical_memory_set_dirty(cmd->xfer.segment * 16 + cmd->xfer.offset);
	break;
    }
}

void extboot_init(BlockDriverState *bs, int cmd)
{
    int *pcmd;

    pcmd = qemu_mallocz(sizeof(int));
    if (!pcmd) {
	fprintf(stderr, "Error allocating memory\n");
	exit(1);
    }

    *pcmd = cmd;
    register_ioport_read(0x404, 1, 1, extboot_read, pcmd);
    register_ioport_write(0x405, 1, 2, extboot_write_cmd, bs);
}
