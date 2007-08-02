/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright IBM Corp. 2006, 2007
 *
 * Authors: Hollis Blanchard <hollisb@us.ibm.com>
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/multiboot2.h>
#include <asm/boot.h>
#include <asm/init.h>

static struct mb2_tag_module *mb2_tag_mod_find(struct mb2_tag_header *tags,
                                                const char *type)
{
    struct mb2_tag_header *tag;

    for_each_tag(tag, tags) {
        if (tag->key == MB2_TAG_MODULE) {
            struct mb2_tag_module *mod = (struct mb2_tag_module *)tag;
            if (!strcmp((char *)mod->type, type))
                return mod;
        }
    }
    return NULL;
}

void parse_multiboot(ulong tags_addr)
{
    struct mb2_tag_header *tags = (struct mb2_tag_header *)tags_addr;
    struct mb2_tag_module *mod;

    if (tags->key != MB2_TAG_START)
        return;

    mod = mb2_tag_mod_find(tags, "kernel");
    if (mod) {
        xen_cmdline = (char *)mod->cmdline;
    }

    mod = mb2_tag_mod_find(tags, "dom0");
    if (mod) {
        dom0_addr = mod->addr;
        dom0_len = mod->size;
        dom0_cmdline = (char *)mod->cmdline;
    }

    mod = mb2_tag_mod_find(tags, "initrd");
    if (mod) {
        initrd_start = mod->addr;
        initrd_len = mod->size;
    }
}
