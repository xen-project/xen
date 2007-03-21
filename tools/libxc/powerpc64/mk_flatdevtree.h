/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright IBM Corporation 2007
 *
 * Authors: Ryan Harper <ryanh@us.ibm.com>
 */

#ifndef MK_FLATDEVTREE_H
#define MK_FLATDEVTREE_H

#include "flatdevtree_env.h"
#include "flatdevtree.h"

extern void free_devtree(struct ft_cxt *root);
extern int make_devtree(struct ft_cxt *root,
                        struct xc_dom_image *dom,
                        unsigned long shadow_mb);

#define MAX_PATH 200
#define BUFSIZE 1024
#define BPH_SIZE 16*1024
#define DTB_FILE "/tmp/domU.dtb"

#endif /* MK_FLATDEVTREE_H */
