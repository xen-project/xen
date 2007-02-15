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
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright Pantelis Antoniou 2006
 * Copyright IBM Corporation 2006, 2007
 * 2006 (c) MontaVista, Software, Inc.
 *
 * Authors: Pantelis Antoniou <pantelis@embeddedalley.com>
 *          Hollis Blanchard <hollisb@us.ibm.com>
 *          Mark A. Greer <mgreer@mvista.com>
 */

#include "flatdevtree.h"

/* Set ptrs to current one's info; return addr of next one */
static u32 *ft_next(u32 *p, const u32 *p_strings, const u32 version,
		u32 **tagpp, char **namepp, char **datapp, u32 **sizepp)
{
	u32 sz;

	*namepp = NULL;
	*datapp = NULL;
	*sizepp = NULL;
	*tagpp = p;

	switch (be32_to_cpu(*p++)) { /* Tag */
	case OF_DT_BEGIN_NODE:
		*namepp = (char *)p;
		p = (u32 *)_ALIGN((unsigned long)p + strlen((char *)p) + 1, 4);
		break;
	case OF_DT_PROP:
		sz = be32_to_cpu(*p);
		*sizepp = p++;
		*namepp = (char *)p_strings + be32_to_cpu(*p++);
		if ((version < 0x10) && (sz >= 8))
			p = (u32 *)_ALIGN((unsigned long)p, 8);
		*datapp = (char *)p;
		p = (u32 *)_ALIGN((unsigned long)p + sz, 4);
		break;
	case OF_DT_END_NODE:
	case OF_DT_NOP:
		break;
	case OF_DT_END:
	default:
		p = NULL;
		break;
	}

	return p;
}

static void ft_put_word(struct ft_cxt *cxt, u32 v)
{
	if (cxt->overflow)	/* do nothing */
		return;

	/* check for overflow */
	if (cxt->p + 4 > cxt->pstr) {
		cxt->overflow = 1;
		return;
	}

	*(u32 *) cxt->p = cpu_to_be32(v);
	cxt->p += 4;
}

static inline void ft_put_bin(struct ft_cxt *cxt, const void *data, int sz)
{
	char *p;

	if (cxt->overflow)	/* do nothing */
		return;

	/* next pointer pos */
	p = (char *) _ALIGN((unsigned long)cxt->p + sz, 4);

	/* check for overflow */
	if (p > cxt->pstr) {
		cxt->overflow = 1;
		return;
	}

	memcpy(cxt->p, data, sz);
	if ((sz & 3) != 0)
		memset(cxt->p + sz, 0, 4 - (sz & 3));
	cxt->p = p;
}

void ft_begin_node(struct ft_cxt *cxt, const char *name)
{
	ft_put_word(cxt, OF_DT_BEGIN_NODE);
	ft_put_bin(cxt, name, strlen(name) + 1);
}

void ft_end_node(struct ft_cxt *cxt)
{
	ft_put_word(cxt, OF_DT_END_NODE);
}

void ft_nop(struct ft_cxt *cxt)
{
	ft_put_word(cxt, OF_DT_NOP);
}

static int lookup_string(struct ft_cxt *cxt, const char *name)
{
	char *p;

	p = cxt->pstr;
	while (p < cxt->pstr_begin) {
		if (strcmp(p, (char *)name) == 0)
			return p - cxt->p_begin;
		p += strlen(p) + 1;
	}

	return -1;
}

void ft_prop(struct ft_cxt *cxt, const char *name,
		const void *data, unsigned int sz)
{
	int len, off;

	if (cxt->overflow)
		return;

	len = strlen(name) + 1;

	off = lookup_string(cxt, name);
	if (off == -1) {
		/* check if we have space */
		if (cxt->p + 12 + sz + len > cxt->pstr) {
			cxt->overflow = 1;
			return;
		}

		cxt->pstr -= len;
		memcpy(cxt->pstr, name, len);
		off = cxt->pstr - cxt->p_begin;
	}

	/* now put offset from beginning of *STRUCTURE* */
	/* will be fixed up at the end */
	ft_put_word(cxt, OF_DT_PROP);
	ft_put_word(cxt, sz);
	ft_put_word(cxt, off);
	ft_put_bin(cxt, data, sz);
}

void ft_prop_str(struct ft_cxt *cxt, const char *name, const char *str)
{
	ft_prop(cxt, name, str, strlen(str) + 1);
}

void ft_prop_int(struct ft_cxt *cxt, const char *name, unsigned int val)
{
	u32 v = cpu_to_be32((u32) val);

	ft_prop(cxt, name, &v, 4);
}

/* start construction of the flat OF tree */
void ft_begin(struct ft_cxt *cxt, void *blob, unsigned int max_size)
{
	struct boot_param_header *bph = blob;
	u32 off;

	/* clear the cxt */
	memset(cxt, 0, sizeof(*cxt));

	cxt->bph = bph;
	cxt->max_size = max_size;

	/* zero everything in the header area */
	memset(bph, 0, sizeof(*bph));

	bph->magic = cpu_to_be32(OF_DT_HEADER);
	bph->version = cpu_to_be32(0x10);
	bph->last_comp_version = cpu_to_be32(0x10);

	/* start pointers */
	cxt->pres_begin = (char *) _ALIGN((unsigned long)(bph + 1), 8);
	cxt->pres = cxt->pres_begin;

	off = (unsigned long)cxt->pres_begin - (unsigned long)bph;
	bph->off_mem_rsvmap = cpu_to_be32(off);

	((u64 *) cxt->pres)[0] = 0;	/* phys = 0, size = 0, terminate */
	((u64 *) cxt->pres)[1] = 0;

	cxt->p_anchor = cxt->pres + 16;	/* over the terminator */
}

/* add a reserver physical area to the rsvmap */
void ft_add_rsvmap(struct ft_cxt *cxt, u64 physaddr, u64 size)
{
	((u64 *) cxt->pres)[0] = cpu_to_be64(physaddr);	/* phys = 0, size = 0, terminate */
	((u64 *) cxt->pres)[1] = cpu_to_be64(size);

	cxt->pres += 16;	/* advance two u64s worth */

	((u64 *) cxt->pres)[0] = 0;	/* phys = 0, size = 0, terminate */
	((u64 *) cxt->pres)[1] = 0;

	/* keep track of size */
	cxt->res_size = cxt->pres + 16 - cxt->pres_begin;

	cxt->p_anchor = cxt->pres + 16;	/* over the terminator */
}

int ft_set_rsvmap(void *bphp, int m, u64 physaddr, u64 size)
{
	const struct boot_param_header *bph = bphp;
	u64 *p_rsvmap = (u64 *)
		((char *)bph + be32_to_cpu(bph->off_mem_rsvmap));
	u32 i;

	for (i = 0;; i++) {
		u64 addr, sz;

		addr = be64_to_cpu(p_rsvmap[i * 2]);
		sz = be64_to_cpu(p_rsvmap[i * 2 + 1]);
		if (addr == 0 && size == 0)
			break;
		if (m == i) {
			p_rsvmap[i * 2] = cpu_to_be64(physaddr);
			p_rsvmap[i * 2 + 1] = cpu_to_be64(size);
			return 0;
		}
	}
	return -1;
}

void ft_begin_tree(struct ft_cxt *cxt)
{
	cxt->p_begin = cxt->p_anchor;
	cxt->pstr_begin = (char *)cxt->bph + cxt->max_size;	/* point at the end */

	cxt->p = cxt->p_begin;
	cxt->pstr = cxt->pstr_begin;
}

int ft_end_tree(struct ft_cxt *cxt)
{
	struct boot_param_header *bph = cxt->bph;
	int off, sz, sz1;
	u32 tag, v;
	char *p;

	ft_put_word(cxt, OF_DT_END);

	if (cxt->overflow)
		return -ENOMEM;

	/* size of the areas */
	cxt->struct_size = cxt->p - cxt->p_begin;
	cxt->strings_size = cxt->pstr_begin - cxt->pstr;

	/* the offset we must move */
	off = (cxt->pstr_begin - cxt->p_begin) - cxt->strings_size;

	/* the new strings start */
	cxt->pstr_begin = cxt->p_begin + cxt->struct_size;

	/* move the whole string area */
	memmove(cxt->pstr_begin, cxt->pstr, cxt->strings_size);

	/* now perform the fixup of the strings */
	p = cxt->p_begin;
	while ((tag = be32_to_cpu(*(u32 *) p)) != OF_DT_END) {
		p += 4;

		if (tag == OF_DT_BEGIN_NODE) {
			p = (char *) _ALIGN((unsigned long)p + strlen(p) + 1, 4);
			continue;
		}

		if (tag == OF_DT_END_NODE || tag == OF_DT_NOP)
			continue;

		if (tag != OF_DT_PROP)
			return -EINVAL;

		sz = be32_to_cpu(*(u32 *) p);
		p += 4;

		v = be32_to_cpu(*(u32 *) p);
		v -= off;
		*(u32 *) p = cpu_to_be32(v);	/* move down */
		p += 4;

		p = (char *) _ALIGN((unsigned long)p + sz, 4);
	}

	/* fix sizes */
	p = (char *)cxt->bph;
	sz = (cxt->pstr_begin + cxt->strings_size) - p;
	sz1 = _ALIGN(sz, 16);	/* align at 16 bytes */
	if (sz != sz1)
		memset(p + sz, 0, sz1 - sz);
	bph->totalsize = cpu_to_be32(sz1);
	bph->off_dt_struct = cpu_to_be32(cxt->p_begin - p);
	bph->off_dt_strings = cpu_to_be32(cxt->pstr_begin - p);

	/* the new strings start */
	cxt->pstr_begin = cxt->p_begin + cxt->struct_size;
	cxt->pstr = cxt->pstr_begin + cxt->strings_size;

	/* mark the size of string structure in bph */
	bph->size_dt_strings = cxt->strings_size;

	return 0;
}

/**********************************************************************/

static inline int isprint(int c)
{
	return c >= 0x20 && c <= 0x7e;
}

static int is_printable_string(const void *data, int len)
{
	const char *s = data;
	const char *ss;

	/* zero length is not */
	if (len == 0)
		return 0;

	/* must terminate with zero */
	if (s[len - 1] != '\0')
		return 0;

	ss = s;
	while (*s && isprint(*s))
		s++;

	/* not zero, or not done yet */
	if (*s != '\0' || (s + 1 - ss) < len)
		return 0;

	return 1;
}

static void print_data(const void *data, int len)
{
	int i;
	const char *s;

	/* no data, don't print */
	if (len == 0)
		return;

	if (is_printable_string(data, len)) {
		printf(" = \"%s\"", (char *)data);
		return;
	}

	switch (len) {
	case 1:		/* byte */
		printf(" = <0x%02x>", (*(char *) data) & 0xff);
		break;
	case 2:		/* half-word */
		printf(" = <0x%04x>", be16_to_cpu(*(u16 *) data) & 0xffff);
		break;
	case 4:		/* word */
		printf(" = <0x%08x>", be32_to_cpu(*(u32 *) data) & 0xffffffffU);
		break;
	case 8:		/* double-word */
		printf(" = <0x%16llx>", be64_to_cpu(*(u64 *) data));
		break;
	default:		/* anything else... hexdump */
		printf(" = [");
		for (i = 0, s = data; i < len; i++)
			printf("%02x%s", s[i], i < len - 1 ? " " : "");
		printf("]");

		break;
	}
}

void ft_dump_blob(const void *bphp)
{
	const struct boot_param_header *bph = bphp;
	const u64 *p_rsvmap = (const u64 *)
		((const char *)bph + be32_to_cpu(bph->off_mem_rsvmap));
	const u32 *p_struct = (const u32 *)
		((const char *)bph + be32_to_cpu(bph->off_dt_struct));
	const u32 *p_strings = (const u32 *)
		((const char *)bph + be32_to_cpu(bph->off_dt_strings));
	const u32 version = be32_to_cpu(bph->version);
	u32 i, *p, *tagp, *sizep;
	char *namep, *datap;
	int depth, shift;
	u64 addr, size;


	if (be32_to_cpu(bph->magic) != OF_DT_HEADER) {
		/* not valid tree */
		return;
	}

	depth = 0;
	shift = 4;

	for (i = 0;; i++) {
		addr = be64_to_cpu(p_rsvmap[i * 2]);
		size = be64_to_cpu(p_rsvmap[i * 2 + 1]);
		if (addr == 0 && size == 0)
			break;

		printf("/memreserve/ 0x%llx 0x%llx;\n", addr, size);
	}

	p = (u32 *)p_struct;
	while ((p = ft_next(p, p_strings, version, &tagp, &namep, &datap,
					&sizep)) != NULL)
		switch (be32_to_cpu(*tagp)) {
		case OF_DT_BEGIN_NODE:
			printf("%*s%s {\n", depth * shift, "", namep);
			depth++;
			break;
		case OF_DT_END_NODE:
			depth--;
			printf("%*s};\n", depth * shift, "");
			break;
		case OF_DT_NOP:
			printf("%*s[NOP]\n", depth * shift, "");
			break;
		case OF_DT_END:
			break;
		case OF_DT_PROP:
			printf("%*s%s", depth * shift, "", namep);
			print_data(datap, *sizep);
			printf(";\n");
			break;
		default:
			fprintf(stderr, "%*s ** Unknown tag 0x%08x\n",
				depth * shift, "", *tagp);
			return;
		}
}

void ft_backtrack_node(struct ft_cxt *cxt)
{
	if (be32_to_cpu(*(u32 *) (cxt->p - 4)) != OF_DT_END_NODE)
		return;		/* XXX only for node */

	cxt->p -= 4;
}

/* note that the root node of the blob is "peeled" off */
void ft_merge_blob(struct ft_cxt *cxt, void *blob)
{
	struct boot_param_header *bph = (struct boot_param_header *)blob;
	u32 *p_struct = (u32 *) ((char *)bph + be32_to_cpu(bph->off_dt_struct));
	u32 *p_strings =
		(u32 *) ((char *)bph + be32_to_cpu(bph->off_dt_strings));
	const u32 version = be32_to_cpu(bph->version);
	u32 *p, *tagp, *sizep;
	char *namep, *datap;
	int depth;

	if (be32_to_cpu(*(u32 *) (cxt->p - 4)) != OF_DT_END_NODE)
		return;		/* XXX only for node */

	cxt->p -= 4;

	depth = 0;
	p = p_struct;
	while ((p = ft_next(p, p_strings, version, &tagp, &namep, &datap,
					&sizep)) != NULL)
		switch (be32_to_cpu(*tagp)) {
		case OF_DT_BEGIN_NODE:
			if (depth++ > 0)
				ft_begin_node(cxt, namep);
			break;
		case OF_DT_END_NODE:
			ft_end_node(cxt);
			if (--depth == 0)
				return;
			break;
		case OF_DT_PROP:
			ft_prop(cxt, namep, datap, *sizep);
			break;
		}
}

/**********************************************************************/

void *ft_find_node(const void *bphp, const char *srch_path)
{
	const struct boot_param_header *bph = bphp;
	u32 *p_struct = (u32 *)((char *)bph + be32_to_cpu(bph->off_dt_struct));
	u32 *p_strings= (u32 *)((char *)bph + be32_to_cpu(bph->off_dt_strings));
	u32 version = be32_to_cpu(bph->version);
	u32 *p, *tagp, *sizep;
	char *namep, *datap;
	static char path[MAX_PATH_LEN];

	path[0] = '\0';
	p = p_struct;

	while ((p = ft_next(p, p_strings, version, &tagp, &namep, &datap,
					&sizep)) != NULL)
		switch (be32_to_cpu(*tagp)) {
		case OF_DT_BEGIN_NODE:
			strcat(path, namep);
			if (!strcmp(path, srch_path))
				return tagp;
			strcat(path, "/");
			break;
		case OF_DT_END_NODE:
			ft_parentize(path, 1);
			break;
		}
	return NULL;
}

int ft_get_prop(const void *bphp, const void *node, const char *propname,
		void *buf, const unsigned int buflen)
{
	const struct boot_param_header *bph = bphp;
	u32 *p_strings= (u32 *)((char *)bph + be32_to_cpu(bph->off_dt_strings));
	u32 version = be32_to_cpu(bph->version);
	u32 *p, *tagp, *sizep, size;
	char *namep, *datap;
	int depth;

	depth = 0;
	p = (u32 *)node;

	while ((p = ft_next(p, p_strings, version, &tagp, &namep, &datap,
					&sizep)) != NULL)
		switch (be32_to_cpu(*tagp)) {
		case OF_DT_BEGIN_NODE:
			depth++;
			break;
		case OF_DT_PROP:
			if ((depth == 1) && !strcmp(namep, propname)) {
				size = min(be32_to_cpu(*sizep), (u32)buflen);
				memcpy(buf, datap, size);
				return size;
			}
			break;
		case OF_DT_END_NODE:
			if (--depth <= 0)
				return -1;
			break;
		}
	return -1;
}

static void ft_modify_prop(void **bphpp, char *datap, u32 *old_prop_sizep,
		const char *buf, const unsigned int buflen)
{
	u32 old_prop_data_len, new_prop_data_len;

	old_prop_data_len = _ALIGN(be32_to_cpu(*old_prop_sizep), 4);
	new_prop_data_len = _ALIGN(buflen, 4);

	/* Check if new prop data fits in old prop data area */
	if (new_prop_data_len == old_prop_data_len) {
		memcpy(datap, buf, buflen);
		*old_prop_sizep = cpu_to_be32(buflen);
	} else {
		/* Need to alloc new area to put larger or smaller ft */
		struct boot_param_header *old_bph = *bphpp, *new_bph;
		u32 *old_tailp, *new_tailp, *new_datap;
		u32 old_total_size, new_total_size, head_len, tail_len, diff, v;

		old_total_size = be32_to_cpu(old_bph->totalsize);
		head_len = (u32)(datap - (char *)old_bph);
		tail_len = old_total_size - (head_len + old_prop_data_len);
		old_tailp = (u32 *)(datap + old_prop_data_len);
		new_total_size = head_len + new_prop_data_len + tail_len;

		if (!(new_bph = malloc(new_total_size))) {
			printf("Can't alloc space for new ft\n");
			ft_exit(-ENOSPC);
		}

		new_datap = (u32 *)((char *)new_bph + head_len);
		new_tailp = (u32 *)((char *)new_datap + new_prop_data_len);

		memcpy(new_bph, *bphpp, head_len);
		memcpy(new_datap, buf, buflen);
		memcpy(new_tailp, old_tailp, tail_len);

		*(new_datap - 2) = cpu_to_be32(buflen); /* Set prop size */

		new_bph->totalsize = cpu_to_be32(new_total_size);
		diff = new_prop_data_len - old_prop_data_len;

		if (be32_to_cpu(old_bph->off_dt_strings)
				> be32_to_cpu(old_bph->off_dt_struct)) {
			v = be32_to_cpu(new_bph->off_dt_strings);
			new_bph->off_dt_strings = cpu_to_be32(v + diff);
		}

		if (be32_to_cpu(old_bph->off_mem_rsvmap)
				> be32_to_cpu(old_bph->off_dt_struct)) {
			v = be32_to_cpu(new_bph->off_mem_rsvmap);
			new_bph->off_mem_rsvmap = cpu_to_be32(v + diff);
		}

		ft_free(*bphpp, old_total_size);
		*bphpp = new_bph;
	}
}

/*
 * - Only modifies existing properties.
 * - The dev tree passed in may be freed and a new one allocated
 *   (and *bphpp set to location of new dev tree).
 */
int ft_set_prop(void **bphpp, const void *node, const char *propname,
		const void *buf, const unsigned int buflen)
{
	struct boot_param_header *bph = *bphpp;
	u32 *p_strings= (u32 *)((char *)bph + be32_to_cpu(bph->off_dt_strings));
	u32 version = be32_to_cpu(bph->version);
	u32 *p, *tagp, *sizep;
	char *namep, *datap;
	int depth;

	depth = 0;
	p = (u32 *)node;

	while ((p = ft_next(p, p_strings, version, &tagp, &namep, &datap,
					&sizep)) != NULL)
		switch (be32_to_cpu(*tagp)) {
		case OF_DT_BEGIN_NODE:
			depth++;
			break;
		case OF_DT_PROP:
			if ((depth == 1) && !strcmp(namep, propname)) {
				ft_modify_prop(bphpp, datap, sizep, buf,
						buflen);
				return be32_to_cpu(*sizep);
			}
			break;
		case OF_DT_END_NODE:
			if (--depth <= 0)
				return -1;
			break;
		}
	return -1;
}
