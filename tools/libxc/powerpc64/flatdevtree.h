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
 */

#ifndef _FLATDEVTREE_H_
#define _FLATDEVTREE_H_

#include "flatdevtree_env.h"

/* Definitions used by the flattened device tree */
#define OF_DT_HEADER            0xd00dfeed      /* marker */
#define OF_DT_BEGIN_NODE        0x1     /* Start of node, full name */
#define OF_DT_END_NODE          0x2     /* End node */
#define OF_DT_PROP              0x3     /* Property: name off, size, content */
#define OF_DT_NOP               0x4     /* nop */
#define OF_DT_END               0x9

#define OF_DT_VERSION           0x10

struct boot_param_header {
	u32 magic;              /* magic word OF_DT_HEADER */
	u32 totalsize;          /* total size of DT block */
	u32 off_dt_struct;      /* offset to structure */
	u32 off_dt_strings;     /* offset to strings */
	u32 off_mem_rsvmap;     /* offset to memory reserve map */
	u32 version;            /* format version */
	u32 last_comp_version;  /* last compatible version */
	/* version 2 fields below */
	u32 boot_cpuid_phys;    /* Physical CPU id we're booting on */
	/* version 3 fields below */
	u32 size_dt_strings;    /* size of the DT strings block */
};

struct ft_cxt {
	struct boot_param_header *bph;
	int max_size;           /* maximum size of tree */
	int overflow;           /* set when this happens */
	char *p, *pstr, *pres;  /* running pointers */
	char *p_begin, *pstr_begin, *pres_begin;        /* starting pointers */
	char *p_anchor;         /* start of constructed area */
	int struct_size, strings_size, res_size;
};

void ft_begin_node(struct ft_cxt *cxt, const char *name);
void ft_end_node(struct ft_cxt *cxt);

void ft_begin_tree(struct ft_cxt *cxt);
int ft_end_tree(struct ft_cxt *cxt);

void ft_nop(struct ft_cxt *cxt);
void ft_prop(struct ft_cxt *cxt, const char *name,
             const void *data, unsigned int sz);
void ft_prop_str(struct ft_cxt *cxt, const char *name, const char *str);
void ft_prop_int(struct ft_cxt *cxt, const char *name, unsigned int val);
void ft_begin(struct ft_cxt *cxt, void *blob, unsigned int max_size);
void ft_add_rsvmap(struct ft_cxt *cxt, u64 physaddr, u64 size);
int ft_set_rsvmap(void *bphp, int m, u64 physaddr, u64 size);

void ft_dump_blob(const void *bphp);
void ft_backtrack_node(struct ft_cxt *cxt);
void ft_merge_blob(struct ft_cxt *cxt, void *blob);

void *ft_find_node(const void *bphp, const char *srch_path);
int ft_get_prop(const void *bphp, const void *node, const char *propname,
		void *buf, const unsigned int buflen);
int ft_set_prop(void **bphp, const void *node, const char *propname,
		const void *buf, const unsigned int buflen);

static inline char *ft_strrchr(const char *s, int c)
{
	const char *p = s + strlen(s);

	do {
		if (*p == (char)c)
			return (char *)p;
	} while (--p >= s);
	return NULL;
}

/* 'path' is modified */
static inline void ft_parentize(char *path, int leave_slash)
{
	char *s = &path[strlen(path) - 1];

	if (*s == '/')
		*s = '\0';
	s = ft_strrchr(path, '/');
	if (s != NULL) {
		if (leave_slash)
			s[1] = '\0';
		else if (s[0] == '/')
			s[0] = '\0';
	}
}

#endif /* FLATDEVTREE_H */
