/*
 * apei-base.c - ACPI Platform Error Interface (APEI) supporting
 * infrastructure
 *
 * APEI allows to report errors (for example from the chipset) to the
 * the operating system. This improves NMI handling especially. In
 * addition it supports error serialization and error injection.
 *
 * For more information about APEI, please refer to ACPI Specification
 * version 4.0, chapter 17.
 *
 * This file has Common functions used by more than one APEI table,
 * including framework of interpreter for ERST and EINJ; resource
 * management for APEI registers.
 *
 * This feature is ported from linux acpi tree
 * Copyright (C) 2009, Intel Corp.
 *	Author: Huang Ying <ying.huang@intel.com>
 *	Ported by: Liu, Jinsong <jinsong.liu@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */
#include <xen/kernel.h>
#include <xen/errno.h>
#include <xen/delay.h>
#include <xen/string.h>
#include <xen/types.h>
#include <xen/spinlock.h>
#include <xen/init.h>
#include <xen/cper.h>
#include <asm/io.h>
#include <acpi/acpi.h>
#include <acpi/apei.h>

#include "apei-internal.h"

/*
 * APEI ERST (Error Record Serialization Table) and EINJ (Error
 * INJection) interpreter framework.
 */

#define APEI_EXEC_PRESERVE_REGISTER	0x1

int apei_exec_ctx_init(struct apei_exec_context *ctx,
			struct apei_exec_ins_type *ins_table,
			u32 instructions,
			struct acpi_whea_header *action_table,
			u32 entries)
{
	if (!ctx)
		return -EINVAL;

	ctx->ins_table = ins_table;
	ctx->instructions = instructions;
	ctx->action_table = action_table;
	ctx->entries = entries;
	return 0;
}

int __apei_exec_read_register(struct acpi_whea_header *entry, u64 *val)
{
	int rc;

	rc = apei_read(val, &entry->register_region);
	if (rc)
		return rc;
	*val >>= entry->register_region.bit_offset;
	*val &= entry->mask;

	return 0;
}

int apei_exec_read_register(struct apei_exec_context *ctx,
			    struct acpi_whea_header *entry)
{
	int rc;
	u64 val = 0;

	rc = __apei_exec_read_register(entry, &val);
	if (rc)
		return rc;
	ctx->value = val;

	return 0;
}

int apei_exec_read_register_value(struct apei_exec_context *ctx,
				  struct acpi_whea_header *entry)
{
	int rc;

	rc = apei_exec_read_register(ctx, entry);
	if (rc)
		return rc;
	ctx->value = (ctx->value == entry->value);

	return 0;
}

int __apei_exec_write_register(struct acpi_whea_header *entry, u64 val)
{
	int rc;

	val &= entry->mask;
	val <<= entry->register_region.bit_offset;
	if (entry->flags & APEI_EXEC_PRESERVE_REGISTER) {
		u64 valr = 0;
		rc = apei_read(&valr, &entry->register_region);
		if (rc)
			return rc;
		valr &= ~(entry->mask << entry->register_region.bit_offset);
		val |= valr;
	}
	rc = apei_write(val, &entry->register_region);

	return rc;
}

int apei_exec_write_register(struct apei_exec_context *ctx,
			     struct acpi_whea_header *entry)
{
	return __apei_exec_write_register(entry, ctx->value);
}

int apei_exec_write_register_value(struct apei_exec_context *ctx,
				   struct acpi_whea_header *entry)
{
	int rc;

	ctx->value = entry->value;
	rc = apei_exec_write_register(ctx, entry);

	return rc;
}

int apei_exec_noop(struct apei_exec_context *ctx,
		   struct acpi_whea_header *entry)
{
	return 0;
}

/*
 * Interpret the specified action. Go through whole action table,
 * execute all instructions belong to the action.
 */
int __apei_exec_run(struct apei_exec_context *ctx, u8 action,
		    bool_t optional)
{
	int rc = -ENOENT;
	u32 i, ip;
	struct acpi_whea_header *entry;
	apei_exec_ins_func_t run;

	ctx->ip = 0;

	/*
	 * "ip" is the instruction pointer of current instruction,
	 * "ctx->ip" specifies the next instruction to executed,
	 * instruction "run" function may change the "ctx->ip" to
	 * implement "goto" semantics.
	 */
rewind:
	ip = 0;
	for (i = 0; i < ctx->entries; i++) {
		entry = &ctx->action_table[i];
		if (entry->action != action)
			continue;
		if (ip == ctx->ip) {
			if (entry->instruction >= ctx->instructions ||
			    !ctx->ins_table[entry->instruction].run) {
				printk(KERN_WARNING
				"Invalid action table, unknown instruction "
				"type: %d\n", entry->instruction);
				return -EINVAL;
			}
			run = ctx->ins_table[entry->instruction].run;
			rc = run(ctx, entry);
			if (rc < 0)
				return rc;
			else if (rc != APEI_EXEC_SET_IP)
				ctx->ip++;
		}
		ip++;
		if (ctx->ip < ip)
			goto rewind;
	}

	return !optional && rc < 0 ? rc : 0;
}

typedef int (*apei_exec_entry_func_t)(struct apei_exec_context *ctx,
				      struct acpi_whea_header *entry,
				      void *data);

static int __init apei_exec_for_each_entry(struct apei_exec_context *ctx,
					   apei_exec_entry_func_t func,
					   void *data,
					   int *end)
{
	u8 ins;
	int i, rc;
	struct acpi_whea_header *entry;
	struct apei_exec_ins_type *ins_table = ctx->ins_table;

	for (i = 0; i < ctx->entries; i++) {
		entry = ctx->action_table + i;
		ins = entry->instruction;
		if (end)
			*end = i;
		if (ins >= ctx->instructions || !ins_table[ins].run) {
			printk(KERN_WARNING "Invalid action table, "
			"unknown instruction type: %d\n", ins);
			return -EINVAL;
		}
		rc = func(ctx, entry, data);
		if (rc)
			return rc;
	}

	return 0;
}

static int __init pre_map_gar_callback(struct apei_exec_context *ctx,
				       struct acpi_whea_header *entry,
				       void *data)
{
	u8 ins = entry->instruction;

	if (ctx->ins_table[ins].flags & APEI_EXEC_INS_ACCESS_REGISTER)
		return apei_pre_map_gar(&entry->register_region);

	return 0;
}

/* Pre-map all GARs in action table. */
int __init apei_exec_pre_map_gars(struct apei_exec_context *ctx)
{
	int rc, end;

	rc = apei_exec_for_each_entry(ctx, pre_map_gar_callback,
				      NULL, &end);
	if (rc) {
		struct apei_exec_context ctx_unmap;
		memcpy(&ctx_unmap, ctx, sizeof(*ctx));
		ctx_unmap.entries = end;
		apei_exec_post_unmap_gars(&ctx_unmap);
	}

	return rc;
}

static int __init post_unmap_gar_callback(struct apei_exec_context *ctx,
					  struct acpi_whea_header *entry,
					  void *data)
{
	u8 ins = entry->instruction;

	if (ctx->ins_table[ins].flags & APEI_EXEC_INS_ACCESS_REGISTER)
		apei_post_unmap_gar(&entry->register_region);

	return 0;
}

/* Post-unmap all GAR in action table. */
int __init apei_exec_post_unmap_gars(struct apei_exec_context *ctx)
{
	return apei_exec_for_each_entry(ctx, post_unmap_gar_callback,
					NULL, NULL);
}
