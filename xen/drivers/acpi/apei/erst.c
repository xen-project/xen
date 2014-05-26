/*
 * APEI Error Record Serialization Table support
 *
 * ERST is a way provided by APEI to save and retrieve hardware error
 * infomation to and from a persistent store.
 *
 * For more information about ERST, please refer to ACPI Specification
 * version 4.0, section 17.4.
 *
 * This feature is ported from linux acpi tree
 * Copyright 2010 Intel Corp.
 *   Author: Huang Ying <ying.huang@intel.com>
 *   Ported by: Liu, Jinsong <jinsong.liu@intel.com>
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <xen/kernel.h>
#include <xen/errno.h>
#include <xen/delay.h>
#include <xen/string.h>
#include <xen/types.h>
#include <xen/spinlock.h>
#include <xen/cper.h>
#include <asm/fixmap.h>
#include <asm/io.h>
#include <acpi/acpi.h>
#include <acpi/apei.h>

#include "apei-internal.h"

/* ERST command status */
#define ERST_STATUS_SUCCESS			0x0
#define ERST_STATUS_NOT_ENOUGH_SPACE		0x1
#define ERST_STATUS_HARDWARE_NOT_AVAILABLE	0x2
#define ERST_STATUS_FAILED			0x3
#define ERST_STATUS_RECORD_STORE_EMPTY		0x4
#define ERST_STATUS_RECORD_NOT_FOUND		0x5

#define ERST_TAB_ENTRY(tab)						\
	((struct acpi_whea_header *)((char *)(tab) +			\
				     sizeof(struct acpi_table_erst)))

#define SPIN_UNIT		1			/* 1us */
/* Firmware should respond within 1 miliseconds */
#define FIRMWARE_TIMEOUT	(1 * 1000)
#define FIRMWARE_MAX_STALL	50			/* 50us */

static struct acpi_table_erst *__read_mostly erst_tab;
static bool_t __read_mostly erst_enabled;

/* ERST Error Log Address Range atrributes */
#define ERST_RANGE_RESERVED	0x0001
#define ERST_RANGE_NVRAM	0x0002
#define ERST_RANGE_SLOW		0x0004

/*
 * ERST Error Log Address Range, used as buffer for reading/writing
 * error records.
 */
static struct erst_erange {
	u64 base;
	u64 size;
	void __iomem *vaddr;
	u32 attr;
} erst_erange;

/*
 * Prevent ERST interpreter to run simultaneously, because the
 * corresponding firmware implementation may not work properly when
 * invoked simultaneously.
 *
 * It is used to provide exclusive accessing for ERST Error Log
 * Address Range too.
 */
static DEFINE_SPINLOCK(erst_lock);

static inline int erst_errno(int command_status)
{
	switch (command_status) {
	case ERST_STATUS_SUCCESS:
		return 0;
	case ERST_STATUS_HARDWARE_NOT_AVAILABLE:
		return -ENODEV;
	case ERST_STATUS_NOT_ENOUGH_SPACE:
		return -ENOSPC;
	case ERST_STATUS_RECORD_STORE_EMPTY:
	case ERST_STATUS_RECORD_NOT_FOUND:
		return -ENOENT;
	default:
		return -EINVAL;
	}
}

static int erst_timedout(u64 *t, u64 spin_unit)
{
	if ((s64)*t < spin_unit) {
		printk(XENLOG_WARNING "Firmware does not respond in time\n");
		return 1;
	}
	*t -= spin_unit;
	udelay(spin_unit);
	return 0;
}

static int erst_exec_load_var1(struct apei_exec_context *ctx,
			       struct acpi_whea_header *entry)
{
	return __apei_exec_read_register(entry, &ctx->var1);
}

static int erst_exec_load_var2(struct apei_exec_context *ctx,
			       struct acpi_whea_header *entry)
{
	return __apei_exec_read_register(entry, &ctx->var2);
}

static int erst_exec_store_var1(struct apei_exec_context *ctx,
				struct acpi_whea_header *entry)
{
	return __apei_exec_write_register(entry, ctx->var1);
}

static int erst_exec_add(struct apei_exec_context *ctx,
			 struct acpi_whea_header *entry)
{
	ctx->var1 += ctx->var2;
	return 0;
}

static int erst_exec_subtract(struct apei_exec_context *ctx,
			      struct acpi_whea_header *entry)
{
	ctx->var1 -= ctx->var2;
	return 0;
}

static int erst_exec_add_value(struct apei_exec_context *ctx,
			       struct acpi_whea_header *entry)
{
	int rc;
	u64 val;

	rc = __apei_exec_read_register(entry, &val);
	if (rc)
		return rc;
	val += ctx->value;
	rc = __apei_exec_write_register(entry, val);
	return rc;
}

static int erst_exec_subtract_value(struct apei_exec_context *ctx,
				    struct acpi_whea_header *entry)
{
	int rc;
	u64 val;

	rc = __apei_exec_read_register(entry, &val);
	if (rc)
		return rc;
	val -= ctx->value;
	rc = __apei_exec_write_register(entry, val);
	return rc;
}

static int erst_exec_stall(struct apei_exec_context *ctx,
			   struct acpi_whea_header *entry)
{
	udelay((ctx->var1 > FIRMWARE_MAX_STALL) ? 
			FIRMWARE_MAX_STALL : 
			ctx->var1);
	return 0;
}

static int erst_exec_stall_while_true(struct apei_exec_context *ctx,
				      struct acpi_whea_header *entry)
{
	int rc;
	u64 val;
	u64 timeout = FIRMWARE_TIMEOUT;
	u64 stall_time = (ctx->var1 > FIRMWARE_MAX_STALL) ? 
				FIRMWARE_MAX_STALL : 
				ctx->var1;

	for (;;) {
		rc = __apei_exec_read_register(entry, &val);
		if (rc)
			return rc;
		if (val != ctx->value)
			break;
		if (erst_timedout(&timeout, stall_time))
			return -EIO;
	}
	return 0;
}

static int erst_exec_skip_next_instruction_if_true(
	struct apei_exec_context *ctx,
	struct acpi_whea_header *entry)
{
	int rc;
	u64 val;

	rc = __apei_exec_read_register(entry, &val);
	if (rc)
		return rc;
	if (val == ctx->value) {
		ctx->ip += 2;
		return APEI_EXEC_SET_IP;
	}

	return 0;
}

static int erst_exec_goto(struct apei_exec_context *ctx,
			  struct acpi_whea_header *entry)
{
	ctx->ip = ctx->value;
	return APEI_EXEC_SET_IP;
}

static int erst_exec_set_src_address_base(struct apei_exec_context *ctx,
					  struct acpi_whea_header *entry)
{
	return __apei_exec_read_register(entry, &ctx->src_base);
}

static int erst_exec_set_dst_address_base(struct apei_exec_context *ctx,
					  struct acpi_whea_header *entry)
{
	return __apei_exec_read_register(entry, &ctx->dst_base);
}

static int erst_exec_move_data(struct apei_exec_context *ctx,
			       struct acpi_whea_header *entry)
{
	int rc;
	u64 offset;
	void *src, *dst;

	/* ioremap does not work in interrupt context */
	if (in_irq()) {
		printk(KERN_WARNING
		       "MOVE_DATA cannot be used in interrupt context\n");
		return -EBUSY;
	}

	rc = __apei_exec_read_register(entry, &offset);
	if (rc)
		return rc;

	src = ioremap(ctx->src_base + offset, ctx->var2);
	if (!src)
		return -ENOMEM;

	dst = ioremap(ctx->dst_base + offset, ctx->var2);
	if (dst) {
		memmove(dst, src, ctx->var2);
		iounmap(dst);
	} else
		rc = -ENOMEM;

	iounmap(src);

	return rc;
}

static struct apei_exec_ins_type erst_ins_type[] = {
	[ACPI_ERST_READ_REGISTER] = {
		.flags = APEI_EXEC_INS_ACCESS_REGISTER,
		.run = apei_exec_read_register,
	},
	[ACPI_ERST_READ_REGISTER_VALUE] = {
		.flags = APEI_EXEC_INS_ACCESS_REGISTER,
		.run = apei_exec_read_register_value,
	},
	[ACPI_ERST_WRITE_REGISTER] = {
		.flags = APEI_EXEC_INS_ACCESS_REGISTER,
		.run = apei_exec_write_register,
	},
	[ACPI_ERST_WRITE_REGISTER_VALUE] = {
		.flags = APEI_EXEC_INS_ACCESS_REGISTER,
		.run = apei_exec_write_register_value,
	},
	[ACPI_ERST_NOOP] = {
		.flags = 0,
		.run = apei_exec_noop,
	},
	[ACPI_ERST_LOAD_VAR1] = {
		.flags = APEI_EXEC_INS_ACCESS_REGISTER,
		.run = erst_exec_load_var1,
	},
	[ACPI_ERST_LOAD_VAR2] = {
		.flags = APEI_EXEC_INS_ACCESS_REGISTER,
		.run = erst_exec_load_var2,
	},
	[ACPI_ERST_STORE_VAR1] = {
		.flags = APEI_EXEC_INS_ACCESS_REGISTER,
		.run = erst_exec_store_var1,
	},
	[ACPI_ERST_ADD] = {
		.flags = 0,
		.run = erst_exec_add,
	},
	[ACPI_ERST_SUBTRACT] = {
		.flags = 0,
		.run = erst_exec_subtract,
	},
	[ACPI_ERST_ADD_VALUE] = {
		.flags = APEI_EXEC_INS_ACCESS_REGISTER,
		.run = erst_exec_add_value,
	},
	[ACPI_ERST_SUBTRACT_VALUE] = {
		.flags = APEI_EXEC_INS_ACCESS_REGISTER,
		.run = erst_exec_subtract_value,
	},
	[ACPI_ERST_STALL] = {
		.flags = 0,
		.run = erst_exec_stall,
	},
	[ACPI_ERST_STALL_WHILE_TRUE] = {
		.flags = APEI_EXEC_INS_ACCESS_REGISTER,
		.run = erst_exec_stall_while_true,
	},
	[ACPI_ERST_SKIP_NEXT_IF_TRUE] = {
		.flags = APEI_EXEC_INS_ACCESS_REGISTER,
		.run = erst_exec_skip_next_instruction_if_true,
	},
	[ACPI_ERST_GOTO] = {
		.flags = 0,
		.run = erst_exec_goto,
	},
	[ACPI_ERST_SET_SRC_ADDRESS_BASE] = {
		.flags = APEI_EXEC_INS_ACCESS_REGISTER,
		.run = erst_exec_set_src_address_base,
	},
	[ACPI_ERST_SET_DST_ADDRESS_BASE] = {
		.flags = APEI_EXEC_INS_ACCESS_REGISTER,
		.run = erst_exec_set_dst_address_base,
	},
	[ACPI_ERST_MOVE_DATA] = {
		.flags = APEI_EXEC_INS_ACCESS_REGISTER,
		.run = erst_exec_move_data,
	},
};

static inline void erst_exec_ctx_init(struct apei_exec_context *ctx)
{
	apei_exec_ctx_init(ctx, erst_ins_type, ARRAY_SIZE(erst_ins_type),
			   ERST_TAB_ENTRY(erst_tab), erst_tab->entries);
}

static int erst_get_erange(struct erst_erange *range)
{
	struct apei_exec_context ctx;
	int rc;

	erst_exec_ctx_init(&ctx);
	rc = apei_exec_run(&ctx, ACPI_ERST_GET_ERROR_RANGE);
	if (rc)
		return rc;
	range->base = apei_exec_ctx_get_output(&ctx);
	rc = apei_exec_run(&ctx, ACPI_ERST_GET_ERROR_LENGTH);
	if (rc)
		return rc;
	range->size = apei_exec_ctx_get_output(&ctx);
	rc = apei_exec_run(&ctx, ACPI_ERST_GET_ERROR_ATTRIBUTES);
	if (rc)
		return rc;
	range->attr = apei_exec_ctx_get_output(&ctx);

	return 0;
}

#ifndef NDEBUG /* currently dead code */

static ssize_t __erst_get_record_count(void)
{
	struct apei_exec_context ctx;
	int rc;
	u64 output;
	ssize_t count;

	erst_exec_ctx_init(&ctx);
	rc = apei_exec_run(&ctx, ACPI_ERST_GET_RECORD_COUNT);
	if (rc)
		return rc;
	count = output = apei_exec_ctx_get_output(&ctx);
	return count >= 0 && count == output ? count : -ERANGE;
}

ssize_t erst_get_record_count(void)
{
	ssize_t count;
	unsigned long flags;

	if (!erst_enabled)
		return -ENODEV;

	spin_lock_irqsave(&erst_lock, flags);
	count = __erst_get_record_count();
	spin_unlock_irqrestore(&erst_lock, flags);

	return count;
}

static int __erst_get_next_record_id(u64 *record_id)
{
	struct apei_exec_context ctx;
	int rc;

	erst_exec_ctx_init(&ctx);
	rc = apei_exec_run(&ctx, ACPI_ERST_GET_RECORD_ID);
	if (rc)
		return rc;
	*record_id = apei_exec_ctx_get_output(&ctx);

	return 0;
}

/*
 * Get the record ID of an existing error record on the persistent
 * storage. If there is no error record on the persistent storage, the
 * returned record_id is APEI_ERST_INVALID_RECORD_ID.
 */
int erst_get_next_record_id(u64 *record_id)
{
	int rc;
	unsigned long flags;

	if (!erst_enabled)
		return -ENODEV;

	spin_lock_irqsave(&erst_lock, flags);
	rc = __erst_get_next_record_id(record_id);
	spin_unlock_irqrestore(&erst_lock, flags);

	return rc;
}

#endif /* currently dead code */

static int __erst_write_to_storage(u64 offset)
{
	struct apei_exec_context ctx;
	u64 timeout = FIRMWARE_TIMEOUT;
	u64 val;
	int rc;

	erst_exec_ctx_init(&ctx);
	rc = apei_exec_run(&ctx, ACPI_ERST_BEGIN_WRITE);
	if (rc)
		return rc;
	apei_exec_ctx_set_input(&ctx, offset);
	rc = apei_exec_run(&ctx, ACPI_ERST_SET_RECORD_OFFSET);
	if (rc)
		return rc;
	rc = apei_exec_run(&ctx, ACPI_ERST_EXECUTE_OPERATION);
	if (rc)
		return rc;
	for (;;) {
		rc = apei_exec_run(&ctx, ACPI_ERST_CHECK_BUSY_STATUS);
		if (rc)
			return rc;
		val = apei_exec_ctx_get_output(&ctx);
		if (!val)
			break;
		if (erst_timedout(&timeout, SPIN_UNIT))
			return -EIO;
	}
	rc = apei_exec_run(&ctx, ACPI_ERST_GET_COMMAND_STATUS);
	if (rc)
		return rc;
	val = apei_exec_ctx_get_output(&ctx);
	rc = apei_exec_run(&ctx, ACPI_ERST_END);
	if (rc)
		return rc;

	return erst_errno(val);
}

#ifndef NDEBUG /* currently dead code */

static int __erst_read_from_storage(u64 record_id, u64 offset)
{
	struct apei_exec_context ctx;
	u64 timeout = FIRMWARE_TIMEOUT;
	u64 val;
	int rc;

	erst_exec_ctx_init(&ctx);
	rc = apei_exec_run(&ctx, ACPI_ERST_BEGIN_READ);
	if (rc)
		return rc;
	apei_exec_ctx_set_input(&ctx, offset);
	rc = apei_exec_run(&ctx, ACPI_ERST_SET_RECORD_OFFSET);
	if (rc)
		return rc;
	apei_exec_ctx_set_input(&ctx, record_id);
	rc = apei_exec_run(&ctx, ACPI_ERST_SET_RECORD_ID);
	if (rc)
		return rc;
	rc = apei_exec_run(&ctx, ACPI_ERST_EXECUTE_OPERATION);
	if (rc)
		return rc;
	for (;;) {
		rc = apei_exec_run(&ctx, ACPI_ERST_CHECK_BUSY_STATUS);
		if (rc)
			return rc;
		val = apei_exec_ctx_get_output(&ctx);
		if (!val)
			break;
		if (erst_timedout(&timeout, SPIN_UNIT))
			return -EIO;
	};
	rc = apei_exec_run(&ctx, ACPI_ERST_GET_COMMAND_STATUS);
	if (rc)
		return rc;
	val = apei_exec_ctx_get_output(&ctx);
	rc = apei_exec_run(&ctx, ACPI_ERST_END);
	if (rc)
		return rc;

	return erst_errno(val);
}

static int __erst_clear_from_storage(u64 record_id)
{
	struct apei_exec_context ctx;
	u64 timeout = FIRMWARE_TIMEOUT;
	u64 val;
	int rc;

	erst_exec_ctx_init(&ctx);
	rc = apei_exec_run(&ctx, ACPI_ERST_BEGIN_CLEAR);
	if (rc)
		return rc;
	apei_exec_ctx_set_input(&ctx, record_id);
	rc = apei_exec_run(&ctx, ACPI_ERST_SET_RECORD_ID);
	if (rc)
		return rc;
	rc = apei_exec_run(&ctx, ACPI_ERST_EXECUTE_OPERATION);
	if (rc)
		return rc;
	for (;;) {
		rc = apei_exec_run(&ctx, ACPI_ERST_CHECK_BUSY_STATUS);
		if (rc)
			return rc;
		val = apei_exec_ctx_get_output(&ctx);
		if (!val)
			break;
		if (erst_timedout(&timeout, SPIN_UNIT))
			return -EIO;
	}
	rc = apei_exec_run(&ctx, ACPI_ERST_GET_COMMAND_STATUS);
	if (rc)
		return rc;
	val = apei_exec_ctx_get_output(&ctx);
	rc = apei_exec_run(&ctx, ACPI_ERST_END);
	if (rc)
		return rc;

	return erst_errno(val);
}

#endif /* currently dead code */

/* NVRAM ERST Error Log Address Range is not supported yet */
static int __erst_write_to_nvram(const struct cper_record_header *record)
{
	/* do not print message, because printk is not safe for NMI */
	return -ENOSYS;
}

#ifndef NDEBUG /* currently dead code */

static int __erst_read_to_erange_from_nvram(u64 record_id, u64 *offset)
{
	printk(KERN_WARNING
		"NVRAM ERST Log Address Range is not implemented yet\n");
	return -ENOSYS;
}

static int __erst_clear_from_nvram(u64 record_id)
{
	printk(KERN_WARNING
		"NVRAM ERST Log Address Range is not implemented yet\n");
	return -ENOSYS;
}

#endif /* currently dead code */

int erst_write(const struct cper_record_header *record)
{
	int rc;
	unsigned long flags;
	struct cper_record_header *rcd_erange;

	if (!record)
		return -EINVAL;

	if (!erst_enabled)
		return -ENODEV;

	if (memcmp(record->signature, CPER_SIG_RECORD, CPER_SIG_SIZE))
		return -EINVAL;

	if (erst_erange.attr & ERST_RANGE_NVRAM) {
		if (!spin_trylock_irqsave(&erst_lock, flags))
			return -EBUSY;
		rc = __erst_write_to_nvram(record);
		spin_unlock_irqrestore(&erst_lock, flags);
		return rc;
	}

	if (record->record_length > erst_erange.size)
		return -EINVAL;

	if (!spin_trylock_irqsave(&erst_lock, flags))
		return -EBUSY;
	memcpy(erst_erange.vaddr, record, record->record_length);
	rcd_erange = erst_erange.vaddr;
	/* signature for serialization system */
	memcpy(&rcd_erange->persistence_information, "ER", 2);

	rc = __erst_write_to_storage(0);
	spin_unlock_irqrestore(&erst_lock, flags);

	return rc;
}

#ifndef NDEBUG /* currently dead code */

static int __erst_read_to_erange(u64 record_id, u64 *offset)
{
	int rc;

	if (erst_erange.attr & ERST_RANGE_NVRAM)
		return __erst_read_to_erange_from_nvram(
			record_id, offset);

	rc = __erst_read_from_storage(record_id, 0);
	if (rc)
		return rc;
	*offset = 0;

	return 0;
}

static ssize_t __erst_read(u64 record_id, struct cper_record_header *record,
			   size_t buflen)
{
	int rc;
	u64 offset;
	ssize_t len;
	struct cper_record_header *rcd_tmp;

	rc = __erst_read_to_erange(record_id, &offset);
	if (rc)
		return rc;
	rcd_tmp = erst_erange.vaddr + offset;
	if (rcd_tmp->record_length > buflen)
		return -ENOBUFS;
	len = rcd_tmp->record_length;
	memcpy(record, rcd_tmp, len);

	return len >= 0 ? len : -ERANGE;
}

/*
 * If return value > buflen, the buffer size is not big enough,
 * else if return value < 0, something goes wrong,
 * else everything is OK, and return value is record length
 */
ssize_t erst_read(u64 record_id, struct cper_record_header *record,
		  size_t buflen)
{
	ssize_t len;
	unsigned long flags;

	if (!erst_enabled)
		return -ENODEV;

	spin_lock_irqsave(&erst_lock, flags);
	len = __erst_read(record_id, record, buflen);
	spin_unlock_irqrestore(&erst_lock, flags);
	return len;
}

/*
 * If return value > buflen, the buffer size is not big enough,
 * else if return value = 0, there is no more record to read,
 * else if return value < 0, something goes wrong,
 * else everything is OK, and return value is record length
 */
ssize_t erst_read_next(struct cper_record_header *record, size_t buflen)
{
	int rc;
	ssize_t len;
	unsigned long flags;
	u64 record_id;

	if (!erst_enabled)
		return -ENODEV;

	spin_lock_irqsave(&erst_lock, flags);
	rc = __erst_get_next_record_id(&record_id);
	if (rc) {
		spin_unlock_irqrestore(&erst_lock, flags);
		return rc;
	}
	/* no more record */
	if (record_id == APEI_ERST_INVALID_RECORD_ID) {
		spin_unlock_irqrestore(&erst_lock, flags);
		return 0;
	}

	len = __erst_read(record_id, record, buflen);
	spin_unlock_irqrestore(&erst_lock, flags);

	return len;
}

int erst_clear(u64 record_id)
{
	int rc;
	unsigned long flags;

	if (!erst_enabled)
		return -ENODEV;

	spin_lock_irqsave(&erst_lock, flags);
	if (erst_erange.attr & ERST_RANGE_NVRAM)
		rc = __erst_clear_from_nvram(record_id);
	else
		rc = __erst_clear_from_storage(record_id);
	spin_unlock_irqrestore(&erst_lock, flags);

	return rc;
}

#endif /* currently dead code */

static int __init erst_check_table(struct acpi_table_erst *erst_tab)
{
	if (erst_tab->header.length < sizeof(*erst_tab))
		return -EINVAL;

	switch (erst_tab->header_length) {
	case sizeof(*erst_tab) - sizeof(erst_tab->header):
	/*
	 * While invalid per specification, there are (early?) systems
	 * indicating the full header size here, so accept that value too.
	 */
	case sizeof(*erst_tab):
		break;
	default:
		return -EINVAL;
	}

	if (erst_tab->entries !=
	    (erst_tab->header.length - sizeof(*erst_tab)) /
	    sizeof(struct acpi_erst_entry))
		return -EINVAL;

	return 0;
}

int __init erst_init(void)
{
	int rc = 0;
	acpi_status status;
	acpi_physical_address erst_addr;
	acpi_native_uint erst_len;
	struct apei_exec_context ctx;

	if (acpi_disabled)
		return -ENODEV;

	status = acpi_get_table_phys(ACPI_SIG_ERST, 0, &erst_addr, &erst_len);
	if (status == AE_NOT_FOUND) {
		printk(KERN_INFO "ERST table was not found\n");
		return -ENODEV;
	}
	if (ACPI_FAILURE(status)) {
		const char *msg = acpi_format_exception(status);
		printk(KERN_WARNING "Failed to get ERST table: %s\n", msg);
		return -EINVAL;
	}
	map_pages_to_xen((unsigned long)__va(erst_addr), PFN_DOWN(erst_addr),
			 PFN_UP(erst_addr + erst_len) - PFN_DOWN(erst_addr),
			 PAGE_HYPERVISOR);
	erst_tab = __va(erst_addr);

	rc = erst_check_table(erst_tab);
	if (rc) {
		printk(KERN_ERR "ERST table is invalid\n");
		return rc;
	}

	erst_exec_ctx_init(&ctx);
	rc = apei_exec_pre_map_gars(&ctx);
	if (rc)
		return rc;

	rc = erst_get_erange(&erst_erange);
	if (rc) {
		if (rc == -ENODEV)
			printk(KERN_INFO
			"The corresponding hardware device or firmware "
			"implementation is not available.\n");
		else
			printk(KERN_ERR
			       "Failed to get Error Log Address Range.\n");
		goto err_unmap_reg;
	}

	erst_erange.vaddr = apei_pre_map(erst_erange.base, erst_erange.size);
	if (!erst_erange.vaddr) {
		rc = -ENOMEM;
		goto err_unmap_reg;
	}

	printk(KERN_INFO "Xen ERST support is initialized.\n");
	erst_enabled = 1;

	return 0;

err_unmap_reg:
	apei_exec_post_unmap_gars(&ctx);
	return rc;
}
