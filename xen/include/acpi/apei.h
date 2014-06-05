/*
 * apei.h - ACPI Platform Error Interface
 */

#ifndef ACPI_APEI_H
#define ACPI_APEI_H

#include <xen/acpi.h>
#include <xen/cper.h>

#define APEI_ERST_INVALID_RECORD_ID	0xffffffffffffffffULL

#define FIX_APEI_RANGE_MAX 64

typedef int (*apei_hest_func_t)(const struct acpi_hest_header *, void *);
int apei_hest_parse(apei_hest_func_t, void *);

int erst_write(const struct cper_record_header *record);
ssize_t erst_get_record_count(void);
int erst_get_next_record_id(u64 *record_id);
ssize_t erst_read(u64 record_id, struct cper_record_header *record,
		  size_t buflen);
ssize_t erst_read_next(struct cper_record_header *record, size_t buflen);
int erst_clear(u64 record_id);

void __iomem *apei_pre_map(paddr_t paddr, unsigned long size);

int apei_pre_map_gar(struct acpi_generic_address *reg);
int apei_post_unmap_gar(struct acpi_generic_address *reg);

int apei_read(u64 *val, struct acpi_generic_address *reg);
int apei_write(u64 val, struct acpi_generic_address *reg);

#endif
