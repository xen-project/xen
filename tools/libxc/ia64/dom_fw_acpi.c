#include <inttypes.h>
#include <xen/acpi.h>

uint8_t
generate_acpi_checksum(void *tbl, unsigned long len)
{
    uint8_t *ptr, sum = 0;

    for ( ptr = tbl; len > 0 ; len--, ptr++ )
        sum += *ptr;

    return 0 - sum;
}
