#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <xen/libelf/libelf.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct elf_binary elf_buf, *elf;
    struct elf_dom_parms parms;

    elf = &elf_buf;

    memset(elf, 0, sizeof(*elf));
    elf_init(elf, (const char *)data, size);
    elf_parse_binary(elf);
    elf_xen_parse(elf, &parms);

    return 0;
}


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
