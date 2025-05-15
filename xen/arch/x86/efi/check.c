int __attribute__((__ms_abi__)) test(int i)
{
    return i;
}

/* In case -mfunction-return is in use. */
void __x86_return_thunk(void) {}

/*
 * Populate an array with "addresses" of relocatable and absolute values.
 * This is to probe ld for (a) emitting base relocations at all and (b) not
 * emitting base relocations for absolute symbols.
 */
extern const unsigned char __image_base__[], __file_alignment__[],
                           __section_alignment__[];
const void *const data[] = {
    __image_base__,
    __file_alignment__,
    __section_alignment__,
    data,
};
