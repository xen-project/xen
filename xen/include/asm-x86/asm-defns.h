#ifndef HAVE_AS_CLAC_STAC
.macro clac
    .byte 0x0f, 0x01, 0xca
.endm

.macro stac
    .byte 0x0f, 0x01, 0xcb
.endm
#endif
